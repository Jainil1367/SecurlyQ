"""LLMExplainer: sanitize -> prompt -> generate -> VALIDATE -> (fallback if anything is off).

The model is never trusted. Its output is accepted only if it is valid JSON matching the
schema, contains no links or commands, makes no overconfident claims, and mentions no IP
address or account that was not in the evidence we sent (a hallucination guard).
"""

import json
import logging
import re
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from functools import lru_cache

from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.llm.bedrock import LLMUnavailable, TextGenerator, build_generator
from app.llm.fallback import build_fallback
from app.llm.prompt import SYSTEM_PROMPT, build_user_message
from app.llm.record import IncidentRecord, build_incident_record
from app.models import Alert, Event
from app.schemas.explanation import ExplanationBody, ExplanationOut

logger = logging.getLogger("securlyq.llm")

_URL = re.compile(r"(?i)(https?://|www\.|ftp://)")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ACCOUNT = re.compile(r"\baccount-\d+\b")
_OVERCLAIM = re.compile(
    r"(?i)\b(definitely|certainly|undoubtedly|without (?:a )?doubt|"
    r"(?:is|was|are|were) (?:a )?confirmed|confirmed (?:attack|breach|compromise|intrusion))\b"
)
_COMMANDISH = re.compile(r"(?i)(```|\brm -rf\b|\bsudo\b|\biptables\b|\bcurl\b|\bwget\b|\bpowershell\b|\bchmod\b)")
_AUTO_ACTION = re.compile(r"(?i)\bautomatic(?:ally)?\w*\s+(?:block|ban|disable|lock|delete|quarantine)")


class OutputRejected(Exception):
    """The model answered, but not in a way we are willing to show."""


def validate_output(raw: str, record: IncidentRecord) -> ExplanationBody:
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        raise OutputRejected("no_json_object")
    try:
        payload = json.loads(raw[start : end + 1])
        body = ExplanationBody.model_validate(payload)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise OutputRejected("schema_mismatch") from exc

    text = "\n".join(body.all_text())
    if _URL.search(text):
        raise OutputRejected("contains_url")
    if _COMMANDISH.search(text):
        raise OutputRejected("contains_command_or_code")
    if _AUTO_ACTION.search(text):
        raise OutputRejected("recommends_automated_action")
    if _OVERCLAIM.search(text):
        raise OutputRejected("overconfident_claim")
    if any(ip not in record.allowed_ips for ip in _IPV4.findall(text)):
        raise OutputRejected("mentions_unknown_ip")
    if any(a not in record.allowed_accounts for a in _ACCOUNT.findall(text)):
        raise OutputRejected("mentions_unknown_account")
    return body


class LLMExplainer:
    def __init__(self, generator: TextGenerator | None, settings: Settings | None = None):
        self.generator = generator
        self.settings = settings or get_settings()

    def explain(self, alert: Alert, evidence: Sequence[tuple[str, Event]]) -> ExplanationOut:
        record = build_incident_record(
            alert,
            evidence,
            max_events=self.settings.llm_max_evidence_events,
            redact_usernames=self.settings.llm_redact_usernames,
        )
        if self.generator is None:
            return build_fallback(record, "llm_disabled")

        started = time.monotonic()
        try:
            result = self.generator.generate(SYSTEM_PROMPT, build_user_message(record))
            body = validate_output(result.text, record)
        except LLMUnavailable as exc:
            self._log(alert, "unavailable", started, detail=str(exc))
            return build_fallback(record, "llm_unavailable")
        except OutputRejected as exc:
            self._log(alert, "rejected", started, detail=str(exc), tokens=(result.input_tokens, result.output_tokens))
            return build_fallback(record, f"invalid_output:{exc}")

        self._log(alert, "ok", started, tokens=(result.input_tokens, result.output_tokens))
        return ExplanationOut(
            **body.model_dump(),
            source="llm",
            model_id=self.generator.model_id,
            generated_at=datetime.now(UTC),
        )

    @staticmethod
    def _log(alert: Alert, outcome: str, started: float, detail: str = "", tokens: tuple[int, int] = (0, 0)) -> None:
        # Metadata only. We never log prompts or completions: they may contain event data.
        logger.info(
            "explain alert=%s outcome=%s latency_ms=%d in_tokens=%d out_tokens=%d %s",
            alert.id, outcome, (time.monotonic() - started) * 1000, tokens[0], tokens[1], detail,
        )


@lru_cache
def _default_explainer() -> LLMExplainer:
    settings = get_settings()
    return LLMExplainer(build_generator(settings), settings)


def get_explainer() -> LLMExplainer:
    """FastAPI dependency. Tests override it with a fake generator."""
    return _default_explainer()


def clear_cache() -> None:
    _default_explainer.cache_clear()
