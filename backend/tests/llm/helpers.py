"""Shared builders for LLM tests: in-memory alerts/events and a scriptable fake model."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from app.llm.bedrock import GenerationResult
from app.models import Alert, Event

BASE = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
_ids = iter(range(1, 1_000_000))


def make_event(seconds=0, ip="203.0.113.9", user="alice", outcome="failure", attributes=None) -> Event:
    i = next(_ids)
    return Event(
        id=i, fingerprint=hashlib.sha256(str(i).encode()).hexdigest(), source="auth", event_type="login",
        outcome=outcome, timestamp=BASE + timedelta(seconds=seconds), source_ip=ip, username=user,
        attributes=attributes or {},
    )


def make_alert(rule_id="failure_then_success", ip="203.0.113.9", user="alice", **kw) -> Alert:
    values = {
        "id": 1, "rule_id": rule_id, "dedup_key": "k", "title": "t", "severity": "high",
        "risk_score": 81.5, "anomaly_score": None, "source_ip": ip, "username": user, "status": "open",
    }
    values.update(kw)
    return Alert(**values)


def attack_evidence(n_failures=12, ip="203.0.113.9", user="alice"):
    pairs = [(f"Failed login for '{user}' from {ip}", make_event(10 * i, ip, user)) for i in range(n_failures)]
    pairs.append((f"Successful login for '{user}' from the same IP", make_event(10 * n_failures + 5, ip, user, "success")))
    return pairs


def good_output(**overrides) -> dict:
    body = {
        "summary": "Potentially suspicious activity: 12 failed logins from 203.0.113.9 for account-1 were followed by a success.",
        "why_flagged": [
            "12 failed logins from 203.0.113.9 within about two minutes.",
            "A successful login for account-1 from the same IP right afterwards.",
        ],
        "benign_possibilities": ["The user mistyped their password repeatedly before succeeding."],
        "investigation_steps": [
            "Ask the owner of account-1 whether they signed in at that time.",
            "Review what account-1 did after the successful login.",
            "Check for other activity from 203.0.113.9.",
        ],
        "uncertainty": "The logs cannot show whether the person signing in was authorized.",
    }
    body.update(overrides)
    return body


class FakeGenerator:
    """Returns scripted responses (str, dict, or an Exception instance to raise)."""

    model_id = "fake-model-v1"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def generate(self, system: str, user: str) -> GenerationResult:
        self.calls.append((system, user))
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        text = item if isinstance(item, str) else json.dumps(item)
        return GenerationResult(text=text, input_tokens=120, output_tokens=80)
