"""Amazon Bedrock access, behind a tiny interface.

Architecture lesson: the rest of the app depends on `TextGenerator` (one method), not
on boto3. That gives us three things: tests run without AWS, switching providers later
touches one file, and failures are translated into ONE exception (`LLMUnavailable`) that
callers know how to handle (fall back to the template explanation).

Credentials: boto3 finds them itself (environment variables locally, the IAM task/instance
role on AWS). They never appear in our code, config files, or logs.
"""

import logging
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.config import Settings

logger = logging.getLogger("securlyq.llm")


class LLMUnavailable(Exception):
    """The model could not be reached or refused the request (network, throttling, permissions...)."""


@dataclass
class GenerationResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str | None = None


class TextGenerator(Protocol):
    model_id: str

    def generate(self, system: str, user: str) -> GenerationResult: ...


class BedrockGenerator:
    """Calls Bedrock's Converse API, which has one request shape for every supported model."""

    def __init__(
        self,
        model_id: str,
        region: str,
        timeout_seconds: int,
        max_tokens: int,
        client: Any | None = None,
    ):
        self.model_id = model_id
        self.max_tokens = max_tokens
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "bedrock-runtime",
                region_name=region,
                config=Config(
                    connect_timeout=3,
                    read_timeout=timeout_seconds,  # never let a slow model hang a request forever
                    retries={"max_attempts": 2, "mode": "standard"},
                ),
            )
        self.client = client

    def generate(self, system: str, user: str) -> GenerationResult:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            response = self.client.converse(
                modelId=self.model_id,
                system=[{"text": system}],
                messages=[{"role": "user", "content": [{"text": user}]}],
                inferenceConfig={"maxTokens": self.max_tokens, "temperature": 0.2},
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            raise LLMUnavailable(f"bedrock:{code}") from exc
        except BotoCoreError as exc:
            raise LLMUnavailable(f"bedrock:{type(exc).__name__}") from exc

        try:
            blocks = response["output"]["message"]["content"]
            text = "".join(b["text"] for b in blocks if "text" in b)
        except (KeyError, TypeError) as exc:
            raise LLMUnavailable("bedrock:malformed_response") from exc

        usage = response.get("usage", {})
        return GenerationResult(
            text=text,
            input_tokens=int(usage.get("inputTokens", 0)),
            output_tokens=int(usage.get("outputTokens", 0)),
            stop_reason=response.get("stopReason"),
        )


def build_generator(settings: Settings) -> TextGenerator | None:
    """None means "LLM off": callers use the deterministic template explanation."""
    if settings.llm_provider == "bedrock":
        return BedrockGenerator(
            model_id=settings.bedrock_model_id,
            region=settings.aws_region,
            timeout_seconds=settings.llm_timeout_seconds,
            max_tokens=settings.llm_max_output_tokens,
        )
    return None
