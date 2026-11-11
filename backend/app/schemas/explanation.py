"""The shape an LLM answer must have before we store or show it.

Lesson: an LLM returns *text*. Treat it like any other untrusted input: parse it,
validate it against a strict schema, and reject anything that doesn't fit.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ShortText = Field(min_length=1, max_length=400)


class ExplanationBody(BaseModel):
    """Exactly the fields we ask the model for. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    summary: str = Field(min_length=20, max_length=700)
    why_flagged: list[str] = Field(min_length=1, max_length=6)
    benign_possibilities: list[str] = Field(min_length=1, max_length=5)
    investigation_steps: list[str] = Field(min_length=2, max_length=7)
    uncertainty: str = Field(min_length=10, max_length=500)

    def all_text(self) -> list[str]:
        return [self.summary, *self.why_flagged, *self.benign_possibilities, *self.investigation_steps, self.uncertainty]


class ExplanationOut(ExplanationBody):
    """What we store and return: the validated body plus provenance."""

    source: Literal["llm", "fallback"]
    model_id: str | None = None
    generated_at: datetime
    fallback_reason: str | None = None  # why the template was used instead of the model
    disclaimer: str = (
        "Automatically generated from alert evidence. This describes potentially suspicious "
        "activity; it does not confirm an attack. A human must decide what to do."
    )
