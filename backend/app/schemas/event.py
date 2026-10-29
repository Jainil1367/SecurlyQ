"""Pydantic schemas: the contract between the outside world and our code.

Lesson: never trust input. Pydantic validates *every* incoming field (type,
length, format) before our business logic ever sees it. Bad data becomes a clean
HTTP 422 error instead of a crash or, worse, a security hole.
"""

import json
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Outcome = Literal["success", "failure", "unknown"]

MAX_ATTRIBUTES_BYTES = 8_192


class EventIn(BaseModel):
    """One raw event as submitted by a client."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source: str = Field(min_length=1, max_length=100, examples=["auth-service"])
    event_type: str = Field(
        min_length=1,
        max_length=50,
        pattern=r"^[a-z0-9_.]+$",
        examples=["login"],
        description="Lowercase identifier, e.g. login, logout, password_reset.",
    )
    timestamp: datetime
    outcome: Outcome = "unknown"
    source_ip: IPv4Address | IPv6Address | None = None
    username: str | None = Field(default=None, max_length=255)
    attributes: dict = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def to_utc(cls, value: datetime) -> datetime:
        """Normalize every timestamp to UTC. Naive timestamps are assumed UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("attributes")
    @classmethod
    def limit_attribute_size(cls, value: dict) -> dict:
        if len(json.dumps(value, default=str)) > MAX_ATTRIBUTES_BYTES:
            raise ValueError(f"attributes must be under {MAX_ATTRIBUTES_BYTES} bytes")
        return value


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    event_type: str
    outcome: str
    timestamp: datetime
    source_ip: str | None
    username: str | None
    attributes: dict

    @field_validator("timestamp")
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        # Databases may hand back naive (SQLite) or session-local (PostgreSQL)
        # datetimes. The API contract is simple: always UTC.
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class IngestResult(BaseModel):
    received: int
    accepted: int
    duplicates: int


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    limit: int
    offset: int
