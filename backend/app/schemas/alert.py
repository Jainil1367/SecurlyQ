from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.schemas.event import EventOut

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["open", "acknowledged", "resolved", "false_positive"]


def _to_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_to_utc)]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    title: str
    severity: Severity
    risk_score: float
    status: AlertStatus
    source_ip: str | None
    username: str | None
    created_at: UtcDatetime
    acknowledged_at: UtcDatetime | None
    evidence_count: int = 0


class EvidenceOut(BaseModel):
    reason: str
    event: EventOut


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    author_id: int | None
    author_email: str | None = None
    notes: str
    updated_at: UtcDatetime


class AlertDetail(AlertOut):
    explanation: dict | None
    evidence: list[EvidenceOut]
    investigation_notes: list[NoteOut]


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    notes: str = Field(min_length=1, max_length=5000)


class AlertSummary(BaseModel):
    total_alerts: int
    by_status: dict[str, int]
    open_by_severity: dict[str, int]
    top_source_ips: list[dict]
    mean_time_to_acknowledge_seconds: float | None


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    since: UtcDatetime | None = None
    until: UtcDatetime | None = None


class AnalysisResultOut(BaseModel):
    events_scanned: int
    findings: int
    alerts_created: int
    window_start: UtcDatetime
    window_end: UtcDatetime
