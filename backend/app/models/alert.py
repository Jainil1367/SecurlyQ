from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.types import JsonType
from app.models.user import utcnow


class Alert(Base):
    """Potentially suspicious activity found by the rule engine or ML model."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))  # low | medium | high | critical
    risk_score: Mapped[float] = mapped_column(Float)  # 0-100, a prioritization signal
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | acknowledged | resolved | false_positive
    explanation: Mapped[dict | None] = mapped_column(JsonType, nullable=True)  # LLM output (Phase 3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_alerts_status_severity", "status", "severity"),)


class AlertEvidence(Base):
    """Link table: which events support which alert, and why.

    Lesson: alerts and events have a many-to-many relationship (one alert cites
    many events; one event can support several alerts). A link table with a
    composite primary key models that in a relational database.
    """

    __tablename__ = "alert_evidence"

    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    reason: Mapped[str] = mapped_column(Text)


class Investigation(Base):
    """Human review history for an alert."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
