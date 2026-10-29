from datetime import datetime

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.types import JsonType
from app.models.user import utcnow


class Event(Base):
    """One normalized security event.

    Design choice: fields we filter on constantly (time, type, IP, user) are
    real typed columns so indexes can make queries fast. Everything else goes in
    the flexible `attributes` JSON column.

    `fingerprint` is a SHA-256 hash of the event's identity. A UNIQUE constraint
    on it lets the database itself guarantee we never store the same event twice.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    source: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(50))
    outcome: Mapped[str] = mapped_column(String(20), default="unknown")  # success | failure | unknown
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attributes: Mapped[dict] = mapped_column(JsonType, default=dict)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        # Composite indexes match our most common query shapes:
        # "events of type X in a time range" and "events from IP Y over time".
        Index("ix_events_type_time", "event_type", "timestamp"),
        Index("ix_events_ip_time", "source_ip", "timestamp"),
        Index("ix_events_user_time", "username", "timestamp"),
    )
