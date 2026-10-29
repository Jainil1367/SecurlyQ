"""Importing every model here guarantees they are registered on Base.metadata,
which Alembic migrations and `create_all` both rely on."""

from app.models.alert import Alert, AlertEvidence, Investigation
from app.models.event import Event
from app.models.user import User

__all__ = ["Alert", "AlertEvidence", "Event", "Investigation", "User"]
