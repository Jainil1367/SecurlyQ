"""Event routes. Routes stay thin: validate -> call a service -> return."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import analyst_or_admin, any_user
from app.core.config import get_settings
from app.db.session import get_db
from app.models import Event, User
from app.schemas.event import EventIn, EventOut, EventPage, IngestResult
from app.services.ingestion import EventIngestionService

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def ingest_events(
    events: list[EventIn],
    db: Session = Depends(get_db),
    _: User = Depends(analyst_or_admin),
) -> IngestResult:
    """Ingest a batch of security events (analyst/admin). Duplicates are skipped, not errors."""
    max_batch = get_settings().max_batch_size
    if not events:
        raise HTTPException(status_code=422, detail="Batch must contain at least one event.")
    if len(events) > max_batch:
        raise HTTPException(
            status_code=413, detail=f"Batch too large: {len(events)} > {max_batch} events."
        )
    return EventIngestionService(db).ingest(events)


@router.get("", response_model=EventPage)
def list_events(
    db: Session = Depends(get_db),
    _: User = Depends(any_user),
    event_type: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> EventPage:
    """List events, newest first, with filters and pagination."""
    query = select(Event)
    if event_type:
        query = query.where(Event.event_type == event_type)
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if username:
        query = query.where(Event.username == username.lower())
    if since:
        query = query.where(Event.timestamp >= since)
    if until:
        query = query.where(Event.timestamp <= until)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset))
    return EventPage(
        items=[EventOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )
