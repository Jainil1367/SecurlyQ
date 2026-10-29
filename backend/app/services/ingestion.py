"""Event ingestion service: validate -> normalize -> deduplicate -> store.

Data-structures lesson: a Python `set` gives O(1) average membership checks, so
removing duplicates from a batch of N events is O(N), not O(N^2).
"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Event
from app.schemas.event import EventIn, IngestResult
from app.services.event_parser import EventParser


class EventIngestionService:
    def __init__(self, db: Session):
        self.db = db

    def ingest(self, events: list[EventIn]) -> IngestResult:
        try:
            return self._ingest_once(events)
        except IntegrityError:
            # Two requests inserted the same fingerprint at the same moment.
            # The UNIQUE constraint caught it; roll back and retry once, which
            # will now see the winner's rows and treat them as duplicates.
            self.db.rollback()
            return self._ingest_once(events)

    def _ingest_once(self, events: list[EventIn]) -> IngestResult:
        # 1. Normalize and drop duplicates *within* this batch (hash set).
        seen: set[str] = set()
        unique_rows: list[dict] = []
        for event in events:
            row = EventParser.normalize(event)
            if row["fingerprint"] not in seen:
                seen.add(row["fingerprint"])
                unique_rows.append(row)

        # 2. Drop events already stored (one indexed query for the whole batch).
        existing = set()
        if seen:
            existing = set(
                self.db.scalars(select(Event.fingerprint).where(Event.fingerprint.in_(seen)))
            )
        new_rows = [r for r in unique_rows if r["fingerprint"] not in existing]

        # 3. Store the rest in a single transaction.
        self.db.add_all(Event(**row) for row in new_rows)
        self.db.commit()

        return IngestResult(
            received=len(events),
            accepted=len(new_rows),
            duplicates=len(events) - len(new_rows),
        )
