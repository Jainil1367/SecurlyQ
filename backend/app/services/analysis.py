"""AnalysisService: load events for a time range, run the rules, save alerts."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.ml.runtime import get_detector
from app.models import Event
from app.services.alert_repository import AlertRepository
from app.services.rules import RuleEngine


class AnalysisTooLarge(Exception):
    """The requested window contains more events than we analyze in one run."""


@dataclass
class AnalysisResult:
    events_scanned: int
    findings: int
    alerts_created: int
    window_start: datetime
    window_end: datetime
    anomaly_model: str | None = None


class AnalysisService:
    def __init__(self, db: Session, engine: RuleEngine | None = None):
        self.db = db
        self.settings = get_settings()
        # No trained model file? get_detector() returns None and we run rules-only.
        self.detector = None if engine else get_detector()
        self.engine = engine or RuleEngine.from_settings(self.settings, detector=self.detector)
        self.repository = AlertRepository(db)

    def run(self, since: datetime | None = None, until: datetime | None = None) -> AnalysisResult:
        until = until or datetime.now(UTC)
        since = since or until - timedelta(hours=self.settings.analysis_lookback_hours)
        cap = self.settings.max_analysis_events

        events = list(
            self.db.scalars(
                select(Event)
                .where(Event.timestamp >= since, Event.timestamp <= until)
                .order_by(Event.timestamp, Event.id)
                .limit(cap + 1)
            )
        )
        if len(events) > cap:
            raise AnalysisTooLarge(f"More than {cap} events in window; choose a smaller time range.")

        findings = self.engine.run(events)
        created = self.repository.save_findings(findings)
        return AnalysisResult(
            events_scanned=len(events),
            findings=len(findings),
            alerts_created=created,
            window_start=since,
            window_end=until,
            anomaly_model=self.detector.metadata.get("model_version") if self.detector else None,
        )
