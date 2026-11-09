"""AlertRepository: the only place that knows how alerts are stored.

Repository pattern lesson: services ask the repository for "save these findings";
they never write SQL themselves. If storage changes, only this class changes.
"""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvidence
from app.services.risk import RiskScorer
from app.services.rules import Finding


class AlertRepository:
    def __init__(self, db: Session, scorer: RiskScorer | None = None):
        self.db = db
        self.scorer = scorer or RiskScorer()

    def save_findings(self, findings: list[Finding]) -> int:
        """Persist findings as alerts, skipping ones that already exist. Returns # created."""
        try:
            return self._save_once(findings)
        except IntegrityError:
            self.db.rollback()  # a concurrent run created the same alert; retry sees it
            return self._save_once(findings)

    def _save_once(self, findings: list[Finding]) -> int:
        if not findings:
            return 0
        keys = {f.dedup_key for f in findings}
        existing = set(self.db.scalars(select(Alert.dedup_key).where(Alert.dedup_key.in_(keys))))

        created = 0
        for finding in findings:
            if finding.dedup_key in existing:
                continue
            existing.add(finding.dedup_key)
            alert = Alert(
                rule_id=finding.rule_id,
                dedup_key=finding.dedup_key,
                title=finding.title,
                severity=finding.severity,
                risk_score=self.scorer.score(finding),
                anomaly_score=finding.anomaly_score,
                source_ip=finding.source_ip,
                username=finding.username,
            )
            self.db.add(alert)
            self.db.flush()  # assigns alert.id so evidence rows can reference it

            seen_events: set[int] = set()
            for event, reason in finding.evidence:
                if event.id in seen_events:
                    continue
                seen_events.add(event.id)
                self.db.add(AlertEvidence(alert_id=alert.id, event_id=event.id, reason=reason))
            created += 1
        self.db.commit()
        return created
