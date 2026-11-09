"""RiskScorer: turns a finding into a 0-100 prioritization score.

Honest framing: this is a *ranking* heuristic, not a calibrated probability.
Phase 3 will blend in the anomaly-model score and then evaluate how well the
score separates real attacks from noise (precision/recall at thresholds).
"""

from app.services.rules import Finding

SEVERITY_BASE = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 90.0}
MAX_EVIDENCE_BONUS = 10.0
ANOMALY_WEIGHT = 10.0  # a maximally unusual bucket adds up to 10 points


class RiskScorer:
    def score(self, finding: Finding) -> float:
        base = SEVERITY_BASE.get(finding.severity, 25.0)
        bonus = min(MAX_EVIDENCE_BONUS, 0.5 * len(finding.evidence))  # more evidence, more concern
        anomaly = ANOMALY_WEIGHT * finding.anomaly_score if finding.anomaly_score is not None else 0.0
        return round(min(100.0, base + bonus + anomaly), 1)
