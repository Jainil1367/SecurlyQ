"""AnomalyAnalyzer logic tested with a stub detector, so results don't depend on ML randomness."""

import hashlib
from datetime import UTC, datetime, timedelta

import numpy as np

from app.ml.features import FEATURE_LABELS
from app.models import Event
from app.services.anomaly import RULE_ID, AnomalyAnalyzer
from app.services.rules import Finding

BASE = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
_ids = iter(range(1, 1_000_000))


class StubDetector:
    """Scores any bucket containing >= `flag_at` events as 0.999, everything else 0.1."""

    threshold = 0.99

    def __init__(self, flag_at=1):
        self.flag_at = flag_at

    def score(self, feats):
        return np.where(feats["n_events"] >= self.flag_at, 0.999, 0.1)

    def explain(self, row, top=3):
        return [{"feature": "n_failures", "label": FEATURE_LABELS["n_failures"], "value": 7.0, "z_score": 9.9}]


def ev(minutes, ip="203.0.113.9", user="alice", outcome="failure"):
    i = next(_ids)
    return Event(
        id=i, fingerprint=hashlib.sha256(str(i).encode()).hexdigest(), source="t", event_type="login",
        outcome=outcome, timestamp=BASE + timedelta(minutes=minutes), source_ip=ip, username=user, attributes={},
    )


def test_consecutive_buckets_merge_into_one_alert():
    events = [ev(m) for m in range(0, 120, 4)]  # one slow attacker, 12 buckets of activity
    findings = AnomalyAnalyzer(StubDetector()).apply(events, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == RULE_ID and f.source_ip == "203.0.113.9" and len(f.evidence) == len(events)
    assert "over 120 min" in f.title and f.anomaly_score == 0.999
    assert "σ" in f.evidence[0][1]


def test_separate_episodes_stay_separate():
    events = [ev(m) for m in (0, 5, 10)] + [ev(m) for m in (300, 305)]  # five hours apart
    assert len(AnalyzerResult(events)) == 2


def AnalyzerResult(events):
    return AnomalyAnalyzer(StubDetector()).apply(events, [])


def test_small_gap_is_bridged_but_large_gap_is_not():
    near = [ev(0), ev(30)]  # 3 buckets apart: same episode
    far = [ev(0), ev(60)]  # 6 buckets apart: two episodes
    assert len(AnalyzerResult(near)) == 1
    assert len(AnalyzerResult(far)) == 2


def test_different_ips_never_merge():
    events = [ev(0, ip="1.1.1.1"), ev(0, ip="2.2.2.2")]
    assert {f.source_ip for f in AnalyzerResult(events)} == {"1.1.1.1", "2.2.2.2"}


def test_buckets_already_explained_by_a_rule_are_enriched_not_duplicated():
    events = [ev(m) for m in range(8)]
    rule_finding = Finding("failed_login_burst", "t", "medium", "k", [(e, "x") for e in events], source_ip="203.0.113.9")
    out = AnomalyAnalyzer(StubDetector()).apply(events, [rule_finding])
    assert len(out) == 1 and out[0].anomaly_score == 0.999  # enriched, no extra model alert


def test_quiet_buckets_produce_nothing():
    assert AnomalyAnalyzer(StubDetector(flag_at=5)).apply([ev(0), ev(1)], []) == []


def test_severity_tiers_follow_threshold():
    class Tiered(StubDetector):
        def score(self, feats):
            return np.full(len(feats), 0.992)  # above 0.99 but below the midpoint 0.995

    assert AnomalyAnalyzer(Tiered()).apply([ev(0)], [])[0].severity == "medium"
    assert AnomalyAnalyzer(StubDetector()).apply([ev(0)], [])[0].severity == "high"  # 0.999 >= 0.995


def test_evidence_is_capped_for_huge_episodes():
    events = [ev(0) for _ in range(500)]
    assert len(AnomalyAnalyzer(StubDetector()).apply(events, [])[0].evidence) == 200
