"""AnomalyAnalyzer: combines the ML detector with rule findings.

Two jobs, one pass:
1. ENRICH: every rule finding gets the highest anomaly score among the (IP, bucket)
   rows its evidence touches. Rules say *what pattern*; the model says *how unusual*.
2. DISCOVER: buckets the model finds unusual that NO rule already explains become
   their own alerts. This is how stealthy activity (e.g. low-and-slow guessing that
   stays under every rule threshold) can still surface.

Alert-fatigue lesson: one slow attack spans many 10-minute buckets. Raising an alert per
bucket would bury an analyst in 14 alerts for ONE incident, so consecutive anomalous
buckets from the same IP are merged into a single episode alert.

Design note: the model never overrides a rule and never closes an alert. It only adds
a second signal, which keeps the system explainable.
"""

from collections import defaultdict

from app.ml.detector import AnomalyDetector
from app.ml.features import BUCKET_SECONDS, bucket_of, build_features, events_to_frame
from app.models import Event
from app.services.rules import Finding

RULE_ID = "anomaly_isolation_forest"
MAX_EVIDENCE_EVENTS = 200  # bound database writes for very busy episodes
MERGE_GAP_BUCKETS = 3  # flagged buckets up to 30 minutes apart belong to the same episode


class AnomalyAnalyzer:
    def __init__(self, detector: AnomalyDetector):
        self.detector = detector

    def apply(self, events: list[Event], findings: list[Finding]) -> list[Finding]:
        feats = build_features(events_to_frame(events))
        if feats.empty:
            return findings
        feats = feats.assign(score=self.detector.score(feats))
        lookup = {(r.source_ip, int(r.bucket)): float(r.score) for r in feats.itertuples()}

        # 1. ENRICH rule findings with the model's opinion.
        covered: set[tuple[str, int]] = set()
        for finding in findings:
            keys = {(e.source_ip, bucket_of(e.timestamp)) for e, _ in finding.evidence if e.source_ip}
            hits = [lookup[k] for k in keys if k in lookup]
            if hits:
                finding.anomaly_score = round(max(hits), 3)
            covered |= keys

        # 2. DISCOVER unusual buckets no rule explains, merged into episodes per IP.
        by_bucket: dict[tuple[str, int], list[Event]] = defaultdict(list)
        for e in events:
            if e.event_type == "login" and e.source_ip:
                by_bucket[(e.source_ip, bucket_of(e.timestamp))].append(e)

        novel_by_ip: dict[str, list] = defaultdict(list)
        for row in feats[feats["score"] >= self.detector.threshold].itertuples():
            if (row.source_ip, int(row.bucket)) not in covered:
                novel_by_ip[row.source_ip].append(row)

        for ip, rows in novel_by_ip.items():
            rows.sort(key=lambda r: r.bucket)
            run = [rows[0]]
            for row in rows[1:]:
                if row.bucket - run[-1].bucket <= MERGE_GAP_BUCKETS * BUCKET_SECONDS:
                    run.append(row)
                else:
                    findings.append(self._episode(ip, run, feats, by_bucket))
                    run = [row]
            findings.append(self._episode(ip, run, feats, by_bucket))
        return findings

    def _episode(self, ip: str, run: list, feats, by_bucket: dict) -> Finding:
        threshold = self.detector.threshold
        top = max(run, key=lambda r: r.score)
        first, last = int(run[0].bucket), int(run[-1].bucket)

        drivers = self.detector.explain(feats.loc[top.Index])
        summary = ", ".join(f"{d['value']:g} {d['label']} ({d['z_score']:+.1f}σ)" for d in drivers)
        reason = (
            f"Unusual activity (more unusual than {top.score:.1%} of training behaviour) "
            f"in the most unusual window: {summary}"
        )

        events: list[Event] = []
        for bucket in range(first, last + BUCKET_SECONDS, BUCKET_SECONDS):
            events.extend(by_bucket.get((ip, bucket), []))
        events = events[:MAX_EVIDENCE_EVENTS]
        users = {e.username for e in events if e.username}

        minutes = (last - first) // 60 + BUCKET_SECONDS // 60
        return Finding(
            rule_id=RULE_ID,
            title=f"Unusual login activity from {ip}" + (f" over {minutes} min" if len(run) > 1 else ""),
            severity="high" if top.score >= threshold + (1 - threshold) / 2 else "medium",
            dedup_key=f"{RULE_ID}:{ip}:{first}",
            evidence=[(e, reason) for e in events],
            source_ip=ip,
            username=next(iter(users)) if len(users) == 1 else None,
            anomaly_score=round(float(top.score), 3),
        )
