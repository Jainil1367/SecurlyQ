"""Fill a database with realistic demo traffic ending "now", then run detection.

    python -m app.ml.seed_demo            # 3 days of events
    python -m app.ml.seed_demo --days 5

Uses the same simulator as training but a different seed and attacker IPs, so the
demo contains attacks the model has never seen. Labels are stripped before ingestion:
the API only ever receives what a real log shipper would send.
"""

import argparse
import logging
from datetime import UTC, datetime, timedelta

from app.db.session import SessionLocal
from app.ml.simulate import SimConfig, attacker_pool, simulate
from app.schemas.event import EventIn
from app.services.analysis import AnalysisService
from app.services.ingestion import EventIngestionService

logger = logging.getLogger("securlyq.demo")
CHUNK = 1000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed demo security events and run analysis.")
    parser.add_argument("--days", type=int, default=3)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args(argv)
    logging.basicConfig(level="INFO", format="%(levelname)s %(message)s")

    now = datetime.now(UTC)
    start = (now - timedelta(days=args.days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    df = simulate(SimConfig(seed=args.seed, start=start, days=args.days, attacker_ips=attacker_pool("198.18.5")))
    df = df[df["timestamp"] <= now]  # no events from the future

    events = [
        EventIn(
            source=r.source,
            event_type=r.event_type,
            timestamp=r.timestamp.to_pydatetime(),
            outcome=r.outcome,
            source_ip=r.source_ip,
            username=r.username,
        )
        for r in df.itertuples(index=False)  # note: is_attack / scenario / incident_id are NOT sent
    ]

    with SessionLocal() as db:
        accepted = 0
        for i in range(0, len(events), CHUNK):
            accepted += EventIngestionService(db).ingest(events[i : i + CHUNK]).accepted
        logger.info("ingested %d new events (%d generated)", accepted, len(events))

        result = AnalysisService(db).run(since=start, until=now)
        logger.info(
            "analysis: scanned=%d findings=%d alerts_created=%d model=%s",
            result.events_scanned,
            result.findings,
            result.alerts_created,
            result.anomaly_model or "none (rules-only)",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
