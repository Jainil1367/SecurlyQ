"""EventParser: turns a validated EventIn into a normalized, fingerprinted record.

OOP lesson (single responsibility): this class does exactly one job. It does not
touch the database or HTTP. That makes it trivial to unit test and reuse (the
rule engine and ML code will rely on the same normalized shape).
"""

import hashlib
import json

from app.schemas.event import EventIn


class EventParser:
    @staticmethod
    def fingerprint(event: EventIn) -> str:
        """Deterministic SHA-256 identity of an event.

        We serialize the identifying fields in a canonical form (sorted keys,
        fixed timestamp format) so the same event always hashes to the same value.
        A hash is a fixed-size "fingerprint": cheap to compare, cheap to index.
        """
        canonical = json.dumps(
            {
                "source": event.source,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "outcome": event.outcome,
                "source_ip": str(event.source_ip) if event.source_ip else None,
                "username": event.username.lower() if event.username else None,
                "attributes": event.attributes,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def normalize(cls, event: EventIn) -> dict:
        """Return column values ready to build an `Event` row."""
        return {
            "fingerprint": cls.fingerprint(event),
            "source": event.source,
            "event_type": event.event_type,
            "outcome": event.outcome,
            "timestamp": event.timestamp,
            "source_ip": str(event.source_ip) if event.source_ip else None,
            "username": event.username.lower() if event.username else None,
            "attributes": event.attributes,
        }
