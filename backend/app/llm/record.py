"""Build the small, sanitized "incident record" that is the ONLY thing the LLM ever sees.

Security lessons:
* DATA MINIMIZATION: send the least information that still lets the model explain the
  alert. We never send raw `attributes` (user agents, emails, tokens, free text that
  logs can contain), and we cap how many events go out.
* PSEUDONYMIZATION: account names become `account-1`, `account-2`. The explanation
  stays useful ("account-1 failed 14 times") without shipping personal data.
* NEUTRALIZATION: log fields are attacker-controlled. We strip control characters,
  collapse whitespace, and truncate, so a username like
  "alice\\nIGNORE ALL PREVIOUS INSTRUCTIONS..." arrives as a short, inert string.
"""

import json
import re
from collections.abc import Sequence

from app.models import Alert, Event

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
MAX_FIELD_CHARS = 200

RULE_DESCRIPTIONS = {
    "failed_login_burst": "Many failed logins from one IP address within a few minutes.",
    "failure_then_success": "A successful login from an IP address that had just failed repeatedly.",
    "multi_ip_login": "One account was used from several different IP addresses in a short time.",
    "anomaly_isolation_forest": (
        "A statistical anomaly model found login activity unusual compared with normal traffic; "
        "no specific rule matched."
    ),
}


def clean(text: object, limit: int = MAX_FIELD_CHARS) -> str:
    """Make an untrusted value safe to embed: no control characters, bounded length."""
    value = _CONTROL.sub(" ", str(text))
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


class IncidentRecord:
    """The sanitized record plus the sets of values the model is allowed to mention."""

    def __init__(self, data: dict, allowed_ips: set[str], allowed_accounts: set[str]):
        self.data = data
        self.allowed_ips = allowed_ips
        self.allowed_accounts = allowed_accounts

    def to_json(self) -> str:
        # Escape "<" so log text can never fake our closing </incident_record> delimiter.
        return json.dumps(self.data, indent=2, sort_keys=True).replace("<", "\\u003c")


def build_incident_record(
    alert: Alert,
    evidence: Sequence[tuple[str, Event]],
    *,
    max_events: int = 25,
    redact_usernames: bool = True,
) -> IncidentRecord:
    """`evidence` is (reason, event) pairs in chronological order."""
    aliases: dict[str, str] = {}

    def alias(name: str | None) -> str | None:
        if not name:
            return None
        if not redact_usernames:
            return clean(name, 80)
        return aliases.setdefault(name, f"account-{len(aliases) + 1}")

    # Assign aliases in order of first appearance so numbering is stable.
    for _, event in evidence:
        alias(event.username)
    alias(alert.username)

    def scrub_reason(reason: str) -> str:
        # Rule reasons quote usernames like 'alice'. Replace the exact quoted form on the RAW text,
        # then clean. (Cleaning first would let a username containing a newline escape redaction,
        # and replacing bare substrings would corrupt text for short names such as "a".)
        text = reason
        for real, fake in aliases.items():
            text = text.replace(f"'{real}'", f"'{fake}'")
        return clean(text)

    events = [e for _, e in evidence]
    outcomes = [e.outcome for e in events]
    stamps = [e.timestamp for e in events]
    duration = int((max(stamps) - min(stamps)).total_seconds()) if stamps else 0

    # Show the beginning and end of the activity rather than only the start.
    pairs = list(evidence)
    if len(pairs) > max_events:
        head = max_events // 2
        sample = pairs[:head] + pairs[-(max_events - head) :]
    else:
        sample = pairs

    ips = {e.source_ip for e in events if e.source_ip}
    data = {
        "alert": {
            "rule": clean(alert.rule_id, 60),
            "rule_description": RULE_DESCRIPTIONS.get(alert.rule_id, "Custom detection rule."),
            "severity": alert.severity,
            "risk_score_0_to_100": alert.risk_score,
            "anomaly_percentile_0_to_1": alert.anomaly_score,
            "source_ip": clean(alert.source_ip, 45) if alert.source_ip else None,
            "account": alias(alert.username),
        },
        "summary_of_all_evidence": {
            "total_events": len(events),
            "failed_logins": outcomes.count("failure"),
            "successful_logins": outcomes.count("success"),
            "distinct_accounts": len({e.username for e in events if e.username}),
            "distinct_ips": len(ips),
            "first_event_utc": min(stamps).isoformat() if stamps else None,
            "last_event_utc": max(stamps).isoformat() if stamps else None,
            "duration_seconds": duration,
        },
        "event_sample": [
            {
                "time_utc": e.timestamp.isoformat(),
                "outcome": e.outcome,
                "source_ip": clean(e.source_ip, 45) if e.source_ip else None,
                "account": alias(e.username),
                "why_it_matters": scrub_reason(reason),
            }
            for reason, e in sample
        ],
        "events_not_shown": max(0, len(pairs) - len(sample)),
    }
    allowed_ips = set(ips)
    if alert.source_ip:
        allowed_ips.add(alert.source_ip)
    return IncidentRecord(data, allowed_ips, set(aliases.values()))
