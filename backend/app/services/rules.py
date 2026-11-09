"""Deterministic detection rules.

Algorithms lesson: every rule is a *sliding window* over time-ordered events.
Naive approach: for each event, re-scan all earlier events -> O(N^2).
Sliding window: keep a `deque` of events inside the window; each event enters
once and leaves once -> O(N). That is the difference between handling 1,000
events and 1,000,000.

OOP lesson: each rule is a subclass of `Rule` with one method, `evaluate`.
Adding a new rule never requires touching existing ones (open/closed principle).
"""

from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from app.core.config import Settings
from app.models import Event

if TYPE_CHECKING:
    from app.ml.detector import AnomalyDetector
    from app.services.anomaly import AnomalyAnalyzer


def utc(dt: datetime) -> datetime:
    """Treat naive datetimes (SQLite) as UTC and convert aware ones (PostgreSQL) to UTC."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


@dataclass
class Finding:
    """What a rule reports: a suspicious pattern plus the events that prove it."""

    rule_id: str
    title: str
    severity: str  # low | medium | high | critical
    dedup_key: str
    evidence: list[tuple[Event, str]]  # (event, why it matters)
    source_ip: str | None = None
    username: str | None = None
    anomaly_score: float | None = None  # 0-1 percentile from the ML model, when available


class Rule(ABC):
    rule_id: str

    @abstractmethod
    def evaluate(self, events: Sequence[Event]) -> list[Finding]:
        """`events` are sorted oldest -> newest."""


def _login_events(events: Sequence[Event]) -> list[Event]:
    return [e for e in events if e.event_type == "login"]


class FailedLoginBurst(Rule):
    """Many failed logins from one IP in a short window (password guessing / brute force)."""

    rule_id = "failed_login_burst"

    def __init__(self, threshold: int, window: timedelta):
        self.threshold = threshold
        self.window = window

    def evaluate(self, events: Sequence[Event]) -> list[Finding]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for e in _login_events(events):
            if e.outcome == "failure" and e.source_ip:
                by_ip[e.source_ip].append(e)

        findings: list[Finding] = []
        for ip, evs in by_ip.items():
            findings.extend(self._scan(ip, evs))
        return findings

    def _scan(self, ip: str, evs: list[Event]) -> list[Finding]:
        findings: list[Finding] = []
        n, i = len(evs), 0
        while i < n:
            # Slide `lo` forward so evs[lo..j] always fits inside the window.
            lo, trigger = i, None
            for j in range(i, n):
                while utc(evs[j].timestamp) - utc(evs[lo].timestamp) > self.window:
                    lo += 1
                if j - lo + 1 >= self.threshold:
                    trigger = j
                    break
            if trigger is None:
                break

            # Merge the whole attack into ONE alert: keep extending while the
            # attacker keeps going (gap between failures <= window).
            end = trigger
            while end + 1 < n and utc(evs[end + 1].timestamp) - utc(evs[end].timestamp) <= self.window:
                end += 1

            episode = evs[lo : end + 1]
            users = {e.username for e in episode if e.username}
            minutes = max(1, round((utc(episode[-1].timestamp) - utc(episode[0].timestamp)).total_seconds() / 60))
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=f"{len(episode)} failed logins from {ip} over {minutes} min",
                    severity="high" if len(episode) >= 3 * self.threshold else "medium",
                    dedup_key=f"{self.rule_id}:{ip}:{episode[0].fingerprint[:16]}",
                    evidence=[(e, f"Failed login for '{e.username or 'unknown'}' from {ip}") for e in episode],
                    source_ip=ip,
                    username=next(iter(users)) if len(users) == 1 else None,
                )
            )
            i = end + 1
        return findings


class FailureThenSuccess(Rule):
    """A successful login from an IP that just failed repeatedly (possible compromised account)."""

    rule_id = "failure_then_success"

    def __init__(self, threshold: int, window: timedelta):
        self.threshold = threshold
        self.window = window

    def evaluate(self, events: Sequence[Event]) -> list[Finding]:
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for e in _login_events(events):
            if e.source_ip:
                by_ip[e.source_ip].append(e)

        findings: list[Finding] = []
        for ip, evs in by_ip.items():
            recent_failures: deque[Event] = deque()
            for e in evs:
                now = utc(e.timestamp)
                while recent_failures and now - utc(recent_failures[0].timestamp) > self.window:
                    recent_failures.popleft()
                if e.outcome == "failure":
                    recent_failures.append(e)
                elif e.outcome == "success" and len(recent_failures) >= self.threshold:
                    failures = list(recent_failures)
                    evidence = [(f, f"Failed login for '{f.username or 'unknown'}' from {ip}") for f in failures]
                    evidence.append((e, f"Successful login for '{e.username}' from the same IP"))
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Successful login from {ip} after {len(failures)} failed attempts",
                            severity="critical" if len(failures) >= 4 * self.threshold else "high",
                            dedup_key=f"{self.rule_id}:{ip}:{e.fingerprint[:16]}",
                            evidence=evidence,
                            source_ip=ip,
                            username=e.username,
                        )
                    )
                    recent_failures.clear()
        return findings


class MultiIPLogin(Rule):
    """One account used from several different IPs in a short window (shared/stolen credentials)."""

    rule_id = "multi_ip_login"

    def __init__(self, threshold: int, window: timedelta):
        self.threshold = threshold
        self.window = window

    def evaluate(self, events: Sequence[Event]) -> list[Finding]:
        by_user: dict[str, list[Event]] = defaultdict(list)
        for e in _login_events(events):
            if e.username and e.source_ip:
                by_user[e.username].append(e)

        findings: list[Finding] = []
        for user, evs in by_user.items():
            in_window: deque[Event] = deque()
            ip_counts: Counter[str] = Counter()
            for e in evs:
                now = utc(e.timestamp)
                while in_window and now - utc(in_window[0].timestamp) > self.window:
                    old = in_window.popleft()
                    ip_counts[old.source_ip] -= 1
                    if ip_counts[old.source_ip] == 0:
                        del ip_counts[old.source_ip]
                in_window.append(e)
                ip_counts[e.source_ip] += 1

                if len(ip_counts) >= self.threshold:
                    episode = list(in_window)
                    any_success = any(x.outcome == "success" for x in episode)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"'{user}' used from {len(ip_counts)} different IPs within "
                            f"{int(self.window.total_seconds() // 60)} min",
                            # Successful access from many places is more concerning than failures alone.
                            severity="high" if any_success else "medium",
                            dedup_key=f"{self.rule_id}:{user}:{episode[0].fingerprint[:16]}",
                            evidence=[(x, f"Login {x.outcome} from {x.source_ip}") for x in episode],
                            username=user,
                        )
                    )
                    in_window.clear()
                    ip_counts.clear()
        return findings


class RuleEngine:
    """Runs every rule over a batch of events and collects the findings."""

    def __init__(self, rules: Sequence[Rule], anomaly: "AnomalyAnalyzer | None" = None):
        self.rules = list(rules)
        self.anomaly = anomaly

    @classmethod
    def from_settings(cls, s: Settings, detector: "AnomalyDetector | None" = None) -> "RuleEngine":
        from app.services.anomaly import (
            AnomalyAnalyzer,  # local import: keeps rules.py importable without ML libs
        )

        return cls(
            [
                FailedLoginBurst(s.burst_threshold, timedelta(minutes=s.burst_window_minutes)),
                FailureThenSuccess(
                    s.fail_then_success_threshold, timedelta(minutes=s.fail_then_success_window_minutes)
                ),
                MultiIPLogin(s.multi_ip_threshold, timedelta(minutes=s.multi_ip_window_minutes)),
            ],
            anomaly=AnomalyAnalyzer(detector) if detector else None,
        )

    def run(self, events: Sequence[Event]) -> list[Finding]:
        ordered = sorted(events, key=lambda e: (utc(e.timestamp), e.id or 0))
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(ordered))
        if self.anomaly:
            findings = self.anomaly.apply(ordered, findings)
        return findings
