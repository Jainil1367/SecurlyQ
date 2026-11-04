"""Rule-engine unit tests. No database or HTTP: rules are plain functions of events."""

import hashlib
from datetime import UTC, datetime, timedelta

from app.models import Event
from app.services.risk import RiskScorer
from app.services.rules import (
    FailedLoginBurst,
    FailureThenSuccess,
    Finding,
    MultiIPLogin,
    RuleEngine,
)

BASE = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
_counter = iter(range(1, 10_000_000))


def ev(at: timedelta, ip="203.0.113.9", user="alice", outcome="failure", event_type="login") -> Event:
    i = next(_counter)
    return Event(
        id=i,
        fingerprint=hashlib.sha256(str(i).encode()).hexdigest(),
        source="test",
        event_type=event_type,
        outcome=outcome,
        timestamp=BASE + at,
        source_ip=ip,
        username=user,
        attributes={},
    )


def secs(n):
    return timedelta(seconds=n)


def mins(n):
    return timedelta(minutes=n)


# ---- FailedLoginBurst -----------------------------------------------------------


def burst():
    return FailedLoginBurst(threshold=10, window=mins(5))


def test_burst_below_threshold_is_quiet():
    assert burst().evaluate([ev(secs(10 * i)) for i in range(9)]) == []


def test_burst_at_threshold_alerts_once():
    findings = burst().evaluate([ev(secs(10 * i)) for i in range(10)])
    assert len(findings) == 1
    f = findings[0]
    assert (f.rule_id, f.severity, f.source_ip, f.username) == ("failed_login_burst", "medium", "203.0.113.9", "alice")
    assert len(f.evidence) == 10


def test_slow_failures_outside_window_do_not_alert():
    # 10 failures but only ~6 ever fall inside any 5-minute window
    assert burst().evaluate([ev(mins(i)) for i in range(10)]) == []


def test_long_attack_is_one_high_severity_alert_not_many():
    findings = burst().evaluate([ev(secs(10 * i)) for i in range(35)])
    assert len(findings) == 1
    assert findings[0].severity == "high" and len(findings[0].evidence) == 35


def test_separate_attacks_get_separate_alerts_and_keys():
    events = [ev(secs(10 * i)) for i in range(10)] + [ev(mins(60) + secs(10 * i)) for i in range(10)]
    findings = burst().evaluate(events)
    assert len(findings) == 2
    assert findings[0].dedup_key != findings[1].dedup_key


def test_failures_are_counted_per_ip():
    events = []
    for i in range(6):
        events += [ev(secs(10 * i), ip="203.0.113.1"), ev(secs(10 * i + 1), ip="203.0.113.2")]
    assert burst().evaluate(events) == []  # 6 + 6, never 10 from one source


def test_multiple_target_users_leaves_username_empty():
    events = [ev(secs(5 * i), user=f"user{i % 3}") for i in range(12)]
    assert burst().evaluate(events)[0].username is None


def test_non_login_and_successful_events_ignored_by_burst():
    events = [ev(secs(i), event_type="file_access") for i in range(20)]
    events += [ev(secs(i), outcome="success") for i in range(20)]
    assert burst().evaluate(events) == []


# ---- FailureThenSuccess ---------------------------------------------------------


def fts():
    return FailureThenSuccess(threshold=5, window=mins(15))


def test_success_after_failures_is_high():
    events = [ev(secs(10 * i)) for i in range(5)] + [ev(secs(100), outcome="success")]
    findings = fts().evaluate(events)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high" and f.username == "alice"
    assert len(f.evidence) == 6
    assert f.evidence[-1][0].outcome == "success"  # the success is the last piece of evidence


def test_too_few_failures_before_success_is_quiet():
    events = [ev(secs(10 * i)) for i in range(4)] + [ev(secs(100), outcome="success")]
    assert fts().evaluate(events) == []


def test_many_failures_before_success_is_critical():
    events = [ev(secs(5 * i)) for i in range(20)] + [ev(secs(200), outcome="success")]
    assert fts().evaluate(events)[0].severity == "critical"


def test_stale_failures_do_not_count():
    events = [ev(secs(10 * i)) for i in range(5)] + [ev(mins(16) + secs(50), outcome="success")]
    assert fts().evaluate(events) == []


def test_success_from_a_different_ip_is_not_correlated():
    events = [ev(secs(10 * i), ip="203.0.113.1") for i in range(8)] + [
        ev(secs(100), ip="203.0.113.2", outcome="success")
    ]
    assert fts().evaluate(events) == []


def test_second_success_does_not_realert():
    events = [ev(secs(10 * i)) for i in range(6)] + [
        ev(secs(100), outcome="success"),
        ev(secs(110), outcome="success"),
    ]
    assert len(fts().evaluate(events)) == 1


# ---- MultiIPLogin ---------------------------------------------------------------


def multi():
    return MultiIPLogin(threshold=3, window=mins(60))


def test_three_ips_in_window_is_medium():
    events = [ev(mins(10 * i), ip=f"198.51.100.{i}") for i in range(3)]
    findings = multi().evaluate(events)
    assert len(findings) == 1 and findings[0].severity == "medium"


def test_multi_ip_with_a_success_is_high():
    events = [ev(mins(10 * i), ip=f"198.51.100.{i}", outcome="success" if i == 1 else "failure") for i in range(3)]
    assert multi().evaluate(events)[0].severity == "high"


def test_same_ip_repeated_is_quiet():
    assert multi().evaluate([ev(mins(i), ip="198.51.100.1") for i in range(10)]) == []


def test_ips_spread_over_hours_are_quiet():
    events = [ev(mins(100 * i), ip=f"198.51.100.{i}") for i in range(3)]
    assert multi().evaluate(events) == []


# ---- RuleEngine & RiskScorer ----------------------------------------------------


def engine():
    return RuleEngine([burst(), fts(), multi()])


def attack_events():
    return [ev(secs(10 * i)) for i in range(12)] + [ev(secs(150), outcome="success")]


def test_engine_runs_all_rules_and_handles_unsorted_input():
    events = attack_events()
    findings = engine().run(list(reversed(events)))
    assert {f.rule_id for f in findings} == {"failed_login_burst", "failure_then_success"}


def test_dedup_keys_are_stable_across_runs():
    events = attack_events()
    first = sorted(f.dedup_key for f in engine().run(events))
    second = sorted(f.dedup_key for f in engine().run(list(reversed(events))))
    assert first == second


def test_benign_activity_produces_no_findings():
    events = [ev(mins(30 * i), outcome="success", user="alice", ip="198.51.100.5") for i in range(10)]
    assert engine().run(events) == []


def test_risk_score_orders_by_severity_and_is_capped():
    scorer = RiskScorer()

    def f(sev, n):
        return Finding("r", "t", sev, "k", [(ev(secs(i)), "x") for i in range(n)])

    assert scorer.score(f("low", 2)) < scorer.score(f("medium", 2)) < scorer.score(f("high", 2))
    assert scorer.score(f("high", 2)) < scorer.score(f("critical", 2))
    assert scorer.score(f("critical", 500)) <= 100.0
    assert scorer.score(f("medium", 40)) == 60.0  # evidence bonus is capped at +10
