"""Synthetic labeled login traffic: realistic normal behaviour plus five attack scenarios.

Honest framing (put this in every report): synthetic data lets us *develop and test*
the pipeline and measure relative differences between approaches. It cannot prove
real-world accuracy, because we wrote both the attacks and the detectors.

Leakage lesson: if the same attacker IP (or the same hour of data) appears in both the
training and test sets, the model can "memorize" instead of generalize and the score
looks better than reality. `simulate_dataset` therefore builds train/validation/test
from *consecutive, non-overlapping days* with *disjoint attacker IP pools*.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import numpy as np
import pandas as pd

SCENARIOS = ["brute_force", "credential_stuffing", "compromise", "low_and_slow", "multi_ip_takeover"]
SCENARIO_WEIGHTS = [0.30, 0.20, 0.20, 0.15, 0.15]

OFFICE_IPS = [f"10.200.0.{i}" for i in range(1, 5)]  # shared NAT: many users, one IP
SERVICE_ACCOUNT = ("svc-backup", "10.0.9.9")


@dataclass(frozen=True)
class SimConfig:
    seed: int
    start: datetime  # midnight UTC of the first simulated day
    days: int
    attacker_ips: tuple[str, ...]
    n_users: int = 60
    attacks_per_day: float = 3.0


def attacker_pool(prefix: str, size: int = 40) -> tuple[str, ...]:
    return tuple(f"{prefix}.{i}" for i in range(10, 10 + size))


def _usernames(n: int) -> list[str]:
    return [f"user{i:03d}" for i in range(n)]


def _ev(ts: datetime, ip: str, user: str, outcome: str, attack: str = "") -> dict:
    return {
        "timestamp": ts,
        "source": "auth-service",
        "event_type": "login",
        "outcome": outcome,
        "source_ip": ip,
        "username": user,
        "is_attack": bool(attack),
        "scenario": attack,
        "incident_id": -1,  # filled in by simulate() for attack events
    }


# ---------------------------------------------------------------- normal behaviour


def _normal_day(rng: np.random.Generator, day: datetime, users: list[str], homes: dict[str, str]) -> list[dict]:
    events: list[dict] = []
    weekend = day.weekday() >= 5
    for user in users:
        if weekend and rng.random() > 0.3:
            continue
        for _ in range(int(rng.integers(1, 4))):
            hour = float(np.clip(rng.normal(14.0, 2.5), 0, 23.9))  # ~9am US-Eastern in UTC
            ts = day + timedelta(hours=hour)
            ip = homes[user]
            if rng.random() < 0.05:  # a second, legitimate device or network (phone)
                ip = f"10.{int(rng.integers(100, 150))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 255))}"
            if rng.random() < 0.03:
                # Benign hard negative: forgot the password, 3-6 failures, then success.
                for k in range(int(rng.integers(3, 7))):
                    events.append(_ev(ts + timedelta(seconds=25 * k), ip, user, "failure"))
                ts += timedelta(seconds=160)
            events.append(_ev(ts, ip, user, "failure" if rng.random() < 0.04 else "success"))

    # A service account logs in every 5 minutes, all day: high volume, perfectly regular.
    svc_user, svc_ip = SERVICE_ACCOUNT
    for k in range(288):
        events.append(_ev(day + timedelta(minutes=5 * k), svc_ip, svc_user, "success"))
    return events


# ---------------------------------------------------------------------- attacks


def _times(rng, t0: datetime, n: int, minutes: float) -> list[datetime]:
    offsets = np.sort(rng.uniform(0, minutes * 60, size=n))
    return [t0 + timedelta(seconds=float(s)) for s in offsets]


def _brute_force(rng, t0, ip, users, pool):
    targets = list(rng.choice(users, size=int(rng.integers(1, 4)), replace=False))
    n = int(rng.integers(15, 200))
    return [_ev(t, ip, str(rng.choice(targets)), "failure", "brute_force") for t in _times(rng, t0, n, rng.uniform(2, 15))]


def _credential_stuffing(rng, t0, ip, users, pool):
    names = list(rng.choice(users, size=int(rng.integers(15, 55)), replace=False))
    times = _times(rng, t0, len(names) * 2, rng.uniform(1, 6))
    events = [
        _ev(t, ip, str(names[i // 2]), "success" if rng.random() < 0.01 else "failure", "credential_stuffing")
        for i, t in enumerate(times)
    ]
    return events


def _compromise(rng, t0, ip, users, pool):
    victim = str(rng.choice(users))
    n = int(rng.integers(6, 30))
    times = _times(rng, t0, n, rng.uniform(1, 6))
    events = [_ev(t, ip, victim, "failure", "compromise") for t in times]
    events.append(_ev(times[-1] + timedelta(seconds=float(rng.uniform(5, 60))), ip, victim, "success", "compromise"))
    return events


def _low_and_slow(rng, t0, ip, users, pool):
    """Deliberately stealthy: one attempt every few minutes. Rules with a 5-minute window miss it."""
    events, t = [], t0
    for _ in range(int(rng.integers(20, 40))):
        events.append(_ev(t, ip, str(rng.choice(users)), "failure", "low_and_slow"))
        t += timedelta(minutes=float(rng.uniform(3, 6)))
    return events


def _multi_ip_takeover(rng, t0, ip, users, pool):
    victim = str(rng.choice(users))
    ips = [ip, *[str(x) for x in rng.choice(pool, size=int(rng.integers(2, 5)), replace=False)]]
    events = []
    for k, attacker_ip in enumerate(ips):
        for t in _times(rng, t0 + timedelta(minutes=6 * k), int(rng.integers(1, 4)), 4):
            events.append(_ev(t, attacker_ip, victim, "success" if rng.random() < 0.4 else "failure", "multi_ip_takeover"))
    return events


_BUILDERS = {
    "brute_force": _brute_force,
    "credential_stuffing": _credential_stuffing,
    "compromise": _compromise,
    "low_and_slow": _low_and_slow,
    "multi_ip_takeover": _multi_ip_takeover,
}


def simulate(cfg: SimConfig) -> pd.DataFrame:
    """Return events with columns: timestamp, source, event_type, outcome, source_ip, username,
    is_attack, scenario, incident_id. Sorted by time. The label columns never go to the production API."""
    rng = np.random.default_rng(cfg.seed)
    users = _usernames(cfg.n_users)
    n_office = cfg.n_users // 3
    homes = {
        u: OFFICE_IPS[i % len(OFFICE_IPS)] if i < n_office else f"10.{10 + i}.{i % 250}.{(i * 7) % 250 + 1}"
        for i, u in enumerate(users)
    }

    events: list[dict] = []
    incident_id = 0
    for d in range(cfg.days):
        day = cfg.start + timedelta(days=d)
        events += _normal_day(rng, day, users, homes)
        for _ in range(int(rng.poisson(cfg.attacks_per_day))):
            scenario = str(rng.choice(SCENARIOS, p=SCENARIO_WEIGHTS))
            # Attackers favour the night: 60% between 00:00 and 10:00 UTC.
            hour = rng.uniform(0, 10) if rng.random() < 0.6 else rng.uniform(10, 23)
            t0 = day + timedelta(hours=float(hour))
            ip = str(rng.choice(cfg.attacker_ips))
            attack_events = _BUILDERS[scenario](rng, t0, ip, users, cfg.attacker_ips)
            for e in attack_events:
                e["incident_id"] = incident_id  # lets us ask "was each attack detected at least once?"
            incident_id += 1
            events += attack_events

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def simulate_dataset(seed: int = 7, quick: bool = False) -> dict[str, pd.DataFrame]:
    """Chronological train / validation / test splits with disjoint attacker IPs."""
    day_counts = {"train": 8, "val": 3, "test": 4} if quick else {"train": 28, "val": 10, "test": 14}
    pools = {
        "train": attacker_pool("198.51.100") + attacker_pool("203.0.113"),
        "val": attacker_pool("192.0.2"),
        "test": attacker_pool("100.64.7"),
    }
    start = datetime(2026, 9, 1, tzinfo=UTC)
    out = {}
    for offset, name in enumerate(["train", "val", "test"]):
        out[name] = simulate(SimConfig(seed=seed * 100 + offset, start=start, days=day_counts[name], attacker_ips=pools[name]))
        start += timedelta(days=day_counts[name])
    return out
