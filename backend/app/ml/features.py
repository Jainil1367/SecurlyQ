"""Feature engineering: raw login events -> one numeric row per (source IP, 10-minute bucket).

Data-science lesson: models don't understand "events", they understand tables of
numbers. Choosing *what one row represents* is the most important modeling decision.
We chose "one source IP during one 10-minute window" because that is the unit an
analyst reasons about ("what was 203.0.113.9 doing at 03:00?").

Each feature answers a question a human analyst would ask:
    n_events         how busy was this IP?
    n_failures       how many logins failed?
    failure_ratio    what fraction failed? (busy-but-successful offices are normal)
    n_users          how many different accounts did it touch? (credential stuffing)
    n_success        how many succeeded?
    max_per_minute   how bursty was it? (machines are faster than people)
    hour_sin/cos     what time of day? (encoded on a circle so 23:50 is near 00:10)
    user_ip_spread   did any account it touched also appear from other IPs? (takeover)
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import numpy as np
import pandas as pd

from app.models import Event

BUCKET_SECONDS = 600

FEATURES = [
    "n_events",
    "n_failures",
    "failure_ratio",
    "n_users",
    "n_success",
    "max_per_minute",
    "hour_sin",
    "hour_cos",
    "user_ip_spread",
]


FEATURE_LABELS = {
    "n_events": "login attempts",
    "n_failures": "failed logins",
    "failure_ratio": "failure ratio",
    "n_users": "distinct accounts targeted",
    "n_success": "successful logins",
    "max_per_minute": "peak attempts per minute",
    "user_ip_spread": "IPs sharing a targeted account",
}


def bucket_of(timestamp: datetime) -> int:
    """Start of the 10-minute bucket (epoch seconds, UTC) containing `timestamp`.

    Naive datetimes (SQLite) are treated as UTC; aware ones (PostgreSQL) are converted.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return int(timestamp.timestamp()) // BUCKET_SECONDS * BUCKET_SECONDS


def events_to_frame(events: Sequence[Event]) -> pd.DataFrame:
    """Keep only login events that have a source IP; return a plain DataFrame."""
    rows = [
        {
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "username": e.username,
            "outcome": e.outcome,
        }
        for e in events
        if e.event_type == "login" and e.source_ip
    ]
    return pd.DataFrame(rows, columns=["timestamp", "source_ip", "username", "outcome"])


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate a login-event frame into the feature table.

    Input columns: timestamp, source_ip, username, outcome.
    Output columns: source_ip, bucket (epoch seconds), plus every name in FEATURES.
    """
    columns = ["source_ip", "bucket", *FEATURES]
    if df.empty:
        return pd.DataFrame(columns=columns)

    d = df.copy()
    ts = pd.to_datetime(d["timestamp"], utc=True)
    epoch = (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().astype("int64")
    d["bucket"] = (epoch // BUCKET_SECONDS) * BUCKET_SECONDS
    d["minute"] = epoch // 60
    d["is_failure"] = (d["outcome"] == "failure").astype(int)
    d["is_success"] = (d["outcome"] == "success").astype(int)

    # How many distinct IPs did each account use in the same bucket?
    spread = (
        d.dropna(subset=["username"])
        .groupby(["bucket", "username"])["source_ip"]
        .nunique()
        .rename("user_ip_spread")
        .reset_index()
    )
    d = d.merge(spread, on=["bucket", "username"], how="left")
    d["user_ip_spread"] = d["user_ip_spread"].fillna(1)

    keys = ["source_ip", "bucket"]
    base = d.groupby(keys).agg(
        n_events=("outcome", "size"),
        n_failures=("is_failure", "sum"),
        n_success=("is_success", "sum"),
        n_users=("username", "nunique"),
        user_ip_spread=("user_ip_spread", "max"),
    )
    per_minute = d.groupby([*keys, "minute"]).size().groupby(level=keys).max().rename("max_per_minute")
    out = base.join(per_minute).reset_index()

    out["failure_ratio"] = out["n_failures"] / out["n_events"]
    hour = (out["bucket"] % 86_400) / 3_600.0
    out["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    out["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    return out[columns].sort_values(["bucket", "source_ip"]).reset_index(drop=True)
