from datetime import UTC, datetime

import pandas as pd
import pytest

from app.ml.features import BUCKET_SECONDS, FEATURES, bucket_of, build_features


def frame(rows):
    return pd.DataFrame(rows, columns=["timestamp", "source_ip", "username", "outcome"])


def t(minute, second=0):
    return datetime(2026, 10, 28, 12, minute, second, tzinfo=UTC)


def test_bucket_alignment_and_naive_timestamps():
    assert bucket_of(t(0)) == bucket_of(t(9, 59))
    assert bucket_of(t(10)) == bucket_of(t(0)) + BUCKET_SECONDS
    assert bucket_of(datetime(2026, 10, 28, 12, 5)) == bucket_of(t(5))  # naive == UTC


def test_features_for_a_brute_force_bucket():
    rows = [(t(1, s), "203.0.113.9", "alice", "failure") for s in range(0, 40, 10)]
    rows.append((t(2), "203.0.113.9", "alice", "success"))
    f = build_features(frame(rows))
    assert len(f) == 1
    r = f.iloc[0]
    assert (r.n_events, r.n_failures, r.n_success, r.n_users) == (5, 4, 1, 1)
    assert r.failure_ratio == pytest.approx(0.8)
    assert r.max_per_minute == 4  # four attempts inside minute :01


def test_one_row_per_ip_and_bucket():
    rows = [
        (t(1), "1.1.1.1", "a", "success"),
        (t(2), "2.2.2.2", "b", "success"),
        (t(12), "1.1.1.1", "a", "success"),
    ]
    assert len(build_features(frame(rows))) == 3


def test_user_ip_spread_detects_shared_account():
    rows = [(t(1), "1.1.1.1", "victim", "failure"), (t(2), "2.2.2.2", "victim", "success"), (t(3), "3.3.3.3", "victim", "failure")]
    f = build_features(frame(rows))
    assert set(f["user_ip_spread"]) == {3}


def test_hour_encoding_is_circular():
    late = build_features(frame([(datetime(2026, 10, 28, 23, 55, tzinfo=UTC), "1.1.1.1", "a", "success")])).iloc[0]
    early = build_features(frame([(datetime(2026, 10, 29, 0, 5, tzinfo=UTC), "1.1.1.1", "a", "success")])).iloc[0]
    assert abs(late.hour_cos - early.hour_cos) < 0.05 and abs(late.hour_sin - early.hour_sin) < 0.3


def test_empty_input_gives_empty_feature_table():
    f = build_features(frame([]))
    assert f.empty and set(FEATURES) <= set(f.columns)
