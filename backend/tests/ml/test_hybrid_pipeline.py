"""The model wired into the real alert pipeline (database + API)."""

import copy

import pytest

from app.core.config import get_settings
from app.ml import runtime
from app.schemas.event import EventIn
from app.services.ingestion import EventIngestionService
from tests.conftest import make_event

TUNED_THRESHOLD = 0.9  # like production, the threshold is tuned on validation data, not left at 0.99


@pytest.fixture()
def model_path(trained_detector, tmp_path, monkeypatch):
    path = tmp_path / "model.joblib"
    tuned = copy.copy(trained_detector)  # don't mutate the session-wide fixture
    tuned.threshold = TUNED_THRESHOLD
    tuned.save(path)
    monkeypatch.setattr(get_settings(), "anomaly_model_path", str(path))
    runtime.clear_cache()
    return path


def ingest_dataset(db, df):
    events = [
        EventIn(
            source=r.source, event_type=r.event_type, timestamp=r.timestamp.to_pydatetime(),
            outcome=r.outcome, source_ip=r.source_ip, username=r.username,
        )
        for r in df.itertuples(index=False)
    ]
    for i in range(0, len(events), 1000):
        EventIngestionService(db).ingest(events[i : i + 1000])


def window(df):
    return {"since": df.timestamp.min().isoformat(), "until": (df.timestamp.max()).isoformat()}


def test_without_a_model_alerts_have_no_anomaly_score(analyst_client):
    analyst_client.post("/api/v1/events", json=[make_event(outcome="failure", timestamp=f"2026-10-28T12:00:{i:02d}Z") for i in range(12)])
    result = analyst_client.post("/api/v1/analysis/run", json={"since": "2026-10-28T00:00:00Z", "until": "2026-10-29T00:00:00Z"}).json()
    assert result["anomaly_model"] is None and result["alerts_created"] >= 1
    assert all(a["anomaly_score"] is None for a in analyst_client.get("/api/v1/alerts").json()["items"])


def test_corrupt_model_falls_back_to_rules_only(analyst_client, trained_detector, tmp_path, monkeypatch):
    path = tmp_path / "bad.joblib"
    trained_detector.save(path)
    path.write_bytes(b"garbage")
    monkeypatch.setattr(get_settings(), "anomaly_model_path", str(path))
    runtime.clear_cache()
    result = analyst_client.post("/api/v1/analysis/run", json={}).json()
    assert result["anomaly_model"] is None  # analysis still works


def test_model_enriches_rule_alerts_and_finds_extra_activity(analyst_client, db_session, quick_data, model_path):
    test_df = quick_data["test"]
    ingest_dataset(db_session, test_df)

    result = analyst_client.post("/api/v1/analysis/run", json=window(test_df)).json()
    assert result["anomaly_model"] == "isolation-forest-v1"

    alerts = analyst_client.get("/api/v1/alerts", params={"limit": 200}).json()["items"]
    rule_alerts = [a for a in alerts if a["rule_id"] != "anomaly_isolation_forest"]
    model_alerts = [a for a in alerts if a["rule_id"] == "anomaly_isolation_forest"]

    assert rule_alerts and any(a["anomaly_score"] is not None for a in rule_alerts)  # enriched
    assert model_alerts, "the model should surface activity that no rule covers"
    assert all(a["anomaly_score"] >= TUNED_THRESHOLD for a in model_alerts)  # only unusual-enough buckets alert
    assert all(0 <= a["anomaly_score"] <= 1 for a in alerts if a["anomaly_score"] is not None)


def test_model_alert_has_human_readable_evidence_reason(analyst_client, db_session, quick_data, model_path):
    ingest_dataset(db_session, quick_data["test"])
    analyst_client.post("/api/v1/analysis/run", json=window(quick_data["test"]))
    alerts = analyst_client.get("/api/v1/alerts", params={"limit": 200}).json()["items"]
    model_alert = next(a for a in alerts if a["rule_id"] == "anomaly_isolation_forest")
    detail = analyst_client.get(f"/api/v1/alerts/{model_alert['id']}").json()
    assert detail["evidence"], "model alerts must be traceable to events"
    reason = detail["evidence"][0]["reason"]
    assert "σ" in reason and "training behaviour" in reason


def test_rerunning_with_model_is_idempotent(analyst_client, db_session, quick_data, model_path):
    ingest_dataset(db_session, quick_data["test"])
    first = analyst_client.post("/api/v1/analysis/run", json=window(quick_data["test"])).json()
    second = analyst_client.post("/api/v1/analysis/run", json=window(quick_data["test"])).json()
    assert first["alerts_created"] > 0 and second["alerts_created"] == 0


def test_anomaly_score_raises_risk_score(model_path):
    from app.services.risk import RiskScorer
    from app.services.rules import Finding

    plain = Finding("r", "t", "medium", "k", [])
    boosted = Finding("r", "t", "medium", "k", [], anomaly_score=1.0)
    assert RiskScorer().score(boosted) == RiskScorer().score(plain) + 10.0
