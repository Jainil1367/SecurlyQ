from tests.conftest import make_event

WINDOW = {"since": "2026-10-28T00:00:00Z", "until": "2026-10-29T00:00:00Z"}


def attack_batch(ip="203.0.113.9", user="alice", failures=12):
    """N failed logins 10s apart, then a success from the same IP."""
    events = [
        make_event(
            source_ip=ip, username=user, outcome="failure", timestamp=f"2026-10-28T12:{(i * 10) // 60:02d}:{(i * 10) % 60:02d}Z"
        )
        for i in range(failures)
    ]
    events.append(make_event(source_ip=ip, username=user, outcome="success", timestamp="2026-10-28T12:05:00Z"))
    return events


def seed_attack(client):
    assert client.post("/api/v1/events", json=attack_batch()).status_code == 201
    resp = client.post("/api/v1/analysis/run", json=WINDOW)
    assert resp.status_code == 200
    return resp.json()


def test_analysis_creates_alerts_with_evidence(analyst_client):
    result = seed_attack(analyst_client)
    assert result["events_scanned"] == 13
    assert result["alerts_created"] == 2

    page = analyst_client.get("/api/v1/alerts").json()
    assert page["total"] == 2
    top = page["items"][0]  # highest risk first
    assert top["rule_id"] == "failure_then_success"
    assert top["severity"] == "high" and top["risk_score"] == 81.5
    assert top["evidence_count"] == 13
    assert top["status"] == "open" and top["source_ip"] == "203.0.113.9"


def test_rerunning_analysis_does_not_duplicate_alerts(analyst_client):
    seed_attack(analyst_client)
    again = analyst_client.post("/api/v1/analysis/run", json=WINDOW).json()
    assert again["findings"] == 2 and again["alerts_created"] == 0
    assert analyst_client.get("/api/v1/alerts").json()["total"] == 2


def test_benign_traffic_creates_no_alerts(analyst_client):
    analyst_client.post(
        "/api/v1/events",
        json=[make_event(outcome="success", timestamp=f"2026-10-28T1{i}:00:00Z") for i in range(5)],
    )
    result = analyst_client.post("/api/v1/analysis/run", json=WINDOW).json()
    assert result["alerts_created"] == 0


def test_alert_detail_has_ordered_evidence_and_reasons(analyst_client):
    seed_attack(analyst_client)
    alert = next(a for a in analyst_client.get("/api/v1/alerts").json()["items"] if a["rule_id"] == "failure_then_success")
    detail = analyst_client.get(f"/api/v1/alerts/{alert['id']}").json()
    stamps = [e["event"]["timestamp"] for e in detail["evidence"]]
    assert stamps == sorted(stamps)
    assert detail["evidence"][-1]["event"]["outcome"] == "success"
    assert "same IP" in detail["evidence"][-1]["reason"]
    assert detail["investigation_notes"] == [] and detail["explanation"] is None


def test_missing_alert_is_404(analyst_client):
    assert analyst_client.get("/api/v1/alerts/999").status_code == 404
    assert analyst_client.patch("/api/v1/alerts/999", json={"status": "resolved"}).status_code == 404


def test_acknowledge_sets_timestamp_and_reopen_clears_it(analyst_client):
    seed_attack(analyst_client)
    alert_id = analyst_client.get("/api/v1/alerts").json()["items"][0]["id"]

    acked = analyst_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "acknowledged"}).json()
    assert acked["status"] == "acknowledged" and acked["acknowledged_at"] is not None

    first_ack = acked["acknowledged_at"]
    resolved = analyst_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "resolved"}).json()
    assert resolved["acknowledged_at"] == first_ack  # first response time is preserved

    reopened = analyst_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "open"}).json()
    assert reopened["acknowledged_at"] is None


def test_invalid_status_rejected(analyst_client):
    seed_attack(analyst_client)
    alert_id = analyst_client.get("/api/v1/alerts").json()["items"][0]["id"]
    assert analyst_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "deleted"}).status_code == 422


def test_notes_are_recorded_with_author(analyst_client):
    seed_attack(analyst_client)
    alert_id = analyst_client.get("/api/v1/alerts").json()["items"][0]["id"]
    resp = analyst_client.post(f"/api/v1/alerts/{alert_id}/notes", json={"notes": "  Checked with the user.  "})
    assert resp.status_code == 201 and resp.json()["notes"] == "Checked with the user."
    notes = analyst_client.get(f"/api/v1/alerts/{alert_id}").json()["investigation_notes"]
    assert [n["author_email"] for n in notes] == ["analyst@example.com"]
    assert analyst_client.post(f"/api/v1/alerts/{alert_id}/notes", json={"notes": "   "}).status_code == 422


def test_filters_by_status_severity_and_min_risk(analyst_client):
    seed_attack(analyst_client)
    items = analyst_client.get("/api/v1/alerts").json()["items"]
    analyst_client.patch(f"/api/v1/alerts/{items[0]['id']}", json={"status": "resolved"})

    assert analyst_client.get("/api/v1/alerts", params={"status": "open"}).json()["total"] == 1
    assert analyst_client.get("/api/v1/alerts", params={"severity": "high"}).json()["total"] == 1
    assert analyst_client.get("/api/v1/alerts", params={"min_risk": 80}).json()["total"] == 1
    assert analyst_client.get("/api/v1/alerts", params={"source_ip": "198.51.100.1"}).json()["total"] == 0
    assert analyst_client.get("/api/v1/alerts", params={"status": "bogus"}).status_code == 422


def test_summary_aggregates(analyst_client):
    analyst_client.post("/api/v1/events", json=attack_batch())
    analyst_client.post("/api/v1/events", json=attack_batch(ip="198.51.100.77", user="bob", failures=11))
    analyst_client.post("/api/v1/analysis/run", json=WINDOW)

    alert_id = analyst_client.get("/api/v1/alerts").json()["items"][0]["id"]
    analyst_client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "acknowledged"})

    s = analyst_client.get("/api/v1/alerts/summary").json()
    assert s["total_alerts"] == 4
    assert s["by_status"] == {"open": 3, "acknowledged": 1}
    assert sum(s["open_by_severity"].values()) == 3
    assert {row["source_ip"] for row in s["top_source_ips"]} == {"203.0.113.9", "198.51.100.77"}
    assert all(row["alerts"] == 2 for row in s["top_source_ips"])
    assert s["mean_time_to_acknowledge_seconds"] is not None


def test_summary_on_empty_database(analyst_client):
    s = analyst_client.get("/api/v1/alerts/summary").json()
    assert s["total_alerts"] == 0 and s["mean_time_to_acknowledge_seconds"] is None


def test_permissions(viewer_client, db_session):
    assert viewer_client.get("/api/v1/alerts").status_code == 200
    assert viewer_client.get("/api/v1/alerts/summary").status_code == 200
    assert viewer_client.post("/api/v1/analysis/run").status_code == 403
    assert viewer_client.patch("/api/v1/alerts/1", json={"status": "resolved"}).status_code == 403
    assert viewer_client.post("/api/v1/alerts/1/notes", json={"notes": "x"}).status_code == 403


def test_unauthenticated_alert_access_rejected(client):
    for path in ("/api/v1/alerts", "/api/v1/alerts/summary", "/api/v1/alerts/1"):
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/analysis/run").status_code == 401


def test_analysis_window_validation(analyst_client):
    bad = analyst_client.post(
        "/api/v1/analysis/run", json={"since": "2026-10-29T00:00:00Z", "until": "2026-10-28T00:00:00Z"}
    )
    assert bad.status_code == 422


def test_analysis_refuses_oversized_window(analyst_client, monkeypatch):
    from app.core.config import get_settings

    analyst_client.post("/api/v1/events", json=attack_batch())
    monkeypatch.setattr(get_settings(), "max_analysis_events", 5)
    assert analyst_client.post("/api/v1/analysis/run", json=WINDOW).status_code == 413
