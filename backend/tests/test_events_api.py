from tests.conftest import make_event


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_ready_checks_database(client):
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_ingest_stores_events(client):
    resp = client.post("/api/v1/events", json=[make_event(), make_event(source_ip="198.51.100.4")])
    assert resp.status_code == 201
    assert resp.json() == {"received": 2, "accepted": 2, "duplicates": 0}
    assert client.get("/api/v1/events").json()["total"] == 2


def test_duplicates_within_batch_are_dropped(client):
    resp = client.post("/api/v1/events", json=[make_event(), make_event()])
    assert resp.json() == {"received": 2, "accepted": 1, "duplicates": 1}


def test_duplicates_across_requests_are_dropped(client):
    client.post("/api/v1/events", json=[make_event()])
    resp = client.post("/api/v1/events", json=[make_event(), make_event(username="bob")])
    assert resp.json() == {"received": 2, "accepted": 1, "duplicates": 1}


def test_invalid_event_returns_422_and_stores_nothing(client):
    resp = client.post("/api/v1/events", json=[make_event(), make_event(source_ip="nope")])
    assert resp.status_code == 422
    assert client.get("/api/v1/events").json()["total"] == 0


def test_empty_batch_rejected(client):
    assert client.post("/api/v1/events", json=[]).status_code == 422


def test_oversized_batch_rejected(client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_batch_size", 2)
    batch = [make_event(source_ip=f"203.0.113.{i}") for i in range(3)]
    assert client.post("/api/v1/events", json=batch).status_code == 413


def test_filters_and_pagination(client):
    batch = [
        make_event(timestamp=f"2026-10-28T12:0{i}:00Z", source_ip="203.0.113.7") for i in range(5)
    ] + [make_event(event_type="logout", outcome="success", source_ip="198.51.100.4")]
    client.post("/api/v1/events", json=batch)

    by_ip = client.get("/api/v1/events", params={"source_ip": "203.0.113.7"}).json()
    assert by_ip["total"] == 5

    by_type = client.get("/api/v1/events", params={"event_type": "logout"}).json()
    assert by_type["total"] == 1

    page = client.get("/api/v1/events", params={"limit": 2, "offset": 0}).json()
    assert len(page["items"]) == 2 and page["total"] == 6

    by_user = client.get("/api/v1/events", params={"username": "ALICE"}).json()
    assert by_user["total"] == 6  # username lookups are case-insensitive


def test_results_are_newest_first(client):
    client.post(
        "/api/v1/events",
        json=[
            make_event(timestamp="2026-10-28T10:00:00Z"),
            make_event(timestamp="2026-10-28T11:00:00Z"),
        ],
    )
    items = client.get("/api/v1/events").json()["items"]
    assert items[0]["timestamp"] > items[1]["timestamp"]


def test_output_timestamps_are_utc(client):
    client.post("/api/v1/events", json=[make_event(timestamp="2026-10-28T08:00:00-04:00")])
    ts = client.get("/api/v1/events").json()["items"][0]["timestamp"]
    assert ts.endswith(("Z", "+00:00"))
    assert "12:00:00" in ts


def test_limit_is_capped(client):
    assert client.get("/api/v1/events", params={"limit": 5000}).status_code == 422
