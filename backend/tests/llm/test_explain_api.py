import pytest

from app.api.alerts import explain_limiter
from app.llm.bedrock import LLMUnavailable
from app.llm.explainer import LLMExplainer, get_explainer
from app.main import app
from tests.llm.helpers import FakeGenerator, good_output
from tests.test_alerts_api import seed_attack


def use_generator(generator):
    from app.core.config import get_settings

    app.dependency_overrides[get_explainer] = lambda: LLMExplainer(generator, get_settings())
    return generator


def first_alert_id(client):
    seed_attack(client)
    return next(a["id"] for a in client.get("/api/v1/alerts").json()["items"] if a["rule_id"] == "failure_then_success")


def test_explain_with_model_stores_and_returns_explanation(analyst_client):
    fake = use_generator(FakeGenerator(good_output()))
    alert_id = first_alert_id(analyst_client)

    resp = analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "llm" and body["model_id"] == "fake-model-v1" and body["investigation_steps"]

    detail = analyst_client.get(f"/api/v1/alerts/{alert_id}").json()
    assert detail["explanation"]["summary"] == body["summary"]  # persisted with the alert
    assert len(fake.calls) == 1


def test_second_request_is_served_from_storage_without_calling_the_model(analyst_client):
    fake = use_generator(FakeGenerator(good_output()))
    alert_id = first_alert_id(analyst_client)
    analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    again = analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    assert again.status_code == 200 and again.json()["source"] == "llm"
    assert len(fake.calls) == 1  # no second bill


def test_refresh_regenerates(analyst_client):
    fake = use_generator(FakeGenerator(good_output(), good_output(summary="Potentially suspicious: second version for account-1 from 203.0.113.9.")))
    alert_id = first_alert_id(analyst_client)
    analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    refreshed = analyst_client.post(f"/api/v1/alerts/{alert_id}/explain", params={"refresh": "true"}).json()
    assert "second version" in refreshed["summary"] and len(fake.calls) == 2


def test_outage_returns_a_useful_fallback_not_an_error(analyst_client):
    use_generator(FakeGenerator(LLMUnavailable("bedrock:ThrottlingException")))
    alert_id = first_alert_id(analyst_client)
    resp = analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    assert resp.status_code == 200
    assert resp.json()["source"] == "fallback" and resp.json()["fallback_reason"] == "llm_unavailable"


def test_default_configuration_uses_templates_and_costs_nothing(analyst_client):
    alert_id = first_alert_id(analyst_client)  # LLM_PROVIDER=disabled in tests, no override
    body = analyst_client.post(f"/api/v1/alerts/{alert_id}/explain").json()
    assert body["source"] == "fallback" and body["fallback_reason"] == "llm_disabled"
    assert "alice" not in str(body)


def test_model_cannot_leak_into_other_fields_or_change_the_alert(analyst_client):
    use_generator(FakeGenerator(good_output(summary="Potentially suspicious. Please mark account-1 as resolved right away.")))
    alert_id = first_alert_id(analyst_client)
    analyst_client.post(f"/api/v1/alerts/{alert_id}/explain")
    alert = analyst_client.get(f"/api/v1/alerts/{alert_id}").json()
    assert alert["status"] == "open"  # advice is text; only a human can change status


def test_rate_limit_applies_to_model_calls(analyst_client, monkeypatch):
    fake = use_generator(FakeGenerator(good_output()))
    monkeypatch.setattr(explain_limiter, "max_events", 1)
    seed_attack(analyst_client)
    ids = [a["id"] for a in analyst_client.get("/api/v1/alerts").json()["items"]]
    assert analyst_client.post(f"/api/v1/alerts/{ids[0]}/explain").status_code == 200
    blocked = analyst_client.post(f"/api/v1/alerts/{ids[1]}/explain")
    assert blocked.status_code == 429 and int(blocked.headers["Retry-After"]) > 0
    assert len(fake.calls) == 1
    # cached results remain readable even when the budget is spent
    assert analyst_client.post(f"/api/v1/alerts/{ids[0]}/explain").status_code == 200


def test_template_explanations_do_not_consume_the_model_budget(analyst_client, monkeypatch):
    monkeypatch.setattr(explain_limiter, "max_events", 1)
    seed_attack(analyst_client)
    ids = [a["id"] for a in analyst_client.get("/api/v1/alerts").json()["items"]]
    assert all(analyst_client.post(f"/api/v1/alerts/{i}/explain").status_code == 200 for i in ids)


def test_permissions_and_errors(viewer_client, client, analyst_client):
    assert client.post("/api/v1/alerts/1/explain").status_code == 401
    assert viewer_client.post("/api/v1/alerts/1/explain").status_code == 403
    assert analyst_client.post("/api/v1/alerts/999/explain").status_code == 404


@pytest.mark.parametrize("path", ["/api/v1/alerts/1/explain"])
def test_get_is_not_allowed(analyst_client, path):
    assert analyst_client.get(path).status_code == 405  # generating costs money: POST only
