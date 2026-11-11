"""Production closes self-signup after the first admin exists; only admins add accounts."""

import pytest

from app.core.config import get_settings
from tests.conftest import TEST_PASSWORD

REGISTER = "/api/v1/auth/register"


@pytest.fixture()
def closed(monkeypatch):
    monkeypatch.setattr(get_settings(), "open_registration", False)


def _register(client, email):
    return client.post(REGISTER, json={"email": email, "password": TEST_PASSWORD})


def test_first_account_can_still_bootstrap_when_closed(client, closed):
    r = _register(client, "first@example.com")
    assert r.status_code == 201
    assert r.json()["role"] == "admin"


def test_second_self_signup_is_refused_when_closed(client, closed):
    assert _register(client, "first@example.com").status_code == 201
    r = _register(client, "stranger@example.com")
    assert r.status_code == 403
    assert "closed" in r.json()["detail"].lower()


def test_open_by_default_for_local_development(client):
    assert _register(client, "a@example.com").status_code == 201
    assert _register(client, "b@example.com").status_code == 201


def test_admin_can_create_an_account_with_a_role(admin_client):
    r = admin_client.post("/api/v1/users", json={"email": "New@Example.com", "password": TEST_PASSWORD, "role": "viewer"})
    assert r.status_code == 201
    assert r.json()["email"] == "new@example.com"
    assert r.json()["role"] == "viewer"


def test_duplicate_email_is_a_conflict(admin_client):
    body = {"email": "dup@example.com", "password": TEST_PASSWORD}
    assert admin_client.post("/api/v1/users", json=body).status_code == 201
    assert admin_client.post("/api/v1/users", json=body).status_code == 409


def test_non_admins_cannot_create_accounts(analyst_client, viewer_client):
    body = {"email": "x@example.com", "password": TEST_PASSWORD}
    assert analyst_client.post("/api/v1/users", json=body).status_code == 403
    assert viewer_client.post("/api/v1/users", json=body).status_code == 403


def test_unknown_fields_are_rejected(admin_client):
    body = {"email": "x@example.com", "password": TEST_PASSWORD, "is_admin": True}
    assert admin_client.post("/api/v1/users", json=body).status_code == 422
