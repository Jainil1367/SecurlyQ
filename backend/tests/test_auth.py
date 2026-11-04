from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from tests.conftest import TEST_PASSWORD, create_user


def login(client, email, password):
    return client.post("/api/v1/auth/login", data={"username": email, "password": password})


# ---- password hashing & tokens -------------------------------------------------


def test_password_hash_is_salted_and_verifiable():
    a, b = hash_password("s3cret-password"), hash_password("s3cret-password")
    assert a != b  # random salt: same password, different hash
    assert verify_password("s3cret-password", a)
    assert not verify_password("wrong", a)
    assert "s3cret" not in a


def test_token_round_trip():
    assert decode_access_token(create_access_token(42)) == 42


def test_expired_token_rejected():
    old = datetime.now(UTC) - timedelta(hours=5)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(create_access_token(1, now=old))


def test_tampered_token_rejected():
    token = create_access_token(1)
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(token[:-2] + ("aa" if not token.endswith("aa") else "bb"))


def test_token_signed_with_other_secret_rejected():
    forged = jwt.encode(
        {"sub": "1", "exp": datetime.now(UTC) + timedelta(hours=1)}, "attacker-secret-attacker-secret!!", "HS256"
    )
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)


def test_alg_none_token_rejected():
    forged = jwt.encode({"sub": "1", "exp": datetime.now(UTC) + timedelta(hours=1)}, key=None, algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)


# ---- register / login / me ------------------------------------------------------


def test_first_user_is_admin_then_analyst(client):
    r1 = client.post("/api/v1/auth/register", json={"email": "Boss@Example.com", "password": TEST_PASSWORD})
    assert r1.status_code == 201 and r1.json()["role"] == "admin"
    assert r1.json()["email"] == "boss@example.com"
    assert "password" not in r1.text and "hashed" not in r1.text
    r2 = client.post("/api/v1/auth/register", json={"email": "two@example.com", "password": TEST_PASSWORD})
    assert r2.json()["role"] == "analyst"


def test_duplicate_email_conflict(client):
    body = {"email": "a@example.com", "password": TEST_PASSWORD}
    client.post("/api/v1/auth/register", json=body)
    assert client.post("/api/v1/auth/register", json=body).status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"email": "not-an-email", "password": TEST_PASSWORD},
        {"email": "a@example.com", "password": "short"},
        {"email": "a@example.com", "password": TEST_PASSWORD, "role": "admin"},  # mass-assignment attempt
    ],
)
def test_register_validation(client, body):
    assert client.post("/api/v1/auth/register", json=body).status_code == 422


def test_login_and_me(client):
    client.post("/api/v1/auth/register", json={"email": "a@example.com", "password": TEST_PASSWORD})
    resp = login(client, "A@example.com", TEST_PASSWORD)
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["email"] == "a@example.com"


def test_bad_credentials_give_identical_errors(client):
    client.post("/api/v1/auth/register", json={"email": "a@example.com", "password": TEST_PASSWORD})
    wrong_pw = login(client, "a@example.com", "nope-nope-nope")
    no_user = login(client, "ghost@example.com", "nope-nope-nope")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()  # no user enumeration


def test_login_is_rate_limited(client):
    client.post("/api/v1/auth/register", json={"email": "a@example.com", "password": TEST_PASSWORD})
    limit = get_settings().login_max_failures
    for _ in range(limit):
        assert login(client, "a@example.com", "wrong-wrong-wrong").status_code == 401
    blocked = login(client, "a@example.com", TEST_PASSWORD)  # even the right password is refused
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


def test_successful_login_resets_failure_count(client):
    client.post("/api/v1/auth/register", json={"email": "a@example.com", "password": TEST_PASSWORD})
    for _ in range(get_settings().login_max_failures - 1):
        login(client, "a@example.com", "wrong-wrong-wrong")
    assert login(client, "a@example.com", TEST_PASSWORD).status_code == 200
    assert login(client, "a@example.com", "wrong-wrong-wrong").status_code == 401  # not 429


def test_garbage_token_is_401(client):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.token"})
    assert resp.status_code == 401


def test_token_for_deleted_user_is_401(client, db_session):
    user = create_user(db_session, "gone@example.com", "analyst")
    token = create_access_token(user.id)
    db_session.delete(user)
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# ---- RBAC -----------------------------------------------------------------------


def test_only_admin_can_list_and_change_roles(admin_client, analyst_client, db_session):
    target = create_user(db_session, "target@example.com", "viewer")
    assert analyst_client.get("/api/v1/users").status_code == 403
    assert admin_client.get("/api/v1/users").status_code == 200

    resp = admin_client.patch(f"/api/v1/users/{target.id}/role", json={"role": "analyst"})
    assert resp.status_code == 200 and resp.json()["role"] == "analyst"


def test_admin_cannot_change_own_role(admin_client):
    resp = admin_client.patch(f"/api/v1/users/{admin_client.user.id}/role", json={"role": "viewer"})
    assert resp.status_code == 400


def test_invalid_role_rejected(admin_client, db_session):
    target = create_user(db_session, "t@example.com", "viewer")
    assert admin_client.patch(f"/api/v1/users/{target.id}/role", json={"role": "root"}).status_code == 422


def test_demotion_takes_effect_immediately(admin_client, analyst_client, db_session):
    """Roles are read from the DB on each request, not baked into the token."""
    assert analyst_client.post("/api/v1/analysis/run").status_code == 200
    admin_client.patch(f"/api/v1/users/{analyst_client.user.id}/role", json={"role": "viewer"})
    assert analyst_client.post("/api/v1/analysis/run").status_code == 403


# ---- rate limiter unit ----------------------------------------------------------


def test_sliding_window_limiter_expires_old_events():
    now = [0.0]
    limiter = SlidingWindowRateLimiter(max_events=3, window_seconds=10, clock=lambda: now[0])
    for _ in range(3):
        limiter.record("k")
    assert limiter.is_blocked("k")
    now[0] = 10.5  # window has slid past all three events
    assert not limiter.is_blocked("k")


def test_limiter_keys_are_independent():
    limiter = SlidingWindowRateLimiter(max_events=1, window_seconds=60)
    limiter.record("a")
    assert limiter.is_blocked("a") and not limiter.is_blocked("b")


# ---- config safety --------------------------------------------------------------


def test_insecure_secret_refused_outside_development():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(environment="production")  # default dev secret must not be accepted
    Settings(environment="production", jwt_secret="x" * 40)  # a real secret is fine
