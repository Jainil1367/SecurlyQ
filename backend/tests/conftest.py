"""Shared test fixtures.

Lesson: unit tests should be fast and isolated. We run them against an in-memory
SQLite database (created fresh for every test) instead of a real PostgreSQL
server. Because FastAPI uses dependency injection, we can swap the real
`get_db` for one that points at SQLite with a single override.
"""

import os

# Must be set before the app imports its settings.
os.environ["DATABASE_URL"] = "sqlite://"
# Tests must not pick up a model someone trained locally: keep them deterministic.
os.environ["ANOMALY_MODEL_PATH"] = "/nonexistent/securlyq-test-model.joblib"
os.environ["LLM_PROVIDER"] = "disabled"  # tests never call a real model

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models as _models  # noqa: F401  (registers tables on Base.metadata)
from app.api.alerts import explain_limiter
from app.api.auth import login_limiter
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.llm import explainer as llm_explainer
from app.main import app
from app.ml import runtime as ml_runtime
from app.models import User


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_global_state():
    login_limiter.clear()
    explain_limiter.clear()
    ml_runtime.clear_cache()
    llm_explainer.clear_cache()
    yield
    login_limiter.clear()
    explain_limiter.clear()
    ml_runtime.clear_cache()
    llm_explainer.clear_cache()


TEST_PASSWORD = "correct-horse-battery"
_TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)  # hash once; Argon2 is deliberately slow


def create_user(db, email: str, role: str) -> User:
    user = User(email=email, hashed_password=_TEST_PASSWORD_HASH, role=role)
    db.add(user)
    db.commit()
    return user


def _client_with_role(db_session, role: str):
    user = create_user(db_session, f"{role}@example.com", role)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    test_client.headers["Authorization"] = f"Bearer {create_access_token(user.id)}"
    test_client.user = user
    return test_client


@pytest.fixture()
def analyst_client(db_session):
    yield _client_with_role(db_session, "analyst")
    app.dependency_overrides.clear()


@pytest.fixture()
def viewer_client(db_session):
    yield _client_with_role(db_session, "viewer")
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_client(db_session):
    yield _client_with_role(db_session, "admin")
    app.dependency_overrides.clear()


def make_event(**overrides) -> dict:
    event = {
        "source": "auth-service",
        "event_type": "login",
        "timestamp": "2026-10-28T12:00:00Z",
        "outcome": "failure",
        "source_ip": "203.0.113.7",
        "username": "Alice",
        "attributes": {"user_agent": "curl/8.0"},
    }
    event.update(overrides)
    return event
