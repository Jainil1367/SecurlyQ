"""Shared test fixtures.

Lesson: unit tests should be fast and isolated. We run them against an in-memory
SQLite database (created fresh for every test) instead of a real PostgreSQL
server. Because FastAPI uses dependency injection, we can swap the real
`get_db` for one that points at SQLite with a single override.
"""

import os

# Must be set before the app imports its settings.
os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models as _models  # noqa: F401  (registers tables on Base.metadata)
from app.db.base import Base
from app.db.session import get_db
from app.main import app


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
