"""CORS is off unless origins are configured, and never wide open."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient


def _app(origins: list[str]) -> TestClient:
    # Same wiring as app.main, on a tiny app so we can vary the settings.
    app = FastAPI()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    return TestClient(app)


def test_allowed_origin_gets_cors_headers() -> None:
    r = _app(["https://app.example.com"]).get("/ping", headers={"Origin": "https://app.example.com"})
    assert r.headers["access-control-allow-origin"] == "https://app.example.com"


def test_other_origin_gets_no_cors_headers() -> None:
    r = _app(["https://app.example.com"]).get("/ping", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_disabled_by_default() -> None:
    r = _app([]).get("/ping", headers={"Origin": "https://app.example.com"})
    assert "access-control-allow-origin" not in r.headers


def test_default_setting_is_empty(monkeypatch) -> None:
    from app.core.config import Settings

    assert Settings().cors_origins == []
