"""Application entry point. Run with: uvicorn app.main:app --reload"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, analysis, auth, events, health, users
from app.core.config import get_settings

settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(
    title="SecurlyQ API",
    description="AI-powered security analytics. Findings are *potentially suspicious*, never confirmed attacks.",
    version="0.2.0",
)

if settings.cors_origins:
    # Explicit allow-list, never "*": the API uses bearer tokens in a header, not cookies.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(events.router)
app.include_router(analysis.router)
app.include_router(alerts.router)
