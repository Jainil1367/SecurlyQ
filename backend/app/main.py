"""Application entry point. Run with: uvicorn app.main:app --reload"""

import logging

from fastapi import FastAPI

from app.api import events, health
from app.core.config import get_settings

settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = FastAPI(
    title="SecurlyQ API",
    description="AI-powered security analytics. Findings are *potentially suspicious*, never confirmed attacks.",
    version="0.1.0",
)

app.include_router(health.router)
app.include_router(events.router)
