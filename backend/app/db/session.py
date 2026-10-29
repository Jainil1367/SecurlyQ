"""Database engine and session management.

Lesson: an *engine* is the connection pool to the database. A *session* is a
short-lived "unit of work": you add/query objects, then commit or roll back.
FastAPI's dependency injection hands each request its own session and closes it
afterwards (the `get_db` generator below).
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
