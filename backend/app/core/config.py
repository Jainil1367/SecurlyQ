"""Application settings.

Lesson: the "12-factor app" rule says configuration lives in the environment,
not in code. pydantic-settings reads environment variables (and a .env file),
validates their types, and gives us one typed `settings` object to import.
That way the same code runs on your laptop, in CI, and on AWS; only the
environment variables change.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://securlyq:securlyq_dev@localhost:5432/securlyq"
    environment: str = "development"
    log_level: str = "INFO"

    # Ingestion safety limits (protect the API from oversized requests).
    max_batch_size: int = 1000


@lru_cache
def get_settings() -> Settings:
    """Cached so we parse the environment once, not on every request."""
    return Settings()
