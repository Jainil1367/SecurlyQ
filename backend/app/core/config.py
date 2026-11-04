"""Application settings.

Lesson: the "12-factor app" rule says configuration lives in the environment,
not in code. pydantic-settings reads environment variables (and a .env file),
validates their types, and gives us one typed `settings` object to import.
That way the same code runs on your laptop, in CI, and on AWS; only the
environment variables change.
"""

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_JWT_SECRET = "dev-only-insecure-secret-change-me-0123456789"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://securlyq:securlyq_dev@localhost:5432/securlyq"
    environment: str = "development"
    log_level: str = "INFO"

    # Ingestion safety limits (protect the API from oversized requests).
    max_batch_size: int = 1000

    # Authentication
    jwt_secret: str = INSECURE_DEV_JWT_SECRET
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60
    login_max_failures: int = 5
    login_window_seconds: int = 300

    # Detection rule thresholds (tunable without code changes)
    burst_threshold: int = 10  # failed logins from one IP...
    burst_window_minutes: int = 5  # ...within this window
    fail_then_success_threshold: int = 5
    fail_then_success_window_minutes: int = 15
    multi_ip_threshold: int = 3  # distinct IPs for one user...
    multi_ip_window_minutes: int = 60  # ...within this window

    # Analysis limits
    analysis_lookback_hours: int = 24
    max_analysis_events: int = 50_000

    @model_validator(mode="after")
    def refuse_insecure_secret_outside_dev(self) -> "Settings":
        """Fail fast: a known default secret in production would let anyone forge tokens."""
        if self.environment != "development" and (
            self.jwt_secret == INSECURE_DEV_JWT_SECRET or len(self.jwt_secret) < 32
        ):
            raise ValueError("JWT_SECRET must be set to a random value of 32+ chars outside development")
        return self


@lru_cache
def get_settings() -> Settings:
    """Cached so we parse the environment once, not on every request."""
    return Settings()
