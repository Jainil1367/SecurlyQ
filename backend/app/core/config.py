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

    # Browser origins allowed to call the API (the deployed dashboard). In development the Vite
    # proxy makes requests same-origin, so this only matters when the frontend is on another domain.
    # Set as JSON in the environment, e.g. CORS_ORIGINS='["https://app.example.com"]'.
    cors_origins: list[str] = []

    # Authentication
    # When false, /auth/register works only to create the very first (admin) account; after that,
    # admins create accounts with POST /users. Production sets this to false.
    open_registration: bool = True
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

    # Machine learning
    anomaly_model_path: str = "models/anomaly_v1.joblib"  # missing file => rules-only mode

    # LLM explanations (Amazon Bedrock). "disabled" => deterministic template explanations only.
    llm_provider: str = "disabled"  # disabled | bedrock
    bedrock_model_id: str = ""  # copy the exact model/inference-profile ID from the Bedrock console
    aws_region: str = "us-east-1"
    llm_timeout_seconds: int = 20
    llm_max_output_tokens: int = 700
    llm_max_evidence_events: int = 25  # cap on events sent to the model (cost + privacy)
    llm_redact_usernames: bool = True  # replace account names with account-1, account-2, ...
    llm_requests_per_hour: int = 30  # per user; protects the AWS bill

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
        if self.llm_provider not in {"disabled", "bedrock"}:
            raise ValueError("LLM_PROVIDER must be 'disabled' or 'bedrock'")
        if self.llm_provider == "bedrock" and not self.bedrock_model_id:
            raise ValueError("BEDROCK_MODEL_ID is required when LLM_PROVIDER=bedrock")
        return self


@lru_cache
def get_settings() -> Settings:
    """Cached so we parse the environment once, not on every request."""
    return Settings()
