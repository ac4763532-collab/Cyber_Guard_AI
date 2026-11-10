"""
CyberGuard AI — Typed Application Settings
============================================================================

Single source of truth for every configurable value in the backend.

Design principles
-----------------
1. **Typed and validated.** Pydantic v2 ``BaseSettings`` reads from ``.env``
   and the process environment, validates types and ranges, and refuses to
   construct ``Settings`` if anything critical is missing or malformed.

2. **Fail-fast in production.** A ``model_validator`` enforces stricter
   rules when ``APP_ENV == "production"``: JWT secret must be strong,
   ``APP_DEBUG`` must be off, and CORS must not contain a wildcard.

3. **Secrets are never logged.** API keys use ``SecretStr`` (auto-masked
   in ``repr`` and ``traceback``). ``DATABASE_URL`` uses a plain string
   because SQLAlchemy needs it, but is wrapped by ``safe_database_url()``
   whenever it must be logged.

4. **Absolute ``.env`` path.** The path is resolved relative to this file,
   so the backend behaves identically regardless of the shell's CWD.

5. **No side effects beyond config loading.** This module does not open
   database connections, contact external APIs, or start background tasks.

Usage
-----
    from app.core.config import settings

    print(settings.APP_NAME)              # "CyberGuard AI"
    print(settings.is_development)        # True / False
    print(settings.cors_origins_list)     # ["http://localhost:5173", ...]
    print(settings.safe_database_url())   # password masked

    # In tests, reset the cache to reload from environment:
    from app.core.config import get_settings
    get_settings.cache_clear()
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse, urlunparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Literal type aliases (mirror .env.example value domains) ────────────────
AppEnv = Literal["development", "staging", "production", "test"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LogFormat = Literal["json", "text"]
LLMProvider = Literal["none", "anthropic", "gemini", "ollama"]
SeverityLevel = Literal["low", "medium", "high", "critical"]


# ── Absolute path to .env, resolved relative to this module ─────────────────
# __file__      → E:\CyberGuard\backend\app\core\config.py
# parent        → ...\app\core
# parent.parent → ...\app
# parent^3      → E:\CyberGuard\backend
_BACKEND_DIR: Path = Path(__file__).resolve().parent.parent.parent
_ENV_FILE: Path = _BACKEND_DIR / ".env"
_ENV_FILE_CONFIG: str | None = str(_ENV_FILE) if _ENV_FILE.is_file() else None


class Settings(BaseSettings):
    """
    Typed application settings loaded from ``.env`` and environment variables.

    Field order follows the section order in ``.env.example`` for readability.
    """

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE_CONFIG,
        env_file_encoding="utf-8",
        extra="ignore",  # do not fail on unknown env vars
    )

    # ────────────────────────────────────────────────────────────────────
    # APPLICATION
    # ────────────────────────────────────────────────────────────────────
    APP_NAME: str = "CyberGuard AI"
    APP_ENV: AppEnv = "development"
    APP_VERSION: str = "0.1.0"
    APP_DEBUG: bool = False

    BACKEND_PUBLIC_URL: str = "http://localhost:8000"
    FRONTEND_PUBLIC_URL: str = "http://localhost:5173"

    # ────────────────────────────────────────────────────────────────────
    # SERVER
    # ────────────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = Field(default=8000, ge=1, le=65535)
    WORKERS: int = Field(default=1, ge=1, le=32)
    CORS_ALLOWED_ORIGINS: str = ""

    # ────────────────────────────────────────────────────────────────────
    # SECURITY / JWT
    # ────────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: SecretStr = Field(default=SecretStr(""))
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, ge=5, le=1440)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=30, ge=1, le=365)
    BCRYPT_ROUNDS: int = Field(default=12, ge=10, le=16)

    # ────────────────────────────────────────────────────────────────────
    # RATE LIMITING
    # ────────────────────────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH_PER_MINUTE: int = Field(default=10, ge=1)
    RATE_LIMIT_INGESTION_PER_MINUTE: int = Field(default=600, ge=1)
    RATE_LIMIT_GENERAL_PER_MINUTE: int = Field(default=120, ge=1)

    # ────────────────────────────────────────────────────────────────────
    # DATABASE (PostgreSQL)
    # ────────────────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(default="postgresql+psycopg://cyberguard:cyberguard_dev@localhost:5432/cyberguard")
    DB_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, le=200)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=1)
    DB_POOL_RECYCLE: int = Field(default=1800, ge=0)
    DB_ECHO: bool = False

    # ────────────────────────────────────────────────────────────────────
    # REDIS
    # ────────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = Field(default=50, ge=1)

    # ────────────────────────────────────────────────────────────────────
    # KAFKA / REDPANDA
    # ────────────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_CLIENT_ID: str = "cyberguard-backend"
    KAFKA_GROUP_ID: str = "cyberguard-agents"
    KAFKA_ENABLED: bool = False
    KAFKA_TOPIC_SECURITY_EVENTS: str = "security-events"
    KAFKA_TOPIC_AGENT_TASKS: str = "agent-tasks"
    KAFKA_TOPIC_AGENT_RESULTS: str = "agent-results"
    KAFKA_TOPIC_CORRELATIONS: str = "correlations"
    KAFKA_TOPIC_INCIDENTS: str = "incidents"
    KAFKA_TOPIC_ALERTS: str = "alerts"
    KAFKA_TOPIC_DEAD_LETTER: str = "dead-letter"

    # ────────────────────────────────────────────────────────────────────
    # FIREBASE AUTHENTICATION
    # ────────────────────────────────────────────────────────────────────
    FIREBASE_CREDENTIALS_PATH: str = "./firebase-service-account.json"
    FIREBASE_PROJECT_ID: str = ""
    FIREBASE_AUTH_ENABLED: bool = False

    # ────────────────────────────────────────────────────────────────────
    # THREAT INTELLIGENCE APIS
    # ────────────────────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: SecretStr = Field(default=SecretStr(""))
    VIRUSTOTAL_RATE_LIMIT_PER_MINUTE: int = Field(default=4, ge=1)
    ABUSEIPDB_API_KEY: SecretStr = Field(default=SecretStr(""))
    ABUSEIPDB_RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1)
    OTX_API_KEY: SecretStr = Field(default=SecretStr(""))
    OTX_RATE_LIMIT_PER_MINUTE: int = Field(default=30, ge=1)
    URLHAUS_ENABLED: bool = True
    NVD_API_KEY: SecretStr = Field(default=SecretStr(""))
    NVD_RATE_LIMIT_PER_MINUTE: int = Field(default=5, ge=1)
    GOOGLE_SAFE_BROWSING_API_KEY: SecretStr = Field(default=SecretStr(""))
    MITRE_ATTACK_ENABLED: bool = True
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: SecretStr = Field(default=SecretStr(""))
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/gmail/oauth/callback"
    MITRE_ATTACK_ENABLED: bool = True

    # ────────────────────────────────────────────────────────────────────
    # AI / LLM
    # ────────────────────────────────────────────────────────────────────
    LLM_PROVIDER: LLMProvider = "none"
    ANTHROPIC_API_KEY: SecretStr = Field(default=SecretStr(""))
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"
    ANTHROPIC_MAX_TOKENS: int = Field(default=2048, ge=1, le=8192)
    ANTHROPIC_TIMEOUT_SECONDS: int = Field(default=60, ge=5)
    GEMINI_API_KEY: SecretStr = Field(default=SecretStr(""))
    GEMINI_MODEL: str = "gemini-1.5-flash"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"

    # ────────────────────────────────────────────────────────────────────
    # AGENTS — global
    # ────────────────────────────────────────────────────────────────────
    AGENT_EXECUTION_ENABLED: bool = True
    AGENT_MAX_RETRIES: int = Field(default=3, ge=0, le=10)
    AGENT_RETRY_BACKOFF_SECONDS: int = Field(default=5, ge=1)
    AGENT_TASK_TIMEOUT_SECONDS: int = Field(default=120, ge=5)
    AGENT_BATCH_SIZE: int = Field(default=50, ge=1, le=1000)

    # ────────────────────────────────────────────────────────────────────
    # AGENTS — per-agent thresholds
    # ────────────────────────────────────────────────────────────────────
    LOG_AGENT_FAILED_LOGIN_THRESHOLD: int = Field(default=5, ge=1)
    LOG_AGENT_FAILED_LOGIN_WINDOW_MINUTES: int = Field(default=10, ge=1)
    LOG_AGENT_PRIVILEGE_ESCALATION_ENABLED: bool = True

    EMAIL_AGENT_MAX_ATTACHMENT_SIZE_BYTES: int = Field(default=26214400, ge=1)
    EMAIL_AGENT_SUSPICIOUS_TLD_SCORE: int = Field(default=40, ge=0, le=100)

    NETWORK_AGENT_PORT_SCAN_THRESHOLD: int = Field(default=20, ge=1)
    NETWORK_AGENT_PORT_SCAN_WINDOW_SECONDS: int = Field(default=60, ge=1)

    IOC_CORRELATION_TIME_WINDOW_MINUTES: int = Field(default=30, ge=1)
    IOC_CORRELATION_MIN_INDICATORS: int = Field(default=2, ge=1)

    INCIDENT_AUTO_CREATE_SEVERITY_THRESHOLD: SeverityLevel = "high"
    INCIDENT_AGENT_MAX_CASES_PER_ANALYST: int = Field(default=20, ge=1)

    REPORT_AGENT_MAX_ROWS: int = Field(default=10000, ge=1)
    REPORT_AGENT_PDF_PAGE_LIMIT: int = Field(default=100, ge=1)

    # ────────────────────────────────────────────────────────────────────
    # COLLECTORS
    # ────────────────────────────────────────────────────────────────────
    COLLECTOR_ENROLLMENT_TOKEN_TTL_MINUTES: int = Field(default=15, ge=1)
    COLLECTOR_HEARTBEAT_INTERVAL_SECONDS: int = Field(default=60, ge=10)
    COLLECTOR_STALE_AFTER_SECONDS: int = Field(default=300, ge=30)
    COLLECTOR_EVENT_BATCH_MAX_SIZE: int = Field(default=500, ge=1, le=10000)
    COLLECTOR_EVENT_MAX_SIZE_BYTES: int = Field(default=262144, ge=1024)
    COLLECTOR_CREDENTIAL_ROTATION_DAYS: int = Field(default=90, ge=1)

    # ────────────────────────────────────────────────────────────────────
    # FILE UPLOADS
    # ────────────────────────────────────────────────────────────────────
    UPLOAD_DIR: str = "./static/uploads"
    REPORT_OUTPUT_DIR: str = "./static/reports"
    MAX_UPLOAD_SIZE_BYTES: int = Field(default=52428800, ge=1024)
    ALLOWED_UPLOAD_MIME_TYPES: str = "application/pdf,text/plain,image/png,image/jpeg"

    # ────────────────────────────────────────────────────────────────────
    # LOGGING
    # ────────────────────────────────────────────────────────────────────
    LOG_LEVEL: LogLevel = "INFO"
    LOG_FORMAT: LogFormat = "json"
    LOG_FILE: str = "./logs/cyberguard.log"
    LOG_ROTATION_MB: int = Field(default=50, ge=1)
    LOG_RETENTION_DAYS: int = Field(default=30, ge=1)

    # ────────────────────────────────────────────────────────────────────
    # DATA RETENTION & PRIVACY
    # ────────────────────────────────────────────────────────────────────
    RETENTION_EVENTS_DAYS: int = Field(default=90, ge=1)
    RETENTION_FINDINGS_DAYS: int = Field(default=180, ge=1)
    RETENTION_ALERTS_DAYS: int = Field(default=365, ge=1)
    RETENTION_INCIDENTS_DAYS: int = Field(default=730, ge=1)
    RETENTION_AUDIT_LOGS_DAYS: int = Field(default=1825, ge=1)
    PRIVACY_REDACT_EMAIL_BODIES: bool = True
    PRIVACY_REDACT_IP_ADDRESSES: bool = False

    # ────────────────────────────────────────────────────────────────────
    # OBSERVABILITY
    # ────────────────────────────────────────────────────────────────────
    SENTRY_DSN: str = ""
    PROMETHEUS_ENABLED: bool = False
    HEALTH_CHECK_PATH: str = "/health"

    # ────────────────────────────────────────────────────────────────────
    # EMAIL / SMTP
    # ────────────────────────────────────────────────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: SecretStr = Field(default=SecretStr(""))
    SMTP_USE_TLS: bool = True
    EMAIL_FROM_ADDRESS: str = "no-reply@cyberguard.local"
    EMAIL_FROM_NAME: str = "CyberGuard AI"

    # ====================================================================
    # FIELD VALIDATORS
    # ====================================================================

    @field_validator("DATABASE_URL")
    @classmethod
    def _validate_database_url(cls, v: str) -> str:
        if not v.startswith(("postgresql://", "postgresql+psycopg://", "postgresql+psycopg2://", "postgresql+asyncpg://")):
            raise ValueError(
                "DATABASE_URL must start with 'postgresql://' or "
                f"'postgresql+psycopg2://'. Received: {v[:30]}..."
            )
        return v

    @field_validator("REDIS_URL")
    @classmethod
    def _validate_redis_url(cls, v: str) -> str:
        if not v.startswith(("redis://", "rediss://")):
            raise ValueError(
                "REDIS_URL must start with 'redis://' or 'rediss://'"
            )
        return v

    @field_validator("BACKEND_PUBLIC_URL", "FRONTEND_PUBLIC_URL", "OLLAMA_BASE_URL")
    @classmethod
    def _validate_http_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"URL must start with 'http://' or 'https://'. Received: {v}"
            )
        return v.rstrip("/")

    # ====================================================================
    # CROSS-FIELD VALIDATORS
    # ====================================================================

    @model_validator(mode="after")
    def _validate_cross_field_rules(self) -> "Settings":
        secret = self.JWT_SECRET_KEY.get_secret_value()

        # In production mode: enforce strict security invariants
        if self.APP_ENV == "production":
            if not secret:
                raise ValueError(
                    "JWT_SECRET_KEY must be provided via environment variable in production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            if len(secret) < 32 or "CHANGE_ME" in secret or secret.startswith("dev_"):
                raise ValueError(
                    "In production, JWT_SECRET_KEY must be a strong random secret "
                    "(at least 32 characters) and must not contain 'CHANGE_ME' or development placeholders."
                )
            if self.APP_DEBUG:
                raise ValueError("APP_DEBUG must be false in production.")
            if not self.cors_origins_list:
                raise ValueError("CORS_ALLOWED_ORIGINS must be set in production.")
            if "*" in self.cors_origins_list:
                raise ValueError("Wildcard '*' is not allowed in CORS_ALLOWED_ORIGINS in production.")
            if "cyberguard_dev" in self.DATABASE_URL:
                raise ValueError("Default development password detected in DATABASE_URL during production startup.")
        else:
            # In development or test mode: auto-assign local development secret if omitted
            if not secret:
                self.JWT_SECRET_KEY = SecretStr("dev_insecure_jwt_secret_key_for_local_development_only_minimum_64_chars_long_123456789")

        # LLM provider must have its API key if selected
        if self.LLM_PROVIDER == "anthropic" and not self.ANTHROPIC_API_KEY.get_secret_value():
            raise ValueError("LLM_PROVIDER=anthropic requires ANTHROPIC_API_KEY")
        if self.LLM_PROVIDER == "gemini" and not self.GEMINI_API_KEY.get_secret_value():
            raise ValueError("LLM_PROVIDER=gemini requires GEMINI_API_KEY")

        return self

    # ====================================================================
    # ENVIRONMENT HELPERS
    # ====================================================================

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @property
    def is_staging(self) -> bool:
        return self.APP_ENV == "staging"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == "test"

    # ====================================================================
    # PARSED LIST HELPERS
    # ====================================================================

    @property
    def is_google_oauth_configured(self) -> bool:
        return bool(self.GOOGLE_CLIENT_ID and (self.GOOGLE_CLIENT_SECRET.get_secret_value() if hasattr(self.GOOGLE_CLIENT_SECRET, "get_secret_value") else str(self.GOOGLE_CLIENT_SECRET)))

    @property
    def google_client_secret_str(self) -> str:
        return (self.GOOGLE_CLIENT_SECRET.get_secret_value() if hasattr(self.GOOGLE_CLIENT_SECRET, "get_secret_value") else str(self.GOOGLE_CLIENT_SECRET))

    @property
    def effective_google_redirect_uri(self) -> str:
        if self.GOOGLE_REDIRECT_URI and not self.GOOGLE_REDIRECT_URI.startswith("http://localhost:8000"):
            return self.GOOGLE_REDIRECT_URI
        if self.BACKEND_PUBLIC_URL and not self.BACKEND_PUBLIC_URL.startswith("http://localhost"):
            return f"{self.BACKEND_PUBLIC_URL.rstrip('/')}/api/v1/gmail/oauth/callback"
        return self.GOOGLE_REDIRECT_URI

    @property
    def cors_origins_list(self) -> list[str]:
        if not self.CORS_ALLOWED_ORIGINS.strip():
            return []
        return [
            origin.strip()
            for origin in self.CORS_ALLOWED_ORIGINS.split(",")
            if origin.strip()
        ]

    @property
    def allowed_upload_mime_types_list(self) -> list[str]:
        if not self.ALLOWED_UPLOAD_MIME_TYPES.strip():
            return []
        return [
            mime.strip()
            for mime in self.ALLOWED_UPLOAD_MIME_TYPES.split(",")
            if mime.strip()
        ]

    # ====================================================================
    # RESOLVED PATH HELPERS (creates directories if missing)
    # ====================================================================

    @property
    def upload_dir_path(self) -> Path:
        path = Path(self.UPLOAD_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def report_output_dir_path(self) -> Path:
        path = Path(self.REPORT_OUTPUT_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def log_file_path(self) -> Path:
        path = Path(self.LOG_FILE).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    # ====================================================================
    # SAFE-LOGGING HELPERS (secrets never appear in log output)
    # ====================================================================

    def safe_database_url(self) -> str:
        """
        Return ``DATABASE_URL`` with the password replaced by ``***``.
        Safe to log; never include the raw URL in logs.
        """
        try:
            parsed = urlparse(self.DATABASE_URL)
            if parsed.password:
                host = parsed.hostname or "unknown"
                port_part = f":{parsed.port}" if parsed.port else ""
                user = parsed.username or ""
                netloc = f"{user}:***@{host}{port_part}"
                return urlunparse(parsed._replace(netloc=netloc))
        except Exception:
            pass
        return "postgresql://<unparseable>"

    def log_config_summary(self) -> dict[str, Any]:
        """
        Return a dict summarizing the effective configuration with all secrets
        masked. Intended to be logged once at startup by ``main.py``.
        """
        return {
            "app_name": self.APP_NAME,
            "app_env": self.APP_ENV,
            "app_version": self.APP_VERSION,
            "debug": self.APP_DEBUG,
            "host": self.HOST,
            "port": self.PORT,
            "database": self.safe_database_url(),
            "redis": self.REDIS_URL,
            "kafka_enabled": self.KAFKA_ENABLED,
            "firebase_auth_enabled": self.FIREBASE_AUTH_ENABLED,
            "llm_provider": self.LLM_PROVIDER,
            "agent_execution_enabled": self.AGENT_EXECUTION_ENABLED,
            "log_level": self.LOG_LEVEL,
            "log_format": self.LOG_FORMAT,
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
        }


# ========================================================================
# FACTORY + MODULE-LEVEL SINGLETON
# ========================================================================

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Load and cache the application settings.

    Fails fast: if any required field is missing, or if production
    validation rules are violated, this raises ``pydantic.ValidationError``
    at import time. That is intentional — the backend must not start with
    an invalid configuration.

    In tests, reset the cache with ``get_settings.cache_clear()`` after
    mutating environment variables.
    """
    return Settings()


# Module-level singleton. Import directly for convenience:
#     from app.core.config import settings
#
# Note: importing this module triggers configuration loading. If the .env
# file is invalid, the import itself raises. This is the desired behavior
# for a production service.
settings: Settings = get_settings()


__all__ = ["Settings", "get_settings", "settings"]