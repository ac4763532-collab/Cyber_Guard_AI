"""
CyberGuard AI - Configuration Management

Centralized configuration using pydantic-settings.
All secrets and configuration are loaded from environment variables.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "CyberGuard AI"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"

    # API
    api_v1_prefix: str = "/api/v1"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database (PostgreSQL)
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "cyberguard"
    db_user: str = "postgres"
    db_password: str = "postgres"
    db_enabled: bool = False  # Set to True when PostgreSQL is available

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Redpanda/Kafka Event Bus
    redpanda_bootstrap_servers: str = "localhost:9092"
    event_bus_enabled: bool = True

    # Security
    secret_key: str = "CHANGE-THIS-IN-PRODUCTION-use-openssl-rand-hex-32"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    token_encryption_key: str = ""  # Fernet key for OAuth token encryption (generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    # Tenant/organization membership assigned to new non-admin accounts
    # that don't specify one (registration, Firebase login). Admins never
    # get a restriction (organization_id=None - see get_authorized_tenant_ids
    # in app/api/v1/logs.py). A single shared default is the simplest
    # correct behavior while there is no real multi-org onboarding flow;
    # change this (or pass organization_id explicitly at registration) once
    # one exists.
    default_organization_id: str = "default"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Firebase Authentication
    firebase_project_id: str = ""
    firebase_service_account_path: str = ""  # Path to service account JSON (optional)

    # LLM (Claude API)
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"

    # Google OAuth (Gmail API)
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v1/gmail/oauth/callback"
    gmail_scopes: str = "https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/userinfo.email"

    # Threat Intelligence APIs
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    google_safe_browsing_api_key: str = ""

    # SMTP (outbound notification email). All optional - when smtp_host
    # is blank, the notification service honestly records delivery as
    # "failed: SMTP not configured" rather than silently no-opting as if
    # it succeeded.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_address: str = "alerts@cyberguard.local"
    smtp_from_name: str = "CyberGuard AI"
    smtp_timeout_seconds: int = 10

    # Optional webhook channel for notifications (e.g. Slack incoming
    # webhook, or a custom integration). Blank disables webhook delivery.
    notification_webhook_url: str = ""

    # URL Analysis
    url_expansion_timeout: int = 5
    url_max_redirects: int = 5
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_email_analysis: str = "30/minute"
    rate_limit_default: str = "100/minute"

    # External API Rate Limiting (Step 9)
    external_vt_rate_limit: int = 3  # requests per minute
    external_vt_rate_window: int = 60  # seconds
    external_abuseipdb_rate_limit: int = 60  # requests per minute
    external_abuseipdb_rate_window: int = 60  # seconds
    external_safe_browsing_daily_limit: int = 8000  # requests per day

    # Threat Intel Cache TTL (Step 9)
    external_cache_ttl_malicious: int = 3600  # 1 hour for malicious
    external_cache_ttl_clean: int = 86400  # 24 hours for clean

    # Circuit Breaker (Step 9)
    external_circuit_failure_threshold: int = 5
    external_circuit_recovery_seconds: int = 60

    # Request Concurrency (Step 9)
    max_concurrent_requests: int = 100
    max_request_queue: int = 200

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = ""
    security_log_file: str = ""

    # Third-party transport logging (Redpanda/Kafka client). aiokafka logs
    # every protocol request/response frame at DEBUG, which floods the
    # terminal whenever LOG_LEVEL=DEBUG is set for the app's own logging -
    # app-level DEBUG should not imply "trace every TCP frame of a client
    # library". This is independent of log_level so genuine aiokafka
    # WARNING/ERROR logs (connection failures, broker errors, etc.) are
    # never hidden - only the per-frame protocol tracing is raised.
    kafka_client_log_level: str = "WARNING"

    # Metrics (Step 10)
    metrics_enabled: bool = True
    metrics_retention_hours: int = 24

    # Log Collector Runtime (Step 8 collection pipeline wiring)
    log_collectors_enabled: bool = False  # Enable embedded Windows/Linux collector supervision

    # Gmail Automatic Polling (app/services/gmail/poller.py)
    gmail_poll_enabled: bool = False  # Enable automatic per-account Gmail polling
    gmail_poll_interval_seconds: float = 60.0  # Interval between poll cycles

    # Windows Collector (Step 8.1)
    windows_collector_enabled: bool = False  # Enable Windows Event Log collection
    windows_event_channel: str = "Security"  # Event Log channel to monitor
    windows_event_ids: str = "4624,4625,4634,4648,4672,4688,4720,4726"  # All 8 supported Event IDs
    windows_poll_interval: float = 5.0  # Seconds between Event Log polls
    windows_batch_size: int = 100  # Max events to read per poll cycle
    windows_collect_command_line: bool = True  # Collect process command lines (will be redacted)

    # Windows Detection Rules (Step 8.2)
    windows_detection_enabled: bool = True  # Enable Windows detection rules
    windows_failed_auth_threshold: int = 5  # Failures to trigger WIN-001
    windows_failed_auth_window: int = 300  # Time window in seconds for WIN-001
    windows_auth_sequence_threshold: int = 3  # Failures before success for WIN-002
    windows_privileged_detection_enabled: bool = True  # Enable WIN-003 (4672)

    # Real-Time Correlation (Step 8.5.3)
    correlation_enabled: bool = True  # Enable automatic correlation on findings
    correlation_window_seconds: int = 900  # 15-minute correlation window
    correlation_bucket_minutes: int = 15  # Fingerprint bucket size
    correlation_max_candidates: int = 100  # Max candidates per correlation
    correlation_min_findings: int = 2  # Minimum findings for correlation

    # Log Ingestion Resource Protection (STEP 4: Secure Ingestion + Tenant Isolation)
    log_ingest_max_entries: int = 1000  # Max ParsedLogEntry items per /logs/ingest request
    log_ingest_max_request_bytes: int = 1_048_576  # 1MB max body size for /logs/ingest
    log_ingest_max_raw_content_bytes: int = 1_048_576  # 1MB max log_content for /logs/ingest/raw

    # Drag-and-drop Log File Upload (POST /analysis/logs/upload)
    log_upload_max_file_size_bytes: int = 5_242_880  # 5MB - smaller than email's 10MB cap since
    # these parsers (CSV/JSON/JSONL, Windows-XML-fallback) are new and unoptimized.
    log_upload_max_files_per_request: int = 1  # Single file only in v1 - see upload feature plan.
    log_upload_dedup_ttl_seconds: int = 120  # Window to reject an identical re-submission.

    # Raw Event Retention (app/retention/cleanup.py). Applies only to
    # log_events - the high-volume raw telemetry table collectors write
    # to. This is deliberately independent of the Events page's display
    # limit (how many rows the UI shows at once) - retention controls how
    # long a row exists in Postgres at all, display limit controls how
    # many of the still-existing rows are fetched for one page view.
    # Default 90 days balances storage growth against forensic/audit
    # value for raw log telemetry; override via LOG_EVENT_RETENTION_DAYS
    # for environments with different compliance requirements.
    #
    # Cleanup NEVER deletes a log_events row that:
    #   - is newer than the cutoff, OR
    #   - has legal_hold = true (see log_events.legal_hold, schema.py), OR
    #   - is referenced (via the events/findings bridge - see
    #     app/retention/cleanup.py's docstring for the exact join) by any
    #     persisted Finding - i.e. any row that contributed to a real
    #     detection result is preserved regardless of age.
    log_event_retention_enabled: bool = True  # Master on/off switch for automatic cleanup
    log_event_retention_days: int = 90  # Delete-eligible once older than this many days
    log_event_retention_check_interval_seconds: int = 3600  # How often the cleanup loop wakes up (hourly)
    log_event_retention_batch_size: int = 500  # Rows deleted per DELETE statement (bounded batch)
    log_event_retention_max_batches_per_tenant_per_run: int = 50  # Caps rows/tenant/run at batch_size * this


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Using lru_cache ensures settings are only loaded once,
    improving performance and consistency.
    """
    return Settings()


# Convenience export
settings = get_settings()
