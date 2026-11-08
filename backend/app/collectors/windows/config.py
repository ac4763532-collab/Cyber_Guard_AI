"""
CyberGuard AI — Windows Collector Configuration
============================================================================

Foundation for the Windows collector. Provides:
    - Typed ``CollectorConfig`` dataclass with every setting the collector needs
    - Loading from ``config.json`` (persistent) + ``.env`` (dev) + defaults
    - Self-assigned ``collector_id`` (UUID persisted to disk on first run)
    - Windows-standard directory creation (``%PROGRAMDATA%\CyberGuard\``)
    - Validation of every field on load

File locations (Windows):
    %PROGRAMDATA%\\CyberGuard\\config.json          — persistent settings
    %PROGRAMDATA%\\CyberGuard\\collector_id         — self-assigned UUID
    %PROGRAMDATA%\\CyberGuard\\queue.db             — durable event queue
    %PROGRAMDATA%\\CyberGuard\\logs\\collector.log  — rotating log

File locations (non-Windows dev/test):
    ~/.cyberguard/config.json
    ~/.cyberguard/collector_id
    ...

Configuration priority (highest to lowest):
    1. Explicit overrides (passed to ``CollectorConfig.load(overrides=...)``)
       — used by ``main.py`` when parsing CLI flags
    2. ``.env`` file (in the working directory) — dev convenience only
    3. ``config.json`` (in PROGRAM_DATA) — written after enrollment
    4. ``DEFAULTS`` dict below — lowest

The enrollment token is **never** stored here. It's passed to
``main.py enroll <token>`` as a CLI argument and only used during the
enrollment handshake. Once enrollment succeeds, the token is discarded
and a long-lived credential is stored (encrypted — see
``credential_store.py``).

This file requires no external dependencies beyond the stdlib. Windows
specific APIs (DPAPI, Event Log) live in their own modules.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any


# ============================================================================
# PATHS
# ============================================================================

def _get_program_data_dir() -> Path:
    """
    Return the base directory for CyberGuard's runtime files.

    On Windows: ``%PROGRAMDATA%\\CyberGuard`` (typically
    ``C:\\ProgramData\\CyberGuard``). This location is writable by
    administrators and the SYSTEM account under which the service runs.

    On non-Windows (dev/test only): ``~/.cyberguard``.
    """
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        return Path(program_data) / "CyberGuard"
    return Path.home() / ".cyberguard"


PROGRAM_DATA_DIR: Path = _get_program_data_dir()
CONFIG_FILE: Path = PROGRAM_DATA_DIR / "config.json"
COLLECTOR_ID_FILE: Path = PROGRAM_DATA_DIR / "collector_id"
QUEUE_FILE: Path = PROGRAM_DATA_DIR / "queue.db"
LOG_DIR: Path = PROGRAM_DATA_DIR / "logs"
LOG_FILE: Path = LOG_DIR / "collector.log"


def ensure_directories() -> None:
    """
    Create the directory structure if missing. Safe to call repeatedly.

    Permissions:
        - The directory inherits the parent's ACLs (``ProgramData`` is
          writable by Administrators and SYSTEM by default).
        - Files inside are created with the process's default ACL.
        - We do not tighten ACLs from Python — that's the installer's
          job (``install_service.ps1`` sets explicit ACLs during install).
    """
    PROGRAM_DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# DEFAULTS
# ============================================================================

DEFAULTS: dict[str, Any] = {
    "backend_url": "http://localhost:8000",
    "credential": None,                     # encrypted blob (set after enrollment)
    "batch_size": 100,                      # events per HTTP request
    "batch_interval_seconds": 10,           # flush interval for the sender
    "heartbeat_interval_seconds": 60,       # how often to send heartbeat
    "max_queue_size": 10000,                # drop-oldest when exceeded
    "event_channels": ["Security", "System", "Application"],
    "event_ids_to_capture": [],             # empty = capture all Event IDs
    "send_retry_max": 5,
    "send_retry_backoff_seconds": 5,
    "read_poll_seconds": 5,                 # how often to poll event log
    "log_level": "INFO",
    "http_timeout_seconds": 30,
    "agent_version": "0.1.0",
}


# ============================================================================
# ENV FILE LOADER
# ============================================================================

def _load_env_file(path: Path) -> dict[str, str]:
    """
    Minimal ``.env`` file parser.

    Supports:
        KEY=value
        KEY="value with spaces"
        KEY='value with spaces'
        # comment lines
        (empty lines)

    Does NOT support:
        Variable substitution (``${OTHER_VAR}``)
        Multi-line values
        Escape sequences in quoted values

    For production, the config comes from ``config.json``. The ``.env``
    file is a dev convenience (e.g. pointing the collector at
    ``http://localhost:8000`` during local testing).
    """
    if not path.exists() or not path.is_file():
        return {}

    env: dict[str, str] = {}
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, raw_value = stripped.partition("=")
        key = key.strip()
        raw_value = raw_value.strip()
        if not key:
            continue
        # Strip matching surrounding quotes
        if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in ('"', "'"):
            raw_value = raw_value[1:-1]
        env[key] = raw_value
    return env


def _env_file_path() -> Path:
    """
    The ``.env`` file lives next to the running script, not in PROGRAM_DATA.

    The intention: a developer can drop ``.env`` in the collector's
    directory (e.g. ``E:\\CyberGuard\\collector\\windows\\.env``) with
    ``BACKEND_URL=http://localhost:8000`` for testing. Production
    deployments don't need this file — config comes from config.json.
    """
    return Path(__file__).resolve().parent / ".env"


# ============================================================================
# COLLECTOR ID
# ============================================================================

def _load_or_create_collector_id() -> uuid.UUID:
    """
    Load the collector's self-assigned UUID from disk, or generate and
    persist one.

    The collector_id is **stable across reinstalls on the same device**.
    It's used by the backend to detect:
        - Same device re-enrolling (update existing installation)
        - Different device (create new installation)

    Format on disk: single line, hex UUID string, no trailing content.
    """
    if COLLECTOR_ID_FILE.exists():
        try:
            content = COLLECTOR_ID_FILE.read_text(encoding="utf-8").strip()
            return uuid.UUID(content)
        except (ValueError, OSError) as exc:
            # Corrupted file — regenerate. Log is unavailable at this
            # point (config not loaded yet), so raise a clear error.
            raise RuntimeError(
                f"collector_id file is corrupt: {COLLECTOR_ID_FILE}. "
                f"Delete it to regenerate (existing installation will be "
                f"orphaned). Error: {exc}"
            )

    # Generate new
    new_id = uuid.uuid4()
    COLLECTOR_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    COLLECTOR_ID_FILE.write_text(str(new_id), encoding="utf-8")
    return new_id


# ============================================================================
# CONFIG DATACLASS
# ============================================================================

@dataclass
class CollectorConfig:
    """
    Typed view of the collector's configuration.

    Instantiated by ``CollectorConfig.load()``. Every field has a
    default in ``DEFAULTS``; callers can override at load time.

    After construction, ``validate()`` enforces every constraint.
    """

    # ── Backend connection (required after enrollment) ─────────────────
    backend_url: str
    credential: str | None               # encrypted at rest

    # ── Identity (auto-generated) ───────────────────────────────────────
    collector_id: uuid.UUID

    # ── Event collection behavior ───────────────────────────────────────
    event_channels: list[str]
    event_ids_to_capture: list[int]
    read_poll_seconds: int

    # ── Send behavior ───────────────────────────────────────────────────
    batch_size: int
    batch_interval_seconds: int
    send_retry_max: int
    send_retry_backoff_seconds: int
    http_timeout_seconds: int

    # ── Heartbeat ───────────────────────────────────────────────────────
    heartbeat_interval_seconds: int

    # ── Queue ───────────────────────────────────────────────────────────
    max_queue_size: int

    # ── Logging / metadata ──────────────────────────────────────────────
    log_level: str
    agent_version: str

    # ── Runtime-only (not persisted) ────────────────────────────────────
    is_enrolled: bool = field(default=False, compare=False)

    # ====================================================================
    # LOAD
    # ====================================================================

    @classmethod
    def load(
        cls,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> "CollectorConfig":
        """
        Load configuration from all sources in priority order.

        Priority (highest first):
            1. ``overrides`` (dict — passed by CLI or tests)
            2. ``.env`` file (next to this module)
            3. ``config.json`` in PROGRAM_DATA
            4. ``DEFAULTS``

        Also:
            - Ensures directories exist
            - Loads or generates ``collector_id``
            - Marks ``is_enrolled = True`` if a credential is present

        Raises
        ------
        RuntimeError
            If ``backend_url`` is missing or malformed after merge
            (should only happen if config.json was manually edited to
            an invalid value).
        """
        ensure_directories()

        # ── 4. Defaults
        merged: dict[str, Any] = dict(DEFAULTS)

        # ── 3. config.json (may not exist on first run)
        if CONFIG_FILE.exists():
            try:
                file_config = json.loads(
                    CONFIG_FILE.read_text(encoding="utf-8")
                )
                if isinstance(file_config, dict):
                    merged.update(file_config)
            except (json.JSONDecodeError, OSError) as exc:
                raise RuntimeError(
                    f"config.json is corrupt: {CONFIG_FILE}. "
                    f"Error: {exc}"
                )

        # ── 2. .env overrides
        env_file = _env_file_path()
        env = _load_env_file(env_file)
        if env:
            merged = _apply_env_overrides(merged, env)

        # ── 1. Caller overrides
        if overrides:
            merged.update(overrides)

        # ── Populate collector_id from disk (not from JSON — file is
        #    the source of truth for identity)
        merged["collector_id"] = _load_or_create_collector_id()

        # ── Build the dataclass
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in merged.items() if k in known_fields}

        config = cls(**filtered)

        # ── Runtime flags
        config.is_enrolled = bool(config.credential)

        # ── Validate
        config.validate()

        return config

    # ====================================================================
    # SAVE
    # ====================================================================

    def save(self) -> None:
        """
        Persist the current config to ``config.json``.

        Excludes runtime-only fields (``is_enrolled``). Includes the
        credential (which should already be encrypted by
        ``credential_store.py`` — this class does not encrypt).

        Called after successful enrollment (to persist the credential
        and backend URL) and after any settings change.
        """
        ensure_directories()

        payload = {
            "backend_url": self.backend_url,
            "credential": self.credential,
            "batch_size": self.batch_size,
            "batch_interval_seconds": self.batch_interval_seconds,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "max_queue_size": self.max_queue_size,
            "event_channels": list(self.event_channels),
            "event_ids_to_capture": list(self.event_ids_to_capture),
            "send_retry_max": self.send_retry_max,
            "send_retry_backoff_seconds": self.send_retry_backoff_seconds,
            "read_poll_seconds": self.read_poll_seconds,
            "log_level": self.log_level,
            "http_timeout_seconds": self.http_timeout_seconds,
            "agent_version": self.agent_version,
        }

        # Write atomically — write to temp then rename
        tmp_path = CONFIG_FILE.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8",
        )
        tmp_path.replace(CONFIG_FILE)

    # ====================================================================
    # VALIDATE
    # ====================================================================

    def validate(self) -> None:
        """
        Enforce every constraint. Raises ``RuntimeError`` on violation.

        Kept separate from ``__post_init__`` so tests can construct
        partial configs and then decide whether to validate.
        """
        errors: list[str] = []

        # backend_url
        if not self.backend_url:
            errors.append("backend_url is empty")
        elif not self.backend_url.startswith(("http://", "https://")):
            errors.append(
                f"backend_url must start with http:// or https://, "
                f"got {self.backend_url!r}"
            )

        # batch_size
        if not (1 <= self.batch_size <= 1000):
            errors.append(
                f"batch_size must be 1-1000, got {self.batch_size}"
            )

        # batch_interval_seconds
        if self.batch_interval_seconds < 1:
            errors.append(
                f"batch_interval_seconds must be >= 1, "
                f"got {self.batch_interval_seconds}"
            )

        # heartbeat_interval_seconds
        if self.heartbeat_interval_seconds < 10:
            errors.append(
                f"heartbeat_interval_seconds must be >= 10, "
                f"got {self.heartbeat_interval_seconds}"
            )

        # max_queue_size
        if self.max_queue_size < 100:
            errors.append(
                f"max_queue_size must be >= 100, "
                f"got {self.max_queue_size}"
            )

        # event_channels
        if not isinstance(self.event_channels, list) or not self.event_channels:
            errors.append("event_channels must be a non-empty list")
        elif not all(isinstance(c, str) and c for c in self.event_channels):
            errors.append("event_channels must contain non-empty strings")

        # event_ids_to_capture
        if not isinstance(self.event_ids_to_capture, list):
            errors.append("event_ids_to_capture must be a list")
        elif not all(
            isinstance(i, int) and i > 0 for i in self.event_ids_to_capture
        ):
            errors.append(
                "event_ids_to_capture must contain positive integers"
            )

        # send_retry_max
        if self.send_retry_max < 1:
            errors.append(
                f"send_retry_max must be >= 1, got {self.send_retry_max}"
            )

        # send_retry_backoff_seconds
        if self.send_retry_backoff_seconds < 1:
            errors.append(
                f"send_retry_backoff_seconds must be >= 1, "
                f"got {self.send_retry_backoff_seconds}"
            )

        # read_poll_seconds
        if self.read_poll_seconds < 1:
            errors.append(
                f"read_poll_seconds must be >= 1, "
                f"got {self.read_poll_seconds}"
            )

        # log_level
        if self.log_level not in (
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL",
        ):
            errors.append(
                f"log_level must be one of DEBUG/INFO/WARNING/ERROR/CRITICAL, "
                f"got {self.log_level!r}"
            )

        # http_timeout_seconds
        if self.http_timeout_seconds < 5:
            errors.append(
                f"http_timeout_seconds must be >= 5, "
                f"got {self.http_timeout_seconds}"
            )

        if errors:
            raise RuntimeError(
                "CollectorConfig validation failed:\n  - "
                + "\n  - ".join(errors)
            )

    # ====================================================================
    # CONVENIENCE
    # ====================================================================

    def to_log_dict(self) -> dict[str, Any]:
        """
        Return a dict safe to log — credential is masked.
        """
        return {
            "backend_url": self.backend_url,
            "collector_id": str(self.collector_id),
            "is_enrolled": self.is_enrolled,
            "batch_size": self.batch_size,
            "batch_interval_seconds": self.batch_interval_seconds,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "max_queue_size": self.max_queue_size,
            "event_channels": list(self.event_channels),
            "event_ids_captured": (
                len(self.event_ids_to_capture)
                if self.event_ids_to_capture else "all"
            ),
            "read_poll_seconds": self.read_poll_seconds,
            "log_level": self.log_level,
            "agent_version": self.agent_version,
        }


# ============================================================================
# ENV OVERRIDE MAPPING
# ============================================================================

#: Map from .env key name → CollectorConfig field name. Env keys are
#: prefixed with ``CG_`` (CyberGuard) to avoid collision with
#: system-wide env vars.
_ENV_KEY_TO_FIELD: dict[str, str] = {
    "CG_BACKEND_URL": "backend_url",
    "CG_BATCH_SIZE": "batch_size",
    "CG_BATCH_INTERVAL_SECONDS": "batch_interval_seconds",
    "CG_HEARTBEAT_INTERVAL_SECONDS": "heartbeat_interval_seconds",
    "CG_MAX_QUEUE_SIZE": "max_queue_size",
    "CG_SEND_RETRY_MAX": "send_retry_max",
    "CG_SEND_RETRY_BACKOFF_SECONDS": "send_retry_backoff_seconds",
    "CG_READ_POLL_SECONDS": "read_poll_seconds",
    "CG_LOG_LEVEL": "log_level",
    "CG_HTTP_TIMEOUT_SECONDS": "http_timeout_seconds",
}


def _apply_env_overrides(
    merged: dict[str, Any],
    env: dict[str, str],
) -> dict[str, Any]:
    """
    Apply .env overrides to the merged config dict.

    Types are coerced:
        - int fields: ``int(value)`` (with error fallback — keep old value)
        - list fields: comma-separated split + strip
    """
    result = dict(merged)

    for env_key, field_name in _ENV_KEY_TO_FIELD.items():
        if env_key not in env:
            continue
        raw = env[env_key].strip()
        if not raw:
            continue

        current = result.get(field_name)

        try:
            if isinstance(current, int):
                result[field_name] = int(raw)
            elif isinstance(current, list):
                result[field_name] = [
                    item.strip() for item in raw.split(",") if item.strip()
                ]
            else:
                result[field_name] = raw
        except (ValueError, AttributeError):
            # Malformed env value — keep the current default and move on
            continue

    # Special handling for channels and event IDs (list-of-strings / list-of-ints)
    if "CG_EVENT_CHANNELS" in env:
        channels = [
            c.strip() for c in env["CG_EVENT_CHANNELS"].split(",") if c.strip()
        ]
        if channels:
            result["event_channels"] = channels

    if "CG_EVENT_IDS" in env:
        try:
            ids = [
                int(i.strip())
                for i in env["CG_EVENT_IDS"].split(",")
                if i.strip()
            ]
            result["event_ids_to_capture"] = ids
        except ValueError:
            pass

    return result


# ============================================================================
# LOGGING SETUP HELPER
# ============================================================================

def configure_logging(config: CollectorConfig) -> None:
    """
    Set up the standard logging configuration for the collector.

    Called once by ``main.py`` after loading config. Sets up:
        - Console handler (stderr)
        - Rotating file handler at ``LOG_FILE``
        - Format with timestamp, level, module
    """
    import logging.handlers

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    # Clear any pre-existing handlers (idempotent re-configuration)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    # Console
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)

    # File (rotating, 10 MB × 5 = 50 MB total)
    file_handler = logging.handlers.RotatingFileHandler(
        filename=str(LOG_FILE),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Quiet noisy third-party loggers unless DEBUG
    if level != logging.DEBUG:
        for noisy in ("urllib3", "httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "CollectorConfig",
    "DEFAULTS",
    "PROGRAM_DATA_DIR",
    "CONFIG_FILE",
    "COLLECTOR_ID_FILE",
    "QUEUE_FILE",
    "LOG_DIR",
    "LOG_FILE",
    "ensure_directories",
    "configure_logging",
]