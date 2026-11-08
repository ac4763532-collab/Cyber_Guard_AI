"""
CyberGuard AI — Linux Collector Configuration
============================================================================

Foundation for the Linux collector. Mirrors the Windows config.py structure
but adapts for the Linux platform:

    Windows                        Linux
    ─────────────────────────      ─────────────────────────────
    %PROGRAMDATA%\\CyberGuard       /etc/cyberguard/collector/
    config.json                    config.json (mode 0600)
    collector_id                   collector_id (persistent UUID)
    queue.db                       queue.db (SQLite)
    logs\\collector.log             /var/log/cyberguard/collector.log
    Windows Event Log              journalctl + /var/log/* files
    DPAPI (credential)             Fernet symmetric encryption
    Windows Service (SCM)          systemd unit

Layout (Linux FHS standard)
---------------------------
    /etc/cyberguard/collector/          — config (root-owned, mode 0640)
        config.json
        collector_id
    /var/lib/cyberguard/collector/      — state (root-owned, mode 0750)
        queue.db
        credential.enc                  — Fernet-encrypted credential
        fernet.key                      — Fernet symmetric key (mode 0600)
    /var/log/cyberguard/                — logs (mode 0750)
        collector.log
        collector.log.1 ... etc

Dev fallback: if the script is NOT running as root, or /etc is not
writable, all paths fall back to:

    ~/.cyberguard/config/
    ~/.cyberguard/state/
    ~/.cyberguard/logs/

This lets developers test on their laptop without sudo. Production
installs (via install_service.sh running as root) use the FHS paths.

Priority (highest to lowest)
----------------------------
    1. Explicit overrides (passed by main.py from CLI flags)
    2. .env file (systemd EnvironmentFile-compatible)
    3. config.json (written after enrollment)
    4. DEFAULTS dict

Linux-specific settings
-----------------------
    use_journald:       bool     — read from systemd journal (default True)
    use_log_files:      bool     — read from /var/log/* files (default True)
    log_files:          list[str] — specific file paths to tail
    journald_units:     list[str] — specific units to filter (empty = all)

The reader supports BOTH simultaneously — most Linux distros need both
(journald for systemd units, files for services that log directly to
/var/log/*.log rather than to journald).

This file requires no external dependencies beyond the stdlib. Fernet
encryption lives in credential_store.py; journald access lives in
log_reader.py.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import uuid
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


# ============================================================================
# PATH RESOLUTION
# ============================================================================

def _is_root() -> bool:
    """Return True if the current process has UID 0."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _resolve_paths() -> tuple[Path, Path, Path]:
    """
    Return (config_dir, state_dir, log_dir).

    Production (root + writable /etc):
        /etc/cyberguard/collector      (config)
        /var/lib/cyberguard/collector  (state)
        /var/log/cyberguard            (logs)

    Dev fallback:
        ~/.cyberguard/config
        ~/.cyberguard/state
        ~/.cyberguard/logs
    """
    if _is_root() and Path("/etc").is_dir() and os.access("/etc", os.W_OK):
        return (
            Path("/etc/cyberguard/collector"),
            Path("/var/lib/cyberguard/collector"),
            Path("/var/log/cyberguard"),
        )
    home = Path.home()
    return (
        home / ".cyberguard" / "config",
        home / ".cyberguard" / "state",
        home / ".cyberguard" / "logs",
    )


CONFIG_DIR, STATE_DIR, LOG_DIR = _resolve_paths()
CONFIG_FILE: Path = CONFIG_DIR / "config.json"
COLLECTOR_ID_FILE: Path = CONFIG_DIR / "collector_id"
QUEUE_FILE: Path = STATE_DIR / "queue.db"
CREDENTIAL_FILE: Path = STATE_DIR / "credential.enc"
FERNET_KEY_FILE: Path = STATE_DIR / "fernet.key"
LOG_FILE: Path = LOG_DIR / "collector.log"


def ensure_directories() -> None:
    """
    Create directories with FHS-appropriate permissions.

    Root:
        config dir: 0750 (root:cyberguard readable by group)
        state dir:  0750
        log dir:    0755 (readable by log-aggregation users)

    Non-root (dev):
        All 0700 — only the current user.
    """
    for directory, mode in (
        (CONFIG_DIR, 0o750 if _is_root() else 0o700),
        (STATE_DIR, 0o750 if _is_root() else 0o700),
        (LOG_DIR, 0o755 if _is_root() else 0o700),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, mode)
        except OSError:
            pass


# ============================================================================
# DEFAULTS
# ============================================================================

DEFAULTS: dict[str, Any] = {
    # Backend connection
    "backend_url": "http://localhost:8000",
    "credential": None,                       # populated after enrollment

    # Event sources
    "use_journald": True,
    "use_log_files": True,
    "log_files": [
        "/var/log/auth.log",       # Debian/Ubuntu auth
        "/var/log/secure",         # RHEL/CentOS auth
        "/var/log/syslog",         # Debian/Ubuntu system
        "/var/log/messages",       # RHEL/CentOS system
        "/var/log/audit/audit.log", # auditd
        "/var/log/kern.log",       # kernel
        "/var/log/sudo.log",       # sudo (if configured)
    ],
    "journald_units": [],          # empty = all units

    # Reader behavior
    "read_poll_seconds": 5,
    "journald_batch_size": 100,    # events per journalctl --since call
    "file_tail_batch_lines": 100,  # lines read per file poll
    "max_events_per_poll": 500,

    # Batching & sending
    "batch_size": 100,
    "batch_interval_seconds": 10,
    "send_retry_max": 5,
    "send_retry_backoff_seconds": 5,
    "http_timeout_seconds": 30,

    # Heartbeat
    "heartbeat_interval_seconds": 60,

    # Local queue
    "max_queue_size": 10000,

    # File watching positions (updated by reader to persist across restarts)
    "file_positions": {},          # {"/var/log/auth.log": <byte_offset>, ...}
    "journald_cursor": None,       # systemd cursor for incremental reads

    # Logging / metadata
    "log_level": "INFO",
    "agent_version": "0.1.0",
}


# ============================================================================
# ENV FILE LOADER (systemd EnvironmentFile-compatible)
# ============================================================================

def _load_env_file(path: Path) -> dict[str, str]:
    """
    Parse a systemd-style env file.

    Supports:
        KEY=value
        KEY="quoted value"
        KEY='quoted value'
        # comments
        (blank lines)

    Not supported: variable expansion, multi-line values.
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
        if (
            len(raw_value) >= 2
            and raw_value[0] == raw_value[-1]
            and raw_value[0] in ('"', "'")
        ):
            raw_value = raw_value[1:-1]
        env[key] = raw_value
    return env


def _env_file_path() -> Path:
    """
    Where to look for .env in dev.

    Two candidates checked in priority:
      1. /etc/cyberguard/collector/.env  (production — systemd EnvironmentFile)
      2. <script_dir>/.env               (dev — next to config.py)
    """
    fhs_path = CONFIG_DIR / ".env"
    if fhs_path.exists():
        return fhs_path
    return Path(__file__).resolve().parent / ".env"


# ============================================================================
# COLLECTOR ID
# ============================================================================

def _load_or_create_collector_id() -> uuid.UUID:
    """
    Load or generate the persistent collector UUID.

    The UUID lives in config_dir/collector_id. It survives restarts,
    reinstalls (if you copy the file), and re-enrollments. Only
    delete the file if you want the collector to present itself as
    a brand-new device to the backend.
    """
    if COLLECTOR_ID_FILE.exists():
        try:
            content = COLLECTOR_ID_FILE.read_text(encoding="utf-8").strip()
            return uuid.UUID(content)
        except (ValueError, OSError) as exc:
            raise RuntimeError(
                f"collector_id file is corrupt: {COLLECTOR_ID_FILE}. "
                f"Delete it to regenerate (existing installation will be "
                f"orphaned). Error: {exc}"
            )

    new_id = uuid.uuid4()
    COLLECTOR_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    COLLECTOR_ID_FILE.write_text(str(new_id), encoding="utf-8")
    try:
        os.chmod(COLLECTOR_ID_FILE, 0o640 if _is_root() else 0o600)
    except OSError:
        pass
    return new_id


# ============================================================================
# CONFIG DATACLASS
# ============================================================================

@dataclass
class CollectorConfig:
    """
    Typed view of the Linux collector's configuration.

    Field-by-field mirror of the Windows CollectorConfig with Linux-
    specific additions (journald, log_files, file_positions,
    journald_cursor).
    """

    # Backend connection
    backend_url: str
    credential: str | None

    # Identity
    collector_id: uuid.UUID

    # Event sources — Linux specific
    use_journald: bool
    use_log_files: bool
    log_files: list[str]
    journald_units: list[str]

    # Reader behavior
    read_poll_seconds: int
    journald_batch_size: int
    file_tail_batch_lines: int
    max_events_per_poll: int

    # Batching & sending
    batch_size: int
    batch_interval_seconds: int
    send_retry_max: int
    send_retry_backoff_seconds: int
    http_timeout_seconds: int

    # Heartbeat
    heartbeat_interval_seconds: int

    # Queue
    max_queue_size: int

    # Persistence of reader state (updated during run)
    file_positions: dict[str, int]
    journald_cursor: str | None

    # Logging / metadata
    log_level: str
    agent_version: str

    # Runtime-only
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

        Ensures directories exist, loads/creates collector_id, validates
        every field, and returns a fully-typed CollectorConfig instance.
        """
        ensure_directories()

        merged: dict[str, Any] = dict(DEFAULTS)

        # ── 3. config.json
        if CONFIG_FILE.exists():
            try:
                file_config = json.loads(
                    CONFIG_FILE.read_text(encoding="utf-8")
                )
                if isinstance(file_config, dict):
                    merged.update(file_config)
            except (json.JSONDecodeError, OSError) as exc:
                raise RuntimeError(
                    f"config.json is corrupt: {CONFIG_FILE}. Error: {exc}"
                )

        # ── 2. .env overrides
        env = _load_env_file(_env_file_path())
        if env:
            merged = _apply_env_overrides(merged, env)

        # ── 1. Caller overrides
        if overrides:
            merged.update(overrides)

        # ── collector_id from disk (file is source of truth)
        merged["collector_id"] = _load_or_create_collector_id()

        # ── Build the dataclass (ignore unknown keys for forward compat)
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in merged.items() if k in known_fields}
        config = cls(**filtered)

        config.is_enrolled = bool(config.credential)
        config.validate()
        return config

    # ====================================================================
    # SAVE
    # ====================================================================

    def save(self) -> None:
        """
        Persist configuration to config.json atomically.

        Sets mode 0640 (root + group) in production, 0600 in dev.
        The credential blob (if present) is already encrypted by
        credential_store.py — this class never sees plaintext.
        """
        ensure_directories()

        payload = {
            "backend_url": self.backend_url,
            "credential": self.credential,
            "use_journald": self.use_journald,
            "use_log_files": self.use_log_files,
            "log_files": list(self.log_files),
            "journald_units": list(self.journald_units),
            "read_poll_seconds": self.read_poll_seconds,
            "journald_batch_size": self.journald_batch_size,
            "file_tail_batch_lines": self.file_tail_batch_lines,
            "max_events_per_poll": self.max_events_per_poll,
            "batch_size": self.batch_size,
            "batch_interval_seconds": self.batch_interval_seconds,
            "send_retry_max": self.send_retry_max,
            "send_retry_backoff_seconds": self.send_retry_backoff_seconds,
            "http_timeout_seconds": self.http_timeout_seconds,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "max_queue_size": self.max_queue_size,
            "file_positions": dict(self.file_positions or {}),
            "journald_cursor": self.journald_cursor,
            "log_level": self.log_level,
            "agent_version": self.agent_version,
        }

        # Atomic write
        tmp = CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o640 if _is_root() else 0o600)
        except OSError:
            pass
        tmp.replace(CONFIG_FILE)

    # ====================================================================
    # VALIDATE
    # ====================================================================

    def validate(self) -> None:
        """
        Enforce every constraint. Raises RuntimeError on any violation.

        Aggregates all errors into one exception so the operator sees
        the full list — not just the first problem.
        """
        errors: list[str] = []

        if not self.backend_url:
            errors.append("backend_url is empty")
        elif not self.backend_url.startswith(("http://", "https://")):
            errors.append(
                f"backend_url must start with http:// or https://, "
                f"got {self.backend_url!r}"
            )

        if not (1 <= self.batch_size <= 1000):
            errors.append(
                f"batch_size must be 1–1000, got {self.batch_size}"
            )

        if self.batch_interval_seconds < 1:
            errors.append(
                f"batch_interval_seconds must be >= 1, "
                f"got {self.batch_interval_seconds}"
            )

        if self.heartbeat_interval_seconds < 10:
            errors.append(
                f"heartbeat_interval_seconds must be >= 10, "
                f"got {self.heartbeat_interval_seconds}"
            )

        if self.max_queue_size < 100:
            errors.append(
                f"max_queue_size must be >= 100, got {self.max_queue_size}"
            )

        if self.read_poll_seconds < 1:
            errors.append(
                f"read_poll_seconds must be >= 1, "
                f"got {self.read_poll_seconds}"
            )

        if self.send_retry_max < 1:
            errors.append(
                f"send_retry_max must be >= 1, got {self.send_retry_max}"
            )

        if self.send_retry_backoff_seconds < 1:
            errors.append(
                f"send_retry_backoff_seconds must be >= 1, "
                f"got {self.send_retry_backoff_seconds}"
            )

        if self.http_timeout_seconds < 5:
            errors.append(
                f"http_timeout_seconds must be >= 5, "
                f"got {self.http_timeout_seconds}"
            )

        if self.log_level not in (
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL",
        ):
            errors.append(
                f"log_level must be one of DEBUG/INFO/WARNING/ERROR/CRITICAL, "
                f"got {self.log_level!r}"
            )

        if not self.use_journald and not self.use_log_files:
            errors.append(
                "At least one of use_journald or use_log_files must be True"
            )

        if self.use_log_files and not self.log_files:
            errors.append(
                "log_files must be non-empty when use_log_files is True"
            )

        if self.journald_batch_size < 1:
            errors.append(
                f"journald_batch_size must be >= 1, "
                f"got {self.journald_batch_size}"
            )

        if self.file_tail_batch_lines < 1:
            errors.append(
                f"file_tail_batch_lines must be >= 1, "
                f"got {self.file_tail_batch_lines}"
            )

        if self.max_events_per_poll < 1:
            errors.append(
                f"max_events_per_poll must be >= 1, "
                f"got {self.max_events_per_poll}"
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
        """Return a dict safe to log — credential excluded."""
        return {
            "backend_url": self.backend_url,
            "collector_id": str(self.collector_id),
            "is_enrolled": self.is_enrolled,
            "use_journald": self.use_journald,
            "use_log_files": self.use_log_files,
            "log_files_count": len(self.log_files),
            "journald_units_count": len(self.journald_units),
            "read_poll_seconds": self.read_poll_seconds,
            "batch_size": self.batch_size,
            "batch_interval_seconds": self.batch_interval_seconds,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "max_queue_size": self.max_queue_size,
            "log_level": self.log_level,
            "agent_version": self.agent_version,
        }


# ============================================================================
# ENV OVERRIDE MAPPING
# ============================================================================

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
    "CG_JOURNALD_BATCH_SIZE": "journald_batch_size",
    "CG_FILE_TAIL_BATCH_LINES": "file_tail_batch_lines",
    "CG_MAX_EVENTS_PER_POLL": "max_events_per_poll",
}


def _apply_env_overrides(
    merged: dict[str, Any],
    env: dict[str, str],
) -> dict[str, Any]:
    """Apply .env file overrides, coercing types."""
    result = dict(merged)

    for env_key, field_name in _ENV_KEY_TO_FIELD.items():
        if env_key not in env:
            continue
        raw = env[env_key].strip()
        if not raw:
            continue

        current = result.get(field_name)

        try:
            if isinstance(current, bool):
                result[field_name] = raw.lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                result[field_name] = int(raw)
            elif isinstance(current, list):
                result[field_name] = [
                    item.strip() for item in raw.split(",") if item.strip()
                ]
            else:
                result[field_name] = raw
        except (ValueError, AttributeError):
            continue

    # Bool toggles for journald / file sources
    if "CG_USE_JOURNALD" in env:
        result["use_journald"] = env["CG_USE_JOURNALD"].strip().lower() in (
            "1", "true", "yes", "on",
        )
    if "CG_USE_LOG_FILES" in env:
        result["use_log_files"] = env["CG_USE_LOG_FILES"].strip().lower() in (
            "1", "true", "yes", "on",
        )

    # Comma-separated list overrides
    if "CG_LOG_FILES" in env:
        files = [
            f.strip() for f in env["CG_LOG_FILES"].split(",") if f.strip()
        ]
        if files:
            result["log_files"] = files

    if "CG_JOURNALD_UNITS" in env:
        units = [
            u.strip() for u in env["CG_JOURNALD_UNITS"].split(",") if u.strip()
        ]
        result["journald_units"] = units

    return result


# ============================================================================
# LOGGING SETUP
# ============================================================================

def configure_logging(config: CollectorConfig) -> None:
    """
    Configure root logger with console + rotating file handlers.

    Same format as the Windows collector:
        2026-11-07 14:23:45 [INFO] app.agents.log_analysis: message
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.log_level, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    # Console (stderr — journald captures it for the systemd unit)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root.addHandler(console)

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=str(LOG_FILE),
        maxBytes=10 * 1024 * 1024,   # 10 MB per file
        backupCount=5,               # keep 5 rotated files
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    try:
        os.chmod(LOG_FILE, 0o640 if _is_root() else 0o600)
    except OSError:
        pass

    # Silence noisy third-party loggers unless DEBUG
    if level != logging.DEBUG:
        for noisy in ("urllib3", "httpx", "httpcore", "systemd"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "CollectorConfig",
    "DEFAULTS",
    "CONFIG_DIR",
    "STATE_DIR",
    "LOG_DIR",
    "CONFIG_FILE",
    "COLLECTOR_ID_FILE",
    "QUEUE_FILE",
    "CREDENTIAL_FILE",
    "FERNET_KEY_FILE",
    "LOG_FILE",
    "ensure_directories",
    "configure_logging",
]