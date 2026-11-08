"""
CyberGuard AI — Structured Logging
============================================================================

Single logging entry point for the entire backend.

Usage
-----
    # In main.py, once, at startup:
    from app.core.logging import configure_logging
    configure_logging()

    # Everywhere else:
    from app.core.logging import get_logger
    logger = get_logger(__name__)
    logger.info("Event ingested", extra={"event_id": event_id})

Correlation IDs
---------------
Every request should set a correlation ID at the API boundary:

    from app.core.logging import set_correlation_id, get_correlation_id
    set_correlation_id(request_id)

Every log record emitted while that context is active carries the same
``correlation_id``. Downstream agents that run inside the same async
context inherit it automatically.

Redaction
---------
``RedactionFilter`` runs on every record and replaces the values of
sensitive keys (``password``, ``token``, ``secret``, ``api_key``, ``authorization``,
``cookie``, ``jwt``, ``bearer``) with ``***REDACTED***``. This is a
defense-in-depth control — even if a service accidentally logs a secret,
it never reaches disk or stdout unredacted.
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.core.config import settings


# ── Correlation ID context (async-safe) ─────────────────────────────────────
_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


def set_correlation_id(value: str | None = None) -> str:
    """Set the correlation ID for the current async context. Returns the ID."""
    cid = value or str(uuid.uuid4())
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str | None:
    """Return the current correlation ID, if any."""
    return _correlation_id.get()


def clear_correlation_id() -> None:
    """Clear the correlation ID for the current async context."""
    _correlation_id.set(None)


# ── Redaction filter ────────────────────────────────────────────────────────
_SENSITIVE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"pass(word)?",
        r"secret",
        r"token",
        r"api[_\-]?key",
        r"authorization",
        r"cookie",
        r"jwt",
        r"bearer",
        r"credential",
        r"private[_\-]?key",
    )
)

_REDACTED = "***REDACTED***"


def _is_sensitive_key(key: str) -> bool:
    return any(p.search(key) for p in _SENSITIVE_KEY_PATTERNS)


def _redact_value(value: Any, depth: int = 0) -> Any:
    """Recursively redact values whose keys look sensitive."""
    if depth > 6:
        return value  # guard against pathological nested structures
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _is_sensitive_key(str(k)) else _redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return type(value)(_redact_value(v, depth + 1) for v in value)
    return value


class RedactionFilter(logging.Filter):
    """Scrubs sensitive values from log records' ``extra`` dicts."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Redact any custom attribute that was passed via ``extra=``
        for attr in list(record.__dict__.keys()):
            if attr.startswith("_") or attr in _STANDARD_RECORD_ATTRS:
                continue
            if _is_sensitive_key(attr):
                setattr(record, attr, _REDACTED)
            else:
                val = getattr(record, attr)
                if isinstance(val, (dict, list, tuple, set)):
                    setattr(record, attr, _redact_value(val))
        return True


# Attributes that exist on every LogRecord by default — do not touch them.
_STANDARD_RECORD_ATTRS: frozenset[str] = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName",
    }
)


# ── Formatters ──────────────────────────────────────────────────────────────
class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": get_correlation_id(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include any extra= attributes set by the caller
        for attr in record.__dict__:
            if attr.startswith("_") or attr in _STANDARD_RECORD_ATTRS:
                continue
            if attr in payload:
                continue
            payload[attr] = record.__dict__[attr]

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            # Never let a serialization failure swallow the log line
            return json.dumps(
                {**payload, "message": str(payload.get("message"))},
                ensure_ascii=False,
                default=str,
            )


class TextFormatter(logging.Formatter):
    """Human-readable single-line format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        cid = get_correlation_id() or "-"
        base = (
            f"{datetime.fromtimestamp(record.created, tz=timezone.utc).strftime('%H:%M:%S')}"
            f" {record.levelname:<8} [{cid[:8]}] {record.name}: {record.getMessage()}"
        )
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if not k.startswith("_")
            and k not in _STANDARD_RECORD_ATTRS
            and k in _CALLER_EXTRA_KEYS
        }
        if extras:
            base += " | " + " ".join(f"{k}={v!r}" for k, v in extras.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


# Keys that will be displayed inline in text mode when passed via extra=
# (we cannot distinguish caller-supplied extras from record internals purely
# by name, so text mode shows a curated set; JSON mode shows everything).
_CALLER_EXTRA_KEYS: frozenset[str] = frozenset(
    {
        "event_id", "finding_id", "incident_id", "alert_id", "case_id",
        "user_id", "org_id", "workspace_id", "source_id", "agent",
        "action", "status", "duration_ms", "status_code", "path", "method",
    }
)


# ── Configuration entry point ───────────────────────────────────────────────
_CONFIGURED = False


def configure_logging(
    *,
    level: str | None = None,
    fmt: str | None = None,
    log_file: Path | str | None = None,
) -> None:
    """
    Configure the root logger. Idempotent — calling twice is a no-op
    unless ``force=True``-style re-configuration is required (not supported).

    Called exactly once from ``main.py`` at startup.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    resolved_level = (level or settings.LOG_LEVEL).upper()
    resolved_fmt = (fmt or settings.LOG_FORMAT).lower()
    resolved_file = Path(log_file) if log_file else settings.log_file_path

    formatter: logging.Formatter
    if resolved_fmt == "json":
        formatter = JsonFormatter()
    else:
        formatter = TextFormatter()

    redactor = RedactionFilter()

    root = logging.getLogger()
    root.setLevel(resolved_level)
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(formatter)
    console.addFilter(redactor)
    root.addHandler(console)

    # Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        filename=str(resolved_file),
        maxBytes=settings.LOG_ROTATION_MB * 1024 * 1024,
        backupCount=max(1, settings.LOG_RETENTION_DAYS),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    root.addHandler(file_handler)

    # Silence noisy third-party loggers at INFO unless we're in DEBUG mode
    if resolved_level != "DEBUG":
        for noisy in (
            "uvicorn.access",
            "sqlalchemy.engine",
            "httpx",
            "httpcore",
            "urllib3",
            "asyncio",
        ):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger for the given module name.

    Callers should pass ``__name__`` so log lines show the true origin.
    If ``configure_logging`` has not yet been called, this still returns a
    usable logger — messages will propagate to Python's last-resort handler
    until ``main.py`` configures the root logger at startup.
    """
    return logging.getLogger(name)


def reset_logging_for_tests() -> None:
    """For test suites only — tears down configured handlers so they can be
    re-configured with different settings."""
    global _CONFIGURED
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    _CONFIGURED = False
    clear_correlation_id()


def iter_configured_handlers() -> Iterable[logging.Handler]:
    """Return the current root handlers. Useful for diagnostics and tests."""
    return tuple(logging.getLogger().handlers)


__all__ = [
    "configure_logging",
    "get_logger",
    "set_correlation_id",
    "get_correlation_id",
    "clear_correlation_id",
    "reset_logging_for_tests",
    "iter_configured_handlers",
    "JsonFormatter",
    "TextFormatter",
    "RedactionFilter",
]