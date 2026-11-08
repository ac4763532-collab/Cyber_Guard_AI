"""
CyberGuard AI — Linux Event Normalizer
============================================================================

Converts raw Linux log entries (from ``log_reader.py``) into CyberGuard's
canonical event shape (``EventIngestRequest`` from ``app/schemas/event.py``).

Why Linux normalization is fundamentally harder than Windows
------------------------------------------------------------
Windows events have a stable numeric Event ID (4624, 4625, 4648, ...).
The mapping is a dict lookup — Event ID → (event_type, category,
severity). Fast, deterministic, exhaustive.

Linux has no equivalent. A "failed login" from sshd is not signalled
by a numeric ID — it's the human-readable string:

    "Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2"

The normalizer must **pattern-match** the message text to classify it.
This is:

    - More fragile (log format changes between distros/versions)
    - Less exhaustive (only patterns we know about are classified)
    - But tractable (the ~30 most important patterns cover >95% of
      security-relevant Linux activity)

Unknown events are NOT dropped — they fall back to
``syslog.<process>.<level>`` with a generic category. The finding
survives; it's just less precisely classified.

Two-stage normalization
-----------------------
    Stage 1: **Source-format parsing** (in log_reader.py)
        - journald JSON → normalized dict
        - syslog RFC 3164/5424 text → parsed dict

    Stage 2: **Semantic classification** (this file)
        - Message text → (event_type, category, severity, action, outcome)
        - Entity extraction (username, source_ip, ...) from the message

This file owns Stage 2. It assumes Stage 1 has produced a dict with
at minimum ``message``, ``source``, and optionally ``timestamp``,
``hostname``, ``process``, ``identifier``, ``level``, ``pid``,
``file_path``.

Pattern catalogue
-----------------
~30 patterns covering:

    SSH / auth:
        - failed_login          (Failed password / Failed publickey)
        - invalid_user_login    (Invalid user X from Y)
        - successful_login      (Accepted password/publickey)
        - login_root            (Accepted ... for root)
        - session_opened        (pam_unix session opened)
        - session_closed        (pam_unix session closed)

    Privilege:
        - sudo_command          (USER=root ; COMMAND=/bin/bash)
        - sudo_session          (pam_unix(sudo:session))
        - sudo_failure          (3 incorrect password attempts)
        - su_switch             (pam_unix(su:session))

    Accounts:
        - user_created          (new user: name=...)
        - user_deleted          (delete user)
        - user_modified         (usermod)
        - password_changed      (password changed for ...)
        - group_created         (new group: name=...)
        - group_member_added    (added to group)

    Kernel / system:
        - oom_kill              (Out of memory: Killed process X)
        - segfault              (segfault at ...)
        - kernel_panic          (Kernel panic)
        - firewall_block        (UFW BLOCK / iptables DROP)
        - service_started       (Started X.service)
        - service_stopped       (Stopped X.service)
        - service_failed        (Failed to start X.service)

    Audit:
        - audit_execve          (type=EXECVE argc=... a0=...)
        - audit_user_auth       (type=USER_AUTH)
        - audit_avc             (type=AVC denied)

    Cron / scheduled:
        - cron_execution        (CRON[...] (user) CMD (...))

    Fallback:
        - syslog.<process>.<level>

Severity mapping
----------------
Each pattern carries its own base severity. Additionally, the syslog
priority (0–7) acts as a floor:

    Priority 0–2 (emerg/crit)   → at least CRITICAL
    Priority 3   (err)          → at least HIGH
    Priority 4   (warning)      → at least MEDIUM

This means a "Failed password" line logged at INFO by sshd still comes
out as MEDIUM (from the pattern), but a "Kernel panic" logged at
CRITICAL stays CRITICAL (from the priority floor).

Entity extraction
-----------------
Named capture groups in each pattern feed entity fields directly:

    username, source_ip, destination_ip, source_port, destination_port,
    process_name, file_path

Any *other* named groups (e.g. ``command`` from sudo, ``target_user``
from su) go into ``normalized_payload`` under ``linux_<group>`` so
agents can inspect them without re-parsing the raw message.

Time
----
The ``timestamp`` field (ISO string from log_reader) is preferred. If
missing or malformed, we fall back to ``datetime.now(UTC)``. The
backend's fingerprint dedup means a slightly-wrong timestamp won't
create duplicates; it just shifts the event's position in the
timeline.

Usage
-----
    from event_normalizer import normalize

    for raw_entry in log_reader.poll():
        payload = normalize(raw_entry)
        if payload is None:
            continue
        queue.enqueue(payload)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.models.enums import EventCategory, EventSeverity


logger = logging.getLogger(__name__)


# ============================================================================
# PATTERN CATALOGUE
# ============================================================================
# Each pattern is a dict:
#   event_type       — stable string used by agent rules
#   regex            — compiled regex, .search() applied to message text
#   category         — EventCategory enum
#   severity         — base EventSeverity
#   action, outcome  — optional action/outcome strings
#
# Named capture groups feed entity fields. Extra groups flow into
# normalized_payload. The order in this list determines match priority
# — more specific patterns go first.

_PATTERNS: list[dict[str, Any]] = [
    # ── SSH: Failed login (most specific form first) ───────────────────
    {
        "event_type": "failed_login",
        "regex": re.compile(
            r"Failed (?:password|publickey|keyboard-interactive/pam) "
            r"for (?:invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>\S+)"
            r"(?: port (?P<source_port>\d+))?",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "login",
        "outcome": "failure",
    },
    {
        "event_type": "invalid_user_login",
        "regex": re.compile(
            r"Invalid user (?P<username>\S+) "
            r"from (?P<source_ip>\S+)"
            r"(?: port (?P<source_port>\d+))?",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "login",
        "outcome": "failure",
    },
    # ── SSH: Successful login ──────────────────────────────────────────
    {
        "event_type": "successful_login",
        "regex": re.compile(
            r"Accepted (?:password|publickey|keyboard-interactive/pam) "
            r"for (?P<username>\S+) "
            r"from (?P<source_ip>\S+)"
            r"(?: port (?P<source_port>\d+))?",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.LOW,
        "action": "login",
        "outcome": "success",
    },
    # ── SSH: Session open / close ──────────────────────────────────────
    {
        "event_type": "session_opened",
        "regex": re.compile(
            r"session opened for user (?P<username>\S+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "session_open",
        "outcome": "success",
    },
    {
        "event_type": "session_closed",
        "regex": re.compile(
            r"session closed for user (?P<username>\S+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "session_close",
        "outcome": "success",
    },
    # ── SSH: Root login ────────────────────────────────────────────────
    {
        "event_type": "login_root",
        "regex": re.compile(
            r"Accepted (?:password|publickey) for root "
            r"from (?P<source_ip>\S+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.HIGH,
        "action": "login",
        "outcome": "success",
    },
    # ── SSH: Disconnect ────────────────────────────────────────────────
    {
        "event_type": "session_disconnected",
        "regex": re.compile(
            r"(?:Disconnected from (?:user |authenticating )?)"
            r"(?:(?P<username>\S+) )?"
            r"(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
            r"(?: port (?P<source_port>\d+))?",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "disconnect",
        "outcome": "success",
    },
    # ── sudo: full command record ──────────────────────────────────────
    # Example: "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    {
        "event_type": "sudo_command",
        "regex": re.compile(
            r"(?P<username>\S+) : (?:TTY=\S+ ; )?"
            r"(?:PWD=\S+ ; )?"
            r"USER=(?P<target_user>\S+) ; "
            r"COMMAND=(?P<command>.+)$",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "sudo",
        "outcome": "success",
    },
    # ── sudo: session (opened/closed) ──────────────────────────────────
    {
        "event_type": "sudo_session",
        "regex": re.compile(
            r"pam_unix\(sudo:session\): session "
            r"(?P<session_action>opened|closed) "
            r"for user (?P<username>\S+)",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.LOW,
        "action": "sudo_session",
        "outcome": None,
    },
    # ── sudo: auth failure ─────────────────────────────────────────────
    {
        "event_type": "sudo_failure",
        "regex": re.compile(
            r"(?P<username>\S+) : \d+ incorrect password attempts",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.HIGH,
        "action": "sudo",
        "outcome": "failure",
    },
    # ── su: privilege switch ───────────────────────────────────────────
    {
        "event_type": "su_switch",
        "regex": re.compile(
            r"pam_unix\(su(?:-l)?:session\): session "
            r"(?P<session_action>opened|closed) "
            r"for user (?P<username>\S+)",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "su",
        "outcome": None,
    },
    # ── Accounts: created / deleted / modified ─────────────────────────
    {
        "event_type": "user_created",
        "regex": re.compile(
            r"new user: name=(?P<username>[^,\s]+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "create_account",
        "outcome": "success",
    },
    {
        "event_type": "user_deleted",
        "regex": re.compile(
            r"delete user ['\u2018\u2019]?(?P<username>[^'\u2018\u2019\s]+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "delete_account",
        "outcome": "success",
    },
    {
        "event_type": "user_modified",
        "regex": re.compile(
            r"(?:usermod|chage).*(?:user|account)\s+['\u2018\u2019]?(?P<username>[^'\u2018\u2019\s]+)",
            re.IGNORECASE,
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "modify_account",
        "outcome": "success",
    },
    {
        "event_type": "password_changed",
        "regex": re.compile(
            r"password changed for (?P<username>\S+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "change_password",
        "outcome": "success",
    },
    {
        "event_type": "group_created",
        "regex": re.compile(
            r"new group: name=(?P<group_name>[^,\s]+)",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "create_group",
        "outcome": "success",
    },
    {
        "event_type": "group_member_added",
        "regex": re.compile(
            r"add ['\u2018\u2019]?(?P<username>[^'\u2018\u2019\s]+)['\u2018\u2019]? to group ['\u2018\u2019]?(?P<group_name>[^'\u2018\u2019\s]+)",
            re.IGNORECASE,
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.HIGH,
        "action": "add_to_group",
        "outcome": "success",
    },
    # ── Kernel: OOM kill ───────────────────────────────────────────────
    {
        "event_type": "oom_kill",
        "regex": re.compile(
            r"Out of memory: Kill(?:ed)? process \d+ \((?P<process_name>[^)]+)\)",
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.HIGH,
        "action": "oom_kill",
        "outcome": "success",
    },
    # ── Kernel: segfault ───────────────────────────────────────────────
    {
        "event_type": "segfault",
        "regex": re.compile(
            r"(?P<process_name>\S+)\[\d+\]: segfault at (?P<address>\S+)",
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.MEDIUM,
        "action": "crash",
        "outcome": "failure",
    },
    # ── Kernel: panic ──────────────────────────────────────────────────
    {
        "event_type": "kernel_panic",
        "regex": re.compile(
            r"Kernel panic|BUG: unable to handle kernel",
            re.IGNORECASE,
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.CRITICAL,
        "action": "kernel_panic",
        "outcome": "failure",
    },
    # ── Firewall: UFW BLOCK ────────────────────────────────────────────
    {
        "event_type": "firewall_block",
        "regex": re.compile(
            r"(?:UFW BLOCK|DROP|REJECT).*?"
            r"SRC=(?P<source_ip>\S+).*?"
            r"DST=(?P<destination_ip>\S+)"
            r"(?:.*?SPT=(?P<source_port>\d+))?"
            r"(?:.*?DPT=(?P<destination_port>\d+))?",
        ),
        "category": EventCategory.NETWORK,
        "severity": EventSeverity.LOW,
        "action": "block",
        "outcome": "failure",
    },
    # ── systemd: service lifecycle ─────────────────────────────────────
    {
        "event_type": "service_started",
        "regex": re.compile(
            r"Started (?P<unit_name>[^.]+\.service)",
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.INFO,
        "action": "service_start",
        "outcome": "success",
    },
    {
        "event_type": "service_stopped",
        "regex": re.compile(
            r"Stopped (?P<unit_name>[^.]+\.service)",
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.INFO,
        "action": "service_stop",
        "outcome": "success",
    },
    {
        "event_type": "service_failed",
        "regex": re.compile(
            r"Failed to start (?P<unit_name>[^.]+\.service)",
        ),
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.MEDIUM,
        "action": "service_start",
        "outcome": "failure",
    },
    # ── Audit: EXECVE ──────────────────────────────────────────────────
    {
        "event_type": "audit_execve",
        "regex": re.compile(
            r"type=EXECVE.*?a0=(?P<command>\S+)",
        ),
        "category": EventCategory.PROCESS,
        "severity": EventSeverity.LOW,
        "action": "execute",
        "outcome": "success",
    },
    # ── Audit: USER_AUTH ───────────────────────────────────────────────
    {
        "event_type": "audit_user_auth",
        "regex": re.compile(
            r"type=USER_AUTH.*?(?:acct|USER_ACCT)=(?:\"|\u201c)?(?P<username>[^\s\"\u201d]+)",
        ),
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "authenticate",
        "outcome": None,
    },
    # ── Audit: AVC denial (SELinux) ────────────────────────────────────
    {
        "event_type": "selinux_denial",
        "regex": re.compile(
            r"type=AVC.*?denied.*?(?:\{[^}]*\}\s+for\s+)?(?:pid=\d+\s+)?"
            r"(?:comm=\"(?P<process_name>[^\"]+)\")?",
        ),
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "access_denied",
        "outcome": "failure",
    },
    # ── Cron: command execution ────────────────────────────────────────
    {
        "event_type": "cron_execution",
        "regex": re.compile(
            r"\((?P<username>\S+)\) CMD \((?P<command>.+)\)",
        ),
        "category": EventCategory.PROCESS,
        "severity": EventSeverity.LOW,
        "action": "cron_run",
        "outcome": "success",
    },
]


# ============================================================================
# SEVERITY / LEVEL MAPS
# ============================================================================

_LEVEL_TO_SEVERITY: dict[str, EventSeverity] = {
    "critical": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
    "info": EventSeverity.INFO,
}

#: Priority floor — syslog priority raises the pattern's base severity.
_PRIORITY_FLOOR: dict[str, EventSeverity] = {
    "critical": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
}

_SEVERITY_RANK: dict[EventSeverity, int] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}

#: IP-like string — used to reject obviously-wrong captures.
_IPV4_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ============================================================================
# HELPERS
# ============================================================================

def _parse_time(value: Any) -> datetime:
    """Parse an ISO timestamp; fall back to now(UTC)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _clean_str(value: Any) -> str | None:
    """Strip a value to a non-empty string, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return None
    if not isinstance(value, str):
        value = str(value)
    stripped = value.strip()
    return stripped if stripped else None


def _clean_ip(value: Any) -> str | None:
    """Strip a captured IP; reject if it doesn't look like an IP."""
    cleaned = _clean_str(value)
    if cleaned is None:
        return None
    # Handle IPv6 in brackets or with leading zeros — just strip whitespace
    if _IPV4_LIKE.match(cleaned):
        return cleaned
    # IPv6 or anything else with a colon — keep as-is
    if ":" in cleaned:
        return cleaned
    # Not IP-shaped — reject
    return None


def _parse_int(value: Any) -> int | None:
    """Parse a captured int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _message_text(raw: dict[str, Any]) -> str | None:
    """
    Extract the message text from a raw entry.

    journald: ``message`` (already extracted by log_reader)
    file:     ``message`` (from syslog parser)
    """
    msg = raw.get("message")
    if isinstance(msg, list):
        # journald sometimes returns byte arrays for non-UTF-8 messages
        try:
            return bytes(msg).decode("utf-8", errors="replace")
        except Exception:
            return None
    return _clean_str(msg)


def _raise_severity_floor(
    base: EventSeverity,
    priority_level: str | None,
) -> EventSeverity:
    """
    Apply the syslog priority as a floor on the pattern's base severity.

    Example: a "Failed login" pattern says MEDIUM. But if sshd logged
    it at priority 3 (error → "high"), we bump to HIGH.

    The inverse never happens — patterns never LOWER a priority-implied
    severity, because pattern base severities are calibrated and stable.
    """
    if priority_level is None:
        return base

    floor = _PRIORITY_FLOOR.get(priority_level)
    if floor is None:
        return base

    if _SEVERITY_RANK.get(floor, 0) > _SEVERITY_RANK.get(base, 0):
        return floor
    return base


def _default_category_for_process(process: str | None) -> EventCategory:
    """Fallback category based on the process name."""
    if not process:
        return EventCategory.OTHER
    p = process.lower()
    if p in ("sshd", "login", "su", "sudo", "pam_unix", "polkitd"):
        return EventCategory.AUTHENTICATION
    if p in ("kernel", "systemd", "systemd-logind"):
        return EventCategory.SYSTEM
    if p in ("audit", "auditd"):
        return EventCategory.AUTHORIZATION
    if p in ("ufw", "iptables", "nft", "firewalld"):
        return EventCategory.NETWORK
    if p == "cron" or p == "crond":
        return EventCategory.PROCESS
    return EventCategory.OTHER


def _sanitize_event_type_name(value: str) -> str:
    """Sanitize a process name for use in an event_type string."""
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_") or "unknown"


# ============================================================================
# PAYLOAD BUILDERS
# ============================================================================

def _build_matched_payload(
    raw: dict[str, Any],
    pattern: dict[str, Any],
    match: re.Match[str],
) -> dict[str, Any]:
    """Build the event payload from a matched pattern."""
    groups = match.groupdict()

    # ── Entity extraction
    username = _clean_str(groups.get("username"))
    source_ip = _clean_ip(groups.get("source_ip"))
    destination_ip = _clean_ip(groups.get("destination_ip"))
    source_port = _parse_int(groups.get("source_port"))
    destination_port = _parse_int(groups.get("destination_port"))

    # Fall back to raw fields for process/hostname/pid
    process_name = _clean_str(
        groups.get("process_name")
        or raw.get("process")
        or raw.get("identifier")
    )
    process_id = _parse_int(raw.get("pid"))
    file_path = _clean_str(groups.get("file_path") or raw.get("file_path"))
    hostname = _clean_str(raw.get("hostname"))

    # ── Severity: pattern base, raised by priority floor
    base_severity = pattern["severity"]
    final_severity = _raise_severity_floor(base_severity, raw.get("level"))

    # ── Time
    event_time = _parse_time(raw.get("timestamp"))

    # ── normalized_payload: extra captured groups + source metadata
    normalized: dict[str, Any] = {}

    # All non-entity captured groups → linux_<name>
    for name, value in groups.items():
        if value is None:
            continue
        if name in (
            "username", "source_ip", "destination_ip",
            "source_port", "destination_port", "process_name", "file_path",
        ):
            continue
        normalized[f"linux_{name}"] = value

    # Source metadata
    normalized["source_format"] = raw.get("format", "unknown")
    if raw.get("source"):
        normalized["source_kind"] = raw.get("source")   # journald | file
    if raw.get("identifier"):
        normalized["syslog_identifier"] = raw.get("identifier")
    if raw.get("unit"):
        normalized["systemd_unit"] = raw.get("unit")
    if raw.get("level"):
        normalized["syslog_level"] = raw.get("level")

    # ── Build the final payload
    return {
        "event_time": event_time.isoformat(),
        "event_type": pattern["event_type"],
        "severity": final_severity.value,
        "category": pattern["category"].value,
        "action": pattern.get("action"),
        "outcome": pattern.get("outcome"),
        "username": username,
        "hostname": hostname,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "process_name": process_name,
        "process_id": process_id,
        "file_path": file_path,
        "url": None,
        "domain": None,
        "email_address": None,
        "hash_md5": None,
        "hash_sha256": None,
        "raw_payload": _extract_raw_payload(raw),
        "normalized_payload": normalized,
        "tags": _build_tags(raw, pattern["event_type"]),
    }


def _build_fallback_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Build the payload when no pattern matched.

    The event is still ingested with a generic ``syslog.<process>.<level>``
    event_type. Agents skip it (no rule matches), but it's in the DB
    and searchable.
    """
    process = _clean_str(raw.get("process") or raw.get("identifier")) or "unknown"
    level = (_clean_str(raw.get("level")) or "info").lower()

    # Category + severity from process and level heuristics
    category = _default_category_for_process(process)
    severity = _LEVEL_TO_SEVERITY.get(level, EventSeverity.INFO)

    event_time = _parse_time(raw.get("timestamp"))

    # Event type: syslog.<sanitized_process>.<level>
    event_type = (
        f"syslog.{_sanitize_event_type_name(process)}."
        f"{_sanitize_event_type_name(level)}"
    )

    normalized: dict[str, Any] = {
        "source_format": raw.get("format", "unknown"),
    }
    if raw.get("source"):
        normalized["source_kind"] = raw.get("source")
    if raw.get("identifier"):
        normalized["syslog_identifier"] = raw.get("identifier")
    if raw.get("unit"):
        normalized["systemd_unit"] = raw.get("unit")
    if raw.get("level"):
        normalized["syslog_level"] = raw.get("level")

    return {
        "event_time": event_time.isoformat(),
        "event_type": event_type,
        "severity": severity.value,
        "category": category.value,
        "action": None,
        "outcome": None,
        "username": None,
        "hostname": _clean_str(raw.get("hostname")),
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "process_name": process,
        "process_id": _parse_int(raw.get("pid")),
        "file_path": _clean_str(raw.get("file_path")),
        "url": None,
        "domain": None,
        "email_address": None,
        "hash_md5": None,
        "hash_sha256": None,
        "raw_payload": _extract_raw_payload(raw),
        "normalized_payload": normalized,
        "tags": _build_tags(raw, None),
    }


def _extract_raw_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Preserve the original raw entry for forensics.

    Includes the full message text, the raw journald JSON (if any),
    and the raw syslog line (if any). Downstream investigators can
    always inspect what was actually logged.
    """
    raw_payload: dict[str, Any] = {
        "source": raw.get("source"),
        "format": raw.get("format"),
        "hostname": raw.get("hostname"),
        "process": raw.get("process"),
        "identifier": raw.get("identifier"),
        "unit": raw.get("unit"),
        "pid": raw.get("pid"),
        "level": raw.get("level"),
        "cursor": raw.get("cursor"),
        "file_path": raw.get("file_path"),
        "raw_line": raw.get("raw_line"),
        "message": _message_text(raw),
    }

    # If journald provided a full raw entry, preserve it (bounded)
    journald_raw = raw.get("raw")
    if isinstance(journald_raw, dict):
        # Cap to avoid unbounded payload size
        raw_payload["journald_fields"] = {
            k: v for k, v in list(journald_raw.items())[:50]
        }

    # Drop None values to keep the payload lean
    return {k: v for k, v in raw_payload.items() if v is not None}


def _build_tags(raw: dict[str, Any], event_type: str | None) -> list[str]:
    """Build the tag list for the event."""
    tags: list[str] = ["linux"]
    if raw.get("source"):
        tags.append(str(raw["source"]))
    if raw.get("process"):
        tags.append(str(raw["process"]))
    if raw.get("identifier"):
        ident = str(raw["identifier"])
        if ident not in tags:
            tags.append(ident)
    if event_type and event_type not in tags:
        tags.append(event_type)
    return tags[:8]  # cap


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def normalize(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert a raw Linux log entry into a CyberGuard event payload.

    Parameters
    ----------
    raw : dict
        The dict yielded by ``LogReader.poll()`` — either a journald
        entry or a parsed syslog line.

    Returns
    -------
    dict | None
        A dict matching ``EventIngestRequest`` fields. None if the
        input is fundamentally unusable (no message, not a dict).
    """
    if not isinstance(raw, dict):
        return None

    message = _message_text(raw)
    if not message:
        # No message text — nothing to pattern-match. Skip.
        return None

    # Try each pattern in order — most specific first
    for pattern in _PATTERNS:
        match = pattern["regex"].search(message)
        if match:
            try:
                payload = _build_matched_payload(raw, pattern, match)
                logger.debug(
                    "Linux event matched",
                    extra={
                        "event_type": pattern["event_type"],
                        "source": raw.get("source"),
                    },
                )
                return payload
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Pattern matched but payload build failed",
                    extra={
                        "event_type": pattern["event_type"],
                        "error": str(exc)[:200],
                    },
                )
                # Fall through to the next pattern

    # No pattern matched — generic fallback
    try:
        payload = _build_fallback_payload(raw)
        logger.debug(
            "Linux event fell through to fallback",
            extra={
                "event_type": payload["event_type"],
                "process": raw.get("process"),
            },
        )
        return payload
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Fallback payload build failed — skipping event",
            extra={"error": str(exc)[:200]},
        )
        return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "normalize",
    "_PATTERNS",
    "_LEVEL_TO_SEVERITY",
]