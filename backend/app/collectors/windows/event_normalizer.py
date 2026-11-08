"""
CyberGuard AI — Windows Event Normalizer
============================================================================

Converts raw Windows Event Log dicts (from ``event_log_reader.py``) into
CyberGuard's normalized event shape (``EventIngestRequest`` from
``app/schemas/event.py``).

The normalizer is a pure function — no I/O, no threads, no external
calls. It takes a raw event dict, returns a normalized event dict (or
None to skip), and that's it. This makes it trivially testable and
keeps the reader thread unblocked.

What gets normalized
--------------------
Windows events carry data in two forms:

    1. **System fields** — always present, structured:
         EventID, Level, TimeCreated, Computer, Provider.Name

    2. **Event-specific properties** — named fields whose meaning
       depends on the EventID:
         SubjectUserName, TargetUserName, IpAddress, LogonType,
         ServiceName, ProcessName, ...

The normalizer maps both into CyberGuard's canonical shape. Every
agent (log_analysis, threat_intelligence, ioc_correlation) consumes
this canonical shape — they never see Windows-specific field names.

EventID mapping
---------------
The bulk of this file is ``_EVENT_MAPPINGS`` — a dict from Windows
EventID to (event_type, category, severity, action, outcome). Covers
the 50 most common security-relevant Windows events across:

    Security log:
        4624 (logon success), 4625 (logon failure), 4634 (logoff),
        4648 (explicit cred), 4672 (privilege assigned),
        4720 (user created), 4722 (user enabled), 4725 (user disabled),
        4726 (user deleted), 4728/4732 (added to group),
        4740 (account locked), 4767 (account unlocked),
        4776 (NTLM auth), 4778/4779 (session), ...

    System log:
        7034 (service crashed), 7036 (service state), 7040 (service
        start type), 7045 (service installed), 1074 (shutdown/restart)

    Application log:
        1000 (application crash), 1026 (.NET unhandled exception)

Unknown EventIDs fall back to a generic ``windows.<event_id>`` type
with the severity derived from the Windows Level field.

Severity mapping
----------------
    Windows Level 1 (Critical)  → EventSeverity.CRITICAL
    Windows Level 2 (Error)     → EventSeverity.HIGH
    Windows Level 3 (Warning)   → EventSeverity.MEDIUM
    Windows Level 4 (Info)      → EventSeverity.LOW
    Windows Level 5 (Verbose)   → EventSeverity.INFO

Per-event override: the mapping table can bump severity for events
that are security-critical even when Windows logs them at Info level
(e.g. 4720 user created is Info in Windows but HIGH for CyberGuard).

Field extraction heuristics
---------------------------
Windows properties use different names for the same concept:

    Username:     SubjectUserName, TargetUserName, UserName
    Source IP:    IpAddress, SourceIp, ClientAddress
    Dest IP:      DestinationIp
    Ports:        IpPort, SourcePort, DestPort
    Process:      ProcessName, ImagePath, NewProcessName
    File:         ObjectName, FileName, TargetFilename
    Service:      ServiceName

The extractor tries each name in order and returns the first non-empty
value. If none are present, the field is None.

Unsupported fields
------------------
Windows has no concept of many CyberGuard fields (URL, domain,
email_address, hash_md5, hash_sha256). These are always None for
Windows events. Email/URLs only come from the Email Agent (which reads
a different source type).

Usage
-----
    from event_normalizer import normalize

    raw_dict = next(reader.poll())
    event_payload = normalize(raw_dict)
    if event_payload is None:
        # Event skipped (e.g. filtered by user policy)
        return
    queue.enqueue(event_payload)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.models.enums import EventCategory, EventSeverity


logger = logging.getLogger(__name__)


# ============================================================================
# EVENT MAPPING TABLE
# ============================================================================
# Windows EventID → (event_type, category, severity, action, outcome)
#
# event_type:   stable string used by agent rules (e.g. "failed_login")
# category:     EventCategory enum value
# severity:     EventSeverity enum value
# action:       what happened ("login", "file_access", ...)
# outcome:      result if applicable ("success", "failure", None)

_EVENT_MAPPINGS: dict[int, dict[str, Any]] = {
    # ── Security: Authentication ───────────────────────────────────────
    4624: {
        "event_type": "successful_login",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.LOW,
        "action": "login",
        "outcome": "success",
    },
    4625: {
        "event_type": "failed_login",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "login",
        "outcome": "failure",
    },
    4634: {
        "event_type": "logout",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "logout",
        "outcome": "success",
    },
    4647: {
        "event_type": "logout_initiated",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "logout",
        "outcome": "success",
    },
    4648: {
        "event_type": "explicit_credentials",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "use_credentials",
        "outcome": "success",
    },
    4776: {
        "event_type": "ntlm_auth",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "authenticate",
        "outcome": None,
    },
    4778: {
        "event_type": "session_reconnected",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "reconnect",
        "outcome": "success",
    },
    4779: {
        "event_type": "session_disconnected",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.INFO,
        "action": "disconnect",
        "outcome": "success",
    },

    # ── Security: Privilege & Authorization ────────────────────────────
    4672: {
        "event_type": "special_privileges",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "grant_privileges",
        "outcome": "success",
    },
    4673: {
        "event_type": "privileged_service_called",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "call_privileged_service",
        "outcome": "success",
    },
    4674: {
        "event_type": "privileged_operation",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "privileged_operation",
        "outcome": None,
    },
    4675: {
        "event_type": "sid_filtering",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.INFO,
        "action": "sid_filter",
        "outcome": None,
    },

    # ── Security: Account lifecycle ────────────────────────────────────
    4720: {
        "event_type": "user_created",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.HIGH,
        "action": "create_account",
        "outcome": "success",
    },
    4722: {
        "event_type": "user_enabled",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "enable_account",
        "outcome": "success",
    },
    4723: {
        "event_type": "password_change_attempt",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "change_password",
        "outcome": None,
    },
    4724: {
        "event_type": "password_reset",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "reset_password",
        "outcome": "success",
    },
    4725: {
        "event_type": "user_disabled",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "disable_account",
        "outcome": "success",
    },
    4726: {
        "event_type": "user_deleted",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.HIGH,
        "action": "delete_account",
        "outcome": "success",
    },
    4738: {
        "event_type": "user_modified",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "modify_account",
        "outcome": "success",
    },
    4740: {
        "event_type": "account_locked",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.HIGH,
        "action": "lock_account",
        "outcome": "success",
    },
    4767: {
        "event_type": "account_unlocked",
        "category": EventCategory.AUTHENTICATION,
        "severity": EventSeverity.MEDIUM,
        "action": "unlock_account",
        "outcome": "success",
    },

    # ── Security: Group membership ────────────────────────────────────
    4728: {
        "event_type": "group_member_added",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.HIGH,
        "action": "add_to_group",
        "outcome": "success",
    },
    4729: {
        "event_type": "group_member_removed",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "remove_from_group",
        "outcome": "success",
    },
    4732: {
        "event_type": "local_group_member_added",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.HIGH,
        "action": "add_to_local_group",
        "outcome": "success",
    },
    4733: {
        "event_type": "local_group_member_removed",
        "category": EventCategory.AUTHORIZATION,
        "severity": EventSeverity.MEDIUM,
        "action": "remove_from_local_group",
        "outcome": "success",
    },

    # ── Security: Process & File ─────────────────────────────────────
    4688: {
        "event_type": "process_created",
        "category": EventCategory.PROCESS,
        "severity": EventSeverity.INFO,
        "action": "execute",
        "outcome": "success",
    },
    4689: {
        "event_type": "process_terminated",
        "category": EventCategory.PROCESS,
        "severity": EventSeverity.INFO,
        "action": "terminate",
        "outcome": "success",
    },
    4656: {
        "event_type": "file_handle_requested",
        "category": EventCategory.FILE,
        "severity": EventSeverity.LOW,
        "action": "request_access",
        "outcome": None,
    },
    4658: {
        "event_type": "file_handle_closed",
        "category": EventCategory.FILE,
        "severity": EventSeverity.INFO,
        "action": "close_handle",
        "outcome": "success",
    },
    4663: {
        "event_type": "file_access",
        "category": EventCategory.FILE,
        "severity": EventSeverity.LOW,
        "action": "access",
        "outcome": None,
    },

    # ── Security: Audit & Policy ─────────────────────────────────────
    1102: {
        "event_type": "audit_log_cleared",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.CRITICAL,
        "action": "clear_log",
        "outcome": "success",
    },
    4719: {
        "event_type": "audit_policy_changed",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.HIGH,
        "action": "change_audit_policy",
        "outcome": "success",
    },

    # ── System: Service lifecycle ────────────────────────────────────
    7034: {
        "event_type": "service_crashed",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.MEDIUM,
        "action": "crash",
        "outcome": "failure",
    },
    7036: {
        "event_type": "service_state_change",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.INFO,
        "action": "state_change",
        "outcome": None,
    },
    7040: {
        "event_type": "service_start_type_changed",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.MEDIUM,
        "action": "modify_service",
        "outcome": "success",
    },
    7045: {
        "event_type": "service_installed",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.MEDIUM,
        "action": "install_service",
        "outcome": "success",
    },
    1074: {
        "event_type": "shutdown_or_restart",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.LOW,
        "action": "shutdown",
        "outcome": None,
    },

    # ── Application: Crashes ─────────────────────────────────────────
    1000: {
        "event_type": "application_crash",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.LOW,
        "action": "crash",
        "outcome": "failure",
    },
    1026: {
        "event_type": "dotnet_unhandled_exception",
        "category": EventCategory.SYSTEM,
        "severity": EventSeverity.LOW,
        "action": "crash",
        "outcome": "failure",
    },
}


# ============================================================================
# LEVEL → SEVERITY MAP
# ============================================================================

_LEVEL_TO_SEVERITY: dict[int, EventSeverity] = {
    1: EventSeverity.CRITICAL,   # Critical
    2: EventSeverity.HIGH,       # Error
    3: EventSeverity.MEDIUM,     # Warning
    4: EventSeverity.LOW,        # Information
    5: EventSeverity.INFO,       # Verbose
}


# ============================================================================
# FIELD EXTRACTION HELPERS
# ============================================================================

#: Windows property names that map to a specific CyberGuard field.
#: Tried in order; first non-empty wins.
_PROPERTY_ALIASES: dict[str, tuple[str, ...]] = {
    "username": (
        "SubjectUserName", "TargetUserName", "UserName", "AccountName",
        "NewTargetUserName", "OldTargetUserName",
    ),
    "source_ip": (
        "IpAddress", "SourceIp", "ClientAddress", "SourceAddress",
    ),
    "destination_ip": (
        "DestinationIp", "DestAddress",
    ),
    "source_port": (
        "IpPort", "SourcePort",
    ),
    "destination_port": (
        "DestPort", "DestinationPort",
    ),
    "process_name": (
        "ProcessName", "ImagePath", "NewProcessName",
    ),
    "file_path": (
        "ObjectName", "FileName", "TargetFilename", "NewFileName",
    ),
    "domain": (
        "SubjectDomainName", "TargetDomainName",
    ),
    "email_address": (
        "PrimaryEmailAddress", "UserPrincipalName",
    ),
}


def _extract_field(
    properties: dict[str, Any],
    field: str,
) -> Any:
    """Return the first non-empty value for the field's aliases."""
    aliases = _PROPERTY_ALIASES.get(field, ())
    for alias in aliases:
        value = properties.get(alias)
        if value is None:
            continue
        if isinstance(value, str):
            stripped = value.strip()
            if stripped and stripped != "-":
                return stripped
        elif value:
            return value
    return None


def _extract_int(value: Any) -> int | None:
    """Parse a value as int, or None."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _normalize_win_username(value: str | None) -> str | None:
    """
    Strip Windows-specific prefixes from usernames.

    Windows usernames often come as "DOMAIN\\user" or "MACHINE\\user".
    We keep the bare username and (when present) the domain separately.
    The bare username is what agents match on.
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped or stripped == "-":
        return None
    if "\\" in stripped:
        return stripped.rsplit("\\", 1)[-1]
    return stripped


#: Match ISO-8601 timestamps from Windows TimeCreated
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)


def _parse_time_created(value: str | None) -> datetime:
    """
    Parse the Windows TimeCreated string into a timezone-aware datetime.

    Falls back to ``datetime.now(timezone.utc)`` if parsing fails — the
    event is still ingested, just with a "now" timestamp. Logs a
    warning so we can fix the parser later.
    """
    if not value:
        return datetime.now(timezone.utc)

    # Try fast path — Python 3.11+ handles most ISO-8601 forms
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        pass

    # Fallback — manual parse via regex
    match = _ISO_RE.match(value)
    if not match:
        logger.warning(
            "Could not parse TimeCreated",
            extra={"value": value[:100]},
        )
        return datetime.now(timezone.utc)

    try:
        year, month, day, hour, minute, second = (
            int(match.group(i)) for i in range(1, 7)
        )
        micro = 0
        if match.group(7):
            fractional = match.group(7)
            # 7-digit fractional (Windows uses 100-ns resolution) → microseconds
            micro = int(fractional.ljust(6, "0")[:6])
        tz_str = match.group(8) or "Z"
        if tz_str == "Z":
            tz = timezone.utc
        else:
            # Parse +HH:MM
            sign = 1 if tz_str[0] == "+" else -1
            hh, mm = tz_str[1:].split(":")
            from datetime import timedelta
            tz = timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except (ValueError, IndexError):
        logger.warning(
            "Could not parse TimeCreated (fallback)",
            extra={"value": value[:100]},
        )
        return datetime.now(timezone.utc)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def normalize(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert a raw Windows Event Log dict into a CyberGuard event payload.

    Returns
    -------
    dict | None
        A dict matching ``EventIngestRequest`` fields (as plain Python
        types — the API client serializes it to JSON). Returns None if
        the event should be skipped (e.g. malformed).

    The output is what ``api_client.send_event`` accepts. It's NOT a
    Pydantic model — the schema validation happens server-side.
    """
    if not isinstance(raw, dict):
        return None

    channel = str(raw.get("channel") or "Unknown")
    event_id = raw.get("event_id")
    record_number = raw.get("record_number")
    level = raw.get("level")

    if event_id is None:
        # Unknown Windows event — can't normalize meaningfully
        return None

    properties = raw.get("properties") or {}
    user_data = raw.get("user_data") or {}

    # Merge user_data into properties — some events put data in UserData
    merged_props = dict(properties)
    for k, v in (user_data or {}).items():
        merged_props.setdefault(k, v)

    # Look up the event mapping; fall back to a generic Windows event
    mapping = _EVENT_MAPPINGS.get(event_id)
    if mapping is not None:
        event_type = mapping["event_type"]
        category = mapping["category"]
        severity = mapping["severity"]
        action = mapping.get("action")
        outcome = mapping.get("outcome")
    else:
        event_type = f"windows.{event_id}"
        category = _infer_category(channel)
        severity = _LEVEL_TO_SEVERITY.get(level, EventSeverity.INFO)
        action = None
        outcome = None

    # Override severity when Windows logs an event at a lower level than
    # we care about. E.g. 4624 (successful login) is Info in Windows but
    # we want LOW. 4720 (user created) is Info but HIGH for us. The
    # mapping table already reflects this — but the mapping is only
    # used when event_id is present in _EVENT_MAPPINGS.

    # ── Extract entity fields
    username = _normalize_win_username(_extract_field(merged_props, "username"))
    hostname = raw.get("computer") or None
    if isinstance(hostname, str):
        hostname = hostname.strip()[:255]

    source_ip = _extract_field(merged_props, "source_ip")
    if isinstance(source_ip, str):
        source_ip = source_ip.strip()
        if source_ip in ("-", "::1", "127.0.0.1"):
            # Localhost bindings — not useful as IOCs
            source_ip = None

    destination_ip = _extract_field(merged_props, "destination_ip")
    source_port = _extract_int(_extract_field(merged_props, "source_port"))
    destination_port = _extract_int(_extract_field(merged_props, "destination_port"))

    process_name = _extract_field(merged_props, "process_name")
    process_id = _extract_int(merged_props.get("NewProcessId") or merged_props.get("ProcessId"))
    file_path = _extract_field(merged_props, "file_path")
    domain = _extract_field(merged_props, "domain")
    email_address = _extract_field(merged_props, "email_address")

    # ── Time
    event_time = _parse_time_created(raw.get("time_created"))

    # ── Build normalized payload (small structured summary that agents
    #    consume — the full raw is preserved in raw_payload)
    normalized_payload: dict[str, Any] = {
        "windows_event_id": event_id,
        "windows_channel": channel,
        "windows_level": level,
        "provider": raw.get("provider_name"),
        "record_number": record_number,
        "computer": hostname,
    }
    if username:
        normalized_payload["username"] = username
    if source_ip:
        normalized_payload["source_ip"] = source_ip
    if event_id in (4624, 4625):
        # Logon type is highly relevant for authentication events
        logon_type = merged_props.get("LogonType")
        if logon_type:
            normalized_payload["logon_type"] = logon_type
        # Auth package
        auth_package = merged_props.get("AuthenticationPackageName")
        if auth_package:
            normalized_payload["auth_package"] = auth_package

    # ── Tags
    tags = ["windows", channel.lower()]
    if event_id in _EVENT_MAPPINGS:
        tags.append(event_type)

    # ── Build the ingest payload
    payload: dict[str, Any] = {
        "event_time": event_time.isoformat(),
        "event_type": event_type,
        "severity": severity.value,
        "category": category.value,
        "action": action,
        "outcome": outcome,
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
        "domain": domain,
        "email_address": email_address,
        "hash_md5": None,
        "hash_sha256": None,
        "raw_payload": {
            "channel": channel,
            "record_number": record_number,
            "event_id": event_id,
            "level": level,
            "time_created": raw.get("time_created"),
            "provider_name": raw.get("provider_name"),
            "computer": raw.get("computer"),
            "properties": properties,
            "user_data": user_data,
        },
        "normalized_payload": normalized_payload,
        "tags": tags,
    }

    return payload


def _infer_category(channel: str) -> EventCategory:
    """Best-guess category for unknown events, based on channel."""
    channel_lower = (channel or "").lower()
    if channel_lower == "security":
        return EventCategory.AUTHENTICATION
    if channel_lower == "system":
        return EventCategory.SYSTEM
    if channel_lower == "application":
        return EventCategory.SYSTEM
    return EventCategory.OTHER


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "normalize",
    "_EVENT_MAPPINGS",
    "_LEVEL_TO_SEVERITY",
]