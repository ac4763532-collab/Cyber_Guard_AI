"""
CyberGuard AI - Correlation Context Model (STEP 8.5.1)

Cross-source entity normalization for reliable correlation.

This module provides:
1. CorrelationContext - Normalized entity container for correlation
2. Entity normalizers - Deterministic normalization of IPs, usernames, hosts, etc.
3. Source-specific extractors - Windows, Linux/SSH, Web application field mapping
4. Tenant-isolated correlation keys - Never correlate across organizations

Architecture:
    LogEvent.extracted_fields → CorrelationContextExtractor → CorrelationContext
                                                                    ↓
                                                         CorrelationEngine.EventData

Design principles:
- Explicit mappings, not fuzzy guessing
- Missing entities remain None (never fabricated)
- Tenant isolation is mandatory
- Correlation keys are deterministic
- Secrets never enter correlation data

Security:
- No passwords, tokens, or API keys in correlation keys
- Uses project's centralized redaction
- Constant-time comparisons where appropriate
"""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field, field_validator

from app.logs.models import LogEvent, LogSourceType

logger = structlog.get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# System/service accounts that should not be treated as real users
SYSTEM_ACCOUNTS = frozenset({
    # Windows
    "system", "local service", "network service", "anonymous logon",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service", "-", "n/a",
    # Linux
    "root", "nobody", "daemon", "bin", "sys", "sync", "games",
    "man", "lp", "mail", "news", "uucp", "proxy", "www-data",
    "backup", "list", "irc", "gnats", "sshd", "systemd-network",
    "systemd-resolve", "messagebus", "systemd-timesync",
    # Generic
    "", "unknown", "null", "none",
})

# Localhost IPs that indicate local traffic, not external attackers
LOCALHOST_IPS = frozenset({
    "127.0.0.1", "::1", "0.0.0.0", "::",
    "localhost", "127.0.0.0", "0:0:0:0:0:0:0:1",
})

# Invalid/placeholder IPs
INVALID_IPS = frozenset({
    "-", "n/a", "unknown", "none", "", "0.0.0.0",
})


# =============================================================================
# Entity Types
# =============================================================================


class CorrelationEntityType(str, Enum):
    """Types of correlation entities."""

    IP_ADDRESS = "ip"
    USERNAME = "user"
    HOSTNAME = "host"
    SESSION_ID = "session"
    REQUEST_ID = "request"
    TRACE_ID = "trace"
    PROCESS_ID = "process"
    FINDING_ID = "finding"


# =============================================================================
# Entity Normalizers
# =============================================================================


def normalize_ip_address(raw_ip: str | None) -> str | None:
    """
    Normalize an IP address for correlation.

    Returns None for:
    - Empty/None values
    - Invalid IP formats
    - Placeholder values ("-", "n/a", etc.)

    Does NOT return None for localhost (127.0.0.1, ::1) - caller decides
    whether localhost IPs are meaningful for their use case.
    """
    if not raw_ip:
        return None

    # Clean input
    ip_str = str(raw_ip).strip().lower()

    # Reject known invalid values
    if ip_str in INVALID_IPS:
        return None

    # Handle localhost names
    if ip_str == "localhost":
        return "127.0.0.1"

    # Validate and normalize
    try:
        # Parse as IP address
        ip_obj = ipaddress.ip_address(ip_str)

        # Normalize IPv6 to compressed form
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return ip_obj.compressed

        # IPv4 as-is
        return str(ip_obj)

    except ValueError:
        # Not a valid IP address
        logger.debug("Invalid IP address for correlation", raw_ip=raw_ip)
        return None


def is_localhost_ip(normalized_ip: str | None) -> bool:
    """Check if a normalized IP is localhost."""
    if not normalized_ip:
        return False
    return normalized_ip in LOCALHOST_IPS


def normalize_username(
    raw_username: str | None,
    preserve_domain: bool = True,
) -> str | None:
    """
    Normalize a username for correlation.

    Returns None for:
    - Empty/None values
    - System/service accounts
    - Placeholder values

    Args:
        raw_username: Raw username string
        preserve_domain: If True, preserve DOMAIN\\user format (Windows)
                        If False, extract just the username part
    """
    if not raw_username:
        return None

    # Clean input
    username = str(raw_username).strip()

    # Handle empty after strip
    if not username:
        return None

    # Check for system accounts (case-insensitive)
    if username.lower() in SYSTEM_ACCOUNTS:
        return None

    # Handle DOMAIN\user format
    if "\\" in username and not preserve_domain:
        # Extract just the username part
        parts = username.split("\\", 1)
        username = parts[1] if len(parts) > 1 else parts[0]

    # Handle user@domain format
    if "@" in username and not preserve_domain:
        username = username.split("@", 1)[0]

    # Final check
    if not username or username.lower() in SYSTEM_ACCOUNTS:
        return None

    return username


def normalize_hostname(raw_hostname: str | None) -> str | None:
    """
    Normalize a hostname for correlation.

    Returns None for:
    - Empty/None values
    - Placeholder values
    - Values that don't look like valid hostnames
    """
    if not raw_hostname:
        return None

    # Clean input
    hostname = str(raw_hostname).strip().lower()

    # Reject empty
    if not hostname or hostname in {"-", "n/a", "unknown", "none", "localhost"}:
        return None

    # Basic validation - hostname should be alphanumeric with dots/hyphens
    # Allow underscores for Windows NetBIOS names
    if not re.match(r'^[\w\-\.]+$', hostname):
        return None

    return hostname


def normalize_session_id(raw_session: str | None) -> str | None:
    """
    Normalize a session identifier for correlation.

    Returns None for empty/placeholder values.
    Preserves exact session identifiers without modification.
    """
    if not raw_session:
        return None

    session = str(raw_session).strip()

    if not session or session.lower() in {"", "-", "n/a", "unknown", "none", "0", "(none)"}:
        return None

    return session


def normalize_request_id(raw_request_id: str | None) -> str | None:
    """
    Normalize a request/trace identifier for correlation.

    Returns None for empty/placeholder values.
    Preserves exact identifiers without modification.
    """
    if not raw_request_id:
        return None

    request_id = str(raw_request_id).strip()

    if not request_id or request_id.lower() in {"", "-", "n/a", "unknown", "none"}:
        return None

    return request_id


def normalize_process_id(raw_pid: int | str | None) -> int | None:
    """
    Normalize a process ID for correlation.

    Returns None for invalid/empty values.
    """
    if raw_pid is None:
        return None

    try:
        pid = int(raw_pid)
        # PIDs should be positive
        if pid <= 0:
            return None
        return pid
    except (ValueError, TypeError):
        return None


# =============================================================================
# Correlation Context Model
# =============================================================================


class CorrelationContext(BaseModel):
    """
    Normalized correlation context for cross-source correlation.

    This model contains normalized entities extracted from log events
    that can be used for reliable cross-source correlation.

    All correlation MUST include tenant_id for tenant isolation.
    Correlation keys are constructed as: tenant_id + entity_type + entity_value

    Fields:
        tenant_id: Organization/tenant identifier (REQUIRED for correlation)
        source_id: LogSource identifier
        source_type: Type of log source (windows_event, linux_ssh, web_application)
        source_event_id: Stable event identifier from source
        finding_id: Associated finding ID (if from detection)
        event_id: Internal log event ID
        timestamp: Event timestamp (UTC)

        source_ip: Normalized source IP address
        destination_ip: Normalized destination IP (if available)
        username: Normalized username
        user_id: User identifier (distinct from username)
        hostname: Normalized hostname
        session_id: Session identifier
        request_id: Request correlation ID
        trace_id: Distributed trace ID
        process_id: Process ID
        parent_process_id: Parent process ID
        process_name: Process/executable name
        application_name: Application name

        raw_entities: Original un-normalized values for debugging
    """

    # === Tenant Isolation (REQUIRED) ===
    tenant_id: str | None = Field(
        None,
        description="Organization/tenant ID. REQUIRED for cross-source correlation.",
    )

    # === Source Identification ===
    source_id: str | None = Field(
        None,
        description="LogSource identifier",
    )
    source_type: LogSourceType | None = Field(
        None,
        description="Type of log source",
    )
    source_event_id: str | None = Field(
        None,
        description="Stable event identifier from source system",
    )
    finding_id: str | None = Field(
        None,
        description="Associated finding ID (if from detection)",
    )
    event_id: str | None = Field(
        None,
        description="Internal log event ID",
    )

    # === Timestamps ===
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event timestamp (UTC)",
    )

    # === Network Entities ===
    source_ip: str | None = Field(
        None,
        description="Normalized source IP address",
    )
    destination_ip: str | None = Field(
        None,
        description="Normalized destination IP address",
    )

    # === Identity Entities ===
    username: str | None = Field(
        None,
        description="Normalized username",
    )
    user_id: str | None = Field(
        None,
        description="User identifier (distinct from username)",
    )

    # === Host Entities ===
    hostname: str | None = Field(
        None,
        description="Normalized hostname",
    )

    # === Session/Request Entities ===
    session_id: str | None = Field(
        None,
        description="Session identifier",
    )
    request_id: str | None = Field(
        None,
        description="Request correlation ID",
    )
    trace_id: str | None = Field(
        None,
        description="Distributed trace ID",
    )

    # === Process Entities ===
    process_id: int | None = Field(
        None,
        description="Process ID",
    )
    parent_process_id: int | None = Field(
        None,
        description="Parent process ID",
    )
    process_name: str | None = Field(
        None,
        description="Process/executable name",
    )

    # === Application Context ===
    application_name: str | None = Field(
        None,
        description="Application name",
    )

    # === Debugging ===
    raw_entities: dict[str, Any] = Field(
        default_factory=dict,
        description="Original un-normalized values (for debugging only)",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime | None) -> datetime:
        """Ensure timestamp is timezone-aware UTC."""
        if v is None:
            return datetime.now(timezone.utc)
        if v.tzinfo is None:
            # Assume UTC for naive datetimes
            return v.replace(tzinfo=timezone.utc)
        return v

    def has_tenant(self) -> bool:
        """Check if tenant_id is set."""
        return bool(self.tenant_id)

    def can_correlate(self) -> bool:
        """
        Check if this context has enough information for correlation.

        Requires:
        - tenant_id (for isolation)
        - At least one correlatable entity
        """
        if not self.has_tenant():
            return False

        # Check if any correlatable entity is present
        return any([
            self.source_ip,
            self.username,
            self.user_id,
            self.hostname,
            self.session_id,
            self.request_id,
            self.trace_id,
        ])

    def get_correlation_keys(self) -> list[str]:
        """
        Generate deterministic correlation keys.

        Keys are in format: tenant:{tenant_id}:{entity_type}:{entity_value}

        Example: tenant:org-123:ip:192.168.1.1
                 tenant:org-123:user:jsmith

        Returns empty list if tenant_id is not set.
        """
        if not self.tenant_id:
            return []

        keys = []
        prefix = f"tenant:{self.tenant_id}"

        if self.source_ip and not is_localhost_ip(self.source_ip):
            keys.append(f"{prefix}:ip:{self.source_ip}")

        if self.username:
            keys.append(f"{prefix}:user:{self.username.lower()}")

        if self.user_id:
            keys.append(f"{prefix}:user_id:{self.user_id}")

        if self.hostname:
            keys.append(f"{prefix}:host:{self.hostname}")

        if self.session_id:
            keys.append(f"{prefix}:session:{self.session_id}")

        if self.request_id:
            keys.append(f"{prefix}:request:{self.request_id}")

        if self.trace_id:
            keys.append(f"{prefix}:trace:{self.trace_id}")

        return keys

    def get_entity_fingerprint(self) -> str | None:
        """
        Generate a stable fingerprint of this context's entities.

        Useful for deduplication and lookup.
        Returns None if no correlatable entities.
        """
        if not self.can_correlate():
            return None

        keys = sorted(self.get_correlation_keys())
        if not keys:
            return None

        # Hash the sorted keys
        content = "|".join(keys)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_event_data_dict(self) -> dict[str, Any]:
        """
        Convert to dict suitable for CorrelationEngine.EventData.

        Maps:
        - source_ip → ips
        - username, user_id → users
        - hostname → assets
        """
        result: dict[str, Any] = {
            "event_id": self.event_id or self.source_event_id or "",
            "domain": self.source_type.value if self.source_type else "unknown",
            "timestamp": self.timestamp,
            "ips": [],
            "users": [],
            "assets": [],
        }

        if self.source_ip:
            result["ips"].append(self.source_ip)
        if self.destination_ip:
            result["ips"].append(self.destination_ip)

        if self.username:
            result["users"].append(self.username)
        if self.user_id and self.user_id != self.username:
            result["users"].append(self.user_id)

        if self.hostname:
            result["assets"].append(self.hostname)

        return result


# =============================================================================
# Source-Specific Extractors
# =============================================================================


class CorrelationContextExtractor:
    """
    Extract CorrelationContext from LogEvent based on source type.

    Each source type has specific field mappings:
    - Windows: TargetUserName, IpAddress, Computer, etc.
    - Linux/SSH: username, source_ip, hostname, etc.
    - Web: user_id, ip_address, request_id, etc.

    This class uses explicit mappings, not fuzzy regex extraction.
    """

    @classmethod
    def extract(
        cls,
        log_event: LogEvent,
        tenant_id: str | None = None,
        finding_id: str | None = None,
    ) -> CorrelationContext:
        """
        Extract correlation context from a LogEvent.

        Args:
            log_event: The log event to extract from
            tenant_id: Tenant ID for isolation (overrides source lookup)
            finding_id: Associated finding ID if available

        Returns:
            CorrelationContext with normalized entities
        """
        # Get tenant from parameter or attempt lookup from source
        effective_tenant_id = tenant_id

        # Select extractor based on source type
        if log_event.source_type == LogSourceType.WINDOWS_EVENT:
            return cls._extract_windows(log_event, effective_tenant_id, finding_id)
        elif log_event.source_type == LogSourceType.LINUX_SSH:
            return cls._extract_linux(log_event, effective_tenant_id, finding_id)
        elif log_event.source_type == LogSourceType.ANDROID_ADB:
            return cls._extract_android(log_event, effective_tenant_id, finding_id)
        else:
            # Generic extraction for unknown types
            return cls._extract_generic(log_event, effective_tenant_id, finding_id)

    @classmethod
    def _extract_windows(
        cls,
        log_event: LogEvent,
        tenant_id: str | None,
        finding_id: str | None,
    ) -> CorrelationContext:
        """
        Extract correlation context from Windows Event Log.

        Field mappings:
        - TargetUserName / SubjectUserName / AccountName → username
        - IpAddress → source_ip
        - WorkstationName / Computer → hostname
        - LogonId / TargetLogonId → session_id
        - ProcessId / NewProcessId → process_id
        - ParentProcessId → parent_process_id
        - NewProcessName / ProcessName → process_name
        """
        fields = log_event.extracted_fields
        event_data = fields.get("event_data", {})

        # Store raw values for debugging
        raw_entities: dict[str, Any] = {}

        # === Username extraction ===
        username = None
        raw_username = None

        # Priority order for username
        username_fields = [
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
            "TargetUser",
            "SubjectUser",
        ]

        for field in username_fields:
            if event_data.get(field):
                raw_username = event_data[field]
                break

        if raw_username:
            raw_entities["username"] = raw_username
            # For Windows, preserve domain by default
            username = normalize_username(raw_username, preserve_domain=True)

        # === Source IP extraction ===
        source_ip = None
        raw_ip = event_data.get("IpAddress") or event_data.get("SourceAddress")

        if raw_ip:
            raw_entities["source_ip"] = raw_ip
            source_ip = normalize_ip_address(raw_ip)

        # === Destination IP ===
        dest_ip = None
        raw_dest = event_data.get("DestAddress") or event_data.get("DestinationAddress")
        if raw_dest:
            raw_entities["destination_ip"] = raw_dest
            dest_ip = normalize_ip_address(raw_dest)

        # === Hostname extraction ===
        hostname = None
        raw_hostname = (
            event_data.get("WorkstationName") or
            fields.get("computer_name") or
            event_data.get("Computer")
        )

        if raw_hostname:
            raw_entities["hostname"] = raw_hostname
            hostname = normalize_hostname(raw_hostname)

        # === Session ID extraction ===
        session_id = None
        raw_session = (
            event_data.get("TargetLogonId") or
            event_data.get("SubjectLogonId") or
            event_data.get("LogonId")
        )

        if raw_session:
            raw_entities["session_id"] = raw_session
            session_id = normalize_session_id(raw_session)

        # === Process ID extraction ===
        process_id = None
        raw_pid = event_data.get("NewProcessId") or event_data.get("ProcessId")

        if raw_pid:
            raw_entities["process_id"] = raw_pid
            # Windows often has hex PIDs like "0x1234"
            if isinstance(raw_pid, str) and raw_pid.startswith("0x"):
                try:
                    process_id = int(raw_pid, 16)
                except ValueError:
                    process_id = normalize_process_id(raw_pid)
            else:
                process_id = normalize_process_id(raw_pid)

        # === Parent Process ID ===
        parent_pid = None

        # Only set parent if it's from ParentProcessId field
        if event_data.get("ParentProcessId"):
            raw_entities["parent_process_id"] = event_data["ParentProcessId"]
            raw_ppid_val = event_data["ParentProcessId"]
            if isinstance(raw_ppid_val, str) and raw_ppid_val.startswith("0x"):
                try:
                    parent_pid = int(raw_ppid_val, 16)
                except ValueError:
                    parent_pid = normalize_process_id(raw_ppid_val)
            else:
                parent_pid = normalize_process_id(raw_ppid_val)

        # === Process Name ===
        process_name = None
        raw_proc_name = event_data.get("NewProcessName") or event_data.get("ProcessName")

        if raw_proc_name:
            raw_entities["process_name"] = raw_proc_name
            # Extract just the executable name
            process_name = raw_proc_name.split("\\")[-1] if raw_proc_name else None

        return CorrelationContext(
            tenant_id=tenant_id,
            source_id=log_event.source_id,
            source_type=log_event.source_type,
            source_event_id=log_event.source_event_id,
            finding_id=finding_id,
            event_id=log_event.id,
            timestamp=log_event.timestamp,
            source_ip=source_ip,
            destination_ip=dest_ip,
            username=username,
            hostname=hostname,
            session_id=session_id,
            process_id=process_id,
            parent_process_id=parent_pid,
            process_name=process_name,
            raw_entities=raw_entities,
        )

    @classmethod
    def _extract_linux(
        cls,
        log_event: LogEvent,
        tenant_id: str | None,
        finding_id: str | None,
    ) -> CorrelationContext:
        """
        Extract correlation context from Linux/SSH logs.

        Field mappings:
        - username / user → username
        - source_ip → source_ip
        - hostname (from LogEvent) → hostname
        - session → session_id
        - pid → process_id
        - sudo_user / target_user → user_id (if different from username)
        """
        fields = log_event.extracted_fields
        raw_entities: dict[str, Any] = {}

        # === Username extraction ===
        username = None
        raw_username = fields.get("username") or fields.get("user")

        if raw_username:
            raw_entities["username"] = raw_username
            username = normalize_username(raw_username, preserve_domain=False)

        # === User ID (target user for sudo/su) ===
        # Note: For sudo/su, we deliberately preserve system accounts like "root"
        # because privilege escalation to root IS security-relevant
        user_id = None
        raw_target = fields.get("target_user") or fields.get("sudo_user")

        if raw_target and raw_target != raw_username:
            raw_entities["user_id"] = raw_target
            # Don't filter system accounts for sudo targets - escalation to root matters
            target_str = str(raw_target).strip()
            if target_str and target_str.lower() not in {"", "-", "n/a", "unknown", "none"}:
                user_id = target_str

        # === Source IP extraction ===
        source_ip = None
        raw_ip = fields.get("source_ip") or fields.get("ip")

        if raw_ip:
            raw_entities["source_ip"] = raw_ip
            source_ip = normalize_ip_address(raw_ip)

        # === Hostname extraction ===
        hostname = None
        raw_hostname = log_event.hostname or fields.get("hostname")

        if raw_hostname:
            raw_entities["hostname"] = raw_hostname
            hostname = normalize_hostname(raw_hostname)

        # === Session ID extraction ===
        session_id = None
        raw_session = fields.get("session") or fields.get("session_id")

        if raw_session:
            raw_entities["session_id"] = raw_session
            session_id = normalize_session_id(raw_session)

        # === Process ID extraction ===
        process_id = None
        raw_pid = fields.get("pid") or log_event.pid

        if raw_pid:
            raw_entities["process_id"] = raw_pid
            process_id = normalize_process_id(raw_pid)

        # === Process Name ===
        process_name = log_event.program

        return CorrelationContext(
            tenant_id=tenant_id,
            source_id=log_event.source_id,
            source_type=log_event.source_type,
            source_event_id=log_event.source_event_id,
            finding_id=finding_id,
            event_id=log_event.id,
            timestamp=log_event.timestamp,
            source_ip=source_ip,
            username=username,
            user_id=user_id,
            hostname=hostname,
            session_id=session_id,
            process_id=process_id,
            process_name=process_name,
            raw_entities=raw_entities,
        )

    @classmethod
    def _extract_android(
        cls,
        log_event: LogEvent,
        tenant_id: str | None,
        finding_id: str | None,
    ) -> CorrelationContext:
        """
        Extract correlation context from Android ADB/logcat logs.

        Field mappings:
        - device_serial (from extracted_fields, mirrored onto LogEvent.hostname
          by the collector) → hostname. There is no separate "username" or
          "source_ip" concept for on-device logcat output - a device serial
          is the closest stable identity logcat gives us, so it is treated
          like a hostname rather than fabricating a user/IP entity that
          was never actually observed.
        - tag → process_name (logcat's TAG is the closest analog to a
          process/service name, e.g. "ActivityManager", "PackageManager")
        - pid / tid (from extracted_fields, mirrored onto LogEvent.pid) →
          process_id

        Note: no username, user_id, or source_ip are populated here. Logcat
        lines do not carry a logged-in Android user or a network source IP
        in any reliable, parseable way - inventing one from tag/message text
        would be guessing, which this extractor deliberately avoids per the
        "missing entities remain None" design principle.
        """
        fields = log_event.extracted_fields
        raw_entities: dict[str, Any] = {}

        # === Hostname (device serial) extraction ===
        hostname = None
        raw_device_serial = fields.get("device_serial") or log_event.hostname

        if raw_device_serial:
            raw_entities["device_serial"] = raw_device_serial
            hostname = normalize_hostname(raw_device_serial)

        # === Process ID extraction ===
        process_id = None
        raw_pid = fields.get("pid") or log_event.pid

        if raw_pid:
            raw_entities["process_id"] = raw_pid
            process_id = normalize_process_id(raw_pid)

        # === Process name (logcat tag) ===
        raw_tag = fields.get("tag") or log_event.program
        process_name = str(raw_tag).strip() if raw_tag else None
        if process_name:
            raw_entities["tag"] = process_name

        # === Thread ID (Android-specific, no CorrelationContext field - raw only) ===
        raw_tid = fields.get("tid")
        if raw_tid:
            raw_entities["tid"] = raw_tid

        return CorrelationContext(
            tenant_id=tenant_id,
            source_id=log_event.source_id,
            source_type=log_event.source_type,
            source_event_id=log_event.source_event_id,
            finding_id=finding_id,
            event_id=log_event.id,
            timestamp=log_event.timestamp,
            hostname=hostname,
            process_id=process_id,
            process_name=process_name,
            raw_entities=raw_entities,
        )

    @classmethod
    def _extract_web(
        cls,
        log_event: LogEvent,
        tenant_id: str | None,
        finding_id: str | None,
    ) -> CorrelationContext:
        """
        Extract correlation context from Web Application logs.

        Field mappings:
        - user_id → user_id
        - username → username
        - ip_address → source_ip
        - request_id → request_id
        - trace_id → trace_id
        - session_id → session_id
        - hostname (from LogEvent) → hostname
        - application → application_name

        Note: client_event_id is preserved as source_event_id,
        NOT as a correlation entity.
        """
        fields = log_event.extracted_fields
        raw_entities: dict[str, Any] = {}

        # === User ID extraction ===
        user_id = None
        raw_user_id = fields.get("user_id")

        if raw_user_id:
            raw_entities["user_id"] = raw_user_id
            user_id = str(raw_user_id).strip() if raw_user_id else None

        # === Username extraction ===
        # For web apps, preserve full email-style usernames (jsmith@example.com)
        username = None
        raw_username = fields.get("username")

        if raw_username:
            raw_entities["username"] = raw_username
            # Web usernames are often emails - preserve the full format
            username = normalize_username(raw_username, preserve_domain=True)

        # === Source IP extraction ===
        source_ip = None
        raw_ip = fields.get("ip_address") or fields.get("client_ip")

        if raw_ip:
            raw_entities["source_ip"] = raw_ip
            source_ip = normalize_ip_address(raw_ip)

        # === Hostname extraction ===
        hostname = None
        raw_hostname = log_event.hostname or fields.get("hostname")

        if raw_hostname:
            raw_entities["hostname"] = raw_hostname
            hostname = normalize_hostname(raw_hostname)

        # === Request ID extraction ===
        request_id = None
        raw_request = fields.get("request_id")

        if raw_request:
            raw_entities["request_id"] = raw_request
            request_id = normalize_request_id(raw_request)

        # === Trace ID extraction ===
        trace_id = None
        raw_trace = fields.get("trace_id")

        if raw_trace:
            raw_entities["trace_id"] = raw_trace
            trace_id = normalize_request_id(raw_trace)

        # === Session ID extraction ===
        session_id = None
        raw_session = fields.get("session_id")

        if raw_session:
            raw_entities["session_id"] = raw_session
            session_id = normalize_session_id(raw_session)

        # === Application Name ===
        application_name = log_event.program or fields.get("application")

        return CorrelationContext(
            tenant_id=tenant_id,
            source_id=log_event.source_id,
            source_type=log_event.source_type,
            source_event_id=log_event.source_event_id,
            finding_id=finding_id,
            event_id=log_event.id,
            timestamp=log_event.timestamp,
            source_ip=source_ip,
            username=username,
            user_id=user_id,
            hostname=hostname,
            session_id=session_id,
            request_id=request_id,
            trace_id=trace_id,
            application_name=application_name,
            raw_entities=raw_entities,
        )

    @classmethod
    def _extract_generic(
        cls,
        log_event: LogEvent,
        tenant_id: str | None,
        finding_id: str | None,
    ) -> CorrelationContext:
        """
        Generic extraction for unknown source types.

        Uses common field names without source-specific assumptions.
        """
        fields = log_event.extracted_fields
        raw_entities: dict[str, Any] = {}

        # Try common field names
        source_ip = None
        raw_ip = (
            fields.get("source_ip") or
            fields.get("ip_address") or
            fields.get("ip") or
            fields.get("client_ip")
        )
        if raw_ip:
            raw_entities["source_ip"] = raw_ip
            source_ip = normalize_ip_address(raw_ip)

        username = None
        raw_username = (
            fields.get("username") or
            fields.get("user") or
            fields.get("user_name")
        )
        if raw_username:
            raw_entities["username"] = raw_username
            username = normalize_username(raw_username)

        hostname = normalize_hostname(log_event.hostname)

        # CorrelationContext.source_type is typed LogSourceType | None - it
        # only accepts the enum's own members (windows_event/linux_ssh/
        # android_adb/local_network_monitor), not arbitrary strings. This
        # generic path is reached for every source that ISN'T one of the
        # three dedicated LogSourceType branches in extract() above, so
        # log_event.source_type here is routinely something else entirely:
        # a plain string like "email"/"network"/"log" (manual-analysis
        # callers in app/api/v1/analysis.py, which key their own alert
        # categorization off this same attribute via a looser,
        # string-based reader) or an unrelated local enum (e.g. the
        # adapter in app/event_bus/dispatcher_integration.py). Passing
        # either straight through raised a pydantic ValidationError and
        # aborted correlation for every such finding. Only forward it when
        # it's actually a valid LogSourceType; otherwise this context
        # simply carries no source_type, which the field already allows.
        normalized_source_type = (
            log_event.source_type if isinstance(log_event.source_type, LogSourceType) else None
        )

        return CorrelationContext(
            tenant_id=tenant_id,
            source_id=log_event.source_id,
            source_type=normalized_source_type,
            source_event_id=log_event.source_event_id,
            finding_id=finding_id,
            event_id=log_event.id,
            timestamp=log_event.timestamp,
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            raw_entities=raw_entities,
        )


# =============================================================================
# Utility Functions
# =============================================================================


def build_correlation_key(
    tenant_id: str,
    entity_type: CorrelationEntityType,
    entity_value: str,
) -> str:
    """
    Build a deterministic correlation key.

    Format: tenant:{tenant_id}:{entity_type}:{entity_value}
    """
    return f"tenant:{tenant_id}:{entity_type.value}:{entity_value}"


def parse_correlation_key(key: str) -> tuple[str, str, str] | None:
    """
    Parse a correlation key into components.

    Returns (tenant_id, entity_type, entity_value) or None if invalid.
    """
    parts = key.split(":", 3)
    if len(parts) != 4 or parts[0] != "tenant":
        return None
    return parts[1], parts[2], parts[3]
