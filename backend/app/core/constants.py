"""
CyberGuard AI — Shared Constants
============================================================================

Centralizes every string constant that code compares against: HTTP header
names, API path prefixes, permission strings, pagination limits, severity
ordering, well-known IDs, MIME types, notification channels, audit action
verbs, and time constants.

What does **not** live here
---------------------------
- Database enums → ``app.models.enums`` (File 15)
- Secrets → ``app.core.config.settings``
- Validation logic → ``app.core.security`` and Pydantic schemas

Design rules
------------
1. This module is a **leaf** — it imports nothing from ``app.*``.
2. All values are immutable (``str``, ``tuple``, ``frozenset``, ``int``).
3. Permission strings are the RBAC source of truth. Any code checking
   access must reference a constant here, never a raw string.
4. Severity ordering is explicit — do not rely on lexicographic comparison.
"""

from __future__ import annotations

from typing import Final


# ============================================================================
# VERSIONING & API
# ============================================================================

API_VERSION: Final[str] = "v1"
API_PREFIX: Final[str] = f"/api/{API_VERSION}"

# Sub-prefixes
API_AUTH_PREFIX: Final[str] = f"{API_PREFIX}/auth"
API_USERS_PREFIX: Final[str] = f"{API_PREFIX}/users"
API_ORGS_PREFIX: Final[str] = f"{API_PREFIX}/organizations"
API_WORKSPACES_PREFIX: Final[str] = f"{API_PREFIX}/workspaces"
API_SOURCES_PREFIX: Final[str] = f"{API_PREFIX}/sources"
API_ENROLLMENT_PREFIX: Final[str] = f"{API_PREFIX}/enrollment"
API_COLLECTOR_PREFIX: Final[str] = f"{API_PREFIX}/collector"
API_EVENTS_PREFIX: Final[str] = f"{API_PREFIX}/events"
API_FINDINGS_PREFIX: Final[str] = f"{API_PREFIX}/findings"
API_ALERTS_PREFIX: Final[str] = f"{API_PREFIX}/alerts"
API_INCIDENTS_PREFIX: Final[str] = f"{API_PREFIX}/incidents"
API_CASES_PREFIX: Final[str] = f"{API_PREFIX}/cases"
API_REPORTS_PREFIX: Final[str] = f"{API_PREFIX}/reports"
API_NOTIFICATIONS_PREFIX: Final[str] = f"{API_PREFIX}/notifications"
API_AI_ANALYST_PREFIX: Final[str] = f"{API_PREFIX}/ai-analyst"
API_MARKETPLACE_PREFIX: Final[str] = f"{API_PREFIX}/marketplace"
API_ADMIN_PREFIX: Final[str] = f"{API_PREFIX}/admin"
API_HEALTH_PREFIX: Final[str] = ""


# ============================================================================
# HTTP HEADERS
# ============================================================================

#: Standard header used to propagate the request correlation ID through logs.
HEADER_CORRELATION_ID: Final[str] = "X-Correlation-ID"

#: Standard header used by clients to request a new correlation ID.
HEADER_REQUEST_ID: Final[str] = "X-Request-ID"

#: Collector authentication header used by device collectors.
HEADER_COLLECTOR_CREDENTIAL: Final[str] = "X-Collector-Credential"

#: Collector identifier header, sent alongside the credential.
HEADER_COLLECTOR_ID: Final[str] = "X-Collector-ID"

#: Collector protocol version header.
HEADER_COLLECTOR_VERSION: Final[str] = "X-Collector-Version"

#: Idempotency key for retry-safe POSTs (event ingestion, etc.).
HEADER_IDEMPOTENCY_KEY: Final[str] = "Idempotency-Key"


# ============================================================================
# CONTENT TYPES
# ============================================================================

CONTENT_TYPE_JSON: Final[str] = "application/json"
CONTENT_TYPE_FORM: Final[str] = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTIPART: Final[str] = "multipart/form-data"
CONTENT_TYPE_TEXT: Final[str] = "text/plain"
CONTENT_TYPE_PDF: Final[str] = "application/pdf"


# ============================================================================
# PERMISSIONS — RBAC SOURCE OF TRUTH
# ============================================================================
# Format: "<resource>:<action>". Roles are granted sets of permissions.
# An analyst, admin, or system component must call
# ``authorization.check_permission(user, PERM_*)`` — never a raw string.

# Users
PERM_USER_READ_SELF: Final[str] = "user:read:self"
PERM_USER_UPDATE_SELF: Final[str] = "user:update:self"
PERM_USER_READ_ANY: Final[str] = "user:read:any"
PERM_USER_UPDATE_ANY: Final[str] = "user:update:any"
PERM_USER_DELETE_ANY: Final[str] = "user:delete:any"
PERM_USER_SUSPEND: Final[str] = "user:suspend"

# Organizations
PERM_ORG_CREATE: Final[str] = "organization:create"
PERM_ORG_READ: Final[str] = "organization:read"
PERM_ORG_UPDATE: Final[str] = "organization:update"
PERM_ORG_DELETE: Final[str] = "organization:delete"
PERM_ORG_INVITE_MEMBER: Final[str] = "organization:invite"
PERM_ORG_REMOVE_MEMBER: Final[str] = "organization:remove_member"
PERM_ORG_MANAGE_ROLES: Final[str] = "organization:manage_roles"

# Workspaces
PERM_WORKSPACE_CREATE: Final[str] = "workspace:create"
PERM_WORKSPACE_READ: Final[str] = "workspace:read"
PERM_WORKSPACE_UPDATE: Final[str] = "workspace:update"
PERM_WORKSPACE_DELETE: Final[str] = "workspace:delete"

# Security sources & collectors
PERM_SOURCE_CREATE: Final[str] = "source:create"
PERM_SOURCE_READ: Final[str] = "source:read"
PERM_SOURCE_UPDATE: Final[str] = "source:update"
PERM_SOURCE_DISABLE: Final[str] = "source:disable"
PERM_SOURCE_REVOKE: Final[str] = "source:revoke"
PERM_SOURCE_ENROLL: Final[str] = "source:enroll"

# Events
PERM_EVENT_READ: Final[str] = "event:read"
PERM_EVENT_INGEST: Final[str] = "event:ingest"

# Findings, alerts, incidents
PERM_FINDING_READ: Final[str] = "finding:read"
PERM_ALERT_READ: Final[str] = "alert:read"
PERM_ALERT_ACKNOWLEDGE: Final[str] = "alert:acknowledge"
PERM_INCIDENT_READ: Final[str] = "incident:read"
PERM_INCIDENT_CREATE: Final[str] = "incident:create"
PERM_INCIDENT_UPDATE: Final[str] = "incident:update"
PERM_INCIDENT_CLOSE: Final[str] = "incident:close"
PERM_INCIDENT_ASSIGN: Final[str] = "incident:assign"

# Cases & evidence
PERM_CASE_READ: Final[str] = "case:read"
PERM_CASE_UPDATE: Final[str] = "case:update"
PERM_CASE_ASSIGN: Final[str] = "case:assign"
PERM_CASE_CLOSE: Final[str] = "case:close"
PERM_EVIDENCE_READ: Final[str] = "evidence:read"
PERM_EVIDENCE_UPLOAD: Final[str] = "evidence:upload"
PERM_EVIDENCE_DOWNLOAD: Final[str] = "evidence:download"
PERM_EVIDENCE_DELETE: Final[str] = "evidence:delete"

# Reports
PERM_REPORT_READ: Final[str] = "report:read"
PERM_REPORT_CREATE: Final[str] = "report:create"
PERM_REPORT_DOWNLOAD: Final[str] = "report:download"

# AI Analyst
PERM_AI_ANALYST_QUERY: Final[str] = "ai_analyst:query"

# Marketplace
PERM_MARKETPLACE_BROWSE: Final[str] = "marketplace:browse"
PERM_MARKETPLACE_PURCHASE: Final[str] = "marketplace:purchase"
PERM_SERVICE_OFFER_CREATE: Final[str] = "service_offering:create"
PERM_SERVICE_OFFER_UPDATE: Final[str] = "service_offering:update"

# Admin / platform
PERM_ADMIN_ANALYST_VERIFY: Final[str] = "admin:analyst_verify"
PERM_ADMIN_ANALYST_REJECT: Final[str] = "admin:analyst_reject"
PERM_ADMIN_ORG_SUSPEND: Final[str] = "admin:org_suspend"
PERM_ADMIN_PLATFORM_CONFIG: Final[str] = "admin:platform_config"
PERM_ADMIN_AUDIT_READ: Final[str] = "admin:audit_read"
PERM_ADMIN_EVIDENCE_ACCESS: Final[str] = "admin:evidence_access"

#: Complete set of permissions — anything not in this set is invalid.
ALL_PERMISSIONS: Final[frozenset[str]] = frozenset(
    v for k, v in globals().items() if k.startswith("PERM_")
)


# ============================================================================
# PAGINATION
# ============================================================================

DEFAULT_PAGE_SIZE: Final[int] = 25
MIN_PAGE_SIZE: Final[int] = 1
MAX_PAGE_SIZE: Final[int] = 200
DEFAULT_PAGE_OFFSET: Final[int] = 0


# ============================================================================
# SEVERITY & PRIORITY
# ============================================================================
# Severity levels are strings shared across models, schemas, and agents.
# Ordering is explicit — do not rely on lexicographic comparison.

SEVERITY_LOW: Final[str] = "low"
SEVERITY_MEDIUM: Final[str] = "medium"
SEVERITY_HIGH: Final[str] = "high"
SEVERITY_CRITICAL: Final[str] = "critical"

SEVERITY_ORDER: Final[tuple[str, ...]] = (
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

SEVERITY_RANK: Final[dict[str, int]] = {
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

#: Default score contribution per severity (for aggregated risk).
SEVERITY_SCORE: Final[dict[str, int]] = {
    SEVERITY_LOW: 10,
    SEVERITY_MEDIUM: 25,
    SEVERITY_HIGH: 50,
    SEVERITY_CRITICAL: 100,
}

PRIORITY_LOW: Final[str] = "low"
PRIORITY_MEDIUM: Final[str] = "medium"
PRIORITY_HIGH: Final[str] = "high"
PRIORITY_URGENT: Final[str] = "urgent"

PRIORITY_ORDER: Final[tuple[str, ...]] = (
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_URGENT,
)


# ============================================================================
# IOC INDICATOR TYPES
# ============================================================================

IOC_IPV4: Final[str] = "ipv4"
IOC_IPV6: Final[str] = "ipv6"
IOC_DOMAIN: Final[str] = "domain"
IOC_URL: Final[str] = "url"
IOC_MD5: Final[str] = "md5"
IOC_SHA1: Final[str] = "sha1"
IOC_SHA256: Final[str] = "sha256"
IOC_EMAIL: Final[str] = "email"
IOC_USERNAME: Final[str] = "username"
IOC_HOSTNAME: Final[str] = "hostname"
IOC_CVE: Final[str] = "cve"

IOC_TYPES: Final[tuple[str, ...]] = (
    IOC_IPV4,
    IOC_IPV6,
    IOC_DOMAIN,
    IOC_URL,
    IOC_MD5,
    IOC_SHA1,
    IOC_SHA256,
    IOC_EMAIL,
    IOC_USERNAME,
    IOC_HOSTNAME,
    IOC_CVE,
)


# ============================================================================
# EVENT SOURCE TYPES
# ============================================================================
# Mirrors the collector "source_type" field. Not a DB enum because collectors
# compare against these strings directly before sending events.

SOURCE_WINDOWS: Final[str] = "windows"
SOURCE_LINUX: Final[str] = "linux"
SOURCE_MACOS: Final[str] = "macos"
SOURCE_ANDROID: Final[str] = "android"
SOURCE_EMAIL: Final[str] = "email"
SOURCE_NETWORK: Final[str] = "network"
SOURCE_WEB_APP: Final[str] = "web_app"
SOURCE_DATABASE: Final[str] = "database"
SOURCE_MANUAL: Final[str] = "manual"

SOURCE_TYPES: Final[tuple[str, ...]] = (
    SOURCE_WINDOWS,
    SOURCE_LINUX,
    SOURCE_MACOS,
    SOURCE_ANDROID,
    SOURCE_EMAIL,
    SOURCE_NETWORK,
    SOURCE_WEB_APP,
    SOURCE_DATABASE,
    SOURCE_MANUAL,
)


# ============================================================================
# NOTIFICATION CHANNELS
# ============================================================================

NOTIFICATION_IN_APP: Final[str] = "in_app"
NOTIFICATION_EMAIL: Final[str] = "email"
NOTIFICATION_WEBHOOK: Final[str] = "webhook"

NOTIFICATION_CHANNELS: Final[tuple[str, ...]] = (
    NOTIFICATION_IN_APP,
    NOTIFICATION_EMAIL,
    NOTIFICATION_WEBHOOK,
)


# ============================================================================
# AUDIT ACTIONS
# ============================================================================
# Every sensitive action must be recorded in the audit log with one of these
# verbs. Never invent ad-hoc audit strings — add to this tuple.

AUDIT_LOGIN_SUCCESS: Final[str] = "auth.login.success"
AUDIT_LOGIN_FAILED: Final[str] = "auth.login.failed"
AUDIT_LOGOUT: Final[str] = "auth.logout"
AUDIT_TOKEN_REFRESH: Final[str] = "auth.token.refresh"

AUDIT_USER_CREATED: Final[str] = "user.created"
AUDIT_USER_UPDATED: Final[str] = "user.updated"
AUDIT_USER_SUSPENDED: Final[str] = "user.suspended"

AUDIT_ORG_CREATED: Final[str] = "organization.created"
AUDIT_ORG_UPDATED: Final[str] = "organization.updated"
AUDIT_ORG_DELETED: Final[str] = "organization.deleted"
AUDIT_ORG_MEMBER_INVITED: Final[str] = "organization.member.invited"
AUDIT_ORG_MEMBER_REMOVED: Final[str] = "organization.member.removed"

AUDIT_SOURCE_ENROLLED: Final[str] = "source.enrolled"
AUDIT_SOURCE_DISABLED: Final[str] = "source.disabled"
AUDIT_SOURCE_REVOKED: Final[str] = "source.revoked"
AUDIT_COLLECTOR_CREDENTIAL_ISSUED: Final[str] = "collector.credential.issued"
AUDIT_COLLECTOR_CREDENTIAL_REVOKED: Final[str] = "collector.credential.revoked"
AUDIT_COLLECTOR_CREDENTIAL_ROTATED: Final[str] = "collector.credential.rotated"

AUDIT_EVIDENCE_ACCESSED: Final[str] = "evidence.accessed"
AUDIT_EVIDENCE_UPLOADED: Final[str] = "evidence.uploaded"
AUDIT_EVIDENCE_DELETED: Final[str] = "evidence.deleted"

AUDIT_CASE_CREATED: Final[str] = "case.created"
AUDIT_CASE_ASSIGNED: Final[str] = "case.assigned"
AUDIT_CASE_REASSIGNED: Final[str] = "case.reassigned"
AUDIT_CASE_CLOSED: Final[str] = "case.closed"

AUDIT_INCIDENT_CREATED: Final[str] = "incident.created"
AUDIT_INCIDENT_SEVERITY_CHANGED: Final[str] = "incident.severity.changed"
AUDIT_INCIDENT_CLOSED: Final[str] = "incident.closed"

AUDIT_REPORT_GENERATED: Final[str] = "report.generated"
AUDIT_REPORT_DOWNLOADED: Final[str] = "report.downloaded"

AUDIT_ANALYST_VERIFIED: Final[str] = "analyst.verified"
AUDIT_ANALYST_REJECTED: Final[str] = "analyst.rejected"
AUDIT_ANALYST_ACCESS_GRANTED: Final[str] = "analyst.access.granted"
AUDIT_ANALYST_ACCESS_REVOKED: Final[str] = "analyst.access.revoked"

AUDIT_ADMIN_ACTION: Final[str] = "admin.action"
AUDIT_PLATFORM_CONFIG_CHANGED: Final[str] = "admin.platform_config.changed"

AUDIT_ACTIONS: Final[frozenset[str]] = frozenset(
    v for k, v in globals().items() if k.startswith("AUDIT_") and isinstance(v, str)
)


# ============================================================================
# WELL-KNOWN IDENTIFIERS
# ============================================================================
# Reserved identifiers used by the platform itself. These must never be
# assigned to a real user, org, or workspace.

SYSTEM_USER_ID: Final[str] = "00000000-0000-0000-0000-000000000000"
SYSTEM_USER_EMAIL: Final[str] = "system@cyberguard.local"
SYSTEM_ORG_ID: Final[str] = "00000000-0000-0000-0000-000000000001"
SYSTEM_WORKSPACE_ID: Final[str] = "00000000-0000-0000-0000-000000000002"


# ============================================================================
# TIME CONSTANTS & FORMATS
# ============================================================================

SECONDS_PER_MINUTE: Final[int] = 60
SECONDS_PER_HOUR: Final[int] = 3600
SECONDS_PER_DAY: Final[int] = 86400
SECONDS_PER_WEEK: Final[int] = 604800

#: Canonical UTC format used in logs and reports.
UTC_DATETIME_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"

#: Short date format for report headers.
DATE_FORMAT: Final[str] = "%Y-%m-%d"


# ============================================================================
# FILE / UPLOAD CONSTANTS
# ============================================================================

#: File extensions accepted for evidence uploads.
ALLOWED_EVIDENCE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".pdf",
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".zip",
        ".gz",
        ".pcap",
    }
)

#: File extensions refused even if MIME type looks OK (defense in depth).
DENIED_UPLOAD_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".bat",
        ".cmd",
        ".ps1",
        ".sh",
        ".msi",
        ".scr",
        ".vbs",
        ".jar",
        ".com",
    }
)

#: Maximum filename length for uploaded files.
MAX_FILENAME_LENGTH: Final[int] = 255


# ============================================================================
# SORT & FILTER DEFAULTS
# ============================================================================

DEFAULT_SORT_ORDER: Final[str] = "desc"
SORT_ORDER_ASC: Final[str] = "asc"
SORT_ORDER_DESC: Final[str] = "desc"
SORT_ORDERS: Final[tuple[str, ...]] = (SORT_ORDER_ASC, SORT_ORDER_DESC)


# ============================================================================
# ERROR CODES (mirror of exception default_code values)
# ============================================================================
# Only codes that cross the API boundary and appear in client error handling
# belong here. Most codes are declared inline in ``app.core.exceptions``.

ERROR_INTERNAL: Final[str] = "INTERNAL_ERROR"
ERROR_VALIDATION: Final[str] = "VALIDATION_ERROR"
ERROR_NOT_FOUND: Final[str] = "NOT_FOUND"
ERROR_UNAUTHORIZED: Final[str] = "AUTHENTICATION_REQUIRED"
ERROR_FORBIDDEN: Final[str] = "FORBIDDEN"
ERROR_CONFLICT: Final[str] = "CONFLICT"
ERROR_RATE_LIMITED: Final[str] = "RATE_LIMITED"


# ============================================================================
# AGENT NAMES
# ============================================================================
# Every agent must be identified by one of these names in logs, findings,
# and internal task messages. Do not use raw strings like "log_agent".

AGENT_EMAIL_ANALYSIS: Final[str] = "email_analysis"
AGENT_LOG_ANALYSIS: Final[str] = "log_analysis"
AGENT_NETWORK_ANALYSIS: Final[str] = "network_analysis"
AGENT_AI_ANALYST: Final[str] = "ai_analyst"
AGENT_THREAT_INTELLIGENCE: Final[str] = "threat_intelligence"
AGENT_IOC_CORRELATION: Final[str] = "ioc_correlation"
AGENT_INCIDENT_RESPONSE: Final[str] = "incident_response"
AGENT_REPORTING: Final[str] = "reporting"

AGENT_NAMES: Final[tuple[str, ...]] = (
    AGENT_EMAIL_ANALYSIS,
    AGENT_LOG_ANALYSIS,
    AGENT_NETWORK_ANALYSIS,
    AGENT_AI_ANALYST,
    AGENT_THREAT_INTELLIGENCE,
    AGENT_IOC_CORRELATION,
    AGENT_INCIDENT_RESPONSE,
    AGENT_REPORTING,
)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # API
    "API_VERSION", "API_PREFIX", "API_AUTH_PREFIX", "API_USERS_PREFIX",
    "API_ORGS_PREFIX", "API_WORKSPACES_PREFIX", "API_SOURCES_PREFIX",
    "API_ENROLLMENT_PREFIX", "API_COLLECTOR_PREFIX", "API_EVENTS_PREFIX",
    "API_FINDINGS_PREFIX", "API_ALERTS_PREFIX", "API_INCIDENTS_PREFIX",
    "API_CASES_PREFIX", "API_REPORTS_PREFIX", "API_NOTIFICATIONS_PREFIX",
    "API_AI_ANALYST_PREFIX", "API_MARKETPLACE_PREFIX", "API_ADMIN_PREFIX",
    "API_HEALTH_PREFIX",
    # Headers
    "HEADER_CORRELATION_ID", "HEADER_REQUEST_ID", "HEADER_COLLECTOR_CREDENTIAL",
    "HEADER_COLLECTOR_ID", "HEADER_COLLECTOR_VERSION", "HEADER_IDEMPOTENCY_KEY",
    # Content types
    "CONTENT_TYPE_JSON", "CONTENT_TYPE_FORM", "CONTENT_TYPE_MULTIPART",
    "CONTENT_TYPE_TEXT", "CONTENT_TYPE_PDF",
    # Permissions
    "ALL_PERMISSIONS",
    # Pagination
    "DEFAULT_PAGE_SIZE", "MIN_PAGE_SIZE", "MAX_PAGE_SIZE", "DEFAULT_PAGE_OFFSET",
    # Severity & priority
    "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_CRITICAL",
    "SEVERITY_ORDER", "SEVERITY_RANK", "SEVERITY_SCORE",
    "PRIORITY_LOW", "PRIORITY_MEDIUM", "PRIORITY_HIGH", "PRIORITY_URGENT",
    "PRIORITY_ORDER",
    # IOC types
    "IOC_TYPES", "IOC_IPV4", "IOC_IPV6", "IOC_DOMAIN", "IOC_URL",
    "IOC_MD5", "IOC_SHA1", "IOC_SHA256", "IOC_EMAIL", "IOC_USERNAME",
    "IOC_HOSTNAME", "IOC_CVE",
    # Source types
    "SOURCE_TYPES", "SOURCE_WINDOWS", "SOURCE_LINUX", "SOURCE_MACOS",
    "SOURCE_ANDROID", "SOURCE_EMAIL", "SOURCE_NETWORK", "SOURCE_WEB_APP",
    "SOURCE_DATABASE", "SOURCE_MANUAL",
    # Notifications
    "NOTIFICATION_IN_APP", "NOTIFICATION_EMAIL", "NOTIFICATION_WEBHOOK",
    "NOTIFICATION_CHANNELS",
    # Audit
    "AUDIT_ACTIONS",
    # Well-known IDs
    "SYSTEM_USER_ID", "SYSTEM_USER_EMAIL", "SYSTEM_ORG_ID", "SYSTEM_WORKSPACE_ID",
    # Time
    "SECONDS_PER_MINUTE", "SECONDS_PER_HOUR", "SECONDS_PER_DAY",
    "SECONDS_PER_WEEK", "UTC_DATETIME_FORMAT", "DATE_FORMAT",
    # Files
    "ALLOWED_EVIDENCE_EXTENSIONS", "DENIED_UPLOAD_EXTENSIONS", "MAX_FILENAME_LENGTH",
    # Sorting
    "DEFAULT_SORT_ORDER", "SORT_ORDER_ASC", "SORT_ORDER_DESC", "SORT_ORDERS",
    # Error codes
    "ERROR_INTERNAL", "ERROR_VALIDATION", "ERROR_NOT_FOUND",
    "ERROR_UNAUTHORIZED", "ERROR_FORBIDDEN", "ERROR_CONFLICT", "ERROR_RATE_LIMITED",
    # Agent names
    "AGENT_NAMES", "AGENT_EMAIL_ANALYSIS", "AGENT_LOG_ANALYSIS",
    "AGENT_NETWORK_ANALYSIS", "AGENT_AI_ANALYST", "AGENT_THREAT_INTELLIGENCE",
    "AGENT_IOC_CORRELATION", "AGENT_INCIDENT_RESPONSE", "AGENT_REPORTING",
]