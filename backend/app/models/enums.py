"""
CyberGuard AI — Database Enumerations
============================================================================

The shared vocabulary of the platform. Every model, schema, service, agent,
and test compares against these strings.

Design decisions
----------------
1. **VARCHAR + CHECK constraint, not native PostgreSQL ENUM.**
   Native PG enums cannot be safely altered in place: adding a value
   requires ``ALTER TYPE ... ADD VALUE``, removing a value is impossible,
   and Alembic autogenerate produces brittle migrations. ``VARCHAR + CHECK``
   provides the same database-level integrity while remaining fully
   transactional to change. Adding a new enum value in the future is a
   single ``ALTER TABLE ... DROP/ADD CONSTRAINT`` migration.

2. **Every enum inherits ``StrEnum(str, Enum)``.**
   Gives ``str(member)`` returns ``member.value`` — essential for JSON
   serialization and for SQLAlchemy to store the string value directly.
   Also provides ``.values()``, ``.is_valid()``, and ``.coerce()``.

3. **Values are added, never removed.**
   Removing an enum value would orphan existing rows and break the CHECK
   constraint. If a value becomes obsolete, mark it deprecated in the
   docstring but keep it in the enum. Historical data retains its meaning.

4. **``enum_column_type(EnumClass)`` returns a pre-configured SAEnum.**
   Models write::

       status: Mapped[UserStatus] = mapped_column(
           enum_column_type(UserStatus), nullable=False
       )

   instead of the verbose ``SAEnum(...)`` call with six arguments.

5. **One column per enum per table.** ``enum_column_type`` names the CHECK
   constraint after the enum class, so two columns of the same enum in the
   same table would collide. For that rare case, pass an explicit ``name=``::

       enum_column_type(IncidentStatus, name="incident_previous_status")

Enum catalog (33 total)
-----------------------
Identity:      UserStatus, OrganizationStatus, WorkspaceType,
               OrganizationRole, WorkspaceRole, AnalystVerificationStatus
Sources:       SourceType, SourceStatus, EnrollmentStatus, CredentialStatus
Detection:     EventSeverity, EventCategory, FindingStatus, FindingCategory,
               AlertStatus, IncidentStatus, IncidentSeverity
Workflow:      CaseStatus, CasePriority, AssignmentStatus, AccessGrantScope,
               EvidenceType
Communication: ConversationStatus, MessageType, NotificationType,
               NotificationChannel
Deliverables:  ReportType, ReportStatus, InvitationStatus
Commerce:      ServiceOfferingStatus, PurchaseStatus, PaymentStatus
Governance:    AuditOutcome
"""

from __future__ import annotations

import re
from enum import Enum

from sqlalchemy import Enum as SAEnum


# ============================================================================
# BASE CLASS
# ============================================================================

class StrEnum(str, Enum):
    """
    Base class for all CyberGuard enums.

    Inherits from both ``str`` and ``Enum`` so that:

      - ``str(member)`` returns ``member.value`` (override below)
      - ``member == "value"`` works without conversion
      - Pydantic serializes to the string value in JSON
      - SQLAlchemy stores the string value in the database column
    """

    def __str__(self) -> str:
        return self.value

    @classmethod
    def values(cls) -> tuple[str, ...]:
        """Return all string values in declaration order."""
        return tuple(member.value for member in cls)

    @classmethod
    def is_valid(cls, value: object) -> bool:
        """Return ``True`` if ``value`` is a valid member value."""
        if not isinstance(value, str):
            return False
        return value in cls.values()

    @classmethod
    def coerce(cls, value: "StrEnum | str") -> "StrEnum":
        """
        Return the enum member for ``value``.

        Accepts either an enum member (returned as-is) or the string value.
        Raises ``ValueError`` for unknown values.
        """
        if isinstance(value, cls):
            return value
        return cls(value)


# ============================================================================
# IDENTITY & ACCESS
# ============================================================================

class UserStatus(StrEnum):
    """Lifecycle states for a user account."""

    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


class OrganizationStatus(StrEnum):
    """Lifecycle states for an organization."""

    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class WorkspaceType(StrEnum):
    """Kind of workspace. Determines default membership and permissions."""

    PERSONAL = "personal"
    ORGANIZATION = "organization"
    SHARED = "shared"


class OrganizationRole(StrEnum):
    """Membership roles within an organization."""

    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_MANAGER = "security_manager"
    ANALYST = "analyst"
    EMPLOYEE = "employee"
    VIEWER = "viewer"


class WorkspaceRole(StrEnum):
    """Roles within a single workspace."""

    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class AnalystVerificationStatus(StrEnum):
    """Verification state of a security analyst's professional profile."""

    PENDING = "pending"
    IN_REVIEW = "in_review"
    VERIFIED = "verified"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


# ============================================================================
# SOURCES & COLLECTORS
# ============================================================================

class SourceType(StrEnum):
    """Category of security telemetry source."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    EMAIL = "email"
    NETWORK = "network"
    WEB_APP = "web_app"
    DATABASE = "database"
    MANUAL = "manual"
    OTHER = "other"


class SourceStatus(StrEnum):
    """
    Connection and monitoring state of a security source.

    Distinct from ``collector_connected`` — the source may be enrolled but
    not sending events. The UI must render all states separately.
    """

    PENDING_ENROLLMENT = "pending_enrollment"
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class EnrollmentStatus(StrEnum):
    """Lifecycle of a one-time source enrollment token."""

    PENDING = "pending"
    REDEEMED = "redeemed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CredentialStatus(StrEnum):
    """Lifecycle of a collector credential (long-lived auth token)."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ============================================================================
# DETECTION
# ============================================================================

class EventSeverity(StrEnum):
    """
    Severity assigned to a security event.

    ``INFO`` is intentionally included — some events are logged for
    completeness but do not indicate risk (e.g. successful logins).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(StrEnum):
    """High-level category of what kind of activity an event describes."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    FILE = "file"
    PROCESS = "process"
    DATABASE = "database"
    EMAIL = "email"
    SYSTEM = "system"
    OTHER = "other"


class FindingStatus(StrEnum):
    """Lifecycle of an agent-generated finding."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"


class FindingCategory(StrEnum):
    """Type of threat a finding represents."""

    PHISHING = "phishing"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    THREAT_INTEL_HIT = "threat_intel_hit"
    CORRELATED_ACTIVITY = "correlated_activity"
    OTHER = "other"


class AlertStatus(StrEnum):
    """Lifecycle of a user-facing alert. Alerts are lower-ceremony than incidents."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentStatus(StrEnum):
    """
    NIST SP 800-61–aligned incident lifecycle.

    A single incident may contain multiple alerts and findings, linked
    via ``IncidentEventLink`` and ``Alert.incident_id``.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(StrEnum):
    """
    Severity of an incident.

    Distinct from ``EventSeverity`` because incidents are an *aggregation*
    of many events — a series of ``medium`` events may justify a ``high``
    incident. The aggregation rule lives in the Incident Response Agent.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# WORKFLOW (CASE, EVIDENCE, ASSIGNMENT)
# ============================================================================

class CaseStatus(StrEnum):
    """Lifecycle of a security case assigned to an analyst."""

    OPEN = "open"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    PENDING_CLIENT = "pending_client"
    PENDING_INFO = "pending_info"
    RESOLVED = "resolved"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class CasePriority(StrEnum):
    """Operational urgency of a case (distinct from its severity)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class AssignmentStatus(StrEnum):
    """State of an analyst's assignment to a case."""

    ACTIVE = "active"
    COMPLETED = "completed"
    REASSIGNED = "reassigned"
    CANCELLED = "cancelled"


class AccessGrantScope(StrEnum):
    """
    Scope of an analyst's access grant to a case.

    Always use the least-privileged scope that satisfies the engagement.
    """

    CASE_READ = "case_read"
    EVIDENCE_READ = "evidence_read"
    CONVERSATION_READ = "conversation_read"
    FULL_CASE = "full_case"


class EvidenceType(StrEnum):
    """Kind of evidence attached to a case."""

    FILE = "file"
    LOG_SNIPPET = "log_snippet"
    NETWORK_CAPTURE = "network_capture"
    SCREENSHOT = "screenshot"
    EMAIL_ARTIFACT = "email_artifact"
    OTHER = "other"


# ============================================================================
# COMMUNICATION
# ============================================================================

class ConversationStatus(StrEnum):
    """Lifecycle of a case conversation thread."""

    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class MessageType(StrEnum):
    """Type of message within a case conversation."""

    TEXT = "text"
    SYSTEM_EVENT = "system_event"
    EVIDENCE_REFERENCE = "evidence_reference"
    STATUS_CHANGE = "status_change"


class NotificationType(StrEnum):
    """Kind of event that produced a notification."""

    ALERT_CREATED = "alert_created"
    INCIDENT_CREATED = "incident_created"
    CASE_ASSIGNED = "case_assigned"
    CASE_REASSIGNED = "case_reassigned"
    CASE_STATUS_CHANGED = "case_status_changed"
    MESSAGE_RECEIVED = "message_received"
    REPORT_READY = "report_ready"
    SYSTEM_NOTICE = "system_notice"
    INVITATION_RECEIVED = "invitation_received"
    ANALYST_VERIFIED = "analyst_verified"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"


class NotificationChannel(StrEnum):
    """Delivery channel for a notification."""

    IN_APP = "in_app"
    EMAIL = "email"
    WEBHOOK = "webhook"


# ============================================================================
# DELIVERABLES (REPORTS & INVITATIONS)
# ============================================================================

class ReportType(StrEnum):
    """Kind of security report."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    INCIDENT = "incident"
    PHISHING = "phishing"
    LOG_ANALYSIS = "log_analysis"
    NETWORK = "network"
    THREAT_INTEL = "threat_intel"
    ORG_RISK = "org_risk"
    ANALYST_PERFORMANCE = "analyst_performance"
    CUSTOM = "custom"


class ReportStatus(StrEnum):
    """Generation state of a security report."""

    QUEUED = "queued"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"
    EXPIRED = "expired"


class InvitationStatus(StrEnum):
    """Lifecycle of an organization invitation."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


# ============================================================================
# COMMERCE (MARKETPLACE)
# ============================================================================

class ServiceOfferingStatus(StrEnum):
    """Lifecycle of an analyst's published service offering."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class PurchaseStatus(StrEnum):
    """Lifecycle of a user's purchase of an analyst service."""

    PENDING = "pending"
    PAYMENT_PROCESSING = "payment_processing"
    PAID = "paid"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class PaymentStatus(StrEnum):
    """State of an individual payment transaction."""

    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"


# ============================================================================
# GOVERNANCE
# ============================================================================

class AuditOutcome(StrEnum):
    """Result recorded for a security audit log entry."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


# ============================================================================
# SQLALCHEMY COLUMN HELPER
# ============================================================================

_SNAKE_CASE_1 = re.compile(r"(.)([A-Z][a-z]+)")
_SNAKE_CASE_2 = re.compile(r"([a-z0-9])([A-Z])")


def _to_snake_case(name: str) -> str:
    """Convert a CamelCase class name to snake_case for constraint names."""
    step1 = _SNAKE_CASE_1.sub(r"\1_\2", name)
    return _SNAKE_CASE_2.sub(r"\1_\2", step1).lower()


def enum_column_type(
    enum_cls: type[StrEnum],
    *,
    length: int = 32,
    name: str | None = None,
) -> SAEnum:
    """
    Return a pre-configured SQLAlchemy ``Enum`` column type for a CyberGuard
    enum class.

    The resulting column is ``VARCHAR(length)`` in PostgreSQL with a CHECK
    constraint restricting it to the enum's values. Adding a new enum value
    in the future requires only an ``ALTER TABLE ... DROP/ADD CONSTRAINT``
    migration — no native enum type to alter.

    Parameters
    ----------
    enum_cls:
        The StrEnum subclass to convert.
    length:
        Width of the VARCHAR column. Defaults to 32; increase only if a
        value ever exceeds 32 characters.
    name:
        Optional override for the constraint name. Required only when a
        single table has two columns of the same enum type.

    Example
    -------
        from sqlalchemy.orm import Mapped, mapped_column
        from app.models.enums import UserStatus, enum_column_type

        class User(Base):
            status: Mapped[UserStatus] = mapped_column(
                enum_column_type(UserStatus),
                nullable=False,
                default=UserStatus.PENDING_VERIFICATION,
                server_default=UserStatus.PENDING_VERIFICATION.value,
            )
    """
    if not (isinstance(enum_cls, type) and issubclass(enum_cls, StrEnum)):
        raise TypeError(
            f"enum_column_type expects a StrEnum subclass, got {enum_cls!r}"
        )

    resolved_name = name or _to_snake_case(enum_cls.__name__)

    return SAEnum(
        enum_cls,
        native_enum=False,
        create_constraint=True,
        length=length,
        name=resolved_name,
        validate_strings=True,
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Base
    "StrEnum",
    "enum_column_type",
    # Identity
    "UserStatus",
    "OrganizationStatus",
    "WorkspaceType",
    "OrganizationRole",
    "WorkspaceRole",
    "AnalystVerificationStatus",
    # Sources
    "SourceType",
    "SourceStatus",
    "EnrollmentStatus",
    "CredentialStatus",
    # Detection
    "EventSeverity",
    "EventCategory",
    "FindingStatus",
    "FindingCategory",
    "AlertStatus",
    "IncidentStatus",
    "IncidentSeverity",
    # Workflow
    "CaseStatus",
    "CasePriority",
    "AssignmentStatus",
    "AccessGrantScope",
    "EvidenceType",
    # Communication
    "ConversationStatus",
    "MessageType",
    "NotificationType",
    "NotificationChannel",
    # Deliverables
    "ReportType",
    "ReportStatus",
    "InvitationStatus",
    # Commerce
    "ServiceOfferingStatus",
    "PurchaseStatus",
    "PaymentStatus",
    # Governance
    "AuditOutcome",
]