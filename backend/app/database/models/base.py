"""
CyberGuard AI - Database Models

Defines the data models for database entities.
Uses Pydantic for validation and serialization.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Types of security events."""
    EMAIL = "email"
    LOG = "log"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    CUSTOM = "custom"


class EventStatus(str, Enum):
    """Processing status of events."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Status of alerts."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class NotificationChannel(str, Enum):
    """Delivery channel for a notification."""
    IN_APP = "in_app"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationStatus(str, Enum):
    """Delivery lifecycle of a notification. Set only by the sending
    service - never trust a client-supplied value for this field."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    READ = "read"


# ============================================================
# Event Model
# ============================================================

class Event(BaseModel):
    """A security event ingested for analysis."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    source: str
    raw_data: dict[str, Any]

    # Processing
    status: EventStatus = EventStatus.PENDING
    processed_at: datetime | None = None

    # Detection results
    risk_score: int = 0
    severity: SeverityLevel = SeverityLevel.INFO
    findings_count: int = 0

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Correlation
    correlation_id: str | None = None
    related_events: list[str] = Field(default_factory=list)

    # Phase 1 (Log Collection -> Automatic Detection): tenant ownership
    # and idempotency key. See the matching ALTER TABLE comment in
    # app/database/schema.py for the full rationale.
    tenant_id: str | None = None
    source_event_id: str | None = None


class EventCreate(BaseModel):
    """Schema for creating an event."""
    event_type: EventType
    source: str
    raw_data: dict[str, Any]

    # Phase 1: always server-resolved (tenant_id from the authenticated
    # caller's authorization, never raw client input; source_event_id
    # from an upstream identifier like log_events.id when this events
    # row is being created on behalf of a log-sourced finding).
    tenant_id: str | None = None
    source_event_id: str | None = None


# ============================================================
# Finding Model
# ============================================================

class FindingStatus(str, Enum):
    """Lifecycle status of a persisted finding (Phase 1)."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Finding(BaseModel):
    """A security finding from detection."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    detection_id: str

    # Finding details
    finding_type: str  # rule, ioc, anomaly
    rule_id: str | None = None
    severity: SeverityLevel
    confidence: float = 0.0

    # Content
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)

    # MITRE ATT&CK
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Phase 1 (Log Collection -> Automatic Detection): lifecycle status
    # and tenant ownership. tenant_id is always set at write time by
    # FindingRepository.create() from the parent event's resolved
    # tenant_id - never trusted from client input.
    status: FindingStatus = FindingStatus.NEW
    tenant_id: str | None = None

    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingCreate(BaseModel):
    """Schema for creating a finding (Phase 1)."""

    event_id: str
    detection_id: str
    finding_type: str
    rule_id: str | None = None
    severity: SeverityLevel
    confidence: float = 0.0
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tenant_id: str | None = None


class FindingQuery(BaseModel):
    """Query parameters for listing findings (Phase 1)."""

    event_id: str | None = None
    # Additive alongside event_id: used by the detection-report endpoint
    # (GET /logs/sources/{id}/report) to fetch findings for a whole batch
    # of events scoped to a source + time range in one query, instead of
    # N single-event_id round trips. event_id (singular) is left untouched
    # for existing single-event callers (e.g. GET /events/{event_id}/findings).
    event_ids: list[str] | None = None
    severity: SeverityLevel | None = None
    rule_id: str | None = None
    status: FindingStatus | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)

    # Tenant isolation - server-resolved only, same convention as
    # LogEventQuery.tenant_id/tenant_ids in app/logs/models.py. A single
    # value scopes to exactly that tenant; tenant_ids (a list) covers the
    # admin/multi-tenant case. Neither set means "no tenant filter" -
    # route handlers must always set one for an authenticated query.
    tenant_id: str | None = None
    tenant_ids: list[str] | None = None


# ============================================================
# Alert Model
# ============================================================

class Alert(BaseModel):
    """A security alert for analyst review."""

    id: str = Field(default_factory=lambda: str(uuid4()))

    # STEP 8.5.4.2: Deduplication and tenant isolation
    fingerprint: str | None = None  # Deterministic deduplication key
    tenant_id: str | None = None    # Tenant isolation

    # Source
    event_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    # Taxonomy the frontend filters on: email_security / log_security /
    # network_security (individual alert, set by _alert_category_for_source()
    # in app/correlation/finding_lifecycle.py) or correlated_threat (set by
    # the correlation alert path). Nullable since older rows predate this
    # column.
    category: str | None = None

    # Alert details
    title: str
    description: str
    severity: SeverityLevel
    risk_score: int = 0

    # Status
    status: AlertStatus = AlertStatus.NEW
    assigned_to: str | None = None

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None

    # Context
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    # MITRE mapping
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Response
    notes: list[dict[str, Any]] = Field(default_factory=list)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)


class AlertCreate(BaseModel):
    """Schema for creating an alert."""
    title: str
    description: str
    severity: SeverityLevel
    risk_score: int = 0
    event_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)


class AlertUpdate(BaseModel):
    """Schema for updating an alert."""
    status: AlertStatus | None = None
    assigned_to: str | None = None
    notes: str | None = None


# ============================================================
# Notification Model
# ============================================================

class Notification(BaseModel):
    """A per-recipient delivery record for an alert.

    Distinct from Alert (tenant-wide detection) - one alert fans out
    into zero or more Notification rows, one per (recipient, channel).
    """

    id: str = Field(default_factory=lambda: str(uuid4()))

    alert_id: str | None = None

    tenant_id: str | None = None
    recipient_user_id: str
    recipient_address: str | None = None

    channel: NotificationChannel
    severity: SeverityLevel

    title: str
    summary: str

    fingerprint: str

    status: NotificationStatus = NotificationStatus.PENDING
    attempts: int = 0
    last_error: str | None = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    queued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sent_at: datetime | None = None
    read_at: datetime | None = None


class NotificationCreate(BaseModel):
    """Schema for creating a notification."""
    alert_id: str | None = None
    tenant_id: str | None = None
    recipient_user_id: str
    recipient_address: str | None = None
    channel: NotificationChannel
    severity: SeverityLevel
    title: str
    summary: str
    fingerprint: str


# ============================================================
# IOC Model (for persistent storage)
# ============================================================

class IOCRecord(BaseModel):
    """An IOC stored in the database."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    ioc_type: str  # ip, domain, url, hash, etc.
    value: str
    threat_level: str  # critical, high, medium, low

    description: str = ""
    source: str = "manual"
    tags: list[str] = Field(default_factory=list)

    # Status
    active: bool = True
    verified: bool = False

    # Timestamps
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None

    # Stats
    hit_count: int = 0
