"""
CyberGuard AI — Security Event Model
============================================================================

The ``security_events`` table: the highest-volume table in the platform.

Every log line, email scan result, network connection, database audit
record, and manual report from every collector becomes one row here.
A mid-sized organization generates millions of rows per year.

Every design decision in this file exists to answer one of five questions:

    Ingestion:   can we write events fast enough?
    Query:       can the dashboard show recent events fast enough?
    Detection:   do agents have the fields they need to reason about?
    Storage:     are we storing things we'll never read?
    Forensics:   can we replay an incident a year later?

Design decisions
----------------
1. **Fingerprint-based deduplication.**
   Every event carries a SHA-256 hash of its normalized payload, scoped
   by source. A collector that retries after a network blip sends the same
   event twice — the unique constraint rejects the duplicate silently.
   Without this, one flaky network cable creates thousands of duplicate
   alerts. Fingerprint computation lives in ``app.services.event_fingerprint``.

2. **Two payloads, both JSONB.**

       raw_payload         — exactly what the collector sent. Forensic only.
       normalized_payload  — standardized shape. What agents consume.

   Storage cost is doubled; forensic value is preserved. For a security
   platform, this is the correct trade-off — ``raw_payload`` is what
   enables "re-run the rules against 6-month-old events to see if
   detection has improved."

3. **``event_time`` ≠ ``received_at``.**

       event_time    — when the event happened on the source
       received_at   — when the backend accepted it

   They differ by milliseconds (normal) or hours (offline collectors
   catching up after downtime). Detection rules must use ``event_time``;
   retention/cleanup must use ``received_at``.

4. **15 denormalized entity columns.**
   ``username``, ``hostname``, ``source_ip``, ``destination_ip``,
   ``source_port``, ``destination_port``, ``process_name``,
   ``process_id``, ``file_path``, ``url``, ``domain``, ``email_address``,
   ``hash_md5``, ``hash_sha256``, and ``metadata`` (JSONB for the long
   tail).

   These are what agents and correlation rules query constantly. Indexed
   columns make those queries fast; ``JSONB ->>`` extraction would be
   slow at scale.

5. **``workspace_id: CASCADE``, ``source_id: SET NULL``.**
   If a workspace is deleted (GDPR), its events go with it. If a source
   is deleted (user removed their device), events persist — forensic
   history survives — but lose FK attribution. The denormalized
   ``hostname`` and ``source_ip`` cover the UI gap.

6. **No ``SoftDeleteMixin``.** Events are hard-deleted by the retention
   service after ``RETENTION_EVENTS_DAYS``. Soft-delete on the highest-
   volume table would double storage cost for zero benefit.

7. **Minimal index set.** For a high-write table, each index slows every
   insert. Only 6 indexes, chosen because they cover the actual query
   patterns. Additional indexes should be added only after
   ``EXPLAIN ANALYZE`` proves them necessary.

8. **Partitioning-ready.** ``received_at`` is ``NOT NULL TIMESTAMPTZ
   DEFAULT now()``. A future migration can add monthly partitioning on
   this column without a table rewrite.

9. **``findings_count`` denormalized.** Incremented transactionally by
   the finding-creation service. Enables "show only events that triggered
   detection" without a JOIN.

Usage
-----
    from app.models import SecurityEvent
    from app.models.enums import EventCategory, EventSeverity

    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=datetime.fromisoformat(payload["timestamp"]),
        severity=EventSeverity.HIGH,
        category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        action="login",
        outcome="failure",
        username="alice",
        source_ip="203.0.113.42",
        fingerprint="a" * 64,
        raw_payload=payload,
        normalized_payload={
            "user": "alice",
            "src_ip": "203.0.113.42",
            "attempts": 1,
        },
    )
    db.add(event)
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    EventCategory,
    EventSeverity,
    enum_column_type,
)


#: Reasonable limits enforced at ORM level. The real work is done by the
#: ingestion validator (app.services.collector_event_validation).
_MAX_EVENT_TYPE_LENGTH = 64
_MAX_ACTION_LENGTH = 64
_MAX_OUTCOME_LENGTH = 32
_MAX_USERNAME_LENGTH = 255
_MAX_HOSTNAME_LENGTH = 255
_MAX_IP_ADDRESS_LENGTH = 45  # IPv6 max with zone id
_MAX_PROCESS_NAME_LENGTH = 255
_MAX_DOMAIN_LENGTH = 253
_MAX_EMAIL_LENGTH = 320
_MAX_HASH_MD5_LENGTH = 32
_MAX_HASH_SHA256_LENGTH = 64
_MAX_URL_LENGTH = 2048
_MAX_FILE_PATH_LENGTH = 4096
_MAX_FINGERPRINT_LENGTH = 64  # SHA-256 hex

#: Guardrail on raw payload size. The collector-side limit
#: (COLLECTOR_EVENT_MAX_SIZE_BYTES, default 256 KB) should fire first;
#: this is defense-in-depth against a misbehaving collector.
_MAX_RAW_PAYLOAD_BYTES = 1_048_576  # 1 MB


class SecurityEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single security event ingested from a collector.

    One row per event. Deduplicated by (workspace_id, fingerprint).
    Hard-deleted by the retention service after ``RETENTION_EVENTS_DAYS``.
    """

    __tablename__ = "security_events"

    __table_args__ = (
        # Fingerprint is SHA-256 hex (64 lowercase hex chars).
        CheckConstraint(
            r"fingerprint ~ '^[a-f0-9]{64}$'",
            name="fingerprint_format",
        ),
        # Ports: 0–65535 (0 permitted for some ICMP-style events).
        CheckConstraint(
            "source_port IS NULL OR (source_port >= 0 AND source_port <= 65535)",
            name="source_port_range",
        ),
        CheckConstraint(
            "destination_port IS NULL OR "
            "(destination_port >= 0 AND destination_port <= 65535)",
            name="destination_port_range",
        ),
        # Findings count non-negative.
        CheckConstraint(
            "findings_count >= 0",
            name="findings_count_non_negative",
        ),
        # Raw payload size positive.
        CheckConstraint(
            "raw_payload_size_bytes >= 0",
            name="raw_payload_size_non_negative",
        ),
        # Deduplication: unique per (workspace, fingerprint).
        Index(
            "uq_events_workspace_fingerprint",
            "workspace_id",
            "fingerprint",
            unique=True,
        ),
        # Main query: recent events in a workspace.
        Index(
            "ix_events_workspace_received",
            "workspace_id",
            "received_at",
        ),
        # Per-source queries ("events from this device").
        Index(
            "ix_events_source_received",
            "source_id",
            "received_at",
        ),
        # Filtered views (dashboard severity filters).
        Index(
            "ix_events_workspace_severity_received",
            "workspace_id",
            "severity",
            "received_at",
        ),
        # Agent queries by event_type within a workspace.
        Index(
            "ix_events_workspace_type_received",
            "workspace_id",
            "event_type",
            "received_at",
        ),
        # IOC correlation: find all events touching an IP.
        Index(
            "ix_events_workspace_source_ip",
            "workspace_id",
            "source_ip",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Tenant & source
    # ────────────────────────────────────────────────────────────────────

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tenant boundary. Deleting the workspace deletes all its events.",
    )

    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Source that produced this event. NULL after source hard-delete — "
            "denormalized hostname/source_ip preserve the entity data."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Timestamps
    # ────────────────────────────────────────────────────────────────────

    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment=(
            "When the event happened **on the source**. Timezone-aware UTC. "
            "Detection rules must use this, not received_at."
        ),
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(__import__("datetime").timezone.utc),
        server_default=func.now(),
        comment=(
            "When the backend accepted this event. Auto-set. Used by retention "
            "and lifecycle queries. Distinct from event_time."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Classification
    # ────────────────────────────────────────────────────────────────────

    severity: Mapped[EventSeverity] = mapped_column(
        enum_column_type(EventSeverity),
        nullable=False,
        default=EventSeverity.INFO,
        server_default=EventSeverity.INFO.value,
        comment="Initial severity from the source. Agents may upgrade it in findings.",
    )

    category: Mapped[EventCategory] = mapped_column(
        enum_column_type(EventCategory),
        nullable=False,
        default=EventCategory.OTHER,
        server_default=EventCategory.OTHER.value,
        comment="What kind of activity (authentication, network, file, ...).",
    )

    event_type: Mapped[str] = mapped_column(
        String(_MAX_EVENT_TYPE_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Free-form type string (e.g. 'failed_login', 'port_scan', "
            "'process_start'). Every agent rule references specific types."
        ),
    )

    action: Mapped[str | None] = mapped_column(
        String(_MAX_ACTION_LENGTH),
        nullable=True,
        comment="What happened (login, logout, execute, read, write, connect, block).",
    )

    outcome: Mapped[str | None] = mapped_column(
        String(_MAX_OUTCOME_LENGTH),
        nullable=True,
        comment="Result of the action (success, failure, denied, unknown).",
    )

    # ────────────────────────────────────────────────────────────────────
    # Deduplication fingerprint
    # ────────────────────────────────────────────────────────────────────

    fingerprint: Mapped[str] = mapped_column(
        String(_MAX_FINGERPRINT_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "SHA-256 hex of (source || event_time_ms || event_type || "
            "action || outcome || username || source_ip || destination_ip). "
            "Computed by app.services.event_fingerprint. Unique per workspace."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Entities (denormalized for query speed)
    # ────────────────────────────────────────────────────────────────────

    username: Mapped[str | None] = mapped_column(
        String(_MAX_USERNAME_LENGTH),
        nullable=True,
        index=True,
        comment="User involved in the event. May not exist as a platform user.",
    )

    hostname: Mapped[str | None] = mapped_column(
        String(_MAX_HOSTNAME_LENGTH),
        nullable=True,
        comment="Device hostname reported by the collector.",
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(_MAX_IP_ADDRESS_LENGTH),
        nullable=True,
        index=True,
        comment="Source IP address (IPv4 or IPv6). Used by IOC correlation.",
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(_MAX_IP_ADDRESS_LENGTH),
        nullable=True,
        index=True,
        comment="Destination IP address. Used by IOC correlation.",
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Source port (0–65535), when applicable.",
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Destination port (0–65535), when applicable.",
    )

    process_name: Mapped[str | None] = mapped_column(
        String(_MAX_PROCESS_NAME_LENGTH),
        nullable=True,
        comment="Executable name involved in the event.",
    )

    process_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Operating-system process ID, when applicable.",
    )

    file_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="File path involved in the event (long — can exceed 255 chars).",
    )

    url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="URL involved (email links, HTTP requests).",
    )

    domain: Mapped[str | None] = mapped_column(
        String(_MAX_DOMAIN_LENGTH),
        nullable=True,
        comment="Domain involved (email sender, DNS query, HTTP host).",
    )

    email_address: Mapped[str | None] = mapped_column(
        String(_MAX_EMAIL_LENGTH),
        nullable=True,
        comment="Email address involved (sender or recipient).",
    )

    hash_md5: Mapped[str | None] = mapped_column(
        String(_MAX_HASH_MD5_LENGTH),
        nullable=True,
        comment="MD5 hash of a file involved in the event.",
    )

    hash_sha256: Mapped[str | None] = mapped_column(
        String(_MAX_HASH_SHA256_LENGTH),
        nullable=True,
        comment="SHA-256 hash of a file involved in the event.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Payloads
    # ────────────────────────────────────────────────────────────────────

    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Exactly what the collector sent. Forensic replay only.",
    )

    normalized_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Standardized event shape. What agents consume.",
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Additional key-value context not covered by the entity columns.",
    )

    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Free-form tags (e.g. ['web_server', 'production', 'finance']).",
    )

    # ────────────────────────────────────────────────────────────────────
    # Denormalized counters
    # ────────────────────────────────────────────────────────────────────

    findings_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="How many agent_findings reference this event. Maintained by finding service.",
    )

    raw_payload_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Size of raw_payload in bytes. Used for retention analytics and alerts.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("fingerprint")
    def _validate_fingerprint(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="fingerprint must be a string",
                code="EVENT_FINGERPRINT_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if len(normalized) != 64 or not all(c in "0123456789abcdef" for c in normalized):
            raise ValidationError(
                message="fingerprint must be 64 lowercase hex characters (SHA-256)",
                code="EVENT_FINGERPRINT_INVALID_FORMAT",
                details={"length": len(normalized)},
            )
        return normalized

    @validates("event_type")
    def _validate_event_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="event_type must be a string",
                code="EVENT_TYPE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="event_type must not be empty",
                code="EVENT_TYPE_EMPTY",
            )
        if len(stripped) > _MAX_EVENT_TYPE_LENGTH:
            raise ValidationError(
                message=f"event_type must not exceed {_MAX_EVENT_TYPE_LENGTH} characters",
                code="EVENT_TYPE_TOO_LONG",
            )
        return stripped

    @validates("severity")
    def _validate_severity(
        self, _key: str, value: EventSeverity | str
    ) -> EventSeverity:
        if isinstance(value, EventSeverity):
            return value
        if isinstance(value, str):
            try:
                return EventSeverity(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid severity {value!r}",
                    code="EVENT_SEVERITY_INVALID",
                    details={"allowed": list(EventSeverity.values())},
                ) from exc
        raise ValidationError(
            message="severity must be an EventSeverity or string",
            code="EVENT_SEVERITY_INVALID_TYPE",
        )

    @validates("category")
    def _validate_category(
        self, _key: str, value: EventCategory | str
    ) -> EventCategory:
        if isinstance(value, EventCategory):
            return value
        if isinstance(value, str):
            try:
                return EventCategory(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid category {value!r}",
                    code="EVENT_CATEGORY_INVALID",
                    details={"allowed": list(EventCategory.values())},
                ) from exc
        raise ValidationError(
            message="category must be an EventCategory or string",
            code="EVENT_CATEGORY_INVALID_TYPE",
        )

    @validates("source_ip", "destination_ip")
    def _validate_ip(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string or None",
                code="EVENT_IP_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_IP_ADDRESS_LENGTH:
            raise ValidationError(
                message=f"{key} must not exceed {_MAX_IP_ADDRESS_LENGTH} characters",
                code="EVENT_IP_TOO_LONG",
            )
        return stripped

    @validates("tags")
    def _validate_tags(self, _key: str, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="tags must be a list of strings",
                code="EVENT_TAGS_INVALID_TYPE",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each tag must be a string",
                    code="EVENT_TAG_INVALID_TYPE",
                )
            stripped = item.strip().lower()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 64:
                raise ValidationError(
                    message="each tag must not exceed 64 characters",
                    code="EVENT_TAG_TOO_LONG",
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_critical(self) -> bool:
        """True if severity is CRITICAL."""
        return self.severity == EventSeverity.CRITICAL

    @property
    def is_high_or_critical(self) -> bool:
        """True if severity is HIGH or CRITICAL."""
        return self.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)

    @property
    def has_findings(self) -> bool:
        """True if any agent finding references this event."""
        return self.findings_count > 0

    @property
    def is_success(self) -> bool:
        """True if the outcome field indicates success."""
        return (self.outcome or "").lower() == "success"

    @property
    def is_failure(self) -> bool:
        """True if the outcome field indicates failure."""
        return (self.outcome or "").lower() == "failure"


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.workspace import Workspace
#     from app.models.source import SecuritySource
#     from app.models.finding import AgentFinding
#     from app.models.incident import IncidentEventLink
#
# class SecurityEvent(...):
#     ...
#     workspace: Mapped["Workspace"] = relationship(
#         "Workspace", back_populates="events"
#     )
#     source: Mapped["SecuritySource | None"] = relationship(
#         "SecuritySource", back_populates="events"
#     )
#     findings: Mapped[list["AgentFinding"]] = relationship(
#         "AgentFinding",
#         back_populates="event",
#         cascade="all, delete-orphan",
#     )
#     incident_links: Mapped[list["IncidentEventLink"]] = relationship(
#         "IncidentEventLink",
#         back_populates="event",
#         cascade="all, delete-orphan",
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityEvent",
    "_MAX_EVENT_TYPE_LENGTH",
    "_MAX_ACTION_LENGTH",
    "_MAX_OUTCOME_LENGTH",
    "_MAX_USERNAME_LENGTH",
    "_MAX_HOSTNAME_LENGTH",
    "_MAX_IP_ADDRESS_LENGTH",
    "_MAX_PROCESS_NAME_LENGTH",
    "_MAX_DOMAIN_LENGTH",
    "_MAX_EMAIL_LENGTH",
    "_MAX_HASH_MD5_LENGTH",
    "_MAX_HASH_SHA256_LENGTH",
    "_MAX_URL_LENGTH",
    "_MAX_FILE_PATH_LENGTH",
    "_MAX_FINGERPRINT_LENGTH",
    "_MAX_RAW_PAYLOAD_BYTES",
]