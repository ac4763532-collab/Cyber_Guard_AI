"""
CyberGuard AI — Security Alerts Model
============================================================================

The ``security_alerts`` table: user-facing notifications promoted from
one or more agent findings.

An alert is a **policy decision**, not a filter. It exists only when an
explicit promotion rule says: "this is worth interrupting a human about".

Design decisions
----------------
1. **Alert ≠ Finding ≠ Event ≠ Incident.**

       Event     — raw telemetry (millions/day)
       Finding   — agent detection claim (hundreds/day)
       Alert     — user-facing notification (dozens/day)
       Incident  — managed investigation (weekly)

   Each tier aggregates the previous. Promotion thresholds are enforced by
   ``alert_service`` (future file), not by the model.

2. **Fingerprint dedup at the pattern level.**
   Same attack pattern (same category + severity + source scope) that
   fires repeatedly → same alert row, ``occurrence_count`` increments.
   Distinct from finding fingerprints (per-event-specific).

3. **Partial unique index** on ``(workspace_id, fingerprint) WHERE
   resolved_at IS NULL``. Active alerts of the same pattern consolidate;
   once resolved, a new occurrence creates a **new** alert. Chain linked
   via ``previous_alert_id`` so history is preserved.

4. **``previous_alert_id`` self-FK.** Enables pattern history across
   resolutions: "this attacker has triggered 12 separate alerts over 6
   months."

5. **``alert_type`` as ``VARCHAR + CHECK``, not an enum.**
   Four values: ``security``, ``operational``, ``compliance``, ``system``.
   Distinct from ``category`` (which is the threat type). Operational
   alerts (collector down) share the notification UX but aren't threats.

6. **``finding_ids`` JSONB array, not a join table.**
   One alert can aggregate hundreds of findings. Same rationale as
   ``event_ids`` in finding.py.

7. **Notification tracking fields.**
   ``notification_sent`` (bool), ``notification_channels_sent`` (JSONB
   array), ``notification_attempts`` (int). Notifications can fail;
   channels differ. This tuple proves state for compliance queries.

8. **User engagement timestamps.**
   ``seen_at`` (user opened the alert), ``acknowledged_at`` (user
   confirmed awareness). Enables SLA measurement and
   "was this user warned?" compliance queries.

9. **``recommended_actions`` JSONB — agent-suggested next steps.**
   E.g. ``[{"action": "reset_password", "priority": "high"},
   {"action": "isolate_device", "target": "host-xyz"}]``. Shown to the
   user as one-click suggestions.

10. **``context`` JSONB — aggregated attacker context.**
    Devices affected, users involved, time range, IPs, MITRE techniques
    seen. Populated by ``alert_service`` when combining findings.

11. **``assigned_to_id`` distinct from case assignment.**
    Alert-level triage (fast) vs case-level investigation (slow).

12. **``incident_id`` FK for promotion.** When the incident response
    agent creates an incident, it links the source alerts here.

13. **No ``SoftDeleteMixin``.** Alerts are hard-deleted after
    ``RETENTION_ALERTS_DAYS`` (365). ``RESOLVED``/``DISMISSED`` status
    keeps historical records.

14. **``priority`` separate from ``severity``.**
    Severity = intrinsic risk. Priority = operational urgency. A CRITICAL
    severity alert on a test machine is LOW priority; a MEDIUM severity
    alert on a production database is HIGH priority. Priority is set by
    policy or analyst.

15. **``expires_at`` for SLA tracking.**
    Set at creation based on severity (critical → 1h, high → 4h, etc.,
    from settings). Analytics queries: "how many alerts breached SLA?"

Usage
-----
    from app.models import SecurityAlert
    from app.models.enums import AlertStatus, EventSeverity, FindingCategory

    alert = SecurityAlert.build(
        workspace_id=workspace.id,
        source_id=source.id,
        fingerprint=compute_alert_fingerprint(
            workspace_id=workspace.id,
            category=FindingCategory.BRUTE_FORCE,
            severity=EventSeverity.HIGH,
            source_id=source.id,
        ),
        alert_type="security",
        title="Multiple failed logins from 203.0.113.42",
        description="6 failed logins in 40s on Priya's Laptop.",
        severity=EventSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
        finding_ids=[str(f.id) for f in findings],
        context={
            "usernames": ["alice"],
            "source_ips": ["203.0.113.42"],
            "hostnames": ["priya-laptop"],
            "time_range": {"start": "...", "end": "..."},
        },
        recommended_actions=[
            {"action": "reset_password", "target": "alice", "priority": "high"},
            {"action": "block_ip", "target": "203.0.113.42", "priority": "medium"},
        ],
        sla_hours=4,
    )
    db.add(alert)
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
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
    AlertStatus,
    EventSeverity,
    FindingCategory,
    enum_column_type,
)


#: Alert type values. Not an enum because operational/system alerts may
#: grow (e.g. ``billing``, ``license``) without requiring a migration.
_ALERT_TYPE_SECURITY = "security"
_ALERT_TYPE_OPERATIONAL = "operational"
_ALERT_TYPE_COMPLIANCE = "compliance"
_ALERT_TYPE_SYSTEM = "system"
_VALID_ALERT_TYPES = frozenset({
    _ALERT_TYPE_SECURITY,
    _ALERT_TYPE_OPERATIONAL,
    _ALERT_TYPE_COMPLIANCE,
    _ALERT_TYPE_SYSTEM,
})

#: Notification channel names. Must match ``app.core.constants`` values.
_VALID_NOTIFICATION_CHANNELS = frozenset({"in_app", "email", "webhook"})

_MAX_TITLE_LENGTH = 255
_MAX_DESCRIPTION_LENGTH = 5000
_MAX_FINGERPRINT_LENGTH = 64
_MAX_FINDING_IDS = 500
_MAX_RECOMMENDED_ACTIONS = 10
_MAX_CONTEXT_SIZE_BYTES = 64 * 1024  # 64 KB
_MAX_NOTIFICATION_ATTEMPTS = 100


class SecurityAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A user-facing alert promoted from one or more agent findings.

    Aggregates findings by pattern. Tracks notification state and user
    engagement. Promotes to incidents when correlation rules dictate.
    """

    __tablename__ = "security_alerts"

    __table_args__ = (
        # Fingerprint format
        CheckConstraint(
            r"fingerprint ~ '^[a-f0-9]{64}$'",
            name="fingerprint_format",
        ),
        # Alert type must be one of the four documented values.
        CheckConstraint(
            "alert_type IN ('security', 'operational', 'compliance', 'system')",
            name="alert_type_values",
        ),
        # Counters non-negative.
        CheckConstraint(
            "occurrence_count >= 1",
            name="occurrence_count_positive",
        ),
        CheckConstraint(
            "notification_attempts >= 0",
            name="notification_attempts_non_negative",
        ),
        # Status consistency: closed statuses require a resolved_at timestamp.
        CheckConstraint(
            "status NOT IN ('resolved', 'dismissed') OR resolved_at IS NOT NULL",
            name="closed_requires_resolved_at",
        ),
        # If seen_at is set, it must be after creation.
        CheckConstraint(
            "seen_at IS NULL OR seen_at >= created_at",
            name="seen_at_after_created",
        ),
        CheckConstraint(
            "acknowledged_at IS NULL OR acknowledged_at >= created_at",
            name="acknowledged_at_after_created",
        ),
        # Dedup: active alerts per pattern are unique.
        # Resolved alerts are excluded — a new occurrence creates a new row.
        Index(
            "uq_alerts_workspace_fingerprint_active",
            "workspace_id",
            "fingerprint",
            unique=True,
            postgresql_where=text("resolved_at IS NULL"),
        ),
        # Main dashboard query: recent alerts in workspace.
        Index(
            "ix_alerts_workspace_created",
            "workspace_id",
            "created_at",
        ),
        # Severity-filtered views.
        Index(
            "ix_alerts_workspace_severity_created",
            "workspace_id",
            "severity",
            "created_at",
        ),
        # Status-filtered views (open / investigating / resolved).
        Index(
            "ix_alerts_workspace_status_created",
            "workspace_id",
            "status",
            "created_at",
        ),
        # Assigned alerts per analyst.
        Index(
            "ix_alerts_assigned_status",
            "assigned_to_id",
            "status",
        ),
        # SLA breach queries.
        Index(
            "ix_alerts_expires_at",
            "expires_at",
        ),
        # Incident correlation.
        Index(
            "ix_alerts_incident_id",
            "incident_id",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Tenant & source
    # ────────────────────────────────────────────────────────────────────

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tenant boundary. Deleting workspace cascades its alerts.",
    )

    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Primary source. NULL for cross-source alerts (e.g. IOC "
            "correlation), or after source hard-delete."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Classification
    # ────────────────────────────────────────────────────────────────────

    alert_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_ALERT_TYPE_SECURITY,
        server_default=_ALERT_TYPE_SECURITY,
        index=True,
        comment="security | operational | compliance | system",
    )

    severity: Mapped[EventSeverity] = mapped_column(
        enum_column_type(EventSeverity),
        nullable=False,
        default=EventSeverity.MEDIUM,
        server_default=EventSeverity.MEDIUM.value,
        index=True,
        comment="Intrinsic risk. May be higher than underlying findings (aggregation).",
    )

    category: Mapped[FindingCategory] = mapped_column(
        enum_column_type(FindingCategory),
        nullable=False,
        default=FindingCategory.OTHER,
        server_default=FindingCategory.OTHER.value,
        index=True,
        comment="Threat category (phishing, brute_force, port_scan, ...).",
    )

    status: Mapped[AlertStatus] = mapped_column(
        enum_column_type(AlertStatus),
        nullable=False,
        default=AlertStatus.NEW,
        server_default=AlertStatus.NEW.value,
        index=True,
        comment="Workflow: new, acknowledged, investigating, resolved, dismissed.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Presentation
    # ────────────────────────────────────────────────────────────────────

    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH),
        nullable=False,
        comment="One-line summary shown in dashboards and notifications.",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Longer narrative shown on the alert detail page.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Finding references
    # ────────────────────────────────────────────────────────────────────

    finding_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Array of finding UUIDs (as strings) aggregated into this alert. "
            "Not a FK — one alert can reference hundreds of findings."
        ),
    )

    finding_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Count of distinct findings aggregated. Denormalized for queries.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Deduplication
    # ────────────────────────────────────────────────────────────────────

    fingerprint: Mapped[str] = mapped_column(
        String(_MAX_FINGERPRINT_LENGTH),
        nullable=False,
        comment=(
            "SHA-256 hex of (workspace_id || category || severity || "
            "source_scope). Identifies the attack *pattern*, not the "
            "specific events. Same pattern → same active alert."
        ),
    )

    previous_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "The last alert of the same pattern that was resolved. "
            "Enables pattern history: 'attacker triggered 12 alerts over 6 months'."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Lifecycle timestamps
    # ────────────────────────────────────────────────────────────────────

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="When this pattern was first detected. Preserved across merges.",
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="When this pattern last re-fired. Updated on dedup merges.",
    )

    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="How many times the pattern has re-fired while active.",
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="SLA deadline based on severity. Used for breach analytics.",
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When the alert was closed (resolved or dismissed).",
    )

    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who closed the alert.",
    )

    resolution_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="What was done to resolve this alert.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Assignment
    # ────────────────────────────────────────────────────────────────────

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Analyst assigned for triage. Distinct from case assignment.",
    )

    assigned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the alert was assigned to assigned_to_id.",
    )

    # ────────────────────────────────────────────────────────────────────
    # User engagement tracking
    # ────────────────────────────────────────────────────────────────────

    seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the user (assignee or recipient) first opened the alert.",
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the user explicitly confirmed awareness.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Notification tracking
    # ────────────────────────────────────────────────────────────────────

    notification_sent: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="True if at least one channel confirmed delivery.",
    )

    notification_channels_sent: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Channels that successfully delivered (in_app, email, webhook).",
    )

    notification_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Total delivery attempts across all channels. For debugging.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Enrichment
    # ────────────────────────────────────────────────────────────────────

    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Aggregated attacker context: usernames, source_ips, hostnames, "
            "time_range, mitre_techniques. Populated by alert_service."
        ),
    )

    recommended_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Agent-suggested next steps: [{action, target, priority}, ...]. "
            "Displayed to the user as one-click suggestions."
        ),
    )

    mitre_techniques: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Union of MITRE ATT&CK techniques from underlying findings.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Promotion
    # ────────────────────────────────────────────────────────────────────

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Incident this alert was promoted into by the incident response agent.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("alert_type")
    def _validate_alert_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="alert_type must be a string",
                code="ALERT_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_ALERT_TYPES:
            raise ValidationError(
                message=f"alert_type must be one of {sorted(_VALID_ALERT_TYPES)}",
                code="ALERT_TYPE_INVALID",
                details={"received": value, "allowed": sorted(_VALID_ALERT_TYPES)},
            )
        return normalized

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="ALERT_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="ALERT_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="ALERT_TITLE_TOO_LONG",
            )
        return stripped

    @validates("fingerprint")
    def _validate_fingerprint(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="fingerprint must be a string",
                code="ALERT_FINGERPRINT_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if len(normalized) != 64 or not all(
            c in "0123456789abcdef" for c in normalized
        ):
            raise ValidationError(
                message="fingerprint must be 64 lowercase hex characters",
                code="ALERT_FINGERPRINT_INVALID_FORMAT",
            )
        return normalized

    @validates("finding_ids")
    def _validate_finding_ids(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="finding_ids must be a list of strings",
                code="ALERT_FINDING_IDS_INVALID_TYPE",
            )
        if len(value) > _MAX_FINDING_IDS:
            raise ValidationError(
                message=f"finding_ids must not exceed {_MAX_FINDING_IDS} items",
                code="ALERT_FINDING_IDS_TOO_MANY",
            )
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each finding_id must be a string",
                    code="ALERT_FINDING_ID_INVALID_TYPE",
                )
            cleaned.append(item.strip())
        return cleaned

    @validates("notification_channels_sent")
    def _validate_channels(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="notification_channels_sent must be a list of strings",
                code="ALERT_CHANNELS_INVALID_TYPE",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each channel must be a string",
                    code="ALERT_CHANNEL_INVALID_TYPE",
                )
            stripped = item.strip().lower()
            if not stripped or stripped in seen:
                continue
            if stripped not in _VALID_NOTIFICATION_CHANNELS:
                raise ValidationError(
                    message=(
                        f"channel must be one of "
                        f"{sorted(_VALID_NOTIFICATION_CHANNELS)}"
                    ),
                    code="ALERT_CHANNEL_INVALID",
                    details={"received": stripped},
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("recommended_actions")
    def _validate_recommended_actions(
        self, _key: str, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="recommended_actions must be a list of objects",
                code="ALERT_RECOMMENDED_ACTIONS_INVALID_TYPE",
            )
        if len(value) > _MAX_RECOMMENDED_ACTIONS:
            raise ValidationError(
                message=f"recommended_actions must not exceed {_MAX_RECOMMENDED_ACTIONS}",
                code="ALERT_RECOMMENDED_ACTIONS_TOO_MANY",
            )
        cleaned: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise ValidationError(
                    message="each recommended action must be an object",
                    code="ALERT_RECOMMENDED_ACTION_INVALID_TYPE",
                )
            action = str(item.get("action", "")).strip()
            if not action:
                raise ValidationError(
                    message="each recommended action must have a non-empty 'action'",
                    code="ALERT_RECOMMENDED_ACTION_MISSING_ACTION",
                )
            cleaned.append(
                {
                    "action": action,
                    "target": item.get("target"),
                    "priority": item.get("priority"),
                    "description": item.get("description"),
                }
            )
        return cleaned

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
                    code="ALERT_SEVERITY_INVALID",
                    details={"allowed": list(EventSeverity.values())},
                ) from exc
        raise ValidationError(
            message="severity must be an EventSeverity or string",
            code="ALERT_SEVERITY_INVALID_TYPE",
        )

    @validates("category")
    def _validate_category(
        self, _key: str, value: FindingCategory | str
    ) -> FindingCategory:
        if isinstance(value, FindingCategory):
            return value
        if isinstance(value, str):
            try:
                return FindingCategory(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid category {value!r}",
                    code="ALERT_CATEGORY_INVALID",
                    details={"allowed": list(FindingCategory.values())},
                ) from exc
        raise ValidationError(
            message="category must be a FindingCategory or string",
            code="ALERT_CATEGORY_INVALID_TYPE",
        )

    @validates("status")
    def _validate_status(
        self, _key: str, value: AlertStatus | str
    ) -> AlertStatus:
        if isinstance(value, AlertStatus):
            return value
        if isinstance(value, str):
            try:
                return AlertStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid status {value!r}",
                    code="ALERT_STATUS_INVALID",
                    details={"allowed": list(AlertStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be an AlertStatus or string",
            code="ALERT_STATUS_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        workspace_id: uuid.UUID,
        fingerprint: str,
        title: str,
        alert_type: str = _ALERT_TYPE_SECURITY,
        severity: EventSeverity = EventSeverity.MEDIUM,
        category: FindingCategory = FindingCategory.OTHER,
        description: str | None = None,
        source_id: uuid.UUID | None = None,
        finding_ids: list[str] | None = None,
        context: dict[str, Any] | None = None,
        recommended_actions: list[dict[str, Any]] | None = None,
        mitre_techniques: list[str] | None = None,
        sla_hours: int | None = None,
        previous_alert_id: uuid.UUID | None = None,
    ) -> "SecurityAlert":
        """
        Construct a new alert.

        ``fingerprint`` identifies the attack pattern (see class docstring).
        Computed by ``alert_service`` from (workspace_id, category,
        severity, source_scope).

        ``sla_hours`` sets ``expires_at``. If None, no SLA is enforced
        (suitable for low-severity informational alerts).
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=sla_hours) if sla_hours else None

        return cls(
            workspace_id=workspace_id,
            source_id=source_id,
            alert_type=alert_type,
            severity=severity,
            category=category,
            title=title,
            description=description,
            finding_ids=finding_ids or [],
            finding_count=len(finding_ids or []),
            fingerprint=fingerprint,
            previous_alert_id=previous_alert_id,
            first_seen_at=now,
            last_seen_at=now,
            occurrence_count=1,
            expires_at=expires,
            context=context or {},
            recommended_actions=recommended_actions or [],
            mitre_techniques=mitre_techniques or [],
        )

    # ====================================================================
    # LIFECYCLE METHODS
    # ====================================================================

    def record_recurrence(
        self,
        new_finding_ids: list[str] | None = None,
    ) -> None:
        """
        Increment ``occurrence_count``, bump ``last_seen_at``, merge new
        finding IDs. Called when the pattern re-fires while the alert is
        still active.
        """
        self.occurrence_count += 1
        self.last_seen_at = datetime.now(timezone.utc)
        if new_finding_ids:
            existing = set(self.finding_ids or [])
            merged = list(existing.union(new_finding_ids))
            self.finding_ids = merged[-_MAX_FINDING_IDS:]
            self.finding_count = len(self.finding_ids)

    def mark_seen(self) -> None:
        """Record that the user opened the alert."""
        if self.seen_at is None:
            self.seen_at = datetime.now(timezone.utc)

    def acknowledge(self) -> None:
        """Record that the user confirmed awareness."""
        if self.acknowledged_at is None:
            self.acknowledged_at = datetime.now(timezone.utc)
        if self.status == AlertStatus.NEW:
            self.status = AlertStatus.ACKNOWLEDGED

    def mark_investigating(self) -> None:
        """Transition to INVESTIGATING."""
        if self.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED):
            self.status = AlertStatus.INVESTIGATING

    def resolve(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """Mark the alert as RESOLVED with optional notes."""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
        if by_user_id is not None:
            self.resolved_by_id = by_user_id
        if notes:
            self.resolution_notes = notes

    def dismiss(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """Mark the alert as DISMISSED."""
        self.status = AlertStatus.DISMISSED
        self.resolved_at = datetime.now(timezone.utc)
        if by_user_id is not None:
            self.resolved_by_id = by_user_id
        if notes:
            self.resolution_notes = notes

    def assign_to(self, user_id: uuid.UUID) -> None:
        """Assign the alert to an analyst for triage."""
        self.assigned_to_id = user_id
        self.assigned_at = datetime.now(timezone.utc)

    def record_notification(
        self,
        *,
        channel: str,
        success: bool,
    ) -> None:
        """
        Record a notification delivery attempt. Call once per (channel,
        attempt). Updates ``notification_sent``, ``notification_channels_sent``,
        and ``notification_attempts`` accordingly.
        """
        self.notification_attempts += 1
        if success:
            existing = set(self.notification_channels_sent or [])
            existing.add(channel.strip().lower())
            self.notification_channels_sent = sorted(existing)
            self.notification_sent = True

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_open(self) -> bool:
        """True if the alert is in an active workflow state."""
        return self.status in (
            AlertStatus.NEW,
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.INVESTIGATING,
        )

    @property
    def is_closed(self) -> bool:
        """True if the alert is resolved or dismissed."""
        return self.status in (AlertStatus.RESOLVED, AlertStatus.DISMISSED)

    @property
    def is_assigned(self) -> bool:
        """True if the alert has an assignee."""
        return self.assigned_to_id is not None

    @property
    def is_promoted_to_incident(self) -> bool:
        """True if this alert was promoted into an incident."""
        return self.incident_id is not None

    @property
    def is_sla_breached(self) -> bool:
        """
        True if the alert is still open and ``expires_at`` has passed.
        """
        if not self.is_open or self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)

    @property
    def sla_remaining_seconds(self) -> int | None:
        """
        Seconds until SLA expiry. Negative if breached. ``None`` if no SLA.
        """
        if self.expires_at is None:
            return None
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return int((exp - datetime.now(timezone.utc)).total_seconds())

    @property
    def age_seconds(self) -> int:
        """Seconds since the alert was created."""
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - created).total_seconds())

    @property
    def time_to_acknowledge_seconds(self) -> int | None:
        """Seconds from creation to acknowledgement. ``None`` if not ack'd."""
        if self.acknowledged_at is None:
            return None
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        ack = self.acknowledged_at
        if ack.tzinfo is None:
            ack = ack.replace(tzinfo=timezone.utc)
        return int((ack - created).total_seconds())

    @property
    def time_to_resolve_seconds(self) -> int | None:
        """Seconds from creation to resolution. ``None`` if not resolved."""
        if self.resolved_at is None:
            return None
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        resolved = self.resolved_at
        if resolved.tzinfo is None:
            resolved = resolved.replace(tzinfo=timezone.utc)
        return int((resolved - created).total_seconds())


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.workspace import Workspace
#     from app.models.source import SecuritySource
#     from app.models.user import User
#     from app.models.finding import AgentFinding
#     from app.models.incident import SecurityIncident
#
# class SecurityAlert(...):
#     ...
#     workspace: Mapped["Workspace"] = relationship(
#         "Workspace", back_populates="alerts"
#     )
#     source: Mapped["SecuritySource | None"] = relationship(
#         "SecuritySource"
#     )
#     assigned_to: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[assigned_to_id]
#     )
#     resolved_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[resolved_by_id]
#     )
#     previous_alert: Mapped["SecurityAlert | None"] = relationship(
#         "SecurityAlert",
#         remote_side="SecurityAlert.id",
#         foreign_keys=[previous_alert_id],
#     )
#     findings: Mapped[list["AgentFinding"]] = relationship(
#         "AgentFinding",
#         back_populates="alert",
#     )
#     incident: Mapped["SecurityIncident | None"] = relationship(
#         "SecurityIncident", back_populates="alerts"
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityAlert",
    "_ALERT_TYPE_SECURITY",
    "_ALERT_TYPE_OPERATIONAL",
    "_ALERT_TYPE_COMPLIANCE",
    "_ALERT_TYPE_SYSTEM",
    "_VALID_ALERT_TYPES",
    "_VALID_NOTIFICATION_CHANNELS",
    "_MAX_TITLE_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_FINGERPRINT_LENGTH",
    "_MAX_FINDING_IDS",
    "_MAX_RECOMMENDED_ACTIONS",
    "_MAX_CONTEXT_SIZE_BYTES",
    "_MAX_NOTIFICATION_ATTEMPTS",
]