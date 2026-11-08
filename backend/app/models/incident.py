"""
CyberGuard AI — Security Incidents and Event Links
============================================================================

Two tables:

    security_incidents      — managed investigation containers with the
                              full NIST SP 800-61 lifecycle
    incident_event_links    — join table linking incidents to events

An incident is created by the Incident Response Agent (or manually by an
analyst) when a pattern of alerts, findings, and events crosses the
threshold for investigation. It aggregates everything related to the
attack into a single coherent workflow object.

Design decisions
----------------
1. **Fingerprint dedup at the pattern level.**
   Same attack pattern (category + scope + fingerprint ingredients) →
   same *active* incident. Once closed, a new occurrence creates a new
   incident, chained via ``previous_incident_id``. This makes MTTR
   analytics correct — we measure "time to close *a* brute-force
   incident", not "time since the brute-force began 6 months ago".

2. **NIST SP 800-61 lifecycle recorded in ``status_history`` JSONB.**
   Every transition is timestamped and attributed. No separate
   status-transitions table needed — incidents change status fewer than
   ~10 times in their entire lifecycle.

3. **Metrics as computed properties, not stored columns.**
   ``time_to_acknowledge_seconds``, ``time_to_resolve_seconds``,
   ``mtta_seconds``, ``mttr_seconds``. Storing them would mean writing
   on every read. The one stored metric — ``mttr_seconds_finalized`` — is
   set once at ``closed_at`` for immutable historical reporting.

4. **``previous_incident_id`` self-FK for recurrence chains.**
   "This attacker triggered 12 incidents over 6 months" is a single
   query up the chain.

5. **``affected_*`` fields as JSONB arrays.**
   ``affected_devices``, ``affected_users``, ``affected_ips``,
   ``mitre_techniques``. Analyst-curated summaries, not source-of-truth
   joins. Fast reads, easy updates.

6. **Separate ``containment_actions`` and ``recovery_actions``.**
   NIST phases have distinct actions. Structuring them separately makes
   post-incident review ("did containment happen before eradication?")
   trivial.

7. **``status_history`` JSONB (append-only).**
   Array of ``{from, to, at, by_user_id, notes}``. Queryable, immutable in
   spirit (service appends), and small (10–20 entries per incident).

8. **No ``case_id`` FK on incident.**
   The relationship is ``case.incident_id → incident.id`` (in File 28).
   One incident can have multiple cases (different analysts, different
   angles). Avoids circular FKs and matches the marketplace model.

9. **``root_cause`` and ``lessons_learned``.**
   Post-incident fields, populated during ``resolved`` and ``closed``.
   Used by the Reporting Agent for trend analysis.

10. **Per-incident SLA capture.**
    ``sla_acknowledge_hours`` and ``sla_resolve_hours`` captured at
    creation. SLA policy changes don't retroactively break historical
    metrics.

11. **``legal_hold_until`` support.**
    Prevents retention cleanup during active investigations. Compliance
    requirement.

12. **Status transition validation.**
    ``can_transition_to()`` enforces the NIST state machine.
    ``advance_status()`` calls it. Prevents impossible states like
    "containment → open".

13. **Timezone correctness everywhere.**

Usage
-----
    from app.models import SecurityIncident
    from app.models.enums import IncidentSeverity, IncidentStatus, FindingCategory

    incident = SecurityIncident.build(
        workspace_id=workspace.id,
        fingerprint=compute_incident_fingerprint(
            workspace_id=workspace.id,
            category=FindingCategory.BRUTE_FORCE,
            severity=IncidentSeverity.HIGH,
            source_id=source.id,
        ),
        title="Sustained brute-force attack against alice@example.com",
        description="6 failed logins in 40s, then successful login.",
        severity=IncidentSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
        alert_ids=[str(a.id) for a in alerts],
        finding_ids=[str(f.id) for f in findings],
        primary_source_id=source.id,
        affected_devices=["priya-laptop"],
        affected_users=["alice"],
        affected_ips=["203.0.113.42"],
        mitre_techniques=["T1110.001"],
        assigned_to_id=analyst.id,
        sla_acknowledge_hours=1,
        sla_resolve_hours=24,
    )
    db.add(incident)
    db.commit()

    # Analyst works the incident
    incident.advance_status(IncidentStatus.INVESTIGATING, by_user_id=analyst.id)
    incident.advance_status(IncidentStatus.CONTAINMENT, by_user_id=analyst.id)
    incident.record_containment_action(
        action="block_ip", target="203.0.113.42",
        by_user_id=analyst.id, result="success",
    )
    incident.advance_status(IncidentStatus.RECOVERY, by_user_id=analyst.id)
    incident.advance_status(IncidentStatus.RESOLVED, by_user_id=analyst.id,
                           notes="Attacker blocked; password reset.")
    incident.advance_status(IncidentStatus.CLOSED, by_user_id=analyst.id)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import (
    InvalidStateTransitionError,
    ValidationError,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    FindingCategory,
    IncidentSeverity,
    IncidentStatus,
    enum_column_type,
)


_MAX_TITLE_LENGTH = 255
_MAX_DESCRIPTION_LENGTH = 10_000
_MAX_FINGERPRINT_LENGTH = 64
_MAX_SUMMARY_LENGTH = 10_000
_MAX_ROOT_CAUSE_LENGTH = 10_000
_MAX_LESSONS_LENGTH = 10_000
_MAX_ALERT_IDS = 500
_MAX_FINDING_IDS = 1000
_MAX_AFFECTED_ITEMS = 500
_MAX_MITRE_TECHNIQUES = 50
_MAX_STATUS_HISTORY = 100
_MAX_ACTIONS = 100
_MAX_TAGS = 30
_MAX_CONTEXT_BYTES = 128 * 1024


#: NIST SP 800-61 state machine. Each state maps to the set of states it
#: may transition to. ``closed`` is terminal unless explicitly reopened.
_ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,  # duplicate / false positive
    }),
    IncidentStatus.INVESTIGATING: frozenset({
        IncidentStatus.CONTAINMENT,
        IncidentStatus.RECOVERY,  # low-severity: skip containment
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,  # false positive
    }),
    IncidentStatus.CONTAINMENT: frozenset({
        IncidentStatus.ERADICATION,
        IncidentStatus.RECOVERY,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.ERADICATION: frozenset({
        IncidentStatus.RECOVERY,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.RECOVERY: frozenset({
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,  # regression detected
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.RESOLVED: frozenset({
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,  # reopened
    }),
    IncidentStatus.CLOSED: frozenset({
        IncidentStatus.INVESTIGATING,  # explicitly reopened by admin
    }),
}


# ============================================================================
# INCIDENT
# ============================================================================

class SecurityIncident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A managed security investigation with the NIST SP 800-61 lifecycle.
    """

    __tablename__ = "security_incidents"

    __table_args__ = (
        CheckConstraint(
            r"fingerprint ~ '^[a-f0-9]{64}$'",
            name="fingerprint_format",
        ),
        CheckConstraint(
            "occurrence_count >= 1",
            name="occurrence_count_positive",
        ),
        CheckConstraint(
            "sla_acknowledge_hours IS NULL OR sla_acknowledge_hours > 0",
            name="sla_ack_hours_positive",
        ),
        CheckConstraint(
            "sla_resolve_hours IS NULL OR sla_resolve_hours > 0",
            name="sla_resolve_hours_positive",
        ),
        # Status consistency with timestamps
        CheckConstraint(
            "status = 'open' OR opened_at IS NOT NULL",
            name="non_open_requires_opened_at",
        ),
        CheckConstraint(
            "status NOT IN ('resolved', 'closed') OR resolved_at IS NOT NULL",
            name="resolved_requires_resolved_at",
        ),
        CheckConstraint(
            "status <> 'closed' OR closed_at IS NOT NULL",
            name="closed_requires_closed_at",
        ),
        # Dedup: active incidents per pattern are unique.
        Index(
            "uq_incidents_workspace_fingerprint_active",
            "workspace_id",
            "fingerprint",
            unique=True,
            postgresql_where=text("closed_at IS NULL"),
        ),
        Index(
            "ix_incidents_workspace_created",
            "workspace_id",
            "created_at",
        ),
        Index(
            "ix_incidents_workspace_status_created",
            "workspace_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_incidents_workspace_severity_created",
            "workspace_id",
            "severity",
            "created_at",
        ),
        Index(
            "ix_incidents_assigned_status",
            "assigned_to_id",
            "status",
        ),
        Index(
            "ix_incidents_expires_at",
            "expires_at",
        ),
    )

    # ─── Tenant & source ────────────────────────────────────────────────
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tenant boundary. Deleting workspace cascades its incidents.",
    )

    primary_source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="The primary source involved. NULL for cross-source incidents.",
    )

    # ─── Classification ─────────────────────────────────────────────────
    severity: Mapped[IncidentSeverity] = mapped_column(
        enum_column_type(IncidentSeverity),
        nullable=False,
        default=IncidentSeverity.MEDIUM,
        server_default=IncidentSeverity.MEDIUM.value,
        index=True,
        comment="Aggregate severity. May exceed individual alert severities.",
    )

    category: Mapped[FindingCategory] = mapped_column(
        enum_column_type(FindingCategory),
        nullable=False,
        default=FindingCategory.OTHER,
        server_default=FindingCategory.OTHER.value,
        index=True,
        comment="Primary threat category.",
    )

    status: Mapped[IncidentStatus] = mapped_column(
        enum_column_type(IncidentStatus),
        nullable=False,
        default=IncidentStatus.OPEN,
        server_default=IncidentStatus.OPEN.value,
        index=True,
        comment="NIST SP 800-61 lifecycle state.",
    )

    # ─── Presentation ───────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH), nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    # ─── Aggregation (JSONB arrays) ─────────────────────────────────────
    alert_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="UUIDs (as strings) of alerts aggregated into this incident.",
    )

    finding_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="UUIDs (as strings) of findings aggregated into this incident.",
    )

    affected_devices: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Hostnames of affected devices. Analyst-curated.",
    )

    affected_users: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Usernames of affected users. Analyst-curated.",
    )

    affected_ips: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="IP addresses involved (attacker and victim).",
    )

    mitre_techniques: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="MITRE ATT&CK techniques observed.",
    )

    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )

    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Free-form structured context from the incident response agent.",
    )

    # ─── Deduplication ──────────────────────────────────────────────────
    fingerprint: Mapped[str] = mapped_column(
        String(_MAX_FINGERPRINT_LENGTH),
        nullable=False,
        comment="SHA-256 of (workspace_id, category, severity, source scope).",
    )

    previous_incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="The prior incident of the same pattern. Enables recurrence chains.",
    )

    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="How many times this pattern has re-fired while the incident was active.",
    )

    # ─── Lifecycle timestamps ───────────────────────────────────────────
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="Earliest event_time among contributing alerts. Preserved across merges.",
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="Most recent re-fire. Updated on dedup merges.",
    )

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        comment="When the incident was created (first transition to OPEN).",
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="First analyst acknowledgement. Feeds MTTA metric.",
    )

    containment_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    eradication_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    recovery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True,
    )

    # ─── SLA ────────────────────────────────────────────────────────────
    sla_acknowledge_hours: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="SLA target for acknowledgement (hours), captured at creation.",
    )
    sla_resolve_hours: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="SLA target for resolution (hours), captured at creation.",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Deadline for resolution (opened_at + sla_resolve_hours).",
    )

    # ─── Assignment ─────────────────────────────────────────────────────
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Primary responsible analyst.",
    )
    assigned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── Resolution ─────────────────────────────────────────────────────
    status_history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Append-only log of {from, to, at, by_user_id, notes}.",
    )

    containment_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Containment steps taken: [{action, target, at, by, result}].",
    )

    recovery_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Recovery steps taken: [{action, target, at, by, result}].",
    )

    root_cause: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Analyst conclusion about root cause. Populated before closure.",
    )

    resolution_summary: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    lessons_learned: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Post-incident review. Used by Reporting Agent for trend analysis.",
    )

    mttr_seconds_finalized: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment=(
            "MTTR in seconds, frozen at closed_at. Stored (not computed) for "
            "immutable historical reporting — recomputing would drift if "
            "timestamps are ever corrected."
        ),
    )

    # ─── Legal hold ─────────────────────────────────────────────────────
    legal_hold_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="If set and in the future, retention cleanup skips this incident.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="INCIDENT_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="INCIDENT_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="INCIDENT_TITLE_TOO_LONG",
            )
        return stripped

    @validates("fingerprint")
    def _validate_fingerprint(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="fingerprint must be a string",
                code="INCIDENT_FP_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if len(normalized) != 64 or not all(
            c in "0123456789abcdef" for c in normalized
        ):
            raise ValidationError(
                message="fingerprint must be 64 lowercase hex characters",
                code="INCIDENT_FP_INVALID_FORMAT",
            )
        return normalized

    @validates("severity")
    def _validate_severity(
        self, _key: str, value: IncidentSeverity | str
    ) -> IncidentSeverity:
        if isinstance(value, IncidentSeverity):
            return value
        if isinstance(value, str):
            try:
                return IncidentSeverity(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid severity {value!r}",
                    code="INCIDENT_SEVERITY_INVALID",
                    details={"allowed": list(IncidentSeverity.values())},
                ) from exc
        raise ValidationError(
            message="severity must be an IncidentSeverity or string",
            code="INCIDENT_SEVERITY_INVALID_TYPE",
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
                    code="INCIDENT_CATEGORY_INVALID",
                    details={"allowed": list(FindingCategory.values())},
                ) from exc
        raise ValidationError(
            message="category must be a FindingCategory or string",
            code="INCIDENT_CATEGORY_INVALID_TYPE",
        )

    @validates("status")
    def _validate_status(
        self, _key: str, value: IncidentStatus | str
    ) -> IncidentStatus:
        if isinstance(value, IncidentStatus):
            return value
        if isinstance(value, str):
            try:
                return IncidentStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid status {value!r}",
                    code="INCIDENT_STATUS_INVALID",
                    details={"allowed": list(IncidentStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be an IncidentStatus or string",
            code="INCIDENT_STATUS_INVALID_TYPE",
        )

    @validates(
        "alert_ids", "finding_ids", "affected_devices", "affected_users",
        "affected_ips", "mitre_techniques", "tags",
    )
    def _validate_string_list(self, key: str, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message=f"{key} must be a list of strings",
                code="INCIDENT_LIST_INVALID_TYPE",
                details={"field": key},
            )
        limit = {
            "alert_ids": _MAX_ALERT_IDS,
            "finding_ids": _MAX_FINDING_IDS,
            "affected_devices": _MAX_AFFECTED_ITEMS,
            "affected_users": _MAX_AFFECTED_ITEMS,
            "affected_ips": _MAX_AFFECTED_ITEMS,
            "mitre_techniques": _MAX_MITRE_TECHNIQUES,
            "tags": _MAX_TAGS,
        }[key]
        if len(value) > limit:
            raise ValidationError(
                message=f"{key} must not exceed {limit} items",
                code="INCIDENT_LIST_TOO_MANY",
                details={"field": key, "limit": limit},
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message=f"each {key} item must be a string",
                    code="INCIDENT_LIST_ITEM_INVALID_TYPE",
                    details={"field": key},
                )
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

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
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        category: FindingCategory = FindingCategory.OTHER,
        description: str | None = None,
        primary_source_id: uuid.UUID | None = None,
        alert_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
        affected_devices: list[str] | None = None,
        affected_users: list[str] | None = None,
        affected_ips: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
        tags: list[str] | None = None,
        context: dict[str, Any] | None = None,
        assigned_to_id: uuid.UUID | None = None,
        assigned_by_id: uuid.UUID | None = None,
        sla_acknowledge_hours: int | None = None,
        sla_resolve_hours: int | None = None,
        first_seen_at: datetime | None = None,
        previous_incident_id: uuid.UUID | None = None,
    ) -> "SecurityIncident":
        """
        Construct a new incident in the OPEN state.
        """
        now = datetime.now(timezone.utc)
        expires = (
            now + timedelta(hours=sla_resolve_hours)
            if sla_resolve_hours
            else None
        )

        inc = cls(
            workspace_id=workspace_id,
            fingerprint=fingerprint,
            title=title,
            description=description,
            severity=severity,
            category=category,
            status=IncidentStatus.OPEN,
            primary_source_id=primary_source_id,
            alert_ids=alert_ids or [],
            finding_ids=finding_ids or [],
            affected_devices=affected_devices or [],
            affected_users=affected_users or [],
            affected_ips=affected_ips or [],
            mitre_techniques=mitre_techniques or [],
            tags=tags or [],
            context=context or {},
            previous_incident_id=previous_incident_id,
            occurrence_count=1,
            first_seen_at=first_seen_at or now,
            last_seen_at=now,
            opened_at=now,
            sla_acknowledge_hours=sla_acknowledge_hours,
            sla_resolve_hours=sla_resolve_hours,
            expires_at=expires,
            assigned_to_id=assigned_to_id,
            assigned_at=now if assigned_to_id else None,
            assigned_by_id=assigned_by_id,
            status_history=[
                {
                    "from": None,
                    "to": IncidentStatus.OPEN.value,
                    "at": now.isoformat(),
                    "by_user_id": str(assigned_by_id) if assigned_by_id else None,
                    "notes": "Incident created.",
                }
            ],
        )
        return inc

    # ====================================================================
    # STATUS TRANSITIONS
    # ====================================================================

    def can_transition_to(self, new_status: IncidentStatus) -> bool:
        """
        Return ``True`` if transitioning from the current status to
        ``new_status`` is permitted by the NIST state machine.
        """
        if not isinstance(new_status, IncidentStatus):
            try:
                new_status = IncidentStatus(new_status)
            except (ValueError, TypeError):
                return False
        if new_status == self.status:
            return False
        allowed = _ALLOWED_TRANSITIONS.get(self.status, frozenset())
        return new_status in allowed

    def advance_status(
        self,
        new_status: IncidentStatus,
        *,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """
        Transition to ``new_status``. Raises ``InvalidStateTransitionError``
        if the transition is not permitted.

        Sets the corresponding phase timestamp (``acknowledged_at``,
        ``containment_at``, etc.) automatically and appends to
        ``status_history``.
        """
        if not self.can_transition_to(new_status):
            raise InvalidStateTransitionError(
                message=(
                    f"Cannot transition incident from "
                    f"{self.status.value!r} to {new_status.value!r}"
                ),
                code="INCIDENT_INVALID_TRANSITION",
                details={
                    "current": self.status.value,
                    "requested": new_status.value,
                    "allowed": [
                        s.value
                        for s in _ALLOWED_TRANSITIONS.get(self.status, frozenset())
                    ],
                },
            )

        now = datetime.now(timezone.utc)
        old_status = self.status
        self.status = new_status

        # Set phase-specific timestamps
        if new_status == IncidentStatus.INVESTIGATING and self.acknowledged_at is None:
            self.acknowledged_at = now
        elif new_status == IncidentStatus.CONTAINMENT and self.containment_at is None:
            self.containment_at = now
        elif new_status == IncidentStatus.ERADICATION and self.eradication_at is None:
            self.eradication_at = now
        elif new_status == IncidentStatus.RECOVERY and self.recovery_at is None:
            self.recovery_at = now
        elif new_status == IncidentStatus.RESOLVED and self.resolved_at is None:
            self.resolved_at = now
        elif new_status == IncidentStatus.CLOSED:
            self.closed_at = now
            # Freeze MTTR once, at closure
            if self.mttr_seconds_finalized is None and self.opened_at is not None:
                opened = self.opened_at
                if opened.tzinfo is None:
                    opened = opened.replace(tzinfo=timezone.utc)
                self.mttr_seconds_finalized = int((now - opened).total_seconds())

        # Append to history
        history = list(self.status_history or [])
        if len(history) < _MAX_STATUS_HISTORY:
            history.append({
                "from": old_status.value,
                "to": new_status.value,
                "at": now.isoformat(),
                "by_user_id": str(by_user_id) if by_user_id else None,
                "notes": notes,
            })
            self.status_history = history

    # ====================================================================
    # ACTION RECORDING
    # ====================================================================

    def record_containment_action(
        self,
        *,
        action: str,
        target: str | None = None,
        by_user_id: uuid.UUID | None = None,
        result: str = "success",
        notes: str | None = None,
    ) -> None:
        """Record a containment action in the incident's audit trail."""
        self._record_action(
            list_name="containment_actions",
            action=action,
            target=target,
            by_user_id=by_user_id,
            result=result,
            notes=notes,
        )

    def record_recovery_action(
        self,
        *,
        action: str,
        target: str | None = None,
        by_user_id: uuid.UUID | None = None,
        result: str = "success",
        notes: str | None = None,
    ) -> None:
        """Record a recovery action in the incident's audit trail."""
        self._record_action(
            list_name="recovery_actions",
            action=action,
            target=target,
            by_user_id=by_user_id,
            result=result,
            notes=notes,
        )

    def _record_action(
        self,
        *,
        list_name: str,
        action: str,
        target: str | None,
        by_user_id: uuid.UUID | None,
        result: str,
        notes: str | None,
    ) -> None:
        actions = list(getattr(self, list_name) or [])
        if len(actions) >= _MAX_ACTIONS:
            raise ValidationError(
                message=f"{list_name} has reached the maximum of {_MAX_ACTIONS} entries",
                code="INCIDENT_ACTIONS_LIMIT_REACHED",
            )
        actions.append({
            "action": action,
            "target": target,
            "at": datetime.now(timezone.utc).isoformat(),
            "by_user_id": str(by_user_id) if by_user_id else None,
            "result": result,
            "notes": notes,
        })
        setattr(self, list_name, actions)

    # ====================================================================
    # MERGE (dedup helper)
    # ====================================================================

    def record_recurrence(
        self,
        *,
        new_alert_ids: list[str] | None = None,
        new_finding_ids: list[str] | None = None,
    ) -> None:
        """Merge a re-fire of the same pattern into this incident."""
        self.occurrence_count += 1
        self.last_seen_at = datetime.now(timezone.utc)
        if new_alert_ids:
            existing = set(self.alert_ids or [])
            merged = list(existing.union(new_alert_ids))
            self.alert_ids = merged[-_MAX_ALERT_IDS:]
        if new_finding_ids:
            existing = set(self.finding_ids or [])
            merged = list(existing.union(new_finding_ids))
            self.finding_ids = merged[-_MAX_FINDING_IDS:]

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_open(self) -> bool:
        """True if the incident is in an active state (not resolved/closed)."""
        return self.status not in (
            IncidentStatus.RESOLVED,
            IncidentStatus.CLOSED,
        )

    @property
    def is_closed(self) -> bool:
        """True if the incident is closed."""
        return self.status == IncidentStatus.CLOSED

    @property
    def is_assigned(self) -> bool:
        """True if an analyst is assigned."""
        return self.assigned_to_id is not None

    @property
    def is_sla_breached(self) -> bool:
        """True if the incident is open and past expires_at."""
        if not self.is_open or self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)

    @property
    def is_under_legal_hold(self) -> bool:
        """True if the incident is currently under legal hold."""
        if self.legal_hold_until is None:
            return False
        hold = self.legal_hold_until
        if hold.tzinfo is None:
            hold = hold.replace(tzinfo=timezone.utc)
        return hold > datetime.now(timezone.utc)

    @property
    def time_to_acknowledge_seconds(self) -> int | None:
        """Seconds between opened_at and acknowledged_at."""
        if self.acknowledged_at is None or self.opened_at is None:
            return None
        opened = self.opened_at
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        ack = self.acknowledged_at
        if ack.tzinfo is None:
            ack = ack.replace(tzinfo=timezone.utc)
        return int((ack - opened).total_seconds())

    @property
    def time_to_resolve_seconds(self) -> int | None:
        """Seconds between opened_at and resolved_at."""
        if self.resolved_at is None or self.opened_at is None:
            return None
        opened = self.opened_at
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        resolved = self.resolved_at
        if resolved.tzinfo is None:
            resolved = resolved.replace(tzinfo=timezone.utc)
        return int((resolved - opened).total_seconds())

    @property
    def mtta_seconds(self) -> int | None:
        """Mean Time To Acknowledge, in seconds."""
        return self.time_to_acknowledge_seconds

    @property
    def mttr_seconds(self) -> int | None:
        """
        Mean Time To Resolve. Returns the frozen value if the incident is
        closed; otherwise computes live.
        """
        if self.mttr_seconds_finalized is not None:
            return self.mttr_seconds_finalized
        return self.time_to_resolve_seconds

    @property
    def age_seconds(self) -> int:
        """Seconds since the incident was opened."""
        if self.opened_at is None:
            return 0
        opened = self.opened_at
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - opened).total_seconds())


# ============================================================================
# INCIDENT EVENT LINK
# ============================================================================

class IncidentEventLink(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Association between an incident and a specific event.

    One incident ↔ many events. One event ↔ many incidents (cross-tenant
    correlation). The link itself carries metadata about how the event
    relates to the incident.
    """

    __tablename__ = "incident_event_links"

    __table_args__ = (
        CheckConstraint(
            "link_type IN ('trigger', 'related', 'evidence', 'ioc_match', 'timeline')",
            name="link_type_values",
        ),
        CheckConstraint(
            "relevance_score IS NULL OR "
            "(relevance_score >= 0.0 AND relevance_score <= 1.0)",
            name="relevance_score_range",
        ),
        UniqueConstraint(
            "incident_id",
            "event_id",
            "link_type",
            name="uq_incident_event_link_type",
        ),
        Index(
            "ix_incident_event_links_incident",
            "incident_id",
        ),
        Index(
            "ix_incident_event_links_event",
            "event_id",
        ),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    link_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="related",
        server_default="related",
        comment=(
            "How the event relates: trigger (caused the incident), "
            "related (same attack), evidence (supports analysis), "
            "ioc_match (IOC correlation), timeline (phase marker)."
        ),
    )

    relevance_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Optional relevance score (0.0–1.0) from correlation engine.",
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Why this event is linked to this incident.",
    )

    added_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User or NULL if added by the incident response agent.",
    )


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
#     from app.models.alert import SecurityAlert
#     from app.models.finding import AgentFinding
#     from app.models.event import SecurityEvent
#     from app.models.case import SecurityCase
#
# class SecurityIncident(...):
#     ...
#     workspace: Mapped["Workspace"] = relationship("Workspace")
#     primary_source: Mapped["SecuritySource | None"] = relationship(
#         "SecuritySource"
#     )
#     assigned_to: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[assigned_to_id]
#     )
#     assigned_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[assigned_by_id]
#     )
#     previous_incident: Mapped["SecurityIncident | None"] = relationship(
#         "SecurityIncident",
#         remote_side="SecurityIncident.id",
#         foreign_keys=[previous_incident_id],
#     )
#     event_links: Mapped[list["IncidentEventLink"]] = relationship(
#         "IncidentEventLink",
#         back_populates="incident",
#         cascade="all, delete-orphan",
#     )
#     cases: Mapped[list["SecurityCase"]] = relationship(
#         "SecurityCase", back_populates="incident"
#     )
#
# class IncidentEventLink(...):
#     ...
#     incident: Mapped["SecurityIncident"] = relationship(
#         "SecurityIncident", back_populates="event_links"
#     )
#     event: Mapped["SecurityEvent"] = relationship("SecurityEvent")
#     added_by: Mapped["User | None"] = relationship("User")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityIncident",
    "IncidentEventLink",
    "_ALLOWED_TRANSITIONS",
    "_MAX_TITLE_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_FINGERPRINT_LENGTH",
    "_MAX_SUMMARY_LENGTH",
    "_MAX_ROOT_CAUSE_LENGTH",
    "_MAX_LESSONS_LENGTH",
    "_MAX_ALERT_IDS",
    "_MAX_FINDING_IDS",
    "_MAX_AFFECTED_ITEMS",
    "_MAX_MITRE_TECHNIQUES",
    "_MAX_STATUS_HISTORY",
    "_MAX_ACTIONS",
    "_MAX_TAGS",
    "_MAX_CONTEXT_BYTES",
]