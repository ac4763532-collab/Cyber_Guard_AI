"""
CyberGuard AI — Security Cases, Assignments, and Access Grants
============================================================================

Three tables that form the platform's case-access control system:

    security_cases          — the analyst work assignment wrapper
    case_assignments        — history of who has worked on each case
    case_access_grants      — explicit scoped access for anyone (analyst,
                              admin, external marketplace analyst)

These three tables together enforce the core security rule from the
project handover:

    "An organization administrator should not automatically gain access
     to all client evidence. Sensitive access must be explicitly granted
     and audited."

The rule is enforced at the schema level:

    - Being an org admin grants NO access to any specific case.
    - Being assigned to a case grants investigation access to that case.
    - Every non-assigned viewer must have an explicit CaseAccessGrant.
    - Every grant has a `purpose` field (why) and a `granted_by_id` (who).
    - Every grant can be revoked, and every revocation is recorded.

Design decisions
----------------
1. **Case ≠ Incident.**
   One incident can have multiple cases (different analysts, different
   angles, internal vs external). FK direction: ``case.incident_id`` →
   ``incident.id``. Nullable — proactive work needs no incident.

2. **``case_number`` is human-readable and globally unique.**
   Format ``CG-YYYY-NNNNNN`` (e.g. ``CG-2026-001042``). Every support
   ticket, report, and audit log references this, not the UUID. The
   generation happens in ``case_service`` — the model only enforces the
   format.

3. **Assignment history vs current assignment.**
   ``case.assigned_to_id`` is the denormalized current primary analyst —
   fast to read. ``case_assignments`` is the full history. A partial
   unique index ``WHERE ended_at IS NULL`` per ``(case_id, role)``
   enforces "at most one active assignment per role per case".

4. **Assignment roles: primary / backup / reviewer.**
   One primary + N backups + N reviewers. Lets a senior analyst shadow a
   junior without splitting responsibility.

5. **Access grants ≠ assignments.**
   Assignment = "this analyst is doing the work".
   Access grant = "this user can see specific parts of this case".

   An org admin who wants to peek at an employee's case must request an
   access grant. That grant is logged with a mandatory ``purpose`` field.
   This is the schema-level enforcement of "don't confuse org admin with
   evidence access".

6. **Four access scopes, least privilege by default.**

       case_read           — case metadata only
       evidence_read       — evidence files + case metadata
       conversation_read   — messages + case metadata
       full_case           — everything

   The default for marketplace engagements is ``case_read``.

7. **Time-limited grants via ``expires_at``.**
   Marketplace engagements are often 7-day or 30-day windows. After
   expiry, ``is_active`` returns False — access auto-revokes without any
   cleanup job.

8. **``revoked_at`` is terminal.**
   A revoked grant cannot be un-revoked. To restore access, a new grant
   is created with a new ``granted_at``. Full audit history preserved.

9. **``status_history`` + ``investigation_notes`` on the case.**
   Append-only JSONB arrays. ``status_history`` records state transitions
   with attribution. ``investigation_notes`` records the analyst's
   thought process with ``note_type`` (observation, action, communication,
   finding).

10. **``linked_engagement_id`` + ``is_billable``.**
    For marketplace cases. Links back to the engagement record
    (marketplace.py). Nullable — internal cases have no engagement.

11. **``sla_deadline_at`` computed at creation.**
    From priority:
        urgent → 4h
        high   → 24h
        medium → 72h
        low    → 1 week

    Captured at creation so SLA policy changes don't retroactively break
    analytics.

12. **No ``SoftDeleteMixin``.**
    Cases are closed or cancelled, never deleted. Historical cases stay
    until retention policy cleanup after ``RETENTION_INCIDENTS_DAYS``.

13. **Timezone correctness everywhere.**

Usage
-----
    from app.models import SecurityCase, CaseAssignment, CaseAccessGrant
    from app.models.enums import (
        AccessGrantScope, CasePriority, CaseStatus, OrganizationRole,
    )

    # Create a case from an incident
    case = SecurityCase.build(
        workspace_id=workspace.id,
        case_number=SecurityCase.generate_case_number(2026, 1042),
        title="Investigate brute force against alice",
        description="...",
        incident_id=incident.id,
        created_by_id=admin.id,
        assigned_to_id=analyst.id,
        assigned_by_id=admin.id,
        priority=CasePriority.HIGH,
        severity=EventSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
    )
    db.add(case)
    db.flush()

    # Create assignment record (in addition to denormalized assigned_to_id)
    assignment = CaseAssignment.build(
        case_id=case.id,
        analyst_user_id=analyst.id,
        assigned_by_id=admin.id,
        role="primary",
    )
    db.add(assignment)

    # Grant external analyst scoped access (marketplace flow)
    grant = CaseAccessGrant.build(
        case_id=case.id,
        grantee_user_id=external_analyst.id,
        granted_by_id=priya.id,
        scope=AccessGrantScope.CASE_READ,
        purpose="Phishing investigation — ₹499 engagement",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(grant)
    db.commit()
"""

from __future__ import annotations

import re
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
    AccessGrantScope,
    AssignmentStatus,
    CasePriority,
    CaseStatus,
    EventSeverity,
    FindingCategory,
    enum_column_type,
)


# ── Constants ───────────────────────────────────────────────────────────────
_CASE_NUMBER_PATTERN = re.compile(r"^CG-\d{4}-\d{6}$")

#: Assignment role values.
_ROLE_PRIMARY = "primary"
_ROLE_BACKUP = "backup"
_ROLE_REVIEWER = "reviewer"
_VALID_ASSIGNMENT_ROLES = frozenset({_ROLE_PRIMARY, _ROLE_BACKUP, _ROLE_REVIEWER})

#: SLA deadlines by priority (hours from creation).
_SLA_BY_PRIORITY: dict[CasePriority, int] = {
    CasePriority.URGENT: 4,
    CasePriority.HIGH: 24,
    CasePriority.MEDIUM: 72,
    CasePriority.LOW: 168,  # 1 week
}

#: NIST-aligned state machine for cases. Less strict than incident — cases
#: can go back to investigating if new evidence emerges.
_ALLOWED_CASE_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({
        CaseStatus.ASSIGNED,
        CaseStatus.CANCELLED,
    }),
    CaseStatus.ASSIGNED: frozenset({
        CaseStatus.INVESTIGATING,
        CaseStatus.OPEN,  # unassigned
        CaseStatus.CANCELLED,
    }),
    CaseStatus.INVESTIGATING: frozenset({
        CaseStatus.PENDING_CLIENT,
        CaseStatus.PENDING_INFO,
        CaseStatus.RESOLVED,
        CaseStatus.CLOSED,
        CaseStatus.CANCELLED,
    }),
    CaseStatus.PENDING_CLIENT: frozenset({
        CaseStatus.INVESTIGATING,
        CaseStatus.RESOLVED,
        CaseStatus.CLOSED,
        CaseStatus.CANCELLED,
    }),
    CaseStatus.PENDING_INFO: frozenset({
        CaseStatus.INVESTIGATING,
        CaseStatus.RESOLVED,
        CaseStatus.CLOSED,
        CaseStatus.CANCELLED,
    }),
    CaseStatus.RESOLVED: frozenset({
        CaseStatus.CLOSED,
        CaseStatus.INVESTIGATING,  # reopened
    }),
    CaseStatus.CLOSED: frozenset({
        CaseStatus.INVESTIGATING,  # explicitly reopened by admin
    }),
    CaseStatus.CANCELLED: frozenset(),  # terminal
}

# ── Limits ──────────────────────────────────────────────────────────────────
_MAX_TITLE_LENGTH = 255
_MAX_DESCRIPTION_LENGTH = 10_000
_MAX_SUMMARY_LENGTH = 10_000
_MAX_RESOLUTION_LENGTH = 10_000
_MAX_NOTE_LENGTH = 5000
_MAX_PURPOSE_LENGTH = 500
_MAX_REVOCATION_REASON_LENGTH = 500
_MAX_REJECTION_REASON_LENGTH = 500
_MAX_TAGS = 30
_MAX_STATUS_HISTORY = 200
_MAX_INVESTIGATION_NOTES = 1000
_MAX_CASE_NUMBER_LENGTH = 16


# ============================================================================
# SECURITY CASE
# ============================================================================

class SecurityCase(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An analyst work assignment wrapper around a security investigation.

    A case can be:
        - linked to an incident (usual) — this is how an incident gets
          worked by one or more analysts
        - standalone (proactive work, drills, compliance audits) — no
          incident_id

    Access to the case and its evidence is granted through
    ``CaseAccessGrant`` rows, not by role or org membership alone.
    """

    __tablename__ = "security_cases"

    __table_args__ = (
        CheckConstraint(
            r"case_number ~ '^CG-\d{4}-\d{6}$'",
            name="case_number_format",
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
        CheckConstraint(
            "status NOT IN ('resolved', 'closed') OR resolved_at IS NOT NULL",
            name="resolved_requires_resolved_at",
        ),
        CheckConstraint(
            "status <> 'closed' OR closed_at IS NOT NULL",
            name="closed_requires_closed_at",
        ),
        # case_number unique within workspace
        Index(
            "uq_cases_workspace_number",
            "workspace_id",
            "case_number",
            unique=True,
        ),
        Index(
            "ix_cases_workspace_status_created",
            "workspace_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_cases_assigned_status",
            "assigned_to_id",
            "status",
        ),
        Index(
            "ix_cases_incident_id",
            "incident_id",
        ),
        Index(
            "ix_cases_priority_status",
            "priority",
            "status",
        ),
    )

    # ─── Tenant & incident ──────────────────────────────────────────────
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Tenant boundary. Deleting workspace cascades its cases.",
    )

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Incident this case investigates. NULL for proactive work, "
            "compliance audits, or drills."
        ),
    )

    # ─── Identity ───────────────────────────────────────────────────────
    case_number: Mapped[str] = mapped_column(
        String(_MAX_CASE_NUMBER_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Human-readable case number, format CG-YYYY-NNNNNN. Generated "
            "by case_service. Referenced in support tickets, reports, and "
            "audit logs instead of UUIDs."
        ),
    )

    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH), nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    # ─── Classification ─────────────────────────────────────────────────
    status: Mapped[CaseStatus] = mapped_column(
        enum_column_type(CaseStatus),
        nullable=False,
        default=CaseStatus.OPEN,
        server_default=CaseStatus.OPEN.value,
        index=True,
        comment="Workflow state. See _ALLOWED_CASE_TRANSITIONS.",
    )

    priority: Mapped[CasePriority] = mapped_column(
        enum_column_type(CasePriority),
        nullable=False,
        default=CasePriority.MEDIUM,
        server_default=CasePriority.MEDIUM.value,
        index=True,
        comment="Operational urgency. Drives SLA deadline.",
    )

    severity: Mapped[EventSeverity] = mapped_column(
        enum_column_type(EventSeverity),
        nullable=False,
        default=EventSeverity.MEDIUM,
        server_default=EventSeverity.MEDIUM.value,
        index=True,
        comment="Inherited from the linked incident, or set explicitly.",
    )

    category: Mapped[FindingCategory] = mapped_column(
        enum_column_type(FindingCategory),
        nullable=False,
        default=FindingCategory.OTHER,
        server_default=FindingCategory.OTHER.value,
        index=True,
    )

    # ─── Assignment (denormalized current state) ────────────────────────
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Current primary analyst. History in case_assignments.",
    )

    assigned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── Lifecycle timestamps ───────────────────────────────────────────
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True,
    )

    closed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── SLA ────────────────────────────────────────────────────────────
    sla_acknowledge_hours: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="SLA target for acknowledgement, captured at creation.",
    )

    sla_resolve_hours: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
    )

    sla_deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="opened_at + sla_resolve_hours. Drives is_overdue.",
    )

    # ─── Content ────────────────────────────────────────────────────────
    summary: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Analyst's one-paragraph summary of the case.",
    )

    resolution_summary: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    status_history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="Append-only log of {from, to, at, by_user_id, notes}.",
    )

    investigation_notes: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Append-only analyst notes: "
            "{at, by_user_id, note, note_type (observation|action|communication|finding)}."
        ),
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
    )

    # ─── Marketplace linkage ────────────────────────────────────────────
    is_billable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="True if work on this case is billable (marketplace flow).",
    )

    linked_engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        index=True,
        comment=(
            "FK to service_purchases (marketplace.py). Set when the case "
            "was created as part of a paid engagement. Nullable to avoid a "
            "circular FK dependency at model load time."
        ),
    )

    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment="How many times this case has been reopened.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("case_number")
    def _validate_case_number(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="case_number must be a string",
                code="CASE_NUMBER_INVALID_TYPE",
            )
        stripped = value.strip().upper()
        if not _CASE_NUMBER_PATTERN.match(stripped):
            raise ValidationError(
                message=(
                    "case_number must match the format "
                    "'CG-YYYY-NNNNNN' (e.g. 'CG-2026-001042')"
                ),
                code="CASE_NUMBER_INVALID_FORMAT",
                details={"received": stripped},
            )
        return stripped

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="CASE_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="CASE_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="CASE_TITLE_TOO_LONG",
            )
        return stripped

    @validates("status")
    def _validate_status(
        self, _key: str, value: CaseStatus | str
    ) -> CaseStatus:
        if isinstance(value, CaseStatus):
            return value
        if isinstance(value, str):
            try:
                return CaseStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid case status {value!r}",
                    code="CASE_STATUS_INVALID",
                    details={"allowed": list(CaseStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be a CaseStatus or string",
            code="CASE_STATUS_INVALID_TYPE",
        )

    @validates("priority")
    def _validate_priority(
        self, _key: str, value: CasePriority | str
    ) -> CasePriority:
        if isinstance(value, CasePriority):
            return value
        if isinstance(value, str):
            try:
                return CasePriority(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid case priority {value!r}",
                    code="CASE_PRIORITY_INVALID",
                    details={"allowed": list(CasePriority.values())},
                ) from exc
        raise ValidationError(
            message="priority must be a CasePriority or string",
            code="CASE_PRIORITY_INVALID_TYPE",
        )

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
                    message=f"Invalid case severity {value!r}",
                    code="CASE_SEVERITY_INVALID",
                    details={"allowed": list(EventSeverity.values())},
                ) from exc
        raise ValidationError(
            message="severity must be an EventSeverity or string",
            code="CASE_SEVERITY_INVALID_TYPE",
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
                    message=f"Invalid case category {value!r}",
                    code="CASE_CATEGORY_INVALID",
                    details={"allowed": list(FindingCategory.values())},
                ) from exc
        raise ValidationError(
            message="category must be a FindingCategory or string",
            code="CASE_CATEGORY_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @staticmethod
    def generate_case_number(year: int, sequence: int) -> str:
        """
        Format a case number from a year and a positive sequence value.
        The caller (``case_service``) is responsible for obtaining the next
        available sequence for the year.
        """
        if not (2000 <= year <= 9999):
            raise ValidationError(
                message="year must be between 2000 and 9999",
                code="CASE_YEAR_INVALID",
                details={"year": year},
            )
        if not (1 <= sequence <= 999_999):
            raise ValidationError(
                message="sequence must be between 1 and 999999",
                code="CASE_SEQUENCE_INVALID",
                details={"sequence": sequence},
            )
        return f"CG-{year:04d}-{sequence:06d}"

    @classmethod
    def build(
        cls,
        *,
        workspace_id: uuid.UUID,
        case_number: str,
        title: str,
        created_by_id: uuid.UUID | None = None,
        description: str | None = None,
        incident_id: uuid.UUID | None = None,
        assigned_to_id: uuid.UUID | None = None,
        assigned_by_id: uuid.UUID | None = None,
        priority: CasePriority = CasePriority.MEDIUM,
        severity: EventSeverity = EventSeverity.MEDIUM,
        category: FindingCategory = FindingCategory.OTHER,
        tags: list[str] | None = None,
        context: dict[str, Any] | None = None,
        is_billable: bool = False,
        linked_engagement_id: uuid.UUID | None = None,
    ) -> "SecurityCase":
        """
        Construct a new case. Sets SLA deadline from priority.
        """
        now = datetime.now(timezone.utc)
        sla_hours = _SLA_BY_PRIORITY.get(priority, 72)
        deadline = now + timedelta(hours=sla_hours)

        initial_status = (
            CaseStatus.ASSIGNED if assigned_to_id is not None
            else CaseStatus.OPEN
        )

        case = cls(
            workspace_id=workspace_id,
            incident_id=incident_id,
            case_number=case_number,
            title=title,
            description=description,
            status=initial_status,
            priority=priority,
            severity=severity,
            category=category,
            assigned_to_id=assigned_to_id,
            assigned_at=now if assigned_to_id else None,
            assigned_by_id=assigned_by_id if assigned_to_id else None,
            created_by_id=created_by_id,
            opened_at=now,
            sla_resolve_hours=sla_hours,
            sla_deadline_at=deadline,
            tags=tags or [],
            context=context or {},
            is_billable=is_billable,
            linked_engagement_id=linked_engagement_id,
            occurrence_count=1,
            status_history=[
                {
                    "from": None,
                    "to": initial_status.value,
                    "at": now.isoformat(),
                    "by_user_id": str(created_by_id) if created_by_id else None,
                    "notes": "Case created.",
                }
            ],
            investigation_notes=[],
        )
        return case

    # ====================================================================
    # STATUS TRANSITIONS
    # ====================================================================

    def can_transition_to(self, new_status: CaseStatus) -> bool:
        """Return True if transitioning to new_status is allowed."""
        if not isinstance(new_status, CaseStatus):
            try:
                new_status = CaseStatus(new_status)
            except (ValueError, TypeError):
                return False
        if new_status == self.status:
            return False
        allowed = _ALLOWED_CASE_TRANSITIONS.get(self.status, frozenset())
        return new_status in allowed

    def advance_status(
        self,
        new_status: CaseStatus,
        *,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """Transition to new_status, updating timestamps and history."""
        if not self.can_transition_to(new_status):
            raise InvalidStateTransitionError(
                message=(
                    f"Cannot transition case from {self.status.value!r} "
                    f"to {new_status.value!r}"
                ),
                code="CASE_INVALID_TRANSITION",
                details={
                    "current": self.status.value,
                    "requested": new_status.value,
                    "allowed": [
                        s.value
                        for s in _ALLOWED_CASE_TRANSITIONS.get(
                            self.status, frozenset()
                        )
                    ],
                },
            )

        now = datetime.now(timezone.utc)
        old_status = self.status
        self.status = new_status

        if new_status == CaseStatus.INVESTIGATING and self.acknowledged_at is None:
            self.acknowledged_at = now
        elif new_status == CaseStatus.RESOLVED and self.resolved_at is None:
            self.resolved_at = now
        elif new_status == CaseStatus.CLOSED:
            self.closed_at = now
            if by_user_id is not None:
                self.closed_by_id = by_user_id

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
    # INVESTIGATION NOTES
    # ====================================================================

    def add_investigation_note(
        self,
        *,
        note: str,
        by_user_id: uuid.UUID,
        note_type: str = "observation",
    ) -> None:
        """Append a note to the investigation log."""
        if not isinstance(note, str) or not note.strip():
            raise ValidationError(
                message="note must be a non-empty string",
                code="CASE_NOTE_EMPTY",
            )
        if len(note) > _MAX_NOTE_LENGTH:
            raise ValidationError(
                message=f"note must not exceed {_MAX_NOTE_LENGTH} characters",
                code="CASE_NOTE_TOO_LONG",
            )
        valid_types = {"observation", "action", "communication", "finding"}
        if note_type not in valid_types:
            raise ValidationError(
                message=f"note_type must be one of {sorted(valid_types)}",
                code="CASE_NOTE_TYPE_INVALID",
                details={"received": note_type},
            )

        notes = list(self.investigation_notes or [])
        if len(notes) >= _MAX_INVESTIGATION_NOTES:
            raise ValidationError(
                message=(
                    f"investigation_notes has reached the maximum "
                    f"of {_MAX_INVESTIGATION_NOTES} entries"
                ),
                code="CASE_NOTES_LIMIT_REACHED",
            )
        notes.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "by_user_id": str(by_user_id),
            "note": note.strip(),
            "note_type": note_type,
        })
        self.investigation_notes = notes

    # ====================================================================
    # ASSIGNMENT (denormalized helper)
    # ====================================================================

    def set_primary_analyst(
        self,
        *,
        analyst_user_id: uuid.UUID,
        assigned_by_id: uuid.UUID,
    ) -> None:
        """
        Update the denormalized ``assigned_to_id`` field. The caller
        (``case_service``) is responsible for also closing the previous
        ``CaseAssignment`` row and creating a new one.
        """
        now = datetime.now(timezone.utc)
        self.assigned_to_id = analyst_user_id
        self.assigned_by_id = assigned_by_id
        self.assigned_at = now
        if self.status == CaseStatus.OPEN:
            self.advance_status(
                CaseStatus.ASSIGNED,
                by_user_id=assigned_by_id,
                notes=f"Assigned to {analyst_user_id}",
            )

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_open(self) -> bool:
        """True if the case is in an active workflow state."""
        return self.status not in (CaseStatus.CLOSED, CaseStatus.CANCELLED)

    @property
    def is_closed(self) -> bool:
        """True if the case is closed."""
        return self.status == CaseStatus.CLOSED

    @property
    def is_cancelled(self) -> bool:
        """True if the case was cancelled (terminal)."""
        return self.status == CaseStatus.CANCELLED

    @property
    def is_assigned(self) -> bool:
        """True if a primary analyst is assigned."""
        return self.assigned_to_id is not None

    @property
    def is_overdue(self) -> bool:
        """True if the case is open and past its SLA deadline."""
        if not self.is_open or self.sla_deadline_at is None:
            return False
        deadline = self.sla_deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return deadline < datetime.now(timezone.utc)

    @property
    def age_seconds(self) -> int:
        """Seconds since the case was opened."""
        if self.opened_at is None:
            return 0
        opened = self.opened_at
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - opened).total_seconds())

    @property
    def time_to_resolve_seconds(self) -> int | None:
        """Seconds from opened_at to resolved_at."""
        if self.resolved_at is None or self.opened_at is None:
            return None
        opened = self.opened_at
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        resolved = self.resolved_at
        if resolved.tzinfo is None:
            resolved = resolved.replace(tzinfo=timezone.utc)
        return int((resolved - opened).total_seconds())


# ============================================================================
# CASE ASSIGNMENT
# ============================================================================

class CaseAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An assignment of an analyst to a case. Preserves full history —
    reassignment closes the previous assignment and creates a new one.

    A case may have at most one active assignment per role at any time,
    enforced by a partial unique index ``WHERE ended_at IS NULL``.
    """

    __tablename__ = "case_assignments"

    __table_args__ = (
        CheckConstraint(
            "role IN ('primary', 'backup', 'reviewer')",
            name="role_values",
        ),
        # One active assignment per (case, role) at a time.
        Index(
            "uq_case_active_assignment_per_role",
            "case_id",
            "role",
            unique=True,
            postgresql_where=text("ended_at IS NULL"),
        ),
        Index(
            "ix_case_assignments_case_id",
            "case_id",
        ),
        Index(
            "ix_case_assignments_analyst_status",
            "analyst_user_id",
            "status",
        ),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    analyst_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="The analyst assigned to this case.",
    )

    assigned_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Who made the assignment.",
    )

    role: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_ROLE_PRIMARY,
        server_default=_ROLE_PRIMARY,
        comment="primary | backup | reviewer",
    )

    status: Mapped[AssignmentStatus] = mapped_column(
        enum_column_type(AssignmentStatus),
        nullable=False,
        default=AssignmentStatus.ACTIVE,
        server_default=AssignmentStatus.ACTIVE.value,
        index=True,
    )

    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
    )

    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When the analyst accepted the assignment.",
    )

    rejected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="When the analyst rejected the assignment.",
    )

    rejection_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        index=True,
        comment="When the assignment ended (completed, reassigned, cancelled).",
    )

    ended_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    ended_reason: Mapped[str | None] = mapped_column(
        String(255), nullable=True,
    )

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        case_id: uuid.UUID,
        analyst_user_id: uuid.UUID,
        assigned_by_id: uuid.UUID | None,
        role: str = _ROLE_PRIMARY,
    ) -> "CaseAssignment":
        """Construct a new active assignment."""
        if role not in _VALID_ASSIGNMENT_ROLES:
            raise ValidationError(
                message=f"role must be one of {sorted(_VALID_ASSIGNMENT_ROLES)}",
                code="CASE_ASSIGNMENT_ROLE_INVALID",
                details={"received": role},
            )
        return cls(
            case_id=case_id,
            analyst_user_id=analyst_user_id,
            assigned_by_id=assigned_by_id,
            role=role,
            status=AssignmentStatus.ACTIVE,
            assigned_at=datetime.now(timezone.utc),
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def accept(self) -> None:
        """Mark as accepted by the analyst."""
        if self.status != AssignmentStatus.ACTIVE:
            raise ValidationError(
                message="Can only accept an active assignment",
                code="CASE_ASSIGNMENT_NOT_ACTIVE",
            )
        self.accepted_at = datetime.now(timezone.utc)

    def reject(self, *, reason: str) -> None:
        """Mark as rejected by the analyst (terminal for this assignment)."""
        now = datetime.now(timezone.utc)
        self.status = AssignmentStatus.CANCELLED
        self.rejected_at = now
        self.rejection_reason = reason.strip()
        self.ended_at = now

    def end(
        self,
        *,
        status: AssignmentStatus = AssignmentStatus.COMPLETED,
        by_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> None:
        """End the assignment (completed, reassigned, or cancelled)."""
        now = datetime.now(timezone.utc)
        self.status = status
        self.ended_at = now
        if by_user_id is not None:
            self.ended_by_id = by_user_id
        if reason:
            self.ended_reason = reason

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_active(self) -> bool:
        """True if the assignment is currently active (not ended)."""
        return self.status == AssignmentStatus.ACTIVE and self.ended_at is None


# ============================================================================
# CASE ACCESS GRANT
# ============================================================================

class CaseAccessGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An explicit, scoped, auditable grant of access to a case for a
    specific user (analyst, admin, or external viewer).

    This is the **only** mechanism (other than being the assigned analyst)
    that lets anyone see a case's metadata or evidence. Being an org
    administrator grants zero implicit access — they must request a grant
    just like anyone else.
    """

    __tablename__ = "case_access_grants"

    __table_args__ = (
        CheckConstraint(
            "expires_at IS NULL OR expires_at > granted_at",
            name="expires_after_granted",
        ),
        CheckConstraint(
            "(revoked_at IS NULL AND revocation_reason IS NULL) "
            "OR (revoked_at IS NOT NULL)",
            name="revocation_pair",
        ),
        # At most one active grant per (case, grantee, scope).
        # Revoked grants are excluded — re-granting creates a new row.
        Index(
            "uq_case_active_grant_per_scope",
            "case_id",
            "grantee_user_id",
            "scope",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index(
            "ix_case_grants_case_id",
            "case_id",
        ),
        Index(
            "ix_case_grants_grantee",
            "grantee_user_id",
            "revoked_at",
        ),
        Index(
            "ix_case_grants_expires_at",
            "expires_at",
        ),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    grantee_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User receiving the access grant.",
    )

    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Who granted access. Must be someone with authority over the case.",
    )

    scope: Mapped[AccessGrantScope] = mapped_column(
        enum_column_type(AccessGrantScope),
        nullable=False,
        comment=(
            "case_read | evidence_read | conversation_read | full_case. "
            "Least privilege by default — callers must justify more."
        ),
    )

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment=(
            "Optional time limit. After expiry, is_active returns False "
            "without any cleanup job."
        ),
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When the grant was explicitly revoked. Terminal.",
    )

    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    revocation_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    purpose: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment=(
            "Why access was granted. Required field — auditable. "
            "E.g. 'Phishing investigation — ₹499 engagement'."
        ),
    )

    notes: Mapped[str | None] = mapped_column(
        Text, nullable=True,
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("purpose")
    def _validate_purpose(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="purpose must be a string",
                code="CASE_GRANT_PURPOSE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="purpose must not be empty",
                code="CASE_GRANT_PURPOSE_EMPTY",
            )
        if len(stripped) > _MAX_PURPOSE_LENGTH:
            raise ValidationError(
                message=f"purpose must not exceed {_MAX_PURPOSE_LENGTH} characters",
                code="CASE_GRANT_PURPOSE_TOO_LONG",
            )
        return stripped

    @validates("scope")
    def _validate_scope(
        self, _key: str, value: AccessGrantScope | str
    ) -> AccessGrantScope:
        if isinstance(value, AccessGrantScope):
            return value
        if isinstance(value, str):
            try:
                return AccessGrantScope(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid grant scope {value!r}",
                    code="CASE_GRANT_SCOPE_INVALID",
                    details={"allowed": list(AccessGrantScope.values())},
                ) from exc
        raise ValidationError(
            message="scope must be an AccessGrantScope or string",
            code="CASE_GRANT_SCOPE_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        case_id: uuid.UUID,
        grantee_user_id: uuid.UUID,
        granted_by_id: uuid.UUID,
        scope: AccessGrantScope,
        purpose: str,
        expires_at: datetime | None = None,
        notes: str | None = None,
    ) -> "CaseAccessGrant":
        """
        Construct a new access grant.

        ``expires_at`` must be in the future if provided. ``purpose`` is
        required — every grant must have a recorded reason.
        """
        now = datetime.now(timezone.utc)
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= now:
                raise ValidationError(
                    message="expires_at must be in the future",
                    code="CASE_GRANT_EXPIRY_IN_PAST",
                )

        return cls(
            case_id=case_id,
            grantee_user_id=grantee_user_id,
            granted_by_id=granted_by_id,
            scope=scope,
            purpose=purpose,
            granted_at=now,
            expires_at=expires_at,
            notes=notes,
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def revoke(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> None:
        """Explicitly revoke this grant. Terminal."""
        if self.revoked_at is not None:
            return
        self.revoked_at = datetime.now(timezone.utc)
        if by_user_id is not None:
            self.revoked_by_id = by_user_id
        if reason:
            if len(reason) > _MAX_REVOCATION_REASON_LENGTH:
                raise ValidationError(
                    message=(
                        f"revocation reason must not exceed "
                        f"{_MAX_REVOCATION_REASON_LENGTH} characters"
                    ),
                    code="CASE_GRANT_REASON_TOO_LONG",
                )
            self.revocation_reason = reason.strip()

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_revoked(self) -> bool:
        """True if the grant has been explicitly revoked."""
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        """True if the grant had an expiry and that moment has passed."""
        if self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    @property
    def is_active(self) -> bool:
        """True if the grant is currently effective (not revoked, not expired)."""
        return not self.is_revoked and not self.is_expired

    @property
    def permits_case_read(self) -> bool:
        """True if this grant allows reading case metadata."""
        return self.is_active and self.scope in (
            AccessGrantScope.CASE_READ,
            AccessGrantScope.EVIDENCE_READ,
            AccessGrantScope.CONVERSATION_READ,
            AccessGrantScope.FULL_CASE,
        )

    @property
    def permits_evidence_read(self) -> bool:
        """True if this grant allows reading evidence."""
        return self.is_active and self.scope in (
            AccessGrantScope.EVIDENCE_READ,
            AccessGrantScope.FULL_CASE,
        )

    @property
    def permits_conversation_read(self) -> bool:
        """True if this grant allows reading case conversation."""
        return self.is_active and self.scope in (
            AccessGrantScope.CONVERSATION_READ,
            AccessGrantScope.FULL_CASE,
        )

    @property
    def is_full_access(self) -> bool:
        """True if this grant provides full-case access."""
        return self.is_active and self.scope == AccessGrantScope.FULL_CASE


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.workspace import Workspace
#     from app.models.incident import SecurityIncident
#     from app.models.user import User
#     from app.models.evidence import SecurityEvidence
#     from app.models.conversation import CaseConversation
#     from app.models.marketplace import ServicePurchase
#
# class SecurityCase(...):
#     ...
#     workspace: Mapped["Workspace"] = relationship("Workspace")
#     incident: Mapped["SecurityIncident | None"] = relationship("SecurityIncident")
#     assigned_to: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[assigned_to_id]
#     )
#     created_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[created_by_id]
#     )
#     assignments: Mapped[list["CaseAssignment"]] = relationship(
#         "CaseAssignment",
#         back_populates="case",
#         cascade="all, delete-orphan",
#     )
#     access_grants: Mapped[list["CaseAccessGrant"]] = relationship(
#         "CaseAccessGrant",
#         back_populates="case",
#         cascade="all, delete-orphan",
#     )
#     evidence: Mapped[list["SecurityEvidence"]] = relationship(
#         "SecurityEvidence", back_populates="case"
#     )
#     conversations: Mapped[list["CaseConversation"]] = relationship(
#         "CaseConversation", back_populates="case"
#     )
#
# class CaseAssignment(...):
#     ...
#     case: Mapped["SecurityCase"] = relationship(
#         "SecurityCase", back_populates="assignments"
#     )
#     analyst: Mapped["User"] = relationship(
#         "User", foreign_keys=[analyst_user_id]
#     )
#     assigned_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[assigned_by_id]
#     )
#
# class CaseAccessGrant(...):
#     ...
#     case: Mapped["SecurityCase"] = relationship(
#         "SecurityCase", back_populates="access_grants"
#     )
#     grantee: Mapped["User"] = relationship(
#         "User", foreign_keys=[grantee_user_id]
#     )
#     granted_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[granted_by_id]
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityCase",
    "CaseAssignment",
    "CaseAccessGrant",
    "_CASE_NUMBER_PATTERN",
    "_VALID_ASSIGNMENT_ROLES",
    "_SLA_BY_PRIORITY",
    "_ALLOWED_CASE_TRANSITIONS",
    "_MAX_TITLE_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_SUMMARY_LENGTH",
    "_MAX_RESOLUTION_LENGTH",
    "_MAX_NOTE_LENGTH",
    "_MAX_PURPOSE_LENGTH",
    "_MAX_REVOCATION_REASON_LENGTH",
    "_MAX_REJECTION_REASON_LENGTH",
    "_MAX_TAGS",
    "_MAX_STATUS_HISTORY",
    "_MAX_INVESTIGATION_NOTES",
    "_MAX_CASE_NUMBER_LENGTH",
]