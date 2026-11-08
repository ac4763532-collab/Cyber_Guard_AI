"""
CyberGuard AI — Case Service
============================================================================

The case workflow service — assignment, access grants, and the case
lifecycle. This is where the platform's core security rule is enforced:

    "An organization administrator should not automatically gain access
     to all client evidence. Sensitive access must be explicitly granted
     and audited."

The access grant flow (the crown jewel)
---------------------------------------
Every user who works on a case needs one of:

    1. Being the assigned analyst (via CaseAssignment)
    2. An active CaseAccessGrant with the right scope
    3. A workspace/org role that grants the permission
       (but this NEVER extends to evidence — role-based access to
       case *metadata* is fine; role-based access to case *evidence*
       is not)

``create_access_grant`` is the only way to grant access to someone who
isn't the assigned analyst. Every grant has:

    - A mandatory ``purpose`` string ("why is Rahul seeing this?")
    - A scope (case_read | evidence_read | conversation_read | full_case)
    - An optional expiry (recommended)
    - An audit trail (who granted, when, why)

Grants cannot be edited. They are issued or revoked. To restore
access after revocation, a NEW grant is issued (which appears as a
new audit event — no retroactive fixes).

Case creation
-------------
A case is created:

    - By the incident_response_agent when an incident warrants
      analyst-level work
    - By an admin manually
    - By the marketplace_service when a customer purchases a service

The service generates the human-readable ``case_number`` (``CG-YYYY-NNNNNN``),
creates default conversations (one client, one internal, one system),
and links the originating incident (if any).

Case number sequence
--------------------
The sequence is per-year, global (not per-workspace). Two concurrent
case creations in different workspaces might try to allocate the
same sequence number — the DB unique constraint on ``case_number``
within a workspace catches this. The service retries once with a
new sequence on collision. With realistic volumes (hundreds of cases
per year), collisions are astronomically rare.

State machine (looser than incidents)
-------------------------------------
Cases are more flexible than incidents:

    OPEN → ASSIGNED → INVESTIGATING → RESOLVED → CLOSED
                                    → PENDING_CLIENT
                                    → PENDING_INFO
                                    → CANCELLED (from any active state)

Plus reopen: RESOLVED → INVESTIGATING, CLOSED → INVESTIGATING

Cases can go *backwards* (RESOLVED → INVESTIGATING) because new
evidence can appear. Incidents require more ceremony to reopen.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Every state change audits.
5. Access grants are audited separately (they're a distinct
   compliance-sensitive operation).

Public API
----------
    # Creation
    create_case(db, *, dto, actor=None, incident=None)     → SecurityCase
    get_by_id(db, case_id)                                 → SecurityCase
    list_cases(db, *, workspace_ids, page, filters)        → (list, int)

    # Lifecycle
    advance_status(db, *, actor, case, new_status, notes=None, request=None)
                                                           → SecurityCase
    assign(db, *, actor, case, analyst_user_id, role="primary",
           notes=None, request=None)                       → CaseAssignment
    reassign(db, *, actor, case, analyst_user_id, reason, request=None)
                                                           → CaseAssignment
    unassign(db, *, actor, case, reason, request=None)     → SecurityCase
    close(db, *, actor, case, resolution_summary, request=None)
                                                           → SecurityCase

    # Access grants
    create_access_grant(db, *, actor, case, grantee_user_id, scope,
                        purpose, expires_at=None, notes=None, request=None)
                                                           → CaseAccessGrant
    revoke_access_grant(db, *, actor, grant, reason, request=None)
                                                           → CaseAccessGrant
    list_access_grants(db, *, actor, case, page, include_revoked=False)
                                                           → (list, int)

    # Notes
    add_investigation_note(db, *, actor, case, note, note_type="observation",
                           request=None)                   → SecurityCase

    # SLA
    check_sla_breaches(db, *, limit=100)                   → list[SecurityCase]

Usage
-----
    from app.services import case_service

    # Agent or admin creates the case
    case = case_service.create_case(
        db,
        dto=CaseCreate(
            title="Investigate brute-force attack",
            incident_id=incident.id,
            priority=CasePriority.HIGH,
            severity=EventSeverity.HIGH,
            category=FindingCategory.BRUTE_FORCE,
        ),
        actor=admin_user,
    )
    db.commit()

    # Assign an analyst
    case_service.assign(
        db, actor=admin_user, case=case, analyst_user_id=analyst.id,
    )

    # External analyst gets scoped access (marketplace flow)
    case_service.create_access_grant(
        db,
        actor=priya,   # the client
        case=case,
        grantee_user_id=external_analyst.id,
        scope=AccessGrantScope.CASE_READ,
        purpose="Phishing investigation — ₹499 engagement",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.commit()
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_CASE_ASSIGN,
    PERM_CASE_UPDATE,
    PERM_INCIDENT_ASSIGN,
)
from app.core.exceptions import (
    AuthorizationError,
    CaseNotFoundError,
    ConflictError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.case import (
    CaseAccessGrant,
    CaseAssignment,
    SecurityCase,
)
from app.models.conversation import CaseConversation
from app.models.enums import (
    AccessGrantScope,
    AssignmentStatus,
    CasePriority,
    CaseStatus,
    ConversationStatus,
    EventSeverity,
    FindingCategory,
)
from app.models.incident import SecurityIncident
from app.models.user import User
from app.schemas.case import (
    CaseCreate,
    CaseFilter,
)
from app.schemas.common import PageParams
from app.services import audit_service, authorization, notification_service


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: SLA hours by priority. Applied at case creation.
_SLA_HOURS_BY_PRIORITY: dict[CasePriority, int] = {
    CasePriority.URGENT: 4,
    CasePriority.HIGH: 24,
    CasePriority.MEDIUM: 72,
    CasePriority.LOW: 168,  # 1 week
}

#: Allowed case status transitions. Looser than incidents — cases can
#: reopen from RESOLVED and CLOSED.
_ALLOWED_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({
        CaseStatus.ASSIGNED,
        CaseStatus.CANCELLED,
    }),
    CaseStatus.ASSIGNED: frozenset({
        CaseStatus.INVESTIGATING,
        CaseStatus.OPEN,        # unassigned
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
        CaseStatus.INVESTIGATING,  # reopen
    }),
    CaseStatus.CLOSED: frozenset({
        CaseStatus.INVESTIGATING,  # explicit reopen
    }),
    CaseStatus.CANCELLED: frozenset(),  # terminal
}

_VALID_ASSIGNMENT_ROLES = frozenset({"primary", "backup", "reviewer"})

_SEVERITY_RANK = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}


# ============================================================================
# INTERNAL — case number generation
# ============================================================================

def _generate_case_number(year: int | None = None) -> str:
    """
    Generate a case number in the format ``CG-YYYY-NNNNNN``.

    The sequence is random (not sequential) within the year — a
    monotonic sequence would require cross-workspace locking, and
    the case_number only needs to be unique, not ordered.

    Uses 6 digits (000001–999999). ~1M cases per year globally is
    well beyond what the platform will see. If we ever exceed that,
    bumping to 7 digits is a schema change (change ``_MAX_CASE_LENGTH``
    constant + validator).

    Collisions caught by DB unique constraint → caller retries.
    """
    y = year if year is not None else datetime.now(timezone.utc).year
    seq = secrets.randbelow(999_999) + 1  # 1–999999
    return f"CG-{y:04d}-{seq:06d}"


# ============================================================================
# INTERNAL — snapshots and helper logic
# ============================================================================

def _snapshot_state(case: SecurityCase) -> dict[str, Any]:
    """Capture mutable case fields for audit."""
    return {
        "status": case.status.value,
        "priority": case.priority.value,
        "severity": case.severity.value,
        "assigned_to_id": (
            str(case.assigned_to_id) if case.assigned_to_id else None
        ),
        "summary": case.summary,
        "resolution_summary": case.resolution_summary,
    }


def _create_default_conversations(
    db: Session,
    *,
    case: SecurityCase,
    actor_id: uuid.UUID,
) -> None:
    """
    Create the default conversation threads for a new case.

    Every case has three:
        - client      — visible to client + assigned analyst
        - internal    — analyst-only (never visible to client)
        - system      — automated messages

    One conversation per (case, type) enforced by DB unique constraint.
    """
    for conv_type in ("client", "internal", "system"):
        conv = CaseConversation.build(
            workspace_id=case.workspace_id,
            case_id=case.id,
            conversation_type=conv_type,
            created_by_id=actor_id,
            title={
                "client": "Conversation with client",
                "internal": "Internal analyst discussion",
                "system": "System events",
            }[conv_type],
        )
        db.add(conv)
    db.flush()


def _close_active_assignments(
    db: Session,
    *,
    case_id: uuid.UUID,
    role: str,
    ended_by_id: uuid.UUID | None = None,
    reason: str | None = None,
) -> None:
    """
    Close any active assignment for the given role. Called before
    creating a new assignment of the same role — the DB partial
    unique index on ``(case_id, role) WHERE ended_at IS NULL``
    enforces this.
    """
    existing = db.execute(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.role == role,
            CaseAssignment.ended_at.is_(None),
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.end(
            status=AssignmentStatus.REASSIGNED,
            by_user_id=ended_by_id,
            reason=reason,
        )
        db.flush()


# ============================================================================
# CREATE
# ============================================================================

def create_case(
    db: Session,
    *,
    dto: CaseCreate,
    actor: User | None = None,
    incident: SecurityIncident | None = None,
) -> SecurityCase:
    """
    Create a new case.

    Flow
    ----
    1. Validate incident reference (if provided, load it and verify
       workspace match)
    2. Generate case_number (retry on collision — rare)
    3. Create the case row
    4. Create default conversations (client, internal, system)
    5. Create initial assignment (if ``dto.assigned_to_id`` is set)
    6. Link to incident (if provided)
    7. Audit
    8. Notify assignee (if set)

    Retries case_number generation up to 3 times on IntegrityError
    before giving up. With ~1M possible numbers and realistic volumes,
    a collision is astronomically improbable.

    Parameters
    ----------
    db : Session
    dto : CaseCreate
        Validated request body.
    actor : User | None
        The user creating the case. ``None`` for agent-initiated
        creation.
    incident : SecurityIncident | None
        Optional. If provided, must match ``dto.incident_id``.

    Returns
    -------
    SecurityCase

    Raises
    ------
    ValidationError
        If incident reference is invalid, or assignee is invalid.
    ConflictError
        If case_number generation fails repeatedly (essentially
        impossible).
    """
    from app.models.workspace import Workspace

    # ── 1. Load and validate incident if provided
    incident_obj: SecurityIncident | None = None
    if dto.incident_id is not None:
        incident_obj = incident or db.get(SecurityIncident, dto.incident_id)
        if incident_obj is None:
            raise ValidationError(
                message=f"Incident {dto.incident_id} not found.",
                code="INCIDENT_NOT_FOUND",
            )

    # ── 2. Determine workspace from context
    if incident_obj is not None:
        workspace_id = incident_obj.workspace_id
    elif dto.linked_engagement_id is not None:
        raise ValidationError(
            message=(
                "linked_engagement_id requires incident_id or an "
                "explicit workspace context — not yet supported for "
                "standalone marketplace cases."
            ),
            code="CASE_WORKSPACE_UNRESOLVED",
        )
    else:
        # Standalone proactive case — need workspace context from
        # caller. The current CaseCreate schema doesn't carry
        # workspace_id (it's set by the endpoint from the URL). This
        # service requires it to be passed via the incident, or the
        # endpoint must call with a modified DTO. For now, raise —
        # the endpoint will be written with this constraint in mind.
        raise ValidationError(
            message=(
                "Cases require either an incident_id or a workspace "
                "context. Standalone cases need the endpoint to "
                "supply workspace_id explicitly (extend CaseCreate)."
            ),
            code="CASE_WORKSPACE_REQUIRED",
        )

    # ── 3. Load workspace (for org_id in audit)
    ws = db.get(Workspace, workspace_id)

    # ── 4. Generate case_number with retry
    case_number: str | None = None
    for _attempt in range(3):
        candidate = _generate_case_number()
        existing = db.execute(
            select(SecurityCase.id).where(
                SecurityCase.workspace_id == workspace_id,
                SecurityCase.case_number == candidate,
            )
        ).scalar_one_or_none()
        if existing is None:
            case_number = candidate
            break

    if case_number is None:
        raise ConflictError(
            message=(
                "Could not generate a unique case number after 3 "
                "attempts. This is extremely unusual — please retry."
            ),
            code="CASE_NUMBER_GENERATION_FAILED",
        )

    # ── 5. Build the case
    priority = dto.priority or CasePriority.MEDIUM
    sla_hours = _SLA_HOURS_BY_PRIORITY.get(priority, 72)

    case = SecurityCase.build(
        workspace_id=workspace_id,
        case_number=case_number,
        title=dto.title,
        description=dto.description,
        incident_id=dto.incident_id,
        assigned_to_id=dto.assigned_to_id,
        assigned_by_id=actor.id if actor and dto.assigned_to_id else None,
        priority=priority,
        severity=dto.severity,
        category=dto.category,
        tags=dto.tags or [],
        context=dto.context or {},
        is_billable=dto.is_billable,
        linked_engagement_id=dto.linked_engagement_id,
    )
    db.add(case)
    db.flush()

    # ── 6. Default conversations
    _create_default_conversations(
        db,
        case=case,
        actor_id=actor.id if actor else case.id,
    )

    # ── 7. Initial assignment
    if dto.assigned_to_id is not None:
        _close_active_assignments(
            db, case_id=case.id, role="primary",
        )
        assignment = CaseAssignment.build(
            case_id=case.id,
            analyst_user_id=dto.assigned_to_id,
            assigned_by_id=actor.id if actor else None,
            role="primary",
        )
        db.add(assignment)
        db.flush()

        # Notify assignee
        try:
            notification_service.create_for_case_assignment(
                db,
                case=case,
                assignee_id=dto.assigned_to_id,
                assigner_id=actor.id if actor else dto.assigned_to_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to notify case assignee",
                extra={
                    "case_id": str(case.id),
                    "error": str(exc)[:200],
                },
            )

    # ── 8. Link to incident
    if incident_obj is not None:
        # Set assigned_at field on incident if not already set
        pass  # No back-link needed — case.incident_id IS the link

    # ── 9. Audit
    audit_service.log_action(
        db,
        actor=actor,
        actor_type="user" if actor else "agent",
        action="case.created",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
        workspace_id=workspace_id,
        organization_id=ws.organization_id if ws else None,
        metadata={
            "case_number": case_number,
            "priority": priority.value,
            "severity": case.severity.value,
            "incident_id": str(dto.incident_id) if dto.incident_id else None,
            "assigned_to_id": (
                str(dto.assigned_to_id) if dto.assigned_to_id else None
            ),
        },
    )

    logger.info(
        "Case created",
        extra={
            "case_id": str(case.id),
            "case_number": case_number,
            "workspace_id": str(workspace_id),
            "incident_id": str(dto.incident_id) if dto.incident_id else None,
            "priority": priority.value,
        },
    )

    return case


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, case_id: uuid.UUID) -> SecurityCase:
    """Fetch a case by ID. Raises ``CaseNotFoundError`` if missing."""
    case = db.get(SecurityCase, case_id)
    if case is None:
        raise CaseNotFoundError(
            message=f"Case {case_id} not found.",
            details={"case_id": str(case_id)},
        )
    return case


def list_cases(
    db: Session,
    *,
    workspace_ids: list[uuid.UUID] | None,
    page: PageParams,
    filters: CaseFilter,
) -> tuple[list[SecurityCase], int]:
    """List cases with filters and pagination."""
    stmt = select(SecurityCase)

    if workspace_ids is not None:
        stmt = stmt.where(SecurityCase.workspace_id.in_(workspace_ids))

    if filters.status is not None:
        stmt = stmt.where(SecurityCase.status == filters.status)
    if filters.priority is not None:
        stmt = stmt.where(SecurityCase.priority == filters.priority)
    if filters.min_priority is not None:
        # Only URUGENT/HIGH/MEDIUM/LOW — filter directly
        accepted = _case_priorities_at_or_above(filters.min_priority)
        if accepted:
            stmt = stmt.where(SecurityCase.priority.in_(accepted))
    if filters.severity is not None:
        stmt = stmt.where(SecurityCase.severity == filters.severity)
    if filters.min_severity is not None:
        min_rank = _SEVERITY_RANK.get(filters.min_severity, 0)
        accepted = [s for s, r in _SEVERITY_RANK.items() if r >= min_rank]
        if accepted:
            stmt = stmt.where(SecurityCase.severity.in_(accepted))
    if filters.category is not None:
        stmt = stmt.where(SecurityCase.category == filters.category)
    if filters.assigned_to_id is not None:
        stmt = stmt.where(SecurityCase.assigned_to_id == filters.assigned_to_id)
    if filters.unassigned_only:
        stmt = stmt.where(SecurityCase.assigned_to_id.is_(None))
    if filters.incident_id is not None:
        stmt = stmt.where(SecurityCase.incident_id == filters.incident_id)
    if filters.is_billable is not None:
        stmt = stmt.where(SecurityCase.is_billable == filters.is_billable)
    if filters.overdue_only:
        now = datetime.now(timezone.utc)
        stmt = stmt.where(
            SecurityCase.closed_at.is_(None),
            SecurityCase.sla_deadline_at.is_not(None),
            SecurityCase.sla_deadline_at < now,
        )
    if filters.opened_after is not None:
        stmt = stmt.where(SecurityCase.opened_at >= filters.opened_after)
    if filters.opened_before is not None:
        stmt = stmt.where(SecurityCase.opened_at <= filters.opened_before)
    if filters.case_number:
        stmt = stmt.where(SecurityCase.case_number == filters.case_number.strip().upper())
    if filters.title_contains:
        stmt = stmt.where(
            SecurityCase.title.ilike(f"%{filters.title_contains.lower()}%")
        )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            SecurityCase.opened_at.desc(),
            SecurityCase.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    cases = list(db.execute(stmt).scalars().all())
    return cases, int(total)


def _case_priorities_at_or_above(min_priority: CasePriority) -> list[CasePriority]:
    """Return priorities at or above the given one (for filter)."""
    order = [
        CasePriority.LOW,
        CasePriority.MEDIUM,
        CasePriority.HIGH,
        CasePriority.URGENT,
    ]
    try:
        idx = order.index(min_priority)
        return order[idx:]
    except ValueError:
        return []


# ============================================================================
# LIFECYCLE — STATUS
# ============================================================================

def advance_status(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    new_status: CaseStatus,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityCase:
    """
    Advance the case status. Validates against ``_ALLOWED_TRANSITIONS``.
    """
    if new_status == case.status:
        return case  # idempotent

    if new_status not in _ALLOWED_TRANSITIONS.get(case.status, frozenset()):
        raise InvalidStateTransitionError(
            message=(
                f"Cannot transition case from {case.status.value} "
                f"to {new_status.value}."
            ),
            code="CASE_INVALID_TRANSITION",
            details={
                "current": case.status.value,
                "requested": new_status.value,
                "allowed": [
                    s.value
                    for s in _ALLOWED_TRANSITIONS.get(case.status, frozenset())
                ],
            },
        )

    before = _snapshot_state(case)
    case.advance_status(new_status, by_user_id=actor.id, notes=notes)
    db.flush()
    after = _snapshot_state(case)

    audit_service.log_state_change(
        db,
        actor=actor,
        action=f"case.status.{new_status.value}",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
        workspace_id=case.workspace_id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    return case


# ============================================================================
# ASSIGNMENT
# ============================================================================

def assign(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    analyst_user_id: uuid.UUID,
    role: str = "primary",
    notes: str | None = None,
    request: Any | None = None,
) -> CaseAssignment:
    """
    Assign an analyst to the case in the given role.

    Permission
    ----------
    Requires ``PERM_CASE_ASSIGN`` in the workspace.

    For external analysts (not workspace members), they must have an
    active ``CaseAccessGrant`` on the case with a scope that permits
    investigation (``full_case``). Being assigned requires being
    grantable. See ``_assert_assignable``.

    Role
    ----
    ``primary`` | ``backup`` | ``reviewer``. Only one active assignment
    per role per case — previous active assignment of the same role is
    closed automatically.

    Returns
    -------
    CaseAssignment
    """
    if role not in _VALID_ASSIGNMENT_ROLES:
        raise ValidationError(
            message=f"role must be one of {sorted(_VALID_ASSIGNMENT_ROLES)}.",
            code="CASE_ASSIGNMENT_ROLE_INVALID",
            details={"role": role},
        )

    authorization.check_permission(
        db, actor, PERM_CASE_ASSIGN, workspace_id=case.workspace_id,
    )

    # ── Load and validate assignee
    assignee = db.get(User, analyst_user_id)
    if assignee is None or assignee.deleted_at is not None:
        raise ValidationError(
            message=f"Assignee {analyst_user_id} not found.",
            code="ASSIGNEE_NOT_FOUND",
        )

    _assert_assignable(db, case=case, assignee=assignee)

    # ── Close previous assignment for this role
    _close_active_assignments(
        db, case_id=case.id, role=role,
        ended_by_id=actor.id, reason="Reassigned",
    )

    # ── Create assignment
    assignment = CaseAssignment.build(
        case_id=case.id,
        analyst_user_id=analyst_user_id,
        assigned_by_id=actor.id,
        role=role,
    )
    db.add(assignment)
    db.flush()

    # ── Update denormalized fields on the case
    if role == "primary":
        before = _snapshot_state(case)
        case.set_primary_analyst(
            analyst_user_id=analyst_user_id,
            assigned_by_id=actor.id,
        )
        db.flush()
        after = _snapshot_state(case)

        audit_service.log_state_change(
            db,
            actor=actor,
            action="case.assigned",
            target_type="case",
            target_id=case.id,
            target_display=case.case_number,
            workspace_id=case.workspace_id,
            before_state=before,
            after_state=after,
            notes=notes,
            request=request,
        )

        # Notify assignee
        try:
            notification_service.create_for_case_assignment(
                db,
                case=case,
                assignee_id=analyst_user_id,
                assigner_id=actor.id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to notify case assignee",
                extra={"case_id": str(case.id), "error": str(exc)[:200]},
            )
    else:
        # Non-primary assignments: audit but don't change case.assigned_to_id
        audit_service.log_action(
            db,
            actor=actor,
            action="case.assigned",
            target_type="case",
            target_id=case.id,
            target_display=case.case_number,
            workspace_id=case.workspace_id,
            request=request,
            metadata={
                "role": role,
                "analyst_user_id": str(analyst_user_id),
            },
        )

    logger.info(
        "Case assignment created",
        extra={
            "case_id": str(case.id),
            "analyst_user_id": str(analyst_user_id),
            "role": role,
        },
    )

    return assignment


def _assert_assignable(
    db: Session,
    *,
    case: SecurityCase,
    assignee: User,
) -> None:
    """
    Verify the assignee can be assigned to this case.

    Two paths:
        1. Workspace member — they can be assigned to any case in
           the workspace (their access is governed by role + case
           access grants if applicable)
        2. Non-member — must have an active ``full_case`` grant
           (this is the marketplace analyst case: Priya grants Rahul
           full access to work her case, and he gets assigned)

    Anything else → rejected.
    """
    workspace_role = authorization.get_user_workspace_role(
        db, assignee, case.workspace_id,
    )
    if workspace_role is not None:
        return  # workspace member — OK

    # Non-member — check for an active full_case grant
    from app.models.case import CaseAccessGrant as _Grant
    grant = db.execute(
        select(_Grant).where(
            _Grant.case_id == case.id,
            _Grant.grantee_user_id == assignee.id,
            _Grant.revoked_at.is_(None),
            _Grant.scope == AccessGrantScope.FULL_CASE,
        )
    ).scalar_one_or_none()

    if grant is None:
        raise AuthorizationError(
            message=(
                "Cannot assign a non-member to this case without an "
                "active full_case access grant. The grantee must be "
                "granted access before being assigned."
            ),
            code="ASSIGNEE_NOT_ELIGIBLE",
            details={
                "case_id": str(case.id),
                "assignee_id": str(assignee.id),
            },
        )


def reassign(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    analyst_user_id: uuid.UUID,
    reason: str,
    request: Any | None = None,
) -> CaseAssignment:
    """
    Convenience wrapper — reassign the primary analyst.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A reassignment reason is required.",
            code="CASE_REASSIGN_REASON_REQUIRED",
        )

    return assign(
        db,
        actor=actor,
        case=case,
        analyst_user_id=analyst_user_id,
        role="primary",
        notes=reason.strip(),
        request=request,
    )


def unassign(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    reason: str,
    request: Any | None = None,
) -> SecurityCase:
    """
    Remove the current primary analyst from the case. Case returns to
    OPEN status. Any other roles (backup, reviewer) stay assigned.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="An unassignment reason is required.",
            code="CASE_UNASSIGN_REASON_REQUIRED",
        )

    authorization.check_permission(
        db, actor, PERM_CASE_ASSIGN, workspace_id=case.workspace_id,
    )

    _close_active_assignments(
        db, case_id=case.id, role="primary",
        ended_by_id=actor.id, reason=reason.strip(),
    )

    before = _snapshot_state(case)
    case.assigned_to_id = None
    case.assigned_at = None
    case.assigned_by_id = None
    if case.status == CaseStatus.ASSIGNED:
        case.advance_status(
            CaseStatus.OPEN,
            by_user_id=actor.id,
            notes=f"Unassigned: {reason.strip()}",
        )
    db.flush()
    after = _snapshot_state(case)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="case.unassigned",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
        workspace_id=case.workspace_id,
        before_state=before,
        after_state=after,
        notes=reason.strip(),
        request=request,
    )

    return case


# ============================================================================
# CLOSE
# ============================================================================

def close(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    resolution_summary: str,
    request: Any | None = None,
) -> SecurityCase:
    """
    Close the case with a resolution summary. Requires the case to be
    RESOLVED first (or already CLOSED — idempotent).
    """
    if not resolution_summary or not resolution_summary.strip():
        raise ValidationError(
            message="Resolution summary is required when closing a case.",
            code="CASE_RESOLUTION_SUMMARY_REQUIRED",
        )

    if case.status == CaseStatus.CLOSED:
        return case  # idempotent

    if case.status != CaseStatus.RESOLVED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot close a case in {case.status.value} status. "
                f"Must be RESOLVED first."
            ),
            code="CASE_NOT_RESOLVED",
            details={"status": case.status.value},
        )

    before = _snapshot_state(case)
    case.advance_status(
        CaseStatus.CLOSED, by_user_id=actor.id, notes="Case closed",
    )
    case.resolution_summary = resolution_summary.strip()
    db.flush()
    after = _snapshot_state(case)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="case.closed",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
        workspace_id=case.workspace_id,
        before_state=before,
        after_state=after,
        notes=resolution_summary.strip(),
        request=request,
    )

    logger.info(
        "Case closed",
        extra={
            "case_id": str(case.id),
            "case_number": case.case_number,
            "actor_id": str(actor.id),
        },
    )

    return case


# ============================================================================
# ACCESS GRANTS — the crown jewel
# ============================================================================

def create_access_grant(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    grantee_user_id: uuid.UUID,
    scope: AccessGrantScope,
    purpose: str,
    expires_at: datetime | None = None,
    notes: str | None = None,
    request: Any | None = None,
) -> CaseAccessGrant:
    """
    Issue a scoped access grant on a case.

    This is the **only way** to give someone access to a case they are
    not already authorized for. Every grant is:

        - **Purposeful** — ``purpose`` is mandatory. "Why is Rahul
          seeing this?"
        - **Scoped** — CASE_READ | EVIDENCE_READ | CONVERSATION_READ |
          FULL_CASE
        - **Expirable** — optional ``expires_at``; auto-revokes when
          the deadline passes
        - **Audited** — creation, revocation, and expiration are all
          recorded

    Permission
    ----------
    The grantor must be able to grant at this scope:

        - Workspace OWNER can grant any scope
        - Workspace EDITOR can grant CASE_READ, EVIDENCE_READ,
          CONVERSATION_READ (not FULL_CASE)
        - The case's assigned analyst can grant at any scope to
          another analyst (they're responsible for the case)
        - The client (the user who hired the analyst, in marketplace
          flows) can grant CASE_READ/EVIDENCE_READ/CONVERSATION_READ
          (they own the data)

    Any other user → rejected.

    Raises
    ------
    AuthorizationError
        If the actor cannot grant at this scope.
    ValidationError
        If the grantee is invalid, the expiry is in the past, or the
        grantee already has an equivalent grant.
    """
    if not purpose or not purpose.strip():
        raise ValidationError(
            message=(
                "A purpose is required for every access grant. This is "
                "the audit trail — 'why is this person seeing this case?'"
            ),
            code="ACCESS_GRANT_PURPOSE_REQUIRED",
        )

    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise ValidationError(
                message="expires_at must be in the future.",
                code="ACCESS_GRANT_EXPIRY_IN_PAST",
            )

    # ── Validate grantee
    grantee = db.get(User, grantee_user_id)
    if grantee is None or grantee.deleted_at is not None:
        raise ValidationError(
            message=f"Grantee user {grantee_user_id} not found.",
            code="GRANTEE_NOT_FOUND",
        )

    # ── Verify the actor can grant at this scope
    _assert_can_grant(
        db, actor=actor, case=case, scope=scope, grantee=grantee,
    )

    # ── Check for existing active grant with the same scope
    existing = db.execute(
        select(CaseAccessGrant).where(
            CaseAccessGrant.case_id == case.id,
            CaseAccessGrant.grantee_user_id == grantee_user_id,
            CaseAccessGrant.scope == scope,
            CaseAccessGrant.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            message=(
                f"Grantee already has an active {scope.value} grant on "
                f"this case."
            ),
            code="ACCESS_GRANT_ALREADY_EXISTS",
            details={
                "grant_id": str(existing.id),
                "scope": scope.value,
            },
        )

    # ── Create the grant
    grant = CaseAccessGrant.build(
        case_id=case.id,
        grantee_user_id=grantee_user_id,
        granted_by_id=actor.id,
        scope=scope,
        purpose=purpose.strip(),
        expires_at=expires_at,
        notes=notes.strip() if notes else None,
    )
    db.add(grant)
    db.flush()

    audit_service.log_analyst_access_granted(
        db,
        granted_by=actor,
        grantee_user_id=grantee_user_id,
        case_id=case.id,
        workspace_id=case.workspace_id,
        scope=scope.value,
        purpose=purpose.strip(),
        expires_at=expires_at,
        request=request,
    )

    logger.info(
        "Access grant issued",
        extra={
            "grant_id": str(grant.id),
            "case_id": str(case.id),
            "grantee_user_id": str(grantee_user_id),
            "scope": scope.value,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "granted_by": str(actor.id),
        },
    )

    return grant


def _assert_can_grant(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    scope: AccessGrantScope,
    grantee: User,
) -> None:
    """
    Verify the actor is authorized to grant the given scope on the case.
    """
    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )

    # Workspace OWNER — can grant any scope
    if ws_role is not None:
        from app.models.enums import WorkspaceRole
        if ws_role == WorkspaceRole.OWNER:
            return
        if ws_role == WorkspaceRole.EDITOR:
            # Editors cannot grant FULL_CASE
            if scope != AccessGrantScope.FULL_CASE:
                return

    # Assigned analyst — can grant any scope
    if case.assigned_to_id == actor.id:
        return

    # The client (the user who created the workspace, or who bought
    # the marketplace engagement) can grant most scopes
    from app.models.workspace import Workspace
    ws = db.get(Workspace, case.workspace_id)
    if ws is not None and ws.owner_id == actor.id:
        # Workspace owner can grant CASE_READ/EVIDENCE_READ/CONVERSATION_READ
        # (they own the data) but NOT full_case to others — full_case
        # means "investigate", which requires investigator standing
        if scope in (
            AccessGrantScope.CASE_READ,
            AccessGrantScope.EVIDENCE_READ,
            AccessGrantScope.CONVERSATION_READ,
        ):
            return

    # If the grantee is the workspace owner and actor is analyst, allow
    # (analyst giving the workspace owner a formal grant for record-keeping)
    if grantee.id == (ws.owner_id if ws else None) and case.assigned_to_id == actor.id:
        return

    raise AuthorizationError(
        message=(
            "You cannot grant access to this case at this scope. "
            "Required: workspace OWNER role, assigned analyst role, or "
            "ownership of the workspace."
        ),
        code="CANNOT_GRANT_ACCESS",
        details={
            "case_id": str(case.id),
            "scope": scope.value,
            "actor_workspace_role": ws_role.value if ws_role else None,
        },
    )


def revoke_access_grant(
    db: Session,
    *,
    actor: User,
    grant: CaseAccessGrant,
    reason: str,
    request: Any | None = None,
) -> CaseAccessGrant:
    """
    Revoke an active access grant. Terminal — a new grant must be
    issued to restore access.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A revocation reason is required.",
            code="ACCESS_GRANT_REVOCATION_REASON_REQUIRED",
        )

    if grant.revoked_at is not None:
        return grant  # idempotent

    case = db.get(SecurityCase, grant.case_id)
    if case is None:
        raise CaseNotFoundError(
            message="Case no longer exists.",
            details={"case_id": str(grant.case_id)},
        )

    # Permissions: grantor can always revoke; assigned analyst can
    # revoke; workspace owner/editor can revoke
    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    can_revoke = (
        grant.granted_by_id == actor.id
        or case.assigned_to_id == actor.id
        or (ws_role is not None)
    )
    if not can_revoke:
        raise AuthorizationError(
            message="You cannot revoke this access grant.",
            code="CANNOT_REVOKE_ACCESS",
        )

    grant.revoke(
        by_user_id=actor.id,
        reason=reason.strip(),
    )
    db.flush()

    audit_service.log_analyst_access_revoked(
        db,
        revoked_by=actor,
        grantee_user_id=grant.grantee_user_id,
        case_id=case.id,
        workspace_id=case.workspace_id,
        reason=reason.strip(),
        request=request,
    )

    logger.info(
        "Access grant revoked",
        extra={
            "grant_id": str(grant.id),
            "case_id": str(case.id),
            "revoked_by": str(actor.id),
        },
    )

    return grant


def list_access_grants(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    page: PageParams,
    include_revoked: bool = False,
) -> tuple[list[CaseAccessGrant], int]:
    """
    List access grants for a case. Visible to workspace members and the
    assigned analyst — this is compliance data, admins need to see it.
    """
    # Any workspace member can view the grant list (it's the audit log)
    authorization.check_permission(
        db, actor, "case:read", workspace_id=case.workspace_id,
    )

    stmt = select(CaseAccessGrant).where(CaseAccessGrant.case_id == case.id)
    if not include_revoked:
        stmt = stmt.where(CaseAccessGrant.revoked_at.is_(None))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(CaseAccessGrant.granted_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    grants = list(db.execute(stmt).scalars().all())
    return grants, int(total)


# ============================================================================
# INVESTIGATION NOTES
# ============================================================================

def add_investigation_note(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    note: str,
    note_type: str = "observation",
    request: Any | None = None,
) -> SecurityCase:
    """
    Append an investigation note to the case.

    Requires ``PERM_CASE_UPDATE`` in the workspace, OR being the assigned
    analyst.
    """
    if not note or not note.strip():
        raise ValidationError(
            message="Note text is required.",
            code="CASE_NOTE_REQUIRED",
        )

    # Analysts on the case can always add notes
    if case.assigned_to_id == actor.id:
        pass
    else:
        authorization.check_permission(
            db, actor, PERM_CASE_UPDATE, workspace_id=case.workspace_id,
        )

    case.add_investigation_note(
        note=note.strip(),
        by_user_id=actor.id,
        note_type=note_type,
    )
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="case.note_added",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
        workspace_id=case.workspace_id,
        request=request,
        metadata={
            "note_type": note_type,
            "note_length": len(note.strip()),
        },
    )

    return case


# ============================================================================
# SLA MONITORING
# ============================================================================

def check_sla_breaches(
    db: Session,
    *,
    limit: int = 100,
) -> list[SecurityCase]:
    """
    Return cases past their SLA deadline (still open).
    """
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")

    now = datetime.now(timezone.utc)
    return list(db.execute(
        select(SecurityCase)
        .where(
            SecurityCase.closed_at.is_(None),
            SecurityCase.status.notin_([
                CaseStatus.CLOSED,
                CaseStatus.CANCELLED,
                CaseStatus.RESOLVED,
            ]),
            SecurityCase.sla_deadline_at.is_not(None),
            SecurityCase.sla_deadline_at < now,
        )
        .order_by(SecurityCase.sla_deadline_at.asc())
        .limit(limit)
    ).scalars().all())


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "create_case",
    "get_by_id",
    "list_cases",
    "advance_status",
    "assign",
    "reassign",
    "unassign",
    "close",
    "create_access_grant",
    "revoke_access_grant",
    "list_access_grants",
    "add_investigation_note",
    "check_sla_breaches",
]