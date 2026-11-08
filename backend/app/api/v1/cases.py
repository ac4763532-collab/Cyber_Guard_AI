"""
CyberGuard AI — Case Endpoints
============================================================================

Case workflow + access grants. The most security-critical router in the
platform — this is where the handover's core rule becomes an API:

    "An organization administrator should not automatically gain access
     to all client evidence. Sensitive access must be explicitly granted
     and audited."

Every access grant endpoint:
    - Requires a mandatory `purpose` string (why is this person seeing it?)
    - Accepts an optional `expires_at` (auto-revoke deadline)
    - Is audited (grant + revocation both write audit rows)
    - Cannot be edited — only revoked and re-issued

Thirteen endpoints across the case workflow:

    GET    /cases                              — list with filters
    GET    /cases/{id}                         — detail
    POST   /cases                              — create (admin/agent)
    PATCH  /cases/{id}                         — update fields
    PATCH  /cases/{id}/status                  — advance status
    PATCH  /cases/{id}/assign                  — assign primary analyst
    POST   /cases/{id}/unassign                — unassign primary
    POST   /cases/{id}/close                   — close (requires summary)
    POST   /cases/{id}/notes                   — add investigation note
    GET    /cases/{id}/assignments             — assignment history
    GET    /cases/{id}/access-grants           — grant list (compliance view)
    POST   /cases/{id}/access-grants           — create scoped grant
    POST   /cases/{id}/access-grants/{gid}/revoke  — revoke grant

Case access foundation
----------------------
Every endpoint requires case access via one of:
    - Assigned analyst (implicit FULL_CASE)
    - Workspace/org role with adequate permissions
    - Active CaseAccessGrant with adequate scope

The specific minimum scope varies per endpoint:
    - Read case metadata → CASE_READ
    - List assignments → CASE_READ
    - List access grants → CASE_READ (compliance requirement)
    - Update case → FULL_CASE (or workspace role)
    - Assign analyst → FULL_CASE (or workspace role)
    - Create/revoke access grant → role-based (see service)
    - Add investigation note → FULL_CASE (or workspace role)
    - Close case → FULL_CASE (or workspace role)
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Body, Depends, Query, status
from sqlalchemy import select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import (
    CaseNotFoundError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.case import (
    CaseAccessGrant,
    CaseAssignment,
)
from app.models.enums import AccessGrantScope
from app.schemas.case import (
    CaseAccessGrantCreate,
    CaseAccessGrantRead,
    CaseAccessGrantRevokeRequest,
    CaseAssignmentCreate,
    CaseAssignmentRead,
    CaseCreate,
    CaseFilter,
    CaseInvestigationNoteCreate,
    CaseList,
    CaseRead,
    CaseStatusUpdate,
    CaseUpdate,
)
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.services import (
    authorization,
    case_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/cases",
    tags=["cases"],
)


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[CaseList],
    summary="List cases",
    description=(
        "Paginated list of cases across the user's accessible workspaces. "
        "Requires `case:read` permission on the workspace.\n\n"
        "Returns lightweight `CaseList` rows. Fetch `GET /cases/{id}` "
        "for the full case including `status_history` and "
        "`investigation_notes`."
    ),
)
def list_cases(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: CaseFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[CaseList]:
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "case:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            return PaginatedResponse[CaseList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    cases, total = case_service.list_cases(
        db,
        workspace_ids=workspace_ids,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[CaseList](
        items=[CaseList.model_validate(c) for c in cases],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{case_id}",
    response_model=CaseRead,
    summary="Get a case by ID",
    description=(
        "Full case view including `status_history`, "
        "`investigation_notes`, and the current primary analyst. Requires "
        "`CASE_READ` scope (satisfied by being the assigned analyst, a "
        "workspace member with the role, or having an active access "
        "grant with CASE_READ scope or above)."
    ),
)
def get_case(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.CASE_READ,
    )
    return CaseRead.model_validate(case)


# ============================================================================
# CREATE
# ============================================================================

@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a case",
    description=(
        "Admin/agent-initiated case creation. The primary creation path "
        "is via `incident_response_agent` or `marketplace_service` — this "
        "endpoint is for admin override and testing.\n\n"
        "Requires `case:update` permission (workspace EDITOR or above). "
        "A `case_number` (CG-YYYY-NNNNNN) is generated automatically. "
        "Default conversations (client, internal, system) are created.\n\n"
        "If `incident_id` is provided, the case aggregates that incident "
        "and is visible to the incident's watchers. If omitted, the case "
        "is a standalone proactive case — the caller must supply "
        "`workspace_id` via `linked_engagement_id` or an extended DTO."
    ),
)
def create_case(
    body: CaseCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
    workspace_id: uuid.UUID = Query(
        ...,
        description=(
            "The workspace this case belongs to. Required for standalone "
            "cases (no `incident_id`). If `incident_id` is set, this must "
            "match the incident's workspace (validated server-side)."
        ),
    ),
) -> CaseRead:
    # Permission check on the workspace
    authorization.check_permission(
        db, current_user, "case:update", workspace_id=workspace_id,
    )

    # The service builds from a CaseCreate DTO. We pass workspace context
    # via a workaround — if incident_id is present, the service fetches
    # the incident and uses its workspace. If not, we inject a synthetic
    # workspace_id into the DTO context. Note: CaseCreate schema doesn't
    # carry workspace_id directly (it comes from the incident) — so we
    # validate the incident here when present.
    if body.incident_id is not None:
        from app.models.incident import SecurityIncident
        incident = db.get(SecurityIncident, body.incident_id)
        if incident is None:
            raise NotFoundError(
                message=f"Incident {body.incident_id} not found.",
                code="INCIDENT_NOT_FOUND",
            )
        if incident.workspace_id != workspace_id:
            raise ValidationError(
                message=(
                    "workspace_id query parameter does not match the "
                    "incident's workspace."
                ),
                code="CASE_WORKSPACE_MISMATCH",
            )

    case = case_service.create_case(
        db, dto=body, actor=current_user,
    )
    db.commit()

    logger.info(
        "Case created via API",
        extra={
            "case_id": str(case.id),
            "case_number": case.case_number,
            "workspace_id": str(workspace_id),
            "actor_id": str(current_user.id),
        },
    )

    return CaseRead.model_validate(case)


# ============================================================================
# UPDATE
# ============================================================================

@router.patch(
    "/{case_id}",
    response_model=CaseRead,
    summary="Update a case",
    description=(
        "Update mutable fields (title, description, priority, severity, "
        "category, summary, resolution_summary, tags). Requires "
        "`FULL_CASE` scope (assigned analyst or full-case grant) or "
        "workspace EDITOR role."
    ),
)
def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    updates = body.model_dump(exclude_unset=True)
    if updates:
        for field, value in updates.items():
            setattr(case, field, value)
        db.flush()

    db.commit()
    return CaseRead.model_validate(case)


# ============================================================================
# STATUS TRANSITION
# ============================================================================

@router.patch(
    "/{case_id}/status",
    response_model=CaseRead,
    summary="Advance a case's status",
    description=(
        "Transitions the case to a new status. The case state machine "
        "is looser than incidents — cases can reopen from RESOLVED or "
        "CLOSED to INVESTIGATING. Every transition is audited."
    ),
)
def advance_case_status(
    case_id: uuid.UUID,
    body: CaseStatusUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    updated = case_service.advance_status(
        db,
        actor=current_user,
        case=case,
        new_status=body.status,
        notes=body.notes,
    )
    db.commit()
    return CaseRead.model_validate(updated)


# ============================================================================
# ASSIGNMENT
# ============================================================================

@router.patch(
    "/{case_id}/assign",
    response_model=CaseAssignmentRead,
    summary="Assign a primary analyst to a case",
    description=(
        "Assigns or reassigns the primary analyst. The new assignee "
        "must be either a workspace member or a non-member with an "
        "active `full_case` grant on this case (the marketplace analyst "
        "case).\n\n"
        "Any existing primary assignment is closed with reason "
        "'Reassigned'. The assignee is notified.\n\n"
        "Requires `case:assign` permission."
    ),
)
def assign_case(
    case_id: uuid.UUID,
    body: CaseAssignmentCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseAssignmentRead:
    case = case_service.get_by_id(db, case_id)

    assignment = case_service.assign(
        db,
        actor=current_user,
        case=case,
        analyst_user_id=body.analyst_user_id,
        role=body.role,
        notes=body.notes,
    )
    db.commit()
    return CaseAssignmentRead.model_validate(assignment)


@router.post(
    "/{case_id}/unassign",
    response_model=CaseRead,
    summary="Unassign the primary analyst",
    description=(
        "Ends the current primary assignment. The case returns to OPEN "
        "status (if it was ASSIGNED). Backup and reviewer assignments "
        "are unaffected. Requires `case:assign` permission."
    ),
)
def unassign_case(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    updated = case_service.unassign(
        db,
        actor=current_user,
        case=case,
        reason=reason,
    )
    db.commit()
    return CaseRead.model_validate(updated)


@router.get(
    "/{case_id}/assignments",
    response_model=list[CaseAssignmentRead],
    summary="List all assignments for a case",
    description=(
        "Returns the full assignment history for the case, including "
        "closed assignments. Requires `CASE_READ` scope."
    ),
)
def list_case_assignments(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> list[CaseAssignmentRead]:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.CASE_READ,
    )

    assignments = list(db.execute(
        select(CaseAssignment)
        .where(CaseAssignment.case_id == case.id)
        .order_by(CaseAssignment.assigned_at.desc())
    ).scalars().all())

    return [CaseAssignmentRead.model_validate(a) for a in assignments]


# ============================================================================
# CLOSE
# ============================================================================

@router.post(
    "/{case_id}/close",
    response_model=CaseRead,
    summary="Close a resolved case",
    description=(
        "Finalizes the case. `resolution_summary` is **required** — "
        "enforced at schema level (min_length=1). The case must be in "
        "RESOLVED status. Requires `FULL_CASE` scope."
    ),
)
def close_case(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    resolution_summary: str = Body(
        embed=True, min_length=1, max_length=10000,
    ),
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    updated = case_service.close(
        db,
        actor=current_user,
        case=case,
        resolution_summary=resolution_summary,
    )
    db.commit()
    return CaseRead.model_validate(updated)


# ============================================================================
# INVESTIGATION NOTES
# ============================================================================

@router.post(
    "/{case_id}/notes",
    response_model=CaseRead,
    summary="Add an investigation note",
    description=(
        "Appends a note to the case's investigation log. Notes are "
        "append-only — there is no update or delete. The `note_type` "
        "categorizes the note (observation / action / communication / "
        "finding).\n\n"
        "Requires `FULL_CASE` scope (or being the assigned analyst)."
    ),
)
def add_investigation_note(
    case_id: uuid.UUID,
    body: CaseInvestigationNoteCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseRead:
    case = case_service.get_by_id(db, case_id)
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    updated = case_service.add_investigation_note(
        db,
        actor=current_user,
        case=case,
        note=body.note,
        note_type=body.note_type,
    )
    db.commit()
    return CaseRead.model_validate(updated)


# ============================================================================
# ACCESS GRANTS — the crown jewel
# ============================================================================

@router.get(
    "/{case_id}/access-grants",
    response_model=PaginatedResponse[CaseAccessGrantRead],
    summary="List access grants for a case",
    description=(
        "Returns all grants (active + revoked) unless `include_revoked="
        "false`. This is compliance data — every case participant can "
        "see who has been granted access and why. Requires `CASE_READ`."
    ),
)
def list_access_grants(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_revoked: bool = Query(default=False),
) -> PaginatedResponse[CaseAccessGrantRead]:
    case = case_service.get_by_id(db, case_id)

    grants, total = case_service.list_access_grants(
        db,
        actor=current_user,
        case=case,
        page=page,
        include_revoked=include_revoked,
    )

    return PaginatedResponse[CaseAccessGrantRead](
        items=[CaseAccessGrantRead.model_validate(g) for g in grants],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{case_id}/access-grants",
    response_model=CaseAccessGrantRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scoped access grant",
    description=(
        "Issues a scoped access grant on the case for a specific user. "
        "This is **the only way** to give someone access to a case they "
        "are not already authorized for.\n\n"
        "**Every grant requires:**\n"
        "- A `purpose` (mandatory) — why is this person seeing this?\n"
        "- A `scope` (defaults to `case_read` — least privilege)\n"
        "- An optional `expires_at` (recommended for marketplace work)\n\n"
        "Grants cannot be edited — only revoked and re-issued. Every "
        "grant is audited (`analyst.access.granted`).\n\n"
        "**Granting authority** (enforced by the service):\n"
        "- Workspace OWNER → any scope\n"
        "- Workspace EDITOR → any scope except `full_case`\n"
        "- Assigned analyst → any scope\n"
        "- Workspace owner (client) → read scopes only"
    ),
    responses={
        201: {"description": "Grant created."},
        400: {"description": "Invalid input (missing purpose, past expiry)."},
        403: {"description": "Actor cannot grant at this scope."},
        404: {"description": "Case or grantee not found."},
        409: {"description": "Grantee already has an active grant at this scope."},
    },
)
def create_access_grant(
    case_id: uuid.UUID,
    body: CaseAccessGrantCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseAccessGrantRead:
    case = case_service.get_by_id(db, case_id)

    grant = case_service.create_access_grant(
        db,
        actor=current_user,
        case=case,
        grantee_user_id=body.grantee_user_id,
        scope=body.scope,
        purpose=body.purpose,
        expires_at=body.expires_at,
        notes=body.notes,
    )
    db.commit()

    logger.info(
        "Access grant created via API",
        extra={
            "grant_id": str(grant.id),
            "case_id": str(case.id),
            "grantee_user_id": str(body.grantee_user_id),
            "scope": body.scope.value if hasattr(body.scope, "value") else str(body.scope),
            "actor_id": str(current_user.id),
        },
    )

    return CaseAccessGrantRead.model_validate(grant)


@router.post(
    "/{case_id}/access-grants/{grant_id}/revoke",
    response_model=CaseAccessGrantRead,
    summary="Revoke an access grant",
    description=(
        "Revokes an active access grant. **Terminal** — a revoked grant "
        "cannot be reactivated. To restore access, create a new grant "
        "(which appears as a new audit event, no retroactive fixes).\n\n"
        "Requires the grant's issuer, the case's assigned analyst, or "
        "workspace membership."
    ),
)
def revoke_access_grant(
    case_id: uuid.UUID,
    grant_id: uuid.UUID,
    body: CaseAccessGrantRevokeRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> CaseAccessGrantRead:
    # Load the grant, verifying it belongs to this case
    grant = db.get(CaseAccessGrant, grant_id)
    if grant is None or grant.case_id != case_id:
        raise NotFoundError(
            message="Access grant not found.",
            code="ACCESS_GRANT_NOT_FOUND",
        )

    revoked = case_service.revoke_access_grant(
        db,
        actor=current_user,
        grant=grant,
        reason=body.reason,
    )
    db.commit()

    logger.info(
        "Access grant revoked via API",
        extra={
            "grant_id": str(revoked.id),
            "case_id": str(case_id),
            "actor_id": str(current_user.id),
        },
    )

    return CaseAccessGrantRead.model_validate(revoked)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]