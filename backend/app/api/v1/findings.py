"""
CyberGuard AI — Finding Endpoints
============================================================================

Query and lifecycle endpoints for agent findings.

Findings aren't ingested via HTTP — they're produced by the 8 detection
agents (Phase I). The API surface here is:

    GET   /findings              — list (workspace-scoped)
    GET   /findings/{id}         — detail with evidence
    PATCH /findings/{id}/status  — transition status

Permission model
----------------
Every endpoint requires ``finding:read`` on the finding's workspace.
Status transitions additionally require ``finding:read`` on the same
workspace — any workspace member who can see a finding can advance its
status (analysts triage findings, admins can override).

If you later need to restrict status changes to analysts only, that's
a permission change in `authorization.py`'s role matrix — no code
change here.

Status transitions
------------------
The finding state machine is validated by
``finding_service.advance_status``. The router just calls it and
returns the updated DTO:

    NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
                                      → DISMISSED
                                      → FALSE_POSITIVE

Terminal statuses (RESOLVED, DISMISSED, FALSE_POSITIVE) cannot
transition further.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import (
    AuthorizationError,
    FindingNotFoundError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.models.finding import AgentFinding
from app.schemas.common import (
    PageMeta,
    PaginatedResponse,
)
from app.schemas.finding import (
    FindingFilter,
    FindingList,
    FindingRead,
    FindingStatusUpdate,
)
from app.services import (
    authorization,
    finding_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/findings",
    tags=["findings"],
)


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[FindingList],
    summary="List findings",
    description=(
        "Paginated list of findings across the user's accessible "
        "workspaces. Requires `finding:read` permission.\n\n"
        "Returns lightweight `FindingList` rows (no `evidence`, no "
        "`event_ids`). Fetch `GET /findings/{id}` for full details.\n\n"
        "Findings are deduplicated by fingerprint — a rule that fires "
        "repeatedly produces one row with `occurrence_count > 1`, not "
        "multiple rows."
    ),
)
def list_findings(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: FindingFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[FindingList]:
    # ── Scope resolution
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "finding:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            return PaginatedResponse[FindingList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    # ── Query via the service
    findings, total = finding_service.list_findings(
        db,
        workspace_ids=workspace_ids,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[FindingList](
        items=[FindingList.model_validate(f) for f in findings],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Get a finding by ID",
    description=(
        "Returns the full finding including `evidence`, `event_ids`, "
        "and `mitre_techniques`. Requires `finding:read` on the "
        "finding's workspace."
    ),
)
def get_finding(
    finding_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> FindingRead:
    finding = finding_service.get_by_id(db, finding_id)

    authorization.check_permission(
        db, current_user, "finding:read",
        workspace_id=finding.workspace_id,
    )

    return FindingRead.model_validate(finding)


# ============================================================================
# STATUS TRANSITION
# ============================================================================

@router.patch(
    "/{finding_id}/status",
    response_model=FindingRead,
    summary="Advance a finding's status",
    description=(
        "Transitions the finding to a new status. The transition must "
        "be valid per the state machine:\n\n"
        "- `NEW` → `ACKNOWLEDGED`, `DISMISSED`, `FALSE_POSITIVE`\n"
        "- `ACKNOWLEDGED` → `INVESTIGATING`, `RESOLVED`, `DISMISSED`, `FALSE_POSITIVE`\n"
        "- `INVESTIGATING` → `RESOLVED`, `DISMISSED`, `FALSE_POSITIVE`\n"
        "- Terminal: `RESOLVED`, `DISMISSED`, `FALSE_POSITIVE`\n\n"
        "Every transition is audited (who, when, why). Returns the "
        "updated finding."
    ),
    responses={
        200: {"description": "Finding updated."},
        403: {"description": "Permission denied (finding:read required)."},
        404: {"description": "Finding not found."},
        409: {"description": "Invalid state transition."},
    },
)
def advance_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> FindingRead:
    finding = finding_service.get_by_id(db, finding_id)

    # Permission: any workspace member with finding:read can advance status
    authorization.check_permission(
        db, current_user, "finding:read",
        workspace_id=finding.workspace_id,
    )

    updated = finding_service.advance_status(
        db,
        actor=current_user,
        finding=finding,
        new_status=body.status,
        notes=body.notes,
    )
    db.commit()

    logger.info(
        "Finding status advanced via API",
        extra={
            "finding_id": str(updated.id),
            "new_status": body.status.value if hasattr(body.status, "value") else body.status,
            "actor_id": str(current_user.id),
        },
    )

    return FindingRead.model_validate(updated)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]