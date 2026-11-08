"""
CyberGuard AI — Workspace Endpoints
============================================================================

HTTP endpoints for workspaces and their members.

Two routers exported from this file:
    ``router``                  — /api/v1/workspaces/*
    ``org_workspaces_router``   — /api/v1/organizations/{org_id}/workspaces/*

The org-scoped routes are in this file (not organizations.py) because
they're workspace operations that happen to be nested under an
organization path. Keeping all workspace operations together makes the
file self-contained and easy to navigate.

Personal vs. organization workspaces
------------------------------------
    - Personal workspaces are created by the user for themselves
    - Organization workspaces are created by an org ADMIN/OWNER
    - Both share the same table, distinguished by workspace_type
    - Personal workspaces cannot be archived (they're tied to user
      lifecycle — deletion cascades from user deletion)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, status
from pydantic import BaseModel, ConfigDict

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import WorkspaceRole, WorkspaceType
from app.models.membership import WorkspaceMembership
from app.schemas.membership import WorkspaceMembershipRead
from app.models.workspace import Workspace
from app.models.user import User
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.workspace import (
    WorkspaceCreate,
    WorkspaceFilter,
    WorkspaceList,
    WorkspaceRead,
    WorkspaceUpdate,
)
from app.services import (
    authorization,
    membership_service,
    organization_service,
    workspace_service,
)


logger = get_logger(__name__)


# ============================================================================
# ROUTER — /api/v1/workspaces
# ============================================================================

router = APIRouter(
    prefix="/workspaces",
    tags=["workspaces"],
)


# ============================================================================
# ORGANIZATION-SCOPED ROUTER — /api/v1/organizations/{org_id}/workspaces
# ============================================================================

org_workspaces_router = APIRouter(
    prefix="/organizations",
    tags=["workspaces"],
)


# ============================================================================
# PERSONAL WORKSPACE CREATION
# ============================================================================

@router.post(
    "",
    response_model=WorkspaceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a personal workspace",
    description=(
        "Creates a personal workspace for the current user. A user can "
        "only have one personal workspace — calling this endpoint again "
        "returns the existing one (idempotent). Any authenticated user "
        "can call this."
    ),
)
def create_personal_workspace(
    current_user: CurrentActiveUser,
    db: DBDep,
) -> WorkspaceRead:
    ws = workspace_service.create_personal_workspace(db, current_user)
    db.commit()
    return WorkspaceRead.model_validate(ws)


# ============================================================================
# WORKSPACE READ
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[WorkspaceList],
    summary="List workspaces the current user belongs to",
    description=(
        "Returns both the user's personal workspace and any organization "
        "workspaces they're an active member of."
    ),
)
def list_my_workspaces(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: WorkspaceFilter = Depends(),
) -> PaginatedResponse[WorkspaceList]:
    workspaces, total = workspace_service.list_user_workspaces(
        db, user=current_user, page=page, filters=filters,
    )
    return PaginatedResponse[WorkspaceList](
        items=[WorkspaceList.model_validate(w) for w in workspaces],
        meta=PageMeta.build(total=total, params=page),
    )


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceRead,
    summary="Get a workspace by ID",
)
def get_workspace(
    workspace_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> WorkspaceRead:
    ws = workspace_service.get_by_id(db, workspace_id)
    authorization.require_workspace_member(db, current_user, ws.id)
    return WorkspaceRead.model_validate(ws)


# ============================================================================
# WORKSPACE UPDATE
# ============================================================================

@router.patch(
    "/{workspace_id}",
    response_model=WorkspaceRead,
    summary="Update a workspace",
    description=(
        "Update mutable fields (name, description, color, icon, settings). "
        "Requires PERM_WORKSPACE_UPDATE — workspace OWNER or org ADMIN."
    ),
)
def update_workspace(
    workspace_id: uuid.UUID,
    body: WorkspaceUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> WorkspaceRead:
    ws = workspace_service.get_by_id(db, workspace_id)
    updated = workspace_service.update_workspace(
        db, actor=current_user, workspace=ws, payload=body,
    )
    db.commit()
    return WorkspaceRead.model_validate(updated)


@router.post(
    "/{workspace_id}/archive",
    response_model=WorkspaceRead,
    summary="Archive a workspace",
    description=(
        "Archives an organization workspace (soft-delete). Requires "
        "PERM_WORKSPACE_DELETE (OWNER only). **Personal workspaces "
        "cannot be archived** — they're tied to the user lifecycle."
    ),
)
def archive_workspace(
    workspace_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> WorkspaceRead:
    ws = workspace_service.get_by_id(db, workspace_id)
    archived = workspace_service.archive_workspace(
        db, actor=current_user, workspace=ws,
    )
    db.commit()
    return WorkspaceRead.model_validate(archived)


# ============================================================================
# WORKSPACE MEMBERS
# ============================================================================

@router.get(
    "/{workspace_id}/members",
    response_model=PaginatedResponse[WorkspaceMembershipRead],
    summary="List workspace members",
)
def list_workspace_members(
    workspace_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_removed: bool = Query(default=False),
) -> PaginatedResponse[WorkspaceMembershipRead]:
    ws = workspace_service.get_by_id(db, workspace_id)
    members, total = membership_service.list_workspace_members(
        db,
        actor=current_user,
        workspace=ws,
        page=page,
        include_removed=include_removed,
    )
    return PaginatedResponse[WorkspaceMembershipRead](
        items=[WorkspaceMembershipRead.model_validate(m) for m in members],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{workspace_id}/members",
    response_model=WorkspaceMembershipRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a member to a workspace",
    description=(
        "Adds an existing user directly to the workspace. For "
        "organization workspaces, the user must already be an active "
        "member of the parent organization. Requires "
        "PERM_WORKSPACE_UPDATE in the workspace."
    ),
)
def add_workspace_member(
    workspace_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    user_id: Annotated[uuid.UUID, Body(embed=True)],
    role: Annotated[str, Body(embed=True)] = "viewer",
) -> WorkspaceMembershipRead:
    try:
        workspace_role = WorkspaceRole(role.strip().lower())
    except ValueError:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=f"Invalid role {role!r}.",
            code="WORKSPACE_ROLE_INVALID",
        )

    ws = workspace_service.get_by_id(db, workspace_id)

    # Load the target user
    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise NotFoundError(
            message=f"User {user_id} not found.",
            code="USER_NOT_FOUND",
        )

    membership = membership_service.add_workspace_member_directly(
        db,
        actor=current_user,
        workspace=ws,
        user=target,
        role=workspace_role,
    )
    db.commit()
    return WorkspaceMembershipRead.model_validate(membership)


@router.patch(
    "/{workspace_id}/members/{user_id}",
    response_model=WorkspaceMembershipRead,
    summary="Change a workspace member's role",
)
def change_workspace_member_role(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    role: Annotated[str, Body(embed=True)],
) -> WorkspaceMembershipRead:
    try:
        workspace_role = WorkspaceRole(role.strip().lower())
    except ValueError:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=f"Invalid role {role!r}.",
            code="WORKSPACE_ROLE_INVALID",
        )

    membership = membership_service.get_active_workspace_member(
        db, user_id=user_id, workspace_id=workspace_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Membership not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    updated = membership_service.change_workspace_role(
        db,
        actor=current_user,
        membership=membership,
        new_role=workspace_role,
    )
    db.commit()
    return WorkspaceMembershipRead.model_validate(updated)


@router.delete(
    "/{workspace_id}/members/{user_id}",
    response_model=MessageResponse,
    summary="Remove a member from a workspace",
)
def remove_workspace_member(
    workspace_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> MessageResponse:
    membership = membership_service.get_active_workspace_member(
        db, user_id=user_id, workspace_id=workspace_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Membership not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    membership_service.remove_workspace_member(
        db,
        actor=current_user,
        membership=membership,
        reason=reason,
    )
    db.commit()
    return MessageResponse(message="Workspace member removed.")


# ============================================================================
# ORGANIZATION-SCOPED WORKSPACE ENDPOINTS
# ============================================================================

@org_workspaces_router.post(
    "/{organization_id}/workspaces",
    response_model=WorkspaceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new workspace in an organization",
    description=(
        "Requires PERM_WORKSPACE_CREATE in the org (ADMIN or OWNER). "
        "The caller is automatically added as OWNER of the new "
        "workspace. The slug must be unique within the organization."
    ),
)
def create_org_workspace(
    organization_id: uuid.UUID,
    body: WorkspaceCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> WorkspaceRead:
    org = organization_service.get_by_id(db, organization_id)

    # If the caller didn't supply a slug, generate one from the name
    payload = body
    if not payload.slug:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=(
                "slug is required when creating an organization workspace. "
                "It must be unique within the organization."
            ),
            code="WORKSPACE_SLUG_REQUIRED",
        )

    ws = workspace_service.create_org_workspace(
        db, actor=current_user, organization=org, payload=payload,
    )
    db.commit()
    return WorkspaceRead.model_validate(ws)


@org_workspaces_router.get(
    "/{organization_id}/workspaces",
    response_model=PaginatedResponse[WorkspaceList],
    summary="List all workspaces in an organization",
    description=(
        "Requires organization membership (any role). Returns all "
        "non-archived workspaces in the org."
    ),
)
def list_org_workspaces(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: WorkspaceFilter = Depends(),
) -> PaginatedResponse[WorkspaceList]:
    org = organization_service.get_by_id(db, organization_id)
    workspaces, total = workspace_service.list_org_workspaces(
        db,
        actor=current_user,
        organization=org,
        page=page,
        filters=filters,
    )
    return PaginatedResponse[WorkspaceList](
        items=[WorkspaceList.model_validate(w) for w in workspaces],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# INLINE SCHEMA — WorkspaceMembershipRead
# ============================================================================
# Belongs in app/schemas/membership.py — extracted in cleanup pass.

class WorkspaceMembershipRead(BaseModel):
    """Read schema for WorkspaceMembership."""
    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
    )

    id: uuid.UUID
    user_id: uuid.UUID
    workspace_id: uuid.UUID
    role: WorkspaceRole

    invited_at: datetime | None = None
    invited_by_id: uuid.UUID | None = None
    joined_at: datetime | None = None

    suspended_at: datetime | None = None
    suspended_until: datetime | None = None
    suspension_reason: str | None = None

    removed_at: datetime | None = None
    removed_by_id: uuid.UUID | None = None
    removal_reason: str | None = None

    # Computed properties
    is_pending: bool = False
    is_active: bool = False
    is_removed: bool = False
    is_suspended: bool = False


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "org_workspaces_router"]