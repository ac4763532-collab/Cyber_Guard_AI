"""
CyberGuard AI — Organization Endpoints
============================================================================

HTTP endpoints for organizations and their membership management.

Two routers exported from this file:
    ``router``              — /api/v1/organizations/*
    ``invitations_router``  — /api/v1/invitations/*

The second router is separate because invitation acceptance is not
organization-scoped — the invitee isn't a member yet. Keeping them in
the same file is for readability; the aggregator in
``api/v1/__init__.py`` mounts them under different prefixes.

Architectural note
------------------
``OrganizationMembershipRead`` is defined inline at the bottom of this
file. It should eventually be extracted to ``schemas/membership.py``
along with ``WorkspaceMembershipRead``. Inline is a pragmatic choice
to keep Phase H moving without adding a schema file mid-phase.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, status

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
    require_permission,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import OrganizationRole
from app.models.membership import OrganizationMembership
from app.models.organization import Organization
from app.models.user import User
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationFilter,
    OrganizationList,
    OrganizationRead,
    OrganizationUpdate,
)
from app.schemas.membership import (
    OrganizationMembershipRead,
    InvitationRead,
)
from app.services import (
    membership_service,
    organization_service,
)


logger = get_logger(__name__)


# ============================================================================
# ROUTER — /api/v1/organizations
# ============================================================================

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"],
)


# ============================================================================
# ORGANIZATION CRUD
# ============================================================================

@router.post(
    "",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new organization",
    description=(
        "Create an organization. The caller becomes the OWNER and a "
        "default workspace is created automatically. Any active user "
        "can create an organization (self-service)."
    ),
)
def create_organization(
    body: OrganizationCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationRead:
    org = organization_service.create_organization(
        db, creator=current_user, payload=body,
    )
    db.commit()
    return OrganizationRead.model_validate(org)


@router.get(
    "",
    response_model=PaginatedResponse[OrganizationList],
    summary="List organizations the current user belongs to",
)
def list_my_organizations(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
) -> PaginatedResponse[OrganizationList]:
    orgs, total = organization_service.list_user_organizations(
        db, user=current_user, page=page,
    )
    return PaginatedResponse[OrganizationList](
        items=[OrganizationList.model_validate(o) for o in orgs],
        meta=PageMeta.build(total=total, params=page),
    )


@router.get(
    "/{organization_id}",
    response_model=OrganizationRead,
    summary="Get an organization by ID",
)
def get_organization(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationRead:
    org = organization_service.get_by_id(db, organization_id)
    # Membership required to view details
    from app.services import authorization
    authorization.require_org_member(db, current_user, org.id)
    return OrganizationRead.model_validate(org)


@router.patch(
    "/{organization_id}",
    response_model=OrganizationRead,
    summary="Update an organization",
    description=(
        "Requires PERM_ORG_UPDATE (workspace ADMIN or OWNER). Cannot "
        "change slug, owner, or status through this endpoint."
    ),
)
def update_organization(
    organization_id: uuid.UUID,
    body: OrganizationUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationRead:
    org = organization_service.get_by_id(db, organization_id)
    updated = organization_service.update_organization(
        db, actor=current_user, organization=org, payload=body,
    )
    db.commit()
    return OrganizationRead.model_validate(updated)


@router.post(
    "/{organization_id}/archive",
    response_model=OrganizationRead,
    summary="Archive an organization",
    description=(
        "Requires PERM_ORG_DELETE (OWNER only). Archival sets status "
        "to ARCHIVED. The org becomes read-only. Retention cleanup is "
        "a separate background job."
    ),
)
def archive_organization(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationRead:
    org = organization_service.get_by_id(db, organization_id)
    archived = organization_service.archive_organization(
        db, actor=current_user, organization=org,
    )
    db.commit()
    return OrganizationRead.model_validate(archived)


# ============================================================================
# SUPER ADMIN — org listing and suspension
# ============================================================================

@router.get(
    "/admin/all",
    response_model=PaginatedResponse[OrganizationRead],
    summary="List ALL organizations (super admin)",
    include_in_schema=True,
    dependencies=[Depends(require_permission("admin:org_suspend"))],
)
def list_all_organizations(
    db: DBDep,
    page: PageDep,
    filters: OrganizationFilter = Depends(),
) -> PaginatedResponse[OrganizationRead]:
    orgs, total = organization_service.list_all_organizations(
        db, page=page, filters=filters,
    )
    return PaginatedResponse[OrganizationRead](
        items=[OrganizationRead.model_validate(o) for o in orgs],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{organization_id}/suspend",
    response_model=OrganizationRead,
    summary="Suspend an organization (super admin only)",
)
def suspend_organization(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> OrganizationRead:
    org = organization_service.get_by_id(db, organization_id)
    suspended = organization_service.suspend_organization(
        db, actor=current_user, organization=org, reason=reason,
    )
    db.commit()
    return OrganizationRead.model_validate(suspended)


@router.post(
    "/{organization_id}/unsuspend",
    response_model=OrganizationRead,
    summary="Lift an organization suspension (super admin only)",
)
def unsuspend_organization(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationRead:
    org = organization_service.get_by_id(db, organization_id)
    unsuspended = organization_service.unsuspend_organization(
        db, actor=current_user, organization=org,
    )
    db.commit()
    return OrganizationRead.model_validate(unsuspended)


# ============================================================================
# MEMBERS
# ============================================================================

@router.get(
    "/{organization_id}/members",
    response_model=PaginatedResponse[OrganizationMembershipRead],
    summary="List organization members",
)
def list_members(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_removed: bool = Query(default=False),
) -> PaginatedResponse[OrganizationMembershipRead]:
    org = organization_service.get_by_id(db, organization_id)
    members, total = membership_service.list_org_members(
        db,
        actor=current_user,
        organization=org,
        page=page,
        include_removed=include_removed,
    )
    return PaginatedResponse[OrganizationMembershipRead](
        items=[OrganizationMembershipRead.model_validate(m) for m in members],
        meta=PageMeta.build(total=total, params=page),
    )


@router.patch(
    "/{organization_id}/members/{user_id}",
    response_model=OrganizationMembershipRead,
    summary="Change a member's role (OWNER only)",
)
def change_member_role(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    role: Annotated[
        str,
        Body(embed=True, description="New OrganizationRole value"),
    ],
    reason: Annotated[str | None, Body(embed=True, max_length=500)] = None,
) -> OrganizationMembershipRead:
    try:
        new_role = OrganizationRole(role.strip().lower())
    except ValueError:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=(
                f"Invalid role {role!r}. Allowed: "
                f"{[r.value for r in OrganizationRole]}"
            ),
            code="ROLE_INVALID",
        )

    membership = membership_service.get_active_org_member(
        db, user_id=user_id, organization_id=organization_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Member not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    updated = membership_service.change_org_role(
        db,
        actor=current_user,
        membership=membership,
        new_role=new_role,
        reason=reason,
    )
    db.commit()
    return OrganizationMembershipRead.model_validate(updated)


@router.post(
    "/{organization_id}/members/{user_id}/suspend",
    response_model=OrganizationMembershipRead,
    summary="Suspend a member (OWNER only)",
)
def suspend_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    until: Annotated[datetime, Body(embed=True)],
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> OrganizationMembershipRead:
    membership = membership_service.get_active_org_member(
        db, user_id=user_id, organization_id=organization_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Member not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    updated = membership_service.suspend_org_member(
        db,
        actor=current_user,
        membership=membership,
        until=until,
        reason=reason,
    )
    db.commit()
    return OrganizationMembershipRead.model_validate(updated)


@router.post(
    "/{organization_id}/members/{user_id}/unsuspend",
    response_model=OrganizationMembershipRead,
    summary="Lift a member suspension",
)
def unsuspend_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OrganizationMembershipRead:
    membership = membership_service.get_active_org_member(
        db, user_id=user_id, organization_id=organization_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Member not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    updated = membership_service.unsuspend_org_member(
        db, actor=current_user, membership=membership,
    )
    db.commit()
    return OrganizationMembershipRead.model_validate(updated)


@router.delete(
    "/{organization_id}/members/{user_id}",
    response_model=MessageResponse,
    summary="Remove a member from an organization",
)
def remove_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> MessageResponse:
    membership = membership_service.get_active_org_member(
        db, user_id=user_id, organization_id=organization_id,
    )
    if membership is None:
        raise NotFoundError(
            message="Member not found.",
            code="MEMBERSHIP_NOT_FOUND",
        )

    membership_service.remove_org_member(
        db,
        actor=current_user,
        membership=membership,
        reason=reason,
    )
    db.commit()
    return MessageResponse(message="Member removed.")


# ============================================================================
# INVITATIONS — creation and revocation (org-scoped)
# ============================================================================

@router.post(
    "/{organization_id}/invitations",
    status_code=status.HTTP_201_CREATED,
    summary="Create a pending invitation",
    description=(
        "Creates a pending invitation for a user to join the org with "
        "a specific role. Returns the invitation and the **plaintext "
        "token** — the token is shown exactly once and must be delivered "
        "to the invitee by email. It cannot be retrieved later."
    ),
)
def create_invitation(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    email: Annotated[str, Body(embed=True, min_length=3, max_length=320)],
    role: Annotated[str, Body(embed=True)],
    personal_message: Annotated[str | None, Body(embed=True, max_length=1000)] = None,
) -> dict:
    try:
        invitation_role = OrganizationRole(role.strip().lower())
    except ValueError:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=f"Invalid role {role!r}.",
            code="INVITATION_ROLE_INVALID",
        )

    org = organization_service.get_by_id(db, organization_id)

    invitation, plaintext_token = membership_service.create_invitation(
        db,
        actor=current_user,
        organization=org,
        email=email,
        role=invitation_role,
        personal_message=personal_message,
    )
    db.commit()

    return {
        "invitation_id": str(invitation.id),
        "email": invitation.email,
        "role": invitation.role.value,
        "expires_at": invitation.expires_at.isoformat(),
        "seconds_until_expiry": invitation.seconds_until_expiry,
        "plaintext_token": plaintext_token,
        "delivery_hint": (
            "Send the plaintext_token to the invitee via email. It is "
            "shown only once and cannot be retrieved later. The invitee "
            "accepts via POST /api/v1/invitations/accept."
        ),
    }


@router.get(
    "/{organization_id}/invitations",
    response_model=PaginatedResponse[InvitationRead],
    summary="List pending invitations for an organization",
)
def list_invitations(
    organization_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
) -> PaginatedResponse[InvitationRead]:
    org = organization_service.get_by_id(db, organization_id)
    invitations, total = membership_service.list_pending_invitations(
        db, actor=current_user, organization=org, page=page,
    )
    return PaginatedResponse[InvitationRead](
        items=[_invitation_to_read(i) for i in invitations],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{organization_id}/invitations/{invitation_id}/revoke",
    response_model=MessageResponse,
    summary="Revoke a pending invitation",
)
def revoke_invitation(
    organization_id: uuid.UUID,
    invitation_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> MessageResponse:
    from app.models.invitation import OrganizationInvitation
    invitation = db.get(OrganizationInvitation, invitation_id)
    if invitation is None or invitation.organization_id != organization_id:
        raise NotFoundError(
            message="Invitation not found.",
            code="INVITATION_NOT_FOUND",
        )

    membership_service.revoke_invitation(
        db, actor=current_user, invitation=invitation, reason=reason,
    )
    db.commit()
    return MessageResponse(message="Invitation revoked.")


# ============================================================================
# ROUTER — /api/v1/invitations
# Accept/decline don't require org membership — the invitee isn't a
# member yet. They only need a valid token.
# ============================================================================

invitations_router = APIRouter(
    prefix="/invitations",
    tags=["invitations"],
)


@invitations_router.post(
    "/accept",
    response_model=OrganizationMembershipRead,
    summary="Accept a pending invitation",
    description=(
        "Accepts an invitation using the plaintext token. The accepting "
        "user's email must match the invited email, and their email must "
        "be verified (both enforced server-side). On success, an active "
        "membership is created and the invitation is marked accepted."
    ),
)
def accept_invitation(
    current_user: CurrentActiveUser,
    db: DBDep,
    token: Annotated[str, Body(embed=True, min_length=20, max_length=200)],
) -> OrganizationMembershipRead:
    membership = membership_service.accept_invitation(
        db, user=current_user, plaintext_token=token,
    )
    db.commit()
    return OrganizationMembershipRead.model_validate(membership)


@invitations_router.post(
    "/decline",
    response_model=MessageResponse,
    summary="Decline a pending invitation",
)
def decline_invitation(
    current_user: CurrentActiveUser,
    db: DBDep,
    token: Annotated[str, Body(embed=True, min_length=20, max_length=200)],
    reason: Annotated[str | None, Body(embed=True, max_length=500)] = None,
) -> MessageResponse:
    membership_service.decline_invitation(
        db, user=current_user, plaintext_token=token, reason=reason,
    )
    db.commit()
    return MessageResponse(message="Invitation declined.")


# ============================================================================
# INLINE RESPONSE SCHEMAS
# ============================================================================
# These belong in app/schemas/membership.py and app/schemas/invitation.py.
# Defined inline here as a pragmatic choice to unblock Phase H — extract
# in a later cleanup pass once all routers are delivered.

from pydantic import BaseModel, ConfigDict, Field  # noqa: E402


class OrganizationMembershipRead(BaseModel):
    """
    Read schema for OrganizationMembership. Populated via
    ``model_validate`` from an ORM instance.
    """
    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
    )

    id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: OrganizationRole

    invited_at: datetime | None = None
    invited_by_id: uuid.UUID | None = None
    joined_at: datetime | None = None

    suspended_at: datetime | None = None
    suspended_until: datetime | None = None
    suspension_reason: str | None = None

    removed_at: datetime | None = None
    removed_by_id: uuid.UUID | None = None
    removal_reason: str | None = None

    # Computed state properties from the model
    is_pending: bool = False
    is_active: bool = False
    is_removed: bool = False
    is_suspended: bool = False


class InvitationRead(BaseModel):
    """
    Read schema for OrganizationInvitation. Never includes the plaintext
    token or hash — only the identification prefix.
    """
    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
    )

    id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    role: OrganizationRole
    invited_by_id: uuid.UUID | None = None
    token_prefix: str
    personal_message: str | None = None
    status: str
    expires_at: datetime
    created_at: datetime

    is_expired: bool = False


def _invitation_to_read(invitation) -> InvitationRead:
    """Map an ORM invitation to the read schema."""
    return InvitationRead.model_validate(invitation)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "invitations_router"]