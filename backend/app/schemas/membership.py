"""
CyberGuard AI — Membership and Invitation Schemas
============================================================================
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.enums import OrganizationRole, WorkspaceRole


class OrganizationMembershipRead(BaseModel):
    """
    Read schema for OrganizationMembership.
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

    is_pending: bool = False
    is_active: bool = False
    is_removed: bool = False
    is_suspended: bool = False


class WorkspaceMembershipRead(BaseModel):
    """
    Read schema for WorkspaceMembership.
    """
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

    removed_at: datetime | None = None
    removed_by_id: uuid.UUID | None = None

    is_pending: bool = False
    is_active: bool = False
    is_removed: bool = False


class InvitationRead(BaseModel):
    """
    Read schema for OrganizationInvitation.
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
