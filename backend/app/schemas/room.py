"""
CyberGuard AI — Room and Join Schemas
============================================================================
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pydantic import Field

from app.schemas.common import CyberGuardBaseSchema, TimestampedModel


class RoomBase(CyberGuardBaseSchema):
    name: str = Field(..., min_length=2, max_length=128, description="Room name")
    description: str | None = Field(default=None, max_length=500, description="Room description")
    join_policy: str = Field(default="direct", description="Policy: 'direct', 'invite_only', 'approval'")


class RoomCreate(RoomBase):
    organization_id: uuid.UUID | None = Field(default=None, description="Organization ID if org-scoped")
    password: str | None = Field(default=None, min_length=4, max_length=128, description="Room password")


class RoomRead(TimestampedModel):
    id: uuid.UUID
    public_room_id: str
    organization_id: uuid.UUID | None = None
    name: str
    description: str | None = None
    join_policy: str
    status: str
    created_by: uuid.UUID
    has_password: bool = False
    member_count: int = 1


class RoomMemberRead(CyberGuardBaseSchema):
    id: uuid.UUID
    room_id: uuid.UUID
    user_id: uuid.UUID
    role: str
    status: str
    joined_at: datetime
    user_name: str | None = None
    public_user_id: str | None = None


class JoinRoomRequest(CyberGuardBaseSchema):
    room_code: str = Field(..., description="Room Code / Public Room ID (e.g. ROOM-XXXX) or Room UUID")
    password: str | None = Field(default=None, description="Password if room is protected")


class JoinRoomResponse(CyberGuardBaseSchema):
    success: bool
    message: str
    room: RoomRead
    member_role: str


class RoomInviteRequest(CyberGuardBaseSchema):
    public_user_id: str = Field(..., description="Target user's unique public User ID (slug)")
    role: str = Field(default="member", description="Assigned room role ('member' or 'analyst')")


class RoomInvitationRead(CyberGuardBaseSchema):
    id: uuid.UUID
    room_id: uuid.UUID
    room_name: str
    public_room_id: str
    inviter_id: uuid.UUID
    inviter_name: str | None = None
    role: str
    status: str
    expires_at: datetime
    created_at: datetime
