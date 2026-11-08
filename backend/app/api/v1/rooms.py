"""
CyberGuard AI — Rooms and Membership API
============================================================================
Endpoints for creating rooms, joining rooms directly with Room ID + password,
managing memberships, and sending invitations.
"""

from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, DBDep
from app.schemas.room import (
    JoinRoomRequest,
    JoinRoomResponse,
    RoomCreate,
    RoomInviteRequest,
    RoomInvitationRead,
    RoomRead,
)
from app.services import room_service


router = APIRouter(
    prefix="/rooms",
    tags=["rooms"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Room or resource not found"},
    },
)


@router.post(
    "/join",
    response_model=JoinRoomResponse,
    status_code=status.HTTP_200_OK,
    summary="Direct join room by Room ID/code and password",
    description="Allows an authenticated user to directly join a room by supplying the room code and password.",
)
def join_room(
    body: JoinRoomRequest,
    current_user: CurrentUser,
    db: DBDep,
) -> JoinRoomResponse:
    room, membership, already_member = room_service.direct_join_room(
        db,
        user=current_user,
        room_code=body.room_code,
        password=body.password,
    )
    db.commit()

    msg = f"Already a member of {room.name}" if already_member else f"Successfully joined {room.name}"
    return JoinRoomResponse(
        success=True,
        message=msg,
        room=RoomRead(
            id=room.id,
            public_room_id=room.public_room_id,
            organization_id=room.organization_id,
            name=room.name,
            description=room.description,
            join_policy=room.join_policy,
            status=room.status,
            created_by=room.created_by,
            has_password=bool(room.password_hash),
            member_count=len(room.members) if room.members else 1,
            created_at=room.created_at,
            updated_at=room.updated_at,
        ),
        member_role=membership.role,
    )


@router.get(
    "/me",
    response_model=List[RoomRead],
    summary="List all rooms the current user is a member of",
)
def get_my_rooms(
    current_user: CurrentUser,
    db: DBDep,
) -> List[RoomRead]:
    rooms = room_service.list_user_rooms(db, current_user.id)
    return [
        RoomRead(
            id=r.id,
            public_room_id=r.public_room_id,
            organization_id=r.organization_id,
            name=r.name,
            description=r.description,
            join_policy=r.join_policy,
            status=r.status,
            created_by=r.created_by,
            has_password=bool(r.password_hash),
            member_count=len(r.members) if r.members else 1,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rooms
    ]


@router.post(
    "",
    response_model=RoomRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new room",
)
def create_new_room(
    body: RoomCreate,
    current_user: CurrentUser,
    db: DBDep,
) -> RoomRead:
    room = room_service.create_room(db, creator=current_user, data=body)
    db.commit()
    return RoomRead(
        id=room.id,
        public_room_id=room.public_room_id,
        organization_id=room.organization_id,
        name=room.name,
        description=room.description,
        join_policy=room.join_policy,
        status=room.status,
        created_by=room.created_by,
        has_password=bool(room.password_hash),
        member_count=1,
        created_at=room.created_at,
        updated_at=room.updated_at,
    )


@router.get(
    "/invitations/me",
    response_model=List[RoomInvitationRead],
    summary="List pending room invitations for the current user",
)
def get_my_invitations(
    current_user: CurrentUser,
    db: DBDep,
) -> List[RoomInvitationRead]:
    return [
        RoomInvitationRead(**inv)
        for inv in room_service.list_user_invitations(db, current_user.id)
    ]


@router.post(
    "/{room_id}/invitations",
    status_code=status.HTTP_201_CREATED,
    summary="Invite a user to a room using their public User ID (slug)",
)
def invite_user(
    room_id: uuid.UUID,
    body: RoomInviteRequest,
    current_user: CurrentUser,
    db: DBDep,
):
    invitation = room_service.invite_to_room(
        db,
        inviter=current_user,
        room_id=room_id,
        target_public_user_id=body.public_user_id,
        role=body.role,
    )
    db.commit()
    return {"success": True, "invitation_id": str(invitation.id), "status": invitation.status}


# Invitation accept / decline routes
invitation_router = APIRouter(
    prefix="/room-invitations",
    tags=["rooms"],
)

@invitation_router.post("/{invitation_id}/accept")
def accept_room_invite(
    invitation_id: uuid.UUID,
    current_user: CurrentUser,
    db: DBDep,
):
    room_service.respond_to_invitation(db, invitation_id=invitation_id, user=current_user, accept=True)
    db.commit()
    return {"success": True, "message": "Invitation accepted"}


@invitation_router.post("/{invitation_id}/decline")
def decline_room_invite(
    invitation_id: uuid.UUID,
    current_user: CurrentUser,
    db: DBDep,
):
    room_service.respond_to_invitation(db, invitation_id=invitation_id, user=current_user, accept=False)
    db.commit()
    return {"success": True, "message": "Invitation declined"}
