"""
CyberGuard AI — Room Service
============================================================================
Handles room creation, direct join with room ID/code + password,
membership verification, and organizer invitations.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ConflictError,
    PermissionDeniedError,
    InvalidCredentialsError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import hash_password, verify_password
from app.models.room import Room, RoomMember, RoomInvitation
from app.models.user import User
from app.schemas.room import RoomCreate
from app.utils.id_generator import generate_room_code


logger = get_logger(__name__)


def create_room(
    db: Session,
    *,
    creator: User,
    data: RoomCreate,
) -> Room:
    """Create a new room and add the creator as owner member."""
    # Generate unique public_room_id
    for _ in range(10):
        code = generate_room_code()
        exists = db.execute(select(Room.id).where(Room.public_room_id == code)).scalar_one_or_none()
        if not exists:
            break

    password_hash = hash_password(data.password) if data.password else None

    room = Room(
        public_room_id=code,
        organization_id=data.organization_id,
        name=data.name.strip(),
        description=data.description.strip() if data.description else None,
        password_hash=password_hash,
        join_policy=data.join_policy or "direct",
        status="active",
        created_by=creator.id,
    )
    db.add(room)
    db.flush()

    # Creator is automatically room owner
    member = RoomMember(
        room_id=room.id,
        user_id=creator.id,
        role="owner",
        status="active",
        joined_at=datetime.now(timezone.utc),
    )
    db.add(member)
    db.flush()

    logger.info("Room created", extra={"room_id": str(room.id), "code": code, "creator": str(creator.id)})
    return room


def direct_join_room(
    db: Session,
    *,
    user: User,
    room_code: str,
    password: str | None = None,
) -> tuple[Room, RoomMember, bool]:
    """
    Directly join a room using Room ID / code and password.
    Returns (room, membership, already_member).
    """
    query_code = room_code.strip()
    stmt = select(Room).where(
        or_(
            Room.public_room_id.ilike(query_code),
            Room.id == (uuid.UUID(query_code) if _is_uuid(query_code) else None),
        )
    )
    room = db.execute(stmt).scalar_one_or_none()

    if not room or room.status != "active":
        raise NotFoundError(message="Room not found or is no longer active", code="ROOM_NOT_FOUND")

    # If already a member
    existing_member = db.execute(
        select(RoomMember).where(RoomMember.room_id == room.id, RoomMember.user_id == user.id)
    ).scalar_one_or_none()

    if existing_member:
        if existing_member.status == "revoked":
            raise PermissionDeniedError(message="Your access to this room was revoked", code="ROOM_ACCESS_REVOKED")
        return room, existing_member, True

    # Check join policy
    if room.join_policy == "invite_only":
        raise PermissionDeniedError(message="This room requires an explicit organizer invitation", code="ROOM_INVITE_ONLY")

    # Verify password if set
    if room.password_hash:
        if not password or not verify_password(password, room.password_hash):
            raise InvalidCredentialsError(
                message="Incorrect room password",
                code="ROOM_INVALID_PASSWORD",
            )

    # Add member
    role = "analyst" if getattr(user, "role", "individual") == "analyst" else "member"
    member = RoomMember(
        room_id=room.id,
        user_id=user.id,
        role=role,
        status="active",
        joined_at=datetime.now(timezone.utc),
    )
    db.add(member)
    db.flush()

    logger.info("User joined room directly", extra={"room_id": str(room.id), "user_id": str(user.id), "role": role})
    return room, member, False


def list_user_rooms(db: Session, user_id: uuid.UUID) -> list[Room]:
    """List all active rooms where the user is an active member."""
    stmt = (
        select(Room)
        .join(RoomMember, RoomMember.room_id == Room.id)
        .where(
            RoomMember.user_id == user_id,
            RoomMember.status == "active",
            Room.status == "active",
            Room.deleted_at.is_(None),
        )
        .order_by(RoomMember.joined_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


def invite_to_room(
    db: Session,
    *,
    inviter: User,
    room_id: uuid.UUID,
    target_public_user_id: str,
    role: str = "member",
) -> RoomInvitation:
    """Invite an existing user by their unique public User ID (slug)."""
    room = db.execute(select(Room).where(Room.id == room_id, Room.deleted_at.is_(None))).scalar_one_or_none()
    if not room:
        raise NotFoundError("Room not found")

    target_user = db.execute(
        select(User).where(User.public_user_id == target_public_user_id.strip())
    ).scalar_one_or_none()
    if not target_user:
        raise NotFoundError("User with this public User ID not found")

    # Check existing membership
    existing = db.execute(
        select(RoomMember).where(RoomMember.room_id == room.id, RoomMember.user_id == target_user.id)
    ).scalar_one_or_none()
    if existing and existing.status == "active":
        raise ConflictError("User is already a member of this room")

    token = secrets.token_urlsafe(32)
    invitation = RoomInvitation(
        room_id=room.id,
        invitee_user_id=target_user.id,
        inviter_user_id=inviter.id,
        token_hash=hash_password(token),
        role=role,
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(invitation)
    db.flush()
    return invitation


def list_user_invitations(db: Session, user_id: uuid.UUID) -> list[dict]:
    """List pending room invitations for the user."""
    stmt = (
        select(RoomInvitation, Room.name, Room.public_room_id, User.full_name)
        .join(Room, Room.id == RoomInvitation.room_id)
        .join(User, User.id == RoomInvitation.inviter_user_id)
        .where(
            RoomInvitation.invitee_user_id == user_id,
            RoomInvitation.status == "pending",
            RoomInvitation.expires_at > datetime.now(timezone.utc),
        )
        .order_by(RoomInvitation.created_at.desc())
    )
    results = db.execute(stmt).all()
    invites = []
    for inv, room_name, room_code, inviter_name in results:
        invites.append({
            "id": inv.id,
            "room_id": inv.room_id,
            "room_name": room_name,
            "public_room_id": room_code,
            "inviter_id": inv.inviter_user_id,
            "inviter_name": inviter_name or "Organizer",
            "role": inv.role,
            "status": inv.status,
            "expires_at": inv.expires_at,
            "created_at": inv.created_at,
        })
    return invites


def respond_to_invitation(
    db: Session,
    *,
    invitation_id: uuid.UUID,
    user: User,
    accept: bool,
) -> bool:
    """Accept or decline an invitation."""
    inv = db.execute(
        select(RoomInvitation).where(
            RoomInvitation.id == invitation_id,
            RoomInvitation.invitee_user_id == user.id,
            RoomInvitation.status == "pending",
        )
    ).scalar_one_or_none()
    if not inv:
        raise NotFoundError("Invitation not found or already processed")

    if accept:
        inv.status = "accepted"
        member = RoomMember(
            room_id=inv.room_id,
            user_id=user.id,
            role=inv.role,
            status="active",
            joined_at=datetime.now(timezone.utc),
            invited_by=inv.inviter_user_id,
        )
        db.add(member)
    else:
        inv.status = "declined"

    db.flush()
    return True


def _is_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except Exception:
        return False
