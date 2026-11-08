"""
CyberGuard AI — Room and Room Membership Models
============================================================================

Entities:
- Room: Private collaboration workspace with member roster, devices, security events,
  and room-scoped communication.
- RoomMember: Membership mapping between User and Room with role and join timestamp.
- RoomInvitation: Targeted invitation sent by Organizer/Admin to a user via public_user_id.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class Room(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A private collaboration and security room workspace."""

    __tablename__ = "rooms"

    public_room_id: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        index=True,
        nullable=False,
        comment="Human-readable room code (e.g. ROOM-7X9B).",
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Parent organization UUID, if org-owned.",
    )

    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Room title / display name.",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Room scope or purpose description.",
    )

    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Hashed password for direct password-protected join (Argon2 / bcrypt).",
    )

    join_policy: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="direct",
        server_default="direct",
        comment="Policy: 'direct' (code+password), 'invite_only', or 'approval'.",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="active",
        server_default="active",
        index=True,
        comment="Room status: 'active', 'archived', 'suspended'.",
    )

    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="User UUID who created this room.",
    )

    members = relationship("RoomMember", back_populates="room", cascade="all, delete-orphan")
    invitations = relationship("RoomInvitation", back_populates="room", cascade="all, delete-orphan")


class RoomMember(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Membership of a user in a room."""

    __tablename__ = "room_members"

    __table_args__ = (
        UniqueConstraint("room_id", "user_id", name="uq_room_member"),
    )

    room_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="member",
        server_default="member",
        comment="Role in room: 'owner', 'admin', 'analyst', 'member', 'viewer'.",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="active",
        server_default="active",
        comment="State: 'active', 'pending_approval', 'revoked'.",
    )

    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    room = relationship("Room", back_populates="members")
    user = relationship("User", foreign_keys=[user_id])


class RoomInvitation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Invitation for a user to join a room."""

    __tablename__ = "room_invitations"

    room_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("rooms.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    invitee_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Invited user's UUID.",
    )

    inviter_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        comment="Organizer or admin who sent the invite.",
    )

    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Secure random invitation token hash.",
    )

    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="member",
        server_default="member",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default="pending",
        comment="State: 'pending', 'accepted', 'declined', 'expired'.",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    room = relationship("Room", back_populates="invitations")
    invitee = relationship("User", foreign_keys=[invitee_user_id])
    inviter = relationship("User", foreign_keys=[inviter_user_id])
