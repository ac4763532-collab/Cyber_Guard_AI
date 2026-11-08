"""Add Rooms, Room Members, Room Invitations, and User Public Slugs

Revision ID: 0002_add_rooms_and_slugs
Revises: 0001_initial_schema
Create Date: 2026-11-08 00:05:00.000000

Increments the schema to support:
1. users.public_user_id (Human-readable public slug: <name>-<role>-<6digits>)
2. users.role (Role persona: individual, analyst, organizer, admin)
3. rooms (Collaborative incident war rooms with direct code+password join)
4. room_members (Room participant roster with composite uniqueness)
5. room_invitations (Public slug targeted invitations with token hashes)
"""

from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_add_rooms_and_slugs"
down_revision: Union[str, Sequence[str], None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Update users table with public_user_id and role ───────────────────
    op.add_column("users", sa.Column("public_user_id", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("role", sa.String(32), nullable=False, server_default="individual"))
    
    # Safely backfill any pre-existing users without a public slug
    op.execute(
        sa.text(
            "UPDATE users SET public_user_id = "
            "lower(regexp_replace(coalesce(full_name, split_part(email, '@', 1)), '[^a-zA-Z0-9]+', '-', 'g')) "
            "|| '-user-' || floor(100000 + random() * 900000)::int "
            "WHERE public_user_id IS NULL"
        )
    )

    op.create_index("ix_users_public_user_id", "users", ["public_user_id"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])

    # ── 2. Create rooms table ────────────────────────────────────────────────
    op.create_table(
        "rooms",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("public_room_id", sa.String(64), nullable=False, unique=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("join_policy", sa.String(32), nullable=False, server_default="direct"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_rooms_public_room_id", "rooms", ["public_room_id"], unique=True)
    op.create_index("ix_rooms_created_by", "rooms", ["created_by"])
    op.create_index("ix_rooms_status", "rooms", ["status"])

    # ── 3. Create room_members table ─────────────────────────────────────────
    op.create_table(
        "room_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("room_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="member"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("invited_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("room_id", "user_id", name="uq_room_member"),
    )
    op.create_index("ix_room_members_room_id", "room_members", ["room_id"])
    op.create_index("ix_room_members_user_id", "room_members", ["user_id"])

    # ── 4. Create room_invitations table ─────────────────────────────────────
    op.create_table(
        "room_invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("room_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("rooms.id", ondelete="CASCADE"), nullable=False),
        sa.Column("invitee_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("inviter_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("role", sa.String(32), nullable=False, server_default="member"),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_room_invitations_token_hash", "room_invitations", ["token_hash"], unique=True)
    op.create_index("ix_room_invitations_room_id", "room_invitations", ["room_id"])
    op.create_index("ix_room_invitations_invitee", "room_invitations", ["invitee_user_id"])


def downgrade() -> None:
    op.drop_table("room_invitations")
    op.drop_table("room_members")
    op.drop_table("rooms")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_index("ix_users_public_user_id", table_name="users")
    op.drop_column("users", "role")
    op.drop_column("users", "public_user_id")
