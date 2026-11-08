"""
CyberGuard AI — Direct User-to-User Messages
============================================================================
Scoped direct messaging between individual users and analysts.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class DirectMessage(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A direct user-to-user message scoped by sender and recipient."""

    __tablename__ = "direct_messages"

    __table_args__ = (
        Index("ix_direct_messages_conversation", "sender_id", "recipient_id", "created_at"),
        Index("ix_direct_messages_unread", "recipient_id", "is_read"),
    )

    sender_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    recipient_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])
