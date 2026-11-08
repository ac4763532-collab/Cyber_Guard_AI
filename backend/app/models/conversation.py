"""
CyberGuard AI — Case Conversations, Messages, Attachments
============================================================================

Three tables that model the communication layer of the platform:

    case_conversations      — thread containers (client, internal, system)
    case_messages           — individual messages (full-text searchable)
    message_attachments     — files attached to messages (informal, lightweight)

Access control
--------------
Who can see a message? The same rules as the parent case:

    - Assigned analysts: always (via CaseAssignment)
    - Users with a CaseAccessGrant of CONVERSATION_READ or FULL_CASE: yes
    - Internal conversations: NEVER visible to the client, regardless of grant
    - System conversations: read-only, visible to all case participants

The rule is enforced by ``authorization_service``, but the schema encodes
it via ``conversation_type`` — the type is the marker that says "this is
not for the client."

Design decisions
----------------
1. **Conversation types separate the audiences.**

       client    — client ↔ assigned analysts
       internal  — analyst ↔ analyst (NEVER visible to client)
       system    — automated messages, no replies

2. **One conversation per (case_id, conversation_type) — unique constraint.**
   Prevents fragmentation. One client thread, one internal thread, one
   system thread per case. If threads need splitting later, add a
   ``subject`` field and relax the uniqueness.

3. **``case_messages.evidence_id`` = message references existing evidence.**
   A message that says "here is the suspicious email" links to
   ``security_evidence``. Different from uploading a file as an attachment
   — evidence goes through the full hash + chain-of-custody pipeline.

4. **``message_attachments`` = lightweight, no chain of custody.**
   Used for "here's a screenshot to illustrate" or "review this export."
   These do NOT require the full evidence treatment. ``content_hash`` is
   still computed for dedup and malware scanning, but they don't have
   ``chain_of_custody``.

5. **Message threading via ``reply_to_id`` self-FK.**
   Threads are 1 level deep. Replies to replies inherit the parent thread
   at the UI layer. ``ON DELETE SET NULL`` — a deleted parent doesn't
   cascade; the child becomes top-level.

6. **Read receipts via ``read_by`` JSONB array.**
   ``[{user_id, at}]``. Per-message granularity. The
   ``unread_count_for_user()`` method on conversation computes unread
   count with a JSONB containment check. For very large teams this could
   be materialized, but JSONB is correct for MVP.

7. **``search_vector`` computed by PostgreSQL.**
   ``TSVECTOR`` column with ``Computed("to_tsvector('simple',
   coalesce(body, ''))", persisted=True)``. The DB generates it
   automatically. The migration adds a GIN index. Full-text search across
   a case's messages is a single query.

8. **Edit tracking: ``edited_at``, ``edit_count``.**
   Preserves the fact of edits. Full edit history (with prior bodies)
   requires a future ``message_revisions`` table.

9. **Soft-delete via ``SoftDeleteMixin``.**
   Deleted messages remain in the DB (compliance) but are excluded from
   queries. Users see ``[message deleted]`` in place of the body.

10. **``is_pinned`` on messages.**
    Analysts can pin "important context" messages so they stay at the top.

11. **Message types: text / system_event / evidence_reference / status_change.**
    System-generated messages can only be created by the backend via the
    service layer. User-created messages are ``text`` or
    ``evidence_reference``.

12. **Denormalized ``last_message_at`` + ``message_count`` on conversation.**
    Kept in sync by the message service. Enables conversation-list queries
    without a JOIN.

13. **Attachment safety: same defense as evidence.**
    ``stored_filename`` is a UUID, extension allow-list enforced, size cap
    enforced, hash computed at upload. Prevents path traversal, malware-
    as-picture, and lets the file be scanned by ClamAV before download in
    a future version.

14. **Orphaned attachments.**
    A user may pre-upload a file, then abandon the message. The
    attachment then has ``message_id = NULL``. The background job cleans
    these up after 24 hours.

15. **Timezone correctness everywhere.**

Usage
-----
    from app.models import CaseConversation, CaseMessage, MessageAttachment
    from app.models.enums import ConversationStatus, MessageType

    # Create the client conversation for a case
    client_conv = CaseConversation.build(
        workspace_id=case.workspace_id,
        case_id=case.id,
        conversation_type="client",
        title="Conversation with client",
        created_by_id=analyst.id,
    )
    db.add(client_conv)
    db.flush()

    # Client sends a message
    msg = CaseMessage.build(
        conversation_id=client_conv.id,
        sender_id=client.id,
        body="Thank you for looking into this.",
        message_type=MessageType.TEXT,
    )
    db.add(msg)

    # Analyst replies with evidence attached
    reply = CaseMessage.build(
        conversation_id=client_conv.id,
        sender_id=analyst.id,
        body="Here is the analysis of the email you forwarded.",
        message_type=MessageType.EVIDENCE_REFERENCE,
        evidence_id=evidence.id,
        reply_to_id=msg.id,
    )
    db.add(reply)
    db.commit()
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    ConversationStatus,
    MessageType,
    enum_column_type,
)


#: Conversation type values. Enforced by CHECK constraint.
_CONVERSATION_TYPE_CLIENT = "client"
_CONVERSATION_TYPE_INTERNAL = "internal"
_CONVERSATION_TYPE_SYSTEM = "system"
_VALID_CONVERSATION_TYPES = frozenset({
    _CONVERSATION_TYPE_CLIENT,
    _CONVERSATION_TYPE_INTERNAL,
    _CONVERSATION_TYPE_SYSTEM,
})

#: Attachment allow-list (same as evidence — same safety concerns).
_ATTACHMENT_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".pdf", ".txt", ".log", ".csv", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".zip", ".gz",
    ".pcap", ".pcapng", ".eml", ".msg",
    ".docx", ".xlsx", ".pptx",
})

_ATTACHMENT_DENIED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".sh",
    ".msi", ".scr", ".vbs", ".jar", ".com", ".app",
    ".php", ".phtml", ".jsp", ".asp", ".aspx", ".cgi",
    ".py", ".rb", ".pl", ".js",
})

#: Per-attachment size cap (10 MB — smaller than evidence, since
#: attachments are informal).
_MAX_ATTACHMENT_SIZE_BYTES = 10_485_760

#: Message body max length (50k — much larger than titles).
_MAX_MESSAGE_BODY_LENGTH = 50_000

_MAX_TITLE_LENGTH = 255
_MAX_STORED_FILENAME_LENGTH = 128
_MAX_ORIGINAL_FILENAME_LENGTH = 255
_MAX_MIME_LENGTH = 128
_MAX_HASH_LENGTH = 64
_MAX_METADATA_BYTES = 32 * 1024
_MAX_READ_BY_ENTRIES = 500

_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


# ============================================================================
# CASE CONVERSATION
# ============================================================================

class CaseConversation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A conversation thread within a security case.

    Exactly one ``client`` and one ``internal`` and one ``system``
    conversation is expected per case. Additional conversations can be
    added later if the schema is relaxed, but for MVP the uniqueness of
    ``(case_id, conversation_type)`` keeps things clean.
    """

    __tablename__ = "case_conversations"

    __table_args__ = (
        CheckConstraint(
            "conversation_type IN ('client', 'internal', 'system')",
            name="conversation_type_values",
        ),
        CheckConstraint(
            "message_count >= 0",
            name="message_count_non_negative",
        ),
        # One conversation of each type per case.
        UniqueConstraint(
            "case_id",
            "conversation_type",
            name="uq_case_conversation_type",
        ),
        Index(
            "ix_case_conversations_case_id",
            "case_id",
        ),
        Index(
            "ix_case_conversations_workspace_type",
            "workspace_id",
            "conversation_type",
        ),
    )

    # ─── Tenant & case ──────────────────────────────────────────────────
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Denormalized for efficient workspace-scoped queries.",
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning case. Deleting the case cascades conversations.",
    )

    # ─── Identity ───────────────────────────────────────────────────────
    conversation_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_CONVERSATION_TYPE_CLIENT,
        server_default=_CONVERSATION_TYPE_CLIENT,
        comment="client | internal | system. Distinguishes audiences.",
    )

    title: Mapped[str | None] = mapped_column(
        String(_MAX_TITLE_LENGTH),
        nullable=True,
        comment="Optional label — e.g. 'Discussion of phishing email'.",
    )

    # ─── Lifecycle ──────────────────────────────────────────────────────
    status: Mapped[ConversationStatus] = mapped_column(
        enum_column_type(ConversationStatus),
        nullable=False,
        default=ConversationStatus.OPEN,
        server_default=ConversationStatus.OPEN.value,
        index=True,
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    closed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── Denormalized counters ─────────────────────────────────────────
    last_message_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of the most recent message. Updated by message service.",
    )

    message_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Total message count. Denormalized for list queries.",
    )

    # ─── Settings ───────────────────────────────────────────────────────
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Conversation-scoped settings: "
            "{allow_attachments, notify_on_message, pinned_message_ids}."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("conversation_type")
    def _validate_conversation_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="conversation_type must be a string",
                code="CONVERSATION_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_CONVERSATION_TYPES:
            raise ValidationError(
                message=(
                    f"conversation_type must be one of "
                    f"{sorted(_VALID_CONVERSATION_TYPES)}"
                ),
                code="CONVERSATION_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_CONVERSATION_TYPES),
                },
            )
        return normalized

    @validates("status")
    def _validate_status(
        self, _key: str, value: ConversationStatus | str
    ) -> ConversationStatus:
        if isinstance(value, ConversationStatus):
            return value
        if isinstance(value, str):
            try:
                return ConversationStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid conversation status {value!r}",
                    code="CONVERSATION_STATUS_INVALID",
                    details={"allowed": list(ConversationStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be a ConversationStatus or string",
            code="CONVERSATION_STATUS_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        workspace_id: uuid.UUID,
        case_id: uuid.UUID,
        conversation_type: str,
        created_by_id: uuid.UUID | None = None,
        title: str | None = None,
        settings: dict[str, Any] | None = None,
    ) -> "CaseConversation":
        """Construct a new conversation thread in OPEN state."""
        return cls(
            workspace_id=workspace_id,
            case_id=case_id,
            conversation_type=conversation_type,
            title=title,
            status=ConversationStatus.OPEN,
            created_by_id=created_by_id,
            settings=settings or {},
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def close(self, *, by_user_id: uuid.UUID | None = None) -> None:
        """Close the conversation. No further messages accepted."""
        if self.status != ConversationStatus.OPEN:
            return
        self.status = ConversationStatus.CLOSED
        self.closed_at = datetime.now(timezone.utc)
        if by_user_id is not None:
            self.closed_by_id = by_user_id

    def archive(self) -> None:
        """Archive the conversation (read-only, hidden from default views)."""
        self.status = ConversationStatus.ARCHIVED

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_open(self) -> bool:
        """True if new messages can be posted."""
        return self.status == ConversationStatus.OPEN

    @property
    def is_client_facing(self) -> bool:
        """True if this conversation is visible to the client."""
        return self.conversation_type == _CONVERSATION_TYPE_CLIENT

    @property
    def is_internal(self) -> bool:
        """True if this is an analyst-only conversation."""
        return self.conversation_type == _CONVERSATION_TYPE_INTERNAL

    @property
    def is_system(self) -> bool:
        """True if this is a system-generated conversation."""
        return self.conversation_type == _CONVERSATION_TYPE_SYSTEM


# ============================================================================
# CASE MESSAGE
# ============================================================================

class CaseMessage(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A single message within a conversation.

    Edits are tracked via ``edited_at`` / ``edit_count``. Deletions are
    soft — the row remains in the DB for compliance, but is excluded from
    queries. Full-text search is powered by the generated ``search_vector``
    column with a GIN index (added by migration).
    """

    __tablename__ = "case_messages"

    __table_args__ = (
        CheckConstraint(
            "edit_count >= 0",
            name="edit_count_non_negative",
        ),
        CheckConstraint(
            "char_length(body) > 0 OR message_type = 'status_change'",
            name="body_required_unless_status_change",
        ),
        Index(
            "ix_case_messages_conversation_created",
            "conversation_id",
            "created_at",
        ),
        Index(
            "ix_case_messages_sender",
            "sender_id",
        ),
        Index(
            "ix_case_messages_reply_to",
            "reply_to_id",
        ),
        # GIN index on search_vector is added by migration:
        # CREATE INDEX ix_case_messages_search_vector ON case_messages
        #     USING gin(search_vector);
    )

    # ─── Parent conversation ────────────────────────────────────────────
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("case_conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning conversation. Deleting the conversation cascades messages.",
    )

    # ─── Author ─────────────────────────────────────────────────────────
    sender_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Author. NULL for system-generated messages.",
    )

    # ─── Content ────────────────────────────────────────────────────────
    message_type: Mapped[MessageType] = mapped_column(
        enum_column_type(MessageType),
        nullable=False,
        default=MessageType.TEXT,
        server_default=MessageType.TEXT.value,
        index=True,
        comment="text | system_event | evidence_reference | status_change.",
    )

    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Message body. Plain text or light markdown.",
    )

    body_html: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Pre-rendered HTML. Populated by the service when markdown is used.",
    )

    # ─── References ─────────────────────────────────────────────────────
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "If this message references a piece of evidence, the FK points "
            "here. Used for evidence_reference messages."
        ),
    )

    reply_to_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("case_messages.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Parent message for threading. NULL for top-level messages.",
    )

    # ─── Flags ──────────────────────────────────────────────────────────
    is_pinned: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="Pinned messages appear at the top of the conversation.",
    )

    # ─── Edit tracking ──────────────────────────────────────────────────
    edited_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the message was last edited. NULL if never edited.",
    )

    edit_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Number of times the message was edited.",
    )

    # ─── Read receipts (JSONB) ─────────────────────────────────────────
    read_by: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Array of {user_id, at} objects. One entry per user who has "
            "read the message. Containment check 'read_by @> [{user_id}]' "
            "is the fast path for unread counts."
        ),
    )

    # ─── Full-text search ──────────────────────────────────────────────
    search_vector: Mapped[str | None] = mapped_column(
        TSVECTOR,
        Computed(
            "to_tsvector('simple', coalesce(body, ''))",
            persisted=True,
        ),
        nullable=True,
        comment=(
            "Auto-computed by PostgreSQL on insert/update. GIN index added "
            "by migration. Do not write directly."
        ),
    )

    # ─── Metadata ──────────────────────────────────────────────────────
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Free-form structured metadata (e.g. status change details).",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("body")
    def _validate_body(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="body must be a string",
                code="MESSAGE_BODY_INVALID_TYPE",
            )
        if len(value) > _MAX_MESSAGE_BODY_LENGTH:
            raise ValidationError(
                message=f"body must not exceed {_MAX_MESSAGE_BODY_LENGTH} characters",
                code="MESSAGE_BODY_TOO_LONG",
            )
        return value

    @validates("message_type")
    def _validate_message_type(
        self, _key: str, value: MessageType | str
    ) -> MessageType:
        if isinstance(value, MessageType):
            return value
        if isinstance(value, str):
            try:
                return MessageType(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid message_type {value!r}",
                    code="MESSAGE_TYPE_INVALID",
                    details={"allowed": list(MessageType.values())},
                ) from exc
        raise ValidationError(
            message="message_type must be a MessageType or string",
            code="MESSAGE_TYPE_INVALID_TYPE",
        )

    @validates("read_by")
    def _validate_read_by(
        self, _key: str, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="read_by must be a list of objects",
                code="MESSAGE_READ_BY_INVALID_TYPE",
            )
        if len(value) > _MAX_READ_BY_ENTRIES:
            raise ValidationError(
                message=f"read_by must not exceed {_MAX_READ_BY_ENTRIES} entries",
                code="MESSAGE_READ_BY_TOO_MANY",
            )
        cleaned: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ValidationError(
                    message="each read_by entry must be an object",
                    code="MESSAGE_READ_BY_ITEM_INVALID_TYPE",
                )
            uid = item.get("user_id")
            if not uid:
                raise ValidationError(
                    message="each read_by entry must have user_id",
                    code="MESSAGE_READ_BY_ITEM_MISSING_USER",
                )
            if uid in seen:
                continue
            seen.add(uid)
            cleaned.append({"user_id": uid, "at": item.get("at")})
        return cleaned

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        conversation_id: uuid.UUID,
        body: str,
        sender_id: uuid.UUID | None = None,
        message_type: MessageType = MessageType.TEXT,
        body_html: str | None = None,
        evidence_id: uuid.UUID | None = None,
        reply_to_id: uuid.UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "CaseMessage":
        """Construct a new message."""
        return cls(
            conversation_id=conversation_id,
            sender_id=sender_id,
            message_type=message_type,
            body=body,
            body_html=body_html,
            evidence_id=evidence_id,
            reply_to_id=reply_to_id,
            metadata_json=metadata or {},
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def edit(self, *, new_body: str, new_body_html: str | None = None) -> None:
        """Update the message body. Increments edit_count."""
        if self.deleted_at is not None:
            raise ValidationError(
                message="Cannot edit a deleted message",
                code="MESSAGE_EDIT_DELETED",
            )
        self.body = new_body
        self.body_html = new_body_html
        self.edited_at = datetime.now(timezone.utc)
        self.edit_count += 1

    def mark_read(self, *, by_user_id: uuid.UUID) -> bool:
        """
        Record that a user has read this message. Returns True if the
        read was new (user had not read before), False if already read.
        """
        uid = str(by_user_id)
        existing = self.read_by or []
        for entry in existing:
            if entry.get("user_id") == uid:
                return False
        if len(existing) >= _MAX_READ_BY_ENTRIES:
            return False
        updated = list(existing)
        updated.append({
            "user_id": uid,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        self.read_by = updated
        return True

    def soft_delete(self) -> None:
        """Soft-delete the message. Body remains in the DB for compliance."""
        if self.deleted_at is None:
            self.deleted_at = datetime.now(timezone.utc)

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_edited(self) -> bool:
        """True if the message has ever been edited."""
        return self.edit_count > 0

    @property
    def is_deleted(self) -> bool:
        """True if the message has been soft-deleted."""
        return self.deleted_at is not None

    @property
    def is_system_generated(self) -> bool:
        """True if this message was generated by the backend, not a user."""
        return self.message_type in (
            MessageType.SYSTEM_EVENT,
            MessageType.STATUS_CHANGE,
        )

    def is_read_by(self, user_id: uuid.UUID) -> bool:
        """True if the given user has read this message."""
        uid = str(user_id)
        for entry in self.read_by or []:
            if entry.get("user_id") == uid:
                return True
        return False


# ============================================================================
# MESSAGE ATTACHMENT
# ============================================================================

class MessageAttachment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A file attached directly to a message.

    Lightweight — no chain of custody, no legal hold, shorter retention.
    For "official" evidence, use ``SecurityEvidence`` instead and link via
    ``CaseMessage.evidence_id``.

    Orphaned attachments (``message_id = NULL``) are cleaned up by the
    background job after 24 hours. This happens when a user pre-uploads a
    file and then abandons the message submission.
    """

    __tablename__ = "message_attachments"

    __table_args__ = (
        CheckConstraint(
            r"content_hash ~ '^[a-f0-9]{64}$'",
            name="content_hash_format",
        ),
        CheckConstraint(
            "file_size_bytes > 0 AND file_size_bytes <= 10485760",
            name="file_size_range",
        ),
        UniqueConstraint(
            "message_id",
            "stored_filename",
            name="uq_message_stored_filename",
        ),
        Index(
            "ix_message_attachments_message_id",
            "message_id",
        ),
        Index(
            "ix_message_attachments_content_hash",
            "content_hash",
        ),
    )

    # ─── Parent message ────────────────────────────────────────────────
    message_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("case_messages.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment=(
            "Owning message. NULL between pre-upload and message creation. "
            "The orphan-cleanup job deletes rows with NULL message_id "
            "older than 24 hours."
        ),
    )

    # ─── Uploader ──────────────────────────────────────────────────────
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ─── File identity ─────────────────────────────────────────────────
    original_filename: Mapped[str] = mapped_column(
        String(_MAX_ORIGINAL_FILENAME_LENGTH), nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(_MAX_STORED_FILENAME_LENGTH),
        nullable=False,
        comment="UUID-based filename on disk. Prevents path traversal.",
    )

    file_extension: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="",
        comment="Lowercase file extension including the leading dot.",
    )

    mime_type: Mapped[str | None] = mapped_column(
        String(_MAX_MIME_LENGTH), nullable=True,
    )

    file_size_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False,
        comment="File size in bytes. Capped at 10 MB by CHECK constraint.",
    )

    content_hash: Mapped[str] = mapped_column(
        String(_MAX_HASH_LENGTH),
        nullable=False,
        comment="SHA-256 hex of file contents. Used for dedup and malware scan.",
    )

    # ─── Metadata ──────────────────────────────────────────────────────
    download_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="How many times the attachment has been downloaded.",
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("content_hash")
    def _validate_hash(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="content_hash must be a string",
                code="ATTACHMENT_HASH_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not _SHA256_PATTERN.match(normalized):
            raise ValidationError(
                message="content_hash must be 64 lowercase hex characters",
                code="ATTACHMENT_HASH_INVALID_FORMAT",
            )
        return normalized

    @validates("stored_filename")
    def _validate_stored_filename(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(
                message="stored_filename must be a non-empty string",
                code="ATTACHMENT_STORED_FILENAME_INVALID",
            )
        stripped = value.strip()
        if len(stripped) > _MAX_STORED_FILENAME_LENGTH:
            raise ValidationError(
                message=f"stored_filename must not exceed {_MAX_STORED_FILENAME_LENGTH} characters",
                code="ATTACHMENT_STORED_FILENAME_TOO_LONG",
            )
        if "/" in stripped or "\\" in stripped or ".." in stripped:
            raise ValidationError(
                message=(
                    "stored_filename must not contain path separators or "
                    "traversal sequences"
                ),
                code="ATTACHMENT_STORED_FILENAME_INVALID_FORMAT",
            )
        return stripped

    @validates("file_extension")
    def _validate_extension(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="file_extension must be a string",
                code="ATTACHMENT_EXTENSION_INVALID_TYPE",
            )
        lowered = value.strip().lower()
        if not lowered:
            return ""
        if not lowered.startswith("."):
            lowered = "." + lowered
        if lowered in _ATTACHMENT_DENIED_EXTENSIONS:
            raise ValidationError(
                message=f"file extension {lowered!r} is not permitted",
                code="ATTACHMENT_EXTENSION_DENIED",
            )
        if lowered not in _ATTACHMENT_ALLOWED_EXTENSIONS:
            raise ValidationError(
                message=f"file extension {lowered!r} is not in the allowed set",
                code="ATTACHMENT_EXTENSION_NOT_ALLOWED",
                details={"allowed": sorted(_ATTACHMENT_ALLOWED_EXTENSIONS)},
            )
        return lowered

    @validates("file_size_bytes")
    def _validate_file_size(self, _key: str, value: int) -> int:
        if not isinstance(value, int):
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValidationError(
                    message="file_size_bytes must be an integer",
                    code="ATTACHMENT_SIZE_INVALID_TYPE",
                ) from exc
        if value <= 0:
            raise ValidationError(
                message="file_size_bytes must be positive",
                code="ATTACHMENT_SIZE_NOT_POSITIVE",
            )
        if value > _MAX_ATTACHMENT_SIZE_BYTES:
            raise ValidationError(
                message=f"file_size_bytes must not exceed {_MAX_ATTACHMENT_SIZE_BYTES}",
                code="ATTACHMENT_SIZE_TOO_LARGE",
            )
        return value

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        original_filename: str,
        stored_filename: str,
        content_hash: str,
        file_size_bytes: int,
        message_id: uuid.UUID | None = None,
        uploaded_by_id: uuid.UUID | None = None,
        mime_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "MessageAttachment":
        """Construct a new attachment. ``message_id`` may be NULL for pre-uploads."""
        ext = ""
        if "." in original_filename:
            ext = "." + original_filename.rsplit(".", 1)[1].lower()
        return cls(
            message_id=message_id,
            uploaded_by_id=uploaded_by_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_extension=ext,
            mime_type=mime_type,
            file_size_bytes=file_size_bytes,
            content_hash=content_hash,
            metadata_json=metadata or {},
        )

    # ====================================================================
    # STORAGE
    # ====================================================================

    def get_storage_path(self) -> Path:
        """
        Compute the on-disk path.

        Layout: {UPLOAD_DIR}/message_attachments/{stored_filename}
        """
        base = Path(settings.UPLOAD_DIR).resolve()
        return base / "message_attachments" / self.stored_filename

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_orphaned(self) -> bool:
        """True if this attachment has no parent message (pre-upload)."""
        return self.message_id is None


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.case import SecurityCase
#     from app.models.user import User
#     from app.models.evidence import SecurityEvidence
#
# class CaseConversation(...):
#     ...
#     case: Mapped["SecurityCase"] = relationship(
#         "SecurityCase", back_populates="conversations"
#     )
#     created_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[created_by_id]
#     )
#     messages: Mapped[list["CaseMessage"]] = relationship(
#         "CaseMessage",
#         back_populates="conversation",
#         cascade="all, delete-orphan",
#     )
#
# class CaseMessage(...):
#     ...
#     conversation: Mapped["CaseConversation"] = relationship(
#         "CaseConversation", back_populates="messages"
#     )
#     sender: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[sender_id]
#     )
#     evidence: Mapped["SecurityEvidence | None"] = relationship(
#         "SecurityEvidence"
#     )
#     reply_to: Mapped["CaseMessage | None"] = relationship(
#         "CaseMessage",
#         remote_side="CaseMessage.id",
#         foreign_keys=[reply_to_id],
#     )
#     attachments: Mapped[list["MessageAttachment"]] = relationship(
#         "MessageAttachment",
#         back_populates="message",
#         cascade="all, delete-orphan",
#     )
#
# class MessageAttachment(...):
#     ...
#     message: Mapped["CaseMessage | None"] = relationship(
#         "CaseMessage", back_populates="attachments"
#     )
#     uploaded_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[uploaded_by_id]
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "CaseConversation",
    "CaseMessage",
    "MessageAttachment",
    "_CONVERSATION_TYPE_CLIENT",
    "_CONVERSATION_TYPE_INTERNAL",
    "_CONVERSATION_TYPE_SYSTEM",
    "_VALID_CONVERSATION_TYPES",
    "_ATTACHMENT_ALLOWED_EXTENSIONS",
    "_ATTACHMENT_DENIED_EXTENSIONS",
    "_MAX_ATTACHMENT_SIZE_BYTES",
    "_MAX_MESSAGE_BODY_LENGTH",
    "_MAX_TITLE_LENGTH",
    "_MAX_STORED_FILENAME_LENGTH",
    "_MAX_ORIGINAL_FILENAME_LENGTH",
    "_MAX_MIME_LENGTH",
    "_MAX_HASH_LENGTH",
    "_MAX_METADATA_BYTES",
    "_MAX_READ_BY_ENTRIES",
    "_SHA256_PATTERN",
]