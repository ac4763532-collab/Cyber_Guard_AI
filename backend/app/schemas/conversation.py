"""
CyberGuard AI — Conversation & Message Schemas
============================================================================

Request/response DTOs for the communication layer of a case:

    - ``case_conversations``   — thread containers (client / internal / system)
    - ``case_messages``        — individual messages (full-text searchable)
    - ``message_attachments``  — file attachments on messages (lightweight)

Design rules
------------
1. **Conversation type determines audience.**
   ``client``     — visible to client + assigned analyst + anyone with
                    ``conversation_read`` or ``full_case`` grant.
   ``internal``   — visible only to analysts. NEVER visible to client.
   ``system``     — automated messages, no replies.

   This is enforced by the service + authorization service, but the
   schema separation makes the intent explicit: a client-facing
   endpoint uses ``ClientMessageRead``; an analyst-facing endpoint
   uses ``MessageRead``.

2. **Message body length is bounded (50 KB).**
   Larger than titles, smaller than attachments. A message with more
   content than that should be an attachment.

3. **Attachments are optional per message.**
   A message can reference a piece of existing ``SecurityEvidence``
   (``evidence_id``) OR carry its own lightweight attachment — but
   not both in the same message. Enforced by the service.

4. **Read receipts are per-user.**
   ``mark_read_at`` on ``MessageRead`` reflects the current user's
   read state. The full ``read_by`` list is only included in
   ``MessageReadWithReceipts``, used when an analyst explicitly
   wants to check who has read a message.

5. **Message threading is one level deep.**
   ``reply_to_id`` points to a top-level message. Replies to replies
   are flattened to the parent for simplicity — the ``thread_depth``
   field in the model was never needed, so we don't expose it.

6. **Edits are tracked but not versioned.**
   ``edited_at`` and ``edit_count`` are exposed. Full revision
   history requires a separate ``message_revisions`` table — future
   feature. For now, edits overwrite in place and are visible via the
   ``is_edited`` flag.

7. **Soft-delete is visible.**
   ``is_deleted`` is exposed on read schemas so the client can show
   "[message deleted]" rather than disappearing the row (which would
   break threading).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import (
    ConversationStatus,
    MessageType,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_CONVERSATION_TYPES = frozenset({"client", "internal", "system"})

_TITLE_MAX = 255
_BODY_MAX = 50_000
_BODY_HTML_MAX = 50_000
_MIME_MAX = 128
_STORED_FILENAME_MAX = 128
_ORIGINAL_FILENAME_MAX = 255
_SHA256_LENGTH = 64

#: Per-attachment size cap (10 MB — smaller than evidence since
#: attachments are informal).
_MAX_ATTACHMENT_SIZE_BYTES = 10_485_760


# ============================================================================
# CONVERSATION — CREATE
# ============================================================================

class ConversationCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /cases/{id}/conversations``.

    Standard cases get one client thread and one internal thread
    auto-created at case creation time. This endpoint exists for
    explicitly adding more threads (e.g. a sub-topic) — rare but
    supported.
    """

    conversation_type: str = Field(
        ...,
        description="client | internal | system",
    )
    title: str | None = Field(default=None, max_length=_TITLE_MAX)

    @field_validator("conversation_type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _CONVERSATION_TYPES:
            raise ValueError(
                f"conversation_type must be one of {sorted(_CONVERSATION_TYPES)}"
            )
        return normalized


# ============================================================================
# CONVERSATION — READ
# ============================================================================

class ConversationRead(TimestampedModel):
    """
    Full conversation view. Returned by ``GET /conversations/{id}``.

    Includes the denormalized ``last_message_at`` and ``message_count``
    so clients can render a conversation list without fetching
    individual messages.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    case_id: uuid.UUID
    conversation_type: str
    title: str | None = None
    status: ConversationStatus
    created_by_id: uuid.UUID | None = None
    closed_at: datetime | None = None
    closed_by_id: uuid.UUID | None = None
    last_message_at: datetime | None = None
    message_count: int = 0
    settings: dict[str, Any] = Field(default_factory=dict)

    # Computed
    is_open: bool = Field(..., description="True if new messages can be posted.")
    is_client_facing: bool = Field(..., description="True if this is a client conversation.")
    is_internal: bool = Field(..., description="True if this is an analyst-only conversation.")
    is_system: bool = Field(..., description="True if system-generated.")


class ConversationList(ORMModel):
    """
    Lightweight conversation view for a case sidebar.
    """

    id: uuid.UUID
    case_id: uuid.UUID
    conversation_type: str
    title: str | None = None
    status: ConversationStatus
    last_message_at: datetime | None = None
    message_count: int = 0


# ============================================================================
# CONVERSATION — UPDATE
# ============================================================================

class ConversationUpdate(CyberGuardBaseSchema):
    """
    Only the title is user-editable. ``conversation_type`` and
    ``case_id`` are set at creation — changing them would break the
    access control model.
    """

    title: str | None = Field(default=None, max_length=_TITLE_MAX)


# ============================================================================
# MESSAGE — CREATE
# ============================================================================

class MessageCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /conversations/{id}/messages``.

    If ``evidence_id`` is set, the message references an existing
    piece of evidence (a ``SecurityEvidence`` row). This is a distinct
    workflow from uploading an attachment: evidence has full chain of
    custody, attachments do not.

    Attachments are uploaded separately (multipart endpoint), then
    linked by ``message_id`` after the message is created. See
    ``MessageAttachmentRead``.
    """

    body: str = Field(
        ...,
        min_length=1,
        max_length=_BODY_MAX,
        description="Message text. Light markdown allowed.",
    )
    body_html: str | None = Field(
        default=None,
        max_length=_BODY_HTML_MAX,
        description=(
            "Pre-rendered HTML. Only accepted from server-side rendering — "
            "clients should send plain text in ``body`` and let the "
            "backend render. This field exists for service-injected "
            "messages (system events, etc.)."
        ),
    )

    message_type: MessageType = Field(
        default=MessageType.TEXT,
        description="text | evidence_reference | system_event | status_change",
    )

    evidence_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If set, this message references an existing piece of "
            "evidence. Mutually exclusive with uploading a new attachment "
            "in the same request."
        ),
    )

    reply_to_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Parent message ID for threading. One level deep — replies "
            "to replies inherit the top-level parent."
        ),
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Extra structured context. Shape varies by message_type — "
            "e.g. status_change messages include {from, to}."
        ),
    )

    @field_validator("body")
    @classmethod
    def _clean_body(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("body must not be empty")
        return v

    @field_validator("message_type")
    @classmethod
    def _validate_message_type(cls, v: MessageType, info) -> MessageType:
        # Only analysts can create system_event / status_change messages.
        # That enforcement happens in the service (they need the current
        # user's role), but the schema-level check for evidence_id +
        # message_type is doable here.
        evidence_id = info.data.get("evidence_id")
        if evidence_id is not None and v == MessageType.SYSTEM_EVENT:
            raise ValueError(
                "evidence_id cannot be combined with message_type='system_event'. "
                "System events are generated by the backend, not attached to "
                "user evidence."
            )
        return v


# ============================================================================
# MESSAGE — READ
# ============================================================================

class MessageRead(TimestampedModel):
    """
    Full message view. Returned by ``GET /messages/{id}`` and by list
    endpoints.

    ``read_by`` is **not** included — it's per-user and could be long.
    Use ``MessageReadWithReceipts`` when read state matters.
    """

    id: uuid.UUID
    conversation_id: uuid.UUID
    sender_id: uuid.UUID | None = None
    message_type: MessageType
    body: str
    body_html: str | None = None
    evidence_id: uuid.UUID | None = None
    reply_to_id: uuid.UUID | None = None
    is_pinned: bool = False
    edited_at: datetime | None = None
    edit_count: int = 0
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_edited: bool = Field(..., description="True if the message has been edited.")
    is_deleted: bool = Field(..., description="True if the message has been soft-deleted.")
    is_system_generated: bool = Field(
        ..., description="True if generated by the backend (not a user).",
    )


class MessageReadWithReceipts(MessageRead):
    """
    Message view with read receipts. Used by analyst-facing endpoints
    when the user explicitly wants to know who has seen a message.
    """

    read_by: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of {user_id, at} objects.",
    )


class MessageList(ORMModel):
    """
    Lightweight message view for conversation history.
    """

    id: uuid.UUID
    conversation_id: uuid.UUID
    sender_id: uuid.UUID | None = None
    message_type: MessageType
    body: str
    is_pinned: bool = False
    is_edited: bool = False
    is_deleted: bool = False
    created_at: datetime
    edited_at: datetime | None = None


# ============================================================================
# MESSAGE — UPDATE
# ============================================================================

class MessageUpdate(CyberGuardBaseSchema):
    """
    Only the body can be edited. ``sender_id``, ``message_type``, and
    the conversation are immutable. ``is_pinned`` is a separate
    endpoint (pinning is a moderation action).

    Edits increment ``edit_count`` and set ``edited_at``. Full revision
    history is not exposed (would require a ``message_revisions`` table).
    """

    body: str = Field(..., min_length=1, max_length=_BODY_MAX)
    body_html: str | None = Field(default=None, max_length=_BODY_HTML_MAX)

    @field_validator("body")
    @classmethod
    def _clean_body(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("body must not be empty")
        return v


class MessagePinUpdate(CyberGuardBaseSchema):
    """Request body for ``PATCH /messages/{id}/pin``."""

    is_pinned: bool = Field(...)


# ============================================================================
# ATTACHMENTS
# ============================================================================

class MessageAttachmentRead(TimestampedModel):
    """
    Attachment on a message. Files are stored under a UUID-based name
    (never the client-supplied filename) to prevent path traversal.

    Attachments have ``content_hash`` for deduplication but no
    chain of custody — they are informal, not evidence.
    """

    id: uuid.UUID
    message_id: uuid.UUID | None = None
    uploaded_by_id: uuid.UUID | None = None
    original_filename: str
    stored_filename: str
    file_extension: str
    mime_type: str | None = None
    file_size_bytes: int
    content_hash: str
    download_count: int = 0
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_orphaned: bool = Field(
        ...,
        description=(
            "True if the attachment was uploaded but not yet attached to "
            "a message. Orphaned attachments are cleaned up after 24h."
        ),
    )


class MessageAttachmentUploadMetadata(CyberGuardBaseSchema):
    """
    Metadata for uploading an attachment. The file is sent as
    ``UploadFile`` in a multipart request — not part of this schema.
    """

    original_filename: str = Field(
        ..., min_length=1, max_length=_ORIGINAL_FILENAME_MAX,
    )

    message_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If provided, attaches to this message immediately. "
            "If omitted, the attachment is orphaned and must be "
            "attached later (typical flow: upload first, send message "
            "with attachment references)."
        ),
    )

    @field_validator("original_filename")
    @classmethod
    def _validate_filename(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("original_filename must not be empty")
        if "/" in stripped or "\\" in stripped:
            raise ValueError(
                "original_filename must not contain path separators"
            )
        return stripped


# ============================================================================
# FILTER
# ============================================================================

class MessageFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering messages within a conversation.
    """

    sender_id: uuid.UUID | None = None
    message_type: MessageType | None = None
    is_pinned: bool | None = None
    has_attachments: bool | None = Field(
        default=None,
        description=(
            "If True, only messages with at least one attachment; "
            "False, only messages without."
        ),
    )

    created_after: datetime | None = None
    created_before: datetime | None = None

    body_contains: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Case-insensitive substring match on body. For larger "
            "searches use the full-text-search endpoint (future)."
        ),
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ConversationCreate",
    "ConversationRead",
    "ConversationList",
    "ConversationUpdate",
    "MessageCreate",
    "MessageRead",
    "MessageReadWithReceipts",
    "MessageList",
    "MessageUpdate",
    "MessagePinUpdate",
    "MessageAttachmentRead",
    "MessageAttachmentUploadMetadata",
    "MessageFilter",
]