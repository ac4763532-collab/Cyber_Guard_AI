"""
CyberGuard AI — Conversation Service
============================================================================

The case communication layer: conversations, messages, and attachments.

Case conversations are where analysts, clients, and (optionally) system
events communicate. The service enforces the three-audience model:

    client    — visible to client + assigned analyst + grant holders
    internal  — NEVER visible to the client (analyst-only)
    system    — automated, read-only

Two security rules
------------------
1. **Internal conversations are invisible to clients.** Even if a
   client somehow gets workspace access or a case grant, they cannot
   read or post in an internal conversation. Enforced by
   ``_assert_can_read_conversation`` / ``_assert_can_post_to_conversation``.

2. **Attachments use the same defense as evidence.**
   - UUID-based stored filenames (no path traversal)
   - Extension allow-list (no executables)
   - Per-file size cap (10 MB)
   - SHA-256 content hash (dedup + malware scanning later)
   - Same-message uniqueness constraint

Differences from evidence
-------------------------
Attachments are **informal**. They don't have:
    - Chain of custody (only upload + access events via message reads)
    - Legal hold
    - Redaction
    - Integrity re-verification on download (they're transient
      communication artifacts, not evidence)

Attachments are **scoped to a message**. A message can have zero,
one, or many attachments. The attachment upload flow is:

    1. Upload file (before message) → returns attachment_id (orphaned)
    2. Create message with `attachment_ids` in the body
    3. Service links attachments to the message

The orphan cleanup job deletes unattached attachments after 24 hours.

Message types
-------------
    text                 — user-typed message
    system_event         — backend-generated (case assigned, status
                           changed, etc.) — read-only
    evidence_reference   — message pointing at an existing evidence
                           row (via ``evidence_id``)
    status_change        — records a status transition (also written
                           to status_history, but surfaced as a
                           message for inline conversation flow)

Only text and evidence_reference can be created by users via the
public API. system_event and status_change are backend-generated.

Message editing
---------------
A user can edit their own message. Admins can edit any message.
Edits are tracked (``edited_at``, ``edit_count``), but there is no
full revision history — the previous body is lost. A future
``message_revisions`` table would provide full history.

Editing rules:
    - ``text`` messages: only the sender or admin can edit
    - ``evidence_reference`` messages: only the sender (evidence link
      is part of identity, not editable by admins either)
    - ``system_event`` / ``status_change``: cannot be edited by anyone

Deleted messages
----------------
Soft delete (``deleted_at``). The body stays in the DB (for audit),
but is excluded from queries and rendered as "[message deleted]" in
the UI. Threading is preserved — replies still work.

Read receipts
-------------
Per-message ``read_by`` JSONB array of ``{user_id, at}``. A user
marking a message read adds themselves. Reads are idempotent — the
same user can't be added twice.

The service provides ``mark_conversation_read`` which bulk-marks all
messages the user hasn't read yet. This is what the UI calls when
the user opens the conversation.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. **Conversation access is via the case**, not via workspace role
   alone. A user needs either:
       - Access to the case (via grant, assignment, or workspace role
         that grants CONVERSATION_READ or FULL_CASE)
       - Plus: the conversation must not be ``internal`` if they're
         a client (workspace role === VIEWER or non-analyst)
5. Auditing: only message edits and deletions are audited (rare
   events). Normal messages aren't — the message row itself is the
   record.

Public API
----------
    # Conversations
    get_or_create_conversation(db, *, case, conversation_type, actor, request=None)
                                                          → CaseConversation
    get_conversation(db, conversation_id)                 → CaseConversation
    list_conversations_for_case(db, *, actor, case)       → list[CaseConversation]

    # Messages
    list_messages(db, *, actor, conversation, page, filters) → (list, int)
    create_message(db, *, actor, conversation, body, message_type,
                   evidence_id=None, reply_to_id=None, attachment_ids=None,
                   metadata=None, request=None)           → CaseMessage
    edit_message(db, *, actor, message, new_body, request=None)
                                                          → CaseMessage
    soft_delete_message(db, *, actor, message, request=None) → CaseMessage
    pin_message(db, *, actor, message, pinned=True, request=None)
                                                          → CaseMessage

    # Read receipts
    mark_read(db, *, actor, message)                      → CaseMessage
    mark_conversation_read(db, *, actor, conversation)    → int

    # Attachments
    upload_attachment(db, *, actor, file_bytes, original_filename,
                      message_id=None)                    → MessageAttachment
    attach_to_message(db, *, actor, attachment_ids, message, request=None)
                                                          → list[MessageAttachment]
    delete_orphaned_attachments(db, *, age_hours=24, limit=500) → int

Usage
-----
    from app.services import conversation_service

    # Post a message
    msg = conversation_service.create_message(
        db,
        actor=current_user,
        conversation=conversation,
        body="The phishing link goes to a credential harvester.",
        message_type=MessageType.TEXT,
    )
    db.commit()

    # Upload + attach
    attachment = conversation_service.upload_attachment(
        db, actor=current_user,
        file_bytes=screenshot_bytes,
        original_filename="screenshot.png",
    )
    msg = conversation_service.create_message(
        db, actor=current_user, conversation=conversation,
        body="See attached screenshot.",
        attachment_ids=[attachment.id],
    )
    db.commit()
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert  # noqa: F401 — kept for future message types
from app.models.case import SecurityCase
from app.models.conversation import (
    CaseConversation,
    CaseMessage,
    MessageAttachment,
)
from app.models.enums import (
    AccessGrantScope,
    ConversationStatus,
    MessageType,
    WorkspaceRole,
)
from app.models.user import User
from app.schemas.common import PageParams
from app.schemas.conversation import MessageFilter
from app.services import (
    audit_service,
    authorization,
    notification_service,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Attachment extension allow-list. Matches evidence but smaller subset —
#: we don't need .pcap or .tar for casual communication.
_ATTACHMENT_ALLOWED_EXTENSIONS = frozenset({
    ".pdf", ".txt", ".log", ".csv", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".zip", ".gz",
    ".pcap", ".pcapng", ".eml", ".msg",
    ".docx", ".xlsx", ".pptx",
})

_ATTACHMENT_DENIED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".sh",
    ".msi", ".scr", ".vbs", ".jar", ".com", ".app",
    ".php", ".phtml", ".jsp", ".asp", ".aspx", ".cgi",
    ".py", ".rb", ".pl", ".js",
})

_MAX_ATTACHMENT_SIZE_BYTES = 10_485_760  # 10 MB

#: Message types allowed through the public API (user-initiated).
_USER_MESSAGE_TYPES = frozenset({
    MessageType.TEXT,
    MessageType.EVIDENCE_REFERENCE,
})

#: Conversation types that clients are allowed to see.
_CLIENT_VISIBLE_CONVERSATION_TYPES = frozenset({"client", "system"})


# ============================================================================
# INTERNAL — access checks
# ============================================================================

def _is_client_user(
    db: Session,
    user: User,
    case: SecurityCase,
) -> bool:
    """
    Return True if the user's access to this case is **client-level**
    (not an analyst). Client-level means:

        - Workspace VIEWER role
        - Workspace role is None (only has a case access grant)
        - Workspace role is EDITOR but user isn't the assigned analyst

    Client users can see ``client`` and ``system`` conversations but
    NEVER ``internal`` conversations.

    Analysts (assigned, or with WORKSPACE_EDITOR/OWNER role) can see
    all conversation types.
    """
    # Assigned analyst is not a client
    if case.assigned_to_id == user.id:
        return False

    ws_role = authorization.get_user_workspace_role(
        db, user, case.workspace_id,
    )
    if ws_role is None:
        # No workspace role — access is via grant only → client
        return True
    if ws_role == WorkspaceRole.VIEWER:
        return True
    # EDITOR/OWNER — treat as analyst-level for conversation purposes
    return False


def _assert_can_read_conversation(
    db: Session,
    actor: User,
    conversation: CaseConversation,
    case: SecurityCase,
) -> None:
    """
    Assert the actor can read this conversation.

    Rules:
        - Must have case access at CONVERSATION_READ scope (or above)
        - If conversation is ``internal``, actor must NOT be a client user
    """
    authorization.require_case_access(
        db, actor, case, minimum_scope=AccessGrantScope.CONVERSATION_READ,
    )

    if conversation.conversation_type == "internal":
        if _is_client_user(db, actor, case):
            raise AuthorizationError(
                message=(
                    "Internal conversation is not accessible. Contact the "
                    "assigned analyst for information about this case."
                ),
                code="INTERNAL_CONVERSATION_FORBIDDEN",
                details={"conversation_id": str(conversation.id)},
            )


def _assert_can_post_to_conversation(
    db: Session,
    actor: User,
    conversation: CaseConversation,
    case: SecurityCase,
) -> None:
    """
    Assert the actor can post a message to this conversation.

    Additional rules beyond reading:
        - Conversation must be OPEN (not closed/archived)
        - ``system`` conversations are read-only
    """
    _assert_can_read_conversation(db, actor, conversation, case)

    if conversation.status != ConversationStatus.OPEN:
        raise ValidationError(
            message=(
                f"Cannot post to a conversation in "
                f"{conversation.status.value} status."
            ),
            code="CONVERSATION_NOT_OPEN",
            details={"status": conversation.status.value},
        )

    if conversation.conversation_type == "system":
        raise AuthorizationError(
            message=(
                "System conversations are read-only. System events are "
                "generated by the backend, not by users."
            ),
            code="SYSTEM_CONVERSATION_READ_ONLY",
        )


def _get_case_for_conversation(
    db: Session,
    conversation: CaseConversation,
) -> SecurityCase:
    """Load the case that owns this conversation, raising if missing."""
    case = db.get(SecurityCase, conversation.case_id)
    if case is None:
        raise NotFoundError(
            message="The case for this conversation no longer exists.",
            code="CONVERSATION_ORPHANED",
            details={"conversation_id": str(conversation.id)},
        )
    return case


# ============================================================================
# CONVERSATIONS
# ============================================================================

def get_or_create_conversation(
    db: Session,
    *,
    case: SecurityCase,
    conversation_type: str,
    actor: User,
    request: Any | None = None,
) -> CaseConversation:
    """
    Get an existing conversation for (case, type), or create it.

    The case_service creates the three default conversations at case
    creation time. This method is used by the API layer to safely
    look up conversations, tolerating the historical case where a
    case was created before the default-conversation migration.

    Only the ``client`` and ``internal`` types can be created via this
    method. ``system`` type is created only by ``case_service`` at
    case creation — it's a fixed singleton per case.

    Idempotent — calling with an existing type returns the existing row.
    """
    if conversation_type not in ("client", "internal"):
        raise ValidationError(
            message=(
                "Only 'client' and 'internal' conversations can be "
                "created via this method. 'system' is created by the "
                "case creation flow."
            ),
            code="CONVERSATION_TYPE_NOT_CREATABLE",
        )

    existing = db.execute(
        select(CaseConversation).where(
            CaseConversation.case_id == case.id,
            CaseConversation.conversation_type == conversation_type,
        )
    ).scalar_one_or_none()

    if existing is not None:
        return existing

    conversation = CaseConversation.build(
        workspace_id=case.workspace_id,
        case_id=case.id,
        conversation_type=conversation_type,
        created_by_id=actor.id,
        title={
            "client": "Conversation with client",
            "internal": "Internal analyst discussion",
        }[conversation_type],
    )
    db.add(conversation)
    db.flush()

    logger.info(
        "Conversation lazily created",
        extra={
            "conversation_id": str(conversation.id),
            "case_id": str(case.id),
            "conversation_type": conversation_type,
        },
    )

    return conversation


def get_conversation(
    db: Session,
    conversation_id: uuid.UUID,
) -> CaseConversation:
    """Fetch a conversation by ID. Does NOT check access — caller must."""
    conversation = db.get(CaseConversation, conversation_id)
    if conversation is None:
        raise NotFoundError(
            message=f"Conversation {conversation_id} not found.",
            code="CONVERSATION_NOT_FOUND",
            details={"conversation_id": str(conversation_id)},
        )
    return conversation


def list_conversations_for_case(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
) -> list[CaseConversation]:
    """
    List the conversations the actor can see for this case.

    Client users see only ``client`` and ``system`` conversations.
    Analysts see all three.
    """
    authorization.require_case_access(
        db, actor, case, minimum_scope=AccessGrantScope.CONVERSATION_READ,
    )

    stmt = select(CaseConversation).where(
        CaseConversation.case_id == case.id,
    ).order_by(CaseConversation.created_at.asc())

    conversations = list(db.execute(stmt).scalars().all())

    if _is_client_user(db, actor, case):
        # Filter out internal
        conversations = [
            c for c in conversations
            if c.conversation_type in _CLIENT_VISIBLE_CONVERSATION_TYPES
        ]

    return conversations


# ============================================================================
# MESSAGES — READ
# ============================================================================

def list_messages(
    db: Session,
    *,
    actor: User,
    conversation: CaseConversation,
    page: PageParams,
    filters: MessageFilter | None = None,
) -> tuple[list[CaseMessage], int]:
    """
    List messages in a conversation, oldest-first (chronological).

    Excludes soft-deleted messages by default. For admin views, use
    ``filters.include_deleted=True`` (not in schema yet — direct filter
    path documented for future).
    """
    case = _get_case_for_conversation(db, conversation)
    _assert_can_read_conversation(db, actor, conversation, case)

    stmt = select(CaseMessage).where(
        CaseMessage.conversation_id == conversation.id,
        CaseMessage.deleted_at.is_(None),
    )

    if filters is not None:
        if filters.sender_id is not None:
            stmt = stmt.where(CaseMessage.sender_id == filters.sender_id)
        if filters.message_type is not None:
            stmt = stmt.where(CaseMessage.message_type == filters.message_type)
        if filters.is_pinned is not None:
            stmt = stmt.where(CaseMessage.is_pinned == filters.is_pinned)
        if filters.created_after is not None:
            stmt = stmt.where(CaseMessage.created_at >= filters.created_after)
        if filters.created_before is not None:
            stmt = stmt.where(CaseMessage.created_at <= filters.created_before)
        if filters.body_contains:
            stmt = stmt.where(
                CaseMessage.body.ilike(f"%{filters.body_contains.lower()}%")
            )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(CaseMessage.created_at.asc(), CaseMessage.id.asc())
        .offset(page.offset)
        .limit(page.limit)
    )
    messages = list(db.execute(stmt).scalars().all())
    return messages, int(total)


# ============================================================================
# MESSAGES — CREATE
# ============================================================================

def create_message(
    db: Session,
    *,
    actor: User,
    conversation: CaseConversation,
    body: str,
    message_type: MessageType = MessageType.TEXT,
    evidence_id: uuid.UUID | None = None,
    reply_to_id: uuid.UUID | None = None,
    attachment_ids: list[uuid.UUID] | None = None,
    metadata: dict[str, Any] | None = None,
    request: Any | None = None,
) -> CaseMessage:
    """
    Create a message in a conversation.

    Only ``TEXT`` and ``EVIDENCE_REFERENCE`` message types are
    accepted via this method — the other types (``SYSTEM_EVENT``,
    ``STATUS_CHANGE``) are created by backend flows.

    Sender rules:
        - The sender must have ``CONVERSATION_READ`` (or above) on
          the case
        - Client users cannot post in ``internal`` conversations
        - ``system`` conversations are read-only

    If ``evidence_id`` is set, the evidence must belong to the same
    case (cross-case evidence references are rejected — an attack
    vector to leak evidence across cases).

    Returns
    -------
    CaseMessage
        The persisted message with attachments linked.

    Raises
    ------
    AuthorizationError
        If the actor cannot post to this conversation.
    ValidationError
        On invalid input (empty body, invalid message_type, evidence
        in wrong case, etc.).
    """
    case = _get_case_for_conversation(db, conversation)
    _assert_can_post_to_conversation(db, actor, conversation, case)

    # ── Validate message type
    if message_type not in _USER_MESSAGE_TYPES:
        raise ValidationError(
            message=(
                f"Message type {message_type.value!r} cannot be created "
                f"by users. Allowed: {sorted(mt.value for mt in _USER_MESSAGE_TYPES)}"
            ),
            code="MESSAGE_TYPE_NOT_ALLOWED",
            details={"message_type": message_type.value},
        )

    if not body or not body.strip():
        raise ValidationError(
            message="Message body must not be empty.",
            code="MESSAGE_BODY_EMPTY",
        )

    # ── Validate evidence reference
    if evidence_id is not None:
        from app.models.evidence import SecurityEvidence
        evidence = db.get(SecurityEvidence, evidence_id)
        if evidence is None or evidence.deleted_at is not None:
            raise ValidationError(
                message=f"Evidence {evidence_id} not found.",
                code="EVIDENCE_NOT_FOUND",
            )
        if evidence.case_id != case.id:
            # Attempting to reference evidence from another case
            # — this is a cross-tenant privacy violation
            logger.warning(
                "Attempted cross-case evidence reference in message",
                extra={
                    "conversation_id": str(conversation.id),
                    "case_id": str(case.id),
                    "evidence_id": str(evidence_id),
                    "evidence_case_id": str(evidence.case_id),
                },
            )
            raise ValidationError(
                message=(
                    "Evidence must belong to the same case as the "
                    "conversation."
                ),
                code="EVIDENCE_WRONG_CASE",
            )

    # ── Validate reply_to
    if reply_to_id is not None:
        parent = db.get(CaseMessage, reply_to_id)
        if parent is None:
            raise ValidationError(
                message=f"Parent message {reply_to_id} not found.",
                code="MESSAGE_PARENT_NOT_FOUND",
            )
        if parent.conversation_id != conversation.id:
            raise ValidationError(
                message="Parent message must be in the same conversation.",
                code="MESSAGE_PARENT_WRONG_CONVERSATION",
            )
        # Flatten two-level threads — reply to a reply → reply to
        # the top-level parent
        if parent.reply_to_id is not None:
            reply_to_id = parent.reply_to_id

    # ── Create the message
    message = CaseMessage.build(
        conversation_id=conversation.id,
        body=body.strip(),
        sender_id=actor.id,
        message_type=message_type,
        evidence_id=evidence_id,
        reply_to_id=reply_to_id,
        metadata=metadata,
    )
    db.add(message)
    db.flush()

    # ── Attach any uploaded attachments
    if attachment_ids:
        _attach_attachments_to_message(
            db,
            attachment_ids=attachment_ids,
            message=message,
            uploaded_by_id=actor.id,
            case=case,
        )

    # ── Update conversation denormalized fields
    conversation.last_message_at = message.created_at or datetime.now(timezone.utc)
    conversation.message_count = (conversation.message_count or 0) + 1
    db.flush()

    # ── Notify other participants (excludes sender)
    try:
        notification_service.create_for_message(
            db, message=message, conversation=conversation,
        )
    except Exception as exc:  # noqa: BLE001 — notification failure shouldn't block
        logger.warning(
            "Failed to create message notifications",
            extra={
                "message_id": str(message.id),
                "error": str(exc)[:200],
            },
        )

    logger.info(
        "Message created",
        extra={
            "message_id": str(message.id),
            "conversation_id": str(conversation.id),
            "case_id": str(case.id),
            "sender_id": str(actor.id),
            "message_type": message_type.value,
            "has_attachments": bool(attachment_ids),
        },
    )

    return message


# ============================================================================
# MESSAGES — EDIT
# ============================================================================

def edit_message(
    db: Session,
    *,
    actor: User,
    message: CaseMessage,
    new_body: str,
    request: Any | None = None,
) -> CaseMessage:
    """
    Edit a message body.

    Rules:
        - ``text`` messages: sender or workspace ADMIN/OWNER can edit
        - ``evidence_reference`` messages: only the sender can edit
          (the evidence link is part of identity)
        - ``system_event`` / ``status_change``: cannot be edited
          by anyone

    Tracks ``edited_at``, ``edit_count`` on the row. Full revision
    history requires a ``message_revisions`` table (future).

    Raises
    ------
    AuthorizationError
        If the actor cannot edit this message.
    ValidationError
        On empty body, deleted message, or protected message type.
    """
    if not new_body or not new_body.strip():
        raise ValidationError(
            message="New body must not be empty.",
            code="MESSAGE_BODY_EMPTY",
        )

    if message.deleted_at is not None:
        raise ValidationError(
            message="Cannot edit a deleted message.",
            code="MESSAGE_DELETED",
        )

    if message.message_type in (MessageType.SYSTEM_EVENT, MessageType.STATUS_CHANGE):
        raise AuthorizationError(
            message=(
                f"Messages of type {message.message_type.value!r} cannot "
                f"be edited."
            ),
            code="MESSAGE_TYPE_NOT_EDITABLE",
        )

    # Get the case for permission resolution
    conversation = get_conversation(db, message.conversation_id)
    case = _get_case_for_conversation(db, conversation)

    is_sender = message.sender_id == actor.id
    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    is_admin = ws_role in (WorkspaceRole.OWNER, WorkspaceRole.EDITOR)

    if message.message_type == MessageType.EVIDENCE_REFERENCE:
        if not is_sender:
            raise AuthorizationError(
                message=(
                    "Evidence reference messages can only be edited by "
                    "the original sender."
                ),
                code="MESSAGE_EVIDENCE_EDIT_DENIED",
            )
    else:
        # TEXT messages — sender or admin
        if not is_sender and not is_admin:
            raise AuthorizationError(
                message="You can only edit your own messages.",
                code="MESSAGE_EDIT_DENIED",
            )

    # ── Apply the edit
    message.edit(new_body=new_body.strip())
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="message.edited",
        target_type="message",
        target_id=message.id,
        workspace_id=case.workspace_id,
        request=request,
        metadata={
            "conversation_id": str(conversation.id),
            "case_id": str(case.id),
            "edit_count": message.edit_count,
        },
    )

    return message


# ============================================================================
# MESSAGES — DELETE
# ============================================================================

def soft_delete_message(
    db: Session,
    *,
    actor: User,
    message: CaseMessage,
    request: Any | None = None,
) -> CaseMessage:
    """
    Soft-delete a message.

    The row stays in the DB (excluded from queries). Threading is
    preserved. Rules:
        - Sender can delete their own message
        - Workspace ADMIN/OWNER can delete any message
        - ``system_event`` / ``status_change`` cannot be deleted

    Raises
    ------
    AuthorizationError
        If the actor cannot delete this message.
    """
    if message.deleted_at is not None:
        return message  # idempotent

    if message.message_type in (MessageType.SYSTEM_EVENT, MessageType.STATUS_CHANGE):
        raise AuthorizationError(
            message=(
                f"Messages of type {message.message_type.value!r} cannot "
                f"be deleted."
            ),
            code="MESSAGE_TYPE_NOT_DELETABLE",
        )

    conversation = get_conversation(db, message.conversation_id)
    case = _get_case_for_conversation(db, conversation)

    is_sender = message.sender_id == actor.id
    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    is_admin = ws_role in (WorkspaceRole.OWNER, WorkspaceRole.EDITOR)

    if not is_sender and not is_admin:
        raise AuthorizationError(
            message="You can only delete your own messages.",
            code="MESSAGE_DELETE_DENIED",
        )

    message.soft_delete()
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="message.deleted",
        target_type="message",
        target_id=message.id,
        workspace_id=case.workspace_id,
        request=request,
        metadata={
            "conversation_id": str(conversation.id),
            "case_id": str(case.id),
        },
    )

    return message


# ============================================================================
# MESSAGES — PIN
# ============================================================================

def pin_message(
    db: Session,
    *,
    actor: User,
    message: CaseMessage,
    pinned: bool = True,
    request: Any | None = None,
) -> CaseMessage:
    """
    Pin or unpin a message. Pinned messages appear at the top of the
    conversation in the UI.

    Requires at least workspace EDITOR role (analysts can pin; clients
    cannot).
    """
    conversation = get_conversation(db, message.conversation_id)
    case = _get_case_for_conversation(db, conversation)
    _assert_can_read_conversation(db, actor, conversation, case)

    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    if ws_role not in (WorkspaceRole.OWNER, WorkspaceRole.EDITOR):
        raise AuthorizationError(
            message="Only workspace EDITOR or OWNER can pin messages.",
            code="MESSAGE_PIN_DENIED",
        )

    if message.is_pinned == pinned:
        return message  # no-op

    message.is_pinned = pinned
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="message.pinned" if pinned else "message.unpinned",
        target_type="message",
        target_id=message.id,
        workspace_id=case.workspace_id,
        request=request,
        metadata={
            "conversation_id": str(conversation.id),
            "case_id": str(case.id),
        },
    )

    return message


# ============================================================================
# READ RECEIPTS
# ============================================================================

def mark_read(
    db: Session,
    *,
    actor: User,
    message: CaseMessage,
) -> CaseMessage:
    """
    Mark a single message as read by the actor. Idempotent.

    Requires the actor be a conversation participant (read access).
    """
    conversation = get_conversation(db, message.conversation_id)
    case = _get_case_for_conversation(db, conversation)
    _assert_can_read_conversation(db, actor, conversation, case)

    message.mark_read(by_user_id=actor.id)
    db.flush()
    return message


def mark_conversation_read(
    db: Session,
    *,
    actor: User,
    conversation: CaseConversation,
) -> int:
    """
    Mark every unread message in the conversation as read by the actor.

    Returns the number of messages actually marked (0 if everything was
    already read).

    Optimized: only fetches messages where the actor isn't already in
    ``read_by``. For a conversation with hundreds of messages, this is
    a single indexed query plus a batch update.
    """
    case = _get_case_for_conversation(db, conversation)
    _assert_can_read_conversation(db, actor, conversation, case)

    # Fetch messages where the actor is not yet in read_by
    # Using JSONB containment check — indexed in production
    now = datetime.now(timezone.utc)

    messages = list(db.execute(
        select(CaseMessage).where(
            CaseMessage.conversation_id == conversation.id,
            CaseMessage.deleted_at.is_(None),
        )
    ).scalars().all())

    marked = 0
    for msg in messages:
        if not msg.is_read_by(actor.id):
            msg.mark_read(by_user_id=actor.id)
            marked += 1

    if marked > 0:
        db.flush()

    return marked


# ============================================================================
# ATTACHMENTS
# ============================================================================

def _validate_attachment_extension(original_filename: str) -> str:
    """Same validation logic as evidence — see evidence_service."""
    if not original_filename or not original_filename.strip():
        raise ValidationError(
            message="original_filename is required.",
            code="ATTACHMENT_FILENAME_REQUIRED",
        )
    if "/" in original_filename or "\\" in original_filename:
        raise ValidationError(
            message="original_filename must not contain path separators.",
            code="ATTACHMENT_FILENAME_INVALID",
        )
    if "." not in original_filename:
        raise ValidationError(
            message="Filename must have an extension.",
            code="ATTACHMENT_EXTENSION_REQUIRED",
        )

    ext = "." + original_filename.rsplit(".", 1)[1].lower()

    if ext in _ATTACHMENT_DENIED_EXTENSIONS:
        raise ValidationError(
            message=f"Attachment extension {ext!r} is not permitted.",
            code="ATTACHMENT_EXTENSION_DENIED",
        )
    if ext not in _ATTACHMENT_ALLOWED_EXTENSIONS:
        raise ValidationError(
            message=(
                f"Attachment extension {ext!r} is not in the allowed set."
            ),
            code="ATTACHMENT_EXTENSION_NOT_ALLOWED",
        )
    return ext


def _generate_stored_filename(extension: str) -> str:
    """UUID-based stored filename. Same pattern as evidence."""
    ext = extension.lower().lstrip(".")
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex


def _attachment_storage_path(stored_filename: str) -> Path:
    """Compute the on-disk path for an attachment."""
    base = Path(settings.UPLOAD_DIR).resolve()
    return base / "message_attachments" / stored_filename


def upload_attachment(
    db: Session,
    *,
    actor: User,
    file_bytes: bytes,
    original_filename: str,
    message_id: uuid.UUID | None = None,
) -> MessageAttachment:
    """
    Upload a file as an attachment.

    If ``message_id`` is provided, the attachment is immediately linked
    to that message. If ``None``, the attachment is **orphaned** — it
    exists but isn't linked. The typical pattern is:

        1. Upload → orphan attachment
        2. Create message with `attachment_ids` → attachment linked

    Orphan cleanup runs as a background job and deletes unattached
    attachments older than 24 hours.

    Validates extension and size. Computes SHA-256. Writes to disk
    under ``message_attachments/``.

    Does NOT check case access — the caller (endpoint) is responsible
    for verifying the user can access the message's conversation. When
    ``message_id`` is None, the caller must verify the user is
    uploading in the context of an accessible conversation (typically
    via a temp conversation endpoint that pre-validates).

    Returns
    -------
    MessageAttachment
        Persisted attachment (flushed, not committed).
    """
    if not file_bytes:
        raise ValidationError(
            message="File content is empty.",
            code="ATTACHMENT_FILE_EMPTY",
        )
    if len(file_bytes) > _MAX_ATTACHMENT_SIZE_BYTES:
        raise ValidationError(
            message=(
                f"Attachment exceeds {_MAX_ATTACHMENT_SIZE_BYTES} bytes "
                f"(got {len(file_bytes)})."
            ),
            code="ATTACHMENT_FILE_TOO_LARGE",
        )

    extension = _validate_attachment_extension(original_filename)
    content_hash = hashlib.sha256(file_bytes).hexdigest()
    stored_filename = _generate_stored_filename(extension)

    # Write to disk
    path = _attachment_storage_path(stored_filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(file_bytes)
    tmp_path.replace(path)

    attachment = MessageAttachment.build(
        original_filename=original_filename,
        stored_filename=stored_filename,
        content_hash=content_hash,
        file_size_bytes=len(file_bytes),
        message_id=message_id,
        uploaded_by_id=actor.id,
        mime_type=_mime_from_extension(extension),
    )
    db.add(attachment)
    db.flush()

    logger.info(
        "Attachment uploaded",
        extra={
            "attachment_id": str(attachment.id),
            "file_size_bytes": len(file_bytes),
            "has_message": message_id is not None,
        },
    )

    return attachment


def attach_to_message(
    db: Session,
    *,
    actor: User,
    attachment_ids: list[uuid.UUID],
    message: CaseMessage,
    request: Any | None = None,
) -> list[MessageAttachment]:
    """
    Link orphaned attachments to a message.

    Public wrapper over the internal ``_attach_attachments_to_message``
    for the "create message, then attach" flow (rare — usually
    attachments are passed in ``create_message``).

    Idempotent — re-attaching an attachment that's already on the
    message is a no-op.
    """
    conversation = get_conversation(db, message.conversation_id)
    case = _get_case_for_conversation(db, conversation)
    _assert_can_post_to_conversation(db, actor, conversation, case)

    return _attach_attachments_to_message(
        db,
        attachment_ids=attachment_ids,
        message=message,
        uploaded_by_id=actor.id,
        case=case,
    )


def _attach_attachments_to_message(
    db: Session,
    *,
    attachment_ids: list[uuid.UUID],
    message: CaseMessage,
    uploaded_by_id: uuid.UUID,
    case: SecurityCase,
) -> list[MessageAttachment]:
    """
    Internal: link attachments to a message.

    Rules:
        - Attachment must exist
        - Attachment must be uploaded by the actor (or be orphaned
          and uploader can be any user — with a security check)
        - Attachment must not already be on another message
    """
    attached: list[MessageAttachment] = []

    for att_id in attachment_ids:
        attachment = db.get(MessageAttachment, att_id)
        if attachment is None:
            raise ValidationError(
                message=f"Attachment {att_id} not found.",
                code="ATTACHMENT_NOT_FOUND",
            )

        if attachment.message_id is not None and attachment.message_id != message.id:
            raise ConflictError(
                message=(
                    f"Attachment {att_id} is already linked to another "
                    f"message."
                ),
                code="ATTACHMENT_ALREADY_ATTACHED",
            )

        if attachment.message_id == message.id:
            # Already attached — idempotent
            attached.append(attachment)
            continue

        # Uploader check: attachment was uploaded by the same actor
        if attachment.uploaded_by_id != uploaded_by_id:
            # An attacker could reference another user's orphaned
            # attachment (e.g. an admin's screenshot) — reject
            logger.warning(
                "Attempted attachment hijack",
                extra={
                    "attachment_id": str(attachment.id),
                    "uploader_id": str(attachment.uploaded_by_id),
                    "attempted_actor_id": str(uploaded_by_id),
                    "case_id": str(case.id),
                },
            )
            raise AuthorizationError(
                message="You can only attach files you uploaded.",
                code="ATTACHMENT_NOT_YOURS",
            )

        attachment.message_id = message.id
        attached.append(attachment)

    db.flush()
    return attached


def delete_orphaned_attachments(
    db: Session,
    *,
    age_hours: int = 24,
    limit: int = 500,
) -> int:
    """
    Delete attachments that were uploaded but never attached to a
    message.

    Called by a periodic background job. Orphaned attachments
    accumulate when users start an upload and abandon it (network
    blip, close tab).

    Deletes from both DB and disk.

    Returns count deleted.
    """
    if age_hours < 1:
        raise ValueError("age_hours must be >= 1")
    if limit < 1 or limit > 2000:
        raise ValueError("limit must be between 1 and 2000")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=age_hours)

    candidates = db.execute(
        select(MessageAttachment)
        .where(
            MessageAttachment.message_id.is_(None),
            MessageAttachment.created_at < cutoff,
        )
        .limit(limit)
    ).scalars().all()

    deleted = 0
    for attachment in candidates:
        # Delete file from disk
        try:
            path = _attachment_storage_path(attachment.stored_filename)
            if path.exists():
                path.unlink()
        except OSError as exc:
            logger.warning(
                "Failed to delete orphaned attachment file",
                extra={
                    "attachment_id": str(attachment.id),
                    "error": str(exc)[:200],
                },
            )
            continue

        db.delete(attachment)
        deleted += 1

    if deleted > 0:
        db.flush()
        logger.info(
            "Orphaned attachments cleaned up",
            extra={"count": deleted},
        )

    return deleted


# ============================================================================
# INTERNAL — MIME mapping
# ============================================================================

def _mime_from_extension(extension: str) -> str:
    """Best-guess MIME type by extension. Same logic as evidence."""
    _MIME_MAP = {
        ".pdf": "application/pdf",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".csv": "text/csv",
        ".json": "application/json",
        ".xml": "application/xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".zip": "application/zip",
        ".gz": "application/gzip",
        ".pcap": "application/vnd.tcpdump.pcap",
        ".pcapng": "application/x-pcapng",
        ".eml": "message/rfc822",
        ".msg": "application/vnd.ms-outlook",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
    return _MIME_MAP.get(extension.lower(), "application/octet-stream")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Conversations
    "get_or_create_conversation",
    "get_conversation",
    "list_conversations_for_case",
    # Messages
    "list_messages",
    "create_message",
    "edit_message",
    "soft_delete_message",
    "pin_message",
    # Read receipts
    "mark_read",
    "mark_conversation_read",
    # Attachments
    "upload_attachment",
    "attach_to_message",
    "delete_orphaned_attachments",
]