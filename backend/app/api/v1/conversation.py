"""
CyberGuard AI — Conversation & Message Endpoints
============================================================================

Case conversations, messages, and message attachments.

Three routers exported from this file:
    ``case_conversations_router``  — /api/v1/cases/{case_id}/conversations
    ``router``                     — /api/v1/conversations/* + /api/v1/messages/*
    ``attachments_router``         — /api/v1/attachments/*

Eleven endpoints covering the full communication workflow:

    GET    /cases/{id}/conversations        — list conversations for a case
    GET    /conversations/{id}              — get one conversation
    GET    /conversations/{id}/messages     — paginated message history
    POST   /conversations/{id}/messages     — post a message
    POST   /conversations/{id}/read-all     — bulk mark read
    POST   /conversations/{id}/attachments  — upload attachment (multipart)
    PATCH  /messages/{id}                   — edit message body
    DELETE /messages/{id}                   — soft delete
    PATCH  /messages/{id}/pin               — pin/unpin
    POST   /messages/{id}/read              — mark read
    GET    /attachments/{id}/download       — download attachment bytes

The internal-conversation rule
------------------------------
Client users cannot read or post to ``internal`` conversations.
Enforced at the service layer (File 87, ``_is_client_user`` +
``_assert_can_read_conversation``). This router does not duplicate
the check — every method takes ``current_user`` and delegates.

The list endpoint (`GET /cases/{id}/conversations`) filters internal
conversations out of the response for client users — the service does
this internally (`list_conversations_for_case`).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    Query,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.conversation import (
    CaseConversation,
    CaseMessage,
    MessageAttachment,
)
from app.models.enums import MessageType
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.conversation import (
    ConversationList,
    ConversationRead,
    MessageAttachmentRead,
    MessageCreate,
    MessageFilter,
    MessageList,
    MessagePinUpdate,
    MessageRead,
    MessageUpdate,
)
from app.services import (
    conversation_service,
)


logger = get_logger(__name__)


_MAX_ATTACHMENT_BYTES = 10_485_760  # 10 MB


# ============================================================================
# ROUTERS
# ============================================================================

case_conversations_router = APIRouter(
    prefix="/cases",
    tags=["conversations"],
)

router = APIRouter(
    tags=["conversations"],
)

attachments_router = APIRouter(
    prefix="/attachments",
    tags=["conversations"],
)


# ============================================================================
# INTERNAL — filename escape for Content-Disposition
# ============================================================================

def _safe_content_disposition(filename: str) -> str:
    """RFC 6266-compliant Content-Disposition with UTF-8 filename*."""
    safe_ascii = "".join(
        c if (32 <= ord(c) < 127 and c not in ('"', '\\', ';')) else "_"
        for c in filename
    ) or "attachment"
    from urllib.parse import quote
    return (
        f'attachment; filename="{safe_ascii}"; '
        f"filename*=UTF-8''{quote(filename, safe='')}"
    )


# ============================================================================
# LIST CONVERSATIONS FOR A CASE
# ============================================================================

@case_conversations_router.get(
    "/{case_id}/conversations",
    response_model=list[ConversationList],
    summary="List conversations for a case",
    description=(
        "Returns the case's conversations. Client users get only "
        "`client` and `system` conversations — `internal` conversations "
        "are filtered out at the service layer.\n\n"
        "Requires `CONVERSATION_READ` scope on the case (assigned "
        "analyst, workspace role, or access grant)."
    ),
)
def list_conversations(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> list[ConversationList]:
    from app.services import case_service
    case = case_service.get_by_id(db, case_id)
    conversations = conversation_service.list_conversations_for_case(
        db, actor=current_user, case=case,
    )
    return [ConversationList.model_validate(c) for c in conversations]


# ============================================================================
# GET CONVERSATION
# ============================================================================

@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationRead,
    summary="Get a conversation",
    description=(
        "Returns one conversation. Requires `CONVERSATION_READ` scope "
        "on the parent case. Client users are rejected from `internal` "
        "conversations."
    ),
)
def get_conversation(
    conversation_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ConversationRead:
    conversation = conversation_service.get_conversation(db, conversation_id)

    # Access check via the service (delegates to case + conversation-type rules)
    from app.models.case import SecurityCase
    case = db.get(SecurityCase, conversation.case_id)
    if case is None:
        raise NotFoundError(
            message="Case for this conversation no longer exists.",
            code="CASE_NOT_FOUND",
        )
    from app.services import authorization
    from app.models.enums import AccessGrantScope
    authorization.require_case_access(
        db, current_user, case,
        minimum_scope=AccessGrantScope.CONVERSATION_READ,
    )
    if conversation.conversation_type == "internal":
        # Reuse the service's rule
        from app.services.conversation_service import _is_client_user
        if _is_client_user(db, current_user, case):
            from app.core.exceptions import AuthorizationError
            raise AuthorizationError(
                message="Internal conversation is not accessible.",
                code="INTERNAL_CONVERSATION_FORBIDDEN",
            )

    return ConversationRead.model_validate(conversation)


# ============================================================================
# LIST MESSAGES
# ============================================================================

@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=PaginatedResponse[MessageList],
    summary="List messages in a conversation",
    description=(
        "Paginated message history, oldest-first (chronological). "
        "Excludes soft-deleted messages. Client users are rejected "
        "from `internal` conversations."
    ),
)
def list_messages(
    conversation_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: MessageFilter = Depends(),
) -> PaginatedResponse[MessageList]:
    conversation = conversation_service.get_conversation(db, conversation_id)
    messages, total = conversation_service.list_messages(
        db,
        actor=current_user,
        conversation=conversation,
        page=page,
        filters=filters,
    )
    return PaginatedResponse[MessageList](
        items=[MessageList.model_validate(m) for m in messages],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# POST MESSAGE
# ============================================================================

@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=MessageRead,
    status_code=status.HTTP_201_CREATED,
    summary="Post a message to a conversation",
    description=(
        "Creates a message in the conversation. Optional `evidence_id` "
        "links the message to a piece of evidence in the same case. "
        "Optional `reply_to_id` threads the message under a parent "
        "(two-level threading — replies to replies flatten to the "
        "top-level parent).\n\n"
        "`attachment_ids` optionally links pre-uploaded orphaned "
        "attachments to this message.\n\n"
        "Only `text` and `evidence_reference` message types are accepted "
        "from user input. System/status messages are backend-generated."
    ),
    responses={
        201: {"description": "Message created."},
        400: {"description": "Empty body, invalid message type, or bad attachment."},
        403: {"description": "Cannot post to this conversation."},
    },
)
def create_message(
    conversation_id: uuid.UUID,
    body: MessageCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
    attachment_ids: list[uuid.UUID] = Body(
        default=[],
        embed=True,
        description=(
            "Optional IDs of pre-uploaded attachments to link to this "
            "message. Attachments must be uploaded via "
            "POST /conversations/{id}/attachments first."
        ),
    ),
) -> MessageRead:
    conversation = conversation_service.get_conversation(db, conversation_id)

    message = conversation_service.create_message(
        db,
        actor=current_user,
        conversation=conversation,
        body=body.body,
        message_type=body.message_type,
        evidence_id=body.evidence_id,
        reply_to_id=body.reply_to_id,
        attachment_ids=attachment_ids or None,
        metadata=body.metadata,
    )
    db.commit()

    logger.info(
        "Message posted via API",
        extra={
            "message_id": str(message.id),
            "conversation_id": str(conversation.id),
            "actor_id": str(current_user.id),
            "has_attachments": bool(attachment_ids),
        },
    )

    return MessageRead.model_validate(message)


# ============================================================================
# EDIT MESSAGE
# ============================================================================

@router.patch(
    "/messages/{message_id}",
    response_model=MessageRead,
    summary="Edit a message body",
    description=(
        "Updates the message body. Rules:\n\n"
        "- `text` messages: sender or workspace ADMIN/OWNER can edit\n"
        "- `evidence_reference` messages: only the sender can edit\n"
        "- `system_event` / `status_change`: cannot be edited\n\n"
        "Increments `edit_count`, sets `edited_at`. Full revision "
        "history is not exposed (future enhancement)."
    ),
)
def edit_message(
    message_id: uuid.UUID,
    body: MessageUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageRead:
    message = db.get(CaseMessage, message_id)
    if message is None:
        raise NotFoundError(
            message=f"Message {message_id} not found.",
            code="MESSAGE_NOT_FOUND",
        )

    updated = conversation_service.edit_message(
        db,
        actor=current_user,
        message=message,
        new_body=body.body,
    )
    db.commit()
    return MessageRead.model_validate(updated)


# ============================================================================
# SOFT DELETE MESSAGE
# ============================================================================

@router.delete(
    "/messages/{message_id}",
    response_model=MessageResponse,
    summary="Soft-delete a message",
    description=(
        "Marks the message as deleted. The body stays in the DB (excluded "
        "from queries). Threading is preserved — replies still reference "
        "the deleted parent. Sender or workspace ADMIN/OWNER can delete."
    ),
)
def delete_message(
    message_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageResponse:
    message = db.get(CaseMessage, message_id)
    if message is None:
        raise NotFoundError(
            message=f"Message {message_id} not found.",
            code="MESSAGE_NOT_FOUND",
        )

    conversation_service.soft_delete_message(
        db, actor=current_user, message=message,
    )
    db.commit()
    return MessageResponse(message="Message deleted.")


# ============================================================================
# PIN / UNPIN MESSAGE
# ============================================================================

@router.patch(
    "/messages/{message_id}/pin",
    response_model=MessageRead,
    summary="Pin or unpin a message",
    description=(
        "Toggles the pinned state. Pinned messages appear at the top of "
        "the conversation in the UI. Requires workspace EDITOR or OWNER "
        "role — clients cannot pin."
    ),
)
def pin_message(
    message_id: uuid.UUID,
    body: MessagePinUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageRead:
    message = db.get(CaseMessage, message_id)
    if message is None:
        raise NotFoundError(
            message=f"Message {message_id} not found.",
            code="MESSAGE_NOT_FOUND",
        )

    updated = conversation_service.pin_message(
        db,
        actor=current_user,
        message=message,
        pinned=body.is_pinned,
    )
    db.commit()
    return MessageRead.model_validate(updated)


# ============================================================================
# MARK READ
# ============================================================================

@router.post(
    "/messages/{message_id}/read",
    response_model=MessageRead,
    summary="Mark a message as read",
    description=(
        "Adds the current user to the message's read receipts. "
        "Idempotent."
    ),
)
def mark_message_read(
    message_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageRead:
    message = db.get(CaseMessage, message_id)
    if message is None:
        raise NotFoundError(
            message=f"Message {message_id} not found.",
            code="MESSAGE_NOT_FOUND",
        )

    updated = conversation_service.mark_read(
        db, actor=current_user, message=message,
    )
    db.commit()
    return MessageRead.model_validate(updated)


# ============================================================================
# BULK MARK READ
# ============================================================================

@router.post(
    "/conversations/{conversation_id}/read-all",
    response_model=dict,
    summary="Mark all messages in a conversation as read",
    description=(
        "Bulk marks every unread message in the conversation as read by "
        "the current user. Called when the user opens the conversation. "
        "Returns the count of messages actually marked."
    ),
)
def mark_conversation_read(
    conversation_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> dict:
    conversation = conversation_service.get_conversation(db, conversation_id)
    count = conversation_service.mark_conversation_read(
        db, actor=current_user, conversation=conversation,
    )
    db.commit()
    return {"marked_read": count}


# ============================================================================
# UPLOAD ATTACHMENT (multipart)
# ============================================================================

@router.post(
    "/conversations/{conversation_id}/attachments",
    response_model=MessageAttachmentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upload an attachment (orphaned)",
    description=(
        "Uploads a file as an orphaned attachment. The attachment is "
        "not linked to any message yet — pass its `id` in "
        "`attachment_ids` when calling `POST /conversations/{id}/messages` "
        "to link it.\n\n"
        "**Max size**: 10 MB. Extension allow-list enforced "
        "(executables rejected).\n\n"
        "Orphaned attachments are deleted after 24 hours if never linked."
    ),
)
async def upload_attachment(
    conversation_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    file: UploadFile = File(..., description="The attachment file. Max 10 MB."),
    original_filename: str = Form(
        ...,
        min_length=1,
        max_length=255,
        description="Client filename for display.",
    ),
) -> MessageAttachmentRead:
    # Verify conversation access before accepting the upload
    conversation = conversation_service.get_conversation(db, conversation_id)
    from app.models.case import SecurityCase
    case = db.get(SecurityCase, conversation.case_id)
    if case is None:
        raise NotFoundError(
            message="Case for this conversation no longer exists.",
            code="CASE_NOT_FOUND",
        )
    from app.services import authorization
    from app.models.enums import AccessGrantScope
    authorization.require_case_access(
        db, current_user, case,
        minimum_scope=AccessGrantScope.CONVERSATION_READ,
    )

    # Read bounded file
    file_bytes = await file.read(_MAX_ATTACHMENT_BYTES + 1)
    if len(file_bytes) > _MAX_ATTACHMENT_BYTES:
        from app.core.exceptions import ValidationError
        raise ValidationError(
            message=f"Attachment exceeds {_MAX_ATTACHMENT_BYTES} bytes.",
            code="ATTACHMENT_FILE_TOO_LARGE",
        )

    attachment = conversation_service.upload_attachment(
        db,
        actor=current_user,
        file_bytes=file_bytes,
        original_filename=original_filename,
    )
    db.commit()

    logger.info(
        "Attachment uploaded via API",
        extra={
            "attachment_id": str(attachment.id),
            "conversation_id": str(conversation.id),
            "file_size_bytes": len(file_bytes),
            "actor_id": str(current_user.id),
        },
    )

    return MessageAttachmentRead.model_validate(attachment)


# ============================================================================
# DOWNLOAD ATTACHMENT (binary)
# ============================================================================

@attachments_router.get(
    "/{attachment_id}/download",
    summary="Download an attachment",
    description=(
        "Streams the attachment bytes. Attachments don't have chain of "
        "custody or integrity re-check — they're informal communication "
        "artifacts. Increments `download_count`. Requires "
        "`CONVERSATION_READ` on the parent case."
    ),
)
def download_attachment(
    attachment_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> Response:
    attachment = db.get(MessageAttachment, attachment_id)
    if attachment is None:
        raise NotFoundError(
            message=f"Attachment {attachment_id} not found.",
            code="ATTACHMENT_NOT_FOUND",
        )

    # Access check — must be able to read the message's conversation
    message = db.get(CaseMessage, attachment.message_id) if attachment.message_id else None
    if message is not None:
        conversation = conversation_service.get_conversation(
            db, message.conversation_id,
        )
        from app.models.case import SecurityCase
        case = db.get(SecurityCase, conversation.case_id)
        if case is None:
            raise NotFoundError(
                message="Case for this attachment no longer exists.",
                code="CASE_NOT_FOUND",
            )
        from app.services import authorization
        from app.models.enums import AccessGrantScope
        authorization.require_case_access(
            db, current_user, case,
            minimum_scope=AccessGrantScope.CONVERSATION_READ,
        )
    else:
        # Orphaned — only the uploader can download it
        if attachment.uploaded_by_id != current_user.id:
            from app.core.exceptions import AuthorizationError
            raise AuthorizationError(
                message="You can only download your own orphaned attachments.",
                code="ATTACHMENT_ACCESS_DENIED",
            )

    path = attachment.get_storage_path()
    if not path.exists() or not path.is_file():
        raise NotFoundError(
            message="Attachment file not found on disk.",
            code="ATTACHMENT_FILE_MISSING",
        )
    file_bytes = path.read_bytes()

    attachment.download_count = (attachment.download_count or 0) + 1
    db.commit()

    headers = {
        "Content-Disposition": _safe_content_disposition(attachment.original_filename),
        "Content-Length": str(len(file_bytes)),
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    return Response(
        content=file_bytes,
        media_type=attachment.mime_type or "application/octet-stream",
        headers=headers,
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "case_conversations_router", "attachments_router"]