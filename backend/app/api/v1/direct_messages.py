"""
CyberGuard AI — Direct Messaging Endpoints
============================================================================
Scoped user-to-user direct messages between clients, analysts, and organizers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentActiveUser, DBDep
from app.core.logging import get_logger
from app.models.direct_message import DirectMessage
from app.models.user import User

logger = get_logger(__name__)

router = APIRouter(
    prefix="/direct-messages",
    tags=["direct-messages"],
)


class DirectMessageItem(BaseModel):
    id: str
    sender_id: str
    sender_public_id: Optional[str] = None
    sender_name: Optional[str] = None
    recipient_id: str
    recipient_public_id: Optional[str] = None
    body: str
    is_me: bool
    is_mine: bool = False
    is_read: bool
    created_at: str
    timestamp: str


class SendDirectMessageRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class ContactItem(BaseModel):
    user_id: str
    id: Optional[str] = None
    public_user_id: str
    user_slug: Optional[str] = None
    full_name: str
    name: Optional[str] = None
    email: str
    role: str
    last_message: Optional[str] = None
    last_message_at: Optional[str] = None
    unread_count: int = 0


def _resolve_target_user(db: Session, target_id_or_slug: str) -> User:
    """Resolve target by UUID, AnalystProfile ID, or by public_user_id / email."""
    clean_target = str(target_id_or_slug).strip().lstrip("@")
    target_user = None

    # 1. Check if it's a UUID (User.id or AnalystProfile.id)
    try:
        user_uuid = uuid.UUID(clean_target)
        target_user = db.get(User, user_uuid)
        if not target_user:
            from app.models.analyst import AnalystProfile
            analyst_profile = db.get(AnalystProfile, user_uuid)
            if analyst_profile and analyst_profile.user_id:
                target_user = db.get(User, analyst_profile.user_id)
    except ValueError:
        pass

    # 2. Match exact public_user_id (case-insensitive)
    if not target_user:
        target_user = db.execute(
            select(User).where(func.lower(User.public_user_id) == clean_target.lower())
        ).scalar_one_or_none()

    # 3. Match email
    if not target_user and "@" in clean_target:
        target_user = db.execute(
            select(User).where(func.lower(User.email) == clean_target.lower())
        ).scalar_one_or_none()

    # 4. Fallback: match prefix / unique ilike on public_user_id
    if not target_user and len(clean_target) >= 4:
        candidates = list(
            db.execute(
                select(User).where(User.public_user_id.ilike(f"%{clean_target}%"))
            ).scalars().all()
        )
        if len(candidates) == 1:
            target_user = candidates[0]

    if not target_user:
        raise HTTPException(
            status_code=404,
            detail=f"User '{target_id_or_slug}' not found. Please provide a valid User ID or public user slug.",
        )
    return target_user


@router.get("/contacts", response_model=List[ContactItem], summary="List all direct message conversation contacts")
def list_contacts(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> List[ContactItem]:
    from app.models.analyst import AnalystProfile

    # Find all distinct user IDs the current user has exchanged messages with
    subquery = db.execute(
        select(DirectMessage.sender_id, DirectMessage.recipient_id, DirectMessage.created_at, DirectMessage.body)
        .where(
            or_(
                DirectMessage.sender_id == current_user.id,
                DirectMessage.recipient_id == current_user.id,
            )
        )
        .order_by(DirectMessage.created_at.desc())
    ).fetchall()

    contacts_map: dict[uuid.UUID, dict[str, Any]] = {}
    for s_id, r_id, created, body in subquery:
        other_id = r_id if s_id == current_user.id else s_id
        if other_id == current_user.id:
            continue
        if other_id not in contacts_map:
            contacts_map[other_id] = {
                "last_message": body,
                "last_message_at": created.isoformat(),
            }

    results: List[ContactItem] = []
    for other_id, meta in contacts_map.items():
        user = db.get(User, other_id)
        if not user:
            continue

        unread = db.execute(
            select(func.count(DirectMessage.id)).where(
                DirectMessage.sender_id == other_id,
                DirectMessage.recipient_id == current_user.id,
                DirectMessage.is_read.is_(False),
            )
        ).scalar() or 0

        # Fetch analyst display name if available
        prof = db.execute(
            select(AnalystProfile).where(AnalystProfile.user_id == user.id)
        ).scalar_one_or_none()

        display_name = (prof.display_name if prof and prof.display_name else None) or user.full_name or user.email.split("@")[0]
        if prof and "Analyst" not in display_name and user.role == "analyst":
            display_name = f"{display_name} (Analyst)"

        results.append(
            ContactItem(
                user_id=str(user.id),
                id=str(user.id),
                public_user_id=user.public_user_id or str(user.id),
                user_slug=user.public_user_id or str(user.id),
                full_name=display_name,
                name=display_name,
                email=user.email,
                role=getattr(user, "role", "individual"),
                last_message=meta["last_message"],
                last_message_at=meta["last_message_at"],
                unread_count=unread,
            )
        )

    return results


@router.get("/{target_id_or_slug}", response_model=List[DirectMessageItem], summary="Get direct message history with a user")
def get_conversation_history(
    target_id_or_slug: str,
    db: DBDep,
    current_user: CurrentActiveUser,
    limit: int = Query(100, ge=1, le=500),
) -> List[DirectMessageItem]:
    clean_target = str(target_id_or_slug).strip().lstrip("@")
    if clean_target in ("", "undefined", "null"):
        return []

    other_user = _resolve_target_user(db, clean_target)
    if other_user.id == current_user.id:
        return []

    from app.models.analyst import AnalystProfile

    messages = list(
        db.execute(
            select(DirectMessage)
            .where(
                or_(
                    and_(DirectMessage.sender_id == current_user.id, DirectMessage.recipient_id == other_user.id),
                    and_(DirectMessage.sender_id == other_user.id, DirectMessage.recipient_id == current_user.id),
                )
            )
            .order_by(DirectMessage.created_at.asc())
            .limit(limit)
        ).scalars().all()
    )

    # Mark incoming as read
    now = datetime.now(timezone.utc)
    updated = False
    for m in messages:
        if m.recipient_id == current_user.id and not m.is_read:
            m.is_read = True
            m.read_at = now
            updated = True
    if updated:
        db.commit()

    # Resolve display names for both parties
    other_prof = db.execute(select(AnalystProfile).where(AnalystProfile.user_id == other_user.id)).scalar_one_or_none()
    other_name = (other_prof.display_name if other_prof and other_prof.display_name else None) or other_user.full_name or other_user.public_user_id

    curr_prof = db.execute(select(AnalystProfile).where(AnalystProfile.user_id == current_user.id)).scalar_one_or_none()
    curr_name = (curr_prof.display_name if curr_prof and curr_prof.display_name else None) or current_user.full_name or current_user.public_user_id

    result: List[DirectMessageItem] = []
    for m in messages:
        is_me = (m.sender_id == current_user.id)
        result.append(
            DirectMessageItem(
                id=str(m.id),
                sender_id=str(m.sender_id),
                sender_public_id=current_user.public_user_id if is_me else other_user.public_user_id,
                sender_name=curr_name if is_me else other_name,
                recipient_id=str(m.recipient_id),
                recipient_public_id=other_user.public_user_id if is_me else current_user.public_user_id,
                body=m.body,
                is_me=is_me,
                is_mine=is_me,
                is_read=m.is_read,
                created_at=m.created_at.isoformat(),
                timestamp=m.created_at.strftime("%I:%M %p"),
            )
        )
    return result


@router.post("/{target_id_or_slug}", response_model=DirectMessageItem, status_code=status.HTTP_201_CREATED, summary="Send a direct message")
def send_direct_message(
    target_id_or_slug: str,
    payload: SendDirectMessageRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> DirectMessageItem:
    clean_target = str(target_id_or_slug).strip().lstrip("@")
    other_user = _resolve_target_user(db, clean_target)
    if other_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot send a direct message to yourself.")

    msg = DirectMessage(
        sender_id=current_user.id,
        recipient_id=other_user.id,
        body=payload.body,
        is_read=False,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    from app.models.analyst import AnalystProfile
    curr_prof = db.execute(select(AnalystProfile).where(AnalystProfile.user_id == current_user.id)).scalar_one_or_none()
    curr_name = (curr_prof.display_name if curr_prof and curr_prof.display_name else None) or current_user.full_name or current_user.public_user_id

    return DirectMessageItem(
        id=str(msg.id),
        sender_id=str(msg.sender_id),
        sender_public_id=current_user.public_user_id,
        sender_name=curr_name,
        recipient_id=str(msg.recipient_id),
        recipient_public_id=other_user.public_user_id,
        body=msg.body,
        is_me=True,
        is_mine=True,
        is_read=False,
        created_at=msg.created_at.isoformat(),
        timestamp=msg.created_at.strftime("%I:%M %p"),
    )
