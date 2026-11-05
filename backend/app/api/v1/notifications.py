"""
CyberGuard AI - Notifications API Endpoints

In-app notification inbox for the authenticated user: list, unread count,
mark as read. Email/webhook delivery happens out-of-band via
NotificationService (see app/services/notifications/service.py) - this
router only exposes the persisted in_app channel rows, which is the
inbox the frontend polls/reads.

Security: every endpoint requires a valid JWT. All queries are scoped to
the authenticated caller's own user id (recipient_user_id) - there is no
route here that lets a user read or mark read another user's
notifications.
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth.jwt import get_current_active_user
from app.auth.models import User
from app.database.models import Notification
from app.database.repositories.notifications import get_notification_repository

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class NotificationResponse(BaseModel):
    """A single in-app notification."""

    id: str
    alert_id: str | None = None
    severity: str
    title: str
    summary: str
    status: str
    created_at: str
    read_at: str | None = None


class UnreadCountResponse(BaseModel):
    """Unread in-app notification count for the caller."""

    unread_count: int


def _to_response(n: Notification) -> NotificationResponse:
    return NotificationResponse(
        id=n.id,
        alert_id=n.alert_id,
        severity=n.severity.value if hasattr(n.severity, "value") else str(n.severity),
        title=n.title,
        summary=n.summary,
        status=n.status.value if hasattr(n.status, "value") else str(n.status),
        created_at=n.created_at.isoformat() if isinstance(n.created_at, datetime) else str(n.created_at),
        read_at=n.read_at.isoformat() if isinstance(n.read_at, datetime) else None,
    )


@router.get(
    "",
    response_model=list[NotificationResponse],
    summary="List My Notifications",
    description="List the authenticated user's in-app notifications, newest first.",
)
async def list_notifications(
    unread_only: bool = Query(False, description="Only return unread notifications"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_active_user),
) -> list[NotificationResponse]:
    repo = get_notification_repository()
    notifications = await repo.list_for_user(
        recipient_user_id=user.id,
        limit=limit,
        offset=offset,
        unread_only=unread_only,
    )
    return [_to_response(n) for n in notifications]


@router.get(
    "/unread-count",
    response_model=UnreadCountResponse,
    summary="Unread Notification Count",
    description="Get the authenticated user's unread in-app notification count.",
)
async def get_unread_count(user: User = Depends(get_current_active_user)) -> UnreadCountResponse:
    repo = get_notification_repository()
    count = await repo.count_unread(user.id)
    return UnreadCountResponse(unread_count=count)


@router.post(
    "/{notification_id}/read",
    response_model=NotificationResponse,
    summary="Mark Notification Read",
    description="Mark one of the authenticated user's own notifications as read.",
)
async def mark_notification_read(
    notification_id: str,
    user: User = Depends(get_current_active_user),
) -> NotificationResponse:
    repo = get_notification_repository()
    updated = await repo.mark_read(notification_id, recipient_user_id=user.id)
    if not updated:
        # Either the notification doesn't exist, or it belongs to a
        # different user - mark_read's query is scoped to recipient_user_id,
        # so both cases return None here. Report 404 either way rather than
        # leaking which case it was.
        raise HTTPException(status_code=404, detail="Notification not found")
    return _to_response(updated)
