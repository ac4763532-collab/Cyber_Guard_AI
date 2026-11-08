"""
CyberGuard AI — Notification Endpoints
============================================================================

The user's notification inbox: list, badge, engagement tracking.

Eight endpoints covering the notification UX:

    GET    /notifications/badge            — sidebar counts (fast)
    GET    /notifications                  — paginated list
    POST   /notifications/{id}/seen        — mark seen
    POST   /notifications/{id}/read        — mark read (implies seen)
    POST   /notifications/{id}/dismiss     — dismiss (optional reason)
    POST   /notifications/{id}/action      — record user action
    POST   /notifications/mark-all-seen    — bulk
    POST   /notifications/mark-all-read    — bulk

Route ordering
--------------
``GET /notifications/badge`` is declared **before**
``GET /notifications/{notification_id}``. Without this, FastAPI would
try to parse the literal string ``"badge"`` as a UUID parameter and
return 422. Same lesson as ``/alerts/badge`` and ``/events/batch``.

Ownership, not workspace
------------------------
Notifications are owned by a user, not by a workspace. A user may
receive notifications from multiple workspaces (their personal, their
team's, another org they're part of). The service's
``_get_notification_or_404`` returns 404 for any notification that
isn't theirs — enumeration is not possible.

The ``related_workspace_id`` field on the notification is a
**grouping hint** (used to group the inbox by workspace in the UI),
not an access control boundary. A notification about workspace X is
visible to the user even if they've since left workspace X — it was
their notification when it was created.

Notification state model
------------------------
    created → seen → read → action-taken
                            → dismissed

    - ``seen_at`` — user opened the inbox and saw this
    - ``read_at`` — user explicitly marked it read
    - ``action_taken_at`` — user did something in response
    - ``dismissed_at`` — user dismissed it

The chain is enforced by the service:
    - ``mark_read`` implies ``mark_seen`` if not already set
    - ``dismiss`` implies ``mark_read``
    - ``record_action`` implies ``mark_read``

None of these are audited — they're engagement signals, not security
actions. The notification row itself carries the timestamps.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.notification import (
    NotificationBadge,
    NotificationDismiss,
    NotificationFilter,
    NotificationList,
    NotificationMarkAllRead,
    NotificationMarkAllSeen,
    NotificationRead,
    NotificationRecordAction,
)
from app.services import notification_service


router = APIRouter(
    prefix="/notifications",
    tags=["notifications"],
)


# ============================================================================
# BADGE (declared FIRST — literal path beats parameterized path)
# ============================================================================

@router.get(
    "/badge",
    response_model=NotificationBadge,
    summary="Get notification badge counts",
    description=(
        "Returns the badge counts for the current user: total active "
        "(non-dismissed, non-expired), unseen, unread, and critical-"
        "priority active. Fast — four indexed COUNT queries.\n\n"
        "Suitable for polling every 30s from the frontend to update "
        "the bell icon."
    ),
)
def get_notification_badge(
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationBadge:
    return notification_service.get_badge_counts(db, user_id=current_user.id)


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[NotificationList],
    summary="List my notifications",
    description=(
        "Paginated list of the current user's notifications. By default, "
        "excludes dismissed and expired notifications (`active_only=true`) "
        "— set `active_only=false` to see the full history.\n\n"
        "Returns lightweight `NotificationList` rows. Fetch "
        "`GET /notifications/{id}` for full details."
    ),
)
def list_notifications(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: NotificationFilter = Depends(),
) -> PaginatedResponse[NotificationList]:
    notifications, total = notification_service.list_notifications(
        db,
        user_id=current_user.id,
        page=page,
        filters=filters,
    )
    return PaginatedResponse[NotificationList](
        items=[NotificationList.model_validate(n) for n in notifications],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# GET ONE
# ============================================================================

@router.get(
    "/{notification_id}",
    response_model=NotificationRead,
    summary="Get a notification by ID",
    description=(
        "Full notification detail. Returns 404 if the notification "
        "doesn't exist or belongs to another user — enumeration is not "
        "possible."
    ),
)
def get_notification(
    notification_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationRead:
    # Service raises NotFoundError (not 403) for other users' notifications
    # — no information leak about existence.
    notification = notification_service._get_notification_or_404(
        db, notification_id, current_user.id,
    )
    return NotificationRead.model_validate(notification)


# ============================================================================
# STATE TRANSITIONS
# ============================================================================

@router.post(
    "/{notification_id}/seen",
    response_model=NotificationRead,
    summary="Mark a notification as seen",
    description=(
        "Records that the user opened the notification. Idempotent — "
        "re-marking a seen notification is a no-op. Reduces the "
        "`unseen_count` badge."
    ),
)
def mark_notification_seen(
    notification_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationRead:
    updated = notification_service.mark_seen(
        db, user_id=current_user.id, notification_id=notification_id,
    )
    db.commit()
    return NotificationRead.model_validate(updated)


@router.post(
    "/{notification_id}/read",
    response_model=NotificationRead,
    summary="Mark a notification as read",
    description=(
        "Records that the user read the notification. Implies 'seen'. "
        "Idempotent. Reduces the `unread_count` badge."
    ),
)
def mark_notification_read(
    notification_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationRead:
    updated = notification_service.mark_read(
        db, user_id=current_user.id, notification_id=notification_id,
    )
    db.commit()
    return NotificationRead.model_validate(updated)


@router.post(
    "/{notification_id}/dismiss",
    response_model=NotificationRead,
    summary="Dismiss a notification",
    description=(
        "Dismisses the notification (removes from active view). Implies "
        "'read'. Idempotent. Optional reason is recorded in "
        "`action_notes` for analytics."
    ),
)
def dismiss_notification(
    notification_id: uuid.UUID,
    body: NotificationDismiss,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationRead:
    updated = notification_service.dismiss(
        db,
        user_id=current_user.id,
        notification_id=notification_id,
        reason=body.reason,
    )
    db.commit()
    return NotificationRead.model_validate(updated)


@router.post(
    "/{notification_id}/action",
    response_model=NotificationRead,
    summary="Record a user action on a notification",
    description=(
        "Records that the user took an action in response (opened the "
        "target, replied, acknowledged, downloaded a report, etc.). "
        "Implies 'read'. Used for engagement analytics — not audited."
    ),
)
def record_notification_action(
    notification_id: uuid.UUID,
    body: NotificationRecordAction,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> NotificationRead:
    updated = notification_service.record_action(
        db,
        user_id=current_user.id,
        notification_id=notification_id,
        action_type=body.action_type,
        notes=body.notes,
    )
    db.commit()
    return NotificationRead.model_validate(updated)


# ============================================================================
# BULK OPERATIONS
# ============================================================================

@router.post(
    "/mark-all-seen",
    response_model=dict,
    summary="Mark all my notifications as seen",
    description=(
        "Bulk marks every unseen notification as seen. Called when the "
        "user opens the notification inbox — the badge count drops to "
        "zero with a single call. Optionally scoped to a workspace via "
        "`workspace_id`."
    ),
)
def mark_all_seen(
    body: NotificationMarkAllSeen,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> dict:
    count = notification_service.mark_all_seen(
        db,
        user_id=current_user.id,
        workspace_id=body.workspace_id,
    )
    db.commit()
    return {"marked_seen": count}


@router.post(
    "/mark-all-read",
    response_model=dict,
    summary="Mark all my notifications as read",
    description=(
        "Bulk marks every seen-but-unread notification as read. "
        "Optionally scoped to a workspace."
    ),
)
def mark_all_read(
    body: NotificationMarkAllRead,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> dict:
    count = notification_service.mark_all_read(
        db,
        user_id=current_user.id,
        workspace_id=body.workspace_id,
    )
    db.commit()
    return {"marked_read": count}


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]