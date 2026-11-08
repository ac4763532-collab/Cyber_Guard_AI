"""
CyberGuard AI — Notification Schemas
============================================================================

Request/response DTOs for the ``notifications`` table.

Notifications are the per-user inbox for everything the platform needs a
user to know about. Each row is one recipient's view of one event, with
its own read/seen/dismiss state.

Design rules
------------
1. **Read-only for recipients.**
   The only writes a recipient does are:
       - mark seen (``POST /notifications/{id}/seen``)
       - mark read (``POST /notifications/{id}/read``)
       - dismiss (``POST /notifications/{id}/dismiss``)

   All three are timestamp-only updates. There is no "create notification"
   endpoint — notifications are created by ``notification_service`` in
   response to events (alert fired, case assigned, message received,
   etc.).

2. **Batched notifications are common.**
   When the same dedup_key fires repeatedly, ``batch_count`` increments.
   The UI renders "5 new alerts from Acme Corp" from a single
   notification row. ``batch_count`` is exposed on both Read and List.

3. **Deep-link context is exposed via ``link_to_type`` + ``link_to_id``.**
   Clients use these to build "click to open" URLs. ``link_url`` is
   used for external URLs (e.g. report downloads).

4. **Priority is separate from notification_type.**
   Type = what event. Priority = urgency. A ``case_assigned`` type
   could be MEDIUM or CRITICAL priority depending on the case severity.

5. **Silent notifications don't trigger audio/email.**
   ``is_silent`` flag is exposed so clients respect it. Backend only
   sends email/webhook for non-silent notifications.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import NotificationType
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_PRIORITIES = frozenset({"low", "medium", "high", "critical"})

_LINK_TYPES = frozenset({
    "alert", "incident", "case", "evidence", "report",
    "conversation", "message", "invitation", "source",
    "collector", "analyst", "organization", "workspace",
})

_ACTION_TYPES = frozenset({
    "opened_target", "replied", "acknowledged", "assigned",
    "resolved", "dismissed_with_reason", "downloaded", "visited_link",
})

_TITLE_MAX = 255
_BODY_MAX = 5000
_LINK_URL_MAX = 2048
_ACTION_NOTES_MAX = 2000


# ============================================================================
# READ
# ============================================================================

class NotificationRead(TimestampedModel):
    """
    Full notification view. Returned by ``GET /notifications/{id}``.

    Includes everything the client needs to render the notification
    and route the user appropriately on click.
    """

    id: uuid.UUID
    recipient_id: uuid.UUID
    notification_type: NotificationType
    priority: str
    title: str
    body: str | None = None
    icon: str | None = None

    link_to_type: str | None = None
    link_to_id: uuid.UUID | None = None
    link_url: str | None = None

    related_workspace_id: uuid.UUID | None = None
    source_type: str | None = None
    source_id: uuid.UUID | None = None

    dedup_key: str | None = None
    batch_count: int = 1
    batch_first_at: datetime | None = None
    batch_last_at: datetime | None = None

    in_app_delivered_at: datetime | None = None
    email_sent_at: datetime | None = None
    email_delivered_at: datetime | None = None
    webhook_sent_at: datetime | None = None
    delivery_failures: int = 0

    seen_at: datetime | None = None
    read_at: datetime | None = None
    dismissed_at: datetime | None = None
    action_taken_at: datetime | None = None
    action_type: str | None = None
    action_notes: str | None = None

    expires_at: datetime | None = None
    is_silent: bool = False

    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_seen: bool = Field(..., description="True if the user has seen this.")
    is_read: bool = Field(..., description="True if the user has read this.")
    is_dismissed: bool = Field(..., description="True if dismissed.")
    is_active: bool = Field(
        ...,
        description="True if not dismissed and not expired — should appear in inbox.",
    )
    is_expired: bool = Field(..., description="True if past expires_at.")
    is_batched: bool = Field(..., description="True if batch_count > 1.")
    is_critical: bool = Field(..., description="True if priority is 'critical'.")
    is_high_priority: bool = Field(
        ..., description="True if priority is 'high' or 'critical'.",
    )
    has_action: bool = Field(..., description="True if the user has taken an action.")
    has_link: bool = Field(..., description="True if the notification has a clickable target.")


class NotificationList(ORMModel):
    """
    Lightweight notification view for the inbox list.

    Omits ``metadata``, ``action_notes``, and delivery timestamps —
    which the inbox doesn't need. Fetch ``GET /notifications/{id}``
    for full details if the client needs them.
    """

    id: uuid.UUID
    notification_type: NotificationType
    priority: str
    title: str
    body: str | None = None
    icon: str | None = None
    link_to_type: str | None = None
    link_to_id: uuid.UUID | None = None
    link_url: str | None = None
    related_workspace_id: uuid.UUID | None = None
    batch_count: int = 1
    seen_at: datetime | None = None
    read_at: datetime | None = None
    dismissed_at: datetime | None = None
    expires_at: datetime | None = None
    is_silent: bool = False
    created_at: datetime
    is_active: bool = True
    is_seen: bool = False
    is_read: bool = False


# ============================================================================
# STATE TRANSITIONS (recipient → backend)
# ============================================================================

class NotificationMarkSeen(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/{id}/seen``. Empty body is
    valid (``{}``). The endpoint records the current timestamp.
    """


class NotificationMarkRead(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/{id}/read``. Empty body is
    valid (``{}``). Implies ``mark_seen`` — a notification cannot be
    read without being seen first.
    """


class NotificationDismiss(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/{id}/dismiss``.

    Optional reason records why the user dismissed. Dismissal without
    a reason is fine (unlike alerts, where dismissal requires reason).
    """

    reason: str | None = Field(
        default=None,
        max_length=_ACTION_NOTES_MAX,
        description="Optional note about why the user dismissed this notification.",
    )


class NotificationRecordAction(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/{id}/action``.

    Recorded when the user takes an action in response to a
    notification — e.g. clicked through to the target, replied, or
    downloaded a report. Used for engagement analytics.
    """

    action_type: str = Field(
        ...,
        description=(
            "What the user did: opened_target | replied | acknowledged | "
            "assigned | resolved | dismissed_with_reason | downloaded | "
            "visited_link"
        ),
    )
    notes: str | None = Field(default=None, max_length=_ACTION_NOTES_MAX)

    @field_validator("action_type")
    @classmethod
    def _validate_action_type(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _ACTION_TYPES:
            raise ValueError(
                f"action_type must be one of {sorted(_ACTION_TYPES)}"
            )
        return normalized


# ============================================================================
# BULK OPERATIONS
# ============================================================================

class NotificationMarkAllSeen(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/seen-all``.

    Marks every unread notification for the current user as seen.
    Called when the user opens the notification inbox — the badge
    count drops to zero without requiring N individual calls.
    """

    workspace_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If provided, only mark notifications scoped to this workspace. "
            "If None, marks every notification for the current user."
        ),
    )


class NotificationMarkAllRead(CyberGuardBaseSchema):
    """
    Request body for ``POST /notifications/read-all``.

    Marks every seen-but-unread notification as read.
    """

    workspace_id: uuid.UUID | None = Field(default=None)


# ============================================================================
# FILTER
# ============================================================================

class NotificationFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /notifications``.
    """

    notification_type: NotificationType | None = None
    priority: str | None = Field(
        default=None,
        description="low | medium | high | critical",
    )

    related_workspace_id: uuid.UUID | None = None
    source_id: uuid.UUID | None = None

    unread_only: bool | None = Field(
        default=None,
        description="If True, only notifications with read_at IS NULL.",
    )
    unseen_only: bool | None = Field(
        default=None,
        description="If True, only notifications with seen_at IS NULL.",
    )
    active_only: bool | None = Field(
        default=True,
        description=(
            "If True (default), exclude dismissed and expired. "
            "Set False to include the full history."
        ),
    )

    created_after: datetime | None = None
    created_before: datetime | None = None

    @field_validator("priority")
    @classmethod
    def _validate_priority(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _PRIORITIES:
            raise ValueError(
                f"priority must be one of {sorted(_PRIORITIES)}"
            )
        return normalized


# ============================================================================
# BADGE / SUMMARY
# ============================================================================

class NotificationBadge(CyberGuardBaseSchema):
    """
    Response for ``GET /notifications/badge``.

    The icon badge count. Cheap to compute (single SQL COUNT) and
    frequently polled by frontends — hence a dedicated endpoint
    instead of requiring the client to fetch the full list.
    """

    total_active: int = Field(..., ge=0)
    unseen_count: int = Field(..., ge=0)
    unread_count: int = Field(..., ge=0)
    critical_count: int = Field(..., ge=0)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "NotificationRead",
    "NotificationList",
    "NotificationMarkSeen",
    "NotificationMarkRead",
    "NotificationDismiss",
    "NotificationRecordAction",
    "NotificationMarkAllSeen",
    "NotificationMarkAllRead",
    "NotificationFilter",
    "NotificationBadge",
]