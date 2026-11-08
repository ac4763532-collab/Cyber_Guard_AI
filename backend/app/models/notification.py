"""
CyberGuard AI — User Notifications
============================================================================

The ``notifications`` table: the per-user inbox for everything the platform
needs a user to know about.

Every notification is a **per-recipient instance** — when an alert fires,
three users each get their own row. Read state, seen state, and dismiss
state are per-user. There is no shared "notification" object.

This is not an event log. It's a personal inbox. Notifications are
ephemeral — hard-deleted after retention (90 days) or ``expires_at``.

Design decisions
----------------
1. **One row per recipient per notification event.**
   Read/dismiss/seen state is per-user, so each user gets their own row.

2. **``dedup_key`` for batching and spam prevention.**
   Partial unique index on ``(recipient_id, dedup_key) WHERE dismissed_at
   IS NULL AND dedup_key IS NOT NULL``. When set, a second notification
   with the same key (while the first is active) merges into the first via
   ``record_batch()`` instead of creating a new row. This is how "5 new
   alerts from acme-corp" works — one notification, batched count 5.

3. **``notification_type`` from ``NotificationType`` enum (12 types).**
   Every category of thing users need to know about has a stable type.

4. **``priority`` distinct from ``notification_type``.**
   A ``case_assigned`` notification is ``medium`` by default, but a
   ``case_assigned`` with ``priority='critical'`` indicates urgent
   attention needed. Sorting and UI filtering use priority.

5. **``link_to_type`` + ``link_to_id`` deep-linking.**
   When the user clicks the notification, they go to ``/alerts/{id}`` or
   ``/cases/CG-2026-001042`` or ``/incidents/{id}``. The frontend has the
   type→route map. ``link_url`` overrides with an external URL when
   needed (e.g. report download links).

6. **Delivery tracking per channel.**
   ``in_app_delivered_at``, ``email_sent_at``, ``email_delivered_at``,
   ``webhook_sent_at``. Plus ``delivery_attempts`` JSONB log — every send
   attempt is recorded. ``delivery_failures`` int counter drives retry.

7. **Engagement tracking.**
   ``seen_at`` (opened the inbox and saw it), ``read_at`` (explicitly
   marked read), ``dismissed_at`` (explicitly dismissed or auto-dismissed
   on action), ``action_taken_at`` + ``action_type`` (user did something
   in response). These are distinct — dashboards need all three.

8. **Batching fields.**
   ``batch_count``, ``batch_first_at``, ``batch_last_at``. Non-batched
   notifications have ``batch_count = 1``.

9. **``expires_at`` for auto-expiry.**
   Some notifications naturally resolve (e.g. "collector offline" expires
   when the collector comes back). The cleanup job removes expired
   notifications automatically.

10. **``related_workspace_id`` for tenant isolation.**
    A user may belong to multiple workspaces. Notifications from workspace
    A should be visually separated from workspace B in the inbox. Also
    used for workspace-scoped queries.

11. **``source_type`` + ``source_id`` for source-scoped notifications.**
    Optional. For notifications about a specific device ("collector
    offline", "credential rotation due").

12. **No ``SoftDeleteMixin``.**
    Notifications are hard-deleted after retention (90 days) or
    ``expires_at``. They're ephemeral UX artifacts — preserving beyond
    usefulness is waste.

13. **``is_silent`` flag.**
    Some notifications (e.g. ``case_status_changed`` from resolved to
    closed) shouldn't trigger a sound/vibration/email. ``is_silent=True``
    tells the frontend and the notification service to only update the
    badge count.

14. **Timezone correctness everywhere.**

Usage
-----
    from app.models import Notification
    from app.models.enums import NotificationType

    # Alert fires → notify the workspace owner and assigned analyst
    for recipient in (owner.id, analyst.id):
        notif = Notification.build(
            recipient_id=recipient,
            notification_type=NotificationType.ALERT_CREATED,
            title="New alert: Brute force on priya-laptop",
            body="6 failed logins in 40s from 203.0.113.42",
            priority="high",
            link_to_type="alert",
            link_to_id=alert.id,
            related_workspace_id=workspace.id,
            dedup_key=f"alert_created:{alert.fingerprint}",
        )
        db.add(notif)

    # Dedup: if the same alert fires again, batch into the existing notification
    existing = find_active_by_dedup_key(recipient_id, dedup_key, db)
    if existing:
        existing.record_batch()
    else:
        create_new_notification(...)

    # User opens the inbox
    notification.mark_seen()

    # User clicks the alert
    notification.mark_read()
    notification.record_action(action_type="opened_alert")

    # User dismisses without action
    notification.dismiss()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import NotificationType, enum_column_type


# ── Priority values ────────────────────────────────────────────────────────
_PRIORITY_LOW = "low"
_PRIORITY_MEDIUM = "medium"
_PRIORITY_HIGH = "high"
_PRIORITY_CRITICAL = "critical"
_VALID_PRIORITIES = frozenset({
    _PRIORITY_LOW,
    _PRIORITY_MEDIUM,
    _PRIORITY_HIGH,
    _PRIORITY_CRITICAL,
})

# ── Link target types ──────────────────────────────────────────────────────
#: Valid values for ``link_to_type``. Matches frontend routing.
_VALID_LINK_TYPES = frozenset({
    "alert",
    "incident",
    "case",
    "evidence",
    "report",
    "conversation",
    "message",
    "invitation",
    "source",
    "collector",
    "analyst",
    "organization",
    "workspace",
})

# ── Action types (what the user did in response) ──────────────────────────
_VALID_ACTION_TYPES = frozenset({
    "opened_target",
    "replied",
    "acknowledged",
    "assigned",
    "resolved",
    "dismissed_with_reason",
    "downloaded",
    "visited_link",
})

# ── Delivery channels ──────────────────────────────────────────────────────
_VALID_CHANNELS = frozenset({"in_app", "email", "webhook"})

# ── Size limits ────────────────────────────────────────────────────────────
_MAX_TITLE_LENGTH = 255
_MAX_BODY_LENGTH = 5000
_MAX_LINK_TYPE_LENGTH = 32
_MAX_LINK_URL_LENGTH = 2048
_MAX_SOURCE_TYPE_LENGTH = 32
_MAX_DEDUP_KEY_LENGTH = 255
_MAX_DELIVERY_ATTEMPTS = 50
_MAX_METADATA_BYTES = 32 * 1024
_MAX_ACTION_NOTES_LENGTH = 2000


class Notification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single notification for a single recipient.

    See the module docstring for the full design rationale. This class
    focuses on lifecycle and state.
    """

    __tablename__ = "notifications"

    __table_args__ = (
        # Priority must be one of the four documented values.
        CheckConstraint(
            "priority IN ('low', 'medium', 'high', 'critical')",
            name="priority_values",
        ),
        # Batch count must be at least 1.
        CheckConstraint(
            "batch_count >= 1",
            name="batch_count_positive",
        ),
        # Delivery failure counter non-negative.
        CheckConstraint(
            "delivery_failures >= 0",
            name="delivery_failures_non_negative",
        ),
        # Read requires seen (you can't read what you haven't seen).
        CheckConstraint(
            "read_at IS NULL OR seen_at IS NOT NULL",
            name="read_requires_seen",
        ),
        # Action requires read (you can't act on what you haven't read).
        CheckConstraint(
            "action_taken_at IS NULL OR read_at IS NOT NULL",
            name="action_requires_read",
        ),
        # Batch timestamps consistency.
        CheckConstraint(
            "batch_first_at IS NULL OR batch_last_at IS NULL OR "
            "batch_last_at >= batch_first_at",
            name="batch_times_ordered",
        ),
        # Expiry must be in the future of creation.
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="expires_after_created",
        ),
        # Partial unique: one active notification per (recipient, dedup_key).
        # De-duplicates notifications that share a key while active.
        Index(
            "uq_notifications_active_dedup",
            "recipient_id",
            "dedup_key",
            unique=True,
            postgresql_where=text(
                "dismissed_at IS NULL AND dedup_key IS NOT NULL"
            ),
        ),
        # Main query: user's active inbox.
        Index(
            "ix_notifications_recipient_active",
            "recipient_id",
            "dismissed_at",
            "created_at",
        ),
        # Unread badge query.
        Index(
            "ix_notifications_recipient_unread",
            "recipient_id",
            "seen_at",
        ),
        # Workspace-scoped queries.
        Index(
            "ix_notifications_workspace_created",
            "related_workspace_id",
            "created_at",
        ),
        # Type filter.
        Index(
            "ix_notifications_type_created",
            "notification_type",
            "created_at",
        ),
        # Priority filter for critical alerts.
        Index(
            "ix_notifications_priority_unread",
            "priority",
            "seen_at",
        ),
        # Deep-link queries.
        Index(
            "ix_notifications_link",
            "link_to_type",
            "link_to_id",
        ),
        # Expiry cleanup.
        Index(
            "ix_notifications_expires_at",
            "expires_at",
        ),
    )

    # ─── Recipient ──────────────────────────────────────────────────────
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User who receives the notification. CASCADE on user delete.",
    )

    # ─── Classification ────────────────────────────────────────────────
    notification_type: Mapped[NotificationType] = mapped_column(
        enum_column_type(NotificationType),
        nullable=False,
        index=True,
        comment="What kind of event this notification is for.",
    )

    priority: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_PRIORITY_MEDIUM,
        server_default=_PRIORITY_MEDIUM,
        index=True,
        comment="Urgency for sorting/filtering: low, medium, high, critical.",
    )

    # ─── Presentation ──────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH),
        nullable=False,
        comment="One-line summary shown in the notification list.",
    )

    body: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Longer text shown on the detail view or tooltip.",
    )

    icon: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Optional icon identifier for UI rendering.",
    )

    # ─── Deep links ────────────────────────────────────────────────────
    link_to_type: Mapped[str | None] = mapped_column(
        String(_MAX_LINK_TYPE_LENGTH),
        nullable=True,
        comment=(
            "Entity type for deep-linking: alert, incident, case, evidence, "
            "report, conversation, message, invitation, source, collector, "
            "analyst, organization, workspace."
        ),
    )

    link_to_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        comment="UUID of the target entity. Paired with link_to_type.",
    )

    link_url: Mapped[str | None] = mapped_column(
        String(_MAX_LINK_URL_LENGTH),
        nullable=True,
        comment=(
            "Full URL for external links (report downloads, etc.). "
            "Overrides link_to_type + link_to_id when set."
        ),
    )

    # ─── Scope ──────────────────────────────────────────────────────────
    related_workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Workspace this notification is scoped to. Enables "
            "workspace-grouped inbox views."
        ),
    )

    source_type: Mapped[str | None] = mapped_column(
        String(_MAX_SOURCE_TYPE_LENGTH),
        nullable=True,
        comment="Optional source kind (windows, linux, email, ...).",
    )

    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_sources.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Optional source instance (e.g. for 'collector offline').",
    )

    # ─── Deduplication & batching ──────────────────────────────────────
    dedup_key: Mapped[str | None] = mapped_column(
        String(_MAX_DEDUP_KEY_LENGTH),
        nullable=True,
        index=True,
        comment=(
            "Optional key for deduplication. When set, notifications with "
            "the same key (while active) merge into the first one instead "
            "of creating a new row."
        ),
    )

    batch_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
        comment=(
            "Number of events aggregated into this notification. "
            "Non-batched notifications have batch_count=1."
        ),
    )

    batch_first_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the first event in the batch.",
    )

    batch_last_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the most recent event in the batch.",
    )

    # ─── Delivery tracking ─────────────────────────────────────────────
    in_app_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="In-app notifications are considered delivered at creation.",
    )

    email_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When an email was dispatched.",
    )

    email_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the email provider confirmed delivery.",
    )

    webhook_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the webhook was successfully POSTed.",
    )

    delivery_attempts: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Append-only log of delivery attempts: "
            "[{channel, at, success, error}]. Capped at _MAX_DELIVERY_ATTEMPTS."
        ),
    )

    delivery_failures: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Total number of failed delivery attempts across all channels.",
    )

    # ─── Engagement tracking ───────────────────────────────────────────
    seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "When the user opened the notification inbox and saw this "
            "notification. Drives the 'unread' badge count."
        ),
    )

    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the user explicitly marked the notification as read.",
    )

    dismissed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the user dismissed the notification without acting.",
    )

    action_taken_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the user took an action in response to this notification.",
    )

    action_type: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        comment=(
            "What the user did: opened_target, replied, acknowledged, "
            "assigned, resolved, dismissed_with_reason, downloaded, visited_link."
        ),
    )

    action_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional notes about the action taken.",
    )

    # ─── Lifecycle ─────────────────────────────────────────────────────
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "Optional auto-expiry. Cleanup job removes expired rows. "
            "Set by the service when the underlying condition can resolve "
            "(e.g. 'collector offline' expires when the collector returns)."
        ),
    )

    is_silent: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment=(
            "If True, no sound/vibration/email is triggered. Only the "
            "badge count updates. Used for low-priority status changes."
        ),
    )

    # ─── Metadata ──────────────────────────────────────────────────────
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Free-form structured metadata for the notification "
            "(e.g. rendered i18n parameters, template variables)."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("priority")
    def _validate_priority(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="priority must be a string",
                code="NOTIFICATION_PRIORITY_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_PRIORITIES:
            raise ValidationError(
                message=f"priority must be one of {sorted(_VALID_PRIORITIES)}",
                code="NOTIFICATION_PRIORITY_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_PRIORITIES),
                },
            )
        return normalized

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="NOTIFICATION_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="NOTIFICATION_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="NOTIFICATION_TITLE_TOO_LONG",
            )
        return stripped

    @validates("body")
    def _validate_body(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="body must be a string or None",
                code="NOTIFICATION_BODY_INVALID_TYPE",
            )
        if len(value) > _MAX_BODY_LENGTH:
            raise ValidationError(
                message=f"body must not exceed {_MAX_BODY_LENGTH} characters",
                code="NOTIFICATION_BODY_TOO_LONG",
            )
        return value

    @validates("notification_type")
    def _validate_notification_type(
        self, _key: str, value: NotificationType | str
    ) -> NotificationType:
        if isinstance(value, NotificationType):
            return value
        if isinstance(value, str):
            try:
                return NotificationType(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid notification_type {value!r}",
                    code="NOTIFICATION_TYPE_INVALID",
                    details={"allowed": list(NotificationType.values())},
                ) from exc
        raise ValidationError(
            message="notification_type must be a NotificationType or string",
            code="NOTIFICATION_TYPE_INVALID_TYPE",
        )

    @validates("link_to_type")
    def _validate_link_type(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="link_to_type must be a string or None",
                code="NOTIFICATION_LINK_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized not in _VALID_LINK_TYPES:
            raise ValidationError(
                message=f"link_to_type must be one of {sorted(_VALID_LINK_TYPES)}",
                code="NOTIFICATION_LINK_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_LINK_TYPES),
                },
            )
        return normalized

    @validates("link_url")
    def _validate_link_url(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="link_url must be a string or None",
                code="NOTIFICATION_LINK_URL_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_LINK_URL_LENGTH:
            raise ValidationError(
                message=f"link_url must not exceed {_MAX_LINK_URL_LENGTH} characters",
                code="NOTIFICATION_LINK_URL_TOO_LONG",
            )
        if not stripped.startswith(("http://", "https://", "/")):
            raise ValidationError(
                message=(
                    "link_url must start with 'http://', 'https://', or '/'"
                ),
                code="NOTIFICATION_LINK_URL_INVALID_SCHEME",
            )
        return stripped

    @validates("dedup_key")
    def _validate_dedup_key(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="dedup_key must be a string or None",
                code="NOTIFICATION_DEDUP_KEY_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_DEDUP_KEY_LENGTH:
            raise ValidationError(
                message=f"dedup_key must not exceed {_MAX_DEDUP_KEY_LENGTH} characters",
                code="NOTIFICATION_DEDUP_KEY_TOO_LONG",
            )
        return stripped

    @validates("action_type")
    def _validate_action_type(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="action_type must be a string or None",
                code="NOTIFICATION_ACTION_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized not in _VALID_ACTION_TYPES:
            raise ValidationError(
                message=f"action_type must be one of {sorted(_VALID_ACTION_TYPES)}",
                code="NOTIFICATION_ACTION_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_ACTION_TYPES),
                },
            )
        return normalized

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        recipient_id: uuid.UUID,
        notification_type: NotificationType,
        title: str,
        body: str | None = None,
        priority: str = _PRIORITY_MEDIUM,
        icon: str | None = None,
        link_to_type: str | None = None,
        link_to_id: uuid.UUID | None = None,
        link_url: str | None = None,
        related_workspace_id: uuid.UUID | None = None,
        source_type: str | None = None,
        source_id: uuid.UUID | None = None,
        dedup_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        expires_at: datetime | None = None,
        is_silent: bool = False,
    ) -> "Notification":
        """
        Construct a new notification.

        In-app delivery is considered instant — ``in_app_delivered_at`` is
        set to now. Email and webhook delivery is triggered by the service
        layer (``notification_service``).
        """
        now = datetime.now(timezone.utc)
        return cls(
            recipient_id=recipient_id,
            notification_type=notification_type,
            priority=priority,
            title=title,
            body=body,
            icon=icon,
            link_to_type=link_to_type,
            link_to_id=link_to_id,
            link_url=link_url,
            related_workspace_id=related_workspace_id,
            source_type=source_type,
            source_id=source_id,
            dedup_key=dedup_key,
            batch_count=1,
            batch_first_at=now,
            batch_last_at=now,
            in_app_delivered_at=now,
            metadata_json=metadata or {},
            expires_at=expires_at,
            is_silent=is_silent,
        )

    # ====================================================================
    # BATCHING
    # ====================================================================

    def record_batch(self, *, count: int = 1) -> None:
        """
        Merge additional events into this notification. Called when a new
        notification with the same ``dedup_key`` (while active) is attempted.
        The batch count is incremented, ``batch_last_at`` is bumped, and
        the title is (optionally) rewritten by the service to say
        "N new alerts" instead of "1 new alert".
        """
        if count < 1:
            raise ValidationError(
                message="count must be at least 1",
                code="NOTIFICATION_BATCH_COUNT_INVALID",
            )
        self.batch_count += count
        self.batch_last_at = datetime.now(timezone.utc)

    # ====================================================================
    # ENGAGEMENT
    # ====================================================================

    def mark_seen(self) -> None:
        """
        Record that the user opened the notification inbox and saw this
        notification. Idempotent — subsequent calls are no-ops.
        """
        if self.seen_at is None:
            self.seen_at = datetime.now(timezone.utc)

    def mark_read(self) -> None:
        """
        Record that the user explicitly marked this notification as read.
        Implies ``mark_seen()``. Idempotent.
        """
        if self.read_at is None:
            now = datetime.now(timezone.utc)
            if self.seen_at is None:
                self.seen_at = now
            self.read_at = now

    def dismiss(self) -> None:
        """
        Record that the user dismissed the notification without acting.
        Implies ``mark_read()``. Idempotent.
        """
        if self.dismissed_at is None:
            now = datetime.now(timezone.utc)
            if self.read_at is None:
                self.mark_read()
            self.dismissed_at = now

    def record_action(
        self,
        *,
        action_type: str,
        notes: str | None = None,
    ) -> None:
        """
        Record that the user took an action in response to this
        notification. Implies ``mark_read()``. Sets ``action_taken_at``
        and stores the action type and optional notes.
        """
        if self.action_taken_at is None:
            if self.read_at is None:
                self.mark_read()
            self.action_taken_at = datetime.now(timezone.utc)
        self.action_type = action_type
        if notes:
            if len(notes) > _MAX_ACTION_NOTES_LENGTH:
                raise ValidationError(
                    message=(
                        f"action_notes must not exceed "
                        f"{_MAX_ACTION_NOTES_LENGTH} characters"
                    ),
                    code="NOTIFICATION_ACTION_NOTES_TOO_LONG",
                )
            self.action_notes = notes.strip()

    # ====================================================================
    # DELIVERY
    # ====================================================================

    def record_delivery_attempt(
        self,
        *,
        channel: str,
        success: bool,
        error: str | None = None,
    ) -> None:
        """
        Record a delivery attempt for a channel. Updates the per-channel
        timestamp on success, appends to ``delivery_attempts``, and
        increments ``delivery_failures`` on failure.
        """
        if channel not in _VALID_CHANNELS:
            raise ValidationError(
                message=f"channel must be one of {sorted(_VALID_CHANNELS)}",
                code="NOTIFICATION_CHANNEL_INVALID",
                details={"received": channel},
            )

        now = datetime.now(timezone.utc)
        attempts = list(self.delivery_attempts or [])

        if len(attempts) >= _MAX_DELIVERY_ATTEMPTS:
            # Do not append — cap reached. Still update counters.
            if not success:
                self.delivery_failures += 1
            return

        attempts.append({
            "channel": channel,
            "at": now.isoformat(),
            "success": success,
            "error": error,
        })
        self.delivery_attempts = attempts

        if success:
            if channel == "in_app":
                self.in_app_delivered_at = now
            elif channel == "email":
                self.email_sent_at = now
                # Provider-confirmed delivery is tracked separately via
                # record_email_delivered()
            elif channel == "webhook":
                self.webhook_sent_at = now
        else:
            self.delivery_failures += 1

    def record_email_delivered(self) -> None:
        """Mark email as confirmed delivered (from provider webhook)."""
        if self.email_delivered_at is None:
            self.email_delivered_at = datetime.now(timezone.utc)

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_seen(self) -> bool:
        """True if the user has seen this notification."""
        return self.seen_at is not None

    @property
    def is_read(self) -> bool:
        """True if the user has read this notification."""
        return self.read_at is not None

    @property
    def is_dismissed(self) -> bool:
        """True if the user dismissed this notification."""
        return self.dismissed_at is not None

    @property
    def is_active(self) -> bool:
        """
        True if the notification is still active — not dismissed, not
        expired. This is the "should it appear in the inbox" check.
        """
        if self.is_dismissed:
            return False
        if self.expires_at is not None:
            exp = self.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return False
        return True

    @property
    def is_expired(self) -> bool:
        """True if the notification's ``expires_at`` has passed."""
        if self.expires_at is None:
            return False
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    @property
    def is_batched(self) -> bool:
        """True if this notification aggregates multiple events."""
        return self.batch_count > 1

    @property
    def is_critical(self) -> bool:
        """True if priority is critical."""
        return self.priority == _PRIORITY_CRITICAL

    @property
    def is_high_priority(self) -> bool:
        """True if priority is high or critical."""
        return self.priority in (_PRIORITY_HIGH, _PRIORITY_CRITICAL)

    @property
    def has_action(self) -> bool:
        """True if the user has taken an action in response."""
        return self.action_taken_at is not None

    @property
    def has_link(self) -> bool:
        """True if the notification has a clickable target."""
        return (
            self.link_url is not None
            or (self.link_to_type is not None and self.link_to_id is not None)
        )

    @property
    def age_seconds(self) -> int:
        """Seconds since the notification was created."""
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - created).total_seconds())

    @property
    def time_to_seen_seconds(self) -> int | None:
        """Seconds from creation to when the user first saw it."""
        if self.seen_at is None:
            return None
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        seen = self.seen_at
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return int((seen - created).total_seconds())

    @property
    def time_to_action_seconds(self) -> int | None:
        """Seconds from creation to when the user acted on it."""
        if self.action_taken_at is None:
            return None
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        action = self.action_taken_at
        if action.tzinfo is None:
            action = action.replace(tzinfo=timezone.utc)
        return int((action - created).total_seconds())


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.user import User
#     from app.models.workspace import Workspace
#     from app.models.source import SecuritySource
#
# class Notification(...):
#     ...
#     recipient: Mapped["User"] = relationship(
#         "User", foreign_keys=[recipient_id]
#     )
#     related_workspace: Mapped["Workspace | None"] = relationship(
#         "Workspace"
#     )
#     source: Mapped["SecuritySource | None"] = relationship(
#         "SecuritySource"
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "Notification",
    "_PRIORITY_LOW",
    "_PRIORITY_MEDIUM",
    "_PRIORITY_HIGH",
    "_PRIORITY_CRITICAL",
    "_VALID_PRIORITIES",
    "_VALID_LINK_TYPES",
    "_VALID_ACTION_TYPES",
    "_VALID_CHANNELS",
    "_MAX_TITLE_LENGTH",
    "_MAX_BODY_LENGTH",
    "_MAX_LINK_TYPE_LENGTH",
    "_MAX_LINK_URL_LENGTH",
    "_MAX_SOURCE_TYPE_LENGTH",
    "_MAX_DEDUP_KEY_LENGTH",
    "_MAX_DELIVERY_ATTEMPTS",
    "_MAX_METADATA_BYTES",
    "_MAX_ACTION_NOTES_LENGTH",
]