"""
CyberGuard AI - Notification Repository

Database operations for Notification entities (per-recipient delivery
records for alerts). Mirrors AlertRepository's conventions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from app.database.connection import get_database
from app.database.models import (
    Notification,
    NotificationCreate,
    NotificationStatus,
)

logger = structlog.get_logger(__name__)


class NotificationRepository:
    """Repository for Notification database operations."""

    def __init__(self):
        self.db = get_database()

    async def create(self, notification: NotificationCreate) -> Notification | None:
        """
        Create a new notification, or return the existing one if this
        exact (recipient, channel, fingerprint) combination was already
        queued - this is the deduplication guarantee from the schema's
        UNIQUE constraint, enforced here via ON CONFLICT DO NOTHING.
        """
        now = datetime.now(timezone.utc)

        query = """
            INSERT INTO notifications (
                id, alert_id, tenant_id,
                recipient_user_id, recipient_address, channel, severity,
                title, summary, fingerprint, status,
                created_at, queued_at
            )
            VALUES (
                gen_random_uuid(), %(alert_id)s, %(tenant_id)s,
                %(recipient_user_id)s, %(recipient_address)s, %(channel)s, %(severity)s,
                %(title)s, %(summary)s, %(fingerprint)s, %(status)s,
                %(created_at)s, %(queued_at)s
            )
            ON CONFLICT (recipient_user_id, channel, fingerprint) DO NOTHING
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "alert_id": notification.alert_id,
            "tenant_id": notification.tenant_id,
            "recipient_user_id": notification.recipient_user_id,
            "recipient_address": notification.recipient_address,
            "channel": notification.channel.value,
            "severity": notification.severity.value,
            "title": notification.title,
            "summary": notification.summary,
            "fingerprint": notification.fingerprint,
            "status": NotificationStatus.PENDING.value,
            "created_at": now,
            "queued_at": now,
        })

        if result:
            return self._row_to_notification(result)

        # Conflict - already queued. Return the existing row so the
        # caller can inspect its real status rather than assuming success.
        logger.debug(
            "Notification already queued (deduplicated)",
            recipient_user_id=notification.recipient_user_id,
            channel=notification.channel.value,
            fingerprint=notification.fingerprint,
        )
        return await self.get_by_fingerprint(
            notification.recipient_user_id, notification.channel.value, notification.fingerprint
        )

    async def get(self, notification_id: str) -> Notification | None:
        """Get a notification by ID."""
        query = "SELECT * FROM notifications WHERE id = %(id)s"
        result = await self.db.execute_one(query, {"id": notification_id})
        return self._row_to_notification(result) if result else None

    async def get_by_fingerprint(
        self, recipient_user_id: str, channel: str, fingerprint: str
    ) -> Notification | None:
        """Get a notification by its deduplication key."""
        query = """
            SELECT * FROM notifications
            WHERE recipient_user_id = %(recipient_user_id)s
              AND channel = %(channel)s
              AND fingerprint = %(fingerprint)s
        """
        result = await self.db.execute_one(query, {
            "recipient_user_id": recipient_user_id,
            "channel": channel,
            "fingerprint": fingerprint,
        })
        return self._row_to_notification(result) if result else None

    async def list_for_user(
        self,
        recipient_user_id: str,
        limit: int = 50,
        offset: int = 0,
        unread_only: bool = False,
    ) -> list[Notification]:
        """List notifications for a user, newest first."""
        conditions = ["recipient_user_id = %(recipient_user_id)s", "channel = 'in_app'"]
        params: dict[str, Any] = {
            "recipient_user_id": recipient_user_id,
            "limit": limit,
            "offset": offset,
        }

        if unread_only:
            conditions.append("read_at IS NULL")

        where_clause = " AND ".join(conditions)

        query = f"""
            SELECT * FROM notifications
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, params)
        return [self._row_to_notification(row) for row in results]

    async def count_unread(self, recipient_user_id: str) -> int:
        """Count unread in-app notifications for a user."""
        query = """
            SELECT COUNT(*) as count FROM notifications
            WHERE recipient_user_id = %(recipient_user_id)s
              AND channel = 'in_app'
              AND read_at IS NULL
        """
        result = await self.db.execute_one(query, {"recipient_user_id": recipient_user_id})
        return result["count"] if result else 0

    async def mark_sent(self, notification_id: str) -> Notification | None:
        """Mark a notification as successfully delivered. Call this only
        after the sending service receives a confirmed success response
        from the provider (SMTP accept, webhook 2xx) - never speculatively."""
        query = """
            UPDATE notifications
            SET status = %(status)s, sent_at = %(sent_at)s, attempts = attempts + 1
            WHERE id = %(id)s
            RETURNING *
        """
        result = await self.db.execute_one(query, {
            "id": notification_id,
            "status": NotificationStatus.SENT.value,
            "sent_at": datetime.now(timezone.utc),
        })
        return self._row_to_notification(result) if result else None

    async def mark_failed(self, notification_id: str, error: str) -> Notification | None:
        """Record a failed delivery attempt with its real error, for retry/audit."""
        query = """
            UPDATE notifications
            SET status = %(status)s, last_error = %(error)s, attempts = attempts + 1
            WHERE id = %(id)s
            RETURNING *
        """
        result = await self.db.execute_one(query, {
            "id": notification_id,
            "status": NotificationStatus.FAILED.value,
            "error": error[:2000],  # bound stored error size
        })
        return self._row_to_notification(result) if result else None

    async def mark_read(self, notification_id: str, recipient_user_id: str) -> Notification | None:
        """Mark a notification read. Scoped to the recipient so one user
        cannot mark another user's notification read."""
        query = """
            UPDATE notifications
            SET status = %(status)s, read_at = %(read_at)s
            WHERE id = %(id)s AND recipient_user_id = %(recipient_user_id)s
            RETURNING *
        """
        result = await self.db.execute_one(query, {
            "id": notification_id,
            "recipient_user_id": recipient_user_id,
            "status": NotificationStatus.READ.value,
            "read_at": datetime.now(timezone.utc),
        })
        return self._row_to_notification(result) if result else None

    def _row_to_notification(self, row: dict[str, Any]) -> Notification:
        """Convert database row to Notification model."""
        return Notification(
            id=str(row["id"]),
            alert_id=str(row["alert_id"]) if row.get("alert_id") else None,
            tenant_id=row.get("tenant_id"),
            recipient_user_id=row["recipient_user_id"],
            recipient_address=row.get("recipient_address"),
            channel=row["channel"],
            severity=row["severity"],
            title=row["title"],
            summary=row["summary"],
            fingerprint=row["fingerprint"],
            status=row.get("status", "pending"),
            attempts=row.get("attempts", 0),
            last_error=row.get("last_error"),
            created_at=row["created_at"],
            queued_at=row["queued_at"],
            sent_at=row.get("sent_at"),
            read_at=row.get("read_at"),
        )


# Singleton
_notification_repo: NotificationRepository | None = None


def get_notification_repository() -> NotificationRepository:
    """Get the notification repository."""
    global _notification_repo
    if _notification_repo is None:
        _notification_repo = NotificationRepository()
    return _notification_repo
