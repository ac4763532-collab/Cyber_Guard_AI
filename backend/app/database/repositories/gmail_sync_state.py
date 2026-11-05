"""
CyberGuard AI - Gmail Sync State Repository

Persists each connected account's Gmail history.list() cursor
(gmail_sync_state table) so the automatic poller
(app/services/gmail/poller.py) only fetches new/changed messages per
cycle instead of re-listing the whole mailbox on every poll - directly
supports the "avoid downloading complete mailbox contents on every
polling cycle" requirement.

Non-sensitive: history_id is an opaque incrementing cursor Gmail itself
exposes via its API, not a credential - unlike oauth_tokens, nothing here
is encrypted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from app.database.connection import get_database

logger = structlog.get_logger(__name__)


class GmailSyncState:
    """Gmail sync state record for one user."""

    def __init__(
        self,
        user_id: str,
        history_id: str | None,
        last_polled_at: datetime | None,
        last_error: str | None,
        last_error_at: datetime | None,
        created_at: datetime,
        updated_at: datetime,
    ):
        self.user_id = user_id
        self.history_id = history_id
        self.last_polled_at = last_polled_at
        self.last_error = last_error
        self.last_error_at = last_error_at
        self.created_at = created_at
        self.updated_at = updated_at


class GmailSyncStateRepository:
    """Repository for gmail_sync_state database operations."""

    def __init__(self):
        self.db = get_database()

    async def get(self, user_id: str) -> GmailSyncState | None:
        """Get the sync state for a user, or None if never polled."""
        query = "SELECT * FROM gmail_sync_state WHERE user_id = %(user_id)s"
        result = await self.db.execute_one(query, {"user_id": user_id})
        return self._row_to_state(result) if result else None

    async def set_history_id(self, user_id: str, history_id: str) -> None:
        """
        Record a successful poll: persist the new history_id cursor and
        clear any previous error (a successful poll supersedes it).
        """
        now = datetime.now(timezone.utc)
        query = """
            INSERT INTO gmail_sync_state (
                user_id, history_id, last_polled_at, last_error, last_error_at,
                created_at, updated_at
            )
            VALUES (
                %(user_id)s, %(history_id)s, %(now)s, NULL, NULL, %(now)s, %(now)s
            )
            ON CONFLICT (user_id) DO UPDATE SET
                history_id = EXCLUDED.history_id,
                last_polled_at = EXCLUDED.last_polled_at,
                last_error = NULL,
                last_error_at = NULL,
                updated_at = EXCLUDED.updated_at
        """
        await self.db.execute(query, {"user_id": user_id, "history_id": history_id, "now": now})

    async def record_error(self, user_id: str, error: str) -> None:
        """
        Record a failed poll without disturbing the existing history_id -
        a transient failure (e.g. token refresh error, network issue)
        must not reset the cursor, only surface the failure for the
        "automatic monitoring" status indicator to show.
        """
        now = datetime.now(timezone.utc)
        query = """
            INSERT INTO gmail_sync_state (
                user_id, history_id, last_polled_at, last_error, last_error_at,
                created_at, updated_at
            )
            VALUES (
                %(user_id)s, NULL, NULL, %(error)s, %(now)s, %(now)s, %(now)s
            )
            ON CONFLICT (user_id) DO UPDATE SET
                last_error = EXCLUDED.last_error,
                last_error_at = EXCLUDED.last_error_at,
                updated_at = EXCLUDED.updated_at
        """
        await self.db.execute(query, {"user_id": user_id, "error": error, "now": now})

    async def clear(self, user_id: str) -> None:
        """Delete sync state for a user (e.g. on Gmail disconnect)."""
        query = "DELETE FROM gmail_sync_state WHERE user_id = %(user_id)s"
        await self.db.execute(query, {"user_id": user_id})

    def _row_to_state(self, row: dict[str, Any]) -> GmailSyncState:
        return GmailSyncState(
            user_id=str(row["user_id"]),
            history_id=row.get("history_id"),
            last_polled_at=row.get("last_polled_at"),
            last_error=row.get("last_error"),
            last_error_at=row.get("last_error_at"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


# Singleton
_gmail_sync_state_repo: GmailSyncStateRepository | None = None


def get_gmail_sync_state_repository() -> GmailSyncStateRepository:
    """Get the Gmail sync state repository."""
    global _gmail_sync_state_repo
    if _gmail_sync_state_repo is None:
        _gmail_sync_state_repo = GmailSyncStateRepository()
    return _gmail_sync_state_repo
