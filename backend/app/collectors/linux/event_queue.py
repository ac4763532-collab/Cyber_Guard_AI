"""
CyberGuard AI — Linux Collector Event Queue
============================================================================

Durable SQLite-backed queue between the log reader and the sender.

Same implementation as the Windows collector's ``event_queue.py`` —
SQLite WAL mode, at-least-once delivery, FIFO ordering, exponential
backoff on failure, bounded size with oldest-drop, 7-day retention.

Why SQLite (and not a message broker)
-------------------------------------
The collector runs on the device. There is no Kafka, no RabbitMQ,
no Redis — installing those on every monitored host is a non-starter.
SQLite is:

    - Zero-dependency (stdlib ``sqlite3``)
    - Durable across crashes
    - Fast (10k+ inserts/sec on consumer hardware)
    - WAL mode — concurrent reads during writes
    - Transactional — atomic dequeue prevents duplicate sends

For a single-process queue with up to ~100k events, this is the right
tool. A message broker would be over-engineering at a scale of one.

Schema
------
    events (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        TEXT NOT NULL UNIQUE,      -- client UUID
        payload         TEXT NOT NULL,             -- JSON event
        created_at      REAL NOT NULL,             -- unix ts
        attempts        INTEGER NOT NULL DEFAULT 0,
        next_retry_at   REAL NOT NULL DEFAULT 0
    )

The ``event_id`` UNIQUE constraint makes enqueue idempotent — a
reader that re-enqueues after a crash produces no duplicate row.
The sender tracks successes against the same UUID so backend
fingerprint dedup is symmetric on both sides.

Guarantees
----------
    - **At-least-once**: rows are deleted only after the backend
      acknowledges. Crash-after-send is harmless — the backend
      fingerprint dedup catches the re-send.
    - **FIFO**: ``dequeue_batch`` orders by ``created_at`` so a
      backlog is drained oldest-first.
    - **Backoff**: failed sends set ``next_retry_at``. Successive
      failures push it further into the future (5s → 300s cap).
    - **Bounded size**: exceeding ``max_queue_size`` drops the
      OLDEST events (recent ones matter more for investigation).
    - **Bounded age**: events older than 7 days drop in cleanup.

Linux-specific notes
--------------------
- Queue file lives at ``/var/lib/cyberguard/collector/queue.db``
  (STATE_DIR from config.py) with mode 0640 root:cyberguard.
- Permissions matter: if the file is writable only by root, the
  collector must run as root (which systemd units do by default).
- The 7-day retention window means a Linux collector that has been
  offline for 8 days will silently drop everything older than 7 days
  on the first cleanup pass. This is intentional — an event from
  8 days ago is not actionable. The ``_MAX_EVENT_AGE_DAYS`` constant
  is where this is defined.

Usage
-----
    from event_queue import EventQueue

    queue = EventQueue()   # opens QUEUE_FILE from config.py

    # Reader thread:
    event_uuid = queue.enqueue({"event_time": "...", "event_type": "..."})

    # Sender thread:
    batch = queue.dequeue_batch(limit=100)
    result = client.send_batch([e.payload for e in batch])
    if result.success:
        queue.mark_sent([e.event_id for e in batch])
    else:
        queue.mark_failed(
            [e.event_id for e in batch],
            should_retry=result.should_retry,
            retry_after_seconds=result.retry_after_seconds,
        )

    # Periodic cleanup (sender loop):
    queue.cleanup_expired()
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config import QUEUE_FILE


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Max send attempts before a row is dropped (retrying won't help).
_MAX_ATTEMPTS = 10

#: Exponential backoff: 5s, 10s, 20s, 40s, 80s … capped at 300s.
_BASE_BACKOFF_SECONDS = 5.0
_MAX_BACKOFF_SECONDS = 300.0

#: Events older than this drop during cleanup — they're no longer
#: actionable. 7 days matches the default retention in most enterprise
#: incident-response playbooks.
_MAX_EVENT_AGE_DAYS = 7

#: SQLite busy timeout (ms) — wait this long on a lock before SQLITE_BUSY.
#: With a single writer thread, contention is rare; this is defensive.
_BUSY_TIMEOUT_MS = 5000


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass(frozen=True)
class QueuedEvent:
    """A single event as stored in the queue."""
    event_id: str
    payload: dict[str, Any]
    created_at: float
    attempts: int


# ============================================================================
# QUEUE
# ============================================================================

class EventQueue:
    """
    SQLite-backed durable event queue.

    Thread-safe for one reader thread + one sender thread (via internal
    ``threading.RLock``). Not safe for multiple writers — the collector's
    architecture uses exactly one of each.
    """

    def __init__(
        self,
        *,
        db_path: Path | str | None = None,
        max_queue_size: int = 10000,
    ) -> None:
        self._db_path = Path(db_path) if db_path else QUEUE_FILE
        self._max_queue_size = max(100, int(max_queue_size))
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._open()

    # ── Lifecycle ──────────────────────────────────────────────────────

    def _open(self) -> None:
        """Open the SQLite connection and ensure the schema is present."""
        if self._conn is not None:
            return

        self._conn = sqlite3.connect(
            str(self._db_path),
            timeout=_BUSY_TIMEOUT_MS / 1000.0,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        self._ensure_schema()

        # Restrict permissions on the queue file (contains event payloads
        # with potential PII or exploitation artifacts). 0640 — root +
        # group. Only meaningful when running as root; the collector's
        # systemd unit handles this from the process side too.
        try:
            import os
            os.chmod(self._db_path, 0o640)
        except OSError:
            pass

        logger.info(
            "EventQueue opened",
            extra={
                "db_path": str(self._db_path),
                "max_queue_size": self._max_queue_size,
            },
        )

    def _ensure_schema(self) -> None:
        """Create the events table and indexes if they don't exist."""
        with self._lock:
            assert self._conn is not None
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at REAL NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_events_next_retry
                    ON events(next_retry_at);
                CREATE INDEX IF NOT EXISTS idx_events_created_at
                    ON events(created_at);
                """
            )
            self._conn.commit()

    def close(self) -> None:
        """Close the connection. Safe to call multiple times."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self._conn = None
                logger.info("EventQueue closed")

    # ── Enqueue ────────────────────────────────────────────────────────

    def enqueue(
        self,
        payload: dict[str, Any],
        *,
        event_id: str | None = None,
    ) -> str:
        """
        Add one event to the queue. Returns the event_id.

        ``event_id`` defaults to a fresh UUID. Callers that can derive
        a stable UUID (e.g. from a hash of the source event fields) can
        pass it and make re-enqueue idempotent — the UNIQUE constraint
        rejects the duplicate silently.

        Raises ValueError if ``payload`` is not JSON-serializable.
        """
        if event_id is None:
            event_id = str(uuid.uuid4())

        try:
            payload_json = json.dumps(payload, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Event payload is not JSON-serializable: {exc}")

        now = time.time()

        with self._lock:
            assert self._conn is not None
            self._enforce_size_cap()

            try:
                self._conn.execute(
                    """
                    INSERT INTO events
                        (event_id, payload, created_at, attempts, next_retry_at)
                    VALUES (?, ?, ?, 0, 0)
                    """,
                    (event_id, payload_json, now),
                )
                self._conn.commit()
                return event_id
            except sqlite3.IntegrityError:
                # Duplicate event_id — re-enqueue after a reader restart.
                # Treat as success (idempotent).
                logger.debug(
                    "Duplicate enqueue ignored",
                    extra={"event_id": event_id},
                )
                return event_id

    def _enforce_size_cap(self) -> None:
        """
        Drop oldest events if we're over ``max_queue_size``. Called
        inside the write lock before each insert.
        """
        assert self._conn is not None
        count = self._conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        if count <= self._max_queue_size:
            return

        to_drop = count - self._max_queue_size
        logger.warning(
            "Event queue exceeded max size — dropping oldest events",
            extra={
                "queue_size": count,
                "max_size": self._max_queue_size,
                "dropping": to_drop,
            },
        )
        self._conn.execute(
            """
            DELETE FROM events
            WHERE id IN (
                SELECT id FROM events
                ORDER BY created_at ASC
                LIMIT ?
            )
            """,
            (to_drop,),
        )

    # ── Dequeue ────────────────────────────────────────────────────────

    def dequeue_batch(self, *, limit: int = 100) -> list[QueuedEvent]:
        """
        Return up to ``limit`` events whose retry time has passed.

        Does NOT delete them — the caller must call ``mark_sent`` or
        ``mark_failed`` after processing. Ordered by ``created_at``
        (oldest first, FIFO).
        """
        limit = max(1, min(1000, int(limit)))
        now = time.time()

        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT event_id, payload, created_at, attempts
                FROM events
                WHERE next_retry_at <= ?
                ORDER BY created_at ASC, id ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()

        result: list[QueuedEvent] = []
        for event_id, payload_json, created_at, attempts in rows:
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                logger.error(
                    "Corrupt payload in queue — dropping",
                    extra={"event_id": event_id},
                )
                self._delete_one(event_id)
                continue
            result.append(QueuedEvent(
                event_id=event_id,
                payload=payload,
                created_at=created_at,
                attempts=attempts,
            ))
        return result

    # ── Acknowledge ────────────────────────────────────────────────────

    def mark_sent(self, event_ids: list[str]) -> int:
        """Delete successfully-sent events. Returns rows deleted."""
        if not event_ids:
            return 0

        with self._lock:
            assert self._conn is not None
            placeholders = ",".join("?" * len(event_ids))
            cursor = self._conn.execute(
                f"DELETE FROM events WHERE event_id IN ({placeholders})",
                event_ids,
            )
            self._conn.commit()
            return cursor.rowcount or 0

    def mark_failed(
        self,
        event_ids: list[str],
        *,
        should_retry: bool,
        retry_after_seconds: int | None = None,
    ) -> int:
        """
        Update failed events with incremented attempt counts and next
        retry times.

        - ``should_retry=False`` OR ``attempts >= _MAX_ATTEMPTS`` → delete
        - Otherwise → set ``next_retry_at`` (honoring server Retry-After
          if present, else exponential backoff)

        Returns the number of events kept (not deleted).
        """
        if not event_ids:
            return 0

        now = time.time()

        with self._lock:
            assert self._conn is not None

            if not should_retry:
                placeholders = ",".join("?" * len(event_ids))
                self._conn.execute(
                    f"DELETE FROM events WHERE event_id IN ({placeholders})",
                    event_ids,
                )
                self._conn.commit()
                logger.warning(
                    "Events dropped (permanent failure)",
                    extra={"count": len(event_ids)},
                )
                return 0

            kept = 0
            dropped = 0
            for event_id in event_ids:
                row = self._conn.execute(
                    "SELECT attempts FROM events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    continue
                attempts = row[0] + 1

                if attempts >= _MAX_ATTEMPTS:
                    self._conn.execute(
                        "DELETE FROM events WHERE event_id = ?",
                        (event_id,),
                    )
                    dropped += 1
                    continue

                if retry_after_seconds is not None and retry_after_seconds > 0:
                    backoff = float(retry_after_seconds)
                else:
                    backoff = min(
                        _MAX_BACKOFF_SECONDS,
                        _BASE_BACKOFF_SECONDS * (2 ** (attempts - 1)),
                    )

                self._conn.execute(
                    """
                    UPDATE events
                    SET attempts = ?, next_retry_at = ?
                    WHERE event_id = ?
                    """,
                    (attempts, now + backoff, event_id),
                )
                kept += 1

            self._conn.commit()

        if dropped > 0:
            logger.warning(
                "Events dropped (max attempts exceeded)",
                extra={"count": dropped, "max_attempts": _MAX_ATTEMPTS},
            )
        return kept

    # ── Cleanup ────────────────────────────────────────────────────────

    def cleanup_expired(self) -> int:
        """
        Delete events older than 7 days. Returns rows deleted.

        Called periodically from the sender loop.
        """
        cutoff = time.time() - (_MAX_EVENT_AGE_DAYS * 86400)

        with self._lock:
            assert self._conn is not None
            cursor = self._conn.execute(
                "DELETE FROM events WHERE created_at < ?",
                (cutoff,),
            )
            self._conn.commit()
            deleted = cursor.rowcount or 0

        if deleted > 0:
            logger.info(
                "Queue cleanup: dropped expired events",
                extra={
                    "count": deleted,
                    "max_age_days": _MAX_EVENT_AGE_DAYS,
                },
            )
        return deleted

    # ── Introspection ──────────────────────────────────────────────────

    def size(self) -> int:
        """Return the current queue depth."""
        with self._lock:
            assert self._conn is not None
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]
            )

    def stats(self) -> dict[str, Any]:
        """Return queue stats for health checks."""
        with self._lock:
            assert self._conn is not None
            count = self._conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]
            if count == 0:
                return {
                    "count": 0,
                    "oldest_age_seconds": None,
                    "max_queue_size": self._max_queue_size,
                }
            oldest = self._conn.execute(
                "SELECT MIN(created_at) FROM events"
            ).fetchone()[0]
            return {
                "count": int(count),
                "oldest_age_seconds": (
                    int(time.time() - oldest) if oldest else None
                ),
                "max_queue_size": self._max_queue_size,
            }

    # ── Internal ───────────────────────────────────────────────────────

    def _delete_one(self, event_id: str) -> None:
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                "DELETE FROM events WHERE event_id = ?",
                (event_id,),
            )
            self._conn.commit()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventQueue",
    "QueuedEvent",
]