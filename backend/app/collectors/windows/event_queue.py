"""
CyberGuard AI — Windows Collector Event Queue
============================================================================

Durable on-disk queue for events between the log reader and the sender.

The collector cannot send events synchronously from the reader — a
backend outage, network blip, or rate limit would block log reading and
eventually cause the OS event log to wrap (Windows rotates channels
when they reach their max size; wrapped events are gone forever).

Instead:
    Reader → queue (local SQLite) → Sender (HTTP)

The queue is the buffer. When the backend is healthy, queue drains
faster than it fills. When the backend is unhealthy, the queue absorbs
the backlog up to ``max_queue_size``, then starts dropping the oldest
events (so recent activity stays visible).

Why SQLite
----------
- **Durable** — survives process crashes and reboots
- **Zero-dependency** — stdlib ``sqlite3`` (no server, no daemon)
- **WAL mode** — concurrent reads + writes without locks
- **Fast** — 10k+ inserts/sec on consumer hardware
- **Transactional** — atomic dequeue prevents duplicate sends

SQLite is not a toy. It's a real database. For a single-process queue
with 10k–100k events, it's the correct choice.

Schema
------
    events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id    TEXT NOT NULL UNIQUE,       -- client-generated UUID
        payload     TEXT NOT NULL,              -- JSON-encoded event
        created_at  REAL NOT NULL,              -- unix timestamp
        attempts    INTEGER NOT NULL DEFAULT 0, -- send attempts
        next_retry_at REAL                       -- backoff scheduling
    )

    indexes:
        idx_events_next_retry  ON (next_retry_at)
        idx_events_created_at  ON (created_at)

The ``event_id`` is a UUID the caller provides. It's stored UNIQUE so
double-enqueue of the same event (e.g. reader replays) doesn't create
duplicates. The sender uses it as an idempotency marker.

Guarantees
----------
    **At-least-once delivery**
    An event is removed from the queue only AFTER a successful backend
    acknowledgement. If the process crashes after send but before
    dequeue, the event is re-sent on restart. The backend deduplicates
    by fingerprint, so re-sends are harmless.

    **FIFO ordering**
    Events are processed in the order they were enqueued. A sender
    batch always contains the OLDEST pending events first.

    **Backoff scheduling**
    Failed sends update ``next_retry_at`` (exponential backoff). The
    sender skips events until their retry time. This prevents one
    broken event from blocking the whole queue.

    **Size cap**
    When ``max_queue_size`` is exceeded, the OLDEST events are
    dropped. Logged at WARNING. Recent events are more valuable than
    old ones for investigation.

    **Bounded retention**
    Events older than ``_MAX_EVENT_AGE_DAYS`` are dropped during the
    cleanup pass (called by the sender loop). Prevents unbounded disk
    usage if the collector is permanently disconnected.

Concurrency
-----------
The queue is safe for one reader thread + one sender thread. It's NOT
safe for multiple writers. The collector's architecture guarantees
this:
    - The reader thread calls ``enqueue()``.
    - The sender thread calls ``dequeue_batch()``, ``mark_sent()``,
      ``mark_failed()``.

SQLite WAL mode allows concurrent read+write transactions. The writer
lock is held briefly per operation (< 1ms for a single insert).

Usage
-----
    from event_queue import EventQueue

    queue = EventQueue()   # opens QUEUE_FILE from config.py

    # Reader thread:
    event_uuid = queue.enqueue({
        "event_time": "...",
        "event_type": "failed_login",
        ...
    })

    # Sender thread:
    batch = queue.dequeue_batch(limit=100)
    result = client.send_batch([e.payload for e in batch])
    if result.success:
        queue.mark_sent([e.event_id for e in batch])
    else:
        queue.mark_failed([e.event_id for e in batch], should_retry=result.should_retry)

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
from typing import Any, Iterator

from config import QUEUE_FILE


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Max attempts before an event is dropped from the queue.
#: After N failed sends, retrying isn't going to help — either the
#: backend is rejecting the payload (validation) or the network is
#: permanently broken. Drop it so the queue doesn't grow unbounded.
_MAX_ATTEMPTS = 10

#: Base backoff for retry scheduling (seconds). Exponential:
#: attempt 1 → 5s, 2 → 10s, 3 → 20s, 4 → 40s, 5 → 80s (capped at 300).
_BASE_BACKOFF_SECONDS = 5.0
_MAX_BACKOFF_SECONDS = 300.0

#: Events older than this are dropped during cleanup.
_MAX_EVENT_AGE_DAYS = 7

#: SQLite busy timeout (ms). If another connection holds the write
#: lock (shouldn't happen — single writer), wait this long before
#: returning SQLITE_BUSY.
_BUSY_TIMEOUT_MS = 5000


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass(frozen=True)
class QueuedEvent:
    """
    One event as stored in the queue.

    Fields:
        event_id    — UUID string. Globally unique per event.
        payload     — The event dict (as sent to the backend).
        created_at  — Unix timestamp when enqueued.
        attempts    — Number of send attempts so far.
    """
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

    Thread-safe for one writer + one reader via an internal lock. Uses
    WAL journal mode for concurrent read/write, plus a coarse Python
    lock to prevent concurrent ``check_same_thread=False`` access on
    the same connection from the reader and sender threads.

    The internal lock is a ``threading.RLock`` — reentrant, so
    ``mark_sent`` can call ``_execute`` while already holding the lock.
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
        # WAL mode — concurrent reads during writes
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Faster writes, still safe (fsync every transaction by default)
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # Foreign keys on for future-proofing
        self._conn.execute("PRAGMA foreign_keys=ON")

        self._ensure_schema()
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
        """Close the underlying connection. Safe to call multiple times."""
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

        If ``event_id`` is not provided, a UUID is generated. Callers
        should pass a stable UUID if they can derive one from the event
        (e.g. hash of source_event_id + timestamp) to make re-enqueues
        idempotent.

        Enforces the queue size cap by dropping the OLDEST events when
        full. Logs at WARNING.

        Raises
        ------
        ValueError
            If ``payload`` is not JSON-serializable.
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

            # Drop oldest events if over cap
            self._enforce_size_cap()

            try:
                self._conn.execute(
                    """
                    INSERT INTO events (event_id, payload, created_at, attempts, next_retry_at)
                    VALUES (?, ?, ?, 0, 0)
                    """,
                    (event_id, payload_json, now),
                )
                self._conn.commit()
                return event_id
            except sqlite3.IntegrityError:
                # Duplicate event_id — caller re-enqueued the same event
                # (e.g. reader replays after crash). Treat as success.
                logger.debug(
                    "Duplicate enqueue ignored",
                    extra={"event_id": event_id},
                )
                return event_id

    def enqueue_batch(
        self,
        payloads: list[dict[str, Any]],
    ) -> list[str]:
        """
        Enqueue multiple events in one transaction. Returns the list of
        event IDs (in the same order as input).
        """
        if not payloads:
            return []

        event_ids: list[str] = []
        rows: list[tuple[str, str, float]] = []
        now = time.time()

        for payload in payloads:
            eid = str(uuid.uuid4())
            try:
                payload_json = json.dumps(payload, separators=(",", ":"))
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "Skipping non-serializable event in batch",
                    extra={"error": str(exc)[:200]},
                )
                continue
            event_ids.append(eid)
            rows.append((eid, payload_json, now))

        if not rows:
            return []

        with self._lock:
            assert self._conn is not None
            self._enforce_size_cap()
            try:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO events
                        (event_id, payload, created_at, attempts, next_retry_at)
                    VALUES (?, ?, ?, 0, 0)
                    """,
                    rows,
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                logger.error(
                    "Batch insert failed",
                    extra={"error": str(exc)[:200], "count": len(rows)},
                )
                return []

        return event_ids

    def _enforce_size_cap(self) -> None:
        """
        If the queue exceeds ``max_queue_size``, delete the oldest rows
        until under cap. Called inside the write lock, before each
        insert. Cheap (one COUNT + one DELETE, both indexed).
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
        Return up to ``limit`` events whose ``next_retry_at`` is in the
        past. Does NOT delete them — the caller must call ``mark_sent``
        or ``mark_failed`` after processing.

        Ordered by ``created_at ASC`` — oldest events first.
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
        """
        Delete successfully-sent events from the queue. Returns the
        number of rows deleted.
        """
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

        If ``should_retry=False`` OR ``attempts >= _MAX_ATTEMPTS``,
        the events are deleted from the queue (permanent failure —
        retrying won't help).

        If ``should_retry=True``, ``next_retry_at`` is set using
        exponential backoff.

        Returns the number of events kept (not deleted).
        """
        if not event_ids:
            return 0

        now = time.time()

        with self._lock:
            assert self._conn is not None

            if not should_retry:
                # Permanent failure — drop
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

            # Increment attempts + schedule retry
            kept = 0
            dropped = 0
            for event_id in event_ids:
                row = self._conn.execute(
                    "SELECT attempts FROM events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    continue  # already gone
                attempts = row[0] + 1
                if attempts >= _MAX_ATTEMPTS:
                    self._conn.execute(
                        "DELETE FROM events WHERE event_id = ?",
                        (event_id,),
                    )
                    dropped += 1
                    continue

                # Honor server Retry-After, else exponential backoff
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
        Delete events older than ``_MAX_EVENT_AGE_DAYS``. Returns the
        number deleted.

        Called periodically by the sender loop. Prevents unbounded disk
        usage when the collector is permanently disconnected from the
        backend.
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
        """Return the current number of queued events."""
        with self._lock:
            assert self._conn is not None
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]
            )

    def stats(self) -> dict[str, Any]:
        """Return counts + oldest-event age for health checks."""
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

    # ── Internal helpers ───────────────────────────────────────────────

    def _delete_one(self, event_id: str) -> None:
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                "DELETE FROM events WHERE event_id = ?",
                (event_id,),
            )
            self._conn.commit()


# ============================================================================
# CONTEXT MANAGER SUPPORT
# ============================================================================

def _iter_events(queue: EventQueue, limit: int) -> Iterator[QueuedEvent]:
    """Iterate over pending events (convenience for tests)."""
    yield from queue.dequeue_batch(limit=limit)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventQueue",
    "QueuedEvent",
]