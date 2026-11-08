"""
CyberGuard AI — Linux Collector Event Sender
============================================================================

The sender thread's logic: pull events from the durable queue, batch
them, send to the backend, handle success/failure per batch.

Architecture
------------
The sender is a pure loop that runs in one thread. Each iteration:

    1. Every 5min: probe the backend's /health
    2. Every 1hr:   run queue.cleanup_expired()
    3. Dequeue a batch (up to ``batch_size`` events)
    4. Empty batch → sleep ``batch_interval_seconds``
    5. Non-empty  → send to backend
       - Success           → mark_sent (delete from queue)
       - Retriable failure → mark_failed with backoff, sleep longer
       - Permanent failure → mark_failed with should_retry=False (drop)

When the queue is empty, the sender sleeps the full interval. When the
queue has more events after a successful send, the sender immediately
loops again — no artificial delay on the drain path.

Health probe cadence
--------------------
A lightweight GET /health runs every ``_HEALTH_PROBE_INTERVAL_SECONDS``
(default 300s). If the backend is unreachable, the sleep interval
**doubles** on each failure up to ``_MAX_SLEEP_INTERVAL_SECONDS``
(default 300s). On recovery it resets to ``batch_interval_seconds``.

The probe is informational — the actual send attempts drive retry
timing. The probe just updates the ``backend_reachable`` flag that
the admin dashboard reads via the heartbeat payload.

State exposed for health checks
-------------------------------
    is_running              — thread is alive
    consecutive_failures    — failures since last success
    last_success_at         — timestamp of last successful send
    last_error              — last error message
    backend_reachable       — last health-probe result

Graceful shutdown
-----------------
The sender runs in a thread. A ``threading.Event`` passed to
``run_forever`` signals it to stop. On stop:

    1. Finish the in-flight send (up to ``_SHUTDOWN_GRACE_SECONDS``, 10s)
    2. Return from the loop
    3. ``main.py`` joins the thread

Events still in the queue stay there for the next start — nothing lost.

Exponential backoff (delegation, not duplication)
-------------------------------------------------
The queue's ``mark_failed`` handles per-event backoff via
``next_retry_at``. The sender does NOT layer its own batch-level
backoff on top. Instead:

    - On retriable failure, ``mark_failed`` schedules each event's
      next retry
    - Sender sleeps the normal interval (or longer if the whole
      backend is down)
    - Next iteration, ``dequeue_batch`` returns only events whose
      ``next_retry_at`` has passed

A server-sent ``Retry-After`` header (from a 429) is honored
per-event via ``mark_failed(retry_after_seconds=...)`` — the sender
does not wait for it directly, it just passes it through.

Ordering
--------
Events are strictly FIFO by ``created_at``. No priority lanes. A
security platform's value is completeness (never miss an event),
not latency on any single event. Time-critical events are critical
in the aggregate — sending one 1 second before or after 100 others
doesn't matter for detection.

Linux-specific considerations
-----------------------------
- Queue file is root-owned (0640) — the collector service runs as
  root via systemd, so this is transparent.
- On modern kernels, a systemd-managed collector under memory pressure
  will be OOM-killed before the sender can exhaust memory. No special
  memory guard needed at this layer.
- If the backend URL is on a remote host that becomes unreachable,
  DNS resolution failure is caught by the same NETWORK_ERROR path as
  connection refused. Both are retriable.

Usage
-----
    from config import CollectorConfig
    from event_queue import EventQueue
    from api_client import ApiClient
    from event_sender import EventSender

    config = CollectorConfig.load()
    queue = EventQueue(max_queue_size=config.max_queue_size)
    client = ApiClient(config)
    sender = EventSender(config, queue, client)

    stop_event = threading.Event()
    sender.run_forever(stop_event)

    # Elsewhere:
    stop_event.set()
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import CollectorConfig
    from event_queue import EventQueue
    from api_client import ApiClient, SendResult


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: How often the sender probes /health. Every 5 minutes is plenty.
_HEALTH_PROBE_INTERVAL_SECONDS = 300.0

#: If the backend is unreachable, double the sleep interval up to this
#: maximum. Prevents hammering a down backend while recovering quickly
#: when it comes back.
_MAX_SLEEP_INTERVAL_SECONDS = 300.0

#: How long to wait for an in-flight send during shutdown.
_SHUTDOWN_GRACE_SECONDS = 10.0

#: How often to run the queue's cleanup_expired pass.
_CLEANUP_INTERVAL_SECONDS = 3600.0


# ============================================================================
# SENDER
# ============================================================================

class EventSender:
    """
    Pulls batches from the queue and sends them to the backend.
    """

    def __init__(
        self,
        config: "CollectorConfig",
        queue: "EventQueue",
        client: "ApiClient",
    ) -> None:
        self._config = config
        self._queue = queue
        self._client = client

        self._batch_size = int(config.batch_size)
        self._base_interval = float(config.batch_interval_seconds)

        # State (read by health.py via stats())
        self._lock = threading.RLock()
        self._is_running: bool = False
        self._consecutive_failures: int = 0
        self._last_success_at: datetime | None = None
        self._last_error: str | None = None
        self._backend_reachable: bool | None = None
        self._last_health_probe_at: float = 0.0
        self._last_cleanup_at: float = 0.0

        # Cumulative stats
        self._total_sent: int = 0
        self._total_failed: int = 0
        self._total_duplicates: int = 0

    # ── State accessors ────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    @property
    def last_success_at(self) -> datetime | None:
        with self._lock:
            return self._last_success_at

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def backend_reachable(self) -> bool | None:
        with self._lock:
            return self._backend_reachable

    def stats(self) -> dict:
        """Snapshot for health checks."""
        with self._lock:
            return {
                "is_running": self._is_running,
                "consecutive_failures": self._consecutive_failures,
                "last_success_at": (
                    self._last_success_at.isoformat()
                    if self._last_success_at else None
                ),
                "last_error": self._last_error,
                "backend_reachable": self._backend_reachable,
                "total_sent": self._total_sent,
                "total_failed": self._total_failed,
                "total_duplicates": self._total_duplicates,
            }

    # ── Main loop ──────────────────────────────────────────────────────

    def run_forever(self, stop_event: threading.Event) -> None:
        """Main sender loop. Blocks until ``stop_event`` is set."""
        with self._lock:
            self._is_running = True

        logger.info(
            "EventSender started",
            extra={
                "batch_size": self._batch_size,
                "base_interval_seconds": self._base_interval,
            },
        )

        current_interval = self._base_interval

        try:
            while not stop_event.is_set():
                now = time.time()

                # ── Periodic health probe
                if now - self._last_health_probe_at > _HEALTH_PROBE_INTERVAL_SECONDS:
                    self._probe_health()
                    self._last_health_probe_at = now

                # ── Periodic queue cleanup
                if now - self._last_cleanup_at > _CLEANUP_INTERVAL_SECONDS:
                    try:
                        self._queue.cleanup_expired()
                    except Exception:  # noqa: BLE001
                        logger.exception("Queue cleanup failed")
                    self._last_cleanup_at = now

                # ── Dequeue
                try:
                    batch = self._queue.dequeue_batch(limit=self._batch_size)
                except Exception:  # noqa: BLE001
                    logger.exception("dequeue_batch failed")
                    stop_event.wait(timeout=current_interval)
                    continue

                if not batch:
                    stop_event.wait(timeout=current_interval)
                    continue

                # ── Send
                payloads = [e.payload for e in batch]
                event_ids = [e.event_id for e in batch]

                result = self._send(payloads)

                if result is None:
                    # Send raised unexpectedly — treat as retriable
                    self._record_failure("send returned None", retriable=True)
                    stop_event.wait(timeout=current_interval)
                    current_interval = min(
                        _MAX_SLEEP_INTERVAL_SECONDS, current_interval * 2
                    )
                    continue

                if result.success:
                    self._handle_success(event_ids, result)
                    # Immediately loop again to drain queue
                    current_interval = self._base_interval
                    stop_event.wait(timeout=0.05)
                else:
                    self._handle_failure(
                        event_ids,
                        result.should_retry,
                        result.retry_after_seconds,
                        error_message=result.error_message or "",
                        error_code=result.error_code or "UNKNOWN",
                    )
                    if result.should_retry:
                        sleep_for = current_interval
                        if result.retry_after_seconds:
                            sleep_for = max(
                                sleep_for,
                                float(result.retry_after_seconds),
                            )
                        else:
                            current_interval = min(
                                _MAX_SLEEP_INTERVAL_SECONDS,
                                current_interval * 2,
                            )
                        stop_event.wait(timeout=sleep_for)

                if stop_event.is_set():
                    break

        except Exception:  # noqa: BLE001
            logger.exception("EventSender crashed unexpectedly")
        finally:
            with self._lock:
                self._is_running = False
            logger.info("EventSender stopped")

    # ── Send helpers ───────────────────────────────────────────────────

    def _send(self, payloads: list[dict]) -> "SendResult | None":
        """Send a batch. Wraps in try/except so the loop never crashes."""
        try:
            return self._client.send_batch(payloads)
        except Exception:  # noqa: BLE001
            logger.exception(
                "send_batch raised unexpectedly",
                extra={"count": len(payloads)},
            )
            return None

    def _handle_success(
        self,
        event_ids: list[str],
        result: "SendResult",
    ) -> None:
        """Delete sent events from the queue, update stats."""
        try:
            deleted = self._queue.mark_sent(event_ids)
        except Exception:  # noqa: BLE001
            logger.exception("mark_sent failed")
            deleted = 0

        with self._lock:
            self._consecutive_failures = 0
            self._last_success_at = datetime.now(timezone.utc)
            self._last_error = None
            self._total_sent += result.ingested
            self._total_duplicates += result.duplicates
            if result.rejected > 0:
                self._total_failed += result.rejected

        if result.rejected > 0:
            logger.warning(
                "Batch partially rejected",
                extra={
                    "ingested": result.ingested,
                    "duplicates": result.duplicates,
                    "rejected": result.rejected,
                },
            )
        elif result.ingested > 0 or result.duplicates > 0:
            logger.info(
                "Batch sent",
                extra={
                    "ingested": result.ingested,
                    "duplicates": result.duplicates,
                    "deleted": deleted,
                },
            )

    def _handle_failure(
        self,
        event_ids: list[str],
        should_retry: bool,
        retry_after: int | None,
        *,
        error_message: str,
        error_code: str,
    ) -> None:
        """Mark failed events for retry (or drop them)."""
        try:
            self._queue.mark_failed(
                event_ids,
                should_retry=should_retry,
                retry_after_seconds=retry_after,
            )
        except Exception:  # noqa: BLE001
            logger.exception("mark_failed raised")

        self._record_failure(error_message, retriable=should_retry)
        logger.warning(
            "Batch send failed",
            extra={
                "count": len(event_ids),
                "error_code": error_code,
                "should_retry": should_retry,
                "consecutive_failures": self._consecutive_failures,
            },
        )

    def _record_failure(self, message: str, *, retriable: bool) -> None:
        with self._lock:
            self._consecutive_failures += 1
            self._last_error = message[:500]
            self._total_failed += 1

    def _probe_health(self) -> None:
        """Lightweight /health probe — updates ``_backend_reachable``."""
        try:
            result = self._client.probe_health()
        except Exception:  # noqa: BLE001
            with self._lock:
                self._backend_reachable = False
            return

        with self._lock:
            self._backend_reachable = result.reachable

        if not result.reachable:
            logger.warning(
                "Backend unreachable (health probe)",
                extra={"error": result.error_message},
            )
        elif result.db_ok is False:
            logger.warning(
                "Backend reachable but DB is down — sends will fail",
            )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventSender",
]