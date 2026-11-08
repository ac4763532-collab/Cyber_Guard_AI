"""
CyberGuard AI — Windows Collector Heartbeat Worker
============================================================================

Sends periodic heartbeats to the backend so the source's
``collector_connected`` indicator stays true and the UI accurately
reflects "the collector is running".

Why heartbeats matter
---------------------
The backend's source model has 5 separate connection indicators (see
``app/models/source.py``). One of them — ``last_heartbeat_at`` — is
updated only when the collector calls ``POST /api/v1/collector/heartbeat``.
If heartbeats stop arriving for ``COLLECTOR_STALE_AFTER_SECONDS``
(300s default), the backend marks the source ``collector_connected=False``
and the UI shows "disconnected".

The heartbeat worker is what keeps that indicator alive. It runs in its
own thread, independent of the sender, so a slow sender (e.g. huge
backlog after a network outage) doesn't cause false "disconnected"
alarms.

Architecture
------------
One thread, one loop, one HTTP call per iteration.

    Loop every ``heartbeat_interval_seconds`` (default 60s):
        1. Gather lightweight stats:
            - queue depth (from EventQueue.stats)
            - optional: CPU and memory usage (from psutil, if installed)
            - optional: sender state (via callback)
        2. Call ``client.heartbeat(...)``
        3. Handle result:
            - Success → reset failure counter, log at DEBUG
            - Retriable failure → log WARNING, double interval (up to max)
            - Permanent failure (401/403) → log ERROR, stop the thread

Permanent failure means the credential is dead (revoked, expired, or
the source was disabled). Continuing to send heartbeats would just
spam the backend. The worker stops and the collector's main thread
notices (via ``is_running``) and triggers a re-enrollment prompt.

Backoff
-------
On retriable failures:

    attempt 1 → normal interval (60s)
    attempt 2 → 2× normal (120s)
    attempt 3 → 4× normal (240s)
    attempt 4+ → capped at ``_MAX_BACKOFF_SECONDS`` (600s)

On success, reset to normal interval.

The backoff prevents the collector from hammering a down backend. It's
the same exponential pattern the sender uses — the collector never
DoSes its own backend.

CPU/memory (optional)
---------------------
If ``psutil`` is installed, the heartbeat includes the collector
process's CPU and memory usage. This helps the admin dashboard spot
"this collector is consuming 90% CPU" without needing remote SSH.

If ``psutil`` is missing, those fields are simply omitted — no error,
no log noise.

Usage
-----
    from config import CollectorConfig
    from api_client import ApiClient
    from event_queue import EventQueue
    from heartbeat_worker import HeartbeatWorker

    config = CollectorConfig.load()
    client = ApiClient(config)
    queue = EventQueue()

    worker = HeartbeatWorker(
        config=config,
        client=client,
        queue=queue,
        sender_stats_callback=lambda: sender.stats(),
    )
    stop_event = threading.Event()
    worker.run_forever(stop_event)

    # Elsewhere:
    print(worker.is_running, worker.consecutive_failures)
    stop_event.set()
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from config import CollectorConfig
    from api_client import ApiClient, HeartbeatResult
    from event_queue import EventQueue


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Maximum interval between heartbeats when the backend is unreachable.
#: Exponential backoff caps here.
_MAX_BACKOFF_SECONDS = 600.0


#: Minimum interval — even if the config says smaller, don't send more
#: often than this. Backend rate limits would punish it.
_MIN_INTERVAL_SECONDS = 10.0


# ============================================================================
# OPTIONAL psutil
# ============================================================================
# Graceful import — psutil is not a hard dependency. If it's missing,
# we skip CPU/memory stats. This keeps the collector installable with
# only stdlib + httpx + pywin32 (a smaller footprint).

_PSUTIL_AVAILABLE = False
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    pass


# ============================================================================
# HEARTBEAT WORKER
# ============================================================================

class HeartbeatWorker:
    """
    Sends periodic heartbeats to the backend.

    Runs in one thread. Exposes read-only state for health checks.
    """

    def __init__(
        self,
        config: "CollectorConfig",
        client: "ApiClient",
        queue: "EventQueue",
        *,
        sender_stats_callback: Callable[[], dict] | None = None,
    ) -> None:
        """
        Parameters
        ----------
        config : CollectorConfig
        client : ApiClient
        queue : EventQueue
            Used to include queue depth in the heartbeat payload —
            valuable telemetry for the admin dashboard.
        sender_stats_callback : Callable[[], dict] | None
            Optional callback that returns the sender's current stats.
            If provided, those stats are included in the heartbeat
            (total_sent, consecutive_failures, etc.). Used by the admin
            dashboard to spot "this collector's sender is broken".
        """
        self._config = config
        self._client = client
        self._queue = queue
        self._sender_stats = sender_stats_callback

        base = max(
            _MIN_INTERVAL_SECONDS,
            float(config.heartbeat_interval_seconds),
        )
        self._base_interval = base

        # State (read by health endpoint / status checks)
        self._lock = threading.RLock()
        self._is_running = False
        self._consecutive_failures = 0
        self._last_success_at: datetime | None = None
        self._last_error: str | None = None
        self._total_sent = 0
        self._total_failed = 0

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

    def stats(self) -> dict:
        """Return a snapshot for health checks."""
        with self._lock:
            return {
                "is_running": self._is_running,
                "consecutive_failures": self._consecutive_failures,
                "last_success_at": (
                    self._last_success_at.isoformat()
                    if self._last_success_at else None
                ),
                "last_error": self._last_error,
                "total_sent": self._total_sent,
                "total_failed": self._total_failed,
                "interval_seconds": self._base_interval,
            }

    # ── Main loop ──────────────────────────────────────────────────────

    def run_forever(self, stop_event: threading.Event) -> None:
        """
        Main heartbeat loop. Blocks until ``stop_event`` is set.

        Terminates when:
            - ``stop_event`` is set
            - A permanent failure occurs (credential dead)
            - An unexpected exception kills the loop (logged, then exits)
        """
        with self._lock:
            self._is_running = True

        logger.info(
            "HeartbeatWorker started",
            extra={"interval_seconds": self._base_interval},
        )

        current_interval = self._base_interval

        try:
            while not stop_event.is_set():
                # ── Send heartbeat
                result = self._send_heartbeat()

                if result is None:
                    # Should not happen — ApiClient is defensive
                    self._record_failure("heartbeat returned None", permanent=False)
                    current_interval = min(
                        _MAX_BACKOFF_SECONDS, current_interval * 2
                    )
                    stop_event.wait(timeout=current_interval)
                    continue

                if result.success:
                    self._record_success()
                    # Reset interval on success
                    current_interval = self._base_interval
                else:
                    permanent = not result.should_retry
                    self._record_failure(
                        result.error_message or "unknown",
                        permanent=permanent,
                    )

                    if permanent:
                        logger.error(
                            "Heartbeat failed permanently — stopping worker. "
                            "Collector likely needs to re-enroll.",
                            extra={
                                "error_code": result.error_code,
                                "error_message": (result.error_message or "")[:300],
                            },
                        )
                        break

                    # Retriable failure — back off
                    current_interval = min(
                        _MAX_BACKOFF_SECONDS, current_interval * 2
                    )
                    logger.warning(
                        "Heartbeat failed (retriable) — backing off",
                        extra={
                            "error_code": result.error_code,
                            "next_interval_seconds": current_interval,
                            "consecutive_failures": self._consecutive_failures,
                        },
                    )

                # ── Sleep until next iteration
                stop_event.wait(timeout=current_interval)

        except Exception:  # noqa: BLE001
            logger.exception("HeartbeatWorker crashed unexpectedly")
        finally:
            with self._lock:
                self._is_running = False
            logger.info("HeartbeatWorker stopped")

    # ── Send ───────────────────────────────────────────────────────────

    def _send_heartbeat(self) -> "HeartbeatResult | None":
        """Send one heartbeat with the current stats."""
        try:
            queue_depth = self._get_queue_depth()
        except Exception:
            queue_depth = None

        cpu, memory = self._get_resource_usage()

        try:
            return self._client.heartbeat(
                queue_depth=queue_depth,
                cpu_percent=cpu,
                memory_percent=memory,
            )
        except Exception:  # noqa: BLE001
            logger.exception("heartbeat call raised unexpectedly")
            return None

    def _get_queue_depth(self) -> int | None:
        """Return current queue size, or None if unavailable."""
        try:
            return int(self._queue.size())
        except Exception:  # noqa: BLE001
            return None

    def _get_resource_usage(self) -> tuple[float | None, float | None]:
        """
        Return (cpu_percent, memory_percent) for the current process.

        Returns (None, None) if psutil is not installed.
        """
        if not _PSUTIL_AVAILABLE:
            return None, None
        try:
            process = psutil.Process()
            return (
                float(process.cpu_percent(interval=None)),
                float(process.memory_percent()),
            )
        except Exception:  # noqa: BLE001
            return None, None

    # ── State updates ──────────────────────────────────────────────────

    def _record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._last_success_at = datetime.now(timezone.utc)
            self._last_error = None
            self._total_sent += 1

        # Only log at DEBUG — heartbeats every 60s at INFO would flood
        logger.debug("Heartbeat sent successfully")

    def _record_failure(self, message: str, *, permanent: bool) -> None:
        with self._lock:
            self._consecutive_failures += 1
            self._last_error = message[:500]
            self._total_failed += 1


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "HeartbeatWorker",
    "_PSUTIL_AVAILABLE",
]