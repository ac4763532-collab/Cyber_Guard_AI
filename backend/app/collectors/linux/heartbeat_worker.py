"""
CyberGuard AI — Linux Collector Heartbeat Worker
============================================================================

Sends periodic heartbeats to the backend so the source's
``collector_connected`` indicator stays true and the UI accurately
reflects "the collector is running".

Why heartbeats matter
---------------------
The backend's source model has 5 connection indicators (see
``app/models/source.py``). One of them — ``last_heartbeat_at`` — is
updated only when the collector calls
``POST /api/v1/collector/heartbeat``. If heartbeats stop arriving for
``COLLECTOR_STALE_AFTER_SECONDS`` (300s default), the backend marks
the source ``collector_connected=False`` and the UI shows "disconnected".

The heartbeat worker keeps that indicator alive. It runs in its own
thread, independent of the sender, so a slow sender (e.g. huge
backlog after a network outage) doesn't cause false "disconnected"
alarms.

Architecture
------------
One thread, one loop, one HTTP call per iteration.

    Loop every ``heartbeat_interval_seconds`` (default 60s):
        1. Gather lightweight stats:
            - queue depth (from EventQueue.stats)
            - CPU and memory usage (from /proc — no psutil required)
            - sender state (via callback)
        2. Call ``client.heartbeat(...)``
        3. Handle result:
            - Success            → reset failure counter, log at DEBUG
            - Retriable failure  → log WARNING, double interval (cap 600s)
            - Permanent failure  → log ERROR, stop the thread

Permanent failure means the credential is dead (revoked, expired, or
the source was disabled). Continuing to send heartbeats would just
spam the backend. The worker stops and ``main.py`` notices (via
``is_running``) and triggers a re-enrollment prompt.

Backoff
-------
On retriable failures:

    attempt 1 → normal interval (60s)
    attempt 2 → 2× normal (120s)
    attempt 3 → 4× normal (240s)
    attempt 4+ → capped at ``_MAX_BACKOFF_SECONDS`` (600s)

On success, reset to normal interval.

The backoff prevents the collector from hammering a down backend.
Same exponential pattern as the sender.

Linux resource metrics (no psutil required)
-------------------------------------------
The Windows collector optionally uses ``psutil`` for CPU/memory stats.
Linux provides equivalent data via ``/proc``:

    /proc/self/stat    — utime, stime, starttime, vsize, rss
    /proc/self/status  — VmRSS (resident set size), VmSize (virtual)

We compute:

    cpu_percent    — (utime+stime) / elapsed_seconds × 100
    memory_percent — VmRSS / system_total_mem × 100

System total memory comes from ``/proc/meminfo`` (MemTotal line).

If ``/proc`` is unavailable (unusual — e.g. some container runtimes
hide it), we fall back to ``psutil`` if installed, or return None
for both. None values are omitted from the heartbeat payload — the
backend's heartbeat endpoint accepts missing optional fields.

Linux-specific behaviour
------------------------
- If the collector runs under systemd, the systemd unit's
  ``MemoryMax=`` and ``CPUQuota=`` directives cap our process. The
  metrics we report are still the process's own usage — not the cap.
  The backend can compare "usage vs. cap" if it wants.
- A collector running as root on a busy host can see non-trivial CPU
  usage during log parsing. That's expected — the metric is for
  operators to spot a runaway collector, not a proxy for system load.

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
from pathlib import Path
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
_MAX_BACKOFF_SECONDS = 600.0

#: Minimum interval — even if config says smaller, don't send more
#: often than this. Backend rate limits would punish it.
_MIN_INTERVAL_SECONDS = 10.0

#: How often to refresh the system-total-memory cache (seconds).
#: The value rarely changes — refreshing it every heartbeat is wasteful.
_MEMINFO_REFRESH_SECONDS = 300.0


# ============================================================================
# OPTIONAL psutil (fallback path only)
# ============================================================================
# On Linux, /proc is available on every normal system. But if a
# sandbox hides it, psutil is a useful fallback if the operator
# happens to have it installed. Same import guard as Windows.

_PSUTIL_AVAILABLE = False
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    pass


# ============================================================================
# /proc HELPERS
# ============================================================================

def _read_proc_stat() -> tuple[int, int, int, int, int] | None:
    """
    Read /proc/self/stat for the current process.

    Returns (utime, stime, rss_pages, vsize_bytes, starttime_ticks)
    or None if the file is unreadable/malformed.

    Format (per proc(5)):
        pid (comm) state ppid pgrp session tty_nr tpgid flags minflt
        cminflt majflt cmajflt utime stime cutime cstime priority nice
        num_threads itrealvalue starttime vsize rss ...

    The ``comm`` field can contain spaces/parens — so we parse from
    the rightmost ``)`` rather than split() on the whole line.
    """
    try:
        content = Path("/proc/self/stat").read_text().strip()
    except (OSError, UnicodeDecodeError):
        return None

    try:
        # Find the closing paren of the comm field, then split the rest
        close_paren = content.rfind(")")
        if close_paren < 0:
            return None
        rest = content[close_paren + 1:].strip().split()
        # rest[0] = state, rest[1] = ppid, ... rest[11] = utime,
        # rest[12] = stime, rest[19] = starttime, rest[20] = vsize,
        # rest[21] = rss
        utime = int(rest[11])
        stime = int(rest[12])
        starttime = int(rest[19])
        vsize = int(rest[20])
        rss_pages = int(rest[21])
        return (utime, stime, rss_pages, vsize, starttime)
    except (IndexError, ValueError):
        return None


def _read_total_memory_bytes() -> int | None:
    """Read MemTotal from /proc/meminfo (in bytes)."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                # Format: "MemTotal:        8027244 kB"
                parts = line.split()
                if len(parts) >= 2:
                    kb = int(parts[1])
                    return kb * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _read_clock_ticks() -> int:
    """
    Return clock ticks per second (``_SC_CLK_TCK``).

    Almost always 100 on Linux. Reading at startup saves repeated
    syscalls.
    """
    try:
        return int(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError, AttributeError):
        return 100


# Standard library fallback for sysconf if os is imported without it
try:
    import os
except ImportError:  # pragma: no cover
    os = None  # type: ignore[assignment]


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
            Used to report queue depth in the heartbeat payload.
        sender_stats_callback : Callable[[], dict] | None
            Optional callback returning sender stats — included in the
            heartbeat metadata for admin dashboards.
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

        # State
        self._lock = threading.RLock()
        self._is_running = False
        self._consecutive_failures = 0
        self._last_success_at: datetime | None = None
        self._last_error: str | None = None
        self._total_sent = 0
        self._total_failed = 0

        # /proc caching
        self._clock_ticks = _read_clock_ticks()
        self._cached_total_mem_bytes: int | None = None
        self._last_meminfo_refresh: float = 0.0
        self._last_proc_stat: tuple[int, int, int, int, int] | None = None
        self._last_proc_stat_time: float = 0.0

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
                    self._record_failure(
                        "heartbeat returned None", permanent=False,
                    )
                    current_interval = min(
                        _MAX_BACKOFF_SECONDS, current_interval * 2,
                    )
                    stop_event.wait(timeout=current_interval)
                    continue

                if result.success:
                    self._record_success()
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
                                "error_message": (
                                    result.error_message or ""
                                )[:300],
                            },
                        )
                        break

                    current_interval = min(
                        _MAX_BACKOFF_SECONDS, current_interval * 2,
                    )
                    logger.warning(
                        "Heartbeat failed (retriable) — backing off",
                        extra={
                            "error_code": result.error_code,
                            "next_interval_seconds": current_interval,
                            "consecutive_failures": self._consecutive_failures,
                        },
                    )

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

        Preferred path: /proc (always available on Linux).
        Fallback:       psutil (if /proc is hidden but psutil works).

        Returns (None, None) if neither path succeeds.
        """
        # ── Try /proc first
        cpu, mem = self._get_usage_from_proc()
        if cpu is not None or mem is not None:
            return cpu, mem

        # ── Fallback to psutil
        return self._get_usage_from_psutil()

    def _get_usage_from_proc(self) -> tuple[float | None, float | None]:
        """Read CPU + memory usage from /proc."""
        now = time.time()

        # ── CPU: delta of (utime+stime) since last reading
        current_stat = _read_proc_stat()
        cpu_percent: float | None = None

        if current_stat is not None and self._last_proc_stat is not None:
            prev_ticks = self._last_proc_stat[0] + self._last_proc_stat[1]
            curr_ticks = current_stat[0] + current_stat[1]
            delta_ticks = curr_ticks - prev_ticks
            delta_time = now - self._last_proc_stat_time

            if delta_time > 0 and delta_ticks >= 0:
                # cpu_percent = (delta_ticks / hz) / delta_seconds × 100
                delta_seconds = delta_ticks / self._clock_ticks
                cpu_percent = round(
                    (delta_seconds / delta_time) * 100.0, 2,
                )

        if current_stat is not None:
            self._last_proc_stat = current_stat
            self._last_proc_stat_time = now

        # ── Memory: VmRSS / MemTotal
        memory_percent: float | None = None

        # Refresh total mem cache every 5min
        if now - self._last_meminfo_refresh > _MEMINFO_REFRESH_SECONDS:
            self._cached_total_mem_bytes = _read_total_memory_bytes()
            self._last_meminfo_refresh = now

        total_mem = self._cached_total_mem_bytes
        if total_mem and total_mem > 0 and current_stat is not None:
            # rss is in pages — convert to bytes
            rss_pages = current_stat[2]
            # Page size: assume 4 KiB (default on x86_64/arm64).
            # Could read via sysconf(_SC_PAGESIZE), but /proc/self/stat
            # rss is already page-count so multiply by pagesize.
            page_size = 4096  # TODO: sysconf(SC_PAGESIZE) if needed
            rss_bytes = rss_pages * page_size
            memory_percent = round(
                (rss_bytes / total_mem) * 100.0, 2,
            )

        return cpu_percent, memory_percent

    def _get_usage_from_psutil(self) -> tuple[float | None, float | None]:
        """Fallback: use psutil (Windows-style)."""
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