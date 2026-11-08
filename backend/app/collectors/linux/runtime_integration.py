"""
CyberGuard AI — Linux Collector Runtime Integration
============================================================================

The bridge between the reader, the queue, and durable cursor state.

`main.py` delegates the reader loop to this file because the loop on
Linux has non-trivial crash-recovery responsibilities that would
otherwise bloat main.py past readability.

Responsibilities
----------------
1. **Construct the reader** from config, restoring its state
   (`journald_cursor`, `file_positions`) so it resumes where the
   last process left off.

2. **Run the reader loop** — poll, normalize, enqueue. Per-event
   error isolation: a single malformed event doesn't stop the loop.

3. **Persist reader state** — atomic save of the cursor and file
   positions to `config.json` after each batch of work. Rate-limited
   to one save per `_STATE_PERSIST_INTERVAL_SECONDS` to prevent
   fsync-flooding on a busy host.

4. **Final state save on shutdown** — called from `main.py`'s
   shutdown path so a clean stop doesn't leave uncommitted cursor
   progress.

5. **Startup verification** — check that saved file positions still
   refer to files with valid inodes. If a file rotated while the
   collector was offline, reset that file's offset to 0 (re-read
   the current file from start).

The critical invariant
----------------------
**The saved cursor must never point PAST events that haven't been
durably enqueued.**

Two failure modes:

    Save too early → lose events
        Reader advances cursor to event #500.
        Crash before queue.insert(event #500).
        Restart loads cursor at #500 → event #500 never enqueued.

    Save too late → re-process on crash (fine, not data loss)
        Reader advances cursor to event #500.
        Queue.insert(event #500) succeeds.
        Crash before persist_reader_state().
        Restart loads cursor at #350 (last save) → re-read #351–500.
        Backend dedup rejects the duplicates.
        Net effect: no loss, some wasted cycles.

We choose the second. Data loss is unacceptable; wasted cycles are
just inefficiency. The queue's UNIQUE(event_id) constraint handles
local dedup of re-enqueued events, and the backend's fingerprint
dedup handles the rest.

Rate-limiting the saves
-----------------------
`persist_reader_state` is called after every batch. But a batch that
takes 50ms and is followed immediately by another batch (queue is
busy) means we'd call it 20× per second — each call is one JSON write
plus one fsync. That's 20 fsyncs/second on the config file.

The mitigation: track the last successful save time. Only actually
save if > `_STATE_PERSIST_INTERVAL_SECONDS` (10s) has elapsed OR the
event is a "hard save" request (batch boundary, shutdown, error).
The trade-off is at most 10 seconds of re-read events per crash —
trivial compared to the fsync pressure.

Startup verification (`verify_saved_state`)
-------------------------------------------
Called once at startup, before the reader loop begins:

    1. For each saved file position:
        - Does the file exist?
        - Does the current inode match the saved inode?
        - Does the current size >= saved offset?
       If any check fails, reset that file's offset to 0.

    2. For the journald cursor: pass through. journalctl itself
       handles invalid cursors by searching backward for a match
       (or erroring out — logged by the reader's own exception
       handler).

The verification prevents the "collector was offline for a week,
log files rotated three times" case where the saved inode points to
a file that no longer exists, causing all subsequent reads to hang
on a deleted file.

Usage
-----
    from runtime_integration import (
        create_reader, verify_saved_state, run_reader_loop,
        ReaderLoopStats,
    )

    reader = create_reader(config)
    resets = verify_saved_state(config)
    if resets:
        logger.info("File offsets reset on startup", extra=resets)

    stats = ReaderLoopStats()
    run_reader_loop(
        config=config,
        reader=reader,
        queue=queue,
        stop_event=stop_event,
        heartbeat=heartbeat,
        stats=stats,
    )
    # run_reader_loop exits only when stop_event is set OR
    # heartbeat.is_running is False.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from event_normalizer import normalize
from log_reader import LogReader


if TYPE_CHECKING:
    from config import CollectorConfig
    from event_queue import EventQueue
    from heartbeat_worker import HeartbeatWorker


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Minimum seconds between successive `config.save()` calls during the
#: reader loop. Bounds fsync pressure on the config file to 6/minute
#: regardless of how fast the reader polls.
_STATE_PERSIST_INTERVAL_SECONDS = 10.0

#: How often the reader loop polls for events. Small yield between
#: non-empty batches — enough to check stop_event, not enough to
#: add measurable latency.
_BATCH_YIELD_SECONDS = 0.1

#: After this many consecutive journalctl failures with a saved cursor,
#: the cursor is cleared and a warning logged. Recovers automatically
#: from journald purges (SystemMaxUse exceeded, journalctl --vacuum,
#: OS reinstall without reformatting /var).
_MAX_JOURNALD_FAILURES_BEFORE_RESET = 5


# ============================================================================
# STATS
# ============================================================================

@dataclass
class ReaderLoopStats:
    """
    Cumulative stats for the reader loop. Not persisted — lives in
    memory for the process lifetime. Consumed by periodic status
    logging and the /health-style local status output.
    """
    started_at: float = field(default_factory=time.time)
    polls: int = 0
    total_read: int = 0
    total_enqueued: int = 0
    total_enqueue_errors: int = 0
    total_normalize_skips: int = 0
    total_poll_errors: int = 0
    consecutive_journald_failures: int = 0
    last_poll_events: int = 0
    last_poll_ms: int = 0
    last_poll_error: str | None = None
    last_persist_at: float = 0.0

    def uptime_seconds(self) -> int:
        return int(time.time() - self.started_at)

    def summary(self) -> dict:
        return {
            "uptime_seconds": self.uptime_seconds(),
            "polls": self.polls,
            "total_read": self.total_read,
            "total_enqueued": self.total_enqueued,
            "total_enqueue_errors": self.total_enqueue_errors,
            "total_normalize_skips": self.total_normalize_skips,
            "total_poll_errors": self.total_poll_errors,
            "last_poll_events": self.last_poll_events,
            "last_poll_ms": self.last_poll_ms,
            "last_poll_error": self.last_poll_error,
            "queue_ratio": (
                round(self.total_enqueued / self.total_read, 3)
                if self.total_read > 0 else None
            ),
        }


# ============================================================================
# READER CONSTRUCTION
# ============================================================================

def create_reader(config: "CollectorConfig") -> LogReader:
    """
    Construct a `LogReader` with state restored from `config`.

    The reader itself does the restoration in its `__init__` (it reads
    `config.journald_cursor` and `config.file_positions`). This wrapper
    exists so main.py can import one function and not worry about the
    reader's constructor signature.
    """
    return LogReader(config)


# ============================================================================
# STARTUP VERIFICATION
# ============================================================================

def verify_saved_state(config: "CollectorConfig") -> dict[str, str]:
    """
    Sanity-check saved file positions on startup.

    Returns a dict mapping `file_path → reason` for every file whose
    saved offset was reset. Empty dict means all saved positions were
    valid.

    Cases detected:
        - **File missing**: path was configured but no longer exists
          (log rotated, or the collector config changed between runs).
          Removed from positions.
        - **Inode mismatch**: file was replaced (logrotate moved the
          old file and created a new one). Position reset to 0.
        - **Size shrunk**: file was truncated in place (e.g. by a
          `: > /var/log/auth.log`). Position reset to 0.

    Called once at startup, before `run_reader_loop` begins. A clean
    startup produces zero resets — the log line "reader state
    verified, no resets" appears once.
    """
    positions = config.file_positions or {}
    if not positions:
        logger.info("Reader state verified, no saved positions")
        return {}

    resets: dict[str, str] = {}
    cleaned: dict[str, dict[str, int]] = {}

    for file_path, raw_state in positions.items():
        # Normalize state shape (handle legacy int-only format)
        if isinstance(raw_state, dict):
            saved_inode = int(raw_state.get("inode", 0))
            saved_offset = int(raw_state.get("offset", 0))
        elif isinstance(raw_state, int):
            saved_inode = 0
            saved_offset = int(raw_state)
        else:
            resets[file_path] = "malformed_state"
            continue

        path = Path(file_path)
        if not path.exists():
            resets[file_path] = "file_missing"
            continue

        try:
            stat = path.stat()
        except OSError as exc:
            resets[file_path] = f"stat_failed:{exc.strerror or 'unknown'}"
            continue

        current_inode = stat.st_ino
        current_size = stat.st_size

        if saved_inode and current_inode != saved_inode:
            # File was replaced (logrotate, manual rotation)
            resets[file_path] = "inode_changed"
            cleaned[file_path] = {"inode": current_inode, "offset": 0}
            continue

        if saved_offset > current_size:
            # File shrank — truncated in place
            resets[file_path] = "size_shrunk"
            cleaned[file_path] = {"inode": current_inode, "offset": 0}
            continue

        # Valid — preserve the saved position
        cleaned[file_path] = {
            "inode": current_inode,
            "offset": saved_offset,
        }

    # Write back the cleaned positions if anything changed
    if resets:
        config.file_positions = cleaned
        try:
            config.save()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to persist cleaned file positions",
                extra={"error": str(exc)[:200]},
            )
        logger.warning(
            "Reader state has resets on startup",
            extra={"resets": resets},
        )
    else:
        logger.info(
            "Reader state verified",
            extra={
                "files_tracked": len(cleaned),
                "journald_cursor_set": bool(config.journald_cursor),
            },
        )

    return resets


# ============================================================================
# STATE PERSISTENCE
# ============================================================================

def persist_reader_state(
    config: "CollectorConfig",
    reader: LogReader,
    *,
    force: bool = False,
    stats: ReaderLoopStats | None = None,
) -> bool:
    """
    Save the reader's current cursor + file positions to `config.json`.

    `force=False` (default): saves only if more than
    `_STATE_PERSIST_INTERVAL_SECONDS` has elapsed since the last save.
    Returns True if a save actually happened.

    `force=True`: saves unconditionally. Used by the shutdown path so
    the last cursor advance is always durable.

    Returns True on successful save (or skip that's within the rate
    limit — from the caller's perspective, "no save needed" is not an
    error), False on hard failure.
    """
    now = time.time()

    if not force and stats is not None:
        elapsed = now - stats.last_persist_at
        if elapsed < _STATE_PERSIST_INTERVAL_SECONDS:
            # Rate-limited — skip
            return True

    # Capture state from the reader
    try:
        config.journald_cursor = reader.get_cursor()
        config.file_positions = reader.get_file_positions()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to read state from reader — skipping persist",
            extra={"error": str(exc)[:200]},
        )
        return False

    try:
        config.save()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to persist reader state to config.json",
            extra={"error": str(exc)[:200]},
        )
        return False

    if stats is not None:
        stats.last_persist_at = now

    logger.debug(
        "Reader state persisted",
        extra={
            "journald_cursor_set": bool(config.journald_cursor),
            "files_tracked": len(config.file_positions or {}),
        },
    )
    return True


# ============================================================================
# READER LOOP
# ============================================================================

def run_reader_loop(
    *,
    config: "CollectorConfig",
    reader: LogReader,
    queue: "EventQueue",
    stop_event: "any",              # threading.Event — type-checked at runtime
    heartbeat: "HeartbeatWorker",
    stats: ReaderLoopStats | None = None,
) -> None:
    """
    The main reader loop. Runs in the caller's thread (typically the
    main thread in main.py).

    Polls the reader, normalizes each event, enqueues it, and
    periodically persists state. Exits when:

        - `stop_event` is set (Ctrl+C or SIGTERM)
        - `heartbeat.is_running` becomes False (credential died)

    Per-event error isolation: a single failed enqueue, a single
    failed normalize, does NOT stop the loop. The failure is logged
    and counted; the loop continues. This is critical because one
    malformed log line should not shut down log collection for the
    whole host.

    On exit, one final forced persist ensures the cursor is at the
    most recent successfully-read position.
    """
    if stats is None:
        stats = ReaderLoopStats()

    poll_interval = float(config.read_poll_seconds)

    logger.info(
        "Reader loop starting",
        extra={
            "poll_seconds": poll_interval,
            "use_journald": config.use_journald,
            "use_log_files": config.use_log_files,
            "log_files_count": len(config.log_files),
        },
    )

    try:
        while not stop_event.is_set():
            # ── Check heartbeat health
            if not heartbeat.is_running:
                logger.error(
                    "Heartbeat worker stopped — credential is likely "
                    "revoked or expired. Stopping reader."
                )
                stop_event.set()
                break

            cycle_start = time.time()
            events_read = 0
            events_enqueued = 0
            events_failed = 0
            events_skipped = 0

            try:
                for raw_event in reader.poll():
                    if stop_event.is_set():
                        break

                    # Normalize
                    try:
                        payload = normalize(raw_event)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Normalizer raised — skipping event",
                            extra={"error": str(exc)[:200]},
                        )
                        events_skipped += 1
                        continue

                    if payload is None:
                        # Normalizer said "skip" — expected for some
                        # raw entries (empty message, etc.)
                        events_skipped += 1
                        continue

                    events_read += 1

                    # Enqueue with per-event error isolation
                    try:
                        queue.enqueue(payload)
                        events_enqueued += 1
                    except Exception as exc:  # noqa: BLE001
                        events_failed += 1
                        logger.warning(
                            "Failed to enqueue event — continuing",
                            extra={
                                "event_type": payload.get("event_type"),
                                "error": str(exc)[:200],
                            },
                        )

                # ── After the batch, persist state (rate-limited)
                persist_reader_state(config, reader, stats=stats)

            except Exception as exc:  # noqa: BLE001
                stats.total_poll_errors += 1
                stats.last_poll_error = str(exc)[:200]
                logger.exception("Reader poll failed — continuing")

                # If journald is the failure, count consecutive failures
                # and reset the cursor after the threshold
                if _looks_like_journald_error(exc):
                    stats.consecutive_journald_failures += 1
                    if (
                        stats.consecutive_journald_failures
                        >= _MAX_JOURNALD_FAILURES_BEFORE_RESET
                        and reader.get_cursor() is not None
                    ):
                        logger.warning(
                            "Repeated journald failures — resetting cursor "
                            "to recover. Events between the last successful "
                            "read and now may be lost.",
                            extra={
                                "failures": stats.consecutive_journald_failures,
                            },
                        )
                        # Both config and reader hold the cursor; reset both
                        config.journald_cursor = None
                        try:
                            reader._cursor = None  # noqa: SLF001
                        except Exception:  # noqa: BLE001
                            pass
                        persist_reader_state(config, reader, force=True, stats=stats)
                        stats.consecutive_journald_failures = 0
                else:
                    stats.consecutive_journald_failures = 0

            # ── Update stats
            stats.polls += 1
            stats.total_read += events_read
            stats.total_enqueued += events_enqueued
            stats.total_enqueue_errors += events_failed
            stats.total_normalize_skips += events_skipped
            stats.last_poll_events = events_read
            stats.last_poll_ms = int((time.time() - cycle_start) * 1000)

            # Reset journald failure counter on success
            if events_read > 0 or stats.last_poll_error is None:
                stats.consecutive_journald_failures = 0

            # ── Log periodically (every ~60 polls ≈ 5min at 5s interval)
            if stats.polls % 60 == 0:
                logger.info(
                    "Reader loop status",
                    extra=stats.summary(),
                )

            # ── Yield
            if events_read == 0:
                stop_event.wait(timeout=poll_interval)
            else:
                stop_event.wait(timeout=_BATCH_YIELD_SECONDS)

    except KeyboardInterrupt:
        logger.info("Reader loop interrupted (KeyboardInterrupt)")
        raise
    except Exception:  # noqa: BLE001
        logger.exception("Reader loop crashed unexpectedly")
        raise
    finally:
        # Final forced save — never lose the last cursor advance
        try:
            persist_reader_state(config, reader, force=True, stats=stats)
        except Exception:  # noqa: BLE001
            logger.exception("Final reader state save failed")

        logger.info(
            "Reader loop stopped",
            extra=stats.summary(),
        )


# ============================================================================
# SHUTDOWN HELPER
# ============================================================================

def save_on_shutdown(
    config: "CollectorConfig",
    reader: LogReader,
) -> None:
    """
    Force a state save from a shutdown signal handler.

    `run_reader_loop` already saves state in its `finally` block, so
    this function is only needed if the shutdown path bypasses the
    loop's cleanup (e.g. a hard SIGTERM delivered while blocked in
    a subprocess). `main.py` calls this from its signal handler as a
    belt-and-suspenders measure.
    """
    try:
        persist_reader_state(config, reader, force=True)
        logger.info("Reader state saved on shutdown signal")
    except Exception:  # noqa: BLE001
        logger.exception("Failed to save reader state on shutdown")


# ============================================================================
# HELPERS
# ============================================================================

def _looks_like_journald_error(exc: BaseException) -> bool:
    """
    Heuristic: is this exception likely from journald specifically?

    Used to decide whether to trigger the auto-reset-cursor logic.
    A file read error should NOT reset the journald cursor.
    """
    msg = str(exc).lower()
    return (
        "journal" in msg
        or "cursor" in msg
        or "systemd" in msg
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ReaderLoopStats",
    "create_reader",
    "verify_saved_state",
    "persist_reader_state",
    "run_reader_loop",
    "save_on_shutdown",
]