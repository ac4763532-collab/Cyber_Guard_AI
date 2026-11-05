"""
CyberGuard AI - Retention Cleanup Scheduler

Runs app.retention.cleanup.run_retention_cleanup() on a fixed interval
as a supervised asyncio background task, started/stopped from the
FastAPI lifespan (see app/main.py) alongside the existing collector
manager and security event consumer.

Why a new asyncio task instead of the existing Celery Beat schedule
(app/tasks/celery_app.py's "cleanup-old-events" entry, which already
points at app.tasks.analysis.cleanup_old_events): that Celery task is a
no-op placeholder, and more importantly this deployment's
docker-compose files run a celery-worker service but no celery-beat
service - so Beat schedules are never actually triggered today
regardless of what the task body does. Rather than deploying a new
infrastructure component (celery-beat) for one periodic job, this
follows the same in-process supervised-task pattern already used for
log collectors (app/logs/collector_manager.py) and the Gmail poller
(app/services/gmail/poller.py), which this codebase already runs
reliably without Celery.
"""

from __future__ import annotations

import asyncio

import structlog

from app.config import get_settings
from app.retention.cleanup import run_retention_cleanup

logger = structlog.get_logger(__name__)

_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


async def _run_loop(stop_event: asyncio.Event) -> None:
    settings = get_settings()
    interval = settings.log_event_retention_check_interval_seconds

    logger.info(
        "Retention cleanup scheduler started",
        interval_seconds=interval,
        retention_days=settings.log_event_retention_days,
        enabled=settings.log_event_retention_enabled,
    )

    while not stop_event.is_set():
        try:
            await run_retention_cleanup()
        except Exception as e:
            # Isolation: a failed cleanup run must never crash the loop -
            # the next scheduled run will simply try again. Nothing about
            # a cleanup failure should affect ingestion/detection, which
            # run on entirely separate tasks/connections.
            logger.error("Retention cleanup run raised unexpectedly", error=str(e))

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass  # Normal case: interval elapsed, loop again


async def start_retention_scheduler() -> None:
    """Start the retention cleanup background task. Safe to call once at startup."""
    global _task, _stop_event

    if _task is not None and not _task.done():
        logger.debug("Retention cleanup scheduler already running")
        return

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_run_loop(_stop_event))


async def stop_retention_scheduler() -> None:
    """Stop the retention cleanup background task. Safe to call even if never started."""
    global _task, _stop_event

    if _stop_event is not None:
        _stop_event.set()

    if _task is not None:
        try:
            await asyncio.wait_for(_task, timeout=10)
        except asyncio.TimeoutError:
            _task.cancel()
        except Exception:
            pass

    _task = None
    _stop_event = None
    logger.info("Retention cleanup scheduler stopped")
