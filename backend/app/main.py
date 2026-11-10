"""
CyberGuard AI — FastAPI Application Entry Point
============================================================================

The application object that everything else plugs into. Runs via:

    uvicorn app.main:app --reload

Responsibilities
----------------
1. **Construct the FastAPI app** with metadata from ``app/__init__.py``.
2. **Register middleware**: correlation ID, body size limit, CORS.
3. **Register exception handlers** for:
   - ``CyberGuardError`` subclasses → their configured status code
   - ``RequestValidationError`` → 422 in our standard error envelope
   - Any other ``Exception`` → safe 500 with correlation ID
4. **Mount the API router** at ``/api/v1``.
5. **Provide infrastructure endpoints**: ``/`` (info) and ``/health``.
6. **Manage lifecycle**:
   - STARTUP: verify DB, start agent runtime thread, start scheduler thread
   - SHUTDOWN: signal both threads, dispose engine, close DB

Background threads
------------------
Two threads are spawned at startup (both daemon threads, both stop
cleanly on shutdown):

    Agent Runtime (from app.agents.runtime)
        Polls security_events for unprocessed events, dispatches to
        the applicable agents, promotes findings to alerts, commits
        in batches. Controlled by ``AGENT_EXECUTION_ENABLED``.

    Scheduler (this file)
        Runs periodic maintenance tasks:
            - Every 60s: incident_response sweep (auto-create incidents
              from HIGH/CRITICAL alerts + route to analysts)
            - Every hour: reporting sweep (daily/weekly/monthly reports
              for active workspaces, idempotent per period)

Both threads are best-effort — if either crashes, the HTTP API
continues to serve requests. Thread crashes are logged at ERROR and
the threads do not restart (failures visible to operators via /health).

Design rules
------------
1. **Single translation point for errors.** The handlers here are the
   only place that constructs HTTP error responses. Everything else
   raises ``CyberGuardError``.

2. **Health checks reflect reality.** ``/health`` returns 200 when the
   DB is reachable, 503 when it isn't. It also reports the status of
   the runtime and scheduler threads for observability.

3. **Startup does not crash in dev if DB is down.** ``require_database_ready``
   runs only in production. In development, a missing DB logs a warning
   and the app still starts.

4. **Middleware order matters.** FastAPI applies middleware in reverse
   registration order. CORS is registered last → runs first → preflight
   OPTIONS never reaches our code.

5. **No bare ``HTTPException``.** The exception handlers here are the
   only place that constructs HTTP error responses.

Usage
-----
    # Development
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

    # Production (workers controlled by env)
    gunicorn app.main:app \\
        --workers 4 --worker-class uvicorn.workers.UvicornWorker \\
        --bind 0.0.0.0:8000
"""

from __future__ import annotations

import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware

from app import (
    __description__,
    __license__,
    __title__,
    __version__,
)
from app.api.v1 import api_router
from app.core.config import settings
from app.core.constants import (
    API_PREFIX,
    API_VERSION,
    HEADER_CORRELATION_ID,
)
from app.core.exceptions import CyberGuardError, ConfigurationError
from app.core.logging import (
    configure_logging,
    get_correlation_id,
    get_logger,
    set_correlation_id,
)
from app.db.session import (
    dispose_engine,
    health_check,
    require_database_ready,
    session_scope,
)


# ============================================================================
# LOGGING — configure before anything else
# ============================================================================

configure_logging()
logger = get_logger(__name__)


# ============================================================================
# BACKGROUND SCHEDULER
# ============================================================================
# Runs periodic maintenance tasks in a daemon thread. Independent from
# the agent runtime thread (which is managed by app.agents.runtime).
#
# The scheduler is deliberately simple:
#   - a loop that sleeps 60s between iterations
#   - each iteration runs the incident sweep
#   - once per wall-clock hour, runs the 3 report frequencies
#
# All tasks are idempotent — running them more often than strictly
# necessary is safe.

_scheduler_thread: threading.Thread | None = None
_scheduler_stop_event: threading.Event | None = None


def _scheduler_loop(stop_event: threading.Event) -> None:
    """
    Background loop that runs periodic maintenance tasks.

    Iteration:
        1. Incident response sweep (every 60s)
        2. Report sweeps (once per wall-clock hour)

    Exits cleanly when ``stop_event`` is set.
    """
    # Import inside the function so the module isn't loaded until the
    # thread actually starts. If an agent module has a syntax error at
    # import time, this thread fails but the HTTP API continues.
    try:
        from app.agents.incident_response import IncidentResponseAgent
        from app.agents.reporting import ReportingAgent
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Scheduler cannot import agents — thread will not run",
            extra={"error": str(exc)[:300]},
        )
        return

    # Construct agents once. They're stateless — safe to reuse across
    # iterations. Their config is read from settings via the runtime.
    try:
        ir_agent = IncidentResponseAgent(
            config={
                "auto_create_severity_threshold": settings.INCIDENT_AUTO_CREATE_SEVERITY_THRESHOLD,
                "max_cases_per_analyst": settings.INCIDENT_AGENT_MAX_CASES_PER_ANALYST,
            }
        )
        report_agent = ReportingAgent(
            config={
                "max_rows": settings.REPORT_AGENT_MAX_ROWS,
                "pdf_page_limit": settings.REPORT_AGENT_PDF_PAGE_LIMIT,
            }
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Scheduler cannot construct agents — thread will not run",
            extra={"error": str(exc)[:300]},
        )
        return

    logger.info("Background scheduler started")
    last_report_hour: int = -1

    try:
        while not stop_event.is_set():
            now = datetime.now(timezone.utc)

            # ── Incident sweep (every iteration = every 60s)
            try:
                with session_scope() as db:
                    counts = ir_agent.run_sweep(db)
                    if any(counts[k] > 0 for k in (
                        "incidents_created", "incidents_merged", "assigned",
                    )):
                        logger.info(
                            "Incident sweep ran",
                            extra=counts,
                        )
            except Exception:  # noqa: BLE001
                logger.exception("Incident sweep failed")

            # ── Report sweeps (once per hour, on the wall-clock hour)
            # ``int(timestamp() // 3600)`` increments exactly at HH:00 UTC.
            current_hour = int(now.timestamp() // 3600)
            if current_hour != last_report_hour:
                for frequency in ("daily", "weekly", "monthly"):
                    try:
                        with session_scope() as db:
                            counts = report_agent.run_scheduled_reports(
                                db, frequency=frequency,
                            )
                            if counts["reports_created"] > 0 or counts["reports_failed"] > 0:
                                logger.info(
                                    f"Scheduled {frequency} reports ran",
                                    extra=counts,
                                )
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            f"Scheduled {frequency} reports failed"
                        )
                last_report_hour = current_hour

            # Sleep until next iteration, but wake early on stop signal
            stop_event.wait(timeout=60.0)

    except Exception:  # noqa: BLE001
        logger.exception("Scheduler crashed unexpectedly")
    finally:
        logger.info("Background scheduler stopped")


# ============================================================================
# LIFESPAN — startup / shutdown hooks
# ============================================================================

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """
    FastAPI lifespan context: runs once at startup and once at shutdown.
    """
    global _scheduler_thread, _scheduler_stop_event

    # ── STARTUP ─────────────────────────────────────────────────────────
    logger.info(
        "%s starting",
        __title__,
        extra={
            "version": __version__,
            "environment": settings.APP_ENV,
            "debug": settings.APP_DEBUG,
        },
    )

    # Log effective configuration (secrets masked — see config.py).
    logger.info(
        "Configuration loaded",
        extra={"config": settings.log_config_summary()},
    )

    # DB health: warn in dev, fail in prod.
    db_ok = health_check()
    if db_ok:
        logger.info("Database reachable at startup")

        # ── Initialize Firebase Admin (if enabled)
        if getattr(settings, "FIREBASE_AUTH_ENABLED", False):
            try:
                import firebase_admin
                from firebase_admin import credentials
                from pathlib import Path
                cred_path = Path(settings.FIREBASE_CREDENTIALS_PATH)
                if not cred_path.is_absolute():
                    cred_path = Path(__file__).resolve().parent.parent / settings.FIREBASE_CREDENTIALS_PATH
                if cred_path.exists():
                    cred = credentials.Certificate(str(cred_path))
                    firebase_admin.initialize_app(cred)
                    logger.info("Firebase Admin initialized successfully")
                else:
                    logger.warning("Firebase credentials file not found at %s", cred_path)
            except ValueError:
                # Already initialized
                pass
            except Exception as exc:
                logger.warning("Failed to initialize Firebase Admin: %s", exc)

        # ── Start agent runtime (if enabled)
        if settings.AGENT_EXECUTION_ENABLED:
            try:
                from app.agents.runtime import start_runtime
                start_runtime(settings)
                logger.info("Agent runtime thread started")
            except Exception:  # noqa: BLE001
                logger.exception("Failed to start agent runtime — continuing without it")
        else:
            logger.info("Agent runtime disabled (AGENT_EXECUTION_ENABLED=false)")

        # ── Start scheduler (skip in test mode to avoid unmanaged background sweeps)
        if not settings.is_test:
            _scheduler_stop_event = threading.Event()
            _scheduler_thread = threading.Thread(
                target=_scheduler_loop,
                args=(_scheduler_stop_event,),
                name="cyberguard-scheduler",
                daemon=True,
            )
            _scheduler_thread.start()
            logger.info("Scheduler thread started")
        else:
            logger.info("Scheduler disabled in test mode")
    else:
        if settings.is_production:
            raise ConfigurationError(
                message=(
                    "Database unreachable at startup in production. "
                    "Refusing to serve requests without persistence."
                ),
                code="DATABASE_UNREACHABLE_AT_STARTUP",
            )
        else:
            logger.warning(
                "Database unreachable at startup — continuing in %s mode. "
                "Background workers paused. /health will return 503 until PostgreSQL is started.",
                settings.APP_ENV,
            )

    logger.info(
        "%s ready — docs at %s/docs",
        __title__,
        settings.BACKEND_PUBLIC_URL,
    )

    yield

    # ── SHUTDOWN ────────────────────────────────────────────────────────
    logger.info("%s shutting down", __title__)

    # Stop scheduler
    if _scheduler_stop_event is not None and _scheduler_thread is not None:
        try:
            _scheduler_stop_event.set()
            _scheduler_thread.join(timeout=30.0)
            if _scheduler_thread.is_alive():
                logger.warning(
                    "Scheduler thread did not stop within 30s — leaving as daemon"
                )
            else:
                logger.info("Scheduler thread stopped")
        except Exception:  # noqa: BLE001
            logger.exception("Error while stopping scheduler")

    # Stop agent runtime
    if settings.AGENT_EXECUTION_ENABLED:
        try:
            from app.agents.runtime import stop_runtime
            stop_runtime(timeout_seconds=30)
            logger.info("Agent runtime stopped")
        except Exception:  # noqa: BLE001
            logger.exception("Error while stopping agent runtime")

    # Dispose DB engine
    try:
        dispose_engine()
        logger.info("Database engine disposed")
    except Exception:  # noqa: BLE001
        logger.warning("Engine disposal failed during shutdown")

    logger.info("%s stopped", __title__)


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title=__title__,
    description=__description__,
    version=__version__,
    license_info={"name": __license__},
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    root_path="",
)


# ============================================================================
# MIDDLEWARE: CORRELATION ID
# ============================================================================

class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Set (or generate) a correlation ID for every request.
    Reads ``X-Correlation-ID`` from the incoming request; if absent,
    generates a fresh UUID. Echoes the ID back as a response header.
    Also logs the request line with duration and status code.
    """

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get(HEADER_CORRELATION_ID)
        correlation_id = incoming.strip() if incoming else str(uuid.uuid4())
        set_correlation_id(correlation_id)

        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.perf_counter() - start) * 1000)
            logger.exception(
                "Unhandled exception during request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                },
            )
            raise

        duration_ms = int((time.perf_counter() - start) * 1000)
        response.headers[HEADER_CORRELATION_ID] = correlation_id

        logger.info(
            "Request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "correlation_id": correlation_id,
            },
        )
        return response


# ============================================================================
# MIDDLEWARE: BODY SIZE LIMIT
# ============================================================================

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject requests whose Content-Length exceeds MAX_UPLOAD_SIZE_BYTES.
    """

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": {
                            "code": "INVALID_CONTENT_LENGTH",
                            "message": "Content-Length header is not a valid integer.",
                        }
                    },
                )

            if length > settings.MAX_UPLOAD_SIZE_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": (
                                f"Request body exceeds the maximum of "
                                f"{settings.MAX_UPLOAD_SIZE_BYTES} bytes."
                            ),
                            "details": {
                                "max_bytes": settings.MAX_UPLOAD_SIZE_BYTES,
                                "actual_bytes": length,
                            },
                        }
                    },
                )

        return await call_next(request)


# ============================================================================
# MIDDLEWARE REGISTRATION
# ============================================================================
# Registration order → execution order (reverse):
#   Registration:  CorrelationID, BodyLimit, CORS
#   Request flow:  CORS → BodyLimit → CorrelationID → route

app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=r"^https://.*(\.pages\.dev|\.onrender\.com)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=[HEADER_CORRELATION_ID],
    max_age=600,
)


# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(CyberGuardError)
async def cyberguard_error_handler(
    request: Request,
    exc: CyberGuardError,
) -> JSONResponse:
    """Translate a ``CyberGuardError`` into an HTTP response."""
    if exc.status_code >= 500:
        logger.error(
            "CyberGuardError (5xx)",
            extra={
                "code": exc.code,
                "status_code": exc.status_code,
                "path": request.url.path,
            },
            exc_info=exc.__cause__ is not None,
        )
    else:
        logger.info(
            "CyberGuardError (4xx)",
            extra={
                "code": exc.code,
                "status_code": exc.status_code,
                "path": request.url.path,
            },
        )

    body = exc.to_dict()
    if "correlation_id" not in body.get("error", {}):
        correlation_id = get_correlation_id()
        if correlation_id:
            body.setdefault("error", {})["correlation_id"] = correlation_id

    headers = {}
    correlation_id = get_correlation_id()
    if correlation_id:
        headers[HEADER_CORRELATION_ID] = correlation_id

    return JSONResponse(
        status_code=exc.status_code,
        content=body,
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Normalize FastAPI's RequestValidationError into our ErrorResponse."""
    logger.info(
        "Request validation failed",
        extra={
            "path": request.url.path,
            "error_count": len(exc.errors()),
        },
    )

    correlation_id = get_correlation_id()
    body = {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed.",
            "details": {"fields": exc.errors()},
        }
    }
    if correlation_id:
        body["error"]["correlation_id"] = correlation_id

    headers = {}
    if correlation_id:
        headers[HEADER_CORRELATION_ID] = correlation_id

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=body,
        headers=headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Catch-all for exceptions that aren't CyberGuardError or validation."""
    correlation_id = get_correlation_id()

    logger.error(
        "Unhandled exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "exception_type": type(exc).__name__,
        },
        exc_info=exc,
    )

    body = {
        "error": {
            "code": "INTERNAL_ERROR",
            "message": (
                "An internal error occurred. "
                "Please contact support with the correlation ID."
            ),
        }
    }
    if correlation_id:
        body["error"]["correlation_id"] = correlation_id

    headers = {}
    if correlation_id:
        headers[HEADER_CORRELATION_ID] = correlation_id

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=body,
        headers=headers,
    )


# ============================================================================
# INFRASTRUCTURE ENDPOINTS
# ============================================================================

@app.get(
    "/",
    tags=["meta"],
    summary="Root API info",
)
@app.head(
    "/",
    include_in_schema=False,
)
@app.get(
    "/api",
    tags=["meta"],
    summary="API information",
)
async def root() -> dict:
    """Root endpoint — returns API metadata and links."""
    return {
        "name": __title__,
        "version": __version__,
        "description": __description__,
        "environment": settings.APP_ENV,
        "api": {
            "version": API_VERSION,
            "base_url": API_PREFIX,
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
        "health": "/health",
    }


@app.get(
    "/health",
    tags=["meta"],
    summary="Health check",
    responses={
        200: {"description": "Service is healthy."},
        503: {"description": "Service is unhealthy — see checks."},
    },
)
async def health() -> JSONResponse:
    """
    Kubernetes-style health check.

    Returns 200 when the DB is reachable, 503 when it isn't. Response
    body carries per-dependency status and background thread status.
    """
    db_ok = health_check()

    # Runtime status
    runtime_status: dict | None = None
    if settings.AGENT_EXECUTION_ENABLED:
        try:
            from app.agents.runtime import get_runtime
            rt = get_runtime()
            if rt is not None:
                runtime_status = {
                    "registered_agents": rt.registered_agents,
                    "watermark": rt.watermark.isoformat(),
                    "last_batch": rt.stats,
                }
        except Exception:
            runtime_status = {"error": "runtime import failed"}

    # Scheduler status
    scheduler_status = {
        "running": (
            _scheduler_thread is not None and _scheduler_thread.is_alive()
        ),
    }

    checks: dict = {
        "db": {"status": "ok" if db_ok else "down"},
        "runtime": runtime_status,
        "scheduler": scheduler_status,
    }
    overall = "ok" if db_ok else "unhealthy"

    body = {
        "status": overall,
        "version": __version__,
        "environment": settings.APP_ENV,
        "checks": checks,
    }

    correlation_id = get_correlation_id()
    if correlation_id:
        body["correlation_id"] = correlation_id

    return JSONResponse(
        status_code=(
            status.HTTP_200_OK if db_ok
            else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        content=body,
        headers=(
            {HEADER_CORRELATION_ID: correlation_id}
            if correlation_id
            else {}
        ),
    )


# ============================================================================
# API ROUTER
# ============================================================================

app.include_router(api_router, prefix=API_PREFIX)

# Mount static files for verified endpoint collector installers
_static_dir = Path(__file__).resolve().parent.parent / 'static'
if _static_dir.exists() and _static_dir.is_dir():
    app.mount('/static', StaticFiles(directory=str(_static_dir)), name='static')


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["app"]