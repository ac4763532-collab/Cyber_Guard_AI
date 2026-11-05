"""
CyberGuard AI - Main Application Entry Point

AI-Driven Multi-Agent Cybersecurity Threat Detection
and Contextual Correlation Platform

This is the FastAPI application entry point.
Run with: uvicorn app.main:app --reload
"""

import asyncio
import logging
import sys

# On Windows, asyncio's default loop is ProactorEventLoop, but psycopg's
# async mode (used by app.database.connection's AsyncConnectionPool)
# requires a SelectorEventLoop - without this, every pool connection
# attempt fails with "Psycopg cannot use the 'ProactorEventLoop' to run
# in async mode", the pool never initializes (30s timeout), and the app
# falls back to running without a database. This must run before any
# event loop is created, i.e. before uvicorn starts serving - setting it
# only inside `if __name__ == "__main__"` below does not cover the
# `uvicorn app.main:app` invocation used in development and the
# docker-compose/production entrypoints, since that path never executes
# this module as __main__. Tests already apply the same fix
# (see tests/conftest.py) - this brings the running app in line with it.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_router
from app.config import settings
from app.middleware.rate_limit import limiter
from app.middleware.concurrency import ConcurrencyLimiterMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.logging import RequestLoggingMiddleware
from app.core.errors import (
    CyberGuardError,
    ErrorCode,
    ErrorResponse,
    RateLimitError,
    get_error_code_for_status,
)
from app.core.error_messages import get_safe_message, sanitize_error_detail


# Wire stdlib logging's root handler/level before structlog.configure()
# below. structlog.stdlib.LoggerFactory() routes every logger.info()/
# .error() call through Python's stdlib `logging` module - without a
# handler attached and the level raised from the stdlib default
# (root logger defaults to WARNING, no handler), every INFO/DEBUG call
# across the entire backend (collector startup, connection, poll-loop
# logging, etc.) is silently dropped before it ever reaches stdout. This
# was discovered while diagnosing why no collector log lines appeared
# despite collector_status reporting "running" - fixing it is required to
# get real backend log evidence, not just an unrelated improvement.
logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(message)s",
    stream=sys.stdout,
)

# Bug fix (terminal flooded with "Request to localhost:9092 ..." /
# "Response from localhost:9092 ..." lines on every startup): aiokafka's
# own loggers (aiokafka.conn, aiokafka.consumer, aiokafka.producer, etc.)
# inherit from the root logger configured above. Raising the app's own
# log_level to DEBUG (as this project's local .env does) was being read by
# aiokafka too, which traces every single Kafka protocol request/response
# frame at DEBUG - that's a third-party transport-layer detail, not
# something app-level DEBUG logging should imply. Capping the "aiokafka"
# namespace independently (via its own settings.kafka_client_log_level,
# default WARNING) stops the per-frame spam while leaving real aiokafka
# WARNING/ERROR logs (broker unreachable, consumer errors, etc.) fully
# visible - this only quiets DEBUG/INFO protocol tracing, never genuine
# errors. Setting the parent "aiokafka" logger covers every submodule
# since none of them set their own level, so logging falls through to
# this one.
logging.getLogger("aiokafka").setLevel(settings.kafka_client_log_level.upper())

# Configure structured logging with contextvars support
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,  # Merge request_id from context
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Handles startup and shutdown events:
    - Startup: Initialize database connections, load models, etc.
    - Shutdown: Close connections, cleanup resources
    """
    # Startup
    logger.info(
        "Starting CyberGuard AI",
        version=settings.app_version,
        environment=settings.environment,
    )

    # Initialize database if enabled
    if settings.db_enabled:
        try:
            from app.database import init_database
            await init_database()
            logger.info("Database connection established")
        except Exception as e:
            logger.warning("Database initialization failed", error=str(e))
    else:
        logger.info("Database disabled - running in memory-only mode")

    # Initialize Redis connection
    try:
        from app.cache import get_redis_client
        redis_client = await get_redis_client()
        health = await redis_client.health_check()
        if health["status"] == "healthy":
            logger.info("Redis connection established", version=health.get("redis_version"))
        else:
            logger.warning("Redis health check failed", error=health.get("error"))
    except Exception as e:
        logger.warning("Redis initialization failed - caching disabled", error=str(e))

    # Initialize Redpanda event bus producer
    try:
        from app.event_bus.producer import init_producer, get_producer
        await init_producer()
        producer = get_producer()
        health = await producer.health_check()
        if health.get("healthy"):
            logger.info(
                "Event bus producer initialized",
                status=health.get("status"),
                brokers=health.get("brokers"),
            )
        else:
            logger.warning(
                "Event bus producer unhealthy",
                status=health.get("status"),
                message=health.get("message"),
            )
    except Exception as e:
        logger.warning("Event bus initialization failed - event streaming disabled", error=str(e))

    # STEP 8.5.6: Start the security event consumer for real-time processing
    try:
        from app.event_bus.dispatcher_integration import start_security_consumer
        await start_security_consumer()
        logger.info("Security event consumer started - listening on security-events topic")
    except Exception as e:
        logger.warning("Security event consumer failed to start", error=str(e))

    # Start embedded log collectors (Windows Event Log, Linux SSH)
    if settings.log_collectors_enabled:
        try:
            from app.logs.collector_manager import get_collector_manager
            collector_manager = get_collector_manager()
            await collector_manager.start_all()
            logger.info(
                "Log collector manager started",
                active_collectors=collector_manager.active_count,
            )
        except Exception as e:
            logger.warning("Log collector manager failed to start", error=str(e))
    else:
        logger.info("Log collectors disabled (log_collectors_enabled=False)")

    # Start automatic Gmail polling (app/services/gmail/poller.py) - makes
    # Email analysis actually automatic for connected Gmail accounts,
    # independent of the embedded log collectors above.
    try:
        from app.services.gmail.poller import start_gmail_poller
        await start_gmail_poller()
    except Exception as e:
        logger.warning("Gmail poller failed to start", error=str(e))

    # Start the evidence-aware retention cleanup scheduler
    # (app/retention/scheduler.py). Independent of collectors/Gmail -
    # periodically deletes log_events rows past the configured retention
    # window that are not referenced by any Finding and not under legal
    # hold. See app/retention/cleanup.py for the full safety invariant.
    if settings.db_enabled:
        try:
            from app.retention.scheduler import start_retention_scheduler
            await start_retention_scheduler()
        except Exception as e:
            logger.warning("Retention cleanup scheduler failed to start", error=str(e))

    # Initialize ML email classifier
    try:
        from app.ml.classifier import load_models, get_model_status

        ml_loaded = load_models()
        ml_status = get_model_status()

        if ml_loaded:
            logger.info(
                "Email ML classifier loaded",
                model=ml_status.get("model"),
                threshold=ml_status.get("threshold"),
            )
        else:
            logger.warning(
                "Email ML classifier unavailable",
                error=ml_status.get("error"),
            )
    except Exception as e:
        logger.warning(
            "Email ML classifier initialization failed",
            error=str(e),
        )

    # TODO: Initialize RAG vector store (Milestone 13)

    logger.info("CyberGuard AI startup complete")

    yield

    # Shutdown
    #
    # Bug fix (Windows/local-network collectors logging "Database not
    # initialized" during every shutdown): this must be the EXACT REVERSE
    # of the startup order above - every embedded collector's run loop
    # calls log_event_repo.create()/update_status() (PostgreSQL) and
    # publish_log_event() (Redpanda) while it is winding down (its final
    # in-flight batch, or the "clean shutdown" status update in
    # collectors/windows.py's _run_collection(), or the ERROR-status write
    # in its except block). Those are real dependencies, not optional
    # ones. The previous order closed the database and event bus FIRST
    # and only stopped collectors LAST, so every single shutdown hit this
    # race: collector.stop() -> cancels/awaits the collection task ->
    # task's own try/except logs "Database not initialized" because the
    # pool was already closed two steps earlier. Collectors (and the
    # security event consumer, which also persists findings via the same
    # pool) must stop WHILE their dependencies are still alive; the
    # database/Redis/event-bus connections are torn down only after that.
    logger.info("Shutting down CyberGuard AI")

    # Stop the retention cleanup scheduler first (reverse of its being the
    # last thing started) - it also depends on the database being alive.
    try:
        from app.retention.scheduler import stop_retention_scheduler
        await stop_retention_scheduler()
    except Exception as e:
        logger.warning("Retention cleanup scheduler stop failed", error=str(e))

    # Stop automatic Gmail polling first - independent of collectors, but
    # also writes to the database (gmail_sync_state) and should not race
    # against it either.
    try:
        from app.services.gmail.poller import stop_gmail_poller
        await stop_gmail_poller()
    except Exception as e:
        logger.warning("Gmail poller stop failed", error=str(e))

    # Stop embedded log collectors WHILE the database/event bus are still
    # up, so their final persistence/status-update calls succeed instead
    # of raising "Database not initialized".
    if settings.log_collectors_enabled:
        try:
            from app.logs.collector_manager import get_collector_manager
            await get_collector_manager().stop_all()
            logger.info("Log collector manager stopped")
        except Exception as e:
            logger.warning("Log collector manager stop failed", error=str(e))

    # STEP 8.5.6: Stop the security event consumer - it also persists
    # findings to PostgreSQL and publishes to Redpanda, so it must stop
    # before those connections close too.
    try:
        from app.event_bus.dispatcher_integration import stop_security_consumer
        await stop_security_consumer()
        logger.info("Security event consumer stopped")
    except Exception as e:
        logger.warning("Security event consumer stop failed", error=str(e))

    # Close event bus producer - after the consumer and collectors (which
    # publish through it) have stopped.
    try:
        from app.event_bus.producer import close_producer
        await close_producer()
        logger.info("Event bus producer closed")
    except Exception as e:
        logger.warning("Event bus producer close failed", error=str(e))

    # Close Redis connection - after everything that might still read/
    # write cache or correlation state during its own shutdown.
    try:
        from app.cache.redis_client import close_redis_client
        await close_redis_client()
        logger.info("Redis connection closed")
    except Exception as e:
        logger.warning("Redis close failed", error=str(e))

    # Close database connection LAST - every component above may still
    # need it while it shuts down.
    if settings.db_enabled:
        try:
            from app.database import close_database
            await close_database()
            logger.info("Database connection closed")
        except Exception as e:
            logger.warning("Database close failed", error=str(e))

    logger.info("CyberGuard AI shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="""
## CyberGuard AI

**AI-Driven Multi-Agent Cybersecurity Threat Detection and Contextual Correlation Platform**

### Features

- **Multi-Agent Architecture**: Specialized agents for email, log, and network analysis
- **Threat Detection**: Rule-based, IOC-based, and ML/anomaly detection
- **Cross-Domain Correlation**: Connect events across multiple security domains
- **AI-Powered Analysis**: LLM-based contextual interpretation and recommendations
- **Real-Time Monitoring**: Live event ingestion and dashboard updates

### API Documentation

- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`
- **OpenAPI Schema**: `/openapi.json`
    """,
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure SlowAPI rate limiting
if settings.rate_limit_enabled:
    app.state.limiter = limiter


def _get_request_id(request: Request) -> str | None:
    """Safely extract request_id from request state."""
    try:
        return getattr(request.state, "request_id", None)
    except Exception:
        return None


# =============================================================================
# Exception Handlers (Step 11)
# =============================================================================


@app.exception_handler(CyberGuardError)
async def cyberguard_error_handler(request: Request, exc: CyberGuardError) -> JSONResponse:
    """
    Handler for CyberGuardError and all subclasses.

    Returns standardized ErrorResponse format.
    """
    request_id = _get_request_id(request)

    logger.warning(
        "CyberGuard error",
        path=request.url.path,
        method=request.method,
        error_code=exc.error_code.value,
        status_code=exc.status_code,
        request_id=request_id,
    )

    response = ErrorResponse(
        error=exc.error_code.value,
        message=exc.message,
        detail=sanitize_error_detail(exc.detail, settings.debug),
        request_id=request_id,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=response.model_dump(mode="json"),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handler for FastAPI request validation errors.

    Returns standardized ErrorResponse format with validation details.
    """
    request_id = _get_request_id(request)

    # Build safe error detail
    if settings.debug:
        # In debug mode, include validation error details
        errors = exc.errors()
        detail = "; ".join(
            f"{'.'.join(str(loc) for loc in e.get('loc', []))}: {e.get('msg', 'invalid')}"
            for e in errors[:5]  # Limit to 5 errors
        )
    else:
        detail = None

    logger.warning(
        "Validation error",
        path=request.url.path,
        method=request.method,
        error_count=len(exc.errors()),
        request_id=request_id,
    )

    response = ErrorResponse(
        error=ErrorCode.VALIDATION_ERROR.value,
        message="Request validation failed",
        detail=detail,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=400,
        content=response.model_dump(mode="json"),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """
    Handler for Starlette/FastAPI HTTPException.

    Converts to standardized ErrorResponse format.
    """
    request_id = _get_request_id(request)

    # Map HTTP status to error code
    error_code = get_error_code_for_status(exc.status_code)

    logger.warning(
        "HTTP exception",
        path=request.url.path,
        method=request.method,
        status_code=exc.status_code,
        request_id=request_id,
    )

    # Sanitize detail
    detail = sanitize_error_detail(str(exc.detail) if exc.detail else None, settings.debug)

    response = ErrorResponse(
        error=error_code.value,
        message=str(exc.detail) if exc.detail and settings.debug else get_safe_message(str(exc.detail) if exc.detail else ""),
        detail=detail,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=response.model_dump(mode="json"),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Handler for SlowAPI rate limit exceeded errors.

    Returns standardized ErrorResponse format with Retry-After header.
    """
    request_id = _get_request_id(request)

    # Log rate limit event
    try:
        from app.logging import log_rate_limit_exceeded

        client_ip = request.client.host if request.client else "unknown"
        log_rate_limit_exceeded(
            endpoint=request.url.path,
            client_ip=client_ip,
            limit=str(exc.detail) if exc.detail else "unknown",
        )
    except Exception:
        pass

    logger.warning(
        "Rate limit exceeded",
        path=request.url.path,
        method=request.method,
        request_id=request_id,
    )

    response = ErrorResponse(
        error=ErrorCode.RATE_LIMITED.value,
        message="Rate limit exceeded. Please slow down your requests.",
        detail=None,
        request_id=request_id,
    )

    # Extract retry-after from exception if available
    retry_after = getattr(exc, "retry_after", 60)

    return JSONResponse(
        status_code=429,
        content=response.model_dump(mode="json"),
        headers={
            "Retry-After": str(retry_after),
            
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler for unhandled errors.

    Logs the error and returns a safe error response
    without exposing internal details in production.
    """
    request_id = _get_request_id(request)

    logger.error(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        error_type=type(exc).__name__,
        request_id=request_id,
        exc_info=True,
    )

    # In debug mode, include controlled error details
    if settings.debug:
        detail = sanitize_error_detail(str(exc), debug=True)
        message = f"Internal error: {type(exc).__name__}"
    else:
        detail = None
        message = "An unexpected error occurred"

    response = ErrorResponse(
        error=ErrorCode.INTERNAL_ERROR.value,
        message=message,
        detail=detail,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=500,
        content=response.model_dump(mode="json"),
    )


# =============================================================================
# Middleware Configuration
# =============================================================================

# Middleware order (applied in reverse - last added runs first):
# 1. RequestID -> 2. RequestLogging -> 3. CORS -> 4. Concurrency -> 5. Routes

# Configure request concurrency limiting (Step 9)
app.add_middleware(
    ConcurrencyLimiterMiddleware,
    max_concurrent=settings.max_concurrent_requests,
    max_queue_size=settings.max_request_queue,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware (Step 10)
app.add_middleware(RequestLoggingMiddleware)

# Request ID middleware (Step 10) - runs first
app.add_middleware(RequestIDMiddleware)


# Include API routers
app.include_router(api_router, prefix=settings.api_v1_prefix)


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict:
    """
    Root endpoint - API information.

    Returns basic API information and links to documentation.
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "AI-Driven Multi-Agent Cybersecurity Threat Detection Platform",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
        "health": f"{settings.api_v1_prefix}/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


