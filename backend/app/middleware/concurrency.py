"""
CyberGuard AI - Request Concurrency Limiter

Limits the number of concurrent requests to prevent system overload.
Uses asyncio semaphore for non-blocking concurrency control.

Separate from rate limiting:
- Rate limiting: requests per time window
- Concurrency limiting: simultaneous requests at any moment
"""

import asyncio
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.config import get_settings


logger = structlog.get_logger(__name__)


class ConcurrencyLimiterMiddleware(BaseHTTPMiddleware):
    """
    Middleware to limit concurrent request processing.

    When max concurrent requests is reached:
    - If queue has room: request waits
    - If queue is full: returns 503 immediately

    This protects against:
    - Memory exhaustion from too many concurrent operations
    - Database connection pool exhaustion
    - External API overwhelm
    """

    def __init__(
        self,
        app,
        max_concurrent: int = 100,
        max_queue_size: int = 200,
        queue_timeout_seconds: float = 30.0,
    ):
        """
        Initialize concurrency limiter.

        Args:
            app: FastAPI application
            max_concurrent: Maximum simultaneous requests being processed
            max_queue_size: Maximum requests waiting in queue
            queue_timeout_seconds: How long a request can wait in queue
        """
        super().__init__(app)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._max_queue_size = max_queue_size
        self._queue_timeout = queue_timeout_seconds
        self._current_queue_size = 0
        self._lock = asyncio.Lock()

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Process request with concurrency limiting."""

        # Skip health checks and static files
        path = request.url.path
        if path in ("/", "/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        # Check if queue has room
        async with self._lock:
            if self._current_queue_size >= self._max_queue_size:
                logger.warning(
                    "Request queue full, rejecting request",
                    path=path,
                    queue_size=self._current_queue_size,
                    max_queue=self._max_queue_size,
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "service_overloaded",
                        "detail": "Server is at capacity. Please retry shortly.",
                        "retry_after": 5,
                    },
                    headers={"Retry-After": "5"},
                )
            self._current_queue_size += 1

        try:
            # Wait for semaphore with timeout
            try:
                await asyncio.wait_for(
                    self._semaphore.acquire(),
                    timeout=self._queue_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Request queue timeout",
                    path=path,
                    timeout=self._queue_timeout,
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "queue_timeout",
                        "detail": "Request timed out waiting in queue.",
                        "retry_after": 10,
                    },
                    headers={"Retry-After": "10"},
                )

            try:
                # Process the request
                response = await call_next(request)
                return response
            finally:
                self._semaphore.release()

        finally:
            async with self._lock:
                self._current_queue_size -= 1


# Default instance configuration
_middleware_instance = None


def get_concurrency_middleware(
    app,
    max_concurrent: int = None,
    max_queue_size: int = None,
) -> ConcurrencyLimiterMiddleware:
    """
    Create concurrency limiter middleware with settings.

    Args:
        app: FastAPI application
        max_concurrent: Override max concurrent (default from settings)
        max_queue_size: Override max queue (default from settings)
    """
    settings = get_settings()

    concurrent = max_concurrent or getattr(settings, "max_concurrent_requests", 100)
    queue = max_queue_size or getattr(settings, "max_request_queue", 200)

    return ConcurrencyLimiterMiddleware(
        app=app,
        max_concurrent=concurrent,
        max_queue_size=queue,
    )
