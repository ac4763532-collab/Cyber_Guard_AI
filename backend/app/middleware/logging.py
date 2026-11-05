"""
CyberGuard AI - Request/Response Logging Middleware

Logs request start/completion with timing for observability.
Integrates with structlog and uses request_id from context.
"""

import time
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


logger = structlog.get_logger(__name__)

# Paths to skip detailed logging (health checks, static files)
SKIP_LOGGING_PATHS = {
    "/",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs request start and completion with timing.

    Logs:
    - request_started: method, path, client_ip, request_id
    - request_completed: method, path, status_code, duration_ms, request_id
    - request_failed: on exception (then re-raises)

    Security:
    - Does NOT log request bodies, passwords, tokens, or sensitive headers
    - Client IP is logged for security audit purposes
    """

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        path = request.url.path

        # Skip logging for certain paths
        if path in SKIP_LOGGING_PATHS:
            return await call_next(request)

        # Get client IP (handles proxies via X-Forwarded-For)
        client_ip = self._get_client_ip(request)
        method = request.method

        # Get request ID from state (set by RequestIDMiddleware)
        request_id = getattr(request.state, "request_id", "unknown")

        # Log request start
        logger.info(
            "request_started",
            method=method,
            path=path,
            client_ip=client_ip,
            request_id=request_id,
        )

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000

            # Log request completion
            logger.info(
                "request_completed",
                method=method,
                path=path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                request_id=request_id,
            )

            return response

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000

            # Log request failure
            logger.error(
                "request_failed",
                method=method,
                path=path,
                duration_ms=round(duration_ms, 2),
                request_id=request_id,
                error_type=type(exc).__name__,
            )

            # Re-raise so FastAPI's exception handling can process it
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, considering proxy headers."""
        # Check X-Forwarded-For first (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain (original client)
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client
        if request.client:
            return request.client.host

        return "unknown"
