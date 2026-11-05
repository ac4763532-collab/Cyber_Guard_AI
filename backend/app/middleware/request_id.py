"""
CyberGuard AI - Request ID Middleware

Assigns a unique request ID to every HTTP request for tracing.
The ID is bound to structlog context and returned in response headers.
"""

import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


REQUEST_ID_HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware that assigns/preserves request IDs for request tracing.

    Behavior:
    - If client sends X-Request-ID header, preserve it
    - Otherwise generate a new UUID4
    - Bind the ID to structlog context for downstream logs
    - Return the ID in response X-Request-ID header
    """

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        # Get existing request ID or generate new one
        request_id = request.headers.get(REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in request state for access by other middleware/routes
        request.state.request_id = request_id

        # Clear and bind to structlog context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response = await call_next(request)
            # Add request ID to response headers
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        except Exception:
            # Re-raise but still try to clear context
            raise
        finally:
            # Clear context after request completes
            structlog.contextvars.clear_contextvars()


def get_request_id(request: Request) -> str:
    """Get request ID from request state, or generate if missing."""
    return getattr(request.state, "request_id", str(uuid.uuid4()))
