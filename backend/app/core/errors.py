"""
CyberGuard AI - Standardized Error Handling

Provides:
- ErrorCode enum for consistent error codes
- ErrorResponse Pydantic model for API responses
- CyberGuardError base exception and specialized exceptions
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Standardized error codes for the API."""

    # Validation errors (400)
    VALIDATION_ERROR = "validation_error"
    INVALID_INPUT = "invalid_input"
    MISSING_FIELD = "missing_field"

    # Authentication errors (401)
    UNAUTHORIZED = "unauthorized"
    INVALID_TOKEN = "invalid_token"
    TOKEN_EXPIRED = "token_expired"

    # Authorization errors (403)
    FORBIDDEN = "forbidden"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"

    # Not found errors (404)
    NOT_FOUND = "not_found"
    RESOURCE_NOT_FOUND = "resource_not_found"

    # Rate limiting errors (429)
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"

    # External service errors (502)
    EXTERNAL_SERVICE_ERROR = "external_service_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    CIRCUIT_OPEN = "circuit_open"

    # Internal errors (500)
    INTERNAL_ERROR = "internal_error"
    ANALYSIS_FAILED = "analysis_failed"


class ErrorResponse(BaseModel):
    """Standardized error response format for all API errors."""

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    detail: Optional[str] = Field(None, description="Additional error details")
    request_id: Optional[str] = Field(None, description="Request ID for tracing")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the error",
    )


class CyberGuardError(Exception):
    """
    Base exception for all CyberGuard AI errors.

    Provides standardized error handling with:
    - Error code
    - HTTP status code
    - Human-readable message
    - Optional detail for debugging
    """

    def __init__(
        self,
        message: str = "An error occurred",
        error_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        status_code: int = 500,
        detail: Optional[str] = None,
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)

    def to_response(self, request_id: Optional[str] = None) -> ErrorResponse:
        """Convert exception to ErrorResponse."""
        return ErrorResponse(
            error=self.error_code.value,
            message=self.message,
            detail=self.detail,
            request_id=request_id,
        )


class ValidationError(CyberGuardError):
    """Raised for input validation failures (HTTP 400)."""

    def __init__(
        self,
        message: str = "Validation failed",
        detail: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.VALIDATION_ERROR,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=400,
            detail=detail,
        )


class AuthenticationError(CyberGuardError):
    """Raised for authentication failures (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication required",
        detail: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.UNAUTHORIZED,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=401,
            detail=detail,
        )


class AuthorizationError(CyberGuardError):
    """Raised for authorization failures (HTTP 403)."""

    def __init__(
        self,
        message: str = "Access denied",
        detail: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.FORBIDDEN,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=403,
            detail=detail,
        )


class NotFoundError(CyberGuardError):
    """Raised when a resource is not found (HTTP 404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        detail: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.NOT_FOUND,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=404,
            detail=detail,
        )


class RateLimitError(CyberGuardError):
    """Raised when rate limit is exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        detail: Optional[str] = None,
        retry_after: Optional[int] = None,
        error_code: ErrorCode = ErrorCode.RATE_LIMITED,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=429,
            detail=detail,
        )
        self.retry_after = retry_after


class ExternalServiceError(CyberGuardError):
    """Raised when an external service fails (HTTP 502)."""

    def __init__(
        self,
        message: str = "External service unavailable",
        detail: Optional[str] = None,
        service_name: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.EXTERNAL_SERVICE_ERROR,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=502,
            detail=detail,
        )
        self.service_name = service_name


class AnalysisError(CyberGuardError):
    """Raised when analysis fails critically (HTTP 500)."""

    def __init__(
        self,
        message: str = "Analysis failed",
        detail: Optional[str] = None,
        error_code: ErrorCode = ErrorCode.ANALYSIS_FAILED,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            detail=detail,
        )


# HTTP status code to error code mapping
HTTP_STATUS_TO_ERROR_CODE: dict[int, ErrorCode] = {
    400: ErrorCode.INVALID_INPUT,
    401: ErrorCode.UNAUTHORIZED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    429: ErrorCode.RATE_LIMITED,
    500: ErrorCode.INTERNAL_ERROR,
    502: ErrorCode.EXTERNAL_SERVICE_ERROR,
    503: ErrorCode.SERVICE_UNAVAILABLE,
}


def get_error_code_for_status(status_code: int) -> ErrorCode:
    """Get the appropriate error code for an HTTP status code."""
    return HTTP_STATUS_TO_ERROR_CODE.get(status_code, ErrorCode.INTERNAL_ERROR)
