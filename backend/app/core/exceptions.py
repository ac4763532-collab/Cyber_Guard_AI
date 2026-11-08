"""
CyberGuard AI — Exception Hierarchy
============================================================================

Every error raised by backend code (services, agents, APIs) must be a
subclass of ``CyberGuardError``. This gives us three guarantees:

1. **Machine-readable error codes.** Every exception carries a stable
   string ``code`` (e.g. ``"AUTH_INVALID_TOKEN"``) that clients and scripts
   can branch on without parsing English messages.

2. **Automatic HTTP translation.** ``main.py`` registers a single handler
   that converts any ``CyberGuardError`` into a JSON response with the
   right status code and error code. Services never touch ``HTTPException``.

3. **Full traceability.** Every exception captures the current correlation
   ID (from ``app.core.logging``) at raise time. Logs and HTTP responses
   share the same identifier, so an incident can be traced end to end.

Exception categories
--------------------
    CyberGuardError                  — root of everything
    ├── ConfigurationError           — misconfigured environment (fatal)
    ├── AuthenticationError          — who are you? (401)
    ├── AuthorizationError           — you can't do that (403)
    ├── NotFoundError                — resource does not exist (404)
    ├── ValidationError              — input failed validation (422)
    ├── ConflictError                — state conflict / duplicate (409)
    ├── RateLimitError               — too many requests (429)
    ├── DatabaseError                — persistence failure (500)
    ├── ExternalServiceError         — third-party API failure (502/503)
    ├── AgentError                   — an agent failed to process (500)
    └── CollectorError               — collector/device problem (400/403)

Raising
-------
    from app.core.exceptions import NotFoundError

    raise NotFoundError(
        message="Incident not found",
        code="INCIDENT_NOT_FOUND",
        details={"incident_id": str(incident_id)},
    )

Handling (in main.py)
---------------------
    from app.core.exceptions import CyberGuardError
    from fastapi import Request
    from fastapi.responses import JSONResponse

    @app.exception_handler(CyberGuardError)
    async def handle(request: Request, exc: CyberGuardError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core.logging import get_correlation_id


# ============================================================================
# ROOT
# ============================================================================

class CyberGuardError(Exception):
    """
    Root of the CyberGuard exception hierarchy.

    Subclasses may override ``status_code`` and ``default_code`` to
    establish category defaults. Individual raise sites can override
    both via constructor arguments.
    """

    # Default HTTP status returned by the API layer
    status_code: ClassVar[int] = 500

    # Default machine-readable code; subclasses usually override
    default_code: ClassVar[str] = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.code: str = code or self.default_code
        self.status_code: int = (
            status_code if status_code is not None else self.status_code
        )
        self.details: dict[str, Any] = dict(details or {})
        self.correlation_id: str | None = get_correlation_id()

        # Preserve the original exception (Python 3.11+ has __cause__ natively
        # via ``raise x from y``, but we also keep an explicit attribute for
        # cases where the raise site uses an async boundary).
        if cause is not None:
            self.__cause__ = cause

    # ── Serialization ──────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        """Serialize for HTTP response body and structured logs."""
        payload: dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            payload["error"]["details"] = _sanitize(self.details)
        if self.correlation_id:
            payload["error"]["correlation_id"] = self.correlation_id
        return payload

    def __repr__(self) -> str:  # pragma: no cover — repr for debugging only
        return (
            f"{self.__class__.__name__}(code={self.code!r}, "
            f"status={self.status_code}, message={self.message!r})"
        )


# ============================================================================
# CATEGORY: CONFIGURATION (fatal at startup)
# ============================================================================

class ConfigurationError(CyberGuardError):
    """Invalid or missing configuration. Should never reach the API layer;
    raised at startup and treated as fatal by ``main.py``."""

    status_code: ClassVar[int] = 500
    default_code: ClassVar[str] = "CONFIGURATION_ERROR"


# ============================================================================
# CATEGORY: AUTHENTICATION (401)
# ============================================================================

class AuthenticationError(CyberGuardError):
    """Caller's identity could not be established."""

    status_code: ClassVar[int] = 401
    default_code: ClassVar[str] = "AUTHENTICATION_REQUIRED"


class InvalidCredentialsError(AuthenticationError):
    """Username/password mismatch or invalid token payload."""

    default_code: ClassVar[str] = "AUTH_INVALID_CREDENTIALS"


class TokenExpiredError(AuthenticationError):
    """JWT or session token has expired."""

    default_code: ClassVar[str] = "AUTH_TOKEN_EXPIRED"


class InvalidTokenError(AuthenticationError):
    """JWT signature invalid, malformed, or wrong algorithm."""

    default_code: ClassVar[str] = "AUTH_INVALID_TOKEN"


class AccountDisabledError(AuthenticationError):
    """User account exists but is disabled, suspended, or unverified."""

    default_code: ClassVar[str] = "AUTH_ACCOUNT_DISABLED"


class MFARequiredError(AuthenticationError):
    """Additional authentication factor required (future use)."""

    status_code: ClassVar[int] = 401
    default_code: ClassVar[str] = "AUTH_MFA_REQUIRED"


# ============================================================================
# CATEGORY: AUTHORIZATION (403)
# ============================================================================

class AuthorizationError(CyberGuardError):
    """Caller is authenticated but not permitted to perform this action."""

    status_code: ClassVar[int] = 403
    default_code: ClassVar[str] = "FORBIDDEN"


class PermissionDeniedError(AuthorizationError):
    """Explicit permission check failed (role, scope, resource grant)."""

    default_code: ClassVar[str] = "PERMISSION_DENIED"


class TenantIsolationError(AuthorizationError):
    """Attempted cross-tenant access. This is a security event and must
    be logged at WARNING or higher by the caller."""

    default_code: ClassVar[str] = "TENANT_ISOLATION_VIOLATION"


class EvidenceAccessDeniedError(AuthorizationError):
    """Access to case evidence was not granted to this caller."""

    default_code: ClassVar[str] = "EVIDENCE_ACCESS_DENIED"


class AnalystNotVerifiedError(AuthorizationError):
    """Analyst attempted to act on a protected resource before verification."""

    default_code: ClassVar[str] = "ANALYST_NOT_VERIFIED"


# ============================================================================
# CATEGORY: NOT FOUND (404)
# ============================================================================

class NotFoundError(CyberGuardError):
    """Requested resource does not exist or is invisible to this tenant."""

    status_code: ClassVar[int] = 404
    default_code: ClassVar[str] = "NOT_FOUND"


class UserNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "USER_NOT_FOUND"


class OrganizationNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "ORGANIZATION_NOT_FOUND"


class WorkspaceNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "WORKSPACE_NOT_FOUND"


class SourceNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "SOURCE_NOT_FOUND"


class EventNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "EVENT_NOT_FOUND"


class FindingNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "FINDING_NOT_FOUND"


class AlertNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "ALERT_NOT_FOUND"


class IncidentNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "INCIDENT_NOT_FOUND"


class CaseNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "CASE_NOT_FOUND"


class ReportNotFoundError(NotFoundError):
    default_code: ClassVar[str] = "REPORT_NOT_FOUND"


# ============================================================================
# CATEGORY: VALIDATION (422)
# ============================================================================

class ValidationError(CyberGuardError):
    """
    Input failed domain validation (not Pydantic schema validation).

    Use this for business-rule validation such as:
        - severity transition not allowed
        - timestamp in the future
        - enrollment token expired
    """

    status_code: ClassVar[int] = 422
    default_code: ClassVar[str] = "VALIDATION_ERROR"


class InvalidInputError(ValidationError):
    default_code: ClassVar[str] = "INVALID_INPUT"


class InvalidStateTransitionError(ValidationError):
    """Attempted a status change that is not permitted by the workflow."""

    default_code: ClassVar[str] = "INVALID_STATE_TRANSITION"


class TokenExpiredValidationError(ValidationError):
    """Domain-level expiry (e.g. enrollment token). Distinct from JWT expiry."""

    default_code: ClassVar[str] = "TOKEN_EXPIRED"


class PayloadTooLargeError(ValidationError):
    """Request body exceeds configured size limit."""

    status_code: ClassVar[int] = 413
    default_code: ClassVar[str] = "PAYLOAD_TOO_LARGE"


# ============================================================================
# CATEGORY: CONFLICT (409)
# ============================================================================

class ConflictError(CyberGuardError):
    """Request conflicts with current state (duplicate, version mismatch)."""

    status_code: ClassVar[int] = 409
    default_code: ClassVar[str] = "CONFLICT"


class DuplicateResourceError(ConflictError):
    default_code: ClassVar[str] = "DUPLICATE_RESOURCE"


class EmailAlreadyExistsError(ConflictError):
    default_code: ClassVar[str] = "EMAIL_ALREADY_EXISTS"


class VersionMismatchError(ConflictError):
    default_code: ClassVar[str] = "VERSION_MISMATCH"


# ============================================================================
# CATEGORY: RATE LIMITING (429)
# ============================================================================

class RateLimitError(CyberGuardError):
    """Caller exceeded the configured rate limit."""

    status_code: ClassVar[int] = 429
    default_code: ClassVar[str] = "RATE_LIMITED"


# ============================================================================
# CATEGORY: DATABASE (500)
# ============================================================================

class DatabaseError(CyberGuardError):
    """
    Persistence-layer failure. Never expose raw SQL errors to clients;
    pass a safe message and log the original exception via ``cause``.
    """

    status_code: ClassVar[int] = 500
    default_code: ClassVar[str] = "DATABASE_ERROR"


class IntegrityViolationError(DatabaseError):
    """FK/unique/check constraint violation detected post-commit attempt."""

    status_code: ClassVar[int] = 409
    default_code: ClassVar[str] = "INTEGRITY_VIOLATION"


# ============================================================================
# CATEGORY: EXTERNAL SERVICES (502 / 503)
# ============================================================================

class ExternalServiceError(CyberGuardError):
    """A third-party API (threat intel, LLM) failed or is unavailable."""

    status_code: ClassVar[int] = 502
    default_code: ClassVar[str] = "EXTERNAL_SERVICE_ERROR"


class ServiceUnavailableError(ExternalServiceError):
    """Third-party service is down or unreachable."""

    status_code: ClassVar[int] = 503
    default_code: ClassVar[str] = "SERVICE_UNAVAILABLE"


class ServiceTimeoutError(ExternalServiceError):
    """Third-party service did not respond within the configured timeout."""

    status_code: ClassVar[int] = 504
    default_code: ClassVar[str] = "SERVICE_TIMEOUT"


class RateLimitedByProviderError(ExternalServiceError):
    """Third-party provider rejected the request due to its own rate limit."""

    status_code: ClassVar[int] = 429
    default_code: ClassVar[str] = "PROVIDER_RATE_LIMITED"


# ============================================================================
# CATEGORY: AGENTS (500)
# ============================================================================

class AgentError(CyberGuardError):
    """An agent failed to process its input. Includes the agent name."""

    status_code: ClassVar[int] = 500
    default_code: ClassVar[str] = "AGENT_ERROR"


class AgentNotRegisteredError(AgentError):
    default_code: ClassVar[str] = "AGENT_NOT_REGISTERED"


class AgentTimeoutError(AgentError):
    status_code: ClassVar[int] = 504
    default_code: ClassVar[str] = "AGENT_TIMEOUT"


class AgentInputError(AgentError):
    """Agent received structurally invalid input."""

    status_code: ClassVar[int] = 422
    default_code: ClassVar[str] = "AGENT_INPUT_ERROR"


# ============================================================================
# CATEGORY: COLLECTORS (400 / 403)
# ============================================================================

class CollectorError(CyberGuardError):
    """Collector/device protocol error."""

    status_code: ClassVar[int] = 400
    default_code: ClassVar[str] = "COLLECTOR_ERROR"


class CollectorAuthError(CollectorError):
    """Collector credential invalid, revoked, or malformed."""

    status_code: ClassVar[int] = 401
    default_code: ClassVar[str] = "COLLECTOR_AUTH_ERROR"


class CollectorRevokedError(CollectorError):
    """Collector credential was explicitly revoked."""

    status_code: ClassVar[int] = 403
    default_code: ClassVar[str] = "COLLECTOR_REVOKED"


class EnrollmentTokenInvalidError(CollectorError):
    """Enrollment token is invalid, already used, or expired."""

    status_code: ClassVar[int] = 400
    default_code: ClassVar[str] = "ENROLLMENT_TOKEN_INVALID"


class SourceDisabledError(CollectorError):
    """Source is disabled; ingestion must stop."""

    status_code: ClassVar[int] = 403
    default_code: ClassVar[str] = "SOURCE_DISABLED"


# ============================================================================
# HELPERS
# ============================================================================

def _sanitize(value: Any, depth: int = 0) -> Any:
    """
    Make ``details`` safe to log and return. Recursively converts non-JSON
    primitives to strings and caps recursion depth. Assumes the caller has
    already excluded real secrets from ``details`` (the API layer redacts
    sensitive keys via ``RedactionFilter`` in logging).
    """
    if depth > 5:
        return str(value)

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _sanitize(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(v, depth + 1) for v in value]

    # Fallback for UUIDs, datetimes, enums, etc.
    try:
        return str(value)
    except Exception:
        return "<unserializable>"


__all__ = [
    # Root
    "CyberGuardError",
    # Configuration
    "ConfigurationError",
    # Authentication
    "AuthenticationError",
    "InvalidCredentialsError",
    "TokenExpiredError",
    "InvalidTokenError",
    "AccountDisabledError",
    "MFARequiredError",
    # Authorization
    "AuthorizationError",
    "PermissionDeniedError",
    "TenantIsolationError",
    "EvidenceAccessDeniedError",
    "AnalystNotVerifiedError",
    # Not Found
    "NotFoundError",
    "UserNotFoundError",
    "OrganizationNotFoundError",
    "WorkspaceNotFoundError",
    "SourceNotFoundError",
    "EventNotFoundError",
    "FindingNotFoundError",
    "AlertNotFoundError",
    "IncidentNotFoundError",
    "CaseNotFoundError",
    "ReportNotFoundError",
    # Validation
    "ValidationError",
    "InvalidInputError",
    "InvalidStateTransitionError",
    "TokenExpiredValidationError",
    "PayloadTooLargeError",
    # Conflict
    "ConflictError",
    "DuplicateResourceError",
    "EmailAlreadyExistsError",
    "VersionMismatchError",
    # Rate limit
    "RateLimitError",
    # Database
    "DatabaseError",
    "IntegrityViolationError",
    # External
    "ExternalServiceError",
    "ServiceUnavailableError",
    "ServiceTimeoutError",
    "RateLimitedByProviderError",
    # Agents
    "AgentError",
    "AgentNotRegisteredError",
    "AgentTimeoutError",
    "AgentInputError",
    # Collectors
    "CollectorError",
    "CollectorAuthError",
    "CollectorRevokedError",
    "EnrollmentTokenInvalidError",
    "SourceDisabledError",
]