"""
CyberGuard AI - Safe Error Messages

Maps internal error messages to user-safe messages that don't expose
sensitive implementation details, API keys, or system information.
"""

import re
from typing import Optional

# Mapping of internal error patterns to safe user-facing messages
_ERROR_MESSAGE_PATTERNS: list[tuple[str, str]] = [
    # Database errors
    (r"database connection failed", "Service temporarily unavailable"),
    (r"db connection refused", "Service temporarily unavailable"),
    (r"postgres.*error", "Service temporarily unavailable"),
    (r"mysql.*error", "Service temporarily unavailable"),
    (r"connection pool exhausted", "Service temporarily unavailable"),
    (r"database timeout", "Service temporarily unavailable"),

    # Redis errors
    (r"redis connection refused", "Service temporarily unavailable"),
    (r"redis.*error", "Service temporarily unavailable"),
    (r"cache.*unavailable", "Service temporarily unavailable"),
    (r"redis timeout", "Service temporarily unavailable"),

    # External API errors
    (r"virustotal api error", "Threat intelligence check unavailable"),
    (r"virustotal.*timeout", "Threat intelligence check unavailable"),
    (r"virustotal.*rate limit", "Threat intelligence check temporarily unavailable"),
    (r"safe browsing.*error", "URL safety check unavailable"),
    (r"safe browsing.*timeout", "URL safety check unavailable"),
    (r"abuseipdb.*error", "IP reputation check unavailable"),
    (r"external service.*unavailable", "External service temporarily unavailable"),
    (r"api key.*invalid", "Service configuration error"),
    (r"api key.*expired", "Service configuration error"),
    (r"unauthorized.*api", "Service configuration error"),

    # Email authentication errors
    (r"dkim verification failed", "Email authentication could not be verified"),
    (r"spf verification failed", "Email authentication could not be verified"),
    (r"dmarc verification failed", "Email authentication could not be verified"),
    (r"dns.*timeout", "Email authentication could not be verified"),
    (r"dns.*lookup.*failed", "Email authentication could not be verified"),

    # ML model errors
    (r"model not loaded", "Analysis service initializing"),
    (r"model.*unavailable", "Analysis service initializing"),
    (r"classifier.*error", "Analysis service temporarily unavailable"),
    (r"prediction.*failed", "Analysis service temporarily unavailable"),

    # File/attachment errors
    (r"file.*too large", "File exceeds size limit"),
    (r"unsupported file type", "File type not supported"),
    (r"file.*corrupted", "File could not be processed"),
    (r"archive.*extraction.*failed", "Archive could not be processed"),

    # Authentication errors
    (r"token.*expired", "Session expired, please log in again"),
    (r"token.*invalid", "Authentication failed"),
    (r"jwt.*error", "Authentication failed"),
    (r"firebase.*error", "Authentication service unavailable"),

    # Network errors
    (r"connection.*refused", "Service temporarily unavailable"),
    (r"connection.*timeout", "Service temporarily unavailable"),
    (r"network.*unreachable", "Service temporarily unavailable"),
    (r"ssl.*error", "Secure connection failed"),

    # Circuit breaker
    (r"circuit.*open", "Service temporarily unavailable"),
    (r"circuit breaker", "Service temporarily unavailable"),
]

# Default safe message for unmatched errors
_DEFAULT_SAFE_MESSAGE = "An error occurred during processing"


def get_safe_message(error: str) -> str:
    """
    Convert an internal error message to a safe user-facing message.

    Args:
        error: The internal error message or exception string

    Returns:
        A safe message that doesn't expose sensitive details

    Example:
        >>> get_safe_message("database connection failed: postgres://user:pass@host")
        "Service temporarily unavailable"

        >>> get_safe_message("virustotal api error: 401 Unauthorized")
        "Threat intelligence check unavailable"
    """
    if not error:
        return _DEFAULT_SAFE_MESSAGE

    error_lower = error.lower()

    for pattern, safe_message in _ERROR_MESSAGE_PATTERNS:
        if re.search(pattern, error_lower, re.IGNORECASE):
            return safe_message

    return _DEFAULT_SAFE_MESSAGE


def sanitize_error_detail(detail: Optional[str], debug: bool = False) -> Optional[str]:
    """
    Sanitize error detail for API response.

    In production (debug=False), returns None to hide internal details.
    In debug mode, returns the detail but strips sensitive patterns.

    Args:
        detail: The error detail string
        debug: Whether debug mode is enabled

    Returns:
        Sanitized detail or None
    """
    if not detail:
        return None

    if not debug:
        return None

    # Even in debug mode, strip certain sensitive patterns
    sensitive_patterns = [
        (r"password[=:]\s*\S+", "password=***"),
        (r"api[_-]?key[=:]\s*\S+", "api_key=***"),
        (r"token[=:]\s*\S+", "token=***"),
        (r"secret[=:]\s*\S+", "secret=***"),
        (r"authorization:\s*bearer\s+\S+", "authorization: bearer ***"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[email]"),
    ]

    sanitized = detail
    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized
