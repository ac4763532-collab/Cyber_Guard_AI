"""
CyberGuard AI - Core Module

Email analysis enums, domain utilities, shared constants, and error handling.
"""

from app.core.errors import (
    ErrorCode,
    ErrorResponse,
    CyberGuardError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ExternalServiceError,
    AnalysisError,
    HTTP_STATUS_TO_ERROR_CODE,
    get_error_code_for_status,
)

from app.core.retry import (
    retry_async,
    with_timeout,
    RetryableError,
    TRANSIENT_EXCEPTIONS,
)

from app.core.error_messages import (
    get_safe_message,
    sanitize_error_detail,
)

from app.core.email_enums import (
    URLCategory,
    AnalysisStatus,
    Verdict,
    BrandDetectionType,
    AuthResult,
    URL_SHORTENER_DOMAINS,
    CDN_DOMAINS,
    TRACKING_DOMAINS,
    AUTH_DOMAINS,
    SUSPICIOUS_TLDS,
    IMPERSONATED_BRANDS,
    LEGITIMATE_BRAND_DOMAINS,
    DOMAIN_TO_BRAND,
    UNSUBSCRIBE_PATTERNS,
)

from app.core.domain_utils import (
    DomainInfo,
    extract_domain_info,
    is_suspicious_tld,
    get_domain_brand,
    is_legitimate_brand_domain,
    classify_url,
    is_url_shortener,
)

__all__ = [
    # Error handling
    "ErrorCode",
    "ErrorResponse",
    "CyberGuardError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ExternalServiceError",
    "AnalysisError",
    "HTTP_STATUS_TO_ERROR_CODE",
    "get_error_code_for_status",
    # Retry utilities
    "retry_async",
    "with_timeout",
    "RetryableError",
    "TRANSIENT_EXCEPTIONS",
    # Safe error messages
    "get_safe_message",
    "sanitize_error_detail",
    # Enums
    "URLCategory",
    "AnalysisStatus",
    "Verdict",
    "BrandDetectionType",
    "AuthResult",
    # Constants
    "URL_SHORTENER_DOMAINS",
    "CDN_DOMAINS",
    "TRACKING_DOMAINS",
    "AUTH_DOMAINS",
    "SUSPICIOUS_TLDS",
    "IMPERSONATED_BRANDS",
    "LEGITIMATE_BRAND_DOMAINS",
    "DOMAIN_TO_BRAND",
    "UNSUBSCRIBE_PATTERNS",
    # Domain utilities
    "DomainInfo",
    "extract_domain_info",
    "is_suspicious_tld",
    "get_domain_brand",
    "is_legitimate_brand_domain",
    "classify_url",
    "is_url_shortener",
]
