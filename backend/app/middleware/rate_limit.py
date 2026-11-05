"""CyberGuard AI - API Rate Limiting."""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings


def _get_limiter_storage_uri() -> str:
    """Get Redis URI for rate limiter storage."""
    settings = get_settings()
    return settings.redis_url


# Redis-backed application-wide rate limiter.
# Client IP address is used as the rate-limit key.
limiter = Limiter(
    key_func=get_remote_address,
    headers_enabled=True,
    retry_after="Retry-After",
    storage_uri=_get_limiter_storage_uri(),
    default_limits=["1000/minute"],  # Global limit
)


# Rate limit constants for use in decorators
# These are defined here so endpoints can import them
RATE_LIMIT_EMAIL_ANALYSIS = "30/minute"
RATE_LIMIT_GMAIL = "60/minute"
RATE_LIMIT_GET = "100/minute"
RATE_LIMIT_DEFAULT = "100/minute"
RATE_LIMIT_GLOBAL = "1000/minute"

# Actions that start/stop a real embedded collector or open a real
# connection to an external system (SSH host, adb device, Windows event
# log) - kept tighter than RATE_LIMIT_DEFAULT since each call can do
# real, possibly slow, outbound work.
RATE_LIMIT_COLLECTOR_ACTION = "20/minute"

# Active nmap port scans are heavier than a simple lookup and can generate
# real outbound network traffic against the target - kept tighter than
# RATE_LIMIT_COLLECTOR_ACTION.
RATE_LIMIT_NETWORK_SCAN = "10/minute"
