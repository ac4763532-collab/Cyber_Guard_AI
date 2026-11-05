"""Google Safe Browsing URL reputation service."""

from __future__ import annotations

import hashlib

import httpx
import structlog

from app.cache.redis_client import get_redis_client
from app.config import get_settings
from app.services.rate_limiting import get_rate_limiter


logger = structlog.get_logger(__name__)

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
]

CACHE_TTL = 300


def _cache_key(urls: list[str]) -> str:
    """Create a stable Redis key for a URL set."""
    normalized = sorted(
        {
            url.strip()
            for url in urls
            if isinstance(url, str) and url.strip()
        }
    )
    digest = hashlib.sha256(
        "|".join(normalized).encode("utf-8")
    ).hexdigest()
    return f"safe_browsing:{digest}"


async def check_urls(urls: list[str]) -> dict:
    """
    Check URLs against Google Safe Browsing.

    Results are cached in Redis for 5 minutes.
    When no API key is configured, the service safely skips
    the external lookup.

    Daily rate limit: 8000 requests/day (configurable).
    """
    settings = get_settings()
    api_key = settings.google_safe_browsing_api_key

    if not api_key:
        return {
            "configured": False,
            "checked": 0,
            "threats": [],
            "error": None,
            "cache_hit": False,
        }

    valid_urls = [
        url.strip()
        for url in urls
        if isinstance(url, str) and url.strip()
    ]

    if not valid_urls:
        return {
            "configured": True,
            "checked": 0,
            "threats": [],
            "error": None,
            "cache_hit": False,
        }

    # Try Redis cache before calling Google.
    redis_client = None
    cache_key = _cache_key(valid_urls)

    try:
        redis_client = await get_redis_client()
        cached = await redis_client.get_json(cache_key)

        if cached is not None:
            cached["cache_hit"] = True
            return cached
    except Exception:
        redis_client = None

    # Check daily rate limit before making API call
    rate_limiter = get_rate_limiter()
    daily_allowed = await rate_limiter.check_daily_limit(
        key="external:safe_browsing",
        daily_limit=settings.external_safe_browsing_daily_limit,
    )

    if not daily_allowed:
        logger.warning(
            "Safe Browsing daily limit exceeded",
            daily_limit=settings.external_safe_browsing_daily_limit,
        )
        return {
            "configured": True,
            "checked": 0,
            "threats": [],
            "error": "Daily API limit exceeded",
            "cache_hit": False,
            "rate_limited": True,
        }

    payload = {
        "client": {
            "clientId": "cyberguard-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
                for url in valid_urls
            ],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                SAFE_BROWSING_URL,
                params={"key": api_key},
                json=payload,
            )

            response.raise_for_status()
            data = response.json()

        threats = []

        for match in data.get("matches", []):
            threat = {
                "url": match.get("threat", {}).get("url"),
                "threat_type": match.get("threatType"),
                "platform_type": match.get("platformType"),
                "cache_duration": match.get("cacheDuration"),
            }
            threats.append(threat)

        result = {
            "configured": True,
            "checked": len(valid_urls),
            "threats": threats,
            "error": None,
            "cache_hit": False,
        }

        if redis_client is not None:
            try:
                await redis_client.set_json(
                    cache_key,
                    result,
                    ttl=CACHE_TTL,
                )
            except Exception:
                pass

        return result

    except httpx.TimeoutException:
        return {
            "configured": True,
            "checked": len(valid_urls),
            "threats": [],
            "error": "Google Safe Browsing request timed out",
            "cache_hit": False,
        }

    except httpx.HTTPStatusError as exc:
        return {
            "configured": True,
            "checked": len(valid_urls),
            "threats": [],
            "error": (
                "Google Safe Browsing API returned "
                f"HTTP {exc.response.status_code}"
            ),
            "cache_hit": False,
        }

    except Exception as exc:
        return {
            "configured": True,
            "checked": len(valid_urls),
            "threats": [],
            "error": str(exc),
            "cache_hit": False,
        }
