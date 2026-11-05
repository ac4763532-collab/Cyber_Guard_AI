"""URL reputation analysis using the existing threat-intelligence service."""

from __future__ import annotations

import hashlib

from app.cache.redis_client import get_redis_client
from app.services.threat_intel.service import IOCType, ThreatIntelService


CACHE_TTL = 3600


def _cache_key(url: str) -> str:
    """Create a stable Redis key for a URL reputation result."""
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"url_reputation:{digest}"


async def check_url_reputation(url: str) -> dict:
    """Check a URL against the configured threat-intelligence sources."""
    if not isinstance(url, str) or not url.strip():
        return {
            "configured": False,
            "url": url,
            "status": "unknown",
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "details": {},
            "error": "Invalid URL",
            "cache_hit": False,
        }

    url = url.strip()
    cache_key = _cache_key(url)

    # Try Redis cache first.
    redis_client = None

    try:
        redis_client = await get_redis_client()
        cached = await redis_client.get_json(cache_key)

        if cached is not None:
            cached["cache_hit"] = True
            return cached
    except Exception:
        redis_client = None

    service = ThreatIntelService()

    if not service.is_configured:
        return {
            "configured": False,
            "url": url,
            "status": "unknown",
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "details": {},
            "error": None,
            "cache_hit": False,
        }

    try:
        result = await service.lookup(IOCType.URL, url)

        vt = result.details.get("virustotal", {})

        malicious_count = int(vt.get("malicious_count", 0))
        suspicious_count = int(vt.get("suspicious_count", 0))

        if result.is_malicious or malicious_count > 0:
            status = "malicious"
        elif suspicious_count > 0:
            status = "suspicious"
        elif result.sources:
            status = "clean"
        else:
            status = "unknown"

        response = {
            "configured": True,
            "url": url,
            "status": status,
            "is_malicious": result.is_malicious,
            "risk_score": result.risk_score,
            "sources": result.sources,
            "details": result.details,
            "error": result.error,
            "cache_hit": False,
        }

        # Store reputation result in Redis for 1 hour.
        if redis_client is not None:
            try:
                await redis_client.set_json(
                    cache_key,
                    response,
                    ttl=CACHE_TTL,
                )
            except Exception:
                pass

        return response

    except Exception as exc:
        return {
            "configured": True,
            "url": url,
            "status": "unknown",
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "details": {},
            "error": str(exc),
            "cache_hit": False,
        }
