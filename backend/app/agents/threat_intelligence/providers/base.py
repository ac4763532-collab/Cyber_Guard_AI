"""
CyberGuard AI — Threat Intelligence Provider Base
============================================================================

The abstract base for every external threat-intel provider.

Every provider subclasses ``ThreatIntelProvider``, sets three class
attributes (``name``, ``requires_api_key``, ``_default_rate_limit_rpm``),
and implements whichever ``lookup_*`` methods it supports. Unsupported
methods inherit the base's implementation, which returns ``None``.

Resilience contract
-------------------
Every provider call is best-effort. The contract is:

    - Never raise
    - Return a ``ProviderResult`` on success
    - Return ``None`` on: no API key, rate limit exceeded, HTTP error,
      timeout, malformed response

The agent that calls providers treats ``None`` as "unknown" — it does
not distinguish between "we asked and the answer was negative" and
"we couldn't ask". Only successful results produce findings.

Rate limiting
-------------
Each provider enforces its own rate limit via an in-memory token bucket.
The bucket refills continuously based on wall-clock time. When empty,
calls return ``None`` immediately (fail-fast, no blocking).

This is a **per-process** limit. If the runtime runs in multiple
processes, the effective rate is N × the configured rate. For MVP with
a single-process runtime, this is correct. Multi-process rate limiting
requires a shared store (Redis) — Phase 13 enhancement.

Caching
-------
Successful results are cached in Redis (if ``REDIS_URL`` is set) with
a 1-hour default TTL. Cache key: ``ti:<provider>:<type>:<indicator>``.

Why cache:
    - Providers charge per request (VirusTotal free tier: 4 req/min)
    - The same IOC appears across many events (one malicious IP may
      appear in 100 events in an hour)
    - Cache converts 100 API calls to 1 + 99 cache hits

Cache failures are silent — if Redis is down, providers still work,
just without caching. No correctness impact, only cost.

ProviderResult shape
--------------------
Every successful lookup returns:

    provider      str    — provider name ("virustotal", "abuseipdb", ...)
    indicator     str    — the IOC that was looked up
    indicator_type str   — "ip" | "domain" | "url" | "hash" | "cve"
    malicious     bool   — provider's verdict
    score         int    — 0-100 normalized risk score
    confidence    float  — 0.0-1.0 (how much we trust this provider's verdict)
    details       str    — human-readable summary
    raw           dict   — provider's full response (for evidence)

The ``score`` and ``confidence`` fields allow the agent to combine
multiple providers intelligently:
    - High score + high confidence = definitely malicious
    - High score + low confidence = suspicious (skip)
    - Multiple providers agree = raise confidence
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger


logger = get_logger(__name__)


# ============================================================================
# RESULT DTO
# ============================================================================

@dataclass(frozen=True)
class ProviderResult:
    """
    A single provider's verdict on one IOC.

    Returned by every ``lookup_*`` method on success. Absence of a
    return (i.e. ``None``) means the provider couldn't answer — not
    that the IOC is safe.
    """
    provider: str
    indicator: str
    indicator_type: str
    malicious: bool
    score: int                          # 0-100
    confidence: float                   # 0.0-1.0
    details: str
    raw: dict[str, Any] = field(default_factory=dict)

    def to_evidence_dict(self) -> dict[str, Any]:
        """Compact dict for embedding in a finding's evidence JSONB."""
        return {
            "provider": self.provider,
            "score": self.score,
            "malicious": self.malicious,
            "confidence": round(self.confidence, 2),
            "details": self.details[:300],
        }


# ============================================================================
# TOKEN BUCKET
# ============================================================================

class _TokenBucket:
    """
    Simple in-memory token bucket for rate limiting.

    Capacity = rate limit (e.g. 4 tokens for 4 requests/min).
    Refill rate = capacity / 60 per second.

    Thread-safe via a lock. Non-blocking: ``acquire()`` returns False
    immediately if no token is available.
    """

    def __init__(self, capacity: int, refill_per_second: float) -> None:
        self._capacity = float(capacity)
        self._refill_rate = refill_per_second
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_rate,
            )
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


# ============================================================================
# REDIS CLIENT (lazy global)
# ============================================================================
# The Redis client is created once per process the first time a
# provider tries to use the cache. If REDIS_URL isn't set, or the
# connection fails, all cache operations become no-ops.

_redis_client: Any = None
_redis_init_lock = threading.Lock()
_redis_available: bool | None = None


def _get_redis_client():
    """Return a cached Redis client, or None if Redis is unavailable."""
    global _redis_client, _redis_available

    if _redis_available is False:
        return None
    if _redis_client is not None:
        return _redis_client

    with _redis_init_lock:
        if _redis_available is False:
            return None
        if _redis_client is not None:
            return _redis_client

        try:
            from app.core.config import settings
            redis_url = settings.REDIS_URL
            if not redis_url:
                _redis_available = False
                return None

            import redis as redis_lib
            client = redis_lib.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
            client.ping()   # verify connection
            _redis_client = client
            _redis_available = True
            logger.info("Threat intel cache: Redis available")
            return client
        except Exception as exc:
            _redis_available = False
            logger.info(
                "Threat intel cache: Redis unavailable (cache disabled)",
                extra={"error": str(exc)[:150]},
            )
            return None


# ============================================================================
# BASE PROVIDER
# ============================================================================

class ThreatIntelProvider:
    """
    Abstract base for threat intel providers.

    Subclasses set:
        name (str)                         — provider identifier
        requires_api_key (bool)            — True if API key is mandatory
        _default_rate_limit_rpm (int)      — rate limit in requests/min

    Subclasses may override:
        _cache_ttl_seconds (int)           — cache lifetime (default 3600)
        _http_timeout_seconds (float)      — per-request timeout (default 10)
        _user_agent (str)                  — HTTP User-Agent header

    Subclasses must implement at least one of the ``lookup_*`` methods.
    The base implementations return ``None`` — used to model "not
    supported" for providers that don't cover every IOC type.
    """

    # Class configuration — subclasses override
    name: str = ""
    requires_api_key: bool = False
    _default_rate_limit_rpm: int = 30

    # Defaults — subclasses may override
    _cache_ttl_seconds: int = 3600
    _http_timeout_seconds: float = 10.0
    _user_agent: str = "CyberGuard-AI/0.1 (threat-intel)"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        rate_limit_rpm: int | None = None,
    ) -> None:
        self._api_key: str | None = api_key or None
        effective_rpm = rate_limit_rpm or self._default_rate_limit_rpm
        self._bucket = _TokenBucket(
            capacity=effective_rpm,
            refill_per_second=effective_rpm / 60.0,
        )
        self._logger = get_logger(f"app.agents.threat_intelligence.{self.name}")

    # ── Availability ──────────────────────────────────────────────────

    @property
    def is_enabled(self) -> bool:
        """
        True if this provider is available for lookups.

        For API-key providers, requires a non-empty key. For free
        providers (URLhaus, NVD, MITRE), always True unless the
        subclass overrides.
        """
        if self.requires_api_key and not self._api_key:
            return False
        return True

    # ── Lookup interface (overridden by subclasses) ───────────────────

    def lookup_ip(self, ip: str) -> ProviderResult | None:
        """Look up an IP address. Base impl returns None (not supported)."""
        return None

    def lookup_domain(self, domain: str) -> ProviderResult | None:
        """Look up a domain. Base impl returns None (not supported)."""
        return None

    def lookup_url(self, url: str) -> ProviderResult | None:
        """Look up a URL. Base impl returns None (not supported)."""
        return None

    def lookup_hash(self, hash_value: str) -> ProviderResult | None:
        """Look up a file hash (MD5/SHA1/SHA256). Base: not supported."""
        return None

    def lookup_cve(self, cve_id: str) -> ProviderResult | None:
        """Look up a CVE. Base impl returns None (not supported)."""
        return None

    # ── Caching ────────────────────────────────────────────────────────

    def _cache_key(self, indicator_type: str, indicator: str) -> str:
        return f"ti:{self.name}:{indicator_type}:{indicator.lower().strip()}"

    def _cache_get(self, key: str) -> ProviderResult | None:
        """Return cached result or None. Never raises."""
        client = _get_redis_client()
        if client is None:
            return None
        try:
            raw = client.get(key)
            if raw is None:
                return None
            import json
            data = json.loads(raw)
            return ProviderResult(
                provider=data["provider"],
                indicator=data["indicator"],
                indicator_type=data["indicator_type"],
                malicious=data["malicious"],
                score=data["score"],
                confidence=data["confidence"],
                details=data["details"],
                raw=data.get("raw", {}),
            )
        except Exception:  # noqa: BLE001 — cache failures are silent
            return None

    def _cache_set(self, key: str, result: ProviderResult) -> None:
        """Write result to cache. Never raises."""
        client = _get_redis_client()
        if client is None:
            return
        try:
            import json
            payload = {
                "provider": result.provider,
                "indicator": result.indicator,
                "indicator_type": result.indicator_type,
                "malicious": result.malicious,
                "score": result.score,
                "confidence": result.confidence,
                "details": result.details,
                "raw": result.raw,
            }
            client.setex(key, self._cache_ttl_seconds, json.dumps(payload))
        except Exception:  # noqa: BLE001
            pass

    # ── Rate limiting ─────────────────────────────────────────────────

    def _acquire_token(self) -> bool:
        """Try to acquire a rate-limit token. Non-blocking."""
        return self._bucket.acquire()

    # ── HTTP helper ───────────────────────────────────────────────────

    def _http_get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Perform a GET request. Return parsed JSON dict on success,
        None on any failure.

        Logs failures at WARNING with the provider name, status code,
        and URL (masked to just the path — no query string, in case
        the query string contains an API key).
        """
        try:
            import httpx
            merged_headers = {
                "Accept": "application/json",
                "User-Agent": self._user_agent,
            }
            if headers:
                merged_headers.update(headers)

            with httpx.Client(timeout=self._http_timeout_seconds) as client:
                response = client.get(url, headers=merged_headers, params=params)

            if response.status_code == 429:
                self._logger.warning(
                    "Provider rate-limited",
                    extra={"provider": self.name, "status": 429},
                )
                return None

            if response.status_code == 404:
                # Not found is a valid response — return empty dict
                # so the caller can distinguish from "provider down".
                return {}

            if response.status_code >= 400:
                self._logger.warning(
                    "Provider HTTP error",
                    extra={
                        "provider": self.name,
                        "status": response.status_code,
                    },
                )
                return None

            return response.json()

        except Exception as exc:  # noqa: BLE001 — network failures are silent
            self._logger.warning(
                "Provider request failed",
                extra={
                    "provider": self.name,
                    "error": str(exc)[:200],
                },
            )
            return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ProviderResult",
    "ThreatIntelProvider",
]