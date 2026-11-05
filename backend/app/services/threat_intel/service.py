"""
CyberGuard AI - Threat Intelligence Service

Provides IOC enrichment via external threat intelligence APIs:
- VirusTotal: URL, domain, IP, file hash reputation
- AbuseIPDB: IP abuse reports

Security:
- API keys stored server-side only
- Results cached to reduce API calls (Redis + local memory)
- Rate limiting respected
- Circuit breaker for resilience
"""

import asyncio
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Any
from functools import lru_cache
from urllib.parse import urlsplit

import httpx
from redis.asyncio import Redis
from pydantic import BaseModel, Field
import structlog

from app.config import get_settings
from app.services.rate_limiting import get_rate_limiter, RateLimitExceeded
from app.services.circuit_breaker import get_circuit_breaker, CircuitOpenError


logger = structlog.get_logger(__name__)


# =============================================================================
# Models
# =============================================================================

class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class ProviderCheckStatus(str, Enum):
    """
    The actual execution outcome of a single provider's request - distinct
    from the reputation verdict. A provider that errored contributed zero
    evidence and must never be conflated with a provider that ran
    successfully and found nothing.
    """
    SUCCESS = "success"
    TIMEOUT = "timeout"
    AUTH_ERROR = "auth_error"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"  # circuit open, transport/connection error, 5xx
    NOT_CONFIGURED = "not_configured"


class ReputationStatus(str, Enum):
    """
    Final reputation classification. Kept separate from each provider's
    ProviderCheckStatus so a failed/timed-out/unauthenticated check can
    never be reported as "checked and found clean".

    Classification policy (documented here as the single source of truth -
    see `_classify` below for the implementation):
      - MALICIOUS: at least one configured provider completed successfully
        (ProviderCheckStatus.SUCCESS) and its data met that provider's
        malicious threshold (VirusTotal: malicious_count > 0; AbuseIPDB:
        abuse_confidence_score >= SUSPICIOUS_ABUSE_SCORE_THRESHOLD, i.e. 50).
      - SUSPICIOUS: no provider met the malicious threshold, but at least
        one successful provider met a lower suspicious threshold
        (AbuseIPDB: 1 <= abuse_confidence_score < 50, or VirusTotal:
        suspicious_count > 0 with malicious_count == 0).
      - CLEAN: every configured, attempted provider completed successfully
        (ProviderCheckStatus.SUCCESS) and none met the suspicious or
        malicious threshold. Requires at least one successful provider.
      - LOOKUP_FAILED: at least one configured provider was attempted but
        did not complete successfully (timeout/auth_error/rate_limited/
        unavailable), AND no other provider's successful result alone
        reached MALICIOUS/SUSPICIOUS. A partial failure can never produce
        CLEAN - at best it produces whatever a surviving successful
        provider's own evidence supports, otherwise LOOKUP_FAILED.
      - UNKNOWN: no provider is configured for this IOC type (nothing was
        attempted at all), so there is no evidence either way.
    """
    MALICIOUS = "malicious"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    LOOKUP_FAILED = "lookup_failed"


# AbuseIPDB confidence-score thresholds (0-100 scale from the provider).
ABUSE_SCORE_MALICIOUS_THRESHOLD = 50
ABUSE_SCORE_SUSPICIOUS_THRESHOLD = 1


class ProviderOutcome(BaseModel):
    """Per-provider execution record, always present for every provider
    that was attempted (configured + applicable to the IOC type) - this is
    what lets the UI say "VirusTotal: timed out, AbuseIPDB: success"
    instead of silently losing a failed provider's row entirely."""
    name: str
    status: ProviderCheckStatus
    detections: Optional[int] = None
    suspicious_detections: Optional[int] = None
    confidence_score: Optional[int] = None
    data_available: bool = False
    last_analysis_at: Optional[str] = None
    detail: Optional[str] = None


class ThreatIntelResult(BaseModel):
    """Result from threat intelligence lookup."""
    ioc_type: IOCType
    ioc_value: str
    reputation_status: ReputationStatus = ReputationStatus.UNKNOWN
    classification_reason: str = "No threat intelligence sources were queried for this indicator."
    # Deprecated boolean mirror of reputation_status, kept only for any
    # existing caller that reads `.is_malicious` directly. New code should
    # read `reputation_status` instead - this is never used to derive
    # reputation_status (it's derived the other way around).
    is_malicious: Optional[bool] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    sources: list[str] = Field(default_factory=list)
    provider_outcomes: list[ProviderOutcome] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False
    lookup_time_ms: int = 0
    error: Optional[str] = None


class VirusTotalResult(BaseModel):
    """Parsed VirusTotal API result."""
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    reputation: int = 0
    categories: list[str] = Field(default_factory=list)
    last_analysis_date: Optional[datetime] = None


class AbuseIPDBResult(BaseModel):
    """Parsed AbuseIPDB API result."""
    abuse_confidence_score: int = 0
    total_reports: int = 0
    is_public: bool = True
    is_tor: bool = False
    isp: str = ""
    country_code: str = ""
    last_reported_at: Optional[datetime] = None


# =============================================================================
# Threat Intelligence Service
# =============================================================================

class ThreatIntelService:
    """
    Threat Intelligence Service for IOC enrichment.

    Integrates with:
    - VirusTotal API v3
    - AbuseIPDB API v2

    Features:
    - Two-tier caching (local memory + Redis)
    - Rate limiting per external API
    - Circuit breaker for resilience
    """

    VT_BASE_URL = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

    # Cache TTL (defaults, overridden by settings)
    CACHE_TTL_SECONDS = 3600  # 1 hour

    def __init__(self):
        self.settings = get_settings()
        self._cache: dict[str, tuple[ThreatIntelResult, datetime]] = {}
        self._redis: Redis | None = None
        try:
            self._redis = Redis.from_url(
                self.settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
        except Exception as exc:
            logger.warning('Redis cache initialization failed', error=str(exc))

        # Check API configuration
        self._vt_enabled = bool(self.settings.virustotal_api_key)
        self._abuseipdb_enabled = bool(self.settings.abuseipdb_api_key)

        if not self._vt_enabled:
            logger.warning("VirusTotal API key not configured")
        if not self._abuseipdb_enabled:
            logger.warning("AbuseIPDB API key not configured")

        # Rate limiters
        self._rate_limiter = get_rate_limiter()

        # Circuit breakers
        self._vt_circuit = get_circuit_breaker(
            "virustotal",
            failure_threshold=self.settings.external_circuit_failure_threshold,
            recovery_timeout_seconds=self.settings.external_circuit_recovery_seconds,
        )
        self._abuseipdb_circuit = get_circuit_breaker(
            "abuseipdb",
            failure_threshold=self.settings.external_circuit_failure_threshold,
            recovery_timeout_seconds=self.settings.external_circuit_recovery_seconds,
        )

    @property
    def is_configured(self) -> bool:
        """Check if at least one threat intel source is configured."""
        return self._vt_enabled or self._abuseipdb_enabled

    @property
    def virustotal_configured(self) -> bool:
        """Whether a VirusTotal API key is configured. Never exposes the key."""
        return self._vt_enabled

    @property
    def abuseipdb_configured(self) -> bool:
        """Whether an AbuseIPDB API key is configured. Never exposes the key."""
        return self._abuseipdb_enabled

    def _get_cache_key(self, ioc_type: IOCType, ioc_value: str) -> str:
        """Generate cache key for IOC."""
        return f"{ioc_type.value}:{ioc_value.lower()}"

    def _get_cached(self, ioc_type: IOCType, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Get cached result if still valid."""
        key = self._get_cache_key(ioc_type, ioc_value)
        if key in self._cache:
            result, cached_at = self._cache[key]
            if datetime.now(timezone.utc) - cached_at < timedelta(seconds=self.CACHE_TTL_SECONDS):
                result.cached = True
                return result
            else:
                del self._cache[key]
        return None

    def _set_cached(self, result: ThreatIntelResult):
        """Cache a result in local memory."""
        key = self._get_cache_key(result.ioc_type, result.ioc_value)
        self._cache[key] = (result, datetime.now(timezone.utc))

    async def _set_redis_cached(self, result: ThreatIntelResult):
        """Cache a result in Redis with appropriate TTL."""
        if self._redis is None:
            return

        key = f"threat_intel:{self._get_cache_key(result.ioc_type, result.ioc_value)}"
        try:
            # Use different TTL for malicious vs clean results
            ttl = (
                self.settings.external_cache_ttl_malicious
                if result.is_malicious
                else self.settings.external_cache_ttl_clean
            )
            data = result.model_dump_json()
            await self._redis.setex(key, ttl, data)
        except Exception as exc:
            logger.warning("Redis threat intel cache write failed", error=str(exc))

    async def _get_redis_cached(self, ioc_type: IOCType, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Get a cached threat-intelligence result from Redis."""
        if self._redis is None:
            return None

        key = f"threat_intel:{self._get_cache_key(ioc_type, ioc_value)}"
        try:
            # Step 10: Track cache requests
            try:
                from app.metrics import increment_cache_request, increment_cache_hit
                import asyncio
                asyncio.create_task(increment_cache_request("threat_intel"))
            except Exception:
                pass

            cached_data = await self._redis.get(key)
            if not cached_data:
                return None

            data = json.loads(cached_data)
            result = ThreatIntelResult(**data)
            result.cached = True

            # Step 10: Track cache hit
            try:
                asyncio.create_task(increment_cache_hit("threat_intel"))
            except Exception:
                pass

            return result
        except Exception as exc:
            logger.warning("Redis threat intel cache read failed", error=str(exc))
            return None

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> ThreatIntelResult:
        """
        Look up an IOC across configured threat intelligence sources.

        Args:
            ioc_type: Type of IOC
            ioc_value: The IOC value to look up

        Returns:
            ThreatIntelResult with combined findings
        """
        start_time = datetime.now(timezone.utc)
        original_value = ioc_value
        try:
            ioc_value = normalize_ioc_value(ioc_type, ioc_value)
        except ValueError:
            raise

        if not _is_safe_for_external_lookup(ioc_type, ioc_value):
            return ThreatIntelResult(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                reputation_status=ReputationStatus.UNKNOWN,
                classification_reason=(
                    "External lookup was skipped because this indicator targets a non-public or local address."
                ),
                details={"lookup_skipped": "non_public_or_local_indicator"},
            )

        # Check local cache first
        cached = self._get_cached(ioc_type, ioc_value)
        if cached:
            logger.debug("Threat intel local cache hit", ioc_type=ioc_type.value, ioc=ioc_value[:50])
            return cached

        # Check Redis cache
        redis_cached = await self._get_redis_cached(ioc_type, ioc_value)
        if redis_cached:
            # Store in local cache too
            self._set_cached(redis_cached)
            logger.debug("Threat intel Redis cache hit", ioc_type=ioc_type.value, ioc=ioc_value[:50])
            return redis_cached

        result = ThreatIntelResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )

        try:
            # Run lookups in parallel based on IOC type
            tasks = []

            if self._vt_enabled:
                if ioc_type == IOCType.IP:
                    tasks.append(self._lookup_vt_ip(ioc_value))
                elif ioc_type == IOCType.DOMAIN:
                    tasks.append(self._lookup_vt_domain(ioc_value))
                elif ioc_type == IOCType.URL:
                    tasks.append(self._lookup_vt_url(ioc_value))
                elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
                    tasks.append(self._lookup_vt_hash(ioc_value))

            if self._abuseipdb_enabled and ioc_type == IOCType.IP:
                tasks.append(self._lookup_abuseipdb(ioc_value))

            if not tasks:
                # Nothing was attempted at all - this is UNKNOWN, not CLEAN:
                # there is no evidence either way, because no provider is
                # configured for this IOC type.
                result.reputation_status = ReputationStatus.UNKNOWN
                result.classification_reason = (
                    "No threat intelligence provider is configured for this indicator type."
                )
                result.error = "No threat intelligence sources configured for this IOC type"
                return result

            # Execute lookups. Providers now return a dict on every path
            # (success or failure) rather than raising, but return_exceptions
            # is kept as a last-resort safety net for a genuinely unexpected
            # crash (e.g. a bug in the provider method itself) so one bad
            # provider can never take down the whole lookup.
            lookup_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Combine results: every attempted provider gets exactly one
            # ProviderOutcome, whether it succeeded or failed, so a failure
            # is always visible and never silently dropped.
            for lr in lookup_results:
                if isinstance(lr, Exception):
                    logger.warning("Threat intel provider crashed unexpectedly", error=str(lr))
                    result.provider_outcomes.append(
                        ProviderOutcome(
                            name="unknown",
                            status=ProviderCheckStatus.UNAVAILABLE,
                            detail=f"Provider check crashed: {lr}",
                        )
                    )
                    continue

                if not isinstance(lr, dict):
                    continue

                source = lr.get("source", "")
                status = ProviderCheckStatus(lr.get("status", ProviderCheckStatus.SUCCESS.value))
                data = lr.get("data", {})

                if "vt" in source:
                    provider_name = "VirusTotal"
                    if status == ProviderCheckStatus.SUCCESS:
                        result.sources.append(provider_name)
                        result.details["virustotal"] = data
                        mal = data.get("malicious_count", 0)
                        sus = data.get("suspicious_count", 0)
                        total = data.get("total_engines", 0)
                        data_available = bool(total) and not data.get("not_found", False)
                        confidence = None
                        if total > 0:
                            confidence = min(100, int((mal * 2 + sus) / total * 100))
                    else:
                        mal = sus = None
                        data_available = False
                        confidence = None
                    result.provider_outcomes.append(
                        ProviderOutcome(
                            name=provider_name,
                            status=status,
                            detections=mal,
                            suspicious_detections=sus,
                            confidence_score=confidence,
                            data_available=data_available,
                            last_analysis_at=data.get("last_analysis_date") if status == ProviderCheckStatus.SUCCESS else None,
                            detail=lr.get("detail"),
                        )
                    )

                elif "abuseipdb" in source:
                    provider_name = "AbuseIPDB"
                    if status == ProviderCheckStatus.SUCCESS:
                        result.sources.append(provider_name)
                        result.details["abuseipdb"] = data
                        abuse_score = data.get("abuse_confidence_score", 0)
                        data_available = "abuse_confidence_score" in data
                    else:
                        abuse_score = None
                        data_available = False
                    result.provider_outcomes.append(
                        ProviderOutcome(
                            name=provider_name,
                            status=status,
                            confidence_score=abuse_score,
                            data_available=data_available,
                            last_analysis_at=data.get("last_reported_at") if status == ProviderCheckStatus.SUCCESS else None,
                            detail=lr.get("detail"),
                        )
                    )

            _classify(result)

            # Calculate lookup time
            result.lookup_time_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

            # Cache result (local + Redis) - only cache a definitive verdict;
            # a LOOKUP_FAILED result must be retried on the next request, not
            # served stale from cache as if it were a real verdict.
            if result.reputation_status != ReputationStatus.LOOKUP_FAILED:
                self._set_cached(result)
                await self._set_redis_cached(result)

            logger.info(
                "Threat intel lookup complete",
                ioc_type=ioc_type.value,
                ioc=ioc_value[:50],
                reputation_status=result.reputation_status.value,
                risk_score=result.risk_score,
                sources=result.sources,
                provider_outcomes=[(o.name, o.status.value) for o in result.provider_outcomes],
            )

            return result

        except Exception as e:
            logger.error("Threat intel lookup error", error=str(e))
            result.reputation_status = ReputationStatus.LOOKUP_FAILED
            result.classification_reason = "The threat intelligence lookup failed unexpectedly."
            result.error = str(e)
            return result

    async def lookup_batch(self, iocs: list[tuple[IOCType, str]]) -> list[ThreatIntelResult]:
        """
        Look up multiple IOCs in parallel.

        Args:
            iocs: List of (ioc_type, ioc_value) tuples

        Returns:
            List of ThreatIntelResult
        """
        tasks = [self.lookup(ioc_type, ioc_value) for ioc_type, ioc_value in iocs]
        return await asyncio.gather(*tasks)

    # -------------------------------------------------------------------------
    # VirusTotal Lookups (with rate limiting and circuit breaker)
    # -------------------------------------------------------------------------

    async def _acquire_vt_rate_limit(self) -> bool:
        """Acquire VirusTotal rate limit token."""
        # Step 10: Track external API call
        try:
            from app.metrics import increment_external_api_call
            asyncio.create_task(increment_external_api_call("virustotal"))
        except Exception:
            pass

        return await self._rate_limiter.acquire(
            key="external:virustotal",
            limit=self.settings.external_vt_rate_limit,
            window_seconds=self.settings.external_vt_rate_window,
            wait=True,
            max_wait_seconds=30.0,
        )

    async def _lookup_vt_ip(self, ip: str) -> dict:
        """Look up IP address on VirusTotal."""
        # Check circuit breaker
        if not await self._vt_circuit.allow_request():
            logger.warning("VirusTotal circuit open, skipping IP lookup", ip=ip[:20])
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal is temporarily unavailable (circuit open)")

        # Rate limiting
        if not await self._acquire_vt_rate_limit():
            logger.warning("VirusTotal rate limit exceeded", ip=ip[:20])
            return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.VT_BASE_URL}/ip_addresses/{ip}",
                    headers={"x-apikey": self.settings.virustotal_api_key},
                    timeout=30.0,
                )

                if response.status_code == 404:
                    await self._vt_circuit.record_success()
                    return {"source": "vt", "status": ProviderCheckStatus.SUCCESS.value, "data": {"not_found": True}}

                response.raise_for_status()
                await self._vt_circuit.record_success()

                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                last_analysis_ts = data.get("last_analysis_date")
                return {
                    "source": "vt",
                    "status": ProviderCheckStatus.SUCCESS.value,
                    "data": {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country", ""),
                        "as_owner": data.get("as_owner", ""),
                        "last_analysis_date": (
                            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).isoformat()
                            if isinstance(last_analysis_ts, (int, float))
                            else None
                        ),
                    }
                }
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException):
            await self._vt_circuit.record_failure()
            logger.warning("VirusTotal IP lookup timed out", ip=ip[:20])
            return _provider_failure("vt", ProviderCheckStatus.TIMEOUT, "VirusTotal request timed out")
        except httpx.HTTPStatusError as exc:
            await self._vt_circuit.record_failure()
            status_code = exc.response.status_code
            logger.error("VirusTotal IP lookup HTTP error", status=status_code)
            if status_code in (401, 403):
                return _provider_failure("vt", ProviderCheckStatus.AUTH_ERROR, "VirusTotal rejected the configured API key")
            if status_code == 429:
                return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, f"VirusTotal returned HTTP {status_code}")
        except Exception as exc:
            await self._vt_circuit.record_failure()
            logger.error("VirusTotal IP lookup failed", error=str(exc))
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal request failed")

    async def _lookup_vt_domain(self, domain: str) -> dict:
        """Look up domain on VirusTotal."""
        # Check circuit breaker
        if not await self._vt_circuit.allow_request():
            logger.warning("VirusTotal circuit open, skipping domain lookup", domain=domain[:30])
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal is temporarily unavailable (circuit open)")

        # Rate limiting
        if not await self._acquire_vt_rate_limit():
            logger.warning("VirusTotal rate limit exceeded", domain=domain[:30])
            return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.VT_BASE_URL}/domains/{domain}",
                    headers={"x-apikey": self.settings.virustotal_api_key},
                    timeout=30.0,
                )

                if response.status_code == 404:
                    await self._vt_circuit.record_success()
                    return {"source": "vt", "status": ProviderCheckStatus.SUCCESS.value, "data": {"not_found": True}}

                response.raise_for_status()
                await self._vt_circuit.record_success()

                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "vt",
                    "status": ProviderCheckStatus.SUCCESS.value,
                    "data": {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "reputation": data.get("reputation", 0),
                        "categories": list(data.get("categories", {}).values()),
                        "registrar": data.get("registrar", ""),
                        "creation_date": data.get("creation_date"),
                    }
                }
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException):
            await self._vt_circuit.record_failure()
            logger.warning("VirusTotal domain lookup timed out", domain=domain[:30])
            return _provider_failure("vt", ProviderCheckStatus.TIMEOUT, "VirusTotal request timed out")
        except httpx.HTTPStatusError as exc:
            await self._vt_circuit.record_failure()
            status_code = exc.response.status_code
            logger.error("VirusTotal domain lookup HTTP error", status=status_code)
            if status_code in (401, 403):
                return _provider_failure("vt", ProviderCheckStatus.AUTH_ERROR, "VirusTotal rejected the configured API key")
            if status_code == 429:
                return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, f"VirusTotal returned HTTP {status_code}")
        except Exception as exc:
            await self._vt_circuit.record_failure()
            logger.error("VirusTotal domain lookup failed", error=str(exc))
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal request failed")

    async def _lookup_vt_url(self, url: str) -> dict:
        """Look up URL on VirusTotal."""
        # Check circuit breaker
        if not await self._vt_circuit.allow_request():
            logger.warning("VirusTotal circuit open, skipping URL lookup")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal is temporarily unavailable (circuit open)")

        # Rate limiting
        if not await self._acquire_vt_rate_limit():
            logger.warning("VirusTotal rate limit exceeded for URL lookup")
            return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")

        try:
            # URL must be base64 encoded without padding
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.VT_BASE_URL}/urls/{url_id}",
                    headers={"x-apikey": self.settings.virustotal_api_key},
                    timeout=30.0,
                )

                if response.status_code == 404:
                    await self._vt_circuit.record_success()
                    return {"source": "vt", "status": ProviderCheckStatus.SUCCESS.value, "data": {"not_found": True}}

                response.raise_for_status()
                await self._vt_circuit.record_success()

                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "vt",
                    "status": ProviderCheckStatus.SUCCESS.value,
                    "data": {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "categories": list(data.get("categories", {}).values()),
                        "final_url": data.get("last_final_url", url),
                        "title": data.get("title", ""),
                    }
                }
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException):
            await self._vt_circuit.record_failure()
            logger.warning("VirusTotal URL lookup timed out")
            return _provider_failure("vt", ProviderCheckStatus.TIMEOUT, "VirusTotal request timed out")
        except httpx.HTTPStatusError as exc:
            await self._vt_circuit.record_failure()
            status_code = exc.response.status_code
            logger.error("VirusTotal URL lookup HTTP error", status=status_code)
            if status_code in (401, 403):
                return _provider_failure("vt", ProviderCheckStatus.AUTH_ERROR, "VirusTotal rejected the configured API key")
            if status_code == 429:
                return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, f"VirusTotal returned HTTP {status_code}")
        except Exception as exc:
            await self._vt_circuit.record_failure()
            logger.error("VirusTotal URL lookup failed", error=str(exc))
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal request failed")

    async def _lookup_vt_hash(self, file_hash: str) -> dict:
        """Look up file hash on VirusTotal."""
        # Check circuit breaker
        if not await self._vt_circuit.allow_request():
            logger.warning("VirusTotal circuit open, skipping hash lookup")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal is temporarily unavailable (circuit open)")

        # Rate limiting
        if not await self._acquire_vt_rate_limit():
            logger.warning("VirusTotal rate limit exceeded for hash lookup")
            return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.VT_BASE_URL}/files/{file_hash}",
                    headers={"x-apikey": self.settings.virustotal_api_key},
                    timeout=30.0,
                )

                if response.status_code == 404:
                    await self._vt_circuit.record_success()
                    return {"source": "vt", "status": ProviderCheckStatus.SUCCESS.value, "data": {"not_found": True}}

                response.raise_for_status()
                await self._vt_circuit.record_success()

                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "vt",
                    "status": ProviderCheckStatus.SUCCESS.value,
                    "data": {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                        "type_description": data.get("type_description", ""),
                        "type_tag": data.get("type_tag", ""),
                        "names": data.get("names", [])[:5],
                        "size": data.get("size", 0),
                    }
                }
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException):
            await self._vt_circuit.record_failure()
            logger.warning("VirusTotal hash lookup timed out")
            return _provider_failure("vt", ProviderCheckStatus.TIMEOUT, "VirusTotal request timed out")
        except httpx.HTTPStatusError as exc:
            await self._vt_circuit.record_failure()
            status_code = exc.response.status_code
            logger.error("VirusTotal hash lookup HTTP error", status=status_code)
            if status_code in (401, 403):
                return _provider_failure("vt", ProviderCheckStatus.AUTH_ERROR, "VirusTotal rejected the configured API key")
            if status_code == 429:
                return _provider_failure("vt", ProviderCheckStatus.RATE_LIMITED, "VirusTotal rate limit exceeded")
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, f"VirusTotal returned HTTP {status_code}")
        except Exception as exc:
            await self._vt_circuit.record_failure()
            logger.error("VirusTotal hash lookup failed", error=str(exc))
            return _provider_failure("vt", ProviderCheckStatus.UNAVAILABLE, "VirusTotal request failed")

    # -------------------------------------------------------------------------
    # AbuseIPDB Lookups (with rate limiting and circuit breaker)
    # -------------------------------------------------------------------------

    async def _lookup_abuseipdb(self, ip: str) -> dict:
        """Look up IP address on AbuseIPDB."""
        # Check circuit breaker
        if not await self._abuseipdb_circuit.allow_request():
            logger.warning("AbuseIPDB circuit open, skipping lookup", ip=ip[:20])
            return _provider_failure("abuseipdb", ProviderCheckStatus.UNAVAILABLE, "AbuseIPDB is temporarily unavailable (circuit open)")

        # Step 10: Track external API call
        try:
            from app.metrics import increment_external_api_call
            asyncio.create_task(increment_external_api_call("abuseipdb"))
        except Exception:
            pass

        # Rate limiting
        allowed = await self._rate_limiter.acquire(
            key="external:abuseipdb",
            limit=self.settings.external_abuseipdb_rate_limit,
            window_seconds=self.settings.external_abuseipdb_rate_window,
            wait=True,
            max_wait_seconds=30.0,
        )
        if not allowed:
            logger.warning("AbuseIPDB rate limit exceeded", ip=ip[:20])
            return _provider_failure("abuseipdb", ProviderCheckStatus.RATE_LIMITED, "AbuseIPDB rate limit exceeded")

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.ABUSEIPDB_BASE_URL}/check",
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": True,
                    },
                    headers={
                        "Key": self.settings.abuseipdb_api_key,
                        "Accept": "application/json",
                    },
                    timeout=30.0,
                )

                response.raise_for_status()
                await self._abuseipdb_circuit.record_success()

                data = response.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "status": ProviderCheckStatus.SUCCESS.value,
                    "data": {
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "is_public": data.get("isPublic", True),
                        "is_tor": data.get("isTor", False),
                        "isp": data.get("isp", ""),
                        "country_code": data.get("countryCode", ""),
                        "domain": data.get("domain", ""),
                        "usage_type": data.get("usageType", ""),
                        "last_reported_at": data.get("lastReportedAt"),
                    }
                }
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException):
            await self._abuseipdb_circuit.record_failure()
            logger.warning("AbuseIPDB lookup timed out", ip=ip[:20])
            return _provider_failure("abuseipdb", ProviderCheckStatus.TIMEOUT, "AbuseIPDB request timed out")
        except httpx.HTTPStatusError as exc:
            await self._abuseipdb_circuit.record_failure()
            status_code = exc.response.status_code
            logger.error("AbuseIPDB lookup HTTP error", status=status_code)
            if status_code in (401, 403):
                return _provider_failure("abuseipdb", ProviderCheckStatus.AUTH_ERROR, "AbuseIPDB rejected the configured API key")
            if status_code == 429:
                return _provider_failure("abuseipdb", ProviderCheckStatus.RATE_LIMITED, "AbuseIPDB rate limit exceeded")
            return _provider_failure("abuseipdb", ProviderCheckStatus.UNAVAILABLE, f"AbuseIPDB returned HTTP {status_code}")
        except Exception as exc:
            await self._abuseipdb_circuit.record_failure()
            logger.error("AbuseIPDB lookup failed", error=str(exc))
            return _provider_failure("abuseipdb", ProviderCheckStatus.UNAVAILABLE, "AbuseIPDB request failed")


def _provider_failure(source: str, status: ProviderCheckStatus, detail: str) -> dict:
    """Build a failed-provider result dict. Used instead of raising so a
    single provider's failure is always a visible, typed outcome rather
    than an exception that `lookup()`'s combine loop could otherwise be
    tempted to swallow."""
    return {"source": source, "status": status.value, "data": {}, "detail": detail}


def normalize_ioc_value(ioc_type: IOCType, value: str) -> str:
    """Validate and normalize an IOC without performing a provider request."""
    if not isinstance(value, str):
        raise ValueError("ioc_value must be a string")

    normalized = value.strip()
    if not normalized or len(normalized) > 4096 or any(ord(char) < 32 for char in normalized):
        raise ValueError("ioc_value is empty, too long, or contains control characters")

    if ioc_type == IOCType.IP:
        try:
            return ipaddress.ip_address(normalized).compressed
        except ValueError as exc:
            raise ValueError("ioc_value must be a valid IPv4 or IPv6 address") from exc

    if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        expected_length = {
            IOCType.HASH_MD5: 32,
            IOCType.HASH_SHA1: 40,
            IOCType.HASH_SHA256: 64,
        }[ioc_type]
        if not re.fullmatch(r"[0-9a-fA-F]{" + str(expected_length) + r"}", normalized):
            raise ValueError(f"ioc_value must be a {expected_length}-character hexadecimal hash")
        return normalized.lower()

    if ioc_type == IOCType.URL:
        parsed = urlsplit(normalized)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("ioc_value must be an absolute HTTP or HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing user credentials are not accepted")
        if not _valid_domain(parsed.hostname) and not _is_ip_address(parsed.hostname):
            raise ValueError("URL host is malformed")
        return normalized

    if ioc_type == IOCType.DOMAIN:
        if not _valid_domain(normalized):
            raise ValueError("ioc_value must be a valid domain name")
        return normalized.rstrip(".").encode("idna").decode("ascii").lower()

    if ioc_type == IOCType.EMAIL:
        if normalized.count("@") != 1:
            raise ValueError("ioc_value must be a valid email address")
        local, domain = normalized.rsplit("@", 1)
        if not local or len(local) > 64 or any(char.isspace() for char in local) or not _valid_domain(domain):
            raise ValueError("ioc_value must be a valid email address")
        return f"{local}@{domain.rstrip('.').encode('idna').decode('ascii').lower()}"

    raise ValueError("Unsupported IOC type")


def _valid_domain(value: str) -> bool:
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        return False
    if not domain or len(domain) > 253:
        return False
    if "." not in domain:
        return False
    label_pattern = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    return all(label_pattern.fullmatch(label) for label in domain.split("."))


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_safe_for_external_lookup(ioc_type: IOCType, value: str) -> bool:
    if ioc_type == IOCType.IP:
        return ipaddress.ip_address(value).is_global

    host = urlsplit(value).hostname if ioc_type == IOCType.URL else value
    if host is None:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        if not _valid_domain(host):
            return False
        normalized_host = host.rstrip(".").lower()
        return not (
            normalized_host == "localhost"
            or normalized_host.endswith((
                ".localhost", ".local", ".internal", ".lan", ".home.arpa",
                ".test", ".invalid", ".example",
            ))
        )


def _classify(result: ThreatIntelResult) -> None:
    """
    Apply the documented classification policy (see ReputationStatus's
    docstring) to `result` in place, using only `result.provider_outcomes`
    - never inferring a verdict from the mere presence/absence of raised
    exceptions, so this function is the single place reputation_status is
    decided.
    """
    successful = [o for o in result.provider_outcomes if o.status == ProviderCheckStatus.SUCCESS]
    failed = [o for o in result.provider_outcomes if o.status != ProviderCheckStatus.SUCCESS]

    if not result.provider_outcomes:
        result.reputation_status = ReputationStatus.UNKNOWN
        result.classification_reason = "No threat intelligence provider is configured for this indicator type."
        result.risk_score = None
        result.is_malicious = None
        return

    is_malicious = False
    is_suspicious = False
    risk_score = 0
    reasons: list[str] = []

    for outcome in successful:
        if outcome.name == "VirusTotal":
            mal = outcome.detections or 0
            if mal > 0:
                is_malicious = True
                reasons.append(f"VirusTotal: {mal} engine(s) flagged this indicator as malicious.")
            elif outcome.confidence_score and outcome.confidence_score > 0:
                is_suspicious = True
                reasons.append("VirusTotal: no engine flagged this as malicious, but some flagged it suspicious.")
            if outcome.confidence_score:
                risk_score = max(risk_score, outcome.confidence_score)
        elif outcome.name == "AbuseIPDB":
            score = outcome.confidence_score or 0
            if score >= ABUSE_SCORE_MALICIOUS_THRESHOLD:
                is_malicious = True
                reasons.append(f"AbuseIPDB: abuse confidence score {score}/100 meets the malicious threshold ({ABUSE_SCORE_MALICIOUS_THRESHOLD}+).")
            elif score >= ABUSE_SCORE_SUSPICIOUS_THRESHOLD:
                is_suspicious = True
                reasons.append(f"AbuseIPDB: abuse confidence score {score}/100 is below the malicious threshold but non-zero.")
            risk_score = max(risk_score, score)

    if is_malicious:
        result.reputation_status = ReputationStatus.MALICIOUS
        result.is_malicious = True
        result.risk_score = risk_score
        result.classification_reason = " ".join(reasons)
        return

    if is_suspicious:
        result.reputation_status = ReputationStatus.SUSPICIOUS
        result.is_malicious = False
        result.risk_score = risk_score
        result.classification_reason = " ".join(reasons)
        return

    if failed:
        # At least one configured provider did not complete successfully,
        # and no successful provider's evidence reached malicious/
        # suspicious. This can never be reported as CLEAN - a failed check
        # is not the same as a check that ran and found nothing.
        failed_names = ", ".join(f"{o.name} ({o.status.value})" for o in failed)
        result.reputation_status = ReputationStatus.LOOKUP_FAILED
        result.is_malicious = None
        result.risk_score = None
        if successful:
            result.classification_reason = (
                f"{', '.join(o.name for o in successful)} completed and found no evidence of malicious activity, "
                f"but {failed_names} could not be checked. This is not a confirmed clean verdict."
            )
        else:
            result.classification_reason = f"All configured providers failed to complete: {failed_names}."
        return

    # Every configured, attempted provider completed successfully and none
    # reached the suspicious/malicious threshold - this is the only path
    # that may report CLEAN.
    result.reputation_status = ReputationStatus.CLEAN
    result.is_malicious = False
    result.risk_score = risk_score
    result.classification_reason = (
        f"{', '.join(o.name for o in successful)} completed successfully and found no evidence of malicious activity."
    )


# =============================================================================
# Singleton Instance
# =============================================================================

_threat_intel_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Get or create the ThreatIntelService singleton."""
    global _threat_intel_service
    if _threat_intel_service is None:
        _threat_intel_service = ThreatIntelService()
    return _threat_intel_service




