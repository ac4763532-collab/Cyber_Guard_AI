"""
CyberGuard AI — AlienVault OTX Provider
============================================================================

AlienVault Open Threat Exchange (OTX) API v1 client.

Endpoints:
    GET /api/v1/indicators/IPv4/{ip}/general
    GET /api/v1/indicators/domain/{domain}/general
    GET /api/v1/indicators/file/{hash}/general
    GET /api/v1/indicators/url/{url}/general

Requires ``OTX_API_KEY`` in environment.
"""

from __future__ import annotations

from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX API v1 client."""

    name = "otx"
    requires_api_key = True
    _default_rate_limit_rpm = 30

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def lookup_ip(self, ip: str) -> ProviderResult | None:
        return self._lookup(f"indicators/IPv4/{ip}/general", ip, "ip")

    def lookup_domain(self, domain: str) -> ProviderResult | None:
        return self._lookup(f"indicators/domain/{domain}/general", domain, "domain")

    def lookup_hash(self, file_hash: str) -> ProviderResult | None:
        return self._lookup(f"indicators/file/{file_hash}/general", file_hash, "hash")

    def lookup_url(self, url: str) -> ProviderResult | None:
        return self._lookup(f"indicators/url/{url}/general", url, "url")

    def _lookup(
        self,
        endpoint: str,
        indicator: str,
        indicator_type: str,
    ) -> ProviderResult | None:
        if not self.is_enabled:
            return None

        clean_indicator = (indicator or "").strip()
        if not clean_indicator:
            return None

        cache_key = self._cache_key(indicator_type, clean_indicator)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._acquire_token():
            self._logger.debug("OTX rate limit exhausted — skipping")
            return None

        data = self._http_get(
            f"{self.BASE_URL}/{endpoint}",
            headers={
                "X-OTX-API-KEY": self._api_key or "",
                "Accept": "application/json",
            },
        )
        if data is None:
            return None

        result = self._parse_response(data, clean_indicator, indicator_type)
        if result is not None:
            self._cache_set(cache_key, result)
        return result

    def _parse_response(
        self,
        data: dict[str, Any],
        indicator: str,
        indicator_type: str,
    ) -> ProviderResult | None:
        pulse_info = data.get("pulse_info", {})
        pulse_count = int(pulse_info.get("count", 0))

        # OTX pulses represent community threat reports
        malicious = pulse_count >= 1
        score = min(100, pulse_count * 20)
        confidence = min(0.95, 0.5 + (pulse_count * 0.1)) if pulse_count > 0 else 0.2

        pulses = pulse_info.get("pulses", [])
        pulse_names = [p.get("name") for p in pulses[:3] if p.get("name")]
        details = (
            f"OTX: Listed in {pulse_count} threat pulse(s): {', '.join(pulse_names)}"
            if pulse_count > 0
            else "OTX: No active threat pulses found"
        )

        return ProviderResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=malicious,
            score=score,
            confidence=confidence,
            details=details,
            raw={"pulse_count": pulse_count, "pulses": pulse_names},
        )


__all__ = ["OTXProvider"]
