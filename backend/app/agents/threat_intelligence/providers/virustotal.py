"""
CyberGuard AI — VirusTotal Provider
============================================================================

VirusTotal's public API v3 for IP / domain / URL / hash reputation.

Free tier: 4 requests/minute, 500/day. Paid tiers scale up.

Endpoints used:
    IP:     /api/v3/ip_addresses/{ip}
    Domain: /api/v3/domains/{domain}
    URL:    /api/v3/urls/{url_id}       (url_id = base64url(url))
    Hash:   /api/v3/files/{hash}

Response parsing:
    ``data.attributes.last_analysis_stats`` contains:
        malicious    — number of engines that flagged it
        suspicious   — number that flagged it as suspicious
        harmless     — number that consider it benign
        undetected   — number that had no opinion

    Score = (malicious / total) × 100
    Malicious verdict: 3+ engines OR (1+ engine AND >20% flagged)

Requires ``VIRUSTOTAL_API_KEY`` in .env. Without it, this provider
is disabled and its ``lookup_*`` methods return None.
"""

from __future__ import annotations

import base64
from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 client."""

    name = "virustotal"
    requires_api_key = True
    _default_rate_limit_rpm = 4   # free tier

    BASE_URL = "https://www.virustotal.com/api/v3"

    # ── Lookups ────────────────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> ProviderResult | None:
        return self._lookup(
            endpoint=f"ip_addresses/{ip}",
            indicator=ip,
            indicator_type="ip",
        )

    def lookup_domain(self, domain: str) -> ProviderResult | None:
        return self._lookup(
            endpoint=f"domains/{domain}",
            indicator=domain,
            indicator_type="domain",
        )

    def lookup_url(self, url: str) -> ProviderResult | None:
        # VT requires URL IDs to be base64url-encoded (no padding)
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        return self._lookup(
            endpoint=f"urls/{url_id}",
            indicator=url,
            indicator_type="url",
        )

    def lookup_hash(self, hash_value: str) -> ProviderResult | None:
        h = (hash_value or "").strip().lower()
        if not h:
            return None
        return self._lookup(
            endpoint=f"files/{h}",
            indicator=h,
            indicator_type="hash",
        )

    # ── Internals ──────────────────────────────────────────────────────

    def _lookup(
        self,
        *,
        endpoint: str,
        indicator: str,
        indicator_type: str,
    ) -> ProviderResult | None:
        if not self.is_enabled:
            return None

        cache_key = self._cache_key(indicator_type, indicator)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._acquire_token():
            self._logger.debug(
                "VirusTotal rate limit exhausted — skipping",
                extra={"indicator": indicator[:100]},
            )
            return None

        data = self._http_get(
            f"{self.BASE_URL}/{endpoint}",
            headers={"x-apikey": self._api_key or ""},
        )
        if data is None:
            return None
        if not data:
            # 404 — indicator unknown to VT. Cache as "not found" so
            # we don't retry it every event. Use malicious=False,
            # score=0, low confidence.
            result = ProviderResult(
                provider=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                malicious=False,
                score=0,
                confidence=0.2,
                details="Not found in VirusTotal",
                raw={},
            )
            self._cache_set(cache_key, result)
            return result

        result = self._parse_response(data, indicator, indicator_type)
        if result is not None:
            self._cache_set(cache_key, result)
        return result

    def _parse_response(
        self,
        data: dict[str, Any],
        indicator: str,
        indicator_type: str,
    ) -> ProviderResult | None:
        try:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected
        except (KeyError, TypeError, ValueError):
            return None

        if total == 0:
            return None

        score = int(round((malicious / total) * 100))

        # Malicious if 3+ engines flagged it, OR >20% flagged it,
        # to catch low-detection threats (e.g. recent malware that
        # only a few engines recognize yet).
        is_malicious = malicious >= 3 or (
            malicious >= 1 and (malicious / total) >= 0.20
        )

        # Confidence grows with the number of engines that have an
        # opinion. Fewer than 5 total → low confidence, since VT may
        # not have enough data on this indicator.
        if total >= 50:
            confidence = 0.95
        elif total >= 20:
            confidence = 0.85
        elif total >= 5:
            confidence = 0.75
        else:
            confidence = 0.60

        details = (
            f"{malicious} of {total} engines flagged as malicious"
            + (f" ({suspicious} suspicious)" if suspicious else "")
        )

        return ProviderResult(
            provider=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=is_malicious,
            score=score,
            confidence=confidence,
            details=details,
            raw={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total,
            },
        )


__all__ = ["VirusTotalProvider"]