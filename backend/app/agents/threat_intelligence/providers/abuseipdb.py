"""
CyberGuard AI — AbuseIPDB Provider
============================================================================

AbuseIPDB's v2 API for IP abuse reports.

Free tier: 60 requests/minute, 1000/day.

Endpoint:
    GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90

Response:
    ``data.abuseConfidenceScore``  — 0-100 (AbuseIPDB's own confidence)
    ``data.totalReports``          — how many reports
    ``data.numDistinctUsers``      — how many distinct reporters
    ``data.countryCode``           — origin country
    ``data.isp``                   — ISP name
    ``data.usageType``             — "Data Center/Web Hosting/Transit" etc.
    ``data.isTor``                 — boolean

Verdict logic:
    malicious if abuseConfidenceScore >= 50
    score = abuseConfidenceScore (already 0-100)

Requires ``ABUSEIPDB_API_KEY``.
"""

from __future__ import annotations

from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API v2 client (IP addresses only)."""

    name = "abuseipdb"
    requires_api_key = True
    _default_rate_limit_rpm = 60

    BASE_URL = "https://api.abuseipdb.com/api/v2"
    MAX_AGE_DAYS = 90

    def lookup_ip(self, ip: str) -> ProviderResult | None:
        if not self.is_enabled:
            return None

        ip_clean = (ip or "").strip()
        if not ip_clean:
            return None

        cache_key = self._cache_key("ip", ip_clean)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._acquire_token():
            self._logger.debug("AbuseIPDB rate limit exhausted — skipping")
            return None

        data = self._http_get(
            f"{self.BASE_URL}/check",
            headers={
                "Key": self._api_key or "",
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip_clean,
                "maxAgeInDays": self.MAX_AGE_DAYS,
            },
        )
        if data is None:
            return None
        if not data:
            return None  # 404 — shouldn't happen for valid IPs, but be safe

        result = self._parse_response(data, ip_clean)
        if result is not None:
            self._cache_set(cache_key, result)
        return result

    def _parse_response(
        self,
        data: dict[str, Any],
        ip: str,
    ) -> ProviderResult | None:
        try:
            d = data["data"]
            confidence_score = int(d.get("abuseConfidenceScore", 0))
            total_reports = int(d.get("totalReports", 0))
            num_distinct_users = int(d.get("numDistinctUsers", 0))
            country = d.get("countryCode")
            isp = d.get("isp")
            usage_type = d.get("usageType")
            is_tor = bool(d.get("isTor", False))
        except (KeyError, TypeError, ValueError):
            return None

        # Verdict: 50+ confidence is abuse. Also flag Tor exit nodes
        # as malicious regardless of score (they're legitimate but
        # security-relevant traffic).
        is_malicious = confidence_score >= 50 or is_tor

        # Effective score:
        #   - confidence_score from AbuseIPDB is already 0-100
        #   - Tor exit nodes get bumped to at least 60 for scoring
        score = confidence_score
        if is_tor:
            score = max(score, 60)

        # Confidence: higher when more reports back the score.
        if total_reports >= 50 and num_distinct_users >= 10:
            confidence = 0.95
        elif total_reports >= 10:
            confidence = 0.85
        elif total_reports >= 3:
            confidence = 0.75
        elif total_reports >= 1:
            confidence = 0.60
        else:
            confidence = 0.40   # no reports → low confidence in "clean" verdict

        details_parts = [f"Abuse confidence {confidence_score}%"]
        if total_reports:
            details_parts.append(f"{total_reports} reports")
        if is_tor:
            details_parts.append("Tor exit node")
        if usage_type:
            details_parts.append(str(usage_type))

        return ProviderResult(
            provider=self.name,
            indicator=ip,
            indicator_type="ip",
            malicious=is_malicious,
            score=score,
            confidence=confidence,
            details=", ".join(details_parts),
            raw={
                "abuse_confidence_score": confidence_score,
                "total_reports": total_reports,
                "num_distinct_users": num_distinct_users,
                "country_code": country,
                "isp": isp,
                "usage_type": usage_type,
                "is_tor": is_tor,
            },
        )


__all__ = ["AbuseIPDBProvider"]