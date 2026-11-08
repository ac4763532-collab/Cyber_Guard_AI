"""
CyberGuard AI — URLhaus Provider
============================================================================

URLhaus (abuse.ch) is a free, no-API-key database of malware
distribution URLs. It's maintained by abuse.ch and community-reported.

API endpoint:
    POST https://urlhaus-api.abuse.ch/v1/url/
    Body: url=https://malicious.example.com/payload.exe

Response (when found):
    query_status: "ok"
    url_status: "online" | "offline" | "unknown"
    threat: "malware_download"
    tags: ["exe", "emotet", ...]
    payloads: [{sha256_hash: "...", ...}]

Response (when not found):
    query_status: "no_results"

Free tier: no rate limit documented, but abuse.ch asks for reasonable
use (≤ 1 req/sec). We enforce 30/min as a conservative cap.

No API key required — this provider is always enabled.
"""

from __future__ import annotations

from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


class URLhausProvider(ThreatIntelProvider):
    """URLhaus (abuse.ch) URL lookup."""

    name = "urlhaus"
    requires_api_key = False
    _default_rate_limit_rpm = 30

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def lookup_url(self, url: str) -> ProviderResult | None:
        if not self.is_enabled:
            return None

        url_clean = (url or "").strip()
        if not url_clean or not url_clean.startswith(("http://", "https://")):
            return None

        cache_key = self._cache_key("url", url_clean)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._acquire_token():
            self._logger.debug("URLhaus rate limit exhausted — skipping")
            return None

        # URLhaus uses POST, not GET
        data = self._http_post(
            f"{self.BASE_URL}/url/",
            data={"url": url_clean},
        )
        if data is None:
            return None

        result = self._parse_response(data, url_clean)
        if result is not None:
            self._cache_set(cache_key, result)
        return result

    def _parse_response(
        self,
        data: dict[str, Any],
        url: str,
    ) -> ProviderResult | None:
        try:
            status = data.get("query_status", "")
        except (AttributeError, TypeError):
            return None

        # "no_results" means the URL isn't known to be malicious.
        # Treat as a clean verdict with low confidence.
        if status == "no_results":
            return ProviderResult(
                provider=self.name,
                indicator=url,
                indicator_type="url",
                malicious=False,
                score=0,
                confidence=0.60,
                details="Not found in URLhaus",
                raw={},
            )

        if status != "ok":
            return None

        # URL is in the database → malicious
        try:
            url_status = data.get("url_status", "unknown")
            threat = data.get("threat", "malware_download")
            tags = data.get("tags") or []
            payloads = data.get("payloads") or []
        except (AttributeError, TypeError):
            return None

        # Score: 90 for online URLs, 70 for offline (was malicious,
        # might be taken down or might be a stale record)
        score = 90 if url_status == "online" else 70

        return ProviderResult(
            provider=self.name,
            indicator=url,
            indicator_type="url",
            malicious=True,
            score=score,
            confidence=0.90,
            details=(
                f"URLhaus: {threat}"
                + (f", status={url_status}" if url_status else "")
                + (f", tags: {','.join(str(t) for t in tags[:5])}" if tags else "")
            ),
            raw={
                "url_status": url_status,
                "threat": threat,
                "tags": tags[:10] if isinstance(tags, list) else [],
                "payload_count": len(payloads) if isinstance(payloads, list) else 0,
            },
        )

    # URLhaus uses POST — override the base's GET helper
    def _http_post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        try:
            import httpx
            merged_headers = {
                "Accept": "application/json",
                "User-Agent": self._user_agent,
            }
            if headers:
                merged_headers.update(headers)

            with httpx.Client(timeout=self._http_timeout_seconds) as client:
                response = client.post(url, headers=merged_headers, data=data)

            if response.status_code == 429:
                self._logger.warning(
                    "URLhaus rate-limited",
                    extra={"provider": self.name, "status": 429},
                )
                return None

            if response.status_code >= 400:
                self._logger.warning(
                    "URLhaus HTTP error",
                    extra={
                        "provider": self.name,
                        "status": response.status_code,
                    },
                )
                return None

            return response.json()
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "URLhaus request failed",
                extra={"provider": self.name, "error": str(exc)[:200]},
            )
            return None


__all__ = ["URLhausProvider"]