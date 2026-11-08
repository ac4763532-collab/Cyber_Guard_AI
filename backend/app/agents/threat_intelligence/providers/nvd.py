"""
CyberGuard AI — NVD (National Vulnerability Database) Provider
============================================================================

NVD provides authoritative CVE data: CVSS scores, CWE classifications,
affected products, references.

API endpoint:
    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234

Response:
    vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore
    vulnerabilities[0].cve.descriptions[...]  (find lang=="en")

Rate limits:
    - Without API key: 5 requests per 30 seconds (~10/min)
    - With API key:    50 requests per 30 seconds (~100/min)

API key is optional (``NVD_API_KEY``). Without it, this provider runs at
the lower rate limit but still works.

CVSS score → severity mapping:
    CVSS ≥ 9.0  → CRITICAL (score 100)
    CVSS ≥ 7.0  → HIGH     (score 80)
    CVSS ≥ 4.0  → MEDIUM   (score 50)
    CVSS < 4.0  → LOW      (score 20)
"""

from __future__ import annotations

from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


class NVDProvider(ThreatIntelProvider):
    """NVD CVE lookup."""

    name = "nvd"
    requires_api_key = False   # optional — lower rate limit without
    _default_rate_limit_rpm = 10

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        rate_limit_rpm: int | None = None,
    ) -> None:
        # Boost rate limit if API key provided
        effective_rpm = rate_limit_rpm
        if effective_rpm is None:
            effective_rpm = 100 if api_key else 10
        super().__init__(api_key=api_key, rate_limit_rpm=effective_rpm)

    def lookup_cve(self, cve_id: str) -> ProviderResult | None:
        if not self.is_enabled:
            return None

        cve_clean = (cve_id or "").strip().upper()
        if not cve_clean.startswith("CVE-"):
            return None

        cache_key = self._cache_key("cve", cve_clean)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._acquire_token():
            self._logger.debug("NVD rate limit exhausted — skipping")
            return None

        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        data = self._http_get(
            self.BASE_URL,
            headers=headers,
            params={"cveId": cve_clean},
        )
        if data is None:
            return None

        result = self._parse_response(data, cve_clean)
        if result is not None:
            self._cache_set(cache_key, result)
        return result

    def _parse_response(
        self,
        data: dict[str, Any],
        cve_id: str,
    ) -> ProviderResult | None:
        try:
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                # CVE not found — treat as unknown, low confidence
                return ProviderResult(
                    provider=self.name,
                    indicator=cve_id,
                    indicator_type="cve",
                    malicious=False,
                    score=0,
                    confidence=0.50,
                    details=f"{cve_id} not found in NVD",
                    raw={},
                )
            vuln = vulns[0]
            cve = vuln["cve"]
        except (KeyError, TypeError, IndexError):
            return None

        # CVSS score — try v3.1, then v3.0, then v2
        cvss_score: float | None = None
        cvss_vector: str | None = None
        try:
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                items = metrics.get(key) or []
                if items:
                    cvss_data = items[0].get("cvssData", {})
                    score_raw = cvss_data.get("baseScore")
                    if score_raw is not None:
                        cvss_score = float(score_raw)
                        cvss_vector = cvss_data.get("vectorString")
                        break
        except (TypeError, ValueError):
            pass

        # Description (English)
        description = ""
        try:
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    description = d.get("value", "")[:500]
                    break
        except (TypeError, AttributeError):
            pass

        # CWE IDs
        cwe_ids: list[str] = []
        try:
            for weakness in cve.get("weaknesses", []):
                for d in weakness.get("description", []):
                    val = d.get("value")
                    if val and val.startswith("CWE-"):
                        cwe_ids.append(val)
        except (TypeError, AttributeError):
            pass

        # Map CVSS → verdict
        if cvss_score is None:
            score = 50
            is_malicious = False
            severity_label = "unknown"
        elif cvss_score >= 9.0:
            score = 100
            is_malicious = True
            severity_label = "CRITICAL"
        elif cvss_score >= 7.0:
            score = 80
            is_malicious = True
            severity_label = "HIGH"
        elif cvss_score >= 4.0:
            score = 50
            is_malicious = False
            severity_label = "MEDIUM"
        else:
            score = 20
            is_malicious = False
            severity_label = "LOW"

        details_parts = [cve_id]
        if cvss_score is not None:
            details_parts.append(f"CVSS {cvss_score:.1f} ({severity_label})")
        if cwe_ids:
            details_parts.append(f"CWE: {','.join(cwe_ids[:3])}")

        return ProviderResult(
            provider=self.name,
            indicator=cve_id,
            indicator_type="cve",
            malicious=is_malicious,
            score=score,
            confidence=0.95,   # NVD is authoritative
            details=", ".join(details_parts),
            raw={
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity_label": severity_label,
                "cwe_ids": cwe_ids[:10],
                "description": description,
            },
        )


__all__ = ["NVDProvider"]