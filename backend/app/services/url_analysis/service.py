"""Unified URL analysis service."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from app.config import get_settings
from app.services.url_analysis.expander import expand_url
from app.services.url_analysis.patterns import analyze_url_patterns, analyze_link_mismatches as detect_link_mismatches
from app.services.url_analysis.reputation import check_url_reputation
from app.services.url_analysis.safe_browsing import check_urls


def _log_suspicious_url_if_needed(
    url: str,
    status: str,
    detection_source: str,
    risk_score: int,
) -> None:
    """Log suspicious URL detection event."""
    if status not in ("malicious", "suspicious"):
        return

    try:
        from app.logging import log_suspicious_url

        # Extract domain only (not full URL with query params)
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]

        log_suspicious_url(
            domain=domain,
            detection_source=detection_source,
            risk_score=risk_score,
            severity="high" if status == "malicious" else "medium",
        )
    except Exception:
        # Logging must never break analysis
        pass


async def analyze_url(url: str) -> dict:
    """Analyze one URL using local and external security signals."""
    if not isinstance(url, str) or not url.strip():
        return {
            "url": url,
            "final_url": url,
            "expanded": False,
            "expansion": {},
            "patterns": {},
            "safe_browsing": {},
            "reputation": {},
            "risk_score": 0,
            "is_malicious": False,
            "status": "unknown",
            "errors": ["Invalid URL"],
        }

    url = url.strip()
    settings = get_settings()
    errors: list[str] = []

    # 1. URL expansion
    try:
        expansion = await expand_url(
            url,
            max_redirects=settings.url_max_redirects,
        )
    except Exception as exc:
        expansion = {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "expanded": False,
            "status_code": None,
            "error": str(exc),
        }

    final_url = expansion.get("final") or url


    # 2. Local pattern analysis
    try:
        patterns = analyze_url_patterns(final_url)
    except Exception as exc:
        patterns = {}
        errors.append(f"Pattern analysis: {exc}")

    # 3. Google Safe Browsing
    try:
        safe_browsing = await check_urls([final_url])
    except Exception as exc:
        safe_browsing = {
            "configured": False,
            "checked": 0,
            "threats": [],
            "error": str(exc),
        }

    if safe_browsing.get("error"):
        errors.append(f"Safe Browsing: {safe_browsing['error']}")

    # 4. VirusTotal / existing threat-intelligence service
    try:
        reputation = await check_url_reputation(final_url)
    except Exception as exc:
        reputation = {
            "configured": False,
            "url": final_url,
            "status": "unknown",
            "is_malicious": False,
            "risk_score": 0,
            "sources": [],
            "details": {},
            "error": str(exc),
        }

    if reputation.get("error"):
        errors.append(f"Reputation: {reputation['error']}")

    # 5. Calculate unified risk score
    risk_score = int(reputation.get("risk_score", 0) or 0)

    threat_matches = safe_browsing.get("threats", [])
    if threat_matches:
        risk_score = max(risk_score, 100)

    pattern_weights = {
        "is_ip_url": 30,
        "has_suspicious_tld": 20,
        "has_excessive_subdomains": 15,
        "has_suspicious_port": 15,
        "is_data_uri": 50,
        "is_very_long_url": 10,
        "has_brand_in_subdomain": 35,
        "has_homograph": 50,
    }

    pattern_score = sum(
        weight
        for name, weight in pattern_weights.items()
        if patterns.get(name, False)
    )

    risk_score = max(risk_score, min(100, pattern_score))

    is_malicious = bool(
        reputation.get("is_malicious")
        or threat_matches
        or patterns.get("has_homograph")
        or patterns.get("is_data_uri")
    )

    if is_malicious:
        status = "malicious"
    elif reputation.get("status") == "suspicious" or pattern_score >= 30:
        status = "suspicious"
    elif reputation.get("status") == "clean" and pattern_score == 0:
        status = "clean"
    else:
        status = "unknown"

    # Step 10: Log suspicious/malicious URLs
    detection_source = "pattern"
    if threat_matches:
        detection_source = "safe_browsing"
    elif reputation.get("is_malicious"):
        detection_source = "virustotal"

    _log_suspicious_url_if_needed(
        url=final_url,
        status=status,
        detection_source=detection_source,
        risk_score=risk_score,
    )

    return {
        "url": url,
        "final_url": final_url,
        "expanded": bool(expansion.get("expanded", False)),
        "expansion": expansion,
        "patterns": patterns,
        "safe_browsing": safe_browsing,
        "reputation": reputation,
        "risk_score": risk_score,
        "is_malicious": is_malicious,
        "status": status,
        "errors": errors,
    }


async def analyze_link_mismatches(html: str) -> list[dict]:
    """Analyze HTML links for displayed-text versus destination mismatches."""
    return detect_link_mismatches(html)


async def analyze_urls(urls: list[str]) -> list[dict]:
    """Analyze multiple URLs sequentially."""
    if not isinstance(urls, list):
        return []

    results = []

    for url in urls:
        results.append(await analyze_url(url))

    return results
