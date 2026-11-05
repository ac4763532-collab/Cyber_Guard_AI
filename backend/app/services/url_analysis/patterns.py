"""Local URL pattern and phishing-indicator detection."""

from __future__ import annotations
from bs4 import BeautifulSoup

import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".country",
    ".gq",
    ".ml",
    ".tk",
    ".top",
    ".xyz",
    ".work",
    ".download",
    ".review",
    ".stream",
    ".buzz",
    ".cam",
    ".live",
}


KNOWN_BRANDS = {
    "apple",
    "amazon",
    "google",
    "microsoft",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "docusign",
    "dropbox",
    "github",
    "outlook",
    "office365",
    "bank",
}


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def is_ip_url(url: str) -> bool:
    """Return True when the URL hostname is an IP address."""
    hostname = _hostname(url)

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def has_suspicious_tld(url: str) -> bool:
    """Return True when the hostname uses a suspicious TLD."""
    hostname = _hostname(url)
    return any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)


def has_excessive_subdomains(url: str, max_parts: int = 4) -> bool:
    """Return True when the hostname contains unusually many labels."""
    hostname = _hostname(url)

    if not hostname:
        return False

    return len(hostname.split(".")) > max_parts


def has_suspicious_port(url: str) -> bool:
    """Return True for non-standard web ports."""
    try:
        parsed = urlparse(url)

        if parsed.port is None:
            return False

        if parsed.scheme.lower() == "http":
            return parsed.port not in {80}

        if parsed.scheme.lower() == "https":
            return parsed.port not in {443}

        return True

    except (ValueError, TypeError):
        return False


def is_data_uri(url: str) -> bool:
    """Return True when the URL is a data URI."""
    return isinstance(url, str) and url.strip().lower().startswith("data:")


def is_very_long_url(url: str, max_length: int = 2000) -> bool:
    """Return True when the URL is unusually long."""
    return isinstance(url, str) and len(url) > max_length


def has_brand_in_subdomain(url: str) -> bool:
    """Detect known brand names appearing in subdomains."""
    hostname = _hostname(url)

    if not hostname:
        return False

    parts = hostname.split(".")

    if len(parts) <= 2:
        return False

    subdomain = ".".join(parts[:-2])

    return any(brand in subdomain for brand in KNOWN_BRANDS)


def has_homograph(url: str) -> bool:
    """
    Detect common Unicode/IDN homograph indicators.

    This is intentionally conservative. It flags Unicode hostnames
    and punycode labels rather than attempting full Unicode confusable
    character analysis.
    """
    hostname = _hostname(url)

    if not hostname:
        return False

    if "xn--" in hostname:
        return True

    return any(ord(char) > 127 for char in hostname)


def analyze_url_patterns(url: str) -> dict:
    """Run all local URL pattern checks."""
    return {
        "url": url,
        "is_ip_url": is_ip_url(url),
        "has_suspicious_tld": has_suspicious_tld(url),
        "has_excessive_subdomains": has_excessive_subdomains(url),
        "has_suspicious_port": has_suspicious_port(url),
        "is_data_uri": is_data_uri(url),
        "is_very_long_url": is_very_long_url(url),
        "has_brand_in_subdomain": has_brand_in_subdomain(url),
        "has_homograph": has_homograph(url),
    }



def analyze_link_mismatches(html: str) -> list[dict]:
    """Find HTML links whose displayed text does not match the destination."""
    if not html:
        return []

    results = []

    try:
        soup = BeautifulSoup(html, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            display_text = anchor.get_text(" ", strip=True)

            if not href or not display_text:
                continue

            display_lower = display_text.lower().strip()
            href_lower = href.lower().strip()

            mismatch = False

            if display_lower.startswith(("http://", "https://", "www.")):
                normalized_display = display_lower.rstrip("/")
                normalized_href = href_lower.rstrip("/")

                if normalized_display != normalized_href:
                    mismatch = True

            if mismatch:
                results.append(
                    {
                        "display_text": display_text[:500],
                        "href": href[:2000],
                        "mismatch": True,
                    }
                )

    except Exception:
        return []

    return results

def analyze_urls(urls: list[str]) -> list[dict]:
    """Analyze multiple URLs."""
    return [
        analyze_url_patterns(url)
        for url in urls
        if isinstance(url, str) and url.strip()
    ]
