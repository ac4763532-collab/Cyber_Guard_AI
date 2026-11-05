"""
CyberGuard AI - Domain Utilities

Proper domain extraction, TLD handling, and domain classification.
Uses the Public Suffix List approach for accurate domain parsing.
"""

import re
from urllib.parse import urlparse
from typing import NamedTuple

from app.core.email_enums import (
    URLCategory,
    URL_SHORTENER_DOMAINS,
    CDN_DOMAINS,
    TRACKING_DOMAINS,
    AUTH_DOMAINS,
    SUSPICIOUS_TLDS,
    LEGITIMATE_BRAND_DOMAINS,
    DOMAIN_TO_BRAND,
    UNSUBSCRIBE_PATTERNS,
)


# =============================================================================
# Public Suffix List (subset of most common TLDs)
# A full implementation would load from publicsuffix.org
# =============================================================================

# Multi-part public suffixes (e.g., co.uk, com.au)
MULTI_PART_SUFFIXES = {
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # Canada (some)
    "gc.ca", "on.ca", "qc.ca", "bc.ca", "ab.ca",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    # Germany
    "de.com",
    # France
    "asso.fr", "nom.fr", "prd.fr",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz", "gen.nz", "kiwi.nz",
    # South Africa
    "co.za", "net.za", "org.za", "gov.za", "edu.za", "ac.za",
    # Generic/other
    "com.mx", "org.mx", "edu.mx", "gob.mx", "net.mx",
    "com.ar", "edu.ar", "gob.ar", "int.ar", "mil.ar", "net.ar", "org.ar",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk",
    "com.tw", "edu.tw", "gov.tw", "net.tw", "org.tw",
}


class DomainInfo(NamedTuple):
    """Parsed domain information."""
    full_domain: str          # e.g., "mail.google.com"
    registered_domain: str    # e.g., "google.com" (registrable domain)
    subdomain: str            # e.g., "mail"
    public_suffix: str        # e.g., "com"
    is_ip: bool               # True if IP address


def extract_domain_info(url_or_domain: str) -> DomainInfo | None:
    """
    Extract domain information from a URL, domain string, or email address.

    Uses proper TLD extraction based on public suffix rules.
    Returns None if parsing fails.
    """
    # Handle email addresses
    if "@" in url_or_domain and "://" not in url_or_domain:
        # Extract domain part from email
        parts = url_or_domain.split("@")
        if len(parts) == 2:
            url_or_domain = parts[1]

    # Handle URLs
    if "://" in url_or_domain:
        try:
            parsed = urlparse(url_or_domain)
            domain = parsed.netloc.lower()
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
            # Remove userinfo if present
            if "@" in domain:
                domain = domain.split("@")[-1]
        except Exception:
            return None
    else:
        domain = url_or_domain.lower().strip()

    if not domain:
        return None

    # Check if it's an IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        return DomainInfo(
            full_domain=domain,
            registered_domain=domain,
            subdomain="",
            public_suffix="",
            is_ip=True,
        )

    # Split domain into parts
    parts = domain.split(".")
    if len(parts) < 2:
        return None

    # Check for multi-part suffix (e.g., co.uk)
    if len(parts) >= 3:
        potential_suffix = ".".join(parts[-2:])
        if potential_suffix in MULTI_PART_SUFFIXES:
            public_suffix = potential_suffix
            registered_domain = ".".join(parts[-3:])
            subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
        else:
            public_suffix = parts[-1]
            registered_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    else:
        # Simple case: example.com
        public_suffix = parts[-1]
        registered_domain = domain
        subdomain = ""

    return DomainInfo(
        full_domain=domain,
        registered_domain=registered_domain,
        subdomain=subdomain,
        public_suffix=public_suffix,
        is_ip=False,
    )


def is_suspicious_tld(domain_info: DomainInfo) -> bool:
    """
    Check if the domain uses a suspicious TLD.

    Note: Common TLDs like .com, .org, .net are NOT suspicious.
    """
    if domain_info.is_ip:
        return False

    tld = f".{domain_info.public_suffix}"
    return tld.lower() in SUSPICIOUS_TLDS


def get_domain_brand(domain_info: DomainInfo) -> str | None:
    """
    Get the brand associated with a domain, if any.

    Returns the brand name if the domain is a legitimate brand domain.
    """
    if domain_info.is_ip:
        return None

    # Check exact registered domain match
    return DOMAIN_TO_BRAND.get(domain_info.registered_domain.lower())


def is_legitimate_brand_domain(domain: str, brand: str) -> bool:
    """
    Check if a domain is a legitimate domain for a brand.
    """
    domain_lower = domain.lower()
    brand_lower = brand.lower()

    legitimate_domains = LEGITIMATE_BRAND_DOMAINS.get(brand_lower, [])

    # Check exact match or subdomain of legitimate domain
    for legit in legitimate_domains:
        if domain_lower == legit or domain_lower.endswith(f".{legit}"):
            return True

    return False


def classify_url(url: str, link_text: str = "") -> tuple[URLCategory, list[str]]:
    """
    Classify a URL into its category.

    Returns:
        Tuple of (category, list of reasons/findings)
    """
    findings = []

    try:
        parsed = urlparse(url)
    except Exception:
        return URLCategory.UNKNOWN, ["Failed to parse URL"]

    domain_info = extract_domain_info(url)
    if not domain_info:
        return URLCategory.UNKNOWN, ["Failed to extract domain"]

    # Check for IP-based URL (suspicious)
    if domain_info.is_ip:
        findings.append(f"URL uses IP address instead of domain: {domain_info.full_domain}")
        return URLCategory.SUSPICIOUS, findings

    registered_domain = domain_info.registered_domain.lower()
    full_domain = domain_info.full_domain.lower()

    # Check for @ symbol deception (MALICIOUS)
    if "@" in url and parsed.username:
        findings.append("URL contains @ symbol to deceive about true destination")
        return URLCategory.MALICIOUS, findings

    # Check for URL shortener (exact domain match only)
    if registered_domain in URL_SHORTENER_DOMAINS or full_domain in URL_SHORTENER_DOMAINS:
        findings.append(f"URL shortener service: {registered_domain}")
        return URLCategory.SHORTENER, findings

    # Check for CDN
    if registered_domain in CDN_DOMAINS or any(full_domain.endswith(f".{cdn}") for cdn in CDN_DOMAINS):
        findings.append(f"Content delivery network: {registered_domain}")
        return URLCategory.CDN, findings

    # Check for tracking domain
    if registered_domain in TRACKING_DOMAINS or any(full_domain.endswith(f".{t}") for t in TRACKING_DOMAINS):
        findings.append(f"Email/marketing tracking domain: {registered_domain}")
        return URLCategory.TRACKING, findings

    # Check for authentication domain
    if full_domain in AUTH_DOMAINS or registered_domain in AUTH_DOMAINS:
        findings.append(f"Authentication/SSO domain: {registered_domain}")
        return URLCategory.AUTHENTICATION, findings

    # Check for unsubscribe link
    path_lower = (parsed.path + parsed.query).lower()
    for pattern in UNSUBSCRIBE_PATTERNS:
        if re.search(pattern, path_lower, re.IGNORECASE):
            findings.append("Unsubscribe/opt-out link")
            return URLCategory.UNSUBSCRIBE, findings

    # Check for static resource
    resource_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'}
    if any(parsed.path.lower().endswith(ext) for ext in resource_extensions):
        findings.append("Static resource file")
        return URLCategory.RESOURCE, findings

    # Check for suspicious TLD
    if is_suspicious_tld(domain_info):
        findings.append(f"Uses frequently-abused TLD: .{domain_info.public_suffix}")
        return URLCategory.SUSPICIOUS, findings

    # Check for display text vs href mismatch
    if link_text:
        # If link text looks like a URL but differs from actual URL
        if re.match(r'^https?://', link_text, re.IGNORECASE):
            link_domain_info = extract_domain_info(link_text)
            if link_domain_info and link_domain_info.registered_domain != registered_domain:
                findings.append(f"Display URL ({link_domain_info.registered_domain}) differs from actual destination ({registered_domain})")
                return URLCategory.MALICIOUS, findings

    # Check for redirect patterns in path/query
    redirect_patterns = [r'[?&](?:url|redirect|redir|goto|link|target|dest|next)=']
    for pattern in redirect_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            findings.append("URL contains redirect parameter")
            return URLCategory.REDIRECT, findings

    # Default: normal URL
    return URLCategory.NORMAL, findings


def is_url_shortener(url: str) -> bool:
    """
    Check if a URL is from a known URL shortener service.

    Only returns True for actual shortener domains, NOT for:
    - Long URLs
    - URLs with query parameters
    - URLs that perform redirects
    """
    domain_info = extract_domain_info(url)
    if not domain_info:
        return False

    registered_domain = domain_info.registered_domain.lower()
    full_domain = domain_info.full_domain.lower()

    return registered_domain in URL_SHORTENER_DOMAINS or full_domain in URL_SHORTENER_DOMAINS
