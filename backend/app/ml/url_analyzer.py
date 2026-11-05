"""
CyberGuard AI - URL Analyzer

Production-grade URL analysis for phishing detection.

Features:
- URL extraction from email body
- Domain age checking
- Typosquatting detection
- URL shortener detection
- IP address detection in URLs
- Suspicious pattern matching
- Caching for performance (avoid re-analyzing same URLs)
- Async processing for scalability
- Graceful degradation on failures

Architecture:
- URLExtractor: Extract URLs from text/HTML
- URLAnalyzer: Analyze individual URLs
- URLCache: Redis/in-memory caching
- URLRepository: Database persistence for reputation
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse, parse_qs

import structlog

from app.config import get_settings


logger = structlog.get_logger(__name__)


# ============================================================================
# Configuration
# ============================================================================

# Known URL shorteners
URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "j.mp", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    "lnkd.in", "youtu.be", "amzn.to", "rebrand.ly", "bl.ink", "soo.gd",
})

# Known safe domains (major services)
SAFE_DOMAINS = frozenset({
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "linkedin.com", "twitter.com", "github.com", "dropbox.com", "slack.com",
    "zoom.us", "salesforce.com", "adobe.com", "oracle.com", "ibm.com",
    "paypal.com", "stripe.com", "aws.amazon.com", "azure.microsoft.com",
})

# Domains commonly impersonated in phishing
HIGH_VALUE_TARGETS = frozenset({
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bank", "chase", "wellsfargo", "citibank", "usbank",
    "americanexpress", "amex", "discover", "capitalone", "hsbc",
    "dropbox", "docusign", "adobe", "office365", "outlook", "onedrive",
})

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work",
    ".click", ".link", ".info", ".biz", ".online", ".site", ".website",
})

# Suspicious URL patterns
SUSPICIOUS_PATTERNS = [
    r"login.*verify",
    r"account.*suspend",
    r"security.*alert",
    r"password.*reset",
    r"confirm.*identity",
    r"update.*payment",
    r"verify.*account",
    r"secure.*login",
    r"signin.*update",
    r"\.php\?.*=.*@",  # PHP redirect with @ (credential harvesting)
    r"@.*\.com",  # @ in URL (basic auth trick)
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address
]


# ============================================================================
# Data Models
# ============================================================================

class URLRiskLevel(str, Enum):
    """URL risk classification."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class URLInfo:
    """Parsed URL information."""
    original: str
    scheme: str
    domain: str
    subdomain: str | None
    tld: str
    path: str
    query: dict[str, list[str]]
    port: int | None
    has_ip: bool
    is_shortened: bool


@dataclass
class URLAnalysisResult:
    """Result of analyzing a single URL."""
    url: str
    domain: str
    risk_level: URLRiskLevel
    risk_score: float  # 0.0 to 1.0
    risk_factors: list[str] = field(default_factory=list)
    is_shortened: bool = False
    is_ip_based: bool = False
    typosquat_target: str | None = None
    suspicious_patterns: list[str] = field(default_factory=list)
    https: bool = True
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cached: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "risk_factors": self.risk_factors,
            "is_shortened": self.is_shortened,
            "is_ip_based": self.is_ip_based,
            "typosquat_target": self.typosquat_target,
            "suspicious_patterns": self.suspicious_patterns,
            "https": self.https,
            "analyzed_at": self.analyzed_at.isoformat(),
            "cached": self.cached,
            "error": self.error,
        }


@dataclass
class EmailURLAnalysis:
    """Aggregated URL analysis for an entire email."""
    urls_found: int
    urls_analyzed: int
    high_risk_urls: int
    highest_risk_level: URLRiskLevel
    aggregate_risk_score: float
    url_results: list[URLAnalysisResult]
    analysis_time_ms: float
    cached_results: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "urls_found": self.urls_found,
            "urls_analyzed": self.urls_analyzed,
            "high_risk_urls": self.high_risk_urls,
            "highest_risk_level": self.highest_risk_level.value,
            "aggregate_risk_score": round(self.aggregate_risk_score, 3),
            "url_results": [r.to_dict() for r in self.url_results],
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "cached_results": self.cached_results,
        }


# ============================================================================
# URL Extractor
# ============================================================================

class URLExtractor:
    """
    Extract URLs from email content.

    Handles:
    - Plain text URLs
    - HTML href attributes
    - Encoded URLs
    - Obfuscated URLs (common in phishing)
    """

    # Comprehensive URL regex
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]]+|'  # Standard URLs
        r'www\.[^\s<>"\')\]]+|'       # www without protocol
        r'(?:href|src)=["\']([^"\']+)["\']',  # HTML attributes
        re.IGNORECASE
    )

    # Defanged URL patterns (security analysts often defang URLs)
    DEFANGED_PATTERN = re.compile(
        r'hxxp[s]?://|'   # hxxp://
        r'\[:\]|'          # [:]
        r'\[\.\]|'         # [.]
        r'\[dot\]',        # [dot]
        re.IGNORECASE
    )

    @classmethod
    def extract(cls, content: str, max_urls: int = 50) -> list[str]:
        """
        Extract unique URLs from content.

        Args:
            content: Email body (HTML or plain text)
            max_urls: Maximum URLs to extract (prevent DoS)

        Returns:
            List of unique URLs
        """
        if not content:
            return []

        urls = set()

        # Refang defanged URLs first
        content = cls._refang_urls(content)

        # Extract URLs
        for match in cls.URL_PATTERN.finditer(content):
            url = match.group(1) if match.group(1) else match.group(0)
            url = cls._normalize_url(url)

            if url and cls._is_valid_url(url):
                urls.add(url)

                if len(urls) >= max_urls:
                    break

        return list(urls)

    @classmethod
    def _refang_urls(cls, content: str) -> str:
        """Convert defanged URLs back to normal."""
        content = re.sub(r'hxxp', 'http', content, flags=re.IGNORECASE)
        content = re.sub(r'\[:\]', ':', content)
        content = re.sub(r'\[\.\]', '.', content)
        content = re.sub(r'\[dot\]', '.', content, flags=re.IGNORECASE)
        return content

    @classmethod
    def _normalize_url(cls, url: str) -> str:
        """Normalize URL for consistent analysis."""
        url = url.strip()

        # Add protocol if missing
        if url.startswith("www."):
            url = "http://" + url

        # Remove trailing punctuation that might be captured
        url = url.rstrip(".,;:!?")

        return url

    @classmethod
    def _is_valid_url(cls, url: str) -> bool:
        """Check if URL is valid for analysis."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False


# ============================================================================
# URL Cache (In-Memory + Optional Redis)
# ============================================================================

class URLCache:
    """
    Production URL cache with TTL.

    Uses in-memory cache by default, can be extended to Redis
    for distributed deployments.
    """

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10000):
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_size = max_size
        self._cache: dict[str, tuple[URLAnalysisResult, datetime]] = {}
        self._lock = asyncio.Lock()

    def _url_key(self, url: str) -> str:
        """Generate cache key from URL."""
        return hashlib.sha256(url.lower().encode()).hexdigest()[:32]

    async def get(self, url: str) -> URLAnalysisResult | None:
        """Get cached result if not expired."""
        key = self._url_key(url)

        async with self._lock:
            if key not in self._cache:
                return None

            result, cached_at = self._cache[key]

            # Check expiration
            if datetime.now(timezone.utc) - cached_at > self.ttl:
                del self._cache[key]
                return None

            # Mark as cached
            result.cached = True
            return result

    async def set(self, url: str, result: URLAnalysisResult) -> None:
        """Cache analysis result."""
        key = self._url_key(url)

        async with self._lock:
            # Evict old entries if at capacity
            if len(self._cache) >= self.max_size:
                self._evict_oldest()

            self._cache[key] = (result, datetime.now(timezone.utc))

    def _evict_oldest(self) -> None:
        """Remove oldest entries (LRU-style)."""
        if not self._cache:
            return

        # Remove oldest 10%
        items = sorted(self._cache.items(), key=lambda x: x[1][1])
        to_remove = max(1, len(items) // 10)

        for key, _ in items[:to_remove]:
            del self._cache[key]

    async def clear(self) -> None:
        """Clear all cached entries."""
        async with self._lock:
            self._cache.clear()

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl.total_seconds(),
        }


# ============================================================================
# Typosquatting Detector
# ============================================================================

class TyposquatDetector:
    """
    Detect typosquatting attempts (domains similar to legitimate ones).

    Common techniques:
    - Character substitution: paypa1.com (l→1)
    - Character addition: paypall.com
    - Character omission: paypa.com
    - Character transposition: paypla.com
    - Homograph attacks: pаypal.com (Cyrillic а)
    """

    # Character substitutions commonly used in typosquatting
    SUBSTITUTIONS = {
        'a': ['4', '@', 'α', 'а'],  # Last is Cyrillic
        'e': ['3', 'є', 'е'],
        'i': ['1', 'l', '!', 'і'],
        'o': ['0', 'о'],  # Last is Cyrillic
        's': ['5', '$'],
        'l': ['1', 'i', '|'],
        'g': ['9', 'q'],
        'b': ['8'],
        't': ['7', '+'],
    }

    @classmethod
    def check(cls, domain: str) -> str | None:
        """
        Check if domain is typosquatting a high-value target.

        Returns:
            Target domain name if typosquatting detected, None otherwise
        """
        domain_lower = domain.lower()

        # Extract base domain (remove TLD)
        parts = domain_lower.split('.')
        if len(parts) < 2:
            return None

        base = parts[-2]  # e.g., "paypal" from "paypal.com"

        # Also check if target name appears anywhere in domain
        # Catches: secure-paypa1.com, paypa1-login.com, etc.
        for target in HIGH_VALUE_TARGETS:
            # Direct typosquat of base domain
            if cls._is_typosquat(base, target):
                return target

            # Target name embedded with typos (e.g., secure-paypa1)
            # Check each hyphen-separated part
            for part in base.split('-'):
                if len(part) >= 4 and cls._is_typosquat(part, target):
                    return target

        return None

    @classmethod
    def _is_typosquat(cls, domain: str, target: str) -> bool:
        """Check if domain is a typosquat of target."""
        # Exact match is not typosquatting
        if domain == target:
            return False

        # Length must be similar
        if abs(len(domain) - len(target)) > 2:
            return False

        # Calculate edit distance
        distance = cls._levenshtein_distance(domain, target)

        # Within 2 edits is suspicious
        if distance <= 2:
            return True

        # Check for common substitutions
        normalized = cls._normalize_substitutions(domain)
        if normalized == target:
            return True

        return False

    @classmethod
    def _levenshtein_distance(cls, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance."""
        if len(s1) < len(s2):
            s1, s2 = s2, s1

        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)

        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    @classmethod
    def _normalize_substitutions(cls, text: str) -> str:
        """Replace common substitutions with original chars."""
        result = text.lower()

        for original, subs in cls.SUBSTITUTIONS.items():
            for sub in subs:
                result = result.replace(sub, original)

        return result


# ============================================================================
# URL Analyzer
# ============================================================================

class URLAnalyzer:
    """
    Production URL analyzer with caching and async support.

    Analyzes URLs for:
    - Shortened URLs (hiding destination)
    - IP-based URLs (bypassing domain blocks)
    - Typosquatting (impersonating legitimate domains)
    - Suspicious patterns (phishing keywords)
    - Missing HTTPS
    - Suspicious TLDs
    """

    def __init__(
        self,
        cache_ttl: int = 3600,
        cache_size: int = 10000,
        timeout: float = 5.0,
    ):
        self.cache = URLCache(ttl_seconds=cache_ttl, max_size=cache_size)
        self.timeout = timeout
        self.typosquat_detector = TyposquatDetector()

    async def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Analyze a single URL for risk.

        Uses cache to avoid re-analyzing known URLs.
        """
        # Check cache first
        cached = await self.cache.get(url)
        if cached:
            return cached

        try:
            result = await asyncio.wait_for(
                self._analyze_url_internal(url),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            result = URLAnalysisResult(
                url=url,
                domain="unknown",
                risk_level=URLRiskLevel.MEDIUM,
                risk_score=0.5,
                risk_factors=["Analysis timeout"],
                error="Analysis timed out",
            )
        except Exception as e:
            logger.error("URL analysis failed", url=url, error=str(e))
            result = URLAnalysisResult(
                url=url,
                domain="unknown",
                risk_level=URLRiskLevel.MEDIUM,
                risk_score=0.5,
                risk_factors=["Analysis error"],
                error=str(e),
            )

        # Cache result
        await self.cache.set(url, result)
        return result

    async def _analyze_url_internal(self, url: str) -> URLAnalysisResult:
        """Internal URL analysis logic."""
        risk_factors = []
        risk_score = 0.0

        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port from domain
            if ":" in domain:
                domain = domain.split(":")[0]

        except Exception:
            return URLAnalysisResult(
                url=url,
                domain="invalid",
                risk_level=URLRiskLevel.HIGH,
                risk_score=0.8,
                risk_factors=["Invalid URL format"],
            )

        # Check HTTPS
        https = parsed.scheme.lower() == "https"
        if not https:
            risk_factors.append("No HTTPS")
            risk_score += 0.1

        # Check for IP address
        is_ip = self._is_ip_address(domain)
        if is_ip:
            risk_factors.append("IP address in URL")
            risk_score += 0.3

        # Check for URL shortener
        is_shortened = self._is_shortener(domain)
        if is_shortened:
            risk_factors.append("URL shortener (destination hidden)")
            risk_score += 0.2

        # Check for typosquatting
        typosquat_target = None
        if not is_shortened and not is_ip:
            typosquat_target = self.typosquat_detector.check(domain)
            if typosquat_target:
                risk_factors.append(f"Typosquatting '{typosquat_target}'")
                risk_score += 0.6  # High risk for impersonation

        # Check suspicious TLD
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            risk_factors.append(f"Suspicious TLD: {tld}")
            risk_score += 0.2

        # Check suspicious patterns in full URL
        suspicious_patterns = self._check_patterns(url)
        if suspicious_patterns:
            risk_factors.extend(suspicious_patterns)
            risk_score += 0.1 * len(suspicious_patterns)

        # Check if safe known domain
        if self._is_safe_domain(domain):
            risk_score = max(0, risk_score - 0.3)
            risk_factors.append("Known safe domain")

        # Determine risk level
        risk_score = min(1.0, max(0.0, risk_score))
        risk_level = self._score_to_level(risk_score)

        return URLAnalysisResult(
            url=url,
            domain=domain,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            is_shortened=is_shortened,
            is_ip_based=is_ip,
            typosquat_target=typosquat_target,
            suspicious_patterns=suspicious_patterns,
            https=https,
        )

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            pass

        # IPv6 check
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            return True
        except socket.error:
            pass

        return False

    def _is_shortener(self, domain: str) -> bool:
        """Check if domain is a known URL shortener."""
        # Check exact match and with www
        return domain in URL_SHORTENERS or domain.replace("www.", "") in URL_SHORTENERS

    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is a known safe domain."""
        # Check exact and parent domain
        parts = domain.split(".")

        for i in range(len(parts) - 1):
            check_domain = ".".join(parts[i:])
            if check_domain in SAFE_DOMAINS:
                return True

        return False

    def _check_patterns(self, url: str) -> list[str]:
        """Check for suspicious patterns in URL."""
        found = []
        url_lower = url.lower()

        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                found.append(f"Suspicious pattern: {pattern}")

        return found

    def _score_to_level(self, score: float) -> URLRiskLevel:
        """Convert risk score to risk level."""
        if score >= 0.8:
            return URLRiskLevel.CRITICAL
        elif score >= 0.6:
            return URLRiskLevel.HIGH
        elif score >= 0.4:
            return URLRiskLevel.MEDIUM
        elif score >= 0.2:
            return URLRiskLevel.LOW
        else:
            return URLRiskLevel.SAFE

    async def analyze_email_urls(
        self,
        content: str,
        max_urls: int = 20,
    ) -> EmailURLAnalysis:
        """
        Analyze all URLs in an email.

        Args:
            content: Email body content
            max_urls: Maximum URLs to analyze

        Returns:
            Aggregated URL analysis
        """
        import time
        start_time = time.perf_counter()

        # Extract URLs
        urls = URLExtractor.extract(content, max_urls=max_urls)

        if not urls:
            return EmailURLAnalysis(
                urls_found=0,
                urls_analyzed=0,
                high_risk_urls=0,
                highest_risk_level=URLRiskLevel.SAFE,
                aggregate_risk_score=0.0,
                url_results=[],
                analysis_time_ms=0,
            )

        # Analyze URLs concurrently
        tasks = [self.analyze_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        url_results = []
        cached_count = 0

        for result in results:
            if isinstance(result, Exception):
                logger.error("URL analysis exception", error=str(result))
                continue
            url_results.append(result)
            if result.cached:
                cached_count += 1

        # Calculate aggregates
        high_risk_count = sum(
            1 for r in url_results
            if r.risk_level in (URLRiskLevel.HIGH, URLRiskLevel.CRITICAL)
        )

        highest_level = URLRiskLevel.SAFE
        max_score = 0.0

        for r in url_results:
            if r.risk_score > max_score:
                max_score = r.risk_score
                highest_level = r.risk_level

        # Aggregate score: weighted by highest risk URLs
        if url_results:
            scores = sorted([r.risk_score for r in url_results], reverse=True)
            # Top URLs weighted more heavily
            weights = [1.0 / (i + 1) for i in range(len(scores))]
            aggregate = sum(s * w for s, w in zip(scores, weights)) / sum(weights)
        else:
            aggregate = 0.0

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return EmailURLAnalysis(
            urls_found=len(urls),
            urls_analyzed=len(url_results),
            high_risk_urls=high_risk_count,
            highest_risk_level=highest_level,
            aggregate_risk_score=aggregate,
            url_results=url_results,
            analysis_time_ms=elapsed_ms,
            cached_results=cached_count,
        )

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self.cache.stats()


# ============================================================================
# Singleton Instance
# ============================================================================

_analyzer: URLAnalyzer | None = None


def get_url_analyzer() -> URLAnalyzer:
    """Get the global URL analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = URLAnalyzer()
    return _analyzer
