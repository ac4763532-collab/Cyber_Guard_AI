"""
CyberGuard AI - URL Analyzer Tests

Production-grade tests for URL analysis including:
- URL extraction
- Typosquatting detection
- Risk scoring
- Cache behavior
- Performance under load
"""

import asyncio
import time
import pytest
from datetime import datetime, timezone

from app.ml.url_analyzer import (
    URLExtractor,
    URLAnalyzer,
    URLCache,
    TyposquatDetector,
    URLRiskLevel,
    URL_SHORTENERS,
    SAFE_DOMAINS,
    get_url_analyzer,
)


# ============================================================================
# URL Extractor Tests
# ============================================================================

class TestURLExtractor:
    """Tests for URL extraction from email content."""

    def test_extract_simple_url(self):
        """Extract basic URL."""
        content = "Click here: https://example.com/page"
        urls = URLExtractor.extract(content)
        assert len(urls) == 1
        assert "example.com" in urls[0]

    def test_extract_multiple_urls(self):
        """Extract multiple URLs."""
        content = """
        Visit https://site1.com and http://site2.com
        Also check www.site3.com
        """
        urls = URLExtractor.extract(content)
        assert len(urls) == 3

    def test_extract_from_html(self):
        """Extract URLs from HTML content."""
        content = """
        <a href="https://example.com/login">Click</a>
        <img src="https://cdn.example.com/img.png">
        """
        urls = URLExtractor.extract(content)
        assert len(urls) >= 2

    def test_extract_defanged_urls(self):
        """Extract defanged URLs (security analyst format)."""
        content = """
        Malicious URL: hxxps://evil[.]com/malware
        Another: hxxp://bad[dot]site[.]com
        """
        urls = URLExtractor.extract(content)
        assert len(urls) == 2
        assert any("evil.com" in url for url in urls)

    def test_extract_max_urls(self):
        """Respect max URL limit (DoS protection)."""
        content = " ".join([f"https://site{i}.com" for i in range(100)])
        urls = URLExtractor.extract(content, max_urls=10)
        assert len(urls) == 10

    def test_extract_empty_content(self):
        """Handle empty content."""
        assert URLExtractor.extract("") == []
        assert URLExtractor.extract(None) == []

    def test_extract_no_urls(self):
        """Handle content with no URLs."""
        content = "This is just plain text with no links."
        assert URLExtractor.extract(content) == []

    def test_extract_unique_urls(self):
        """Return unique URLs only."""
        content = """
        https://example.com
        https://example.com
        https://example.com
        """
        urls = URLExtractor.extract(content)
        assert len(urls) == 1


# ============================================================================
# Typosquat Detector Tests
# ============================================================================

class TestTyposquatDetector:
    """Tests for typosquatting detection."""

    def test_detect_character_substitution(self):
        """Detect l→1 substitution (paypa1)."""
        result = TyposquatDetector.check("paypa1.com")
        assert result == "paypal"

    def test_detect_character_omission(self):
        """Detect missing character (payal)."""
        result = TyposquatDetector.check("payal.com")
        assert result == "paypal"

    def test_detect_character_addition(self):
        """Detect extra character (paypall)."""
        result = TyposquatDetector.check("paypall.com")
        assert result == "paypal"

    def test_detect_transposition(self):
        """Detect transposed characters (paypla)."""
        result = TyposquatDetector.check("paypla.com")
        assert result == "paypal"

    def test_detect_amazon_variants(self):
        """Detect Amazon typosquats."""
        variants = ["amaz0n.com", "amazom.com", "amazonn.com"]
        for variant in variants:
            result = TyposquatDetector.check(variant)
            assert result == "amazon", f"Failed for {variant}"

    def test_detect_microsoft_variants(self):
        """Detect Microsoft typosquats."""
        variants = ["micros0ft.com", "microsft.com", "mircosoft.com"]
        for variant in variants:
            result = TyposquatDetector.check(variant)
            assert result == "microsoft", f"Failed for {variant}"

    def test_legitimate_domain(self):
        """Legitimate domains should not trigger."""
        result = TyposquatDetector.check("paypal.com")
        assert result is None

    def test_unrelated_domain(self):
        """Unrelated domains should not trigger."""
        result = TyposquatDetector.check("mycompany.com")
        assert result is None


# ============================================================================
# URL Cache Tests
# ============================================================================

class TestURLCache:
    """Tests for URL caching."""

    @pytest.fixture
    def cache(self):
        return URLCache(ttl_seconds=60, max_size=100)

    @pytest.mark.asyncio
    async def test_cache_miss(self, cache):
        """Cache miss returns None."""
        result = await cache.get("https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit(self, cache):
        """Cache hit returns stored result."""
        from app.ml.url_analyzer import URLAnalysisResult

        original = URLAnalysisResult(
            url="https://example.com",
            domain="example.com",
            risk_level=URLRiskLevel.LOW,
            risk_score=0.2,
        )

        await cache.set("https://example.com", original)
        result = await cache.get("https://example.com")

        assert result is not None
        assert result.url == original.url
        assert result.cached is True

    @pytest.mark.asyncio
    async def test_cache_expiration(self):
        """Expired entries are not returned."""
        cache = URLCache(ttl_seconds=0, max_size=100)  # Immediate expiry

        from app.ml.url_analyzer import URLAnalysisResult

        original = URLAnalysisResult(
            url="https://example.com",
            domain="example.com",
            risk_level=URLRiskLevel.LOW,
            risk_score=0.2,
        )

        await cache.set("https://example.com", original)
        await asyncio.sleep(0.1)
        result = await cache.get("https://example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_cache_eviction(self):
        """Cache evicts old entries when full."""
        cache = URLCache(ttl_seconds=3600, max_size=10)

        from app.ml.url_analyzer import URLAnalysisResult

        # Fill cache
        for i in range(15):
            result = URLAnalysisResult(
                url=f"https://site{i}.com",
                domain=f"site{i}.com",
                risk_level=URLRiskLevel.LOW,
                risk_score=0.1,
            )
            await cache.set(f"https://site{i}.com", result)

        # Should not exceed max size
        assert len(cache._cache) <= 10


# ============================================================================
# URL Analyzer Tests
# ============================================================================

class TestURLAnalyzer:
    """Tests for URL analysis."""

    @pytest.fixture
    def analyzer(self):
        return URLAnalyzer(cache_ttl=60)

    @pytest.mark.asyncio
    async def test_analyze_safe_url(self, analyzer):
        """Analyze a known safe URL."""
        result = await analyzer.analyze_url("https://google.com")

        assert result.domain == "google.com"
        assert result.risk_level in (URLRiskLevel.SAFE, URLRiskLevel.LOW)
        assert result.https is True

    @pytest.mark.asyncio
    async def test_analyze_http_url(self, analyzer):
        """HTTP URLs should be flagged."""
        result = await analyzer.analyze_url("http://example.com")

        assert result.https is False
        assert "No HTTPS" in result.risk_factors

    @pytest.mark.asyncio
    async def test_analyze_ip_url(self, analyzer):
        """IP-based URLs should be flagged."""
        result = await analyzer.analyze_url("http://192.168.1.1/login")

        assert result.is_ip_based is True
        assert result.risk_score > 0.3
        assert any("IP address" in f for f in result.risk_factors)

    @pytest.mark.asyncio
    async def test_analyze_shortened_url(self, analyzer):
        """URL shorteners should be flagged."""
        result = await analyzer.analyze_url("https://bit.ly/abc123")

        assert result.is_shortened is True
        assert any("shortener" in f.lower() for f in result.risk_factors)

    @pytest.mark.asyncio
    async def test_analyze_typosquat_url(self, analyzer):
        """Typosquatting URLs should be flagged."""
        result = await analyzer.analyze_url("https://paypa1.com/login")

        assert result.typosquat_target == "paypal"
        assert result.risk_level in (URLRiskLevel.MEDIUM, URLRiskLevel.HIGH, URLRiskLevel.CRITICAL)

    @pytest.mark.asyncio
    async def test_analyze_suspicious_tld(self, analyzer):
        """Suspicious TLDs should be flagged."""
        result = await analyzer.analyze_url("https://secure-login.tk")

        assert any(".tk" in f for f in result.risk_factors)
        assert result.risk_score > 0.1

    @pytest.mark.asyncio
    async def test_analyze_email_urls(self, analyzer):
        """Analyze all URLs in email content."""
        content = """
        Dear Customer,

        Your account needs verification. Click here:
        https://paypa1.com/verify

        Or visit our help page:
        https://support.microsoft.com/help

        Best,
        Support Team
        """

        result = await analyzer.analyze_email_urls(content)

        assert result.urls_found == 2
        assert result.urls_analyzed == 2
        # paypa1.com should be flagged as typosquat
        assert any(r.typosquat_target == "paypal" for r in result.url_results)

    @pytest.mark.asyncio
    async def test_caching_behavior(self, analyzer):
        """Second analysis should use cache."""
        url = "https://example.com/test"

        result1 = await analyzer.analyze_url(url)
        assert result1.cached is False

        result2 = await analyzer.analyze_url(url)
        assert result2.cached is True

    @pytest.mark.asyncio
    async def test_empty_email_analysis(self, analyzer):
        """Handle email with no URLs."""
        result = await analyzer.analyze_email_urls("No links here.")

        assert result.urls_found == 0
        assert result.urls_analyzed == 0
        assert result.highest_risk_level == URLRiskLevel.SAFE


# ============================================================================
# Integration Tests
# ============================================================================

class TestURLAnalyzerIntegration:
    """Integration tests for production scenarios."""

    @pytest.mark.asyncio
    async def test_phishing_email_detection(self):
        """Full phishing email detection scenario."""
        analyzer = get_url_analyzer()

        phishing_email = """
        URGENT: Your PayPal Account Has Been Limited!

        Dear Valued Customer,

        We have noticed unusual activity on your account.
        Please verify your information immediately:

        https://paypa1.com/verify-account

        If you don't verify within 24 hours, your account will be suspended.

        Click here if the above link doesn't work:
        http://192.168.1.100/paypal/login.php

        PayPal Security Team
        """

        result = await analyzer.analyze_email_urls(phishing_email)

        # Should detect both malicious URLs
        assert result.urls_found >= 2
        # At least one should be typosquat, one should be IP-based
        assert any(r.typosquat_target == "paypal" for r in result.url_results)
        assert any(r.is_ip_based for r in result.url_results)
        assert result.aggregate_risk_score > 0.3

    @pytest.mark.asyncio
    async def test_legitimate_email(self):
        """Legitimate email should have low risk."""
        analyzer = get_url_analyzer()

        legitimate_email = """
        Hi Team,

        Here's the meeting link:
        https://zoom.us/j/123456789

        You can also check the docs here:
        https://docs.google.com/document/d/abc123

        Best,
        Alice
        """

        result = await analyzer.analyze_email_urls(legitimate_email)

        assert result.high_risk_urls == 0
        assert result.highest_risk_level in (URLRiskLevel.SAFE, URLRiskLevel.LOW)

    @pytest.mark.asyncio
    async def test_concurrent_analysis(self):
        """Test concurrent URL analysis performance."""
        analyzer = get_url_analyzer()

        # Create 20 different URLs
        urls = [f"https://site{i}.com/page" for i in range(20)]
        content = " ".join(urls)

        result = await analyzer.analyze_email_urls(content, max_urls=20)

        assert result.urls_analyzed == 20
        assert result.analysis_time_ms < 5000  # Should complete in under 5s


# ============================================================================
# Performance Tests
# ============================================================================

class TestURLAnalyzerPerformance:
    """Performance and load tests."""

    @pytest.mark.asyncio
    async def test_cache_improves_performance(self):
        """Cached requests should be faster."""
        import time

        analyzer = URLAnalyzer(cache_ttl=60)
        url = "https://example.com/test"

        # First request (uncached)
        start = time.perf_counter()
        await analyzer.analyze_url(url)
        first_time = time.perf_counter() - start

        # Second request (cached)
        start = time.perf_counter()
        await analyzer.analyze_url(url)
        cached_time = time.perf_counter() - start

        # Cached should be faster
        assert cached_time < first_time

    @pytest.mark.asyncio
    async def test_batch_analysis_performance(self):
        """Batch URL analysis should complete in reasonable time."""
        analyzer = URLAnalyzer()

        # Simulate 50 emails with 5 URLs each
        emails = []
        for i in range(50):
            content = " ".join([f"https://site{i}_{j}.com" for j in range(5)])
            emails.append(content)

        start = time.perf_counter()

        # Analyze all emails
        tasks = [analyzer.analyze_email_urls(email) for email in emails]
        results = await asyncio.gather(*tasks)

        elapsed = time.perf_counter() - start

        # Should process 50 emails in under 10 seconds
        assert elapsed < 10.0
        assert all(r.urls_analyzed == 5 for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
