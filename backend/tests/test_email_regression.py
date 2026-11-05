"""
CyberGuard AI - Email Analysis Regression Tests

Comprehensive test suite for the email security agent.
Tests validate proper detection, categorization, and scoring.

Run with: pytest backend/tests/test_email_regression.py -v
"""

import pytest
import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

# Import the v2 agent
from app.agents.email_agent_v2 import EmailAgent
from app.core.email_enums import (
    Verdict,
    URLCategory,
    AnalysisStatus,
    BrandDetectionType,
)
from app.core.domain_utils import (
    extract_domain_info,
    classify_url,
    is_url_shortener,
    is_suspicious_tld,
    is_legitimate_brand_domain,
)


# =============================================================================
# Test Fixtures
# =============================================================================

# These are classification/scoring regression tests, not live third-party
# API tests. Without this mock, every test touching a URL makes a real
# outbound call to VirusTotal and AbuseIPDB (both have real API keys
# configured in .env) with a 30s httpx timeout each. That made the full
# suite stall for minutes per test and, under CI/sandboxed network
# conditions, can hang well past any reasonable per-test timeout - this is
# what caused the backend test suite to appear to stall indefinitely.
#
# check_url_reputation/check_urls are patched at their point of use inside
# app.services.url_analysis.service (not at their definition module) since
# that module imported them by name with `from ... import ...`, which binds
# the name in its own namespace - patching the origin module would not
# affect calls made through app.services.url_analysis.service.analyze_url.
#
# The mocked return values match exactly what these functions already
# return in production when no threat-intel signal is available (e.g. no
# API key configured, or a clean/unknown verdict) - no assertion in this
# file is about VirusTotal/AbuseIPDB/Safe Browsing behavior, so this does
# not weaken what these tests actually verify (SPF/DKIM/DMARC handling,
# brand impersonation, URL pattern/category detection, risk scoring from
# local signals).
#
# Live, unmocked verification of the real VirusTotal/AbuseIPDB/Safe
# Browsing integration belongs in a dedicated opt-in integration test
# (see tests/test_step71_redpanda_live.py for the established pattern of
# gating real external calls behind an env var), not in this file.
@pytest.fixture(autouse=True)
def mock_external_threat_intel():
    """Prevent email classification tests from making real network calls
    to VirusTotal/AbuseIPDB/Safe Browsing."""
    reputation_response = {
        "configured": False,
        "url": "",
        "status": "unknown",
        "is_malicious": False,
        "risk_score": 0,
        "sources": [],
        "details": {},
        "error": None,
        "cache_hit": False,
    }
    safe_browsing_response = {
        "configured": False,
        "checked": 0,
        "threats": [],
        "error": None,
        "cache_hit": False,
    }

    async def fake_check_url_reputation(url: str) -> dict:
        return {**reputation_response, "url": url}

    async def fake_check_urls(urls: list[str]) -> dict:
        return dict(safe_browsing_response)

    with patch(
        "app.services.url_analysis.service.check_url_reputation",
        side_effect=fake_check_url_reputation,
    ), patch(
        "app.services.url_analysis.service.check_urls",
        side_effect=fake_check_urls,
    ):
        yield


@pytest.fixture
def agent():
    """Create an EmailAgent instance for testing."""
    return EmailAgent()


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def run_analysis(agent: EmailAgent, data: dict) -> dict:
    """Run email analysis synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(agent.analyze(data))
        return result.model_dump() if hasattr(result, 'model_dump') else result.__dict__
    finally:
        loop.close()


# =============================================================================
# TEST 1: Legitimate OpenAI Email
# =============================================================================

class TestLegitimateOpenAIEmail:
    """Test that legitimate OpenAI emails are classified as benign."""

    TEST_DATA = {
        "sender": "no-reply@openai.com",
        "subject": "Your API usage report for September 2024",
        "body": """Hi there,

Your monthly API usage report is ready. Here's a summary:

- Total API calls: 125,432
- Total tokens: 45.2M
- Cost: $127.50

View your full usage report at: https://platform.openai.com/account/usage

Best,
The OpenAI Team

To manage your email preferences, visit: https://platform.openai.com/account/settings
""",
        "headers": {
            "From": "OpenAI <no-reply@openai.com>",
            "Reply-To": "no-reply@openai.com",
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
    }

    def test_classification_is_benign(self, agent):
        """Legitimate OpenAI email should be benign."""
        result = run_analysis(agent, self.TEST_DATA)
        assert result["classification"] in ["benign", "suspicious"]
        # Should not be phishing or malicious
        assert result["classification"] not in ["phishing", "malicious"]

    def test_low_risk_score(self, agent):
        """Risk score should be low."""
        result = run_analysis(agent, self.TEST_DATA)
        assert result["risk_score"] < 30, f"Risk score {result['risk_score']} too high for legitimate email"

    def test_no_brand_impersonation_finding(self, agent):
        """Should NOT flag as brand impersonation."""
        result = run_analysis(agent, self.TEST_DATA)
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        assert not any("impersonation" in name for name in finding_names), \
            "Legitimate OpenAI email should not trigger impersonation"

    def test_urls_not_flagged_as_malicious(self, agent):
        """OpenAI URLs should not be flagged as malicious."""
        result = run_analysis(agent, self.TEST_DATA)
        for finding in result.get("findings", []):
            if "URL" in finding.get("name", ""):
                assert finding.get("severity") not in ["critical", "high"], \
                    f"OpenAI URL should not be high severity: {finding}"


# =============================================================================
# TEST 2: Legitimate Newsletter
# =============================================================================

class TestLegitimateNewsletter:
    """Test that legitimate newsletters are not flagged as phishing."""

    TEST_DATA = {
        "sender": "newsletter@techcrunch.com",
        "subject": "TechCrunch Daily: AI Funding Hits Record High",
        "body": """Good morning!

Here's what's happening in tech today:

📰 Top Stories:
1. OpenAI raises $6B in new funding round
2. Google announces Pixel 9 with advanced AI features
3. Microsoft Teams gets major update

Read more: https://techcrunch.com/daily-digest

Tracking pixel: https://links.techcrunch.com/track/click/abc123

---
You're receiving this because you subscribed to TechCrunch Daily.
Unsubscribe: https://techcrunch.com/unsubscribe?email=user@example.com
Manage preferences: https://techcrunch.com/email-preferences
""",
        "headers": {
            "From": "TechCrunch <newsletter@techcrunch.com>",
            "List-Unsubscribe": "<https://techcrunch.com/unsubscribe>",
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
    }

    def test_classification_is_benign(self, agent):
        """Newsletter should be classified as benign."""
        result = run_analysis(agent, self.TEST_DATA)
        assert result["classification"] in ["benign", "suspicious"]
        assert result["classification"] != "phishing"

    def test_tracking_url_not_flagged_as_ioc(self, agent):
        """Tracking URLs should not be flagged as IOCs."""
        result = run_analysis(agent, self.TEST_DATA)
        indicators = result.get("indicators", [])
        # Tracking domains should not be in IOCs
        assert not any("track" in ioc.lower() for ioc in indicators), \
            "Tracking URLs should not be classified as IOCs"

    def test_unsubscribe_is_trust_signal(self, agent):
        """Unsubscribe link should be recognized (not flagged as suspicious)."""
        result = run_analysis(agent, self.TEST_DATA)
        # With unsubscribe links present, the email should still be benign/suspicious
        # and not be classified as phishing
        assert result["classification"] != "phishing"
        assert result["risk_score"] < 50


# =============================================================================
# TEST 3: Legitimate Tracking URL
# =============================================================================

class TestLegitimateTrackingURL:
    """Test that tracking URLs are properly categorized."""

    def test_mailchimp_tracking_url(self):
        """Mailchimp tracking URL should be categorized as TRACKING."""
        url = "https://click.mailchimp.com/track/click/30012345.67890/aHR0cHM6Ly9leGFtcGxlLmNvbQ"
        category, _ = classify_url(url)
        assert category == URLCategory.TRACKING

    def test_sendgrid_tracking_url(self):
        """SendGrid tracking URL should be categorized as TRACKING."""
        url = "https://u12345.ct.sendgrid.net/ls/click?upn=abc123xyz"
        category, _ = classify_url(url)
        assert category == URLCategory.TRACKING

    def test_hubspot_tracking_url(self):
        """HubSpot tracking URL should be categorized as TRACKING."""
        url = "https://track.hubspot.com/__tracking/click/12345"
        # Note: This tests the domain matching logic
        domain_info = extract_domain_info(url)
        assert domain_info is not None
        assert "hubspot" in domain_info.registered_domain


# =============================================================================
# TEST 4: Legitimate CDN URL
# =============================================================================

class TestLegitimateCDNURL:
    """Test that CDN URLs are properly categorized and not flagged."""

    def test_cloudfront_cdn(self):
        """CloudFront CDN URL should be categorized as CDN."""
        url = "https://d1234567890.cloudfront.net/images/logo.png"
        category, _ = classify_url(url)
        assert category == URLCategory.CDN

    def test_cloudflare_cdn(self):
        """Cloudflare CDN URL should be categorized as CDN."""
        url = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
        category, _ = classify_url(url)
        assert category == URLCategory.CDN

    def test_akamai_cdn(self):
        """Akamai CDN URL should be categorized as CDN."""
        url = "https://a1234.akamaihd.net/assets/bundle.js"
        category, _ = classify_url(url)
        assert category == URLCategory.CDN

    def test_cdn_url_not_ioc(self, agent):
        """CDN URLs should not be promoted to IOCs."""
        data = {
            "sender": "marketing@company.com",
            "subject": "Check out our new product",
            "body": """
            See the product image: https://d1234567890.cloudfront.net/products/new.png
            """,
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        }
        result = run_analysis(agent, data)
        indicators = result.get("indicators", [])
        assert not any("cloudfront.net" in ioc for ioc in indicators)


# =============================================================================
# TEST 5: Known URL Shortener
# =============================================================================

class TestKnownURLShortener:
    """Test that known URL shorteners are properly detected."""

    def test_bitly_is_shortener(self):
        """bit.ly should be detected as URL shortener."""
        assert is_url_shortener("https://bit.ly/abc123")

    def test_tinyurl_is_shortener(self):
        """tinyurl.com should be detected as URL shortener."""
        assert is_url_shortener("https://tinyurl.com/y1234567")

    def test_t_co_is_shortener(self):
        """t.co (Twitter) should be detected as URL shortener."""
        assert is_url_shortener("https://t.co/abcXYZ123")

    def test_long_url_not_shortener(self):
        """Long URL with query params should NOT be classified as shortener."""
        url = "https://www.example.com/products/electronics/smartphones/iphone-15?color=blue&size=256gb&utm_source=email&utm_medium=newsletter&utm_campaign=fall2024"
        assert not is_url_shortener(url)

    def test_redirect_url_not_shortener(self):
        """URL with redirect parameter should NOT be classified as shortener."""
        url = "https://auth.example.com/login?redirect=https://dashboard.example.com/home"
        assert not is_url_shortener(url)

    def test_shortener_category(self):
        """Shortener should be categorized correctly."""
        url = "https://bit.ly/3xyz123"
        category, _ = classify_url(url)
        assert category == URLCategory.SHORTENER


# =============================================================================
# TEST 6: Suspicious TLD
# =============================================================================

class TestSuspiciousTLD:
    """Test that suspicious TLDs are properly detected."""

    def test_xyz_is_suspicious(self):
        """The .xyz TLD should be flagged as suspicious."""
        domain_info = extract_domain_info("https://login-secure.xyz")
        assert domain_info is not None
        assert is_suspicious_tld(domain_info)

    def test_top_is_suspicious(self):
        """The .top TLD should be flagged as suspicious."""
        domain_info = extract_domain_info("https://account-verify.top")
        assert domain_info is not None
        assert is_suspicious_tld(domain_info)

    def test_com_is_not_suspicious(self):
        """The .com TLD should NOT be flagged as suspicious."""
        domain_info = extract_domain_info("https://example.com")
        assert domain_info is not None
        assert not is_suspicious_tld(domain_info)

    def test_org_is_not_suspicious(self):
        """The .org TLD should NOT be flagged as suspicious."""
        domain_info = extract_domain_info("https://wikipedia.org")
        assert domain_info is not None
        assert not is_suspicious_tld(domain_info)

    def test_co_uk_is_not_suspicious(self):
        """The .co.uk TLD should NOT be flagged as suspicious."""
        domain_info = extract_domain_info("https://bbc.co.uk")
        assert domain_info is not None
        assert not is_suspicious_tld(domain_info)


# =============================================================================
# TEST 7: Brand Mention (not impersonation)
# =============================================================================

class TestBrandMention:
    """Test that brand mentions are NOT flagged as impersonation."""

    def test_news_about_microsoft_not_impersonation(self, agent):
        """News article mentioning Microsoft should not be impersonation."""
        data = {
            "sender": "news@techsite.com",
            "subject": "Microsoft announces new AI features",
            "body": """
            Microsoft announced today that it will be releasing new AI features
            for its Office suite. The company said the features will be available
            to all Microsoft 365 subscribers by the end of the year.

            Read more at: https://techsite.com/news/microsoft-ai-features
            """,
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        }
        result = run_analysis(agent, data)
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        assert not any("impersonation" in name for name in finding_names)

    def test_forum_discussing_google_not_impersonation(self, agent):
        """Forum email discussing Google should not be impersonation."""
        data = {
            "sender": "notifications@forum.dev",
            "subject": "Re: Google Cloud vs AWS pricing",
            "body": """
            User replied to your thread:

            "I've been using Google Cloud for 2 years now. Their pricing is
            competitive with AWS, but I find the Google console easier to use."

            View discussion: https://forum.dev/thread/12345
            """,
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        }
        result = run_analysis(agent, data)
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        assert not any("impersonation" in name for name in finding_names)


# =============================================================================
# TEST 8: Brand Impersonation
# =============================================================================

class TestBrandImpersonation:
    """Test that actual brand impersonation IS detected."""

    def test_fake_paypal_impersonation(self, agent):
        """Fake PayPal email should trigger impersonation detection."""
        data = {
            "sender": "security@paypa1-secure.xyz",  # Note: paypa1 with number
            "subject": "Your PayPal account has been limited",
            "body": """
            Dear PayPal Customer,

            We've noticed unusual activity on your PayPal account.
            Your account access has been limited until you verify your identity.

            Please verify your account immediately to restore access:
            https://paypa1-secure.xyz/verify-account

            If you don't verify within 24 hours, your account will be suspended.

            PayPal Security Team
            """,
            "authentication": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        }
        result = run_analysis(agent, data)

        # Should detect impersonation or phishing
        assert result["classification"] in ["phishing", "malicious", "suspicious"]
        assert result["risk_score"] >= 40

        # Should have impersonation-related finding
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_impersonation = any("impersonation" in name or "paypal" in name for name in finding_names)
        assert has_impersonation, f"Should detect PayPal impersonation. Findings: {finding_names}"


# =============================================================================
# TEST 9: Reply-To Mismatch
# =============================================================================

class TestReplyToMismatch:
    """Test Reply-To header mismatch detection."""

    def test_reply_to_mismatch_detected(self, agent):
        """Different Reply-To domain should be detected."""
        data = {
            "sender": "ceo@company.com",
            "subject": "Urgent wire transfer needed",
            "body": """
            Hi,

            I need you to process an urgent wire transfer of $50,000
            to our new vendor. Please reply to confirm.

            Thanks,
            CEO
            """,
            "headers": {
                "From": "CEO <ceo@company.com>",
                "Reply-To": "ceo.urgent@gmail.com",  # Different domain!
            },
        }
        result = run_analysis(agent, data)

        # Should detect Reply-To mismatch
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_reply_to_finding = any("reply-to" in name for name in finding_names)
        assert has_reply_to_finding, "Should detect Reply-To domain mismatch"

    def test_same_domain_reply_to_ok(self, agent):
        """Same domain Reply-To should not trigger finding."""
        data = {
            "sender": "sales@company.com",
            "subject": "Your order confirmation",
            "body": "Thank you for your order.",
            "headers": {
                "From": "Sales <sales@company.com>",
                "Reply-To": "support@company.com",  # Same domain
            },
        }
        result = run_analysis(agent, data)

        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_reply_to_finding = any("reply-to" in name for name in finding_names)
        assert not has_reply_to_finding, "Same-domain Reply-To should not trigger alert"


# =============================================================================
# TEST: Header domain bracket stripping (regression for stray ">" leaking
# into finding evidence, e.g. "mykeymate.com>")
# =============================================================================

class TestHeaderDomainBracketStripping:
    """Regression test for the mykeymate.com> evidence-text bug: finding
    evidence must show the clean registered domain, not a raw bracketed
    header value with a trailing '>'."""

    def test_reply_to_mismatch_evidence_has_no_angle_bracket(self, agent):
        data = {
            "sender": "ceo@company.com",
            "subject": "test",
            "body": "test",
            "headers": {
                "From": "CEO <ceo@company.com>",
                "Reply-To": "<attacker@mykeymate.com>",
            },
        }
        result = run_analysis(agent, data)
        evidence_text = " ".join(
            e for f in result.get("findings", []) for e in f.get("evidence", [])
        )
        assert ">" not in evidence_text
        assert "mykeymate.com" in evidence_text

    def test_return_path_mismatch_evidence_has_no_angle_bracket(self, agent):
        data = {
            "sender": "ceo@company.com",
            "subject": "test",
            "body": "test",
            "headers": {
                "From": "<ceo@company.com>",
                "Return-Path": "<bounce@mykeymate.com>",
            },
        }
        result = run_analysis(agent, data)
        evidence_text = " ".join(
            e for f in result.get("findings", []) for e in f.get("evidence", [])
        )
        assert ">" not in evidence_text
        assert "mykeymate.com" in evidence_text


# =============================================================================
# TEST 10: SPF Failure
# =============================================================================

class TestSPFFailure:
    """Test SPF failure detection."""

    def test_spf_fail_detected(self, agent):
        """SPF failure should be detected and raise risk."""
        data = {
            "sender": "important@bank.com",
            "subject": "Account statement",
            "body": "Your monthly statement is attached.",
            "authentication": {
                "spf": "fail",
                "dkim": "pass",
                "dmarc": "pass",
            },
        }
        result = run_analysis(agent, data)

        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_spf_finding = any("spf" in name and "fail" in name for name in finding_names)
        assert has_spf_finding, "Should detect SPF failure"

    def test_spf_pass_is_trust_signal(self, agent):
        """SPF pass should contribute to lower risk score."""
        data = {
            "sender": "newsletter@company.com",
            "subject": "Weekly update",
            "body": "Here's your weekly update.",
            "authentication": {
                "spf": "pass",
                "dkim": "pass",
                "dmarc": "pass",
            },
        }
        result = run_analysis(agent, data)
        # With all auth passing, risk should be low
        assert result["risk_score"] < 20, "All auth passing should keep risk low"
        # Should not have auth failure findings
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        assert not any("fail" in name for name in finding_names)


# =============================================================================
# TEST 11: DKIM Failure
# =============================================================================

class TestDKIMFailure:
    """Test DKIM failure detection."""

    def test_dkim_fail_detected(self, agent):
        """DKIM failure should be detected."""
        data = {
            "sender": "sender@company.com",
            "subject": "Important document",
            "body": "Please review the attached document.",
            "authentication": {
                "spf": "pass",
                "dkim": "fail",
                "dmarc": "pass",
            },
        }
        result = run_analysis(agent, data)

        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_dkim_finding = any("dkim" in name and "fail" in name for name in finding_names)
        assert has_dkim_finding, "Should detect DKIM failure"


# =============================================================================
# TEST 12: DMARC Failure
# =============================================================================

class TestDMARCFailure:
    """Test DMARC failure detection."""

    def test_dmarc_fail_detected(self, agent):
        """DMARC failure should be detected as high severity."""
        data = {
            "sender": "sender@company.com",
            "subject": "Account update required",
            "body": "Please update your account information.",
            "authentication": {
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
            },
        }
        result = run_analysis(agent, data)

        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_dmarc_finding = any("dmarc" in name and "fail" in name for name in finding_names)
        assert has_dmarc_finding, "Should detect DMARC failure"

        # DMARC fail should significantly increase risk
        assert result["risk_score"] >= 25, "DMARC failure should increase risk score"


# =============================================================================
# TEST 13: Credential Phishing
# =============================================================================

class TestCredentialPhishing:
    """Test credential phishing detection."""

    def test_credential_phishing_detected(self, agent):
        """Credential phishing email should be detected."""
        data = {
            "sender": "security@account-verify.xyz",
            "subject": "URGENT: Verify your account now",
            "body": """
            Dear Customer,

            We detected suspicious activity on your account. Your account will be
            suspended within 24 hours unless you verify your identity.

            Click here to verify: https://account-verify.xyz/login

            Please enter your username and password to confirm your identity.

            If you don't verify immediately, you will lose access to your account.

            Security Team
            """,
            "authentication": {
                "spf": "none",
                "dkim": "none",
                "dmarc": "none",
            },
        }
        result = run_analysis(agent, data)

        # Should be classified as phishing
        assert result["classification"] in ["phishing", "malicious"]
        assert result["risk_score"] >= 50

        # Should detect credential request
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_credential_finding = any("credential" in name for name in finding_names)
        assert has_credential_finding, "Should detect credential request"


# =============================================================================
# TEST 14: Malicious URL
# =============================================================================

class TestMaliciousURL:
    """Test malicious URL detection."""

    def test_at_symbol_deception_detected(self, agent):
        """URL with @ symbol deception should be detected as malicious."""
        data = {
            "sender": "alerts@service.com",
            "subject": "Verify your account",
            "body": """
            Click here to verify: https://google.com@evil-site.xyz/steal-creds
            """,
        }
        result = run_analysis(agent, data)

        # Should detect malicious URL
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_malicious_url = any("malicious" in name or "deceptive" in name for name in finding_names)
        assert has_malicious_url, "Should detect @ symbol URL deception"

    def test_ip_based_url_flagged(self, agent):
        """IP-based URL should be flagged as suspicious."""
        data = {
            "sender": "sender@company.com",
            "subject": "Check this link",
            "body": """
            Click here: http://192.168.1.100/login/verify.php
            """,
        }
        result = run_analysis(agent, data)

        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        has_ip_url = any("ip" in name.lower() and "url" in name.lower() for name in finding_names)
        assert has_ip_url, "Should detect IP-based URL"


# =============================================================================
# Domain Parsing Tests
# =============================================================================

class TestDomainParsing:
    """Test proper domain extraction and TLD handling."""

    def test_simple_domain(self):
        """Test simple .com domain extraction."""
        info = extract_domain_info("https://example.com/path")
        assert info is not None
        assert info.registered_domain == "example.com"
        assert info.public_suffix == "com"

    def test_subdomain_extraction(self):
        """Test subdomain extraction."""
        info = extract_domain_info("https://mail.google.com/inbox")
        assert info is not None
        assert info.registered_domain == "google.com"
        assert info.subdomain == "mail"

    def test_multi_part_suffix(self):
        """Test multi-part TLD like .co.uk."""
        info = extract_domain_info("https://www.bbc.co.uk/news")
        assert info is not None
        assert info.registered_domain == "bbc.co.uk"
        assert info.public_suffix == "co.uk"

    def test_ip_address(self):
        """Test IP address detection."""
        info = extract_domain_info("http://192.168.1.1/admin")
        assert info is not None
        assert info.is_ip is True
        assert info.full_domain == "192.168.1.1"


# =============================================================================
# Summary Test Report
# =============================================================================

class TestSummaryReport:
    """Generate a summary report of test results."""

    def test_run_all_and_report(self, agent, capsys):
        """Run key scenarios and print summary."""
        scenarios = [
            ("Legitimate OpenAI email", TestLegitimateOpenAIEmail.TEST_DATA, ["benign"]),
            ("Legitimate newsletter", TestLegitimateNewsletter.TEST_DATA, ["benign", "suspicious"]),
            ("Credential phishing", TestCredentialPhishing().test_credential_phishing_detected.__doc__, None),
        ]

        print("\n" + "=" * 60)
        print("EMAIL ANALYSIS TEST SUMMARY")
        print("=" * 60)

        # Run legitimate OpenAI
        result = run_analysis(agent, TestLegitimateOpenAIEmail.TEST_DATA)
        openai_pass = result["classification"] in ["benign", "suspicious"]
        print(f"✓ Legitimate OpenAI: {result['classification']} (score: {result['risk_score']})" if openai_pass else f"✗ Legitimate OpenAI: {result['classification']}")

        # Run newsletter
        result = run_analysis(agent, TestLegitimateNewsletter.TEST_DATA)
        newsletter_pass = result["classification"] in ["benign", "suspicious"]
        print(f"✓ Legitimate newsletter: {result['classification']} (score: {result['risk_score']})" if newsletter_pass else f"✗ Newsletter: {result['classification']}")

        print("=" * 60)

        # This test always passes - it's just for reporting
        assert True


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
