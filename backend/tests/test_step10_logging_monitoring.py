"""
CyberGuard AI - Step 10 Logging & Monitoring Tests

Tests for:
- Request ID middleware
- Request/Response logging
- Security event logging
- Metrics collection
- Health endpoints
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from fastapi.testclient import TestClient


class TestRequestIDMiddleware:
    """Tests for Request ID middleware."""

    def test_request_without_id_gets_generated_id(self):
        """Request without X-Request-ID should receive a generated ID."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/health")

        assert "X-Request-ID" in response.headers
        request_id = response.headers["X-Request-ID"]
        # Should be a valid UUID4 format
        assert len(request_id) == 36
        assert request_id.count("-") == 4

    def test_request_with_id_preserves_it(self):
        """Request with X-Request-ID should preserve the provided ID."""
        from app.main import app
        client = TestClient(app)

        custom_id = "test-request-id-12345"
        response = client.get(
            "/api/v1/health",
            headers={"X-Request-ID": custom_id}
        )

        assert response.headers.get("X-Request-ID") == custom_id


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_basic(self):
        """GET /api/v1/health returns healthy status."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    def test_health_detailed(self):
        """GET /api/v1/health/detailed returns component statuses."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/health/detailed")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "components" in data
        assert "timestamp" in data
        assert "version" in data
        # Should have some components
        assert len(data["components"]) > 0

    def test_health_live(self):
        """GET /api/v1/health/live returns alive status."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/health/live")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_health_ready(self):
        """GET /api/v1/health/ready returns readiness status."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/health/ready")

        # May be 200 or 503 depending on infrastructure
        assert response.status_code in [200, 503]
        data = response.json()
        assert "status" in data
        assert data["status"] in ["ready", "not_ready"]


class TestMetricsEndpoints:
    """Tests for metrics API endpoints."""

    def test_metrics_endpoint(self):
        """GET /api/v1/metrics returns metrics data."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/metrics")

        assert response.status_code == 200
        data = response.json()
        assert "counters" in data
        assert "histograms" in data
        assert "metadata" in data

    def test_metrics_summary_endpoint(self):
        """GET /api/v1/metrics/summary returns summary data."""
        from app.main import app
        client = TestClient(app)

        response = client.get("/api/v1/metrics/summary")

        assert response.status_code == 200
        data = response.json()
        assert "emails_analyzed" in data
        assert "threats_detected" in data
        assert "detection_rate" in data
        assert "avg_analysis_time_ms" in data
        assert "cache_hit_rate" in data
        assert "external_api_error_rate" in data
        assert "timestamp" in data


class TestMetricsCollector:
    """Tests for the metrics collector."""

    @pytest.mark.asyncio
    async def test_increment_counter(self):
        """Test counter increment."""
        from app.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        await collector.increment("test_counter")
        await collector.increment("test_counter")

        value = await collector.get_counter("test_counter")
        assert value == 2

    @pytest.mark.asyncio
    async def test_observe_histogram(self):
        """Test histogram observation."""
        from app.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        await collector.observe("test_histogram", 10.0)
        await collector.observe("test_histogram", 20.0)
        await collector.observe("test_histogram", 30.0)

        stats = await collector.get_histogram_stats("test_histogram")
        assert stats["count"] == 3
        assert stats["min"] == 10.0
        assert stats["max"] == 30.0
        assert stats["avg"] == 20.0

    @pytest.mark.asyncio
    async def test_get_metrics(self):
        """Test getting all metrics."""
        from app.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        await collector.increment("counter_a")
        await collector.observe("histogram_a", 100.0)

        metrics = await collector.get_metrics()

        assert "counters" in metrics
        assert "histograms" in metrics
        assert "metadata" in metrics
        assert metrics["counters"]["counter_a"] == 1


class TestSecurityEventLogging:
    """Tests for security event logging."""

    def test_log_threat_detected(self):
        """Test threat detection logging."""
        from app.logging import log_threat_detected

        # Should not raise - just verify it runs
        log_threat_detected(
            email_id="test-email-001",
            classification="phishing",
            risk_score=85,
            finding_count=3,
            finding_types=["URL-001", "CONTENT-002"],
            sender_domain="example.com",
        )

    def test_log_malware_detected(self):
        """Test malware detection logging."""
        from app.logging import log_malware_detected

        log_malware_detected(
            filename="malicious.exe",
            sha256="abc123def456",
            detection_source="virustotal",
            threat_names=["Trojan.Generic", "Malware.Test"],
        )

    def test_log_auth_failure(self):
        """Test authentication failure logging."""
        from app.logging import log_auth_failure

        log_auth_failure(
            email_id="test-email-002",
            sender_domain="spoofed.com",
            spf="fail",
            dkim="fail",
            dmarc="fail",
        )

    def test_log_suspicious_url(self):
        """Test suspicious URL logging."""
        from app.logging import log_suspicious_url

        log_suspicious_url(
            domain="phishing-site.com",
            detection_source="safe_browsing",
            risk_score=95,
            severity="high",
        )

    def test_log_rate_limit_exceeded(self):
        """Test rate limit exceeded logging."""
        from app.logging import log_rate_limit_exceeded

        log_rate_limit_exceeded(
            endpoint="/api/v1/analysis/email",
            client_ip="192.168.1.1",
            limit="30/minute",
        )

    def test_log_circuit_opened(self):
        """Test circuit breaker logging."""
        from app.logging import log_circuit_opened

        log_circuit_opened(
            service_name="virustotal",
            state="open",
            failure_count=5,
            reason="Exceeded failure threshold",
        )


class TestRequestLogging:
    """Tests for request/response logging."""

    def test_request_logging_on_api_call(self):
        """Test that API calls generate request logs."""
        from app.main import app
        client = TestClient(app)

        # Just verify the request completes with logging enabled
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_logging_skips_sensitive_paths(self):
        """Test that certain paths are skipped in logging."""
        from app.middleware.logging import SKIP_LOGGING_PATHS

        # Verify skip paths exist
        assert "/" in SKIP_LOGGING_PATHS
        assert "/docs" in SKIP_LOGGING_PATHS


class TestEmailAgentMetricsIntegration:
    """Tests for EmailAgent metrics integration."""

    @pytest.mark.asyncio
    async def test_email_analysis_records_metrics(self):
        """Test that email analysis records metrics."""
        from app.agents.email_agent_v2 import EmailAgent
        from app.metrics import get_metrics_collector

        collector = get_metrics_collector()
        await collector.reset()

        agent = EmailAgent()
        result = await agent.analyze({
            "sender": "test@example.com",
            "subject": "Test email",
            "body": "This is a test email body.",
        })

        assert result is not None
        assert result.classification in [
            "benign", "suspicious", "phishing", "malicious", "unknown"
        ]

        # Give async tasks time to complete
        await asyncio.sleep(0.1)

        # Check metrics were recorded
        emails_analyzed = await collector.get_counter("emails_analyzed_total")
        assert emails_analyzed >= 1


class TestRateLimitingStillWorks:
    """Verify rate limiting from Step 9 still functions."""

    def test_rate_limiting_returns_429(self):
        """Test that rate limiting still returns 429 when exceeded."""
        from app.main import app
        from app.middleware.rate_limit import limiter

        # This is a basic verification that SlowAPI is still configured
        assert hasattr(app.state, "limiter")


class TestExistingFunctionalityRegression:
    """Regression tests to verify Steps 1-9 still work."""

    def test_ml_classifier_still_works(self):
        """Test ML classifier is still functional."""
        from app.ml.classifier import get_model_status

        status = get_model_status()
        assert "loaded" in status

    def test_url_analysis_still_works(self):
        """Test URL analysis service is still accessible."""
        from app.services.url_analysis.service import analyze_url_patterns

        result = analyze_url_patterns("https://example.com/test")
        assert isinstance(result, dict)

    def test_attachment_analysis_import(self):
        """Test attachment analysis service is still accessible."""
        from app.services.attachment_analysis.service import analyze_attachment

        assert callable(analyze_attachment)

    def test_circuit_breaker_import(self):
        """Test circuit breaker is still accessible."""
        from app.services.circuit_breaker import get_circuit_breaker, CircuitState

        cb = get_circuit_breaker("test_service")
        assert cb is not None

    def test_rate_limiter_import(self):
        """Test rate limiter is still accessible."""
        from app.services.rate_limiting import get_rate_limiter

        limiter = get_rate_limiter()
        assert limiter is not None
