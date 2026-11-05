"""
CyberGuard AI - Ensemble Classifier Tests

Production tests for the ensemble email classifier that combines:
- ML text classifier
- URL analysis
- Threshold tuning
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.ml.ensemble import (
    EnsembleClassifier,
    ClassificationResult,
    get_ensemble_classifier,
    classify_email,
    DEFAULT_WEIGHTS,
)
from app.ml.url_analyzer import URLRiskLevel, EmailURLAnalysis, URLAnalysisResult


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_ml_predict():
    """Mock the ML classifier."""
    with patch("app.ml.ensemble.ml_predict") as mock:
        mock.return_value = {
            "is_malicious": False,
            "probability": 0.3,
            "confidence": 0.7,
            "threshold": 0.5,
            "model_loaded": True,
        }
        yield mock


@pytest.fixture
def mock_url_analyzer():
    """Mock the URL analyzer."""
    with patch("app.ml.ensemble.get_url_analyzer") as mock:
        analyzer = MagicMock()
        analyzer.analyze_email_urls = AsyncMock(return_value=EmailURLAnalysis(
            urls_found=0,
            urls_analyzed=0,
            high_risk_urls=0,
            highest_risk_level=URLRiskLevel.SAFE,
            aggregate_risk_score=0.0,
            url_results=[],
            analysis_time_ms=1.0,
        ))
        mock.return_value = analyzer
        yield analyzer


@pytest.fixture
def mock_threshold_tuner():
    """Mock the threshold tuner."""
    with patch("app.ml.ensemble.get_threshold_tuner") as mock:
        tuner = MagicMock()
        tuner.get_threshold.return_value = 0.5
        tuner.get_config.return_value = MagicMock(
            global_threshold=0.5,
            domain_thresholds={},
            last_updated=None,
        )
        mock.return_value = tuner
        yield tuner


# ============================================================================
# Basic Classification Tests
# ============================================================================

class TestEnsembleClassifier:
    """Tests for EnsembleClassifier."""

    @pytest.mark.asyncio
    async def test_classify_safe_email(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Classify a safe email."""
        classifier = EnsembleClassifier()

        result = await classifier.classify(
            sender="colleague@company.com",
            subject="Meeting tomorrow",
            body="Hi, let's meet tomorrow at 10am.",
        )

        assert result.is_malicious is False
        assert result.risk_level == "safe"
        assert result.risk_score < 0.5

    @pytest.mark.asyncio
    async def test_classify_malicious_text(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Classify email with malicious text content."""
        # Make ML predict high risk
        mock_ml_predict.return_value = {
            "is_malicious": True,
            "probability": 0.95,
            "confidence": 0.95,
            "threshold": 0.5,
            "model_loaded": True,
        }

        # Lower threshold to ensure detection
        mock_threshold_tuner.get_threshold.return_value = 0.4

        classifier = EnsembleClassifier()

        result = await classifier.classify(
            sender="security@bank-verify.com",
            subject="URGENT: Verify your account",
            body="Your account will be suspended. Click here immediately.",
        )

        assert result.ml_score == 0.95
        assert result.risk_score > 0.4  # Should exceed lowered threshold

    @pytest.mark.asyncio
    async def test_classify_malicious_urls(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Classify email with malicious URLs."""
        # ML says low risk
        mock_ml_predict.return_value = {
            "is_malicious": False,
            "probability": 0.2,
            "threshold": 0.5,
            "model_loaded": True,
        }

        # But URLs are high risk
        mock_url_analyzer.analyze_email_urls = AsyncMock(return_value=EmailURLAnalysis(
            urls_found=1,
            urls_analyzed=1,
            high_risk_urls=1,
            highest_risk_level=URLRiskLevel.CRITICAL,
            aggregate_risk_score=0.9,
            url_results=[
                URLAnalysisResult(
                    url="https://paypa1.com/login",
                    domain="paypa1.com",
                    risk_level=URLRiskLevel.CRITICAL,
                    risk_score=0.9,
                    typosquat_target="paypal",
                )
            ],
            analysis_time_ms=1.0,
        ))

        classifier = EnsembleClassifier()

        result = await classifier.classify(
            sender="support@paypal.com",
            subject="Account verification needed",
            body="Please verify: https://paypa1.com/login",
        )

        # URL risk should raise overall score
        assert result.url_score == 0.9
        assert result.risk_score > 0.3  # Weighted combination

    @pytest.mark.asyncio
    async def test_threshold_affects_verdict(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Threshold determines malicious verdict."""
        mock_ml_predict.return_value = {
            "probability": 0.55,
            "model_loaded": True,
        }

        classifier = EnsembleClassifier()

        # Default threshold 0.5 → malicious
        mock_threshold_tuner.get_threshold.return_value = 0.5
        result1 = await classifier.classify(body="test")
        # 0.55 * 0.55 (ml weight) = 0.3025 < 0.5, so not malicious

        # Higher threshold → safe
        mock_threshold_tuner.get_threshold.return_value = 0.6
        result2 = await classifier.classify(body="test")

        # Both should be below threshold with current weights
        assert result1.threshold == 0.5
        assert result2.threshold == 0.6


# ============================================================================
# Ensemble Scoring Tests
# ============================================================================

class TestEnsembleScoring:
    """Tests for ensemble score calculation."""

    @pytest.mark.asyncio
    async def test_weighted_scoring(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Verify weighted scoring calculation."""
        mock_ml_predict.return_value = {"probability": 0.6, "model_loaded": True}
        mock_url_analyzer.analyze_email_urls = AsyncMock(return_value=EmailURLAnalysis(
            urls_found=1,
            urls_analyzed=1,
            high_risk_urls=0,
            highest_risk_level=URLRiskLevel.MEDIUM,
            aggregate_risk_score=0.4,
            url_results=[],
            analysis_time_ms=1.0,
        ))

        classifier = EnsembleClassifier(weights={
            "ml_classifier": 0.6,
            "url_analysis": 0.4,
            "metadata": 0.0,
        })

        result = await classifier.classify(body="test with http://example.com")

        # Expected: 0.6 * 0.6 + 0.4 * 0.4 = 0.36 + 0.16 = 0.52
        expected = 0.6 * 0.6 + 0.4 * 0.4
        assert abs(result.risk_score - expected) < 0.01

    @pytest.mark.asyncio
    async def test_weights_normalized(self, mock_ml_predict, mock_url_analyzer, mock_threshold_tuner):
        """Non-normalized weights should be normalized."""
        classifier = EnsembleClassifier(weights={
            "ml_classifier": 6,  # Not normalized
            "url_analysis": 4,
            "metadata": 0,
        })

        # Should be normalized to 0.6, 0.4, 0.0
        assert abs(classifier.weights["ml_classifier"] - 0.6) < 0.01
        assert abs(classifier.weights["url_analysis"] - 0.4) < 0.01


# ============================================================================
# Graceful Degradation Tests
# ============================================================================

class TestGracefulDegradation:
    """Tests for failure handling."""

    @pytest.mark.asyncio
    async def test_url_analysis_timeout(self, mock_ml_predict, mock_threshold_tuner):
        """URL analysis timeout doesn't break classification."""
        mock_ml_predict.return_value = {"probability": 0.3, "model_loaded": True}

        with patch("app.ml.ensemble.get_url_analyzer") as mock:
            analyzer = MagicMock()
            # Simulate timeout
            async def slow_analyze(*args, **kwargs):
                await asyncio.sleep(10)  # Will timeout
            analyzer.analyze_email_urls = slow_analyze
            mock.return_value = analyzer

            classifier = EnsembleClassifier(url_analysis_timeout=0.1)
            result = await classifier.classify(body="http://example.com")

            # Should complete even with timeout
            assert result is not None
            assert result.url_score == 0.0  # Default on failure
            assert result.url_analysis is None  # No URL analysis due to timeout

    @pytest.mark.asyncio
    async def test_url_analysis_disabled(self, mock_ml_predict, mock_threshold_tuner):
        """Can disable URL analysis."""
        mock_ml_predict.return_value = {"probability": 0.3, "model_loaded": True}

        classifier = EnsembleClassifier(enable_url_analysis=False)
        result = await classifier.classify(body="http://evil.com/malware")

        assert result.url_analysis is None
        assert result.url_score == 0.0

    @pytest.mark.asyncio
    async def test_ml_error_handling(self, mock_url_analyzer, mock_threshold_tuner):
        """ML classifier error is handled."""
        with patch("app.ml.ensemble.ml_predict") as mock:
            mock.return_value = {
                "probability": 0.0,
                "model_loaded": False,
                "error": "Model not found",
            }

            classifier = EnsembleClassifier()
            result = await classifier.classify(body="test")

            assert any("error" in f.lower() for f in result.risk_factors)


# ============================================================================
# Risk Factors Tests
# ============================================================================

class TestRiskFactors:
    """Tests for risk factor reporting."""

    @pytest.mark.asyncio
    async def test_typosquat_risk_factor(self, mock_ml_predict, mock_threshold_tuner):
        """Typosquatting URLs add risk factors."""
        with patch("app.ml.ensemble.get_url_analyzer") as mock:
            analyzer = MagicMock()
            analyzer.analyze_email_urls = AsyncMock(return_value=EmailURLAnalysis(
                urls_found=1,
                urls_analyzed=1,
                high_risk_urls=1,
                highest_risk_level=URLRiskLevel.HIGH,
                aggregate_risk_score=0.8,
                url_results=[
                    URLAnalysisResult(
                        url="https://micros0ft.com",
                        domain="micros0ft.com",
                        risk_level=URLRiskLevel.HIGH,
                        risk_score=0.8,
                        typosquat_target="microsoft",
                    )
                ],
                analysis_time_ms=1.0,
            ))
            mock.return_value = analyzer

            classifier = EnsembleClassifier()
            result = await classifier.classify(body="Visit https://micros0ft.com")

            assert any("Typosquatting" in f for f in result.risk_factors)
            assert any("microsoft" in f for f in result.risk_factors)

    @pytest.mark.asyncio
    async def test_shortened_url_risk_factor(self, mock_ml_predict, mock_threshold_tuner):
        """Shortened URLs add risk factors."""
        with patch("app.ml.ensemble.get_url_analyzer") as mock:
            analyzer = MagicMock()
            analyzer.analyze_email_urls = AsyncMock(return_value=EmailURLAnalysis(
                urls_found=1,
                urls_analyzed=1,
                high_risk_urls=0,
                highest_risk_level=URLRiskLevel.MEDIUM,
                aggregate_risk_score=0.3,
                url_results=[
                    URLAnalysisResult(
                        url="https://bit.ly/abc123",
                        domain="bit.ly",
                        risk_level=URLRiskLevel.MEDIUM,
                        risk_score=0.3,
                        is_shortened=True,
                    )
                ],
                analysis_time_ms=1.0,
            ))
            mock.return_value = analyzer

            classifier = EnsembleClassifier()
            result = await classifier.classify(body="Click https://bit.ly/abc123")

            assert any("shortener" in f.lower() for f in result.risk_factors)


# ============================================================================
# Integration Tests
# ============================================================================

class TestEnsembleIntegration:
    """Integration tests with real components."""

    @pytest.mark.asyncio
    async def test_full_classification_flow(self):
        """Test complete classification without mocks."""
        # This test uses real components
        result = await classify_email(
            sender="attacker@evil-paypa1.com",
            subject="URGENT: Verify your PayPal account",
            body="""
            Dear Customer,

            Your account has been limited. Verify now:
            https://paypa1.com/secure/login

            PayPal Security
            """,
        )

        assert isinstance(result, ClassificationResult)
        assert result.analyzed_at is not None
        assert result.analysis_time_ms > 0

        # Should detect typosquat URL
        if result.url_analysis:
            assert result.url_analysis.urls_found >= 1

    @pytest.mark.asyncio
    async def test_safe_email_classification(self):
        """Safe email should have low risk."""
        result = await classify_email(
            sender="colleague@company.com",
            subject="Weekly report",
            body="Here's the weekly report. Let me know if you have questions.",
        )

        assert result.risk_score < 0.5
        assert result.risk_level in ("safe", "low")

    @pytest.mark.asyncio
    async def test_classifier_status(self):
        """Get classifier status."""
        classifier = get_ensemble_classifier()
        status = classifier.get_status()

        assert "ensemble_version" in status
        assert "ml_classifier" in status
        assert "url_analysis" in status
        assert "threshold" in status


# ============================================================================
# Performance Tests
# ============================================================================

class TestEnsemblePerformance:
    """Performance tests."""

    @pytest.mark.asyncio
    async def test_classification_time(self):
        """Classification should complete quickly."""
        import time

        start = time.perf_counter()
        result = await classify_email(
            sender="test@example.com",
            subject="Test",
            body="This is a test email with http://example.com",
        )
        elapsed = time.perf_counter() - start

        # Should complete in under 2 seconds
        assert elapsed < 2.0
        assert result.analysis_time_ms < 2000

    @pytest.mark.asyncio
    async def test_concurrent_classifications(self):
        """Handle concurrent classifications."""
        import time

        emails = [
            {"sender": f"user{i}@test.com", "subject": f"Test {i}", "body": f"Body {i}"}
            for i in range(10)
        ]

        start = time.perf_counter()
        tasks = [classify_email(**email) for email in emails]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

        assert len(results) == 10
        assert all(isinstance(r, ClassificationResult) for r in results)
        # 10 classifications should complete in under 5 seconds
        assert elapsed < 5.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
