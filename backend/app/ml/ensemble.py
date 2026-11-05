"""
CyberGuard AI - Ensemble Classifier

Production-grade email classification combining:
1. ML text classifier (TF-IDF + LogisticRegression)
2. URL analyzer (phishing link detection)
3. Threshold tuning (feedback-adjusted thresholds)

Architecture:
- Parallel analysis for performance
- Weighted scoring with configurable weights
- Graceful degradation (URL failure doesn't break analysis)
- Comprehensive logging for debugging
- Caching for repeated content
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from app.ml.classifier import predict as ml_predict, preprocess_email, get_model_status
from app.ml.url_analyzer import get_url_analyzer, EmailURLAnalysis, URLRiskLevel
from app.ml.threshold_tuner import get_threshold_tuner


logger = structlog.get_logger(__name__)


# ============================================================================
# Configuration
# ============================================================================

# Default weights for ensemble scoring
DEFAULT_WEIGHTS = {
    "ml_classifier": 0.55,    # Text-based ML model
    "url_analysis": 0.35,     # URL risk analysis
    "metadata": 0.10,         # Sender/header analysis (future)
}

# Minimum weights (safety bounds)
MIN_WEIGHTS = {
    "ml_classifier": 0.3,
    "url_analysis": 0.1,
    "metadata": 0.0,
}


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ClassificationResult:
    """Complete email classification result."""

    # Final verdict
    is_malicious: bool
    risk_score: float  # 0.0 to 1.0
    confidence: float
    risk_level: str  # safe, low, medium, high, critical

    # Component scores
    ml_score: float
    url_score: float
    metadata_score: float

    # Threshold used
    threshold: float
    threshold_source: str  # default, tuned, domain_specific

    # Detailed results
    url_analysis: EmailURLAnalysis | None
    risk_factors: list[str] = field(default_factory=list)

    # Performance
    analysis_time_ms: float = 0.0

    # Metadata
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    model_version: str = "ensemble_v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_malicious": self.is_malicious,
            "risk_score": round(self.risk_score, 4),
            "confidence": round(self.confidence, 4),
            "risk_level": self.risk_level,
            "component_scores": {
                "ml_classifier": round(self.ml_score, 4),
                "url_analysis": round(self.url_score, 4),
                "metadata": round(self.metadata_score, 4),
            },
            "threshold": round(self.threshold, 4),
            "threshold_source": self.threshold_source,
            "url_analysis": self.url_analysis.to_dict() if self.url_analysis else None,
            "risk_factors": self.risk_factors,
            "analysis_time_ms": round(self.analysis_time_ms, 2),
            "analyzed_at": self.analyzed_at.isoformat(),
            "model_version": self.model_version,
        }


# ============================================================================
# Ensemble Classifier
# ============================================================================

class EnsembleClassifier:
    """
    Production ensemble classifier for email threat detection.

    Combines multiple signals:
    - ML text classification (existing TF-IDF model)
    - URL analysis (new phishing link detection)
    - Sender/metadata analysis (future expansion)

    Features:
    - Async parallel analysis
    - Configurable weights
    - Feedback-tuned thresholds
    - Graceful degradation
    - Comprehensive logging
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        enable_url_analysis: bool = True,
        enable_metadata_analysis: bool = False,  # Future
        url_analysis_timeout: float = 5.0,
    ):
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self.enable_url_analysis = enable_url_analysis
        self.enable_metadata_analysis = enable_metadata_analysis
        self.url_analysis_timeout = url_analysis_timeout

        self._validate_weights()

        # Get components
        self.url_analyzer = get_url_analyzer() if enable_url_analysis else None
        self.threshold_tuner = get_threshold_tuner()

    def _validate_weights(self) -> None:
        """Validate and normalize weights."""
        total = sum(self.weights.values())
        if total == 0:
            raise ValueError("Weights cannot all be zero")

        # Normalize to sum to 1.0
        self.weights = {k: v / total for k, v in self.weights.items()}

    async def classify(
        self,
        sender: str = "",
        subject: str = "",
        body: str = "",
    ) -> ClassificationResult:
        """
        Classify an email using ensemble of analyzers.

        Args:
            sender: Email sender
            subject: Email subject
            body: Email body (HTML or plain text)

        Returns:
            ClassificationResult with comprehensive analysis
        """
        start_time = time.perf_counter()
        risk_factors = []

        # Get threshold
        threshold, threshold_source = self._get_threshold(sender)

        # Run analyses in parallel
        ml_task = asyncio.create_task(self._run_ml_classifier(sender, subject, body))

        url_task = None
        if self.enable_url_analysis and body:
            url_task = asyncio.create_task(self._run_url_analysis(body))

        # Wait for ML classifier (required)
        ml_result = await ml_task
        ml_score = ml_result.get("probability", 0.0)

        if ml_result.get("error"):
            risk_factors.append(f"ML classifier error: {ml_result['error']}")

        # Wait for URL analysis (optional)
        url_analysis = None
        url_score = 0.0

        if url_task:
            try:
                url_analysis = await asyncio.wait_for(
                    url_task,
                    timeout=self.url_analysis_timeout,
                )
                url_score = url_analysis.aggregate_risk_score

                # Add URL risk factors
                if url_analysis.high_risk_urls > 0:
                    risk_factors.append(
                        f"{url_analysis.high_risk_urls} high-risk URL(s) detected"
                    )

                for url_result in url_analysis.url_results:
                    if url_result.typosquat_target:
                        risk_factors.append(
                            f"Typosquatting detected: {url_result.domain} → {url_result.typosquat_target}"
                        )
                    if url_result.is_shortened:
                        risk_factors.append(
                            f"URL shortener hiding destination: {url_result.domain}"
                        )

            except asyncio.TimeoutError:
                logger.warning("URL analysis timed out")
                risk_factors.append("URL analysis timed out")
            except Exception as e:
                logger.error("URL analysis failed", error=str(e))
                risk_factors.append(f"URL analysis error: {str(e)}")

        # Metadata analysis (future)
        metadata_score = 0.0

        # Calculate ensemble score
        ensemble_score = self._calculate_ensemble_score(
            ml_score=ml_score,
            url_score=url_score,
            metadata_score=metadata_score,
        )

        # Determine verdict
        is_malicious = ensemble_score >= threshold

        # Calculate confidence
        confidence = abs(ensemble_score - threshold) + 0.5
        confidence = min(1.0, confidence)

        # Determine risk level
        risk_level = self._score_to_level(ensemble_score)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ClassificationResult(
            is_malicious=is_malicious,
            risk_score=ensemble_score,
            confidence=confidence,
            risk_level=risk_level,
            ml_score=ml_score,
            url_score=url_score,
            metadata_score=metadata_score,
            threshold=threshold,
            threshold_source=threshold_source,
            url_analysis=url_analysis,
            risk_factors=risk_factors,
            analysis_time_ms=elapsed_ms,
        )

    async def _run_ml_classifier(
        self,
        sender: str,
        subject: str,
        body: str,
    ) -> dict[str, Any]:
        """Run ML classifier (sync function wrapped in executor)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: ml_predict(sender=sender, subject=subject, body=body),
        )

    async def _run_url_analysis(self, body: str) -> EmailURLAnalysis:
        """Run URL analysis."""
        return await self.url_analyzer.analyze_email_urls(body)

    def _get_threshold(self, sender: str) -> tuple[float, str]:
        """Get threshold and its source."""
        # Extract domain for domain-specific threshold
        domain = None
        if sender and "@" in sender:
            domain = sender.split("@")[-1].lower()

        threshold = self.threshold_tuner.get_threshold(domain)
        config = self.threshold_tuner.get_config()

        # Determine source
        if domain and domain in config.domain_thresholds:
            source = "domain_specific"
        elif config.last_updated:
            source = "tuned"
        else:
            source = "default"

        return threshold, source

    def _calculate_ensemble_score(
        self,
        ml_score: float,
        url_score: float,
        metadata_score: float,
    ) -> float:
        """Calculate weighted ensemble score."""
        score = (
            ml_score * self.weights.get("ml_classifier", 0) +
            url_score * self.weights.get("url_analysis", 0) +
            metadata_score * self.weights.get("metadata", 0)
        )

        return min(1.0, max(0.0, score))

    def _score_to_level(self, score: float) -> str:
        """Convert score to risk level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "safe"

    def get_status(self) -> dict[str, Any]:
        """Get classifier status."""
        ml_status = get_model_status()
        threshold_config = self.threshold_tuner.get_config()

        return {
            "ensemble_version": "v1",
            "ml_classifier": ml_status,
            "url_analysis": {
                "enabled": self.enable_url_analysis,
                "cache_stats": self.url_analyzer.get_cache_stats() if self.url_analyzer else None,
            },
            "metadata_analysis": {
                "enabled": self.enable_metadata_analysis,
            },
            "weights": self.weights,
            "threshold": {
                "current": threshold_config.global_threshold,
                "domain_specific": len(threshold_config.domain_thresholds),
                "last_tuned": threshold_config.last_updated.isoformat() if threshold_config.last_updated else None,
            },
        }


# ============================================================================
# Singleton Instance
# ============================================================================

_classifier: EnsembleClassifier | None = None


def get_ensemble_classifier() -> EnsembleClassifier:
    """Get the global ensemble classifier instance."""
    global _classifier
    if _classifier is None:
        _classifier = EnsembleClassifier()
    return _classifier


async def classify_email(
    sender: str = "",
    subject: str = "",
    body: str = "",
) -> ClassificationResult:
    """
    Convenience function to classify an email.

    Uses the global ensemble classifier instance.
    """
    classifier = get_ensemble_classifier()
    return await classifier.classify(sender=sender, subject=subject, body=body)
