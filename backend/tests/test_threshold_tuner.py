"""
CyberGuard AI - Threshold Tuner Tests

Tests for feedback-based threshold tuning that allows
user feedback to improve detection WITHOUT retraining.
"""

import json
import pytest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from app.ml.threshold_tuner import (
    ThresholdTuner,
    ThresholdConfig,
    FeedbackStats,
    DEFAULT_THRESHOLD,
    MIN_THRESHOLD,
    MAX_THRESHOLD,
    MIN_SAMPLES_FOR_ADJUSTMENT,
)


@pytest.fixture
def temp_config_dir():
    """Create temporary directory for config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def tuner(temp_config_dir):
    """Create a fresh threshold tuner."""
    return ThresholdTuner(config_dir=temp_config_dir)


class TestThresholdConfig:
    """Tests for ThresholdConfig dataclass."""

    def test_default_values(self):
        config = ThresholdConfig()
        assert config.global_threshold == DEFAULT_THRESHOLD
        assert config.domain_thresholds == {}
        assert config.feedback_samples_used == 0

    def test_to_dict(self):
        config = ThresholdConfig(
            global_threshold=0.6,
            feedback_samples_used=100,
        )
        data = config.to_dict()
        assert data["global_threshold"] == 0.6
        assert data["feedback_samples_used"] == 100

    def test_from_dict(self):
        data = {
            "global_threshold": 0.7,
            "domain_thresholds": {"example.com": 0.4},
            "feedback_samples_used": 50,
        }
        config = ThresholdConfig.from_dict(data)
        assert config.global_threshold == 0.7
        assert config.domain_thresholds["example.com"] == 0.4


class TestFeedbackStats:
    """Tests for FeedbackStats dataclass."""

    def test_fp_rate_calculation(self):
        stats = FeedbackStats(
            total_samples=100,
            false_positives=10,
            false_negatives=5,
        )
        assert stats.fp_rate == 0.1
        assert stats.fn_rate == 0.05

    def test_zero_samples(self):
        stats = FeedbackStats()
        assert stats.fp_rate == 0.0
        assert stats.fn_rate == 0.0


class TestThresholdTuner:
    """Tests for ThresholdTuner."""

    def test_default_threshold(self, tuner):
        """New tuner starts with default threshold."""
        assert tuner.get_threshold() == DEFAULT_THRESHOLD

    def test_set_threshold(self, tuner):
        """Can manually set threshold."""
        result = tuner.set_threshold(0.6, reason="Test")

        assert result["success"] is True
        assert result["new_threshold"] == 0.6
        assert tuner.get_threshold() == 0.6

    def test_set_threshold_bounds(self, tuner):
        """Cannot set threshold outside allowed range."""
        result_low = tuner.set_threshold(0.1)  # Below MIN
        assert result_low["success"] is False

        result_high = tuner.set_threshold(0.95)  # Above MAX
        assert result_high["success"] is False

    def test_domain_specific_threshold(self, tuner):
        """Can set domain-specific thresholds."""
        tuner.set_threshold(0.7, domain="suspicious.com")

        # Domain-specific threshold
        assert tuner.get_threshold("suspicious.com") == 0.7

        # Other domains get global threshold
        assert tuner.get_threshold("normal.com") == DEFAULT_THRESHOLD

    def test_reset_threshold(self, tuner):
        """Can reset threshold to default."""
        tuner.set_threshold(0.7)
        assert tuner.get_threshold() == 0.7

        tuner.reset_threshold()
        assert tuner.get_threshold() == DEFAULT_THRESHOLD

    def test_reset_domain_threshold(self, tuner):
        """Can reset domain-specific threshold."""
        tuner.set_threshold(0.7, domain="test.com")

        result = tuner.reset_threshold(domain="test.com")
        assert result["success"] is True
        assert tuner.get_threshold("test.com") == DEFAULT_THRESHOLD

    def test_config_persistence(self, temp_config_dir):
        """Config persists across instances."""
        tuner1 = ThresholdTuner(config_dir=temp_config_dir)
        tuner1.set_threshold(0.65)

        tuner2 = ThresholdTuner(config_dir=temp_config_dir)
        assert tuner2.get_threshold() == 0.65

    def test_adjustment_history(self, tuner):
        """Adjustments are recorded in history."""
        tuner.set_threshold(0.6, reason="First change")
        tuner.set_threshold(0.7, reason="Second change")

        config = tuner.get_config()
        assert len(config.adjustment_history) == 2
        assert config.adjustment_history[0]["reason"] == "First change"


class TestThresholdTuning:
    """Tests for automatic threshold tuning based on feedback."""

    @pytest.mark.asyncio
    async def test_tune_insufficient_samples(self, tuner):
        """Won't adjust with too few samples."""
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=5,  # Below MIN_SAMPLES_FOR_ADJUSTMENT
                false_positives=2,
            )

            result = await tuner.tune_thresholds()

            assert "Insufficient feedback" in result["reason"]
            assert result["applied"] is False

    @pytest.mark.asyncio
    async def test_tune_high_fp_raises_threshold(self, tuner):
        """High false positive rate raises threshold."""
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=100,
                false_positives=20,  # 20% FP rate
                false_negatives=1,
            )

            result = await tuner.tune_thresholds(target_fp_rate=0.05)

            assert result["recommended_threshold"] > DEFAULT_THRESHOLD
            assert "false positive" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_tune_high_fn_lowers_threshold(self, tuner):
        """High false negative rate lowers threshold."""
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=100,
                false_positives=1,
                false_negatives=15,  # 15% FN rate
            )

            result = await tuner.tune_thresholds(target_fn_rate=0.02)

            assert result["recommended_threshold"] < DEFAULT_THRESHOLD
            assert "false negative" in result["reason"].lower()

    @pytest.mark.asyncio
    async def test_tune_dry_run(self, tuner):
        """Dry run calculates but doesn't apply."""
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=100,
                false_positives=20,
            )

            result = await tuner.tune_thresholds(dry_run=True)

            assert result["applied"] is False
            assert tuner.get_threshold() == DEFAULT_THRESHOLD

    @pytest.mark.asyncio
    async def test_tune_applies_changes(self, tuner):
        """Tuning applies changes when not dry run."""
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=100,
                false_positives=20,
            )

            result = await tuner.tune_thresholds(dry_run=False)

            assert result["applied"] is True
            assert tuner.get_threshold() == result["recommended_threshold"]


class TestClassifierIntegration:
    """Tests for threshold tuner integration with classifier."""

    def test_classifier_uses_tuned_threshold(self, temp_config_dir):
        """Classifier's get_threshold() uses tuned threshold."""
        tuner = ThresholdTuner(config_dir=temp_config_dir)
        tuner.set_threshold(0.7)

        with patch("app.ml.threshold_tuner.get_threshold_tuner", return_value=tuner):
            from app.ml.classifier import get_threshold

            threshold = get_threshold()
            assert threshold == 0.7

    def test_classifier_domain_threshold(self, temp_config_dir):
        """Classifier uses domain-specific threshold."""
        tuner = ThresholdTuner(config_dir=temp_config_dir)
        tuner.set_threshold(0.8, domain="risky.com")

        with patch("app.ml.threshold_tuner.get_threshold_tuner", return_value=tuner):
            from app.ml.classifier import get_threshold

            assert get_threshold("user@risky.com") == 0.8
            assert get_threshold("user@safe.com") == DEFAULT_THRESHOLD


class TestFeedbackImprovesDetection:
    """
    Tests verifying that feedback NOW improves detection.

    This is the key improvement over the previous implementation
    where feedback had NO effect on the model.
    """

    @pytest.mark.asyncio
    async def test_feedback_affects_classification(self, temp_config_dir):
        """
        Demonstrate that feedback changes classification results.

        Scenario:
        - Email gets probability 0.55 (just above 0.5 threshold → malicious)
        - Many false positives are reported
        - Threshold is raised to 0.6
        - Same email now classified as benign
        """
        tuner = ThresholdTuner(config_dir=temp_config_dir)

        # Initial: 0.55 > 0.5 → malicious
        initial_threshold = tuner.get_threshold()
        probability = 0.55
        is_malicious_before = probability >= initial_threshold
        assert is_malicious_before is True

        # Simulate high FP feedback → raise threshold
        with patch.object(tuner, "analyze_feedback") as mock_analyze:
            mock_analyze.return_value = FeedbackStats(
                total_samples=100,
                false_positives=25,  # 25% FP rate - too many false alarms!
            )
            await tuner.tune_thresholds(target_fp_rate=0.05)

        # After tuning: threshold should be higher
        new_threshold = tuner.get_threshold()
        assert new_threshold > 0.5

        # Same email now classified differently
        is_malicious_after = probability >= new_threshold
        assert is_malicious_after is False  # Now benign!

    def test_feedback_workflow(self, tuner):
        """
        Complete workflow: feedback → analyze → tune → improved detection.
        """
        # Step 1: Initial state
        assert tuner.get_threshold() == 0.5

        # Step 2: Admin reviews feedback and sees high FP rate
        # (simulated - in reality comes from analyze_feedback)

        # Step 3: Admin decides to raise threshold
        tuner.set_threshold(0.6, reason="Too many false positives from user feedback")

        # Step 4: Detection is now less aggressive
        # Email with 0.55 probability no longer flagged
        assert 0.55 < tuner.get_threshold()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
