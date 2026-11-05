"""
CyberGuard AI - Threshold Tuner

Adjusts classification thresholds based on user feedback patterns.
This allows feedback to improve detection WITHOUT retraining the model,
preserving the Step 12 privacy design (no email body storage needed).

How it works:
- Analyzes approved feedback (false positives, false negatives)
- Calculates error rates by category (sender domain type, etc.)
- Adjusts thresholds to minimize errors
- Stores thresholds in JSON for persistence
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from app.config import get_settings


logger = structlog.get_logger(__name__)


# Default threshold configuration
DEFAULT_THRESHOLD = 0.5
MIN_THRESHOLD = 0.3
MAX_THRESHOLD = 0.8

# Minimum feedback samples before adjusting
MIN_SAMPLES_FOR_ADJUSTMENT = 10


@dataclass
class ThresholdConfig:
    """Threshold configuration with metadata."""

    global_threshold: float = DEFAULT_THRESHOLD
    domain_thresholds: dict[str, float] = field(default_factory=dict)
    last_updated: datetime | None = None
    feedback_samples_used: int = 0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    adjustment_history: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "global_threshold": self.global_threshold,
            "domain_thresholds": self.domain_thresholds,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "feedback_samples_used": self.feedback_samples_used,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "adjustment_history": self.adjustment_history[-10:],  # Keep last 10
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThresholdConfig":
        return cls(
            global_threshold=data.get("global_threshold", DEFAULT_THRESHOLD),
            domain_thresholds=data.get("domain_thresholds", {}),
            last_updated=datetime.fromisoformat(data["last_updated"]) if data.get("last_updated") else None,
            feedback_samples_used=data.get("feedback_samples_used", 0),
            false_positive_rate=data.get("false_positive_rate", 0.0),
            false_negative_rate=data.get("false_negative_rate", 0.0),
            adjustment_history=data.get("adjustment_history", []),
        )


@dataclass
class FeedbackStats:
    """Statistics from feedback analysis."""

    total_samples: int = 0
    false_positives: int = 0  # Flagged as malicious, but was benign
    false_negatives: int = 0  # Flagged as benign, but was malicious
    wrong_category: int = 0
    by_sender_domain: dict[str, dict] = field(default_factory=dict)

    @property
    def fp_rate(self) -> float:
        """False positive rate."""
        if self.total_samples == 0:
            return 0.0
        return self.false_positives / self.total_samples

    @property
    def fn_rate(self) -> float:
        """False negative rate."""
        if self.total_samples == 0:
            return 0.0
        return self.false_negatives / self.total_samples

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "wrong_category": self.wrong_category,
            "fp_rate": self.fp_rate,
            "fn_rate": self.fn_rate,
            "by_sender_domain": self.by_sender_domain,
        }


class ThresholdTuner:
    """
    Tune classification thresholds based on feedback patterns.

    This is the key to making feedback useful WITHOUT storing email bodies.
    By analyzing error patterns, we can adjust thresholds to:
    - Reduce false positives (raise threshold → less aggressive)
    - Reduce false negatives (lower threshold → more aggressive)
    - Apply domain-specific thresholds (e.g., stricter for external senders)
    """

    CONFIG_FILE = "threshold_config.json"

    def __init__(self, config_dir: str | Path | None = None):
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path(__file__).parent / "models"

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.config_dir / self.CONFIG_FILE

        self._config = self._load_config()

    def _load_config(self) -> ThresholdConfig:
        """Load threshold configuration from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return ThresholdConfig.from_dict(data)
            except Exception as e:
                logger.warning("Failed to load threshold config", error=str(e))

        return ThresholdConfig()

    def _save_config(self) -> None:
        """Save threshold configuration to file."""
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self._config.to_dict(), f, indent=2)

    def get_threshold(self, sender_domain: str | None = None) -> float:
        """
        Get the classification threshold.

        Args:
            sender_domain: Optional sender domain for domain-specific threshold

        Returns:
            Threshold value (0.0 to 1.0)
        """
        if sender_domain and sender_domain in self._config.domain_thresholds:
            return self._config.domain_thresholds[sender_domain]

        return self._config.global_threshold

    def get_config(self) -> ThresholdConfig:
        """Get the current threshold configuration."""
        return self._config

    async def analyze_feedback(self, limit: int = 1000) -> FeedbackStats:
        """
        Analyze feedback to calculate error rates.

        Returns:
            FeedbackStats with error analysis
        """
        from app.database.repositories.feedback import get_feedback_repository

        stats = FeedbackStats()

        try:
            repo = get_feedback_repository()

            # Get all approved feedback (not just untrained)
            feedback_items = await repo.get_approved_for_training(
                limit=limit,
                exclude_trained=False,  # Include all approved feedback
            )

            for item in feedback_items:
                stats.total_samples += 1

                feedback_type = item.feedback_type.value

                if feedback_type == "false_positive":
                    stats.false_positives += 1
                elif feedback_type == "false_negative":
                    stats.false_negatives += 1
                elif feedback_type == "wrong_category":
                    stats.wrong_category += 1

                # Track by sender domain
                if item.email_sender:
                    domain = self._extract_domain(item.email_sender)
                    if domain not in stats.by_sender_domain:
                        stats.by_sender_domain[domain] = {
                            "total": 0,
                            "false_positives": 0,
                            "false_negatives": 0,
                        }

                    stats.by_sender_domain[domain]["total"] += 1
                    if feedback_type == "false_positive":
                        stats.by_sender_domain[domain]["false_positives"] += 1
                    elif feedback_type == "false_negative":
                        stats.by_sender_domain[domain]["false_negatives"] += 1

        except Exception as e:
            logger.error("Failed to analyze feedback", error=str(e))

        return stats

    async def tune_thresholds(
        self,
        target_fp_rate: float = 0.05,
        target_fn_rate: float = 0.02,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Automatically tune thresholds based on feedback.

        Args:
            target_fp_rate: Target false positive rate (default 5%)
            target_fn_rate: Target false negative rate (default 2%)
            dry_run: If True, calculate but don't apply changes

        Returns:
            Tuning result with recommendations
        """
        stats = await self.analyze_feedback()

        result = {
            "feedback_stats": stats.to_dict(),
            "current_threshold": self._config.global_threshold,
            "recommended_threshold": self._config.global_threshold,
            "adjustment": 0.0,
            "reason": "No adjustment needed",
            "applied": False,
        }

        # Need minimum samples for reliable adjustment
        if stats.total_samples < MIN_SAMPLES_FOR_ADJUSTMENT:
            result["reason"] = f"Insufficient feedback ({stats.total_samples} < {MIN_SAMPLES_FOR_ADJUSTMENT})"
            return result

        current = self._config.global_threshold
        recommended = current

        # Calculate adjustment based on error rates
        if stats.fp_rate > target_fp_rate:
            # Too many false positives → raise threshold (less aggressive)
            adjustment = min(0.1, (stats.fp_rate - target_fp_rate) * 2)
            recommended = min(MAX_THRESHOLD, current + adjustment)
            result["reason"] = f"High false positive rate ({stats.fp_rate:.1%} > {target_fp_rate:.1%})"

        elif stats.fn_rate > target_fn_rate:
            # Too many false negatives → lower threshold (more aggressive)
            adjustment = min(0.1, (stats.fn_rate - target_fn_rate) * 2)
            recommended = max(MIN_THRESHOLD, current - adjustment)
            result["reason"] = f"High false negative rate ({stats.fn_rate:.1%} > {target_fn_rate:.1%})"

        else:
            result["reason"] = "Error rates within target range"

        result["recommended_threshold"] = round(recommended, 3)
        result["adjustment"] = round(recommended - current, 3)

        # Apply if not dry run
        if not dry_run and recommended != current:
            self._apply_threshold(
                new_threshold=recommended,
                stats=stats,
                reason=result["reason"],
            )
            result["applied"] = True

        return result

    def _apply_threshold(
        self,
        new_threshold: float,
        stats: FeedbackStats,
        reason: str,
    ) -> None:
        """Apply a new threshold and record the change."""
        old_threshold = self._config.global_threshold

        self._config.global_threshold = new_threshold
        self._config.last_updated = datetime.now(timezone.utc)
        self._config.feedback_samples_used = stats.total_samples
        self._config.false_positive_rate = stats.fp_rate
        self._config.false_negative_rate = stats.fn_rate

        # Record in history
        self._config.adjustment_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "old_threshold": old_threshold,
            "new_threshold": new_threshold,
            "reason": reason,
            "feedback_samples": stats.total_samples,
            "fp_rate": stats.fp_rate,
            "fn_rate": stats.fn_rate,
        })

        self._save_config()

        logger.info(
            "Threshold updated",
            old=old_threshold,
            new=new_threshold,
            reason=reason,
        )

    def set_threshold(
        self,
        threshold: float,
        domain: str | None = None,
        reason: str = "Manual override",
    ) -> dict[str, Any]:
        """
        Manually set a threshold.

        Args:
            threshold: New threshold value
            domain: If provided, set domain-specific threshold
            reason: Reason for the change

        Returns:
            Result of the operation
        """
        # Validate threshold
        if not MIN_THRESHOLD <= threshold <= MAX_THRESHOLD:
            return {
                "success": False,
                "error": f"Threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}",
            }

        if domain:
            old = self._config.domain_thresholds.get(domain, self._config.global_threshold)
            self._config.domain_thresholds[domain] = threshold
        else:
            old = self._config.global_threshold
            self._config.global_threshold = threshold

        self._config.last_updated = datetime.now(timezone.utc)
        self._config.adjustment_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "old_threshold": old,
            "new_threshold": threshold,
            "domain": domain,
            "reason": reason,
            "manual": True,
        })

        self._save_config()

        logger.info(
            "Threshold manually set",
            threshold=threshold,
            domain=domain,
            reason=reason,
        )

        return {
            "success": True,
            "old_threshold": old,
            "new_threshold": threshold,
            "domain": domain,
        }

    def reset_threshold(self, domain: str | None = None) -> dict[str, Any]:
        """Reset threshold to default."""
        if domain:
            if domain in self._config.domain_thresholds:
                del self._config.domain_thresholds[domain]
                self._save_config()
                return {"success": True, "message": f"Domain threshold for {domain} removed"}
            return {"success": False, "message": f"No domain threshold for {domain}"}

        self._config.global_threshold = DEFAULT_THRESHOLD
        self._save_config()
        return {"success": True, "message": "Global threshold reset to default"}

    def _extract_domain(self, email: str) -> str:
        """Extract domain from email address."""
        if "@" in email:
            return email.split("@")[-1].lower()
        return email.lower()


# Singleton instance
_tuner: ThresholdTuner | None = None


def get_threshold_tuner() -> ThresholdTuner:
    """Get the global threshold tuner instance."""
    global _tuner
    if _tuner is None:
        _tuner = ThresholdTuner()
    return _tuner
