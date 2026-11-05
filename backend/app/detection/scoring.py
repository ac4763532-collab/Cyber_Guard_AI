"""
CyberGuard AI - Risk Scoring Engine

Calculates risk scores based on multiple factors:
- Detection findings severity
- IOC matches threat level
- Anomaly severity
- Correlation strength
- Asset criticality
"""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
import structlog

from app.detection.rules.base import RuleMatch, RuleSeverity
from app.detection.ioc import IOCMatch, ThreatLevel
from app.detection.anomaly import Anomaly


logger = structlog.get_logger(__name__)


class RiskLevel(str, Enum):
    """Risk level categories."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskScore(BaseModel):
    """Calculated risk score with breakdown."""

    total_score: int = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    risk_level: RiskLevel = Field(..., description="Categorized risk level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the score")

    # Score breakdown
    rule_score: float = Field(0.0, description="Score from rule matches")
    ioc_score: float = Field(0.0, description="Score from IOC matches")
    anomaly_score: float = Field(0.0, description="Score from anomalies")
    correlation_score: float = Field(0.0, description="Score from correlations")

    # Weights used
    weights: dict[str, float] = Field(default_factory=dict)

    # Contributing factors
    contributing_factors: list[str] = Field(default_factory=list)


class RiskScoringEngine:
    """
    Risk Scoring Engine for calculating composite risk scores.

    Uses weighted scoring based on:
    - Rule match severities
    - IOC threat levels
    - Anomaly severity scores
    - Correlation factors

    Risk Score Ranges:
    - 0-24:  LOW
    - 25-49: MEDIUM
    - 50-74: HIGH
    - 75-100: CRITICAL
    """

    # Default weights for different factors
    DEFAULT_WEIGHTS = {
        "rule_match": 0.35,
        "ioc_match": 0.30,
        "anomaly": 0.20,
        "correlation": 0.15,
    }

    # Severity to score mapping
    SEVERITY_SCORES = {
        RuleSeverity.CRITICAL: 100,
        RuleSeverity.HIGH: 75,
        RuleSeverity.MEDIUM: 50,
        RuleSeverity.LOW: 25,
        RuleSeverity.INFO: 10,
    }

    # Threat level to score mapping
    THREAT_SCORES = {
        ThreatLevel.CRITICAL: 100,
        ThreatLevel.HIGH: 80,
        ThreatLevel.MEDIUM: 50,
        ThreatLevel.LOW: 25,
        ThreatLevel.UNKNOWN: 15,
    }

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._normalize_weights()

    def _normalize_weights(self) -> None:
        """Normalize weights to sum to 1.0."""
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

    def calculate(
        self,
        rule_matches: list[RuleMatch] | None = None,
        ioc_matches: list[IOCMatch] | None = None,
        anomalies: list[Anomaly] | None = None,
        correlation_factor: float = 0.0,
        asset_criticality: float = 1.0,
    ) -> RiskScore:
        """
        Calculate composite risk score.

        Args:
            rule_matches: Detection rule matches
            ioc_matches: IOC matches
            anomalies: Detected anomalies
            correlation_factor: Score boost from correlation (0-1)
            asset_criticality: Asset importance multiplier (0.5-2.0)

        Returns:
            RiskScore with breakdown
        """
        rule_matches = rule_matches or []
        ioc_matches = ioc_matches or []
        anomalies = anomalies or []

        contributing_factors = []

        # Calculate component scores
        rule_score = self._calculate_rule_score(rule_matches)
        if rule_score > 0:
            contributing_factors.append(f"Rule matches: {len(rule_matches)}")

        ioc_score = self._calculate_ioc_score(ioc_matches)
        if ioc_score > 0:
            contributing_factors.append(f"IOC matches: {len(ioc_matches)}")

        anomaly_score = self._calculate_anomaly_score(anomalies)
        if anomaly_score > 0:
            contributing_factors.append(f"Anomalies: {len(anomalies)}")

        correlation_score = correlation_factor * 100
        if correlation_score > 0:
            contributing_factors.append(f"Correlation factor: {correlation_factor:.2f}")

        # Calculate weighted total
        weighted_score = (
            rule_score * self.weights.get("rule_match", 0.35) +
            ioc_score * self.weights.get("ioc_match", 0.30) +
            anomaly_score * self.weights.get("anomaly", 0.20) +
            correlation_score * self.weights.get("correlation", 0.15)
        )

        # Apply asset criticality multiplier
        weighted_score *= min(max(asset_criticality, 0.5), 2.0)

        # Ensure score is within bounds
        total_score = int(min(max(weighted_score, 0), 100))

        # Determine risk level
        risk_level = self._score_to_level(total_score)

        # Calculate confidence based on data quality
        confidence = self._calculate_confidence(
            rule_matches, ioc_matches, anomalies
        )

        return RiskScore(
            total_score=total_score,
            risk_level=risk_level,
            confidence=confidence,
            rule_score=rule_score,
            ioc_score=ioc_score,
            anomaly_score=anomaly_score,
            correlation_score=correlation_score,
            weights=self.weights,
            contributing_factors=contributing_factors,
        )

    def _calculate_rule_score(self, matches: list[RuleMatch]) -> float:
        """Calculate score from rule matches."""
        if not matches:
            return 0.0

        # Take the highest severity match as base
        max_score = 0.0
        total_confidence = 0.0

        for match in matches:
            severity_score = self.SEVERITY_SCORES.get(match.severity, 25)
            weighted = severity_score * match.confidence
            max_score = max(max_score, weighted)
            total_confidence += match.confidence

        # Boost for multiple matches (diminishing returns)
        match_multiplier = 1.0 + (len(matches) - 1) * 0.1
        match_multiplier = min(match_multiplier, 1.5)

        # Average confidence
        avg_confidence = total_confidence / len(matches) if matches else 0.0

        return min(max_score * match_multiplier, 100.0)

    def _calculate_ioc_score(self, matches: list[IOCMatch]) -> float:
        """Calculate score from IOC matches."""
        if not matches:
            return 0.0

        max_score = 0.0

        for match in matches:
            threat_score = self.THREAT_SCORES.get(match.ioc.threat_level, 25)
            max_score = max(max_score, threat_score)

        # Boost for multiple IOC types
        unique_types = set(m.ioc.ioc_type for m in matches)
        type_multiplier = 1.0 + (len(unique_types) - 1) * 0.15
        type_multiplier = min(type_multiplier, 1.5)

        return min(max_score * type_multiplier, 100.0)

    def _calculate_anomaly_score(self, anomalies: list[Anomaly]) -> float:
        """Calculate score from anomalies."""
        if not anomalies:
            return 0.0

        # Weight by severity and confidence
        weighted_scores = [
            a.severity_score * a.confidence * 100
            for a in anomalies
        ]

        # Take average of top anomalies
        weighted_scores.sort(reverse=True)
        top_scores = weighted_scores[:3]  # Consider top 3

        if top_scores:
            return min(sum(top_scores) / len(top_scores), 100.0)
        return 0.0

    def _score_to_level(self, score: int) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 75:
            return RiskLevel.CRITICAL
        elif score >= 50:
            return RiskLevel.HIGH
        elif score >= 25:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _calculate_confidence(
        self,
        rule_matches: list[RuleMatch],
        ioc_matches: list[IOCMatch],
        anomalies: list[Anomaly],
    ) -> float:
        """Calculate overall confidence in the risk score."""
        confidences = []

        # Rule match confidences
        for match in rule_matches:
            confidences.append(match.confidence)

        # IOC matches are high confidence by nature
        for _ in ioc_matches:
            confidences.append(0.9)

        # Anomaly confidences
        for anomaly in anomalies:
            confidences.append(anomaly.confidence)

        if not confidences:
            return 0.5  # Neutral confidence with no data

        # Weight average towards higher confidences
        confidences.sort(reverse=True)
        weighted_sum = sum(c * (0.9 ** i) for i, c in enumerate(confidences))
        weight_total = sum(0.9 ** i for i in range(len(confidences)))

        return min(weighted_sum / weight_total, 1.0) if weight_total > 0 else 0.5


# Singleton instance
_engine: RiskScoringEngine | None = None


def get_scoring_engine() -> RiskScoringEngine:
    """Get the global risk scoring engine."""
    global _engine
    if _engine is None:
        _engine = RiskScoringEngine()
    return _engine
