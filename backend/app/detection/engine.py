"""
CyberGuard AI - Detection Engine

Main orchestrator for all detection capabilities:
- Rule-based detection
- IOC matching
- Anomaly detection
- Risk scoring

This is the central entry point for detection operations.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
import structlog

from app.detection.rules.registry import get_rule_registry, RuleCategory
from app.detection.rules.base import RuleMatch
from app.detection.ioc import get_ioc_matcher, IOCMatch
from app.detection.anomaly import get_anomaly_detector, Anomaly
from app.detection.scoring import get_scoring_engine, RiskScore, RiskLevel


logger = structlog.get_logger(__name__)


class DetectionResult(BaseModel):
    """Complete detection result from all detection methods."""

    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Detection outputs
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    ioc_matches: list[IOCMatch] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)

    # Risk assessment
    risk_score: RiskScore | None = None

    # Summary
    total_findings: int = 0
    highest_severity: str = "info"

    # Processing info
    processing_time_ms: float = 0.0


class DetectionEngine:
    """
    Central Detection Engine orchestrating all detection methods.

    Flow:
    1. Rule evaluation
    2. IOC matching
    3. Anomaly detection
    4. Risk scoring
    5. Result aggregation

    Usage:
        engine = DetectionEngine()
        result = engine.detect(event_data)
    """

    def __init__(self):
        self.rule_registry = get_rule_registry()
        self.ioc_matcher = get_ioc_matcher()
        self.anomaly_detector = get_anomaly_detector()
        self.scoring_engine = get_scoring_engine()

        logger.info(
            "DetectionEngine initialized",
            rules_count=len(self.rule_registry.get_all()),
            iocs_count=self.ioc_matcher.get_ioc_count(),
        )

    def detect(
        self,
        data: dict[str, Any],
        categories: list[RuleCategory] | None = None,
        skip_rules: bool = False,
        skip_ioc: bool = False,
        skip_anomaly: bool = False,
        correlation_factor: float = 0.0,
        asset_criticality: float = 1.0,
    ) -> DetectionResult:
        """
        Run full detection pipeline on data.

        Args:
            data: Event/content data to analyze
            categories: Optional rule categories to limit detection
            skip_rules: Skip rule-based detection
            skip_ioc: Skip IOC matching
            skip_anomaly: Skip anomaly detection
            correlation_factor: External correlation score (0-1)
            asset_criticality: Asset importance multiplier

        Returns:
            DetectionResult with all findings
        """
        start_time = datetime.now(timezone.utc)

        rule_matches: list[RuleMatch] = []
        ioc_matches: list[IOCMatch] = []
        anomalies: list[Anomaly] = []

        # 1. Rule-based detection
        if not skip_rules:
            try:
                rule_matches = self.rule_registry.evaluate_all(data, categories)
                logger.debug("Rule detection complete", matches=len(rule_matches))
            except Exception as e:
                logger.error("Rule detection failed", error=str(e))

        # 2. IOC matching
        if not skip_ioc:
            try:
                ioc_matches = self.ioc_matcher.match(data)
                logger.debug("IOC matching complete", matches=len(ioc_matches))
            except Exception as e:
                logger.error("IOC matching failed", error=str(e))

        # 3. Anomaly detection
        if not skip_anomaly:
            try:
                anomalies = self.anomaly_detector.detect(data)
                logger.debug("Anomaly detection complete", anomalies=len(anomalies))
            except Exception as e:
                logger.error("Anomaly detection failed", error=str(e))

        # 4. Risk scoring
        try:
            risk_score = self.scoring_engine.calculate(
                rule_matches=rule_matches,
                ioc_matches=ioc_matches,
                anomalies=anomalies,
                correlation_factor=correlation_factor,
                asset_criticality=asset_criticality,
            )
        except Exception as e:
            logger.error("Risk scoring failed", error=str(e))
            risk_score = RiskScore(
                total_score=0,
                risk_level=RiskLevel.INFO,
                confidence=0.0,
            )

        # Calculate processing time
        end_time = datetime.now(timezone.utc)
        processing_time_ms = (end_time - start_time).total_seconds() * 1000

        # Determine highest severity
        highest_severity = self._get_highest_severity(rule_matches, ioc_matches, anomalies)

        # Total findings
        total_findings = len(rule_matches) + len(ioc_matches) + len(anomalies)

        result = DetectionResult(
            rule_matches=rule_matches,
            ioc_matches=ioc_matches,
            anomalies=anomalies,
            risk_score=risk_score,
            total_findings=total_findings,
            highest_severity=highest_severity,
            processing_time_ms=processing_time_ms,
        )

        logger.info(
            "Detection complete",
            detection_id=result.detection_id,
            total_findings=total_findings,
            risk_score=risk_score.total_score if risk_score else 0,
            risk_level=risk_score.risk_level.value if risk_score else "info",
            processing_time_ms=processing_time_ms,
        )

        return result

    def detect_rules_only(
        self,
        data: dict[str, Any],
        categories: list[RuleCategory] | None = None,
    ) -> list[RuleMatch]:
        """Run only rule-based detection."""
        return self.rule_registry.evaluate_all(data, categories)

    def detect_ioc_only(self, data: dict[str, Any]) -> list[IOCMatch]:
        """Run only IOC matching."""
        return self.ioc_matcher.match(data)

    def detect_anomalies_only(self, data: dict[str, Any]) -> list[Anomaly]:
        """Run only anomaly detection."""
        return self.anomaly_detector.detect(data)

    def get_statistics(self) -> dict[str, Any]:
        """Get detection engine statistics."""
        return {
            "rules": self.rule_registry.get_statistics(),
            "iocs": self.ioc_matcher.get_statistics(),
            "baselines": len(self.anomaly_detector.get_all_baselines()),
        }

    def _get_highest_severity(
        self,
        rule_matches: list[RuleMatch],
        ioc_matches: list[IOCMatch],
        anomalies: list[Anomaly],
    ) -> str:
        """Determine highest severity across all findings."""
        severity_order = ["critical", "high", "medium", "low", "info"]

        highest = "info"

        for match in rule_matches:
            sev = match.severity.value
            if severity_order.index(sev) < severity_order.index(highest):
                highest = sev

        for match in ioc_matches:
            threat = match.ioc.threat_level.value
            if threat in severity_order:
                if severity_order.index(threat) < severity_order.index(highest):
                    highest = threat

        for anomaly in anomalies:
            if anomaly.severity_score >= 0.8:
                sev = "high"
            elif anomaly.severity_score >= 0.5:
                sev = "medium"
            else:
                sev = "low"
            if severity_order.index(sev) < severity_order.index(highest):
                highest = sev

        return highest


# Singleton instance
_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    """Get the global detection engine."""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
