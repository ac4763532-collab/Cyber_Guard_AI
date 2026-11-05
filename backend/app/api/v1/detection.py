"""
CyberGuard AI - Detection API Endpoints

Provides direct access to detection engine capabilities.
"""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.detection import (
    get_detection_engine,
    DetectionResult,
    get_ioc_matcher,
    get_anomaly_detector,
)
from app.detection.rules import get_rule_registry


router = APIRouter(prefix="/detection", tags=["Detection"])


class DetectionRequest(BaseModel):
    """Request for detection analysis."""

    data: dict[str, Any] = Field(..., description="Data to analyze")
    skip_rules: bool = Field(False, description="Skip rule-based detection")
    skip_ioc: bool = Field(False, description="Skip IOC matching")
    skip_anomaly: bool = Field(False, description="Skip anomaly detection")
    correlation_factor: float = Field(0.0, ge=0.0, le=1.0, description="Correlation boost")
    asset_criticality: float = Field(1.0, ge=0.5, le=2.0, description="Asset importance")


class DetectionResponse(BaseModel):
    """Detection analysis response."""

    detection_id: str
    total_findings: int
    highest_severity: str
    risk_score: int
    risk_level: str
    confidence: float
    rule_matches: int
    ioc_matches: int
    anomalies: int
    processing_time_ms: float
    details: dict[str, Any] | None = None


@router.post(
    "/analyze",
    response_model=DetectionResponse,
    summary="Run Detection Analysis",
    description="Run full detection pipeline on provided data.",
)
async def run_detection(request: DetectionRequest) -> DetectionResponse:
    """Run detection analysis on provided data."""
    engine = get_detection_engine()

    result = engine.detect(
        data=request.data,
        skip_rules=request.skip_rules,
        skip_ioc=request.skip_ioc,
        skip_anomaly=request.skip_anomaly,
        correlation_factor=request.correlation_factor,
        asset_criticality=request.asset_criticality,
    )

    return DetectionResponse(
        detection_id=result.detection_id,
        total_findings=result.total_findings,
        highest_severity=result.highest_severity,
        risk_score=result.risk_score.total_score if result.risk_score else 0,
        risk_level=result.risk_score.risk_level.value if result.risk_score else "info",
        confidence=result.risk_score.confidence if result.risk_score else 0.0,
        rule_matches=len(result.rule_matches),
        ioc_matches=len(result.ioc_matches),
        anomalies=len(result.anomalies),
        processing_time_ms=result.processing_time_ms,
        details={
            "rule_matches": [
                {
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "severity": m.severity.value,
                    "description": m.description,
                }
                for m in result.rule_matches
            ],
            "ioc_matches": [
                {
                    "ioc_type": m.ioc.ioc_type.value,
                    "value": m.matched_value,
                    "threat_level": m.ioc.threat_level.value,
                    "field": m.matched_field,
                }
                for m in result.ioc_matches
            ],
            "contributing_factors": result.risk_score.contributing_factors if result.risk_score else [],
        },
    )


@router.get(
    "/statistics",
    summary="Get Detection Statistics",
    description="Get statistics for the detection engine.",
)
async def get_statistics() -> dict[str, Any]:
    """Get detection engine statistics."""
    engine = get_detection_engine()
    return engine.get_statistics()


@router.get(
    "/rules",
    summary="List Detection Rules",
    description="List all available detection rules.",
)
async def list_rules() -> dict[str, Any]:
    """List all detection rules."""
    registry = get_rule_registry()
    rules = registry.get_all(enabled_only=False)

    return {
        "total": len(rules),
        "rules": [rule.to_dict() for rule in rules],
    }


@router.get(
    "/iocs",
    summary="Get IOC Statistics",
    description="Get IOC database statistics.",
)
async def get_ioc_stats() -> dict[str, Any]:
    """Get IOC statistics."""
    matcher = get_ioc_matcher()
    return matcher.get_statistics()
