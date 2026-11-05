"""
CyberGuard AI - Detection Package

Provides multi-layered threat detection:
- Rule-based detection
- IOC matching
- Anomaly detection
- Risk scoring
"""

from app.detection.engine import DetectionEngine, DetectionResult, get_detection_engine
from app.detection.scoring import RiskScore, RiskLevel, RiskScoringEngine, get_scoring_engine
from app.detection.ioc import IOC, IOCMatch, IOCMatcher, IOCType, ThreatLevel, get_ioc_matcher
from app.detection.anomaly import Anomaly, AnomalyDetector, get_anomaly_detector

__all__ = [
    # Engine
    "DetectionEngine",
    "DetectionResult",
    "get_detection_engine",
    # Scoring
    "RiskScore",
    "RiskLevel",
    "RiskScoringEngine",
    "get_scoring_engine",
    # IOC
    "IOC",
    "IOCMatch",
    "IOCMatcher",
    "IOCType",
    "ThreatLevel",
    "get_ioc_matcher",
    # Anomaly
    "Anomaly",
    "AnomalyDetector",
    "get_anomaly_detector",
]
