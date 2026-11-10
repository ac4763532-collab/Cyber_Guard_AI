"""
CyberGuard AI — Machine Learning API Endpoints
============================================================================

Exposes production scikit-learn models for real-time inference:
- Supervised TF-IDF Phishing Email Classification
- Unsupervised Isolation Forest Anomaly Detection
- Random Forest Network Intrusion Classification
"""

from __future__ import annotations

from typing import Any, List, Optional
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.services.ml_service import ml_engine

router = APIRouter(
    prefix="/ml",
    tags=["machine-learning"],
)


# ──────────────────────────────────────────────────────────────────────────
# REQUEST & RESPONSE SCHEMAS
# ──────────────────────────────────────────────────────────────────────────

class EmailClassificationRequest(BaseModel):
    subject: str = Field(..., description="Email subject line", examples=["Urgent: Verify Your Account"])
    body_text: str = Field(default="", description="Email body text", examples=["Please update credentials immediately"])
    sender: str = Field(default="", description="Sender email address")
    urls: List[str] = Field(default_factory=list, description="Extracted URLs from email")


class EmailClassificationResponse(BaseModel):
    verdict: str  # phishing | suspicious | clean
    risk_score: int  # 0 to 100
    phishing_probability: float
    confidence: float
    model_version: str
    indicators: List[str]


class LogAnomalyRequest(BaseModel):
    failed_logins: int = Field(default=0, ge=0)
    event_rate: float = Field(default=1.0, ge=0.0)
    entropy: float = Field(default=3.0, ge=0.0)
    bytes_transferred: int = Field(default=500, ge=0)
    unique_ports: int = Field(default=1, ge=1)
    off_hours: int = Field(default=0, ge=0, le=1)
    privilege_escalation: int = Field(default=0, ge=0, le=1)


class LogAnomalyResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    risk_score: int
    severity: str  # critical | high | medium | low
    confidence: float
    contributing_features: List[str]
    model_version: str


class NetworkThreatRequest(BaseModel):
    src_bytes: int = Field(default=1000, ge=0)
    dst_bytes: int = Field(default=2000, ge=0)
    dst_port: int = Field(default=443, ge=1, le=65535)
    packet_count: int = Field(default=10, ge=1)
    duration_ms: int = Field(default=200, ge=0)


class NetworkThreatResponse(BaseModel):
    attack_type: str  # benign | port_scan | brute_force | data_exfiltration
    risk_level: str  # critical | high | medium | low
    risk_score: int
    confidence: float
    model_version: str


# ──────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────

@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="Get Machine Learning Engine status and model inventory",
)
def get_ml_status() -> dict[str, Any]:
    """Returns status, frameworks, algorithms, and active models in the ML engine."""
    return ml_engine.get_status()


@router.post(
    "/classify-email",
    response_model=EmailClassificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Classify email for phishing using Supervised NLP (TF-IDF + Naive Bayes)",
)
def classify_email(body: EmailClassificationRequest) -> EmailClassificationResponse:
    """Evaluates text, headers, and URLs through the trained ML phishing classifier."""
    result = ml_engine.predict_email_phishing(
        subject=body.subject,
        body_text=body.body_text,
        sender=body.sender,
        urls=body.urls,
    )
    return EmailClassificationResponse(**result)


@router.post(
    "/detect-log-anomaly",
    response_model=LogAnomalyResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect behavioral log and authentication anomalies using Isolation Forest",
)
def detect_log_anomaly(body: LogAnomalyRequest) -> LogAnomalyResponse:
    """Evaluates multi-dimensional telemetry against statistical enterprise baselines."""
    result = ml_engine.detect_log_anomaly(
        failed_logins=body.failed_logins,
        event_rate=body.event_rate,
        entropy=body.entropy,
        bytes_transferred=body.bytes_transferred,
        unique_ports=body.unique_ports,
        off_hours=body.off_hours,
        privilege_escalation=body.privilege_escalation,
    )
    return LogAnomalyResponse(**result)


@router.post(
    "/predict-network-threat",
    response_model=NetworkThreatResponse,
    status_code=status.HTTP_200_OK,
    summary="Classify network traffic flows using Random Forest",
)
def predict_network_threat(body: NetworkThreatRequest) -> NetworkThreatResponse:
    """Classifies network flow characteristics into attack categories."""
    result = ml_engine.predict_network_threat(
        src_bytes=body.src_bytes,
        dst_bytes=body.dst_bytes,
        dst_port=body.dst_port,
        packet_count=body.packet_count,
        duration_ms=body.duration_ms,
    )
    return NetworkThreatResponse(**result)
