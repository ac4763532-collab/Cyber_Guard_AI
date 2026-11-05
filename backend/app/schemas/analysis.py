"""
CyberGuard AI - Analysis Request/Response Schemas

Pydantic schemas for analysis API endpoints.
"""

import ipaddress
import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Addresses that must never be accepted as a network-scan target, even with
# authorized=True - these point at the scanning host itself or at cloud
# instance-metadata services, never at a genuine third-party/LAN target.
# Shared by NetworkAnalysisRequest.validate_target (below) and
# NetworkAgent.validate() (app/agents/network_agent.py) so the two checks
# can't silently drift apart.
_BLOCKED_METADATA_ADDRESSES = {
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "fd00:ec2::254",  # AWS IMDSv2 (IPv6)
}


def validate_scan_target_address(target: str) -> str | None:
    """
    Reject scan targets that are never appropriate, regardless of the
    caller's authorized=True claim: loopback, link-local, and cloud
    metadata addresses.

    Deliberately does NOT reject RFC1918 private ranges (10.0.0.0/8,
    172.16.0.0/12, 192.168.0.0/16) - scanning one's own LAN is an explicit
    supported use case, gated by the authorized confirmation instead.

    Returns an error message string if the target should be rejected, or
    None if it passes this check (format/CIDR-range validation happens
    separately).
    """
    host = target.split("/")[0]

    if host in _BLOCKED_METADATA_ADDRESSES:
        return f"'{host}' is a cloud instance-metadata address and cannot be scanned."

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Not a bare IP (e.g. a CIDR base already validated elsewhere, or
        # malformed) - let the caller's own format validation handle it.
        return None

    if addr.is_loopback:
        return f"'{host}' is a loopback address and cannot be scanned."
    if addr.is_link_local:
        return f"'{host}' is a link-local address and cannot be scanned."

    return None


class AnalysisType(str, Enum):
    """Types of security analysis."""
    EMAIL = "email"
    LOG = "log"
    NETWORK = "network"


# =============================================================================
# Email Analysis Schemas
# =============================================================================

class EmailAnalysisRequest(BaseModel):
    """Request schema for email analysis."""

    sender: str = Field(..., min_length=1, description="Sender email address")
    recipient: str | None = Field(None, description="Recipient email address")
    subject: str = Field(..., min_length=1, description="Email subject line")
    body: str = Field(..., min_length=1, description="Email body content")

    # Optional fields for enhanced analysis
    headers: dict[str, str] | None = Field(None, description="Email headers")
    urls: list[str] | None = Field(None, description="URLs found in the email")
    attachments: list[dict[str, Any]] | None = Field(
        None, description="Attachment metadata (filename, size, type)"
    )
    received_at: datetime | None = Field(None, description="When email was received")

    @field_validator("sender")
    @classmethod
    def validate_sender(cls, v: str) -> str:
        # Basic email format check (full validation in agent)
        if "@" not in v and "<" not in v:
            raise ValueError("Sender must contain @ or be in 'Name <email>' format")
        return v.strip()

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "sender": "security@bank-verify.com",
                    "recipient": "user@example.com",
                    "subject": "Urgent: Verify Your Account",
                    "body": "Dear Customer, Your account has been compromised. Click here to verify: http://bit.ly/verify-now",
                    "urls": ["http://bit.ly/verify-now"],
                }
            ]
        }
    }


# =============================================================================
# Log Analysis Schemas
# =============================================================================

class LogAnalysisRequest(BaseModel):
    """Request schema for log analysis."""

    log_content: str = Field(..., min_length=1, description="Raw log content to analyze")
    log_type: str | None = Field(
        None,
        description="Type of log (auth, syslog, apache, nginx, firewall, etc.)"
    )
    source_host: str | None = Field(None, description="Hostname where logs originated")
    time_range_start: datetime | None = Field(None, description="Start of time range")
    time_range_end: datetime | None = Field(None, description="End of time range")

    @field_validator("log_content")
    @classmethod
    def validate_log_content(cls, v: str) -> str:
        # Check for minimum meaningful content
        lines = [l for l in v.strip().split("\n") if l.strip()]
        if len(lines) == 0:
            raise ValueError("Log content must contain at least one non-empty line")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "log_content": """Sep 13 09:30:01 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22
Sep 13 09:30:05 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22
Sep 13 09:30:10 server sshd[12347]: Failed password for admin from 192.168.1.100 port 22
Sep 13 09:30:15 server sshd[12348]: Accepted password for admin from 192.168.1.100 port 22""",
                    "log_type": "auth",
                    "source_host": "server.example.com",
                }
            ]
        }
    }


# =============================================================================
# Network Analysis Schemas
# =============================================================================

class NetworkAnalysisRequest(BaseModel):
    """Request schema for network analysis."""

    target: str = Field(
        ...,
        min_length=1,
        description="Target IP address or CIDR range (must be authorized)"
    )
    scan_type: str = Field(
        default="basic",
        description="Type of scan: basic, service, or full"
    )

    # Safety acknowledgment
    authorized: bool = Field(
        ...,
        description="Confirmation that you are authorized to scan this target"
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()

        # Basic IP/CIDR format validation
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$"
        if not re.match(ip_pattern, v):
            raise ValueError(
                "Target must be a valid IP address (e.g., 192.168.1.1) "
                "or CIDR range (e.g., 192.168.1.0/24)"
            )

        # Reject loopback/link-local/cloud-metadata targets outright, even
        # with authorized=True. RFC1918 private ranges are intentionally
        # NOT blocked here - see validate_scan_target_address's docstring.
        rejection = validate_scan_target_address(v)
        if rejection:
            raise ValueError(rejection)

        return v

    @field_validator("authorized")
    @classmethod
    def validate_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm authorization to scan the target. "
                "Only scan systems you own or have explicit permission to assess."
            )
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        allowed = {"basic", "service", "full"}
        if v.lower() not in allowed:
            raise ValueError(f"scan_type must be one of: {', '.join(allowed)}")
        return v.lower()

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target": "192.168.1.0/24",
                    "scan_type": "service",
                    "authorized": True,
                }
            ]
        }
    }


class NetworkLookupRequest(BaseModel):
    """
    Request schema for the lightweight "Analyze" lookup (DNS/geoip/RDAP/
    threat-intel on public records) - distinct from NetworkAnalysisRequest,
    which authorizes an active port scan of a target's live systems.

    No `authorized` field: this endpoint only queries public DNS,
    geolocation, RDAP, and threat-intel data about the target, it never
    connects to or probes the target itself.
    """

    target: str = Field(..., min_length=1, description="IP address or domain to look up")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"target": "8.8.8.8"},
                {"target": "example.com"},
            ]
        }
    }


# =============================================================================
# Response Schemas
# =============================================================================


class FeedbackLinks(BaseModel):
    """Links for reporting feedback on an analysis."""

    report_false_positive: str
    report_missed_threat: str


class FindingResponse(BaseModel):
    """Response schema for a single finding."""

    finding_id: str
    rule_id: str | None = None
    name: str
    description: str
    severity: str
    confidence: float
    evidence: list[str]
    mitre_techniques: list[str]
    recommendations: list[str]
    metadata: dict[str, Any] | None = None
    source_ip: str | None = None
    host: str | None = None
    timestamp: str | None = None


class AnalysisHistoryResponse(BaseModel):
    """Lightweight summary row for GET /analysis/history. Not a full report."""

    id: str
    classification: str
    severity: str
    risk_score: int
    confidence: float
    analyzed_at: datetime
    email_sender: str | None = None
    email_subject: str | None = None
    processing_time_ms: float | None = None
    context: dict[str, Any] | None = None


class LogFileUploadResponse(BaseModel):
    """
    Response schema for POST /analysis/logs/upload.

    Extends the same fields as AnalysisResponse with upload-specific
    metadata. When `preview_only=True` was requested, the AnalysisResponse
    fields (classification/severity/findings/etc.) are omitted entirely
    (None) since no analysis was run - only parsing/preview happened.
    """

    # Upload metadata
    filename: str
    size_bytes: int
    declared_source_type: str
    detected_source_type: str
    parsed_event_count: int
    skipped_line_count: int
    preview_events: list[dict[str, Any]]
    encoding_fallback_used: bool
    preview_only: bool

    # Analysis result fields (populated unless preview_only=True)
    result_id: str | None = None
    analysis_type: str | None = None
    agent_version: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    processing_time_ms: float | None = None
    classification: str | None = None
    severity: str | None = None
    confidence: float | None = None
    risk_score: int | None = None
    findings: list[FindingResponse] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    summary: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    feedback: FeedbackLinks | None = None
    success: bool = True
    error: str | None = None


class AnalysisResponse(BaseModel):
    """Response schema for analysis results."""

    result_id: str
    analysis_type: str
    agent_version: str

    # Timing
    started_at: datetime
    completed_at: datetime | None
    processing_time_ms: float | None

    # Classification
    classification: str
    severity: str
    confidence: float
    risk_score: int

    # Findings
    findings: list[FindingResponse]
    indicators: list[str]

    # Summary
    summary: str
    recommendations: list[str]
    metadata: dict[str, Any] | None = None

    # Log-analysis-specific context (None/empty for email/network analysis)
    source: str | None = None
    processed_event_count: int | None = None
    affected_systems: list[str] = Field(default_factory=list)
    affected_accounts: list[str] = Field(default_factory=list)

    # Network-analysis-specific context (None/empty for email/log analysis).
    # data_source distinguishes a real nmap scan ("nmap") from fabricated
    # demo data ("simulated") - callers must never present simulated
    # results as if a real scan occurred. scan_warnings carries non-fatal
    # caveats (e.g. "nmap not installed").
    data_source: str | None = None
    scan_warnings: list[str] = Field(default_factory=list)

    # Feedback links (Step 12)
    feedback: FeedbackLinks | None = None

    # Status
    success: bool
    error: str | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "result_id": "550e8400-e29b-41d4-a716-446655440000",
                    "analysis_type": "email",
                    "agent_version": "0.1.0",
                    "started_at": "2024-01-15T10:30:00Z",
                    "completed_at": "2024-01-15T10:30:01Z",
                    "processing_time_ms": 125.5,
                    "classification": "phishing",
                    "severity": "high",
                    "confidence": 0.92,
                    "risk_score": 85,
                    "findings": [
                        {
                            "finding_id": "f1",
                            "name": "Suspicious sender domain",
                            "description": "Sender domain mimics legitimate bank",
                            "severity": "high",
                            "confidence": 0.95,
                            "evidence": ["Domain: bank-verify.com"],
                            "mitre_techniques": ["T1566.001"],
                            "recommendations": ["Block sender domain"],
                        }
                    ],
                    "indicators": ["bank-verify.com", "bit.ly/verify-now"],
                    "summary": "High-confidence phishing email detected",
                    "recommendations": ["Block sender", "Report to security team"],
                    "success": True,
                }
            ]
        }
    }


class DetectionReportResponse(BaseModel):
    """
    Response schema for GET /logs/sources/{source_id}/report.

    Computed on demand from persisted `events`/`findings`/`alerts` rows
    scoped to a log source + time range - there is no separate "report" or
    "run" row persisted anywhere (see the plan's rationale: a new table
    would duplicate EventStatus semantics and has no natural close/batch
    boundary for an always-on collector). Reuses FindingResponse for the
    findings list rather than inventing a second finding shape.

    `status` is one of exactly 7 values, each derived only from real
    events.status counts in the requested window - never fabricated:
    monitoring / detection_in_progress / detection_completed /
    completed_with_findings / completed_no_threats / partially_completed /
    failed. `collector_status` is the live, in-memory supervisor state
    (CollectorSupervisorStatus.state, same as _source_to_response's
    collector_status key) - kept as a separate field so the report's own
    completion status is never confused with "is the collector currently
    running".
    """

    source_id: str
    source_name: str
    source_type: str
    hostname: str | None = None

    time_range_start: datetime
    time_range_end: datetime
    generated_at: datetime

    status: str
    collector_status: str | None = None

    events_processed: int
    events_pending: int
    events_failed: int
    findings_count: int
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    findings: list[FindingResponse] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)

