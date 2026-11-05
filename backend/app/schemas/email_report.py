"""
CyberGuard AI - Enhanced Email Investigation Report Schema

Professional SOC-style report structure for email security analysis.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class DetectionStatus(str, Enum):
    """Status for each detector."""
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"
    NOT_AVAILABLE = "not_available"
    NOT_APPLICABLE = "not_applicable"


class AuthStatus(str, Enum):
    """Email authentication result status."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"
    NOT_AVAILABLE = "not_available"


class RiskLevel(str, Enum):
    """Risk level classification."""
    CRITICAL = "critical"   # 80-100
    HIGH = "high"           # 60-79
    MEDIUM = "medium"       # 30-59
    LOW = "low"             # 0-29


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILENAME = "filename"


# =============================================================================
# Report Sections
# =============================================================================

class VerdictSection(BaseModel):
    """Top-level verdict of the investigation."""
    classification: str = Field(..., description="benign, suspicious, phishing, malicious")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    risk_level: RiskLevel = Field(..., description="Risk level based on score")
    severity: str = Field(..., description="Highest finding severity")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    confidence_reasons: list[str] = Field(default_factory=list, description="Why this confidence level")


class SenderIntelligence(BaseModel):
    """Sender analysis section."""
    from_address: str = ""
    from_display_name: str = ""
    from_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""

    # Detection flags
    is_free_email_provider: bool = False
    is_suspicious_tld: bool = False
    is_lookalike_domain: bool = False
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False

    findings: list[dict[str, Any]] = Field(default_factory=list)


class AuthenticationResult(BaseModel):
    """Single authentication check result."""
    status: AuthStatus = AuthStatus.UNKNOWN
    evidence: str = ""
    domain: str = ""
    reason: str = ""


class AuthenticationSection(BaseModel):
    """Email authentication analysis section."""
    spf: AuthenticationResult = Field(default_factory=AuthenticationResult)
    dkim: AuthenticationResult = Field(default_factory=AuthenticationResult)
    dmarc: AuthenticationResult = Field(default_factory=AuthenticationResult)
    raw_header: str = ""


class ExtractedURL(BaseModel):
    """Single extracted URL with analysis."""
    url: str
    domain: str = ""
    scheme: str = ""
    display_text: str = ""

    # Analysis results
    is_shortener: bool = False
    is_ip_based: bool = False
    is_suspicious_tld: bool = False
    has_at_symbol: bool = False
    display_href_mismatch: bool = False

    # Threat intel (if available)
    threat_intel_status: str = "not_checked"
    threat_intel_result: Optional[dict[str, Any]] = None

    severity: str = "info"
    findings: list[str] = Field(default_factory=list)


class URLIntelligence(BaseModel):
    """URL analysis section."""
    total_urls: int = 0
    suspicious_urls: int = 0
    urls: list[ExtractedURL] = Field(default_factory=list)
    status: DetectionStatus = DetectionStatus.NOT_DETECTED


class ContentAnalysisMatch(BaseModel):
    """A matched content pattern."""
    pattern_type: str  # urgency, credential_request, etc.
    matched_text: str
    severity: str


class ContentAnalysisSection(BaseModel):
    """Content analysis section."""
    urgency_detected: bool = False
    urgency_matches: list[str] = Field(default_factory=list)

    credential_request_detected: bool = False
    credential_matches: list[str] = Field(default_factory=list)

    brand_impersonation_detected: bool = False
    impersonated_brands: list[str] = Field(default_factory=list)

    social_engineering_score: int = 0
    matches: list[ContentAnalysisMatch] = Field(default_factory=list)


class AttachmentAnalysis(BaseModel):
    """Single attachment analysis."""
    filename: str
    extension: str = ""
    mime_type: str = ""
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""

    # Risk indicators
    is_dangerous_extension: bool = False
    is_double_extension: bool = False
    is_macro_enabled: bool = False
    is_archive: bool = False
    is_disk_image: bool = False
    has_mime_mismatch: bool = False

    severity: str = "info"
    findings: list[str] = Field(default_factory=list)

    # Threat intel (if available)
    threat_intel_status: str = "not_checked"
    threat_intel_result: Optional[dict[str, Any]] = None


class AttachmentSection(BaseModel):
    """Attachment analysis section."""
    total_attachments: int = 0
    dangerous_attachments: int = 0
    attachments: list[AttachmentAnalysis] = Field(default_factory=list)
    status: DetectionStatus = DetectionStatus.NOT_APPLICABLE


class HeaderForensics(BaseModel):
    """Header forensics section."""
    message_id: str = ""
    message_id_present: bool = True

    received_hops: int = 0
    excessive_hops: bool = False

    has_private_ip: bool = False
    has_localhost: bool = False
    has_timestamp_anomaly: bool = False

    return_path_from_mismatch: bool = False

    received_chain: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    status: DetectionStatus = DetectionStatus.UNKNOWN


class IOCEntry(BaseModel):
    """Single IOC entry."""
    ioc_type: IOCType
    value: str
    source: str = ""  # Where it was found
    threat_intel_status: str = "not_checked"
    threat_intel_result: Optional[dict[str, Any]] = None


class IOCInventory(BaseModel):
    """IOC inventory section."""
    total_iocs: int = 0
    iocs: list[IOCEntry] = Field(default_factory=list)

    # Grouped for convenience
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    """Threat intelligence lookup result."""
    ioc: str
    ioc_type: str
    provider: str  # virustotal, abuseipdb
    status: str  # clean, suspicious, malicious, unknown, error
    risk_score: int = 0
    detection_ratio: str = ""  # e.g., "5/70" for VT
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class ThreatIntelSection(BaseModel):
    """Threat intelligence section."""
    status: str = "not_configured"  # configured, not_configured, partial
    providers_available: list[str] = Field(default_factory=list)
    results: list[ThreatIntelResult] = Field(default_factory=list)
    malicious_count: int = 0
    suspicious_count: int = 0


class FindingDetail(BaseModel):
    """Detailed finding for report."""
    finding_id: str
    rule_id: Optional[str] = None
    title: str
    severity: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    source: str = ""  # Which analyzer produced this
    risk_contribution: int = 0
    why_it_matters: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    """Risk score breakdown."""
    total_score: int = 0

    # Component scores
    sender_score: int = 0
    authentication_score: int = 0
    url_score: int = 0
    content_score: int = 0
    attachment_score: int = 0
    header_score: int = 0
    threat_intel_score: int = 0

    # Finding counts by severity
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0


class CampaignIndicators(BaseModel):
    """Campaign detection indicators (for batch analysis)."""
    is_potential_campaign: bool = False
    campaign_id: Optional[str] = None
    campaign_score: int = 0
    campaign_confidence: float = 0.0

    related_email_count: int = 0
    shared_domains: list[str] = Field(default_factory=list)
    shared_ips: list[str] = Field(default_factory=list)
    shared_senders: list[str] = Field(default_factory=list)
    subject_similarity: float = 0.0
    temporal_cluster: bool = False

    indicators: list[str] = Field(default_factory=list)


class RecommendationItem(BaseModel):
    """A single recommendation."""
    action: str
    priority: str  # immediate, high, medium, low
    based_on: str  # Which finding triggered this
    details: str = ""


# =============================================================================
# Main Report Schema
# =============================================================================

class EmailInvestigationReport(BaseModel):
    """
    Complete Email Security Investigation Report.

    Professional SOC-style report with all analysis sections.
    """

    # Metadata
    report_id: str
    investigation_timestamp: datetime
    analysis_duration_ms: float = 0.0
    agent_version: str = "0.1.0"

    # Email identifiers
    email_source: str = "manual"  # manual, gmail
    gmail_message_id: Optional[str] = None

    # ===== REPORT SECTIONS =====

    # 1. Verdict (top of report)
    verdict: VerdictSection

    # 2. Executive Summary
    executive_summary: str = ""

    # 3. Key Findings (top findings)
    key_findings: list[FindingDetail] = Field(default_factory=list)

    # 4. Sender Intelligence
    sender: SenderIntelligence = Field(default_factory=SenderIntelligence)

    # 5. Authentication
    authentication: AuthenticationSection = Field(default_factory=AuthenticationSection)

    # 6. URL Intelligence
    urls: URLIntelligence = Field(default_factory=URLIntelligence)

    # 7. Content Analysis
    content: ContentAnalysisSection = Field(default_factory=ContentAnalysisSection)

    # 8. Attachment Analysis
    attachments: AttachmentSection = Field(default_factory=AttachmentSection)

    # 9. Header Forensics
    headers: HeaderForensics = Field(default_factory=HeaderForensics)

    # 10. Threat Intelligence
    threat_intel: ThreatIntelSection = Field(default_factory=ThreatIntelSection)

    # 11. IOC Inventory
    iocs: IOCInventory = Field(default_factory=IOCInventory)

    # 12. Risk Breakdown
    risk_breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)

    # 13. Campaign Correlation (if batch)
    campaign: Optional[CampaignIndicators] = None

    # 14. All Findings (detailed)
    all_findings: list[FindingDetail] = Field(default_factory=list)

    # 15. Recommendations
    recommendations: list[RecommendationItem] = Field(default_factory=list)

    # 16. Detection Status Summary
    detection_status: dict[str, str] = Field(default_factory=dict)

    # Raw data (for debugging/advanced users)
    raw_email_metadata: Optional[dict[str, Any]] = None


def get_risk_level(score: int) -> RiskLevel:
    """Convert risk score to risk level."""
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 60:
        return RiskLevel.HIGH
    elif score >= 30:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW
