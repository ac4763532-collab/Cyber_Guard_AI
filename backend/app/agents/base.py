"""
CyberGuard AI - Base Agent Interface

All specialized security agents must implement this interface.
Provides a consistent contract for the Task Dispatcher.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AgentType(str, Enum):
    """Types of security analysis agents."""
    EMAIL = "email"
    LOG = "log"
    NETWORK = "network"
    THREAT_INTEL = "threat_intel"
    IOC_CORRELATION = "ioc_correlation"
    INCIDENT_RESPONSE = "incident_response"
    REPORTING = "reporting"


class Severity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentStatus(str, Enum):
    """Agent operational status."""
    PENDING = "pending"
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"


class Finding(BaseModel):
    """A single security finding from an agent."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str | None = Field(None, description="ID of the detection rule that triggered")
    name: str = Field(..., description="Short name of the finding")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    # Structured source attribution - optional because only LogAgent
    # populates these today (from parsed event dicts), and even there
    # host/timestamp are only available on SSH/sudo-regex-matched events,
    # not the generic auth-failure/success fallback. Email/network agents
    # leave all three None.
    #
    # timestamp is deliberately `str | None`, not `datetime`: syslog-style
    # timestamps ("Jan 15 10:23:45") carry no year, so parsing one into a
    # real datetime would require fabricating a year that isn't in the
    # source data. We store the raw matched string as-is rather than
    # invent precision we don't have.
    source_ip: str | None = Field(None, description="Source IP associated with this finding, if known")
    host: str | None = Field(None, description="Hostname associated with this finding, if known")
    timestamp: str | None = Field(None, description="Raw timestamp string of the triggering event, if known (syslog format has no year, so this is not parsed into a datetime)")


class AgentResult(BaseModel):
    """Result from an agent analysis."""

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_type: AgentType = Field(..., description="Type of agent that produced this result")
    agent_version: str = Field(default="0.1.0", description="Agent version")

    # Timing
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = Field(None)
    processing_time_ms: float | None = Field(None, description="Processing time in milliseconds")

    # Classification
    classification: str = Field(..., description="Overall classification (e.g., malicious, suspicious, benign)")
    severity: Severity = Field(..., description="Overall severity")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence score")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")

    # Findings
    findings: list[Finding] = Field(default_factory=list, description="Detailed findings")
    indicators: list[str] = Field(default_factory=list, description="IOCs extracted")

    # Summary
    summary: str = Field(..., description="Human-readable summary")
    recommendations: list[str] = Field(default_factory=list, description="Overall recommendations")

    # Raw data reference
    input_hash: str | None = Field(None, description="Hash of input data for deduplication")

    # Log-analysis-specific context - optional because only LogAgent
    # populates these; email/network agents leave them at their defaults.
    source: str | None = Field(None, description="Declared log source/type for this analysis, if known")
    processed_event_count: int | None = Field(None, description="Number of individual log events parsed and analyzed")
    affected_systems: list[str] = Field(default_factory=list, description="Unique hosts/IPs implicated across all findings")
    affected_accounts: list[str] = Field(default_factory=list, description="Unique usernames implicated across all findings")

    # Network-analysis-specific context - optional because only
    # NetworkAgent populates these; email/log agents leave them at their
    # defaults. data_source must be surfaced to the caller whenever a scan
    # could not actually be performed (e.g. nmap missing) and simulated
    # data was returned instead - never silently presenting fabricated
    # scan results as if they were real.
    data_source: str | None = Field(None, description="How this result's evidence was obtained, e.g. 'nmap' or 'simulated'")
    scan_warnings: list[str] = Field(default_factory=list, description="Non-fatal caveats about this scan, e.g. 'nmap not installed - results are simulated, not a real scan'")

    # Error handling
    success: bool = Field(True, description="Whether analysis completed successfully")
    error: str | None = Field(None, description="Error message if failed")

    # General-purpose extension bag. Optional because most agents leave it
    # empty - use it for result-level evidence that must survive regardless
    # of classification (e.g. ThreatIntelAgent's per-provider outcomes),
    # since `findings` is only populated for classifications that represent
    # a confirmed threat worth recording.
    metadata: dict[str, Any] = Field(default_factory=dict, description="Agent-specific extra data not covered by the fields above")

    def complete(self) -> None:
        """Mark the result as complete and calculate processing time."""
        self.completed_at = datetime.now(timezone.utc)
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.processing_time_ms = delta.total_seconds() * 1000


class BaseAgent(ABC):
    """
    Abstract base class for all security analysis agents.

    Each specialized agent (Email, Log, Network) must implement:
    - validate(): Validate the input data
    - analyze(): Perform the security analysis
    - get_status(): Return current agent status

    The base class provides common functionality for:
    - Result building
    - Error handling
    - Logging
    - Metrics
    """

    agent_type: AgentType
    agent_name: str
    agent_version: str = "0.1.0"

    def __init__(self):
        self._status = AgentStatus.PENDING
        self._total_analyzed = 0
        self._error_count = 0
        self._last_run: datetime | None = None
        self._last_successful_run: datetime | None = None

    @property
    def status(self) -> AgentStatus:
        """Get current agent status."""
        return self._status

    @property
    def stats(self) -> dict[str, Any]:
        """Get agent statistics."""
        return {
            "agent_type": self.agent_type.value,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "status": self._status.value,
            "total_analyzed": self._total_analyzed,
            "error_count": self._error_count,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "last_successful_run": (
                self._last_successful_run.isoformat()
                if self._last_successful_run
                else None
            ),
        }

    @abstractmethod
    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        """
        Validate input data before analysis.

        Args:
            data: Raw input data to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass

    @abstractmethod
    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        """
        Perform security analysis on the input data.

        Args:
            data: Validated input data

        Returns:
            AgentResult with findings and classification
        """
        pass

    async def run(self, data: dict[str, Any]) -> AgentResult:
        """
        Main entry point for running an analysis.

        Handles validation, execution, error handling, and metrics.

        Args:
            data: Raw input data

        Returns:
            AgentResult (may contain error if validation/analysis failed)
        """
        self._status = AgentStatus.BUSY
        self._last_run = datetime.now(timezone.utc)

        try:
            # Validate input
            is_valid, error = await self.validate(data)
            if not is_valid:
                self._error_count += 1
                self._status = AgentStatus.ERROR
                result = self._create_error_result(f"Validation failed: {error}")
                result.complete()
                return result

            # Run analysis
            result = await self.analyze(data)
            result.complete()

            self._total_analyzed += 1
            if result.success:
                self._last_successful_run = result.completed_at
                self._status = AgentStatus.ONLINE
            else:
                self._error_count += 1
                self._status = AgentStatus.ERROR

            return result

        except Exception as e:
            self._error_count += 1
            self._status = AgentStatus.ERROR
            result = self._create_error_result(f"Analysis error: {str(e)}")
            result.complete()
            return result

    def _create_error_result(self, error: str) -> AgentResult:
        """Create an error result."""
        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification="error",
            severity=Severity.INFO,
            confidence=0.0,
            risk_score=0,
            summary=f"Analysis failed: {error}",
            success=False,
            error=error,
        )

    def _create_result(
        self,
        classification: str,
        severity: Severity,
        confidence: float,
        risk_score: int,
        findings: list[Finding],
        summary: str,
        indicators: list[str] | None = None,
        recommendations: list[str] | None = None,
        source: str | None = None,
        processed_event_count: int | None = None,
        affected_systems: list[str] | None = None,
        affected_accounts: list[str] | None = None,
        data_source: str | None = None,
        scan_warnings: list[str] | None = None,
    ) -> AgentResult:
        """Helper to create a successful result."""
        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification=classification,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            indicators=indicators or [],
            summary=summary,
            recommendations=recommendations or [],
            success=True,
            source=source,
            processed_event_count=processed_event_count,
            affected_systems=affected_systems or [],
            affected_accounts=affected_accounts or [],
            data_source=data_source,
            scan_warnings=scan_warnings or [],
        )
