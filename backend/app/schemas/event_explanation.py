"""
CyberGuard AI — Security Event Explanation Schemas
============================================================================
Pydantic DTOs for enriched security event explanations.
Supports both non-technical (Simple View) and security professional (Analyst View)
perspectives powered by genuine Windows event knowledge-base definitions.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import CyberGuardBaseSchema


class WhoInvolvedSchema(CyberGuardBaseSchema):
    """Details identifying users and security principals involved in the event."""

    account_name: Optional[str] = Field(default=None, description="Primary user account name")
    account_type: Optional[str] = Field(
        default="User Account",
        description="Type of account (e.g. System, Admin, Machine, or User)",
    )
    initiating_user: Optional[str] = Field(default=None, description="Account that triggered the activity")
    target_user: Optional[str] = Field(default=None, description="Target account acted upon")
    domain: Optional[str] = Field(default=None, description="Windows domain or local machine context")
    user_sid: Optional[str] = Field(default=None, description="Security Identifier (SID)")
    explanation: str = Field(
        ...,
        description="Plain-language description of who or what initiated this activity",
    )


class WhereHappenedSchema(CyberGuardBaseSchema):
    """Contextual location details distinguishing local monitored device from remote sources."""

    monitored_device: str = Field(..., description="The enrolled computer where the event was logged")
    source_workstation: Optional[str] = Field(
        default=None,
        description="Remote workstation/caller machine name if connection was remote",
    )
    source_ip: Optional[str] = Field(default=None, description="Originating network IP address")
    channel: Optional[str] = Field(default="Security", description="Windows Event Log channel")
    process_path: Optional[str] = Field(default=None, description="Executable program that performed the action")
    explanation: str = Field(
        ...,
        description="Plain-language explanation of where the event occurred",
    )


class WhenHappenedSchema(CyberGuardBaseSchema):
    """Precise temporal attributes with human-friendly relative time."""

    timestamp: datetime = Field(..., description="Exact event timestamp in UTC")
    timestamp_formatted: str = Field(..., description="Human readable formatted date and time")
    relative_time: str = Field(..., description="Relative time (e.g. '5 minutes ago')")
    timezone: str = Field(default="UTC", description="Time zone of record")


class SimpleViewSchema(CyberGuardBaseSchema):
    """Six essential answers for everyday computer users."""

    what_happened: str = Field(..., description="1. Plain English description of the event")
    who: WhoInvolvedSchema = Field(..., description="2. Who or what was involved")
    where: WhereHappenedSchema = Field(..., description="3. Where it occurred")
    when: WhenHappenedSchema = Field(..., description="4. When it occurred")
    why_it_matters: str = Field(..., description="5. Security context without exaggeration")
    what_should_i_do: List[str] = Field(
        default_factory=list,
        description="6. Actionable recommendations",
    )


class MitreAttackSchema(CyberGuardBaseSchema):
    """MITRE ATT&CK technique reference for security analysts."""

    technique_id: str = Field(..., description="Technique ID (e.g. T1078)")
    technique_name: str = Field(..., description="Technique name (e.g. Valid Accounts)")
    tactic: str = Field(..., description="Tactical category (e.g. Defense Evasion, Execution)")
    url: str = Field(..., description="Official MITRE ATT&CK documentation URL")
    mapping_reason: Optional[str] = Field(
        default=None,
        description="Reason why this technique applies based on detection engine evidence",
    )
    supporting_evidence: Optional[str] = Field(
        default=None,
        description="Specific indicators or rule matches establishing the technique",
    )


class AnalystViewSchema(CyberGuardBaseSchema):
    """Technical forensic evidence for cybersecurity analysts."""

    technical_properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted key-value technical properties (LogonType, Status, ProcessId, etc.)",
    )
    mitre_attack: Optional[MitreAttackSchema] = Field(
        default=None,
        description="Verified MITRE ATT&CK mapping if applicable",
    )
    detection_rule: Optional[str] = Field(
        default=None,
        description="Triggered detection rule ID if associated with a security finding",
    )
    raw_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Full original collected event payload",
    )


class EventExplanationResponse(CyberGuardBaseSchema):
    """Complete enriched explanation response for a security event."""

    event_id: uuid.UUID = Field(..., description="CyberGuard security event identifier")
    device_id: Optional[uuid.UUID] = Field(default=None, description="Associated device ID")
    device_name: str = Field(..., description="Associated device name or hostname")
    original_event_id: Optional[str] = Field(
        default=None,
        description="Original Windows Event ID (e.g. 4624, 4625, 4688, 7045)",
    )
    title: str = Field(..., description="Human-readable event title from knowledge base")
    short_description: str = Field(..., description="Brief one-sentence description")
    severity: str = Field(
        ...,
        description="Evaluated severity: 'informational', 'low', 'medium', 'high', 'critical'",
    )
    assessment: str = Field(
        ...,
        description="Behavioral assessment: 'normal', 'unusual', 'suspicious', 'unknown'",
    )
    threat_status: str = Field(
        ...,
        description="Threat lifecycle: 'no_threat_established', 'under_investigation', 'confirmed_threat'",
    )
    definition_status: str = Field(
        ...,
        description="KB verification: 'verified', 'partially_verified', 'unverified', 'unknown_definition'",
    )
    category: str = Field(..., description="Event category (Authentication, Process, System, etc.)")
    event_time: datetime = Field(..., description="Original event time")
    event_time_formatted: str = Field(..., description="Formatted event timestamp")
    relative_time: str = Field(..., description="Relative time string")

    simple_view: SimpleViewSchema = Field(..., description="Six-section simple view for users")
    analyst_view: AnalystViewSchema = Field(..., description="Technical evidence view for analysts")
