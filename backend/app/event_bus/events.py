"""
CyberGuard AI - Event Bus Events

Common event envelope for all security events.

The SecurityEvent model defines the standard envelope for all events
flowing through the Redpanda event bus. It is designed for:
- Schema versioning for forward/backward compatibility
- Unique event IDs for idempotency
- Correlation IDs for tracing related events
- Tenant isolation where applicable
- Timestamps for ordering and debugging

Note: This reuses the existing EventType enum from app.database.models.base
to avoid duplicate event type definitions.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.database.models.base import EventType, SeverityLevel


class EventEnvelope(BaseModel):
    """
    Base event envelope for all Redpanda events.

    Every event published to the event bus MUST use this envelope.
    The payload field contains the event-specific data.

    Attributes:
        event_id: Unique identifier for this event (for idempotency)
        event_type: Type of security event (email, log, network, etc.)
        schema_version: Version of the event schema (for compatibility)
        timestamp: When the event was created (UTC ISO format)
        source: System/component that generated the event
        correlation_id: ID to correlate related events (optional)
        tenant_id: Tenant identifier for multi-tenant deployments (optional)
        payload: Event-specific data
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique event identifier (UUID)",
    )
    event_type: str = Field(
        ...,
        description="Type of event (e.g., 'email', 'log', 'network')",
    )
    schema_version: int = Field(
        default=1,
        description="Schema version for compatibility checking",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event creation timestamp (UTC)",
    )
    source: str = Field(
        ...,
        description="System/component that generated the event",
    )
    correlation_id: str | None = Field(
        default=None,
        description="ID to correlate related events",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Tenant identifier for multi-tenant deployments",
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific data",
    )

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "payload": self.payload,
        }


class SecurityEvent(EventEnvelope):
    """
    Security-specific event with severity and classification.

    Extends the base envelope with security-relevant fields.
    Used for security events flowing through the security-events topic.
    """

    severity: SeverityLevel = Field(
        default=SeverityLevel.INFO,
        description="Event severity level",
    )
    classification: str | None = Field(
        default=None,
        description="Threat classification (e.g., 'phishing', 'malware')",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Risk score (0-100)",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="IOCs or indicators extracted from the event",
    )

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        base = super().to_json_dict()
        base.update({
            "severity": self.severity.value,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "indicators": self.indicators,
        })
        return base


class DeadLetterEvent(BaseModel):
    """
    Event wrapper for messages that failed processing.

    When a message cannot be processed (malformed, validation error, etc.),
    it is wrapped in a DeadLetterEvent and sent to the dead-letter topic
    for investigation.

    Attributes:
        dlq_id: Unique ID for this dead letter entry
        original_topic: Topic the message came from
        original_partition: Partition the message came from (if available)
        original_offset: Offset of the message (if available)
        original_event_id: Event ID if extractable from the payload
        failure_reason: Human-readable reason for failure
        failure_type: Category of failure (validation, deserialization, etc.)
        failed_at: Timestamp when failure occurred
        original_payload: Raw message content (if safe to include)
        retry_count: Number of times processing was attempted
    """

    dlq_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique dead letter entry ID",
    )
    original_topic: str = Field(
        ...,
        description="Topic the message originated from",
    )
    original_partition: int | None = Field(
        default=None,
        description="Partition number (if available)",
    )
    original_offset: int | None = Field(
        default=None,
        description="Message offset (if available)",
    )
    original_event_id: str | None = Field(
        default=None,
        description="Event ID if extractable from payload",
    )
    failure_reason: str = Field(
        ...,
        description="Human-readable failure reason",
    )
    failure_type: str = Field(
        default="unknown",
        description="Failure category (validation, deserialization, processing)",
    )
    failed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when failure occurred",
    )
    original_payload: str | None = Field(
        default=None,
        description="Original message content (if safe to include)",
    )
    retry_count: int = Field(
        default=0,
        description="Number of processing attempts",
    )

    def to_json_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "dlq_id": self.dlq_id,
            "original_topic": self.original_topic,
            "original_partition": self.original_partition,
            "original_offset": self.original_offset,
            "original_event_id": self.original_event_id,
            "failure_reason": self.failure_reason,
            "failure_type": self.failure_type,
            "failed_at": self.failed_at.isoformat(),
            "original_payload": self.original_payload,
            "retry_count": self.retry_count,
        }
