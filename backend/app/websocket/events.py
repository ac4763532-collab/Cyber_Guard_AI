"""
CyberGuard AI - WebSocket Events

Event types and broadcasting utilities.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
import structlog

from app.websocket.manager import get_connection_manager


logger = structlog.get_logger(__name__)


class WSEventType(str, Enum):
    """WebSocket event types."""

    # System events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    HEARTBEAT = "heartbeat"

    # Security events
    NEW_EVENT = "new_event"
    EVENT_UPDATED = "event_updated"

    # Alert events
    NEW_ALERT = "new_alert"
    ALERT_UPDATED = "alert_updated"
    ALERT_RESOLVED = "alert_resolved"

    # Agent events
    AGENT_STATUS = "agent_status"
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETE = "analysis_complete"

    # Detection events
    THREAT_DETECTED = "threat_detected"
    IOC_MATCHED = "ioc_matched"
    ANOMALY_DETECTED = "anomaly_detected"

    # Correlation events
    CORRELATION_FOUND = "correlation_found"


class WSEvent(BaseModel):
    """WebSocket event structure."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: WSEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Event data
    data: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    severity: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "severity": self.severity,
            "source": self.source,
        }


async def broadcast_event(
    event_type: WSEventType,
    data: dict[str, Any],
    channels: list[str] | None = None,
    severity: str | None = None,
    source: str | None = None,
) -> int:
    """
    Broadcast an event to WebSocket clients.

    Args:
        event_type: Type of event
        data: Event data
        channels: Channels to broadcast to (default: ["events"])
        severity: Event severity
        source: Event source

    Returns:
        Number of clients that received the message
    """
    manager = get_connection_manager()

    event = WSEvent(
        event_type=event_type,
        data=data,
        severity=severity,
        source=source,
    )

    target_channels = channels or ["events"]

    sent_count = await manager.broadcast_to_channels(
        event.to_dict(),
        target_channels,
    )

    logger.debug(
        "Event broadcast",
        event_type=event_type.value,
        channels=target_channels,
        recipients=sent_count,
    )

    return sent_count


async def broadcast_alert(
    alert_id: str,
    title: str,
    severity: str,
    event_type: WSEventType = WSEventType.NEW_ALERT,
    additional_data: dict[str, Any] | None = None,
) -> int:
    """Broadcast an alert event."""
    data = {
        "alert_id": alert_id,
        "title": title,
        "severity": severity,
        **(additional_data or {}),
    }

    return await broadcast_event(
        event_type=event_type,
        data=data,
        channels=["alerts", "system"],
        severity=severity,
        source="alert_system",
    )


async def broadcast_alert_to_tenant(
    tenant_id: str,
    alert_id: str,
    title: str,
    severity: str,
    event_type: WSEventType = WSEventType.NEW_ALERT,
    additional_data: dict[str, Any] | None = None,
) -> int:
    """
    Broadcast a new/updated alert to only the connections scoped to
    `tenant_id` (see ConnectionManager.broadcast_to_tenant /
    app/websocket/auth.py's resolve_tenant_scope).

    This is additive and deliberately separate from broadcast_alert():
    broadcast_alert() keeps its existing untenanted fan-out to every
    "alerts" channel subscriber (used today by the manual alerts.py
    endpoints), while this is the tenant-isolated path the correlation /
    finding-lifecycle pipeline uses for alerts created from real detection
    - callers must always have a concrete tenant_id (never broadcast
    cross-tenant; admin/unscoped connections rely on their own tenant_id
    being included in whichever tenant this fires for, not a separate
    all-tenants fan-out).
    """
    manager = get_connection_manager()

    event = WSEvent(
        event_type=event_type,
        data={
            "alert_id": alert_id,
            "title": title,
            "severity": severity,
            **(additional_data or {}),
        },
        severity=severity,
        source="alert_system",
    )

    sent_count = await manager.broadcast_to_tenant(
        event.to_dict(),
        tenant_id=tenant_id,
        channel="alerts",
    )

    logger.debug(
        "Tenant alert broadcast",
        event_type=event_type.value,
        alert_id=alert_id,
        tenant_id=tenant_id,
        recipients=sent_count,
    )

    return sent_count


async def broadcast_threat_detection(
    detection_id: str,
    findings_count: int,
    risk_score: int,
    highest_severity: str,
    source_agent: str,
) -> int:
    """Broadcast a threat detection event."""
    data = {
        "detection_id": detection_id,
        "findings_count": findings_count,
        "risk_score": risk_score,
        "highest_severity": highest_severity,
        "source_agent": source_agent,
    }

    return await broadcast_event(
        event_type=WSEventType.THREAT_DETECTED,
        data=data,
        channels=["events", "alerts"],
        severity=highest_severity,
        source=source_agent,
    )


async def broadcast_agent_status(
    agent_name: str,
    status: str,
    message: str | None = None,
) -> int:
    """Broadcast agent status update."""
    data = {
        "agent": agent_name,
        "status": status,
        "message": message,
    }

    return await broadcast_event(
        event_type=WSEventType.AGENT_STATUS,
        data=data,
        channels=["agents", "system"],
        source=agent_name,
    )
