"""
CyberGuard AI — Network Security Endpoints
============================================================================
Handles network flow telemetry, sensor health, suspicious connection queries,
and real-time port sweep / anomalous egress detection.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.base import AgentContext
from app.agents.network_analysis.agent import NetworkAnalysisAgent
from app.api.deps import CurrentActiveUser, DBDep
from app.core.logging import get_logger
from app.models.enums import EventCategory, EventSeverity, SourceType
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.services import workspace_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/network",
    tags=["network"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    return workspace_service.create_personal_workspace(db, user)


class NetworkSummaryResponse(BaseModel):
    sensors: int
    flows_count: int
    suspicious: int
    active_threat_feeds: List[str]
    message: Optional[str] = None


class FlowRecord(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "TCP"
    severity: str
    action: str
    rule: Optional[str] = None
    threat_intel_match: bool = False


class IngestFlowItem(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    action: str = "allowed"


class IngestFlowBatchRequest(BaseModel):
    sensor_id: Optional[uuid.UUID] = None
    flows: List[IngestFlowItem]


@router.get("/summary", response_model=NetworkSummaryResponse, summary="Get network security telemetry summary")
def get_network_summary(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> NetworkSummaryResponse:
    workspace = _get_user_workspace(db, current_user)

    sensors_count = db.execute(
        select(func.count(SecuritySource.id))
        .where(
            SecuritySource.workspace_id == workspace.id,
            SecuritySource.source_type == SourceType.NETWORK,
        )
    ).scalar() or 0

    flows_count = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.category == EventCategory.NETWORK,
        )
    ).scalar() or 0

    suspicious_count = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.category == EventCategory.NETWORK,
            SecurityEvent.severity.in_([EventSeverity.HIGH, EventSeverity.CRITICAL]),
        )
    ).scalar() or 0

    msg = None
    if sensors_count == 0 and flows_count == 0:
        msg = "No authorized network sensor is connected."

    return NetworkSummaryResponse(
        sensors=sensors_count,
        flows_count=flows_count,
        suspicious=suspicious_count,
        active_threat_feeds=["Internal IOC Engine", "AbuseIPDB"],
        message=msg,
    )


@router.get("/flows", response_model=List[FlowRecord], summary="List ingested network flow records")
def list_network_flows(
    db: DBDep,
    current_user: CurrentActiveUser,
    limit: int = Query(50, ge=1, le=200),
) -> List[FlowRecord]:
    workspace = _get_user_workspace(db, current_user)

    events = list(
        db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.workspace_id == workspace.id,
                SecurityEvent.category == EventCategory.NETWORK,
            )
            .order_by(SecurityEvent.received_at.desc())
            .limit(limit)
        ).scalars().all()
    )

    items: List[FlowRecord] = []
    for ev in events:
        proto = "TCP"
        if ev.normalized_payload and "protocol" in ev.normalized_payload:
            proto = str(ev.normalized_payload["protocol"])

        rule_name = None
        if ev.normalized_payload and "rule" in ev.normalized_payload:
            rule_name = str(ev.normalized_payload["rule"])

        items.append(
            FlowRecord(
                id=str(ev.id),
                timestamp=ev.received_at.isoformat(),
                source_ip=ev.source_ip or "0.0.0.0",
                destination_ip=ev.destination_ip or "0.0.0.0",
                source_port=ev.source_port,
                destination_port=ev.destination_port,
                protocol=proto,
                severity=ev.severity.value,
                action=ev.action or "allowed",
                rule=rule_name,
                threat_intel_match=ev.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL],
            )
        )

    return items


@router.post("/telemetry", status_code=status.HTTP_201_CREATED, summary="Ingest network telemetry flow batch")
def ingest_network_telemetry(
    payload: IngestFlowBatchRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    workspace = _get_user_workspace(db, current_user)
    agent = NetworkAnalysisAgent(config={})

    ingested = 0
    flagged = 0

    for flow in payload.flows:
        ev_time = flow.timestamp or datetime.now(timezone.utc)
        fp_raw = f"{flow.source_ip}:{flow.source_port}->{flow.destination_ip}:{flow.destination_port}|{ev_time.isoformat()}"
        fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

        event = SecurityEvent(
            workspace_id=workspace.id,
            source_id=payload.sensor_id,
            event_time=ev_time,
            severity=EventSeverity.INFO,
            category=EventCategory.NETWORK,
            event_type="network_flow",
            action=flow.action,
            outcome="allowed",
            fingerprint=fp,
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            source_port=flow.source_port,
            destination_port=flow.destination_port,
            raw_payload=flow.model_dump(),
            normalized_payload={
                "protocol": flow.protocol,
                "bytes_sent": flow.bytes_sent,
                "bytes_received": flow.bytes_received,
            },
        )
        db.add(event)
        db.flush()

        ctx = AgentContext(db=db, event=event, source=None, workspace_id=workspace.id)
        res = agent.process(ctx)
        if res.findings:
            flagged += len(res.findings)
            for f in res.findings:
                f.workspace_id = workspace.id
                f.primary_event_id = event.id
                db.add(f)

        ingested += 1

    db.commit()

    return {
        "status": "ingested",
        "total_flows": ingested,
        "flagged_threats": flagged,
    }
