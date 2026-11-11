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
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.agents.base import AgentContext
from app.agents.network_analysis.agent import NetworkAnalysisAgent
from app.api.deps import CurrentActiveUser, DBDep
from app.core.logging import get_logger
from app.models.enums import EventCategory, EventSeverity, SourceStatus, SourceType
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.source import SecuritySourceCreate
from app.services import enrollment_service, source_service, workspace_service
from app.services.ml_service import ml_engine

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


class EnrollNetworkSensorRequest(BaseModel):
    name: str = Field("Office Gateway Sensor", min_length=1, max_length=120)
    description: Optional[str] = "Network flow inspection & egress monitoring gateway"


class EnrollNetworkSensorResponse(BaseModel):
    sensor_id: str
    name: str
    source_key: str
    status: str
    enrollment_token: str
    docker_command: str
    linux_probe_command: str
    ingest_endpoint: str


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
            or_(
                SecuritySource.source_type == SourceType.NETWORK,
                SecuritySource.source_type.in_([SourceType.WINDOWS, SourceType.LINUX]),
            ),
            SecuritySource.collector_connected == True,
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

        # ML Threat Classification (Random Forest)
        ml_threat = ml_engine.predict_network_threat(
            src_bytes=flow.bytes_sent,
            dst_bytes=flow.bytes_received,
            dst_port=flow.destination_port,
            packet_count=max(1, (flow.bytes_sent + flow.bytes_received) // 128),
            duration_ms=120,
        )

        norm_payload = dict(event.normalized_payload or {})
        norm_payload["ml_threat"] = ml_threat
        event.normalized_payload = norm_payload

        is_flagged = False
        if res.findings:
            is_flagged = True
            for f in res.findings:
                f.workspace_id = workspace.id
                f.primary_event_id = event.id
                db.add(f)

        if ml_threat.get("attack_type") != "benign" and ml_threat.get("risk_score", 0) >= 70:
            is_flagged = True
            event.severity = EventSeverity.HIGH if ml_threat["risk_score"] < 90 else EventSeverity.CRITICAL

        if is_flagged:
            flagged += 1

        ingested += 1

    if payload.sensor_id:
        sensor = db.execute(
            select(SecuritySource).where(
                SecuritySource.id == payload.sensor_id,
                SecuritySource.workspace_id == workspace.id,
            )
        ).scalar_one_or_none()
        if sensor:
            now_dt = datetime.now(timezone.utc)
            sensor.last_heartbeat_at = now_dt
            sensor.last_event_at = now_dt
            sensor.collector_connected = True
            sensor.status = SourceStatus.ACTIVE
            sensor.events_ingested_count = (sensor.events_ingested_count or 0) + ingested
            db.add(sensor)

    db.commit()

    return {
        "status": "ingested",
        "total_flows": ingested,
        "flagged_threats": flagged,
    }


@router.post("/sensors/enroll", response_model=EnrollNetworkSensorResponse, status_code=status.HTTP_201_CREATED, summary="Enroll a network security sensor")
def enroll_network_sensor(
    payload: EnrollNetworkSensorRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> EnrollNetworkSensorResponse:
    workspace = _get_user_workspace(db, current_user)

    src_create = SecuritySourceCreate(
        name=payload.name.strip() or "Primary Network Gateway",
        description=payload.description,
        source_type=SourceType.NETWORK,
    )
    source = source_service.create_source(
        db,
        actor=current_user,
        workspace=workspace,
        payload=src_create,
    )
    source.collection_active = True
    source.os_version = "Gateway Sensor v1.0"
    source.agent_version = "1.0.0"

    _, plaintext_token = enrollment_service.create_enrollment_token(
        db,
        actor=current_user,
        source=source,
        ttl_minutes=60,
    )
    db.commit()
    db.refresh(source)

    server_base = "https://cyberguard-api-7z5k.onrender.com"
    docker_cmd = (
        f"docker run -d --name cyberguard-network-sensor --restart always --net=host \\\n"
        f"  -e CYBERGUARD_SERVER=\"{server_base}\" \\\n"
        f"  -e SENSOR_ID=\"{source.id}\" \\\n"
        f"  -e SENSOR_TOKEN=\"{plaintext_token}\" \\\n"
        f"  cyberguard/network-sensor:latest"
    )
    linux_cmd = (
        f"curl -sSL \"{server_base}/static/install_linux.sh\" | \\\n"
        f"  sudo bash -s -- --token \"{plaintext_token}\" --server \"{server_base}\" --device-id \"{source.id}\""
    )
    ingest_url = f"{server_base}/api/v1/network/telemetry"

    return EnrollNetworkSensorResponse(
        sensor_id=str(source.id),
        name=source.name,
        source_key=source.source_key,
        status="ready",
        enrollment_token=plaintext_token,
        docker_command=docker_cmd,
        linux_probe_command=linux_cmd,
        ingest_endpoint=ingest_url,
    )


@router.post("/sensors/{sensor_id}/verify", status_code=status.HTTP_200_OK, summary="Send verified test flows for network sensor")
def verify_network_sensor(
    sensor_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    workspace = _get_user_workspace(db, current_user)
    sensor = db.execute(
        select(SecuritySource).where(
            SecuritySource.id == sensor_id,
            SecuritySource.workspace_id == workspace.id,
        )
    ).scalar_one_or_none()
    if not sensor:
        raise HTTPException(status_code=404, detail="Network sensor not found in workspace")

    sample_flows = [
        IngestFlowItem(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.105",
            destination_ip="8.8.8.8",
            source_port=53214,
            destination_port=53,
            protocol="UDP",
            bytes_sent=74,
            bytes_received=128,
            action="allowed",
        ),
        IngestFlowItem(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.105",
            destination_ip="142.250.190.46",
            source_port=49822,
            destination_port=443,
            protocol="TCP",
            bytes_sent=1420,
            bytes_received=5820,
            action="allowed",
        ),
        IngestFlowItem(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.42",
            destination_ip="185.220.101.5",
            source_port=61234,
            destination_port=4444,
            protocol="TCP",
            bytes_sent=512,
            bytes_received=0,
            action="blocked",
        ),
    ]

    batch_req = IngestFlowBatchRequest(sensor_id=sensor_id, flows=sample_flows)
    result = ingest_network_telemetry(payload=batch_req, db=db, current_user=current_user)
    return {
        "status": "verified",
        "sensor_id": str(sensor_id),
        "sensor_name": sensor.name,
        "flows_ingested": result.get("total_flows", len(sample_flows)),
        "flagged_threats": result.get("flagged_threats", 0),
    }
