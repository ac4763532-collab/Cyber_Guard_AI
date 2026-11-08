"""
CyberGuard AI — Devices API Endpoints
============================================================================
Provides unified device management endpoints for frontend:
  - GET    /devices              — List user's enrolled devices
  - POST   /devices              — Register a new device and get enrollment token
  - GET    /devices/{id}         — Get specific device details
  - DELETE /devices/{id}         — Delete or archive device
  - POST   /devices/{id}/challenge — Generate a fresh enrollment challenge
  - POST   /devices/{id}/revoke  — Revoke credentials for this device
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentActiveUser, DBDep
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import SourceStatus, SourceType
from app.models.finding import AgentFinding
from app.models.source import SecuritySource
from app.models.collector_credential import CollectorCredential
from app.models.enrollment import SourceEnrollment
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.source import SecuritySourceCreate
from app.services import (
    collector_credential_service,
    enrollment_service,
    source_service,
    workspace_service,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/devices",
    tags=["devices"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    """Resolve or create the user's active personal workspace."""
    return workspace_service.create_personal_workspace(db, user)


class DeviceItem(BaseModel):
    id: str
    name: str
    type: str  # desktop | mobile | tablet | server | other
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: str  # protected | at_risk | offline | pending | revoked
    last_scan: Optional[str] = None
    last_heartbeat: Optional[str] = None
    threat_count: int = 0
    collector_connected: bool = False
    source_key: str
    created_at: str


class DeviceRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    os_type: str = Field("windows", description="windows | linux | macos | android | other")
    description: Optional[str] = None


class DeviceRegisterResponse(BaseModel):
    id: str
    source_key: str
    name: str
    os_type: str
    status: str
    enrollment_token: str
    expires_at: str
    powershell_install_command: str
    bash_install_command: str


class DeviceDetailsResponse(BaseModel):
    id: str
    name: str
    type: str
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    last_heartbeat: Optional[str] = None
    last_event_at: Optional[str] = None
    collector_connected: bool
    collection_active: bool
    threat_count: int
    findings: List[dict[str, Any]]
    credentials_count: int
    enrollment_tokens_count: int
    created_at: str


def _calculate_device_status(source: SecuritySource, threat_count: int) -> str:
    """Compute normalized status string for frontend."""
    if source.status == SourceStatus.PENDING_ENROLLMENT:
        return "pending"
    if source.status == SourceStatus.REVOKED or source.status == SourceStatus.DECOMMISSIONED:
        return "revoked"

    now = datetime.now(timezone.utc)
    is_online = False
    if source.collector_connected and source.last_heartbeat_at:
        delta = (now - source.last_heartbeat_at).total_seconds()
        is_online = delta <= 300  # 5 minutes

    if not is_online:
        return "offline"
    if threat_count > 0:
        return "at_risk"
    return "protected"


def _map_source_type_to_frontend(st: SourceType) -> str:
    mapping = {
        SourceType.WINDOWS: "desktop",
        SourceType.LINUX: "server",
        SourceType.MACOS: "desktop",
        SourceType.ANDROID: "mobile",
    }
    return mapping.get(st, "other")


@router.get("", response_model=List[DeviceItem], summary="List all enrolled devices for current user")
def list_devices(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> List[DeviceItem]:
    workspace = _get_user_workspace(db, current_user)

    sources = list(
        db.execute(
            select(SecuritySource)
            .where(SecuritySource.workspace_id == workspace.id)
            .order_by(SecuritySource.created_at.desc())
        ).scalars().all()
    )

    items: List[DeviceItem] = []
    for src in sources:
        # Count unresolved findings for this device
        threat_count = db.execute(
            select(func.count(AgentFinding.id))
            .where(
                AgentFinding.source_id == src.id,
                AgentFinding.status.in_(["new", "investigating", "acknowledged"]),
            )
        ).scalar() or 0

        dev_status = _calculate_device_status(src, threat_count)
        items.append(
            DeviceItem(
                id=str(src.id),
                name=src.name,
                type=_map_source_type_to_frontend(src.source_type),
                os_version=src.os_version,
                agent_version=src.agent_version,
                hostname=src.hostname,
                ip_address=src.ip_address,
                status=dev_status,
                last_scan=src.last_event_at.isoformat() if src.last_event_at else None,
                last_heartbeat=src.last_heartbeat_at.isoformat() if src.last_heartbeat_at else None,
                threat_count=threat_count,
                collector_connected=src.collector_connected,
                source_key=src.source_key,
                created_at=src.created_at.isoformat(),
            )
        )

    return items


@router.post("", response_model=DeviceRegisterResponse, status_code=status.HTTP_201_CREATED, summary="Register a device and get enrollment challenge")
def register_device(
    payload: DeviceRegisterRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> DeviceRegisterResponse:
    workspace = _get_user_workspace(db, current_user)

    st_map = {
        "windows": SourceType.WINDOWS,
        "linux": SourceType.LINUX,
        "macos": SourceType.MACOS,
        "android": SourceType.ANDROID,
    }
    src_type = st_map.get(payload.os_type.lower(), SourceType.OTHER)

    src_create = SecuritySourceCreate(
        name=payload.name,
        description=payload.description,
        source_type=src_type,
    )

    source = source_service.create_source(
        db,
        actor=current_user,
        workspace=workspace,
        payload=src_create,
    )

    # Issue single-use enrollment token
    enrollment, plaintext_token = enrollment_service.create_enrollment_token(
        db,
        actor=current_user,
        source=source,
        ttl_minutes=30,
    )

    db.commit()
    db.refresh(source)

    backend_url = "http://localhost:8000"
    ps_cmd = (
        f'& (Invoke-RestMethod "{backend_url}/static/install_windows.ps1") '
        f'-Token "{plaintext_token}" -Server "{backend_url}"'
    )
    sh_cmd = (
        f'curl -sSL "{backend_url}/static/install_linux.sh" | '
        f'sudo bash -s -- --token "{plaintext_token}" --server "{backend_url}"'
    )

    return DeviceRegisterResponse(
        id=str(source.id),
        source_key=source.source_key,
        name=source.name,
        os_type=payload.os_type,
        status="pending",
        enrollment_token=plaintext_token,
        expires_at=enrollment.expires_at.isoformat(),
        powershell_install_command=ps_cmd,
        bash_install_command=sh_cmd,
    )


@router.get("/{device_id}", response_model=DeviceDetailsResponse, summary="Get device details")
def get_device(
    device_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> DeviceDetailsResponse:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    threat_count = db.execute(
        select(func.count(AgentFinding.id))
        .where(
            AgentFinding.source_id == source.id,
            AgentFinding.status.in_(["new", "investigating", "acknowledged"]),
        )
    ).scalar() or 0

    findings_records = list(
        db.execute(
            select(AgentFinding)
            .where(AgentFinding.source_id == source.id)
            .order_by(AgentFinding.created_at.desc())
            .limit(10)
        ).scalars().all()
    )

    findings_list = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "confidence": f.confidence,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings_records
    ]

    creds_count = db.execute(
        select(func.count(CollectorCredential.id))
        .where(CollectorCredential.source_id == source.id)
    ).scalar() or 0

    tokens_count = db.execute(
        select(func.count(SourceEnrollment.id))
        .where(SourceEnrollment.source_id == source.id)
    ).scalar() or 0

    dev_status = _calculate_device_status(source, threat_count)

    return DeviceDetailsResponse(
        id=str(source.id),
        name=source.name,
        type=_map_source_type_to_frontend(source.source_type),
        os_version=source.os_version,
        agent_version=source.agent_version,
        hostname=source.hostname,
        ip_address=source.ip_address,
        status=dev_status,
        last_heartbeat=source.last_heartbeat_at.isoformat() if source.last_heartbeat_at else None,
        last_event_at=source.last_event_at.isoformat() if source.last_event_at else None,
        collector_connected=source.collector_connected,
        collection_active=source.collection_active,
        threat_count=threat_count,
        findings=findings_list,
        credentials_count=creds_count,
        enrollment_tokens_count=tokens_count,
        created_at=source.created_at.isoformat(),
    )


@router.delete("/{device_id}", status_code=status.HTTP_200_OK, summary="Delete device")
def delete_device(
    device_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, str]:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    source_service.archive_source(db, actor=current_user, source=source)
    db.commit()
    return {"status": "deleted"}


@router.post("/{device_id}/challenge", summary="Generate a fresh enrollment challenge for existing device")
def generate_challenge(
    device_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    # Put back to pending enrollment if needed
    source.status = SourceStatus.PENDING_ENROLLMENT
    db.flush()

    # Revoke any prior unredeemed tokens so fresh challenge can be issued
    active_tokens = list(
        db.execute(
            select(SourceEnrollment).where(
                SourceEnrollment.source_id == source.id,
                SourceEnrollment.redeemed_at.is_(None),
                SourceEnrollment.revoked_at.is_(None),
            )
        ).scalars().all()
    )
    for tok in active_tokens:
        enrollment_service.revoke_token(
            db, actor=current_user, token=tok, reason="Re-enrollment challenge requested"
        )
    db.flush()

    enrollment, plaintext_token = enrollment_service.create_enrollment_token(
        db,
        actor=current_user,
        source=source,
        ttl_minutes=15,
    )
    db.commit()

    return {
        "device_id": str(source.id),
        "enrollment_token": plaintext_token,
        "expires_at": enrollment.expires_at.isoformat(),
    }
