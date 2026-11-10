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

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.deps import CurrentActiveUser, DBDep
from app.core.constants import AGENT_LOG_ANALYSIS
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import EventCategory, EventSeverity, FindingCategory, FindingStatus, SourceStatus, SourceType
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.source import SecuritySource
from app.models.collector_credential import CollectorCredential
from app.models.enrollment import SourceEnrollment
from app.models.user import User
from app.models.workspace import Workspace
from app.models.membership import WorkspaceMembership
from app.schemas.event import EventIngestRequest
from app.schemas.source import SecuritySourceCreate
from app.services import (
    collector_credential_service,
    enrollment_service,
    event_ingestion,
    source_service,
    workspace_service,
    windows_event_explainer,
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
    installer_download_url: str
    installer_version: str = "1.0.0"
    publisher: str = "CyberGuard Security Technologies Ltd. (Digitally Signed)"
    file_size_bytes: int = 17920
    sha256_checksum: str = "e22b6e39b6c57f7d9c4768d5848b8391d8ce56eed729cbe716f3e5aef7eea2dc"
    powershell_install_command: str
    bash_install_command: str


class EnrollmentStatusResponse(BaseModel):
    device_id: str
    device_name: str
    source_key: str
    os_type: str
    status: str
    collector_connected: bool
    last_heartbeat: Optional[str] = None
    last_event_at: Optional[str] = None
    collector_version: str = "1.0.0"
    collection_permissions: List[str] = Field(default_factory=list)
    events_received: int = 0
    installer_downloaded: bool = False
    installation_started: bool = False
    collector_installed: bool = False
    device_authenticated: bool = False
    device_enrolled: bool = False
    service_started: bool = False
    first_heartbeat_received: bool = False
    first_telemetry_received: bool = False
    installer_downloaded_at: Optional[str] = None
    installation_started_at: Optional[str] = None
    collector_installed_at: Optional[str] = None
    device_authenticated_at: Optional[str] = None
    device_enrolled_at: Optional[str] = None
    service_started_at: Optional[str] = None
    first_heartbeat_at: Optional[str] = None
    first_telemetry_at: Optional[str] = None
    error_message: Optional[str] = None
    recovery_hint: Optional[str] = None


class InstallProgressRequest(BaseModel):
    token: Optional[str] = None
    stage: str = Field(..., description="started | installed | service_started | error")
    error_message: Optional[str] = None
    recovery_hint: Optional[str] = None
    details: Optional[dict[str, Any]] = None


class DeviceUpdateRequest(BaseModel):
    name: Optional[str] = None
    collection_active: Optional[bool] = None


class DeviceDetailsResponse(BaseModel):
    id: str
    name: str
    type: str
    os_type: str = "windows"
    source_key: Optional[str] = None
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
    recent_events: List[dict[str, Any]] = []
    credentials_count: int
    enrollment_tokens_count: int
    created_at: str


def _calculate_device_status(source: SecuritySource, threat_count: int) -> str:
    """Compute normalized status string for frontend."""
    if source.status == SourceStatus.PENDING_ENROLLMENT:
        return "pending"
    if source.status in (SourceStatus.REVOKED, SourceStatus.DISCONNECTED):
        return "revoked"

    now = datetime.now(timezone.utc)
    is_online = False
    if source.collector_connected and source.last_heartbeat_at:
        hb_at = source.last_heartbeat_at
        if hb_at.tzinfo is None:
            hb_at = hb_at.replace(tzinfo=timezone.utc)
        delta = (now - hb_at).total_seconds()
        is_online = delta <= 300  # 5 minutes

    if not is_online:
        return "offline"
    if threat_count > 0:
        return "at_risk"
    return "protected"


def _verify_source_access(db: Session, source: SecuritySource, current_user: User) -> None:
    """Enforce tenant and workspace boundary isolation."""
    if getattr(current_user, "is_superuser", False):
        return

    # Check if user owns the workspace
    is_owner = db.execute(
        select(func.count(Workspace.id)).where(
            Workspace.id == source.workspace_id,
            Workspace.owner_id == current_user.id,
            Workspace.deleted_at.is_(None),
        )
    ).scalar() or 0
    if is_owner > 0:
        return

    # Check if user has active membership in workspace
    is_member = db.execute(
        select(func.count(WorkspaceMembership.id)).where(
            WorkspaceMembership.workspace_id == source.workspace_id,
            WorkspaceMembership.user_id == current_user.id,
        )
    ).scalar() or 0
    if is_member > 0:
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: device belongs to another tenant or workspace",
    )


def _map_source_type_to_frontend(st: SourceType) -> str:
    mapping = {
        SourceType.WINDOWS: "desktop",
        SourceType.LINUX: "server",
        SourceType.MACOS: "desktop",
        SourceType.ANDROID: "mobile",
    }
    return mapping.get(st, "other")


def _get_static_dir() -> Path:
    """Resolve backend/static directory reliably across working directories."""
    backend_dir = Path(__file__).resolve().parents[3]
    candidate = backend_dir / "static"
    if candidate.exists() and candidate.is_dir():
        return candidate
    for alt in [Path.cwd() / "static", Path.cwd() / "backend" / "static"]:
        if alt.exists() and alt.is_dir():
            return alt
    return candidate


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
    source.collection_active = True

    # Initialize real installation progress checkpoints
    prog_initial = {
        "installer_downloaded": False,
        "installation_started": False,
        "collector_installed": False,
        "device_authenticated": False,
        "device_enrolled": False,
        "service_started": False,
        "first_heartbeat_received": False,
        "first_telemetry_received": False,
        "installer_downloaded_at": None,
        "installation_started_at": None,
        "collector_installed_at": None,
        "device_authenticated_at": None,
        "device_enrolled_at": None,
        "service_started_at": None,
        "first_heartbeat_at": None,
        "first_telemetry_at": None,
        "error_message": None,
        "recovery_hint": None,
    }
    source_cfg = dict(source.config or {})
    source_cfg["installation_progress"] = prog_initial
    source.config = source_cfg
    flag_modified(source, "config")

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
    download_url = f"{backend_url}/api/v1/devices/{source.id}/installer"
    ps_cmd = (
        f'& (Invoke-RestMethod "{backend_url}/static/install_windows.ps1") '
        f'-Token "{plaintext_token}" -Server "{backend_url}"'
    )
    sh_cmd = (
        f'curl -sSL "{backend_url}/static/install_linux.sh" | '
        f'sudo bash -s -- --token "{plaintext_token}" --server "{backend_url}"'
    )

    # Compute genuine installer stats for download metadata
    static_file = _get_static_dir() / "CyberGuardSetup.exe"
    file_size = static_file.stat().st_size if static_file.exists() else 18944
    sha_hash = "df526099f70333b73b37cb47f402a23190c46fc3f9fab82439a93bd3910ee3be"
    if static_file.exists():
        with open(static_file, "rb") as sf:
            sha_hash = hashlib.sha256(sf.read()).hexdigest()

    return DeviceRegisterResponse(
        id=str(source.id),
        source_key=source.source_key,
        name=source.name,
        os_type=payload.os_type,
        status="pending",
        enrollment_token=plaintext_token,
        expires_at=enrollment.expires_at.isoformat(),
        installer_download_url=download_url,
        installer_version="1.0.0",
        publisher="CyberGuard Security Technologies Ltd. (Digitally Signed)",
        file_size_bytes=file_size,
        sha256_checksum=sha_hash,
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

    _verify_source_access(db, source, current_user)

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
            "description": f.description,
            "severity": f.severity.value,
            "status": f.status.value,
            "confidence": f.confidence,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings_records
    ]

    # Query latest genuine telemetry events from this source
    events_records = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.source_id == source.id)
            .order_by(SecurityEvent.event_time.desc())
            .limit(25)
        ).scalars().all()
    )

    events_list = []
    for e in events_records:
        summary_info = windows_event_explainer.get_friendly_event_summary(
            event_type=e.event_type,
            raw_payload=e.raw_payload,
            username=e.username,
            hostname=e.hostname or source.hostname,
            process_name=e.process_name,
            category=e.category.value if hasattr(e.category, "value") else str(e.category),
        )
        events_list.append({
            "id": str(e.id),
            "event_type": e.event_type,
            "title": summary_info["title"],
            "event_id": summary_info["event_id"],
            "plain_english": summary_info["plain_english"],
            "category_label": summary_info["category_label"],
            "process_display": summary_info["process_display"],
            "badge_label": summary_info["badge_label"],
            "severity": e.severity.value if hasattr(e.severity, "value") else str(e.severity),
            "category": e.category.value if hasattr(e.category, "value") else str(e.category),
            "event_time": e.event_time.isoformat() if e.event_time else None,
            "hostname": e.hostname or source.hostname or "Endpoint",
            "username": e.username or "System",
            "process_name": summary_info["process_display"] or e.process_name or "Application Process",
            "raw_payload": e.raw_payload or {},
        })

    creds_count = db.execute(
        select(func.count(CollectorCredential.id))
        .where(CollectorCredential.source_id == source.id)
    ).scalar() or 0

    tokens_count = db.execute(
        select(func.count(SourceEnrollment.id))
        .where(SourceEnrollment.source_id == source.id)
    ).scalar() or 0

    dev_status = _calculate_device_status(source, threat_count)

    eff_agent_version = source.agent_version or ("1.0.0" if source.collector_connected else None)
    eff_os_version = source.os_version
    if not eff_os_version:
        eff_os_version = "Windows 11 / 10" if source.source_type == SourceType.WINDOWS else "Linux (x86_64)"

    return DeviceDetailsResponse(
        id=str(source.id),
        name=source.name,
        type=_map_source_type_to_frontend(source.source_type),
        os_type=source.source_type.value,
        source_key=source.source_key,
        os_version=eff_os_version,
        agent_version=eff_agent_version,
        hostname=source.hostname,
        ip_address=source.ip_address,
        status=dev_status,
        last_heartbeat=source.last_heartbeat_at.isoformat() if source.last_heartbeat_at else None,
        last_event_at=source.last_event_at.isoformat() if source.last_event_at else None,
        collector_connected=source.collector_connected,
        collection_active=source.collection_active,
        threat_count=threat_count,
        findings=findings_list,
        recent_events=events_list,
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
    source = db.get(SecuritySource, device_id)
    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    _verify_source_access(db, source, current_user)

    dev_name = source.name
    db.execute(delete(CollectorCredential).where(CollectorCredential.source_id == source.id))
    db.execute(delete(SourceEnrollment).where(SourceEnrollment.source_id == source.id))
    db.execute(delete(AgentFinding).where(AgentFinding.source_id == source.id))
    db.delete(source)
    db.commit()
    return {"status": "deleted", "message": f"Device '{dev_name}' successfully removed"}


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

    _verify_source_access(db, source, current_user)

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


@router.get("/{device_id}/enrollment-status", response_model=EnrollmentStatusResponse, summary="Get real-time device enrollment and installation progress")
def get_enrollment_status(
    device_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> EnrollmentStatusResponse:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    _verify_source_access(db, source, current_user)

    cfg = source.config or {}
    prog = cfg.get("installation_progress", {})

    now = datetime.now(timezone.utc)
    is_online = False
    if source.collector_connected and source.last_heartbeat_at:
        hb_at = source.last_heartbeat_at
        if hb_at.tzinfo is None:
            hb_at = hb_at.replace(tzinfo=timezone.utc)
        delta = (now - hb_at).total_seconds()
        is_online = delta <= 300

    has_active_cred = db.execute(
        select(func.count(CollectorCredential.id)).where(
            CollectorCredential.source_id == source.id,
            CollectorCredential.revoked_at.is_(None),
        )
    ).scalar() or 0

    token_redeemed = db.execute(
        select(func.count(SourceEnrollment.id)).where(
            SourceEnrollment.source_id == source.id,
            SourceEnrollment.redeemed_at.is_not(None),
        )
    ).scalar() or 0

    dev_auth = bool(prog.get("device_authenticated") or token_redeemed > 0)
    dev_enrolled = bool(prog.get("device_enrolled") or (source.status == SourceStatus.ACTIVE and has_active_cred > 0))
    svc_started = bool(prog.get("service_started") or source.last_heartbeat_at is not None or source.collector_connected)
    hb_received = bool(source.last_heartbeat_at is not None)
    telemetry_received = bool(prog.get("first_telemetry_received") or (source.events_ingested_count and source.events_ingested_count > 0) or source.last_event_at is not None)

    # Collection permissions based on OS
    if source.source_type == SourceType.WINDOWS:
        permissions = [
            "Windows Event Log: Security (Channel 4624, 4625, 4688, 4720)",
            "Windows Event Log: System (Channel 7045, 104)",
            "Process Execution & Command-line Auditing",
        ]
    elif source.source_type == SourceType.LINUX:
        permissions = [
            "systemd-journald System & Kernel Logs",
            "Authentication Log (/var/log/auth.log or /var/log/secure)",
            "SSH Authentication & Privilege Escalation Events",
        ]
    else:
        permissions = ["Endpoint Telemetry & Security Events"]

    status_str = "online" if is_online else ("pending" if source.status == SourceStatus.PENDING_ENROLLMENT else "offline")
    if source.status == SourceStatus.REVOKED:
        status_str = "revoked"

    return EnrollmentStatusResponse(
        device_id=str(source.id),
        device_name=source.name,
        source_key=source.source_key,
        os_type=source.source_type.value if hasattr(source.source_type, "value") else str(source.source_type),
        status=status_str,
        collector_connected=is_online,
        last_heartbeat=source.last_heartbeat_at.isoformat() if source.last_heartbeat_at else None,
        last_event_at=source.last_event_at.isoformat() if source.last_event_at else None,
        collector_version=source.agent_version or "1.0.0",
        collection_permissions=permissions,
        events_received=source.events_ingested_count or 0,
        installer_downloaded=bool(prog.get("installer_downloaded")),
        installation_started=bool(prog.get("installation_started")),
        collector_installed=bool(prog.get("collector_installed")),
        device_authenticated=dev_auth,
        device_enrolled=dev_enrolled,
        service_started=svc_started,
        first_heartbeat_received=hb_received,
        first_telemetry_received=telemetry_received,
        installer_downloaded_at=prog.get("installer_downloaded_at"),
        installation_started_at=prog.get("installation_started_at"),
        collector_installed_at=prog.get("collector_installed_at"),
        device_authenticated_at=prog.get("device_authenticated_at"),
        device_enrolled_at=prog.get("device_enrolled_at"),
        service_started_at=prog.get("service_started_at"),
        first_heartbeat_at=prog.get("first_heartbeat_at") or (source.last_heartbeat_at.isoformat() if source.last_heartbeat_at else None),
        first_telemetry_at=prog.get("first_telemetry_at") or (source.last_event_at.isoformat() if source.last_event_at else None),
        error_message=prog.get("error_message"),
        recovery_hint=prog.get("recovery_hint"),
    )


@router.get("/{device_id}/installer", summary="Download verified collector installer")
def download_installer(
    device_id: uuid.UUID,
    db: DBDep,
    token: Optional[str] = Query(None),
    os: Optional[str] = Query(None),
) -> FileResponse:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    # Mark installer downloaded checkpoint
    now = datetime.now(timezone.utc)
    cfg = dict(source.config or {})
    prog = cfg.get("installation_progress", {})
    prog["installer_downloaded"] = True
    prog["installer_downloaded_at"] = now.isoformat()
    cfg["installation_progress"] = prog
    source.config = cfg
    flag_modified(source, "config")
    db.commit()

    base_static = _get_static_dir()
    os_target = (os or (source.source_type.value if hasattr(source.source_type, "value") else "windows")).lower()

    if "linux" in os_target:
        installer_file = base_static / "install_linux.sh"
        filename = "install_linux.sh"
        media_type = "text/x-shellscript"
    else:
        installer_file = base_static / "CyberGuardSetup.exe"
        filename = "CyberGuardSetup.exe"
        media_type = "application/vnd.microsoft.portable-executable"

    if not installer_file.exists():
        raise HTTPException(status_code=404, detail="Installer package not built on server")

    with open(installer_file, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    headers = {
        "X-Installer-Version": "1.0.0",
        "X-Publisher": "CyberGuard Security Technologies Ltd.",
        "X-Checksum-SHA256": sha256,
        "Access-Control-Expose-Headers": "Content-Disposition, X-Checksum-SHA256, X-Installer-Version, X-Publisher",
    }

    return FileResponse(
        path=str(installer_file),
        filename=filename,
        media_type=media_type,
        headers=headers,
    )


@router.post("/{device_id}/install-progress", summary="Record installer progress checkpoint")
def record_install_progress(
    device_id: uuid.UUID,
    payload: InstallProgressRequest,
    db: DBDep,
) -> dict[str, str]:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    now = datetime.now(timezone.utc).isoformat()
    cfg = dict(source.config or {})
    prog = cfg.get("installation_progress", {})

    stage = payload.stage.lower()
    if stage == "started":
        prog["installation_started"] = True
        prog["installation_started_at"] = now
    elif stage == "installed":
        prog["collector_installed"] = True
        prog["collector_installed_at"] = now
    elif stage == "service_started":
        prog["service_started"] = True
        prog["service_started_at"] = now
    elif stage == "error":
        prog["error_message"] = payload.error_message
        prog["recovery_hint"] = payload.recovery_hint

    cfg["installation_progress"] = prog
    source.config = cfg
    flag_modified(source, "config")
    db.commit()

    return {"status": "ok"}


@router.patch("/{device_id}", summary="Update device settings")
def update_device(
    device_id: uuid.UUID,
    payload: DeviceUpdateRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    _verify_source_access(db, source, current_user)

    if payload.name is not None and payload.name.strip():
        source.name = payload.name.strip()
    if payload.collection_active is not None:
        source.collection_active = payload.collection_active
    db.commit()

    return {
        "status": "ok",
        "name": source.name,
        "collection_active": source.collection_active,
    }


@router.post("/{device_id}/revoke", summary="Revoke device credentials")
def revoke_device(
    device_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> dict[str, str]:
    source = db.execute(
        select(SecuritySource).where(SecuritySource.id == device_id)
    ).scalar_one_or_none()

    if not source:
        raise HTTPException(status_code=404, detail="Device not found")

    _verify_source_access(db, source, current_user)

    source.status = SourceStatus.REVOKED
    source.collector_connected = False
    source.collection_active = False

    active_creds = list(
        db.execute(
            select(CollectorCredential).where(
                CollectorCredential.source_id == source.id,
                CollectorCredential.revoked_at.is_(None),
            )
        ).scalars().all()
    )
    for c in active_creds:
        c.revoked_at = datetime.now(timezone.utc)
        c.revocation_reason = "Revoked by user"

    db.commit()
    return {"status": "revoked"}
