"""
CyberGuard AI — Collector Endpoints
============================================================================
Endpoints used directly by the Windows and Linux endpoint collectors:
  - POST /api/v1/collector/enroll    — Redeem single-use token for credential
  - POST /api/v1/collector/heartbeat — Keep-alive & health metrics
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.deps import DBDep
from app.core.constants import HEADER_COLLECTOR_CREDENTIAL, HEADER_COLLECTOR_ID
from app.core.exceptions import CollectorAuthError
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.enums import SourceStatus
from app.models.source import SourceCredential as CollectorCredential
from app.services import collector_credential_service, enrollment_service
from app.services.collector_credential_service import VerifiedCredential

logger = get_logger(__name__)

router = APIRouter(
    prefix="/collector",
    tags=["collector"],
)


# ============================================================================
# SCHEMAS
# ============================================================================

class CollectorEnrollRequest(BaseModel):
    token: str = Field(..., description="Plaintext single-use enrollment token")
    collector_id: uuid.UUID = Field(..., description="Collector device UUID")
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    hardware_fingerprint: Optional[str] = None


class CollectorEnrollResponse(BaseModel):
    plaintext_credential: str
    credential_prefix: str
    collector_credential_id: uuid.UUID
    expires_at: Optional[str] = None
    heartbeat_interval_seconds: int = 60


class CollectorHeartbeatRequest(BaseModel):
    collector_id: uuid.UUID
    hostname: Optional[str] = None
    queue_depth: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None


class CollectorHeartbeatResponse(BaseModel):
    status: str = "ok"
    timestamp: str
    collection_active: bool = True


# ============================================================================
# DEPENDENCY
# ============================================================================

def get_verified_collector(
    db: Session = Depends(get_db),
    collector_credential: Optional[str] = Header(
        default=None,
        alias=HEADER_COLLECTOR_CREDENTIAL,
    ),
    collector_id: Optional[str] = Header(
        default=None,
        alias=HEADER_COLLECTOR_ID,
    ),
) -> VerifiedCredential:
    if not collector_credential:
        raise CollectorAuthError(
            message=f"Missing {HEADER_COLLECTOR_CREDENTIAL} header.",
            code="COLLECTOR_CREDENTIAL_HEADER_MISSING",
        )
    return collector_credential_service.verify_credential(
        db, collector_credential, from_ip=None,
    )


# ============================================================================
# ROUTES
# ============================================================================

@router.post(
    "/enroll",
    response_model=CollectorEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Redeem collector enrollment token",
)
def enroll_collector(
    payload: CollectorEnrollRequest,
    db: DBDep,
    request: Request,
) -> CollectorEnrollResponse:
    """
    Redeems an enrollment token issued by an organization or user workspace.
    Returns long-lived collector credential exactly once.
    """
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    result = enrollment_service.redeem_token(
        db,
        plaintext_token=payload.token,
        collector_id=payload.collector_id,
        hostname=payload.hostname,
        os_version=payload.os_version,
        agent_version=payload.agent_version,
        hardware_fingerprint=payload.hardware_fingerprint,
        redeemed_ip=client_ip,
        redeemed_user_agent=user_agent,
    )

    if payload.os_version:
        result.source.os_version = payload.os_version[:64]
    if payload.agent_version:
        result.source.agent_version = payload.agent_version[:32]
    if payload.hostname:
        result.source.hostname = payload.hostname[:255]
    if client_ip:
        result.source.ip_address = client_ip[:45]

    # Record real installation progress checkpoints
    now_iso = datetime.now(timezone.utc).isoformat()
    if isinstance(result.source.config, dict):
        cfg = dict(result.source.config)
        prog = cfg.get("installation_progress", {})
        prog["device_authenticated"] = True
        prog["device_authenticated_at"] = now_iso
        prog["device_enrolled"] = True
        prog["device_enrolled_at"] = now_iso
        cfg["installation_progress"] = prog
        result.source.config = cfg
        flag_modified(result.source, "config")

    db.commit()

    return CollectorEnrollResponse(
        plaintext_credential=result.plaintext_credential,
        credential_prefix=result.credential_prefix,
        collector_credential_id=result.collector_credential_id,
        expires_at=result.credential_expires_at.isoformat() if result.credential_expires_at else None,
        heartbeat_interval_seconds=result.heartbeat_interval_seconds,
    )


@router.post(
    "/heartbeat",
    response_model=CollectorHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Collector keep-alive heartbeat",
)
def heartbeat_collector(
    payload: CollectorHeartbeatRequest,
    db: DBDep,
    verified: VerifiedCredential = Depends(get_verified_collector),
) -> CollectorHeartbeatResponse:
    """
    Records heartbeat from an enrolled collector. Updates source last_heartbeat_at
    and collector_connected flag.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    verified.source.last_heartbeat_at = now
    verified.source.collector_connected = True
    if payload.hostname:
        verified.source.hostname = payload.hostname
    if not verified.source.agent_version:
        verified.source.agent_version = "1.0.0"

    now_iso = now.isoformat()
    if isinstance(verified.source.config, dict):
        cfg = dict(verified.source.config)
        prog = cfg.get("installation_progress", {})
        prog["service_started"] = True
        prog["service_started_at"] = prog.get("service_started_at") or now_iso
        prog["first_heartbeat_received"] = True
        prog["first_heartbeat_at"] = prog.get("first_heartbeat_at") or now_iso
        cfg["installation_progress"] = prog
        verified.source.config = cfg
        flag_modified(verified.source, "config")

    db.flush()
    db.commit()

    return CollectorHeartbeatResponse(
        status="ok",
        timestamp=now.isoformat(),
        collection_active=bool(verified.source.collection_active),
    )


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Collector subsystem health check",
)
def collector_health():
    return {
        "status": "healthy",
        "service": "CyberGuard Collector Gateway",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/config",
    status_code=status.HTTP_200_OK,
    summary="Fetch runtime collector configuration and scopes",
)
def get_collector_config(
    verified: VerifiedCredential = Depends(get_verified_collector),
):
    source = verified.source
    return {
        "source_id": str(source.id),
        "source_name": source.name,
        "os_type": source.source_type.value if hasattr(source.source_type, "value") else str(source.source_type),
        "collection_active": bool(source.collection_active),
        "heartbeat_interval_seconds": 30,
        "batch_size": 50,
        "flush_interval_seconds": 10,
        "monitored_channels": [
            "Security",
            "System",
        ] if "windows" in str(source.source_type).lower() else ["syslog", "auth", "journal"],
    }


@router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    summary="Collector self-revocation on graceful uninstall",
)
def revoke_collector(
    db: DBDep,
    verified: VerifiedCredential = Depends(get_verified_collector),
):
    source = verified.source
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
        c.revocation_reason = "Revoked by collector uninstall"

    db.commit()
    return {"status": "revoked", "device_id": str(source.id)}


@router.get(
    "/update/check",
    status_code=status.HTTP_200_OK,
    summary="Check for latest collector updates",
)
def check_collector_update(
    os: str = "windows",
    current_version: str = "1.0.0",
):
    return {
        "latest_version": "1.0.0",
        "is_update_available": False,
        "download_url": "/api/v1/devices/installer",
        "sha256": "7b5e81301ea068be7ced1997485f1fd27459b4627722bbc2221308295a7c63b2",
        "mandatory": False,
        "changelog": "CyberGuard AI non-technical collector service release.",
    }
