"""Authenticated tenant-scoped incident lifecycle endpoints."""

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.agents.base import AgentType
from app.agents.dispatcher import get_dispatcher
from app.api.v1.logs import TenantAuthorization, get_authorized_tenant_ids
from app.auth.jwt import get_current_active_user
from app.auth.models import User, UserRole
from app.database.repositories.findings import get_finding_repository
from app.database.repositories.incidents import get_incident_repository

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class QualifyRequest(BaseModel):
    finding_id: str = Field(..., min_length=1)


class StatusUpdateRequest(BaseModel):
    status: Literal["investigating", "containment_in_progress", "resolved", "closed"]
    reason: str = Field(..., min_length=3, max_length=1000)


def _require_manager(user: User) -> None:
    if user.role not in (UserRole.ADMIN, UserRole.ANALYST):
        raise HTTPException(status_code=403, detail="Only analysts and administrators can manage incidents")


def _serialize(incident: Any) -> dict[str, Any]:
    return incident.model_dump(mode="json", exclude={"tenant_id", "fingerprint"})


@router.get("")
async def list_incidents(
    limit: int = Query(100, ge=1, le=500),
    status: Literal["open", "investigating", "containment_in_progress", "resolved", "closed"] | None = None,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
    _user: User = Depends(get_current_active_user),
) -> list[dict[str, Any]]:
    incidents = await get_incident_repository().list(auth.tenant_ids, limit=limit, status=status)
    return [_serialize(incident) for incident in incidents]


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
    _user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    incident = await get_incident_repository().get(incident_id, auth.tenant_ids)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize(incident)


@router.post("/qualify")
async def qualify_finding(
    request: QualifyRequest,
    user: User = Depends(get_current_active_user),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict[str, Any]:
    _require_manager(user)
    finding = await get_finding_repository().get(request.finding_id, tenant_ids=auth.tenant_ids)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.tenant_id:
        raise HTTPException(status_code=409, detail="Finding has no verified tenant ownership")

    result = await get_dispatcher().dispatch(
        AgentType.INCIDENT_RESPONSE,
        {
            "finding_id": finding.id,
            "tenant_id": finding.tenant_id,
            "actor_id": user.id,
        },
    )
    if not result.success:
        raise HTTPException(status_code=503, detail=result.error or result.summary)
    return {
        "classification": result.classification,
        "summary": result.summary,
        "recommendations": result.recommendations,
        "metadata": result.metadata,
    }


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    request: StatusUpdateRequest,
    user: User = Depends(get_current_active_user),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict[str, Any]:
    _require_manager(user)
    try:
        incident = await get_incident_repository().transition(
            incident_id=incident_id,
            tenant_ids=auth.tenant_ids,
            status=request.status,
            actor_id=user.id,
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize(incident)
