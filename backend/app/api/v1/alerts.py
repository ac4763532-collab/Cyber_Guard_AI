"""
CyberGuard AI - Alerts API Endpoints

Alert management and notification endpoints.
Uses PostgreSQL for persistent storage via AlertRepository.
"""

from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database.models import AlertStatus, SeverityLevel, AlertCreate, AlertUpdate, Alert
from app.database.repositories.alerts import get_alert_repository
from app.websocket import broadcast_alert, WSEventType

# Reused, not reimplemented: the same JWT-authenticated tenant-resolution
# dependency app/api/v1/logs.py already defines (admin -> tenant_ids=None
# "see all", any other role -> pinned to their own organization_id). No
# second tenant-authorization implementation is introduced here.
from app.api.v1.logs import TenantAuthorization, get_authorized_tenant_ids

logger = structlog.get_logger(__name__)


router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertCreateRequest(BaseModel):
    """Request to create an alert."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field("", max_length=5000)
    severity: SeverityLevel
    risk_score: int = Field(0, ge=0, le=100)
    source: str = Field("manual", max_length=100)
    event_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class AlertUpdateRequest(BaseModel):
    """Request to update an alert."""

    status: AlertStatus | None = None
    assigned_to: str | None = None
    note: str | None = None


class AlertResponse(BaseModel):
    """Alert response model."""

    id: str
    title: str
    description: str
    severity: str
    risk_score: int
    status: str
    source: str
    assigned_to: str | None = None
    event_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    notes: list[dict[str, Any]] = Field(default_factory=list)
    category: str | None = None
    created_at: str
    updated_at: str
    acknowledged_at: str | None = None
    resolved_at: str | None = None


def _db_alert_to_response(alert: Alert) -> AlertResponse:
    """Convert database Alert model to API response."""
    return AlertResponse(
        id=alert.id,
        title=alert.title,
        description=alert.description or "",
        severity=alert.severity.value if isinstance(alert.severity, SeverityLevel) else alert.severity,
        risk_score=alert.risk_score,
        status=alert.status.value if isinstance(alert.status, AlertStatus) else alert.status,
        source="manual",  # Source not stored in DB schema, default to manual
        assigned_to=alert.assigned_to,
        event_id=alert.event_id,
        finding_ids=alert.finding_ids,
        iocs=[],  # IOCs not stored in current schema
        mitre_techniques=alert.mitre_techniques,
        notes=alert.notes,
        category=alert.category,
        created_at=alert.created_at.isoformat() if isinstance(alert.created_at, datetime) else str(alert.created_at),
        updated_at=alert.updated_at.isoformat() if isinstance(alert.updated_at, datetime) else str(alert.updated_at),
        acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
    )


@router.post(
    "",
    response_model=AlertResponse,
    summary="Create Alert",
    description="Create a new security alert.",
)
async def create_alert(request: AlertCreateRequest) -> AlertResponse:
    """Create a new alert."""
    repo = get_alert_repository()

    # Create alert via repository
    alert_create = AlertCreate(
        title=request.title,
        description=request.description,
        severity=request.severity,
        risk_score=request.risk_score,
        event_id=request.event_id,
        finding_ids=request.finding_ids,
    )

    alert = await repo.create(alert_create)

    # Pre-existing gap, not introduced here: AlertCreate/repo.create() has
    # no tenant_id field at all, so a manually-created alert never gets a
    # tenant_id. That means it is invisible to the new tenant-scoped
    # real-time delivery path (broadcast_alert_to_tenant /
    # GET /alerts/recent, both of which require a concrete tenant_id) -
    # it will still appear in the untenanted broadcast_alert() call below
    # and in GET /alerts, just not pushed as a tenant-scoped popup. Not
    # fixed here (would require a schema/model change out of scope for
    # this feature); surfaced loudly so it isn't silently invisible.
    if not getattr(alert, "tenant_id", None):
        logger.warning(
            "Alert created via POST /alerts has no tenant_id - it will "
            "not be delivered through the tenant-scoped real-time alert "
            "popup/siren path (only the legacy untenanted WS broadcast)",
            alert_id=alert.id,
        )

    # Broadcast new alert via WebSocket
    await broadcast_alert(
        alert_id=alert.id,
        title=request.title,
        severity=request.severity.value,
        event_type=WSEventType.NEW_ALERT,
        additional_data={"risk_score": request.risk_score},
    )

    return _db_alert_to_response(alert)


@router.get(
    "",
    response_model=list[AlertResponse],
    summary="List Alerts",
    description="List alerts with optional filters.",
)
async def list_alerts(
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    category: str | None = Query(
        None,
        description="Filter by category: email_security, log_security, network_security, correlated_threat",
    ),
    limit: int = Query(50, ge=1, le=100, description="Max results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
) -> list[AlertResponse]:
    """List alerts with filters."""
    repo = get_alert_repository()

    alerts = await repo.list(
        limit=limit,
        offset=offset,
        status=status,
        severity=severity,
        category=category,
    )

    return [_db_alert_to_response(a) for a in alerts]


@router.get(
    "/statistics",
    summary="Get Alert Statistics",
    description="Get alert statistics.",
)
async def get_statistics() -> dict[str, Any]:
    """Get alert statistics."""
    repo = get_alert_repository()

    by_status = await repo.count_by_status()
    by_severity = await repo.count_by_severity()

    # Calculate total and open counts
    total = sum(by_status.values())
    open_statuses = ["new", "acknowledged", "investigating"]
    open_count = sum(by_status.get(s, 0) for s in open_statuses)

    return {
        "total": total,
        "open": open_count,
        "by_status": by_status,
        "by_severity": by_severity,
    }


@router.get(
    "/recent",
    response_model=list[AlertResponse],
    summary="Get Recently Delivered Alerts",
    description=(
        "Recover alerts the caller may have missed while disconnected "
        "from the real-time WebSocket feed. Tenant-scoped exactly like "
        "every other query in this router: admins see every tenant, any "
        "other role is pinned to their own organization_id regardless of "
        "what is requested."
    ),
)
async def get_recent_alerts(
    since: datetime | None = Query(
        None,
        description=(
            "ISO 8601 timestamp - only alerts created at or after this "
            "time are returned. Pass the timestamp of the last alert the "
            "client successfully processed to catch up without "
            "re-fetching everything."
        ),
    ),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> list[AlertResponse]:
    """
    This route must stay registered before GET /{alert_id} - FastAPI
    matches routes in registration order, and /{alert_id} would otherwise
    swallow the literal path "/recent" as if "recent" were an alert id.
    """
    repo = get_alert_repository()

    alerts = await repo.list_recent_for_tenants(
        tenant_ids=auth.tenant_ids,
        since=since,
        limit=limit,
    )

    return [_db_alert_to_response(a) for a in alerts]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get Alert",
    description="Get alert details by ID.",
)
async def get_alert(alert_id: str) -> AlertResponse:
    """Get an alert by ID."""
    repo = get_alert_repository()

    alert = await repo.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _db_alert_to_response(alert)


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update Alert",
    description="Update an alert's status or assignment.",
)
async def update_alert(alert_id: str, update: AlertUpdateRequest) -> AlertResponse:
    """Update an alert."""
    repo = get_alert_repository()

    # Check alert exists
    existing = await repo.get(alert_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Alert not found")

    old_status = existing.status

    # Build update object
    alert_update = AlertUpdate(
        status=update.status,
        assigned_to=update.assigned_to,
        notes=update.note,
    )

    updated = await repo.update(alert_id, alert_update)
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update alert")

    # Broadcast status change
    if update.status:
        event_type = WSEventType.ALERT_RESOLVED if update.status == AlertStatus.RESOLVED else WSEventType.ALERT_UPDATED
        await broadcast_alert(
            alert_id=alert_id,
            title=updated.title,
            severity=updated.severity.value if isinstance(updated.severity, SeverityLevel) else updated.severity,
            event_type=event_type,
            additional_data={
                "old_status": old_status.value if isinstance(old_status, AlertStatus) else old_status,
                "new_status": update.status.value,
            },
        )

    return _db_alert_to_response(updated)


@router.delete(
    "/{alert_id}",
    summary="Delete Alert",
    description="Delete an alert (soft delete by marking as resolved).",
)
async def delete_alert(alert_id: str) -> dict[str, str]:
    """Delete an alert."""
    repo = get_alert_repository()

    existing = await repo.get(alert_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Soft delete - mark as resolved
    alert_update = AlertUpdate(status=AlertStatus.RESOLVED)
    await repo.update(alert_id, alert_update)

    return {"status": "deleted", "alert_id": alert_id}
