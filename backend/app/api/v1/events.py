"""
CyberGuard AI - Events API Endpoints

Security event ingestion and management.
Uses PostgreSQL for persistent storage via EventRepository.

Phase 1 (Log Collection -> Automatic Detection):
- Every route now requires a valid JWT and is scoped to the caller's
  authorized tenant(s) via get_authorized_tenant_ids(), reusing the
  exact TenantAuthorization pattern already established in
  app/api/v1/logs.py (no second auth implementation introduced here).
- tenant_id is always derived server-side from the authenticated
  caller - never trusted from client-supplied request fields.
- Cross-tenant lookups return 404 ("not found"), never 403, matching
  logs.py's no-existence-leakage convention.
- New findings routes: GET /events/{event_id}/findings,
  GET /findings/{finding_id}, PATCH /findings/{finding_id}.
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.v1.logs import TenantAuthorization, _not_found, get_authorized_tenant_ids
from app.auth.jwt import get_current_active_user
from app.auth.models import User
from app.config import get_settings
from app.database.models import (
    Event,
    EventCreate,
    EventStatus,
    EventType,
    Finding,
    FindingQuery,
    FindingStatus,
    SeverityLevel,
)
from app.database.repositories.events import get_event_repository
from app.database.repositories.findings import get_finding_repository
from app.detection import get_detection_engine
from app.services.audit import record_audit_event
from app.websocket import broadcast_event, WSEventType


router = APIRouter(prefix="/events", tags=["Events"])
findings_router = APIRouter(prefix="/findings", tags=["Findings"])


def require_findings_write(user: User = Depends(get_current_active_user)) -> User:
    """
    Dependency for mutating finding endpoints (status change).

    Requires the manage_incidents permission - findings status changes
    are an investigation action, reusing this existing permission tier
    rather than introducing a new permission category for a single new
    field.
    """
    if not user.has_permission("manage_incidents"):
        from fastapi import status as _status

        raise HTTPException(
            status_code=_status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to update findings",
        )
    return user


class EventCreateRequest(BaseModel):
    """Request to create/ingest an event."""

    event_type: EventType
    source: str = Field(..., min_length=1, max_length=255)
    raw_data: dict[str, Any]
    auto_analyze: bool = Field(True, description="Automatically run detection")


class EventResponse(BaseModel):
    """Event response model."""

    id: str
    event_type: str
    source: str
    status: str
    risk_score: int
    severity: str
    findings_count: int
    created_at: str
    processed_at: str | None = None


class FindingResponse(BaseModel):
    """Finding response model."""

    id: str
    event_id: str
    detection_id: str
    finding_type: str
    rule_id: str | None
    severity: str
    confidence: float
    title: str
    description: str
    evidence: dict[str, Any]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    status: str
    created_at: str


class FindingStatusUpdateRequest(BaseModel):
    """Request to update a finding's status."""

    status: FindingStatus


def _db_event_to_response(event: Event) -> EventResponse:
    """Convert database Event model to API response."""
    return EventResponse(
        id=event.id,
        event_type=event.event_type.value if isinstance(event.event_type, EventType) else event.event_type,
        source=event.source,
        status=event.status.value if isinstance(event.status, EventStatus) else event.status,
        risk_score=event.risk_score,
        severity=event.severity.value if isinstance(event.severity, SeverityLevel) else event.severity,
        findings_count=event.findings_count,
        created_at=event.created_at.isoformat() if isinstance(event.created_at, datetime) else str(event.created_at),
        processed_at=event.processed_at.isoformat() if event.processed_at else None,
    )


def _db_event_to_full_dict(event: Event) -> dict[str, Any]:
    """Convert database Event model to full dict response (includes raw_data)."""
    return {
        "id": event.id,
        "event_type": event.event_type.value if isinstance(event.event_type, EventType) else event.event_type,
        "source": event.source,
        "raw_data": event.raw_data,
        "status": event.status.value if isinstance(event.status, EventStatus) else event.status,
        "risk_score": event.risk_score,
        "severity": event.severity.value if isinstance(event.severity, SeverityLevel) else event.severity,
        "findings_count": event.findings_count,
        "created_at": event.created_at.isoformat() if isinstance(event.created_at, datetime) else str(event.created_at),
        "updated_at": event.updated_at.isoformat() if isinstance(event.updated_at, datetime) else str(event.updated_at),
        "processed_at": event.processed_at.isoformat() if event.processed_at else None,
        "correlation_id": event.correlation_id,
        "related_events": event.related_events,
    }


def _db_finding_to_response(finding: Finding) -> FindingResponse:
    """Convert database Finding model to API response."""
    return FindingResponse(
        id=finding.id,
        event_id=finding.event_id,
        detection_id=finding.detection_id,
        finding_type=finding.finding_type,
        rule_id=finding.rule_id,
        severity=finding.severity.value if isinstance(finding.severity, SeverityLevel) else finding.severity,
        confidence=finding.confidence,
        title=finding.title,
        description=finding.description,
        evidence=finding.evidence,
        mitre_tactics=finding.mitre_tactics,
        mitre_techniques=finding.mitre_techniques,
        status=finding.status.value if isinstance(finding.status, FindingStatus) else finding.status,
        created_at=finding.created_at.isoformat() if isinstance(finding.created_at, datetime) else str(finding.created_at),
    )


@router.post(
    "",
    response_model=EventResponse,
    summary="Ingest Event",
    description="Ingest a new security event for analysis.",
)
async def ingest_event(
    request: EventCreateRequest,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
    user: User = Depends(get_current_active_user),
) -> EventResponse:
    """Ingest and optionally analyze a security event."""
    repo = get_event_repository()

    # tenant_id is always derived server-side from the authenticated
    # caller's resolved authorization - never from a client-supplied
    # field (EventCreateRequest has none). An admin with no single
    # tenant scoped (auth.tenant_ids is None) creates an org-less event,
    # same accepted gap as logs.py's create_log_source for admins with
    # no organization_id of their own.
    tenant_id = auth.tenant_ids[0] if auth.tenant_ids else None

    event_create = EventCreate(
        event_type=request.event_type,
        source=request.source,
        raw_data=request.raw_data,
        tenant_id=tenant_id,
    )

    event = await repo.create(event_create)

    # Auto-analyze if requested
    if request.auto_analyze:
        try:
            engine = get_detection_engine()
            result = engine.detect(request.raw_data)

            # Update event with detection results
            severity_enum = SeverityLevel(result.highest_severity) if result.highest_severity in [s.value for s in SeverityLevel] else SeverityLevel.INFO

            event = await repo.update_status(
                event_id=event.id,
                status=EventStatus.COMPLETED,
                risk_score=result.risk_score.total_score if result.risk_score else 0,
                severity=severity_enum,
                findings_count=result.total_findings,
            )

            # Broadcast if threats detected
            if result.total_findings > 0:
                await broadcast_event(
                    event_type=WSEventType.THREAT_DETECTED,
                    data={
                        "event_id": event.id,
                        "findings_count": result.total_findings,
                        "risk_score": event.risk_score,
                        "severity": event.severity.value if isinstance(event.severity, SeverityLevel) else event.severity,
                    },
                    channels=["events", "alerts"],
                    severity=event.severity.value if isinstance(event.severity, SeverityLevel) else event.severity,
                )

        except Exception:
            # Mark as failed
            event = await repo.update_status(
                event_id=event.id,
                status=EventStatus.FAILED,
            )

    # Broadcast new event
    await broadcast_event(
        event_type=WSEventType.NEW_EVENT,
        data={"event_id": event.id, "event_type": request.event_type.value},
        channels=["events"],
    )

    return _db_event_to_response(event)


@router.get(
    "",
    response_model=dict,
    summary="List Events",
    description=(
        "List security events with filters, scoped to the caller's authorized "
        "tenant(s). Returns up to 1000 of the latest matching events per page "
        "(deterministic sort by created_at then id) - this is a display/API "
        "page-size limit only and never affects how many events are stored, "
        "processed by detection, or retained. Use offset to page through "
        "older events; `total` reports the full matching count so the "
        "frontend can tell the user there are more results beyond this page."
    ),
)
async def list_events(
    event_type: str | None = Query(None),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    search: str | None = Query(None, min_length=2, max_length=200),
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """List events with filters, with a real total count for pagination."""
    repo = get_event_repository()

    events = await repo.list(
        limit=limit,
        offset=offset,
        event_type=event_type,
        status=status,
        severity=severity,
        search=search,
        start_time=start_time,
        end_time=end_time,
        tenant_ids=auth.tenant_ids,
    )
    total = await repo.count(
        event_type=event_type,
        status=status,
        severity=severity,
        search=search,
        start_time=start_time,
        end_time=end_time,
        tenant_ids=auth.tenant_ids,
    )

    return {
        "events": [_db_event_to_response(e) for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/statistics",
    summary="Get Event Statistics",
    description="Get event processing statistics, scoped to the caller's authorized tenant(s).",
)
async def get_statistics(
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict[str, Any]:
    """Get event statistics."""
    repo = get_event_repository()

    stats = await repo.get_statistics(tenant_ids=auth.tenant_ids)

    # Format response similar to old API
    return {
        "total": stats.get("total", 0),
        "by_type": stats.get("by_type", {}),
        "by_status": {
            "pending": stats.get("pending", 0),
            "processing": stats.get("processing", 0),
            "completed": stats.get("completed", 0),
            "failed": stats.get("failed", 0),
        },
        "by_severity": {
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
        },
        "avg_risk_score": round(stats.get("avg_risk_score", 0) or 0, 1),
    }


@router.get(
    "/{event_id}",
    response_model=dict[str, Any],
    summary="Get Event",
    description="Get event details including raw data.",
)
async def get_event(
    event_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict[str, Any]:
    """Get full event details, scoped to the caller's authorized tenant(s)."""
    repo = get_event_repository()

    event = await repo.get(event_id, tenant_ids=auth.tenant_ids)
    if not event:
        raise _not_found("Event not found")

    return _db_event_to_full_dict(event)


@router.post(
    "/{event_id}/reanalyze",
    response_model=EventResponse,
    summary="Reanalyze Event",
    description="Re-run detection on an existing event.",
)
async def reanalyze_event(
    event_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> EventResponse:
    """Reanalyze an event, scoped to the caller's authorized tenant(s)."""
    repo = get_event_repository()

    event = await repo.get(event_id, tenant_ids=auth.tenant_ids)
    if not event:
        raise _not_found("Event not found")

    engine = get_detection_engine()
    result = engine.detect(event.raw_data)

    # Update event with new detection results
    severity_enum = SeverityLevel(result.highest_severity) if result.highest_severity in [s.value for s in SeverityLevel] else SeverityLevel.INFO

    updated_event = await repo.update_status(
        event_id=event_id,
        status=EventStatus.COMPLETED,
        risk_score=result.risk_score.total_score if result.risk_score else 0,
        severity=severity_enum,
        findings_count=result.total_findings,
    )

    return _db_event_to_response(updated_event)


@router.get(
    "/{event_id}/findings",
    response_model=list[FindingResponse],
    summary="List Findings for an Event",
    description="List findings linked to a specific event, scoped to the caller's authorized tenant(s).",
)
async def list_event_findings(
    event_id: str,
    severity: SeverityLevel | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> list[FindingResponse]:
    """List findings for an event. The event itself must be visible to the caller first."""
    event_repo = get_event_repository()
    event = await event_repo.get(event_id, tenant_ids=auth.tenant_ids)
    if not event:
        raise _not_found("Event not found")

    finding_repo = get_finding_repository()
    query = FindingQuery(
        event_id=event_id,
        severity=severity,
        limit=limit,
        offset=offset,
        tenant_ids=auth.tenant_ids,
    )
    findings = await finding_repo.list(query)
    return [_db_finding_to_response(f) for f in findings]


@findings_router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get Finding",
    description="Get a single finding by ID, scoped to the caller's authorized tenant(s).",
)
async def get_finding(
    finding_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> FindingResponse:
    """Get a finding by ID."""
    finding_repo = get_finding_repository()
    finding = await finding_repo.get(finding_id, tenant_ids=auth.tenant_ids)
    if not finding:
        raise _not_found("Finding not found")
    return _db_finding_to_response(finding)


@findings_router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update Finding Status",
    description="Update a finding's investigation status (acknowledge/resolve/mark false positive).",
)
async def update_finding_status(
    finding_id: str,
    request: FindingStatusUpdateRequest,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
    user: User = Depends(require_findings_write),
) -> FindingResponse:
    """Update a finding's status, scoped to the caller's authorized tenant(s)."""
    finding_repo = get_finding_repository()

    existing = await finding_repo.get(finding_id, tenant_ids=auth.tenant_ids)
    if not existing:
        raise _not_found("Finding not found")

    old_status = existing.status.value if isinstance(existing.status, FindingStatus) else existing.status

    updated = await finding_repo.update_status(
        finding_id=finding_id,
        status=request.status,
        tenant_ids=auth.tenant_ids,
    )
    if not updated:
        raise _not_found("Finding not found")

    await record_audit_event(
        action="finding_status_changed",
        entity_type="finding",
        entity_id=finding_id,
        user_id=getattr(user, "id", None),
        old_value={"status": old_status},
        new_value={"status": request.status.value},
    )

    return _db_finding_to_response(updated)
