"""
CyberGuard AI - Correlation API Endpoints

Provides cross-domain correlation capabilities.
"""

from typing import Any
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.base import AgentType
from app.agents.dispatcher import get_dispatcher
from app.auth.jwt import get_current_active_user
from app.auth.models import User
from app.correlation import get_correlation_engine, CorrelationResult
from app.correlation.engine import EventData
from app.database.repositories.correlated_activities import CorrelatedActivityRepository


router = APIRouter(prefix="/correlation", tags=["Correlation"])


class CorrelateRequest(BaseModel):
    """Request for correlation analysis."""

    events: list[dict[str, Any]] = Field(
        ...,
        description="Events to correlate",
        min_length=1,
        max_length=500,
    )
    time_window_hours: float = Field(
        24.0,
        description="Time window for temporal correlation",
        ge=1.0,
        le=168.0,  # max 1 week
    )


class CorrelationSummary(BaseModel):
    """Summary of correlation results."""

    correlation_id: str
    event_count: int
    groups_found: int
    cross_domain_groups: int
    potential_incidents: int
    total_correlations: int
    processing_time_ms: float


class CorrelationResponse(BaseModel):
    """Full correlation response."""

    summary: CorrelationSummary
    groups: list[dict[str, Any]]
    analysis_scope: str = "unpersisted_hypothesis"


@router.post(
    "/analyze",
    response_model=CorrelationResponse,
    summary="Correlate Events",
    description="Find relationships between security events across domains.",
)
async def correlate_events(
    request: CorrelateRequest,
    _user: User = Depends(get_current_active_user),
) -> CorrelationResponse:
    """Analyze caller-supplied hypotheses; this does not persist events."""
    engine = get_correlation_engine()

    # Convert request events to EventData
    events = []
    for evt in request.events:
        events.append(EventData(
            event_id=evt.get("event_id", ""),
            domain=evt.get("domain", "unknown"),
            timestamp=evt.get("timestamp", ""),
            ips=evt.get("ips", []),
            domains=evt.get("domains", []),
            urls=evt.get("urls", []),
            hashes=evt.get("hashes", []),
            emails=evt.get("emails", []),
            users=evt.get("users", []),
            assets=evt.get("assets", []),
            risk_score=evt.get("risk_score", 0),
            severity=evt.get("severity", "info"),
            mitre_techniques=evt.get("mitre_techniques", []),
            mitre_tactics=evt.get("mitre_tactics", []),
        ))

    # Run correlation
    result = engine.correlate(
        events=events,
        time_window=timedelta(hours=request.time_window_hours),
    )

    # Build response
    groups_data = []
    for group in result.groups:
        groups_data.append({
            "group_id": group.group_id,
            "event_ids": group.event_ids,
            "domains": group.domains,
            "risk_score": group.risk_score,
            "severity": group.severity,
            "shared_iocs": group.shared_iocs,
            "shared_users": group.shared_users,
            "attack_techniques": group.attack_techniques,
            "correlation_count": len(group.correlations),
            "first_seen": group.first_seen.isoformat(),
            "last_seen": group.last_seen.isoformat(),
        })

    return CorrelationResponse(
        summary=CorrelationSummary(
            correlation_id=result.correlation_id,
            event_count=result.event_count,
            groups_found=len(result.groups),
            cross_domain_groups=result.cross_domain_groups,
            potential_incidents=result.potential_incidents,
            total_correlations=result.total_correlations,
            processing_time_ms=result.processing_time_ms,
        ),
        groups=groups_data,
    )


@router.get(
    "/statistics",
    summary="Get Correlation Statistics",
    description="Get correlation engine configuration and stats.",
)
async def get_statistics(
    _user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Get correlation engine statistics."""
    engine = get_correlation_engine()
    return engine.get_statistics()


class IOCCorrelationRequest(BaseModel):
    """Request to re-run correlation over a chosen set of persisted findings."""

    finding_ids: list[str] = Field(
        ...,
        description="IDs of previously-created findings to correlate",
        min_length=2,
    )


class IOCCorrelationGroupResponse(BaseModel):
    """One correlated group from an on-demand correlation run."""

    group_id: str
    event_ids: list[str]
    domains: list[str]
    risk_score: int
    severity: str
    shared_iocs: list[dict[str, Any]]
    shared_users: list[str]
    attack_techniques: list[str]


class IOCCorrelationResponse(BaseModel):
    """Response for an on-demand IOC correlation run."""

    classification: str
    severity: str
    risk_score: int
    summary: str
    groups: list[IOCCorrelationGroupResponse]
    missing_finding_ids: list[str]
    persisted_activity_ids: list[str | None]
    recommendations: list[str]
    success: bool
    error: str | None = None


@router.post(
    "/ioc",
    response_model=IOCCorrelationResponse,
    summary="On-Demand IOC Correlation",
    description=(
        "Re-run correlation over a chosen set of previously-created findings "
        "via the IOC Correlation Agent. Separate from and does not interfere "
        "with the automatic real-time correlation pipeline - this never "
        "creates alerts, only persists CorrelatedActivity records."
    ),
)
async def correlate_findings(
    request: IOCCorrelationRequest,
    user: User = Depends(get_current_active_user),
) -> IOCCorrelationResponse:
    """Dispatch an on-demand correlation run through the IOC Correlation Agent."""
    if not user.organization_id:
        raise HTTPException(
            status_code=400,
            detail="User has no associated organization - cannot scope correlation to a tenant.",
        )

    dispatcher = get_dispatcher()
    agent_result = await dispatcher.dispatch(
        AgentType.IOC_CORRELATION,
        {
            "finding_ids": request.finding_ids,
            "tenant_id": user.organization_id,
        },
    )

    if not agent_result.success:
        raise HTTPException(status_code=400, detail=agent_result.error or agent_result.summary)

    metadata = agent_result.metadata or {}
    groups = [
        IOCCorrelationGroupResponse(
            group_id=f.metadata.get("group_id", ""),
            event_ids=f.metadata.get("event_ids", []),
            domains=f.metadata.get("domains", []),
            risk_score=int(f.confidence * 100),
            severity=f.severity.value,
            shared_iocs=f.metadata.get("shared_iocs", []),
            shared_users=f.metadata.get("shared_users", []),
            attack_techniques=f.mitre_techniques,
        )
        for f in agent_result.findings
    ]

    return IOCCorrelationResponse(
        classification=agent_result.classification,
        severity=agent_result.severity.value,
        risk_score=agent_result.risk_score,
        summary=agent_result.summary,
        groups=groups,
        missing_finding_ids=metadata.get("missing_finding_ids", []),
        persisted_activity_ids=metadata.get("persisted_activity_ids", []),
        recommendations=agent_result.recommendations,
        success=agent_result.success,
        error=agent_result.error,
    )


class RecorrelateRequest(BaseModel):
    """Request to re-run on-demand correlation over a chosen set of findings."""

    finding_ids: list[str] = Field(
        ...,
        description="IDs of previously-created findings to correlate",
        min_length=2,
    )


@router.post(
    "/recorrelate",
    response_model=IOCCorrelationResponse,
    summary="Re-correlate Findings On Demand",
    description=(
        "Alias for POST /correlation/ioc - dispatches the same on-demand "
        "IOC Correlation Agent run over a chosen set of findings. Kept as "
        "a separate, more discoverable path for the 'Re-correlate' UI "
        "action; behavior is identical to /correlation/ioc."
    ),
)
async def recorrelate(
    request: RecorrelateRequest,
    user: User = Depends(get_current_active_user),
) -> IOCCorrelationResponse:
    """Re-run on-demand correlation - thin alias of correlate_findings."""
    return await correlate_findings(
        IOCCorrelationRequest(finding_ids=request.finding_ids),
        user=user,
    )


class CorrelatedActivityResponse(BaseModel):
    """One persisted correlated activity record."""

    correlation_id: str
    fingerprint: str
    finding_ids: list[str]
    event_ids: list[str]
    source_types: list[str]
    correlation_type: str
    correlation_strength: float
    shared_entities: dict[str, Any]
    risk_score: int
    correlation_bucket: str
    timestamp: str
    created_at: str | None = None


@router.get(
    "/activities",
    response_model=list[CorrelatedActivityResponse],
    summary="List Persisted Correlated Activities",
    description=(
        "Tenant-scoped list of previously-persisted CorrelatedActivity "
        "records, from both the automatic real-time pipeline and "
        "on-demand IOC Correlation Agent runs."
    ),
)
async def list_activities(
    limit: int = 100,
    offset: int = 0,
    user: User = Depends(get_current_active_user),
) -> list[CorrelatedActivityResponse]:
    """List persisted correlated activities for the caller's tenant."""
    if not user.organization_id:
        raise HTTPException(
            status_code=400,
            detail="User has no associated organization - cannot scope correlation activities to a tenant.",
        )

    from app.database.connection import get_database

    repo = CorrelatedActivityRepository(db=get_database())
    rows = await repo.list_by_tenant(
        tenant_id=user.organization_id,
        limit=min(limit, 500),
        offset=max(offset, 0),
    )

    activities = []
    for row in rows:
        activities.append(
            CorrelatedActivityResponse(
                correlation_id=str(row["correlation_id"]),
                fingerprint=row["fingerprint"],
                finding_ids=[str(fid) for fid in (row.get("finding_ids") or [])],
                event_ids=[str(eid) for eid in (row.get("event_ids") or [])],
                source_types=row.get("source_types") or [],
                correlation_type=row.get("correlation_type", "unknown"),
                correlation_strength=float(row.get("correlation_strength", 0.0)),
                shared_entities=row.get("shared_entities") or {},
                risk_score=int(row.get("risk_score", 0)),
                correlation_bucket=row.get("correlation_bucket", ""),
                timestamp=row["timestamp"].isoformat() if row.get("timestamp") else "",
                created_at=row["created_at"].isoformat() if row.get("created_at") else None,
            )
        )
    return activities
