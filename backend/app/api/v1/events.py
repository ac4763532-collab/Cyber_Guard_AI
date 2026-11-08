"""
CyberGuard AI — Event Endpoints
============================================================================

Event ingestion (collector-authenticated) and event query (user-authenticated).

Two auth flows in one file
--------------------------
    Ingestion (POST /events, POST /events/batch):
        Auth via ``X-Collector-Credential`` header — the collector's
        device credential. Resolves to
        ``VerifiedCredential(source, credential, installation)`` via
        ``get_verified_collector``.

    Query (GET /events, GET /events/{id}):
        Auth via standard bearer JWT. Workspace-scoped access enforced
        in the endpoint via ``authorization``.

Response contract
-----------------
Ingestion:
    POST /events → 200 {status, event_id}  (status: "ingested"|"duplicate")
    POST /events/batch → 200 BatchIngestResult

Duplicates are reported as ``status="duplicate"`` and are NOT errors.
The collector treats any 2xx as success.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.constants import (
    HEADER_COLLECTOR_CREDENTIAL,
    HEADER_COLLECTOR_ID,
)
from app.core.exceptions import (
    CollectorAuthError,
    EventNotFoundError,
)
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.common import (
    PageMeta,
    PaginatedResponse,
)
from app.schemas.event import (
    EventBatchIngestRequest,
    EventBatchIngestResponse,
    EventFilter,
    EventIngestRequest,
    EventIngestResult,
    EventList,
    EventRead,
)
from app.services import (
    authorization,
    collector_credential_service,
    event_ingestion,
)
from app.services.collector_credential_service import VerifiedCredential


logger = get_logger(__name__)


router = APIRouter(
    prefix="/events",
    tags=["events"],
)


# ============================================================================
# COLLECTOR AUTH DEPENDENCY
# ============================================================================

def get_verified_collector(
    db: Session = Depends(get_db),
    collector_credential: str | None = Header(
        default=None,
        alias=HEADER_COLLECTOR_CREDENTIAL,
        description=(
            "Collector's device credential. Format: `cgc_<random>`. "
            "Sent as a header, not a bearer token."
        ),
    ),
    collector_id: str | None = Header(
        default=None,
        alias=HEADER_COLLECTOR_ID,
        description="Collector's self-assigned UUID (optional).",
    ),
) -> VerifiedCredential:
    """
    Verify the collector's credential and resolve
    ``VerifiedCredential(source, credential, installation)``.
    """
    if not collector_credential:
        raise CollectorAuthError(
            message=(
                f"Missing {HEADER_COLLECTOR_CREDENTIAL} header. Collectors "
                f"must send their issued credential on every request."
            ),
            code="COLLECTOR_CREDENTIAL_HEADER_MISSING",
        )

    return collector_credential_service.verify_credential(
        db, collector_credential, from_ip=None,
    )


# ============================================================================
# INGESTION — batch (declared first to avoid route collision with any
# future POST /{event_id} route)
# ============================================================================

@router.post(
    "/batch",
    response_model=EventBatchIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch event ingestion (collector)",
    description=(
        "Ingest up to 500 events in a single request. Collectors should "
        "prefer this over single-event ingestion.\n\n"
        "**Auth**: `X-Collector-Credential` header (not a bearer token).\n\n"
        "**Response**: per-event results in input order. Duplicates are "
        "reported as `status=duplicate` — treat the response as success "
        "when the HTTP status is 200."
    ),
    responses={
        200: {"description": "Batch processed; check results for per-event status."},
        401: {"description": "Collector credential missing or invalid."},
        403: {"description": "Source disabled/revoked, or collection paused."},
        422: {"description": "Batch schema validation failed."},
    },
)
def ingest_event_batch(
    body: EventBatchIngestRequest,
    db: DBDep,
    verified: VerifiedCredential = Depends(get_verified_collector),
) -> EventBatchIngestResponse:
    """
    Ingest a batch of events. The ``db`` dependency and the one used
    internally by ``get_verified_collector`` resolve to the same session
    (FastAPI caches dependencies within a request), so the whole batch
    commits together.
    """
    result = event_ingestion.ingest_batch(
        db,
        source=verified.source,
        credential=verified.credential,
        payloads=body.events,
    )
    db.commit()

    logger.info(
        "Batch ingestion endpoint complete",
        extra={
            "source_id": str(verified.source.id),
            "total": result.total_received,
            "ingested": result.ingested,
            "duplicates": result.duplicates,
            "rejected": result.rejected,
        },
    )

    return EventBatchIngestResponse(
        total_received=result.total_received,
        ingested=result.ingested,
        duplicates=result.duplicates,
        rejected=result.rejected,
        results=[
            EventIngestResult(
                client_ref=r.client_ref,
                status=r.status,
                event_id=r.event_id,
                error_code=r.error_code,
                error_message=r.error_message,
            )
            for r in result.results
        ],
    )


# ============================================================================
# INGESTION — single event
# ============================================================================

@router.post(
    "",
    response_model=EventIngestResult,
    status_code=status.HTTP_200_OK,
    summary="Single event ingestion (collector)",
    description=(
        "Ingest one event. Returns `status=ingested` (new) or "
        "`status=duplicate` (fingerprint match — existing event's ID "
        "returned). For high-volume collectors, prefer POST /events/batch."
    ),
    responses={
        200: {"description": "Event processed (check status field)."},
        401: {"description": "Collector credential missing or invalid."},
        403: {"description": "Source disabled/revoked, or collection paused."},
        422: {"description": "Event schema validation failed."},
    },
)
def ingest_event_single(
    body: EventIngestRequest,
    db: DBDep,
    verified: VerifiedCredential = Depends(get_verified_collector),
) -> EventIngestResult:
    """Ingest a single event from a collector."""
    result = event_ingestion.ingest_single(
        db,
        source=verified.source,
        credential=verified.credential,
        payload=body,
    )
    db.commit()

    return EventIngestResult(
        client_ref=None,
        status=result.status,
        event_id=result.event_id,
        error_code=None,
        error_message=None,
    )


# ============================================================================
# QUERY — list
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[EventList],
    summary="List events (user)",
    description=(
        "Paginated list of events across the user's accessible "
        "workspaces. Requires `event:read` permission on the workspace "
        "(checked for a specific workspace when `workspace_id` is given, "
        "otherwise scoped to the user's workspace set).\n\n"
        "Returns lightweight `EventList` rows (no payloads). Fetch "
        "`GET /events/{id}` for the full event."
    ),
)
def list_events(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: EventFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[EventList]:
    # ── Determine scope
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "event:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            # No workspaces → empty result (correct, not an error)
            return PaginatedResponse[EventList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    # ── Build query
    stmt = select(SecurityEvent).where(
        SecurityEvent.workspace_id.in_(workspace_ids),
    )

    if filters.source_id is not None:
        stmt = stmt.where(SecurityEvent.source_id == filters.source_id)
    if filters.event_type:
        stmt = stmt.where(SecurityEvent.event_type == filters.event_type)
    if filters.severity is not None:
        stmt = stmt.where(SecurityEvent.severity == filters.severity)
    if filters.category is not None:
        stmt = stmt.where(SecurityEvent.category == filters.category)
    if filters.username:
        stmt = stmt.where(SecurityEvent.username == filters.username.lower())
    if filters.hostname:
        stmt = stmt.where(SecurityEvent.hostname == filters.hostname.lower())
    if filters.source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == filters.source_ip)
    if filters.destination_ip:
        stmt = stmt.where(SecurityEvent.destination_ip == filters.destination_ip)
    if filters.has_findings is not None:
        if filters.has_findings:
            stmt = stmt.where(SecurityEvent.findings_count > 0)
        else:
            stmt = stmt.where(SecurityEvent.findings_count == 0)
    if filters.event_time_after is not None:
        stmt = stmt.where(SecurityEvent.event_time >= filters.event_time_after)
    if filters.event_time_before is not None:
        stmt = stmt.where(SecurityEvent.event_time <= filters.event_time_before)
    if filters.received_after is not None:
        stmt = stmt.where(SecurityEvent.received_at >= filters.received_after)
    if filters.received_before is not None:
        stmt = stmt.where(SecurityEvent.received_at <= filters.received_before)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            SecurityEvent.event_time.desc(),
            SecurityEvent.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    events = list(db.execute(stmt).scalars().all())

    return PaginatedResponse[EventList](
        items=[EventList.model_validate(e) for e in events],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# QUERY — detail
# ============================================================================

@router.get(
    "/{event_id}",
    response_model=EventRead,
    summary="Get an event by ID (user)",
    description=(
        "Returns the full event including both payloads. Requires "
        "`event:read` on the event's workspace."
    ),
)
def get_event(
    event_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> EventRead:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise EventNotFoundError(
            message=f"Event {event_id} not found.",
            details={"event_id": str(event_id)},
        )

    authorization.check_permission(
        db, current_user, "event:read", workspace_id=event.workspace_id,
    )

    return EventRead.model_validate(event)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "get_verified_collector"]