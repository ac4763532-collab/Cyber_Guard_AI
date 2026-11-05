"""
CyberGuard AI - Log Analysis API Endpoints

REST API for log sources, log events, and log ingestion.

Endpoints:
- Log Sources: CRUD for log source configuration
- Log Events: Query and list collected log events
- Log Ingestion: Receive logs from external collectors

Security:
- Do not expose encrypted_config in responses
- Do not expose credentials through any endpoint
- Validate and sanitize all inputs

STEP 4 (Secure Log Ingestion + Tenant Isolation):
- POST /ingest and POST /ingest/raw now require a valid ingestion API key
  (the same app.auth.ingestion_keys / app.api.v1.web_ingest machinery
  already used by /logs/web/ingest - not a second auth system).
  source_id/tenant_id are always resolved server-side from the
  authenticated key, never trusted from client-supplied query params.
- GET /sources, /sources/{id}, /events, /events/{id}, /events/statistics
  now require a valid JWT (human analyst) and are scoped to the caller's
  authorized tenant(s) via get_authorized_tenant_ids(). See that
  function's docstring for the documented interim rule and its limits
  (User has no organization_id field today - this is a real, flagged
  limitation, not hidden).
- Cross-tenant lookups return 404 ("not found"), never 403, so a caller
  cannot distinguish "doesn't exist" from "exists but isn't yours".
"""

from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from pydantic import BaseModel, Field as PydanticField, ValidationError

from app.auth.ingestion_keys import IngestionApiKey, verify_source_tenant_match
from app.auth.jwt import get_current_active_user, require_role
from app.auth.models import User, UserRole
from app.config import settings
from app.logs.connection_check import (
    ConnectionCheckResult,
    check_android_connection,
    check_linux_connection,
    check_local_network_connection,
    check_windows_connection,
)
from app.logs.models import (
    CollectorType,
    LogEvent,
    LogEventQuery,
    LogLevel,
    LogSource,
    LogSourceCreate,
    LogSourceStatus,
    LogSourceType,
    LogSourceUpdate,
    ParsedLogEntry,
)
from app.middleware.rate_limit import RATE_LIMIT_COLLECTOR_ACTION, RATE_LIMIT_DEFAULT, RATE_LIMIT_GET, limiter

router = APIRouter(prefix="/logs", tags=["Logs"])
logger = structlog.get_logger(__name__)


# Each embedded source_type has exactly one correct collector_type - the
# two must always agree for build_collector_for_source() to build the
# right collector. Previously LogSourceCreate.collector_type defaulted to
# CollectorType.HTTP_RECEIVER and nothing derived the correct value
# server-side, so any create request that omitted collector_type (every
# frontend call does) silently got the wrong one - the source would sit at
# status="pending" forever since it was never recognized as "embedded" by
# the start_source gate below. Fixed by deriving collector_type from
# source_type unconditionally for every type that has exactly one correct
# collector - this is not something a caller should be able to override.
_EMBEDDED_SOURCE_COLLECTOR_TYPES: dict[LogSourceType, CollectorType] = {
    LogSourceType.WINDOWS_EVENT: CollectorType.WINDOWS_AGENT,
    LogSourceType.LINUX_SSH: CollectorType.LINUX_AGENT,
    LogSourceType.ANDROID_ADB: CollectorType.ANDROID_AGENT,
    LogSourceType.LOCAL_NETWORK_MONITOR: CollectorType.LOCAL_NETWORK_AGENT,
}


# =============================================================================
# Response Schemas (to avoid exposing internal fields)
# =============================================================================


def _source_to_response(source: LogSource, manager: Any = None) -> dict[str, Any]:
    """
    Convert LogSource to API response (excludes encrypted_config).

    When a CollectorManager is supplied, attaches the real, in-memory
    live supervisor telemetry (CollectorSupervisorStatus) as a separate
    `collector_status` key - never merged into or confused with the
    DB-persisted fields above, which can be stale (see restart_log_source's
    own caveat comment). `collector_status` is `None` whenever no live
    supervisor exists for this source (e.g. PENDING/DISABLED sources,
    HTTP_RECEIVER collector type, or the backend hasn't re-started this
    collector since its last restart) - this is an honest absence signal,
    never a fabricated "stopped"/"idle" placeholder.
    """
    data = source.to_dict(include_encrypted=False)

    collector_status: dict[str, Any] | None = None
    if manager is not None:
        live_status = manager.get_source_status(source.id)
        if live_status is not None:
            collector_status = {
                "state": live_status.state.value
                if hasattr(live_status.state, "value")
                else live_status.state,
                "started_at": live_status.started_at.isoformat() if live_status.started_at else None,
                "last_successful_collection_at": (
                    live_status.last_successful_collection_at.isoformat()
                    if live_status.last_successful_collection_at
                    else None
                ),
                # events_collected/events_published/checkpoint_updates are
                # intentionally NOT included here - they are declared on
                # CollectorSupervisorStatus but never incremented anywhere
                # in app/logs/ (confirmed by audit). Exposing them would
                # make an always-0 field look like a real, monitored
                # counter - the opposite of this API's "no fabricated
                # telemetry" rule. See collector_manager.py's
                # CollectorSupervisorStatus for the same note.
                "reconnect_count": live_status.reconnect_count,
                "error_count": live_status.error_count,
                "last_error": live_status.last_error,
                "last_error_at": live_status.last_error_at.isoformat() if live_status.last_error_at else None,
            }

    data["collector_status"] = collector_status
    return data


def _event_to_response(event: LogEvent) -> dict[str, Any]:
    """Convert LogEvent to API response."""
    return event.to_dict()


def _not_found(detail: str) -> HTTPException:
    """
    A generic 404 used for both "truly doesn't exist" and "exists but
    belongs to another tenant" cases (Part 12: never reveal existence of
    other tenants'/orgs' resources via a differently-worded or
    differently-coded response).
    """
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


# =============================================================================
# Authorization: ingestion (machine, API key)
# =============================================================================
#
# app.api.v1.web_ingest.get_authenticated_key is already a plain FastAPI
# dependency callable (api_key: str | None = Depends(api_key_header) ->
# IngestionApiKey) and is reused directly by the ingestion endpoints
# below, imported lazily inside each endpoint to avoid an import-order
# dependency between the two router modules. No second API-key
# authentication implementation is introduced here.


# =============================================================================
# Authorization: queries (human analyst, JWT)
# =============================================================================


class TenantAuthorization:
    """
    Resolved tenant authorization for a JWT-authenticated query.

    is_admin=True means "see all tenants" (tenant_ids is None in that
    case - repository methods treat None as "no tenant filter").
    is_admin=False means tenant_ids is a concrete, non-empty list the
    caller is allowed to see (today always exactly one explicit tenant,
    see get_authorized_tenant_ids).
    """

    def __init__(self, is_admin: bool, tenant_ids: list[str] | None):
        self.is_admin = is_admin
        self.tenant_ids = tenant_ids


async def get_authorized_tenant_ids(
    user: User = Depends(get_current_active_user),
    tenant_id: str | None = Query(
        None,
        description=(
            "Tenant/organization to scope this query to. Non-admin users "
            "may omit this - it defaults to their own organization_id. "
            "Admin users may omit this to see all tenants, or supply it "
            "to scope to one."
        ),
    ),
) -> TenantAuthorization:
    """
    Resolve which tenant(s) the current JWT-authenticated user may query.

    STEP 4 (Secure Ingestion + Tenant Isolation), updated after adding a
    real `organization_id` column to `users` (see app/database/schema.py
    and app/auth/models.py):

    - UserRole.ADMIN: may see all tenants (matches the existing
      admin-bypass pattern in User.has_permission()). If `tenant_id` is
      supplied, scope to just that one instead.
    - Any other role: is ALWAYS pinned to their own `user.organization_id`
      - the `tenant_id` query parameter is accepted for backward
        compatibility but ignored for non-admins rather than trusted, so
        a non-admin can no longer request another tenant's data just by
        knowing/guessing a valid tenant_id string (this closes the gap
        the previous version of this function explicitly flagged).
      - A non-admin with no organization_id assigned (e.g. a legacy row
        from before this column existed) gets 400, not a silent "see
        everything" fallback - fail closed, not open.
    """
    if user.role == UserRole.ADMIN:
        if tenant_id:
            return TenantAuthorization(is_admin=True, tenant_ids=[tenant_id])
        return TenantAuthorization(is_admin=True, tenant_ids=None)

    if tenant_id and tenant_id != user.organization_id:
        logger.warning(
            "Query rejected: non-admin requested a tenant_id other than "
            "their own organization_id",
            user_id=getattr(user, "id", None),
            requested_tenant_id=tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for the requested tenant_id",
        )

    if not user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Your account has no organization_id assigned - contact "
                "an administrator"
            ),
        )

    return TenantAuthorization(is_admin=False, tenant_ids=[user.organization_id])


def _apply_tenant_authorization(query: LogEventQuery, auth: TenantAuthorization) -> None:
    """Stamp the server-resolved tenant scope onto a LogEventQuery."""
    if auth.tenant_ids is not None:
        query.tenant_ids = auth.tenant_ids


# =============================================================================
# Log Sources Endpoints
# =============================================================================


@router.post(
    "/sources",
    summary="Create Log Source",
    description="""
Create a new log source configuration.

Log sources define where logs come from and how they should be processed.
Actual log collection is performed by external collectors, not by CyberGuard.

**Source Types (STEP 9):**
- `windows_event`: Windows Event Log
- `linux_ssh`: Linux syslog/auth log, collected via SSH
- `android_adb`: Android device logs, collected via ADB/logcat
  (requires `adb` installed and the device already connected/authorized
  on this backend host - see AndroidADBCollectorConfig)

**Security:**
- Do NOT include credentials in the `configuration` field
- Credentials should be configured separately via secure channels
    """,
    response_model=dict,
)
async def create_log_source(
    request: Request,
    source: LogSourceCreate,
    user: User = Depends(get_current_active_user),
) -> dict:
    """Create a new log source."""
    logger.info(
        "Creating log source",
        name=source.name,
        source_type=source.source_type.value,
        user_id=getattr(user, "id", None),
    )

    try:
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()

        # Check for duplicate name
        existing = await repo.get_by_name(source.name)
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Log source with name '{source.name}' already exists",
            )

        # If plaintext credentials were supplied, encrypt them server-side
        # into encrypted_config before storage. Never log or echo the
        # plaintext - source.credentials is a write-only, excluded field.
        if source.credentials is not None:
            import json as _json

            from app.services.token_encryption import get_token_encryption_service

            encryption_service = get_token_encryption_service()
            source.encrypted_config = encryption_service.encrypt(
                _json.dumps(source.credentials)
            )

        # organization_id is always resolved server-side from the
        # authenticated creator, never from client input - this is what
        # makes the source visible to that user (and other members of
        # their org) via list_log_sources/get_log_source's tenant filter.
        # Admins have no organization_id of their own (None); sources they
        # create stay org-less too, same as before this fix - that's an
        # accepted gap until real multi-org admin assignment exists.
        #
        # collector_type is always derived from source_type here, never
        # trusted from the client - see _EMBEDDED_SOURCE_COLLECTOR_TYPES's
        # comment. Without this, every embedded source_type (not just the
        # new local_network_monitor) would be created with the schema's
        # CollectorType.HTTP_RECEIVER default and never actually start.
        if source.source_type in _EMBEDDED_SOURCE_COLLECTOR_TYPES:
            source.collector_type = _EMBEDDED_SOURCE_COLLECTOR_TYPES[source.source_type]

        created = await repo.create(
            source,
            created_by=getattr(user, "id", None),
            organization_id=user.organization_id,
        )

        # Start an embedded collector supervisor immediately for source
        # types that have one (windows_event, linux_ssh, android_adb,
        # local_network_monitor).
        # Without this, a newly-created source would only start collecting
        # after the next full app restart (CollectorManager.start_all()
        # only scans existing sources at startup) - it would otherwise sit
        # at status="pending" indefinitely. STEP 9: android_adb added here
        # alongside windows_event/linux_ssh since it has an embedded
        # collector too (AndroidADBCollector) - this was previously missed,
        # which would have left every newly-created Android source stuck
        # at "pending" until the next restart.
        if created.source_type in _EMBEDDED_SOURCE_COLLECTOR_TYPES:
            try:
                from app.logs.collector_manager import get_collector_manager

                get_collector_manager().start_source(created)
            except Exception as e:
                # Don't fail source creation if the collector can't start
                # yet (e.g. invalid configuration) - the source row still
                # exists and can be retried/edited. Surfaced via the
                # source's own status field, not a 500 here.
                logger.error(
                    "Failed to start collector for new log source",
                    source_id=created.id,
                    source_type=created.source_type.value,
                    error=str(e),
                )

        from app.services.audit import record_audit_event

        await record_audit_event(
            action="log_source_created",
            entity_type="log_source",
            entity_id=created.id,
            user_id=getattr(user, "id", None),
            new_value={
                "name": created.name,
                "source_type": created.source_type.value,
                "status": created.status.value if hasattr(created.status, "value") else created.status,
            },
        )

        return _source_to_response(created)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create log source", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create log source")


@router.get(
    "/sources",
    summary="List Log Sources",
    description="List all configured log sources with optional filtering, scoped to the caller's authorized tenant(s).",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def list_log_sources(
    request: Request,
    response: Response,
    status_filter: LogSourceStatus | None = Query(None, alias="status", description="Filter by status"),
    source_type: LogSourceType | None = Query(None, description="Filter by source type"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """List log sources, scoped to the caller's authorized tenant(s)."""
    try:
        from app.logs.collector_manager import get_collector_manager
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        sources = await repo.list(
            status=status_filter,
            source_type=source_type,
            limit=limit,
            offset=offset,
        )
        total = await repo.count(status=status_filter)

        # Tenant isolation (STEP 4): LogSourceRepository.list()/count()
        # have no tenant parameter (sources are relatively few and the
        # existing repository API is intentionally left unchanged here
        # per the "don't touch unrelated code" scope boundary) - filter
        # the resolved page in-process against the caller's authorized
        # tenant set instead. For a non-admin, tenant_ids is always a
        # single known tenant.
        if auth.tenant_ids is not None:
            allowed = set(auth.tenant_ids)
            sources = [s for s in sources if s.organization_id in allowed]

        manager = get_collector_manager()
        return {
            "sources": [_source_to_response(s, manager) for s in sources],
            "total": total if auth.is_admin else len(sources),
            "limit": limit,
            "offset": offset,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to list log sources", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list log sources")


@router.get(
    "/sources/{source_id}",
    summary="Get Log Source",
    description="Get a log source by ID. Only visible if it belongs to a tenant the caller is authorized for.",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def get_log_source(
    request: Request,
    response: Response,
    source_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Get a log source by ID."""
    try:
        from app.logs.collector_manager import get_collector_manager
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        source = await repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        # Tenant isolation (Part 12): a source that exists but belongs to
        # another tenant returns the exact same 404 as one that doesn't
        # exist at all.
        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        return _source_to_response(source, get_collector_manager())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get log source", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get log source")


def _compute_report_status(
    *, events_processed: int, events_pending: int, events_failed: int, findings_count: int
) -> str:
    """
    Map real event-status counts (within the requested window) to exactly
    one of the 7 supported detection-report statuses. Every branch is keyed
    off counts actually read from the `events` table - never fabricated.
    """
    if events_processed == 0:
        if events_pending > 0:
            return "detection_in_progress"
        return "monitoring"

    if events_failed == events_processed:
        return "failed"

    if events_failed > 0:
        return "partially_completed"

    if findings_count > 0:
        return "completed_with_findings"

    return "completed_no_threats"


@router.get(
    "/sources/{source_id}/report",
    summary="Get Detection Report for a Log Source",
    description="""
Compute a detection report for a log source (including Local Network
Monitor sources, which are log sources with source_type=local_network_monitor)
over a time range, from persisted events/findings/alerts - never fabricated.

**Query params:**
- `since` / `until`: time range (defaults to the source's created_at through now)

Only visible if the source belongs to a tenant the caller is authorized for.
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def get_log_source_report(
    request: Request,
    response: Response,
    source_id: str,
    since: datetime | None = Query(None, description="Start of the report window (default: source creation time)"),
    until: datetime | None = Query(None, description="End of the report window (default: now)"),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """
    Build a DetectionReportResponse for one log source, scoped to the
    caller's authorized tenant(s).

    Join path (no schema change - see plan): LogEventRepository.list()
    (source_id + time range, already supported) -> collect log_events.id
    values -> EventRepository.list_by_source_event_ids() (events.source_event_id
    is set to the originating log_events.id by
    app/event_bus/dispatcher_integration.py's _resolve_event_id_for_finding())
    -> FindingRepository.list(event_ids=...) / AlertRepository.list_by_event_ids()
    for the linked findings/alerts.
    """
    try:
        from app.database.models import FindingQuery
        from app.database.repositories.alerts import get_alert_repository
        from app.database.repositories.events import get_event_repository
        from app.database.repositories.findings import get_finding_repository
        from app.logs.collector_manager import get_collector_manager
        from app.logs.models import LogEventQuery
        from app.logs.repository import get_log_event_repository, get_log_source_repository

        source_repo = get_log_source_repository()
        source = await source_repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        time_range_start = since or source.created_at
        time_range_end = until or datetime.now(tz=time_range_start.tzinfo)

        # Step 1: real log_events rows for this source in the window
        # (source_id is a genuine FK - already-supported filter).
        log_event_query = LogEventQuery(
            source_id=source_id,
            start_time=time_range_start,
            end_time=time_range_end,
            limit=1000,
        )
        _apply_tenant_authorization(log_event_query, auth)
        log_event_repo = get_log_event_repository()
        log_events = await log_event_repo.list(log_event_query)
        log_event_ids = [le.id for le in log_events]

        # Step 2: the `events` rows recording each one's real processing
        # outcome (status/severity/findings_count), joined via
        # source_event_id - never via the free-text events.source column.
        event_repo = get_event_repository()
        events = await event_repo.list_by_source_event_ids(
            log_event_ids, tenant_ids=auth.tenant_ids
        )

        events_pending = sum(1 for e in events if e.status.value in ("pending", "processing"))
        events_failed = sum(1 for e in events if e.status.value == "failed")
        events_processed = sum(1 for e in events if e.status.value in ("completed", "failed"))

        severity_breakdown: dict[str, int] = {}
        for e in events:
            if e.status.value == "completed" and e.findings_count > 0:
                severity_breakdown[e.severity.value] = severity_breakdown.get(e.severity.value, 0) + 1

        # Real last_error string only - from the live collector supervisor
        # telemetry, never invented. live_status may be None (no live
        # supervisor for this source right now, e.g. after a backend
        # restart) - that's an honest absence, not a fabricated "no errors".
        errors: list[str] = []
        manager = get_collector_manager()
        live_status = manager.get_source_status(source.id)
        collector_status_value: str | None = None
        if live_status is not None:
            collector_status_value = (
                live_status.state.value if hasattr(live_status.state, "value") else live_status.state
            )
            if live_status.last_error:
                errors = [live_status.last_error]

        event_ids = [e.id for e in events]

        # Step 3: findings/alerts/incidents actually linked to those events.
        finding_repo = get_finding_repository()
        findings = await finding_repo.list(
            FindingQuery(event_ids=event_ids, tenant_ids=auth.tenant_ids, limit=1000)
        )

        alert_repo = get_alert_repository()
        alerts = await alert_repo.list_by_event_ids(event_ids)
        alert_ids = [a.id for a in alerts]

        report_status = _compute_report_status(
            events_processed=events_processed,
            events_pending=events_pending,
            events_failed=events_failed,
            findings_count=len(findings),
        )

        findings_response = [
            {
                "finding_id": f.id,
                "rule_id": f.rule_id,
                "name": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "evidence": [f"{k}: {v}" for k, v in (f.evidence or {}).items()],
                "mitre_techniques": f.mitre_techniques,
                "recommendations": [],
                "metadata": None,
                "source_ip": None,
                "host": source.name,
                "timestamp": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ]

        report = {
            "source_id": source.id,
            "source_name": source.name,
            "source_type": source.source_type.value,
            "hostname": log_events[0].hostname if log_events else None,
            "time_range_start": time_range_start.isoformat(),
            "time_range_end": time_range_end.isoformat(),
            "generated_at": datetime.now(tz=time_range_end.tzinfo).isoformat(),
            "status": report_status,
            "collector_status": collector_status_value,
            "events_processed": events_processed,
            "events_pending": events_pending,
            "events_failed": events_failed,
            "findings_count": len(findings),
            "severity_breakdown": severity_breakdown,
            "errors": errors,
            "findings": findings_response,
            "alert_ids": alert_ids,
        }
        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to build detection report", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to build detection report")


@router.patch(
    "/sources/{source_id}",
    summary="Update Log Source",
    description="Update a log source configuration. Only visible/editable if it belongs to a tenant the caller is authorized for.",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def update_log_source(
    request: Request,
    response: Response,
    source_id: str,
    update: LogSourceUpdate,
    user: User = Depends(get_current_active_user),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Update a log source."""
    logger.info("Updating log source", source_id=source_id, user_id=getattr(user, "id", None))

    try:
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        existing = await repo.get(source_id)
        if not existing:
            raise _not_found("Log source not found")

        # Tenant isolation (fixes a real pre-existing gap: this route
        # previously had NO tenant check at all, unlike every other
        # /sources/{id} route - any authenticated user of any org could
        # update any other tenant's source). Same "exists but isn't
        # yours" -> 404 convention as GET/restart.
        if auth.tenant_ids is not None and existing.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        old_status = existing.status.value if hasattr(existing.status, "value") else existing.status

        updated = await repo.update(source_id, update)

        if not updated:
            raise _not_found("Log source not found")

        new_status = updated.status.value if hasattr(updated.status, "value") else updated.status
        if update.status is not None and new_status != old_status:
            from app.services.audit import record_audit_event

            # "enabled"/"disabled" are the two statuses the frontend
            # actually toggles between via this route (see
            # LogSourceStatus) - use those more specific action names
            # when they apply, otherwise a generic status-change action.
            action = {
                "active": "log_source_enabled",
                "disabled": "log_source_disabled",
            }.get(new_status, "log_source_status_changed")

            await record_audit_event(
                action=action,
                entity_type="log_source",
                entity_id=source_id,
                user_id=getattr(user, "id", None),
                old_value={"status": old_status},
                new_value={"status": new_status},
            )

        return _source_to_response(updated)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update log source", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to update log source")


_EMBEDDED_COLLECTOR_TYPES = (
    LogSourceType.WINDOWS_EVENT,
    LogSourceType.LINUX_SSH,
    LogSourceType.ANDROID_ADB,
    LogSourceType.LOCAL_NETWORK_MONITOR,
)

# Collector actions below involve real connections to external systems
# (SSH, adb, the Windows event log) or irreversibly change what's being
# monitored - gated to admins only, reusing the require_role() dependency
# factory that already exists (app/auth/jwt.py) but was previously
# unused anywhere in this file, meaning any authenticated role including
# viewer could start/stop/restart/delete a collector today.
_require_admin = require_role([UserRole.ADMIN])


@router.post(
    "/sources/{source_id}/restart",
    summary="Restart Log Source Collector",
    description="""
Restart the embedded collector for a log source (windows_event, linux_ssh,
or android_adb). Admin only.

Useful after fixing an external problem that caused a collector to fail
(e.g. granting the backend process the required Windows "Event Log
Readers" privilege, fixing SSH connectivity, or authorizing/reconnecting
an Android device over adb) - this re-runs the same start path used at
creation time without needing to delete and recreate the source.

No-op (200, source unchanged) if a supervisor for this source is already
running. Source types with no embedded collector always return 400 -
there is nothing to restart for them.
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_COLLECTOR_ACTION)
async def restart_log_source(
    request: Request,
    response: Response,
    source_id: str,
    user: User = Depends(_require_admin),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Restart the collector supervisor for a log source."""
    logger.info("Restarting log source collector", source_id=source_id, user_id=getattr(user, "id", None))

    try:
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        source = await repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        # Tenant isolation (Part 12): same "exists but isn't yours" -> 404
        # treatment as every other /sources/{id} endpoint.
        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        if source.source_type not in _EMBEDDED_COLLECTOR_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Source type '{source.source_type.value}' has no embedded "
                    "collector to restart."
                ),
            )

        from app.logs.collector_manager import get_collector_manager

        get_collector_manager().start_source(source)

        from app.services.audit import record_audit_event

        # Previously missing (gap flagged in audit): create/update/delete
        # all record an audit event, but restart never did.
        await record_audit_event(
            action="log_source_restarted",
            entity_type="log_source",
            entity_id=source_id,
            user_id=getattr(user, "id", None),
            old_value={"status": source.status.value if hasattr(source.status, "value") else source.status},
        )

        # Re-read so the response reflects the restart attempt. start_source()
        # schedules the supervisor asynchronously, so the status here may
        # still be the pre-restart value (e.g. "error") for a moment - the
        # frontend should refetch after a short delay, same as after create.
        refreshed = await repo.get(source_id)
        return _source_to_response(refreshed or source)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to restart log source collector", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to restart log source collector")


@router.post(
    "/sources/{source_id}/stop",
    summary="Stop Log Source Collector",
    description="""
Stop the embedded collector for a log source and mark it disabled so it
does not silently restart on the next backend process restart. Admin only.

Source types with no embedded collector always return 400. If the
collector does not finish shutting down within 15 seconds, this returns
202 ("stop requested") rather than fabricating a confirmed-stopped
response - stopping is allowed to be slow, but a success response must
mean a real, observed shutdown, not an assumed one.
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_COLLECTOR_ACTION)
async def stop_log_source(
    request: Request,
    response: Response,
    source_id: str,
    user: User = Depends(_require_admin),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Stop the collector supervisor for a log source."""
    logger.info("Stopping log source collector", source_id=source_id, user_id=getattr(user, "id", None))

    try:
        import asyncio

        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        source = await repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        if source.source_type not in _EMBEDDED_COLLECTOR_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Source type '{source.source_type.value}' has no embedded "
                    "collector to stop."
                ),
            )

        from app.logs.collector_manager import get_collector_manager

        manager = get_collector_manager()

        try:
            await asyncio.wait_for(manager.stop_source(source_id), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning(
                "Stop request timed out waiting for collector shutdown",
                source_id=source_id,
            )
            response.status_code = status.HTTP_202_ACCEPTED
            refreshed = await repo.get(source_id)
            result = _source_to_response(refreshed or source, manager)
            result["stop_confirmed"] = False
            result["message"] = (
                "Stop requested but the collector had not finished shutting "
                "down within 15 seconds. It may still be stopping - check "
                "collector_status shortly."
            )
            return result

        # Persist DISABLED so start_all() (run on every backend process
        # restart) does not silently resume a source the user explicitly
        # stopped - mirrors how start_all() already skips DISABLED sources.
        await repo.update_status(source_id, LogSourceStatus.DISABLED)

        from app.services.audit import record_audit_event

        await record_audit_event(
            action="log_source_stopped",
            entity_type="log_source",
            entity_id=source_id,
            user_id=getattr(user, "id", None),
            old_value={"status": source.status.value if hasattr(source.status, "value") else source.status},
            new_value={"status": LogSourceStatus.DISABLED.value},
        )

        refreshed = await repo.get(source_id)
        result = _source_to_response(refreshed or source, manager)
        result["stop_confirmed"] = True
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to stop log source collector", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to stop log source collector")


async def _run_connection_check(source_type: LogSourceType, config: Any) -> ConnectionCheckResult:
    """Dispatch to the right standalone connection-check probe."""
    if source_type == LogSourceType.WINDOWS_EVENT:
        return await check_windows_connection(config)
    if source_type == LogSourceType.LINUX_SSH:
        return await check_linux_connection(config)
    if source_type == LogSourceType.ANDROID_ADB:
        return await check_android_connection(config)
    if source_type == LogSourceType.LOCAL_NETWORK_MONITOR:
        return await check_local_network_connection(config)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Source type '{source_type.value}' has no connection check.",
    )


@router.post(
    "/sources/{source_id}/check-connection",
    summary="Check Connection/Permissions For An Existing Log Source",
    description="""
Run a real, side-effect-free pre-flight check against an existing
source's configured target (opens then closes the Windows event log /
SSH connection, or probes Android device state) without starting full
collection. Admin only.

Returns the real underlying error (e.g. the specific Windows privilege
error, SSH authentication failure, or adb device state) on failure -
never a generic "check failed" message.
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_COLLECTOR_ACTION)
async def check_log_source_connection(
    request: Request,
    response: Response,
    source_id: str,
    user: User = Depends(_require_admin),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Run a connection/permission pre-flight check for an existing source."""
    import asyncio

    try:
        from app.logs.collector_manager import _decrypt_source_credentials
        from app.logs.collectors.android import AndroidADBCollectorConfig
        from app.logs.collectors.linux import LinuxSSHCollectorConfig
        from app.logs.collectors.windows import WindowsCollectorConfig
        from app.logs.collectors.local_network import LocalNetworkMonitorConfig
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        source = await repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        if source.source_type not in _EMBEDDED_COLLECTOR_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Source type '{source.source_type.value}' has no connection check.",
            )

        credentials = _decrypt_source_credentials(source)

        try:
            if source.source_type == LogSourceType.WINDOWS_EVENT:
                cfg = {**source.configuration}
                if "event_ids" in cfg and isinstance(cfg["event_ids"], list):
                    cfg["event_ids"] = set(cfg["event_ids"])
                config = WindowsCollectorConfig(source_id=source.id, organization_id=source.organization_id, **cfg)
            elif source.source_type == LogSourceType.LINUX_SSH:
                cfg = {**source.configuration, **credentials}
                config = LinuxSSHCollectorConfig(source_id=source.id, organization_id=source.organization_id, **cfg)
            elif source.source_type == LogSourceType.LOCAL_NETWORK_MONITOR:
                cfg = {**source.configuration}
                config = LocalNetworkMonitorConfig(source_id=source.id, organization_id=source.organization_id, **cfg)
            else:
                cfg = {**source.configuration}
                config = AndroidADBCollectorConfig(source_id=source.id, organization_id=source.organization_id, **cfg)
        except ValidationError as e:
            # The stored configuration itself is invalid (e.g. hand-edited
            # directly in the DB, or a since-removed field) - this is a
            # real, honest failure to report, not a 500. Never silently
            # treat an unbuildable config as a successful check.
            result = ConnectionCheckResult(
                ok=False,
                source_type=source.source_type,
                message="The stored configuration for this source is invalid.",
                detail=str(e),
            )
            from app.services.audit import record_audit_event

            await record_audit_event(
                action="log_source_connection_checked",
                entity_type="log_source",
                entity_id=source_id,
                user_id=getattr(user, "id", None),
                new_value={"ok": False, "source_type": source.source_type.value},
            )
            return result.model_dump(mode="json")

        try:
            result = await asyncio.wait_for(
                _run_connection_check(source.source_type, config), timeout=20.0
            )
        except asyncio.TimeoutError:
            result = ConnectionCheckResult(
                ok=False,
                source_type=source.source_type,
                message="Connection check timed out after 20 seconds.",
            )

        from app.services.audit import record_audit_event

        await record_audit_event(
            action="log_source_connection_checked",
            entity_type="log_source",
            entity_id=source_id,
            user_id=getattr(user, "id", None),
            new_value={"ok": result.ok, "source_type": source.source_type.value},
        )

        return result.model_dump(mode="json")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to check log source connection", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check log source connection")


class ConnectionCheckPreviewRequest(BaseModel):
    """Request body for the pre-create connection-check preview."""

    source_type: LogSourceType
    configuration: dict[str, Any] = PydanticField(default_factory=dict)
    credentials: dict[str, Any] | None = None


@router.post(
    "/sources/check-connection/preview",
    summary="Check Connection/Permissions Before Creating A Log Source",
    description="""
Run the same real pre-flight check as /sources/{id}/check-connection, but
against a configuration that has not been saved yet - for use from the
Add Log Source form before submitting. Persists nothing: no log_sources
row, no encrypted_config, nothing. Admin only (matches the gating on the
other collector-action routes).
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_COLLECTOR_ACTION)
async def check_log_source_connection_preview(
    request: Request,
    response: Response,
    body: ConnectionCheckPreviewRequest,
    user: User = Depends(_require_admin),
) -> dict:
    """Run a connection/permission pre-flight check against an unsaved configuration."""
    import asyncio

    try:
        from app.logs.collectors.android import AndroidADBCollectorConfig
        from app.logs.collectors.linux import LinuxSSHCollectorConfig
        from app.logs.collectors.windows import WindowsCollectorConfig
        from app.logs.collectors.local_network import LocalNetworkMonitorConfig

        if body.source_type not in _EMBEDDED_COLLECTOR_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Source type '{body.source_type.value}' has no connection check.",
            )

        credentials = body.credentials or {}

        # No source_id exists yet - "preview" is a synthetic placeholder,
        # never persisted or used to look anything up.
        try:
            if body.source_type == LogSourceType.WINDOWS_EVENT:
                cfg = {**body.configuration}
                if "event_ids" in cfg and isinstance(cfg["event_ids"], list):
                    cfg["event_ids"] = set(cfg["event_ids"])
                config = WindowsCollectorConfig(source_id="preview", **cfg)
            elif body.source_type == LogSourceType.LINUX_SSH:
                cfg = {**body.configuration, **credentials}
                config = LinuxSSHCollectorConfig(source_id="preview", **cfg)
            elif body.source_type == LogSourceType.LOCAL_NETWORK_MONITOR:
                cfg = {**body.configuration}
                config = LocalNetworkMonitorConfig(source_id="preview", **cfg)
            else:
                cfg = {**body.configuration}
                config = AndroidADBCollectorConfig(source_id="preview", **cfg)
        except ValidationError as e:
            # Invalid form input (e.g. an unsupported channel/hostname
            # format) is a real, honest check failure to surface to the
            # Add Source modal - not a 500. The field-level errors come
            # straight from the collector's own config model, so they're
            # just as real as any other check-connection failure.
            result = ConnectionCheckResult(
                ok=False,
                source_type=body.source_type,
                message="The provided configuration is invalid.",
                detail=str(e),
            )
            from app.services.audit import record_audit_event

            await record_audit_event(
                action="log_source_connection_checked",
                entity_type="log_source",
                entity_id="preview",
                user_id=getattr(user, "id", None),
                new_value={"ok": False, "source_type": body.source_type.value},
            )
            return result.model_dump(mode="json")

        try:
            result = await asyncio.wait_for(
                _run_connection_check(body.source_type, config), timeout=20.0
            )
        except asyncio.TimeoutError:
            result = ConnectionCheckResult(
                ok=False,
                source_type=body.source_type,
                message="Connection check timed out after 20 seconds.",
            )

        from app.services.audit import record_audit_event

        await record_audit_event(
            action="log_source_connection_checked",
            entity_type="log_source",
            entity_id="preview",
            user_id=getattr(user, "id", None),
            new_value={"ok": result.ok, "source_type": body.source_type.value},
        )

        return result.model_dump(mode="json")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to check preview log source connection", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check connection")


@router.delete(
    "/sources/{source_id}",
    summary="Delete Log Source",
    description="Delete a log source. Associated log events are preserved. Admin only.",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def delete_log_source(
    request: Request,
    response: Response,
    source_id: str,
    user: User = Depends(_require_admin),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Delete a log source."""
    logger.info("Deleting log source", source_id=source_id, user_id=getattr(user, "id", None))

    try:
        from app.logs.repository import get_log_source_repository

        repo = get_log_source_repository()
        source = await repo.get(source_id)

        if not source:
            raise _not_found("Log source not found")

        # Tenant isolation (fixes a real pre-existing gap: this route
        # previously had NO tenant check at all - any authenticated user
        # of any org could delete any other tenant's source).
        if auth.tenant_ids is not None and source.organization_id not in auth.tenant_ids:
            raise _not_found("Log source not found")

        await repo.delete(source_id)

        from app.services.audit import record_audit_event

        await record_audit_event(
            action="log_source_removed",
            entity_type="log_source",
            entity_id=source_id,
            user_id=getattr(user, "id", None),
            old_value={"name": source.name, "source_type": source.source_type.value},
        )

        return {"deleted": True, "source_id": source_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete log source", source_id=source_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete log source")


# =============================================================================
# Log Events Endpoints
# =============================================================================


@router.get(
    "/events",
    summary="List Log Events",
    description="""
Query and list log events with filtering, scoped to the caller's authorized tenant(s).

**Filters:**
- `source_id`: Filter by log source
- `source_type`: Filter by source type
- `hostname`: Filter by hostname
- `level`: Filter by log level
- `category`: Filter by category
- `analyzed`: Filter by analysis status
- `search`: Full-text search in message
- `start_time` / `end_time`: Time range filter
- `tenant_id`: Required for non-admin users; selects which authorized tenant to query
    """,
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def list_log_events(
    request: Request,
    response: Response,
    source_id: str | None = Query(None),
    source_type: LogSourceType | None = Query(None),
    hostname: str | None = Query(None),
    level: LogLevel | None = Query(None),
    category: str | None = Query(None),
    analyzed: bool | None = Query(None),
    search: str | None = Query(None, min_length=2, max_length=200),
    start_time: datetime | None = Query(None),
    end_time: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """List log events with filters, scoped to the caller's authorized tenant(s)."""
    try:
        from app.logs.repository import get_log_event_repository

        repo = get_log_event_repository()

        query = LogEventQuery(
            source_id=source_id,
            source_type=source_type,
            hostname=hostname,
            level=level,
            category=category,
            analyzed=analyzed,
            search=search,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )
        _apply_tenant_authorization(query, auth)

        events = await repo.list(query)
        total = await repo.count(query)

        return {
            "events": [_event_to_response(e) for e in events],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to list log events", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list log events")


@router.get(
    "/events/statistics",
    summary="Get Log Statistics",
    description="Get log event statistics for the specified time period, scoped to the caller's authorized tenant(s).",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def get_log_statistics(
    request: Request,
    response: Response,
    source_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Get log event statistics, scoped to the caller's authorized tenant(s)."""
    try:
        from app.logs.repository import (
            get_log_event_repository,
            get_log_source_repository,
        )

        # If a specific source_id was requested, it must belong to an
        # authorized tenant - otherwise behave as if it doesn't exist
        # (Part 12), returning empty statistics rather than another
        # tenant's data or a differently-coded error.
        if source_id and auth.tenant_ids is not None:
            source_repo = get_log_source_repository()
            source = await source_repo.get(source_id)
            if not source or source.organization_id not in auth.tenant_ids:
                return {
                    "period_hours": hours,
                    "source_id": source_id,
                    "statistics": {},
                }

        repo = get_log_event_repository()
        stats = await repo.get_statistics(source_id=source_id, hours=hours)

        return {
            "period_hours": hours,
            "source_id": source_id,
            "statistics": stats,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get log statistics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get log statistics")


# NOTE: this route must stay registered AFTER /events/statistics (and any
# other literal /events/<word> route added in future). FastAPI/Starlette
# matches routes in registration order, so a dynamic "/events/{event_id}"
# registered first would swallow "/events/statistics" as a request for
# the literal event_id "statistics" - which is exactly the bug this
# ordering fixes (confirmed via a live request: it was returning the
# "Failed to get log event" error, from this handler's own except block,
# for a GET to /events/statistics).
@router.get(
    "/events/{event_id}",
    summary="Get Log Event",
    description="Get a single log event by ID. Only visible if it belongs to a tenant the caller is authorized for.",
    response_model=dict,
)
@limiter.limit(RATE_LIMIT_GET)
async def get_log_event(
    request: Request,
    response: Response,
    event_id: str,
    auth: TenantAuthorization = Depends(get_authorized_tenant_ids),
) -> dict:
    """Get a log event by ID."""
    try:
        from app.logs.repository import get_log_event_repository

        repo = get_log_event_repository()
        event = await repo.get(event_id, tenant_ids=auth.tenant_ids)

        if not event:
            raise _not_found("Log event not found")

        return _event_to_response(event)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get log event", event_id=event_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get log event")


# =============================================================================
# Log Ingestion Endpoints
# =============================================================================


@router.post(
    "/ingest",
    summary="Ingest Log Events",
    description=f"""
Receive log events from external collectors.

This endpoint accepts parsed log entries from collectors and:
1. Stores them in the database
2. Publishes them to Redpanda for real-time analysis
3. Updates source statistics

**Authentication:** Provide `X-Ingestion-Key` header with a valid API key
(the same mechanism used by `/logs/web/ingest`).

**Limits:**
- Max {settings.log_ingest_max_entries} entries per request
- Max {settings.log_ingest_max_request_bytes // 1024}KB request body
- Rate limited to 1000 requests per minute

**Security:**
- `source_id` and `tenant_id` are always resolved from the authenticated
  API key, never from client-supplied query parameters or entry content
- Logs must be pre-processed to remove any secrets; raw content is also
  redacted server-side before persistence
    """,
    response_model=dict,
    responses={
        401: {"description": "Invalid or missing API key"},
        403: {"description": "Source not authorized for this key"},
        413: {"description": "Request too large"},
    },
)
@limiter.limit("1000/minute")
async def ingest_logs(
    request: Request,
    entries: list[ParsedLogEntry],
    source_id: str | None = Query(
        None,
        description="Ignored if present - source identity is always taken from the authenticated API key.",
    ),
    publish_to_bus: bool = Query(True, description="Publish to event bus for analysis"),
) -> dict:
    """Ingest log events from external collectors."""
    from app.api.v1.web_ingest import get_authenticated_key

    key: IngestionApiKey = await get_authenticated_key(
        api_key=request.headers.get("X-Ingestion-Key")
    )

    if source_id and source_id != key.source_id:
        logger.warning(
            "Ingest request supplied a source_id query param that does not "
            "match the authenticated key's bound source - ignoring the "
            "client-supplied value",
            key_id=key.id,
            key_source_id=key.source_id,
            requested_source_id=source_id,
        )

    if not entries:
        return {"ingested": 0, "published": 0}

    if len(entries) > settings.log_ingest_max_entries:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many entries: max {settings.log_ingest_max_entries} per request",
        )

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.log_ingest_max_request_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request body exceeds {settings.log_ingest_max_request_bytes // 1024}KB limit",
        )

    logger.info(
        "Ingesting log entries",
        count=len(entries),
        source_id=key.source_id,
        organization_id=key.organization_id,
    )

    try:
        from app.logs.models import LogEvent
        from app.logs.repository import (
            get_log_event_repository,
            get_log_source_repository,
        )

        event_repo = get_log_event_repository()
        source_repo = get_log_source_repository()

        # Resolve and verify source ownership from the authenticated key
        # only (STEP 4 Part 3/10) - never from client input.
        source = await source_repo.get(key.source_id)
        try:
            verify_source_tenant_match(source, key)
        except PermissionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="LogSource not authorized for this API key",
            )

        # verify_source_tenant_match() above already raises PermissionError
        # (mapped to 403, caught before reaching here) when source is None -
        # so source is always non-None at this point. No fallback literal
        # is needed (STEP 9: the old fallback to the now-removed
        # LogSourceType.WEB_APPLICATION was dead code; removed rather than
        # replaced with a different fabricated default).
        source_type = source.source_type

        # Convert entries to LogEvents. source_id and tenant_id are always
        # the authenticated key's own values - entry.source_id (if a
        # client supplied one) is never trusted for identity/ownership.
        log_events = []
        for entry in entries:
            log_event = LogEvent.from_parsed_entry(
                entry, source_type, tenant_id=key.organization_id
            )
            log_event.source_id = key.source_id
            log_events.append(log_event)

        # Store in database (redaction applied in repository)
        stored_count, _ = await event_repo.create_batch(log_events)

        # Update source statistics
        await source_repo.update_event_stats(key.source_id, stored_count)

        # Publish to event bus
        published_count = 0
        if publish_to_bus:
            from app.logs.event_bus_integration import publish_log_events_batch
            success, _ = await publish_log_events_batch(log_events)
            published_count = success

        return {
            "ingested": stored_count,
            "published": published_count,
            "source_id": key.source_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to ingest logs", error=str(e), source_id=key.source_id)
        raise HTTPException(status_code=500, detail="Failed to ingest logs")


@router.post(
    "/ingest/raw",
    summary="Ingest Raw Log Content",
    description=f"""
Ingest raw log content for parsing and analysis.

This endpoint accepts raw log text and:
1. Parses it using the LogAgent's parser
2. Stores parsed events
3. Triggers security analysis

Useful for manual log submission or file uploads.

**Authentication:** Provide `X-Ingestion-Key` header with a valid API key
(the same mechanism used by `/logs/web/ingest`). This endpoint accepts
free-form text but is NOT an authentication bypass - the same key
verification and tenant/source ownership checks as `/ingest` apply.

**Limits:**
- Max {settings.log_ingest_max_raw_content_bytes // 1024}KB of raw content per request
    """,
    response_model=dict,
    responses={
        401: {"description": "Invalid or missing API key"},
        403: {"description": "Source not authorized for this key"},
        413: {"description": "Request too large"},
    },
)
@limiter.limit("100/minute")
async def ingest_raw_logs(
    request: Request,
    log_content: str = Query(..., min_length=1, description="Raw log content"),
    source_id: str | None = Query(
        None,
        description="Ignored if present - source identity is always taken from the authenticated API key.",
    ),
    source_type: LogSourceType | None = Query(
        None,
        description=(
            "Ignored if present - source_type is always taken from the "
            "authenticated key's bound LogSource, never from client input "
            "(STEP 9: this previously defaulted to the now-removed "
            "web_application type, which silently mislabeled every "
            "request where a caller didn't pass one explicitly)."
        ),
    ),
    hostname: str | None = Query(None),
    analyze: bool = Query(True, description="Run security analysis"),
) -> dict:
    """Ingest raw log content."""
    from app.api.v1.web_ingest import get_authenticated_key

    key: IngestionApiKey = await get_authenticated_key(
        api_key=request.headers.get("X-Ingestion-Key")
    )

    if source_id and source_id != key.source_id:
        logger.warning(
            "Raw ingest request supplied a source_id query param that does "
            "not match the authenticated key's bound source - ignoring the "
            "client-supplied value",
            key_id=key.id,
            key_source_id=key.source_id,
            requested_source_id=source_id,
        )

    content_bytes = len(log_content.encode("utf-8"))
    if content_bytes > settings.log_ingest_max_raw_content_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"log_content exceeds "
                f"{settings.log_ingest_max_raw_content_bytes // 1024}KB limit"
            ),
        )

    try:
        from app.logs.repository import (
            get_log_event_repository,
            get_log_source_repository,
        )

        source_repo = get_log_source_repository()
        source = await source_repo.get(key.source_id)
        try:
            verify_source_tenant_match(source, key)
        except PermissionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="LogSource not authorized for this API key",
            )

        # Resolve source_type server-side from the authenticated key's own
        # bound LogSource (verify_source_tenant_match above guarantees
        # `source` is non-None here) - the query param above is ignored,
        # never trusted, for the same reason source_id is ignored.
        if source_type is not None and source_type != source.source_type:
            logger.warning(
                "Raw ingest request supplied a source_type query param that "
                "does not match the authenticated key's bound source - "
                "ignoring the client-supplied value",
                key_id=key.id,
                bound_source_type=source.source_type.value,
                requested_source_type=source_type.value,
            )
        source_type = source.source_type

        logger.info(
            "Ingesting raw log content",
            content_length=len(log_content),
            source_type=source_type.value,
            source_id=key.source_id,
        )

        # Parse and create log events
        lines = [line.strip() for line in log_content.strip().split("\n") if line.strip()]

        if len(lines) > settings.log_ingest_max_entries:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Too many log lines: max {settings.log_ingest_max_entries} per request",
            )

        if not lines:
            return {"ingested": 0, "analyzed": False}

        from datetime import datetime, timezone

        from app.logs.models import LogEvent, LogLevel

        log_events = []
        for line in lines:
            event = LogEvent(
                source_id=key.source_id,
                source_type=source_type,
                hostname=hostname,
                timestamp=datetime.now(timezone.utc),
                level=LogLevel.INFO,
                message=line,
                raw_content=line,
                tenant_id=key.organization_id,
            )
            log_events.append(event)

        # Store events (centralized redaction applied in repository
        # before persistence - never bypassed here)
        repo = get_log_event_repository()
        stored_count, _ = await repo.create_batch(log_events)

        # Run analysis if requested. This dispatches the ORIGINAL
        # log_content for in-memory analysis only (LogAgent.analyze()
        # does not persist or log raw content) - persisted LogEvents
        # above already went through redact_log_event() in the
        # repository, so stored data is redacted regardless of this path.
        analysis_result = None
        if analyze:
            from app.agents import AgentType, get_dispatcher
            dispatcher = get_dispatcher()
            result = await dispatcher.dispatch(AgentType.LOG, {
                "log_content": log_content,
                "log_type": source_type.value,
                "source_host": hostname,
            })
            analysis_result = {
                "classification": result.classification,
                "severity": result.severity.value,
                "risk_score": result.risk_score,
                "findings_count": len(result.findings),
            }

        return {
            "ingested": stored_count,
            "analyzed": analyze,
            "analysis_result": analysis_result,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to ingest raw logs", error=str(e), source_id=key.source_id)
        raise HTTPException(status_code=500, detail="Failed to ingest logs")
