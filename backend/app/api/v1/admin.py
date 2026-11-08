"""
CyberGuard AI — Admin Endpoints
============================================================================

Platform-level administration: analyst verification workflow, audit
log access, and platform health monitoring.

Ten endpoints — all super-admin only:

    GET  /admin/analysts/pending            — pending applications
    GET  /admin/analysts                    — all analysts (status filter)
    POST /admin/analysts/{profile_id}/review      — start review
    POST /admin/analysts/{profile_id}/approve     — approve
    POST /admin/analysts/{profile_id}/reject      — reject with reason
    POST /admin/analysts/{profile_id}/suspend     — suspend verified analyst
    POST /admin/analysts/{profile_id}/reactivate  — lift suspension
    GET  /admin/audit                       — query audit log
    GET  /admin/audit/stats                 — audit aggregate stats
    GET  /admin/platform/health             — platform health summary

Super-admin enforcement
-----------------------
Every endpoint requires an ``admin:*`` permission. These currently
**fail closed** — no user has them until a super admin column is
formalized via migration (adds ``is_super_admin`` to ``users``).

This is intentional. The endpoints exist, are documented, and are
auditable — but nobody can use them until the super admin concept is
explicitly configured. Opening them prematurely (e.g. "any workspace
OWNER can verify analysts") would create a privilege escalation path
that's hard to close.

Once the migration lands, the endpoints work without code changes —
the ``require_permission("admin:analyst_verify")`` dependency
resolves to True for super admins automatically.

Admin actions are audited
-------------------------
Every mutation (approve, reject, suspend, reactivate) writes an audit
row via the service layer. These are among the highest-signal audit
events in the platform — a compromised super admin account leaves a
complete trail of every action.

Audit query endpoints
---------------------
``GET /admin/audit`` and ``GET /admin/audit/stats`` expose the
``security_audit_logs`` table. Both require ``admin:audit_read``. The
query endpoint has mandatory filters to prevent full-table scans — see
``AuditLogFilter``.

Platform health
---------------
``GET /admin/platform/health`` returns a snapshot of platform-level
metrics. Designed for super-admin dashboards — no sensitive content,
just counts and statuses.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
    require_permission,
)
from app.core.exceptions import (
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.analyst import AnalystProfile
from app.models.collector_credential import CollectorCredential
from app.models.enums import (
    AnalystVerificationStatus,
    IncidentStatus,
    PurchaseStatus,
    SourceStatus,
    UserStatus,
)
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.incident import SecurityIncident
from app.models.marketplace import ServicePurchase
from app.models.source import SecuritySource
from app.models.user import User
from app.schemas.analyst import (
    AnalystProfileRead,
)
from app.schemas.audit import (
    AuditLogFilter,
    AuditLogList,
    AuditLogRead,
    AuditLogStats,
)
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.services import (
    analyst_service,
    audit_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[
        # Every endpoint in this router requires authentication.
        # Individual endpoints add the specific admin:* permission.
        Depends(require_permission("admin:platform_config")),
    ],
)


# ============================================================================
# INLINE SCHEMAS — platform health
# ============================================================================

class PlatformHealthSnapshot(BaseModel):
    """Aggregate platform health metrics for super-admin dashboards."""
    model_config = ConfigDict(extra="forbid")

    generated_at: datetime

    users: dict
    sources: dict
    events: dict
    findings: dict
    incidents: dict
    collectors: dict
    marketplace: dict


# ============================================================================
# ANALYST VERIFICATION
# ============================================================================

@router.get(
    "/analysts/pending",
    response_model=PaginatedResponse[AnalystProfileRead],
    summary="List pending analyst applications (super admin)",
    description=(
        "Returns applications awaiting review (PENDING or IN_REVIEW), "
        "ordered by submission time ascending (oldest first). "
        "Requires `admin:analyst_verify`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def list_pending_analysts(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
) -> PaginatedResponse[AnalystProfileRead]:
    profiles, total = analyst_service.list_pending_applications(
        db, actor=current_user, page=page,
    )
    return PaginatedResponse[AnalystProfileRead](
        items=[AnalystProfileRead.model_validate(p) for p in profiles],
        meta=PageMeta.build(total=total, params=page),
    )


@router.get(
    "/analysts",
    response_model=PaginatedResponse[AnalystProfileRead],
    summary="List all analyst profiles (super admin)",
    description=(
        "Returns all analyst profiles, optionally filtered by verification "
        "status. Requires `admin:analyst_verify`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def list_all_analysts(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    status_filter: AnalystVerificationStatus | None = Query(
        default=None,
        alias="status",
        description="Filter by verification status.",
    ),
) -> PaginatedResponse[AnalystProfileRead]:
    profiles, total = analyst_service.list_all_analysts(
        db,
        actor=current_user,
        page=page,
        status=status_filter,
    )
    return PaginatedResponse[AnalystProfileRead](
        items=[AnalystProfileRead.model_validate(p) for p in profiles],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/analysts/{profile_id}/review",
    response_model=AnalystProfileRead,
    summary="Start review of an analyst application",
    description=(
        "Transitions PENDING → IN_REVIEW. Requires `admin:analyst_verify`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def start_analyst_review(
    profile_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AnalystProfileRead:
    profile = analyst_service.get_by_id(db, profile_id)
    updated = analyst_service.start_review(
        db, actor=current_user, profile=profile,
    )
    db.commit()
    return AnalystProfileRead.model_validate(updated)


@router.post(
    "/analysts/{profile_id}/approve",
    response_model=AnalystProfileRead,
    summary="Approve an analyst application",
    description=(
        "Transitions IN_REVIEW → VERIFIED. Sets `verified_by_id` and "
        "`verification_completed_at`. The analyst can then publish "
        "offerings and accept cases. Requires `admin:analyst_verify`.\n\n"
        "Optional `notes` are recorded in `verification_notes` (admin-only "
        "field, not visible to the analyst)."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def approve_analyst(
    profile_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    notes: Annotated[str | None, Body(embed=True, max_length=5000)] = None,
) -> AnalystProfileRead:
    profile = analyst_service.get_by_id(db, profile_id)
    updated = analyst_service.approve_application(
        db, actor=current_user, profile=profile, notes=notes,
    )
    db.commit()

    logger.info(
        "Analyst application approved",
        extra={
            "profile_id": str(profile_id),
            "admin_id": str(current_user.id),
        },
    )

    return AnalystProfileRead.model_validate(updated)


@router.post(
    "/analysts/{profile_id}/reject",
    response_model=AnalystProfileRead,
    summary="Reject an analyst application",
    description=(
        "Transitions IN_REVIEW → REJECTED. `reason` is required — it's "
        "surfaced to the applicant and recorded in the audit trail. The "
        "analyst must wait 30 days before re-applying. Requires "
        "`admin:analyst_reject`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_reject"))],
)
def reject_analyst(
    profile_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=2000),
) -> AnalystProfileRead:
    profile = analyst_service.get_by_id(db, profile_id)
    updated = analyst_service.reject_application(
        db, actor=current_user, profile=profile, reason=reason,
    )
    db.commit()

    logger.info(
        "Analyst application rejected",
        extra={
            "profile_id": str(profile_id),
            "admin_id": str(current_user.id),
        },
    )

    return AnalystProfileRead.model_validate(updated)


@router.post(
    "/analysts/{profile_id}/suspend",
    response_model=AnalystProfileRead,
    summary="Suspend a verified analyst",
    description=(
        "Transitions VERIFIED → SUSPENDED. The analyst cannot accept new "
        "cases. `reason` is required. Requires `admin:analyst_verify`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def suspend_analyst(
    profile_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=2000),
) -> AnalystProfileRead:
    profile = analyst_service.get_by_id(db, profile_id)
    updated = analyst_service.suspend_analyst(
        db, actor=current_user, profile=profile, reason=reason,
    )
    db.commit()

    logger.warning(
        "Analyst suspended",
        extra={
            "profile_id": str(profile_id),
            "admin_id": str(current_user.id),
        },
    )

    return AnalystProfileRead.model_validate(updated)


@router.post(
    "/analysts/{profile_id}/reactivate",
    response_model=AnalystProfileRead,
    summary="Reactivate a suspended analyst",
    description=(
        "Transitions SUSPENDED → VERIFIED. The analyst must still "
        "explicitly set `available_for_hire=true` to accept new cases. "
        "Requires `admin:analyst_verify`."
    ),
    dependencies=[Depends(require_permission("admin:analyst_verify"))],
)
def reactivate_analyst(
    profile_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AnalystProfileRead:
    profile = analyst_service.get_by_id(db, profile_id)
    updated = analyst_service.reactivate_analyst(
        db, actor=current_user, profile=profile,
    )
    db.commit()
    return AnalystProfileRead.model_validate(updated)


# ============================================================================
# AUDIT LOG
# ============================================================================

@router.get(
    "/audit",
    response_model=PaginatedResponse[AuditLogList],
    summary="Query the audit log (super admin)",
    description=(
        "Paginated query over `security_audit_logs`. **A time range is "
        "required** (`created_after` and/or `created_before`) — "
        "unbounded queries would scan years of rows. Set at least one of "
        "`created_after`, `created_before`, `actor_id`, or `target_id` "
        "to bound the query.\n\n"
        "Requires `admin:audit_read`."
    ),
    dependencies=[Depends(require_permission("admin:audit_read"))],
)
def query_audit_log(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: AuditLogFilter = Depends(),
) -> PaginatedResponse[AuditLogList]:
    # Require at least one bounding filter (time or entity)
    has_bound = any([
        filters.created_after,
        filters.created_before,
        filters.actor_id,
        filters.target_id,
        filters.correlation_id,
    ])
    if not has_bound:
        raise ValidationError(
            message=(
                "Audit queries require at least one bounding filter: "
                "created_after, created_before, actor_id, target_id, or "
                "correlation_id. Unbounded scans are rejected."
            ),
            code="AUDIT_QUERY_UNBOUNDED",
        )

    rows, total = audit_service.query_audit_logs(
        db, page=page, filters=filters,
    )
    return PaginatedResponse[AuditLogList](
        items=[AuditLogList.model_validate(r) for r in rows],
        meta=PageMeta.build(total=total, params=page),
    )


@router.get(
    "/audit/{log_id}",
    response_model=AuditLogRead,
    summary="Get a single audit log entry",
    description=(
        "Full audit row including `before_state` / `after_state` "
        "snapshots. Requires `admin:audit_read`."
    ),
    dependencies=[Depends(require_permission("admin:audit_read"))],
)
def get_audit_log(
    log_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AuditLogRead:
    from app.models.audit import SecurityAuditLog
    row = db.get(SecurityAuditLog, log_id)
    if row is None:
        raise NotFoundError(
            message=f"Audit log entry {log_id} not found.",
            code="AUDIT_LOG_NOT_FOUND",
        )
    return AuditLogRead.model_validate(row)


@router.get(
    "/audit/stats",
    response_model=AuditLogStats,
    summary="Audit log aggregate statistics",
    description=(
        "Aggregated counts over audit rows matching the filters: total "
        "entries, breakdown by actor type, breakdown by outcome, top 10 "
        "actions, failure count, unrecognized-action count, and the "
        "time range covered. Requires `admin:audit_read`."
    ),
    dependencies=[Depends(require_permission("admin:audit_read"))],
)
def get_audit_stats(
    current_user: CurrentActiveUser,
    db: DBDep,
    filters: AuditLogFilter = Depends(),
) -> AuditLogStats:
    return audit_service.compute_stats(db, filters=filters)


# ============================================================================
# PLATFORM HEALTH
# ============================================================================

@router.get(
    "/platform/health",
    response_model=PlatformHealthSnapshot,
    summary="Platform health snapshot (super admin)",
    description=(
        "Aggregate metrics for platform monitoring: user counts, source "
        "status, recent event volume, incident load, collector health, "
        "and marketplace activity.\n\n"
        "All metrics are non-sensitive counts. Requires "
        "`admin:platform_config`."
    ),
)
def get_platform_health(
    current_user: CurrentActiveUser,
    db: DBDep,
) -> PlatformHealthSnapshot:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # ── Users
    total_users = db.execute(
        select(func.count()).select_from(User).where(User.deleted_at.is_(None))
    ).scalar_one()
    active_users = db.execute(
        select(func.count()).select_from(User).where(
            User.deleted_at.is_(None),
            User.status == UserStatus.ACTIVE,
        )
    ).scalar_one()

    # ── Sources
    total_sources = db.execute(
        select(func.count()).select_from(SecuritySource)
    ).scalar_one()
    active_sources = db.execute(
        select(func.count()).select_from(SecuritySource).where(
            SecuritySource.status == SourceStatus.ACTIVE,
        )
    ).scalar_one()

    # ── Events (last 24h)
    events_24h = db.execute(
        select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.received_at >= day_ago,
        )
    ).scalar_one()

    # ── Findings (last 24h)
    findings_24h = db.execute(
        select(func.count()).select_from(AgentFinding).where(
            AgentFinding.first_seen_at >= day_ago,
        )
    ).scalar_one()

    # ── Incidents (open count)
    open_incidents = db.execute(
        select(func.count()).select_from(SecurityIncident).where(
            SecurityIncident.status != IncidentStatus.CLOSED,
        )
    ).scalar_one()

    # ── Collectors (active installations)
    active_collectors = db.execute(
        select(func.count()).select_from(CollectorCredential).where(
            CollectorCredential.status == "active",
        )
    ).scalar_one()

    # ── Marketplace (active offerings + completed purchases)
    active_offerings = db.execute(
        select(func.count()).select_from(
            __import__(
                "app.models.marketplace", fromlist=["AnalystServiceOffering"]
            ).AnalystServiceOffering
        ).where(
            __import__(
                "app.models.marketplace", fromlist=["AnalystServiceOffering"]
            ).AnalystServiceOffering.status == "active",
        )
    ).scalar_one()

    completed_purchases = db.execute(
        select(func.count()).select_from(ServicePurchase).where(
            ServicePurchase.purchase_status == PurchaseStatus.COMPLETED,
        )
    ).scalar_one()

    return PlatformHealthSnapshot(
        generated_at=now,
        users={
            "total": int(total_users),
            "active": int(active_users),
        },
        sources={
            "total": int(total_sources),
            "active": int(active_sources),
        },
        events={
            "last_24h": int(events_24h),
        },
        findings={
            "last_24h": int(findings_24h),
        },
        incidents={
            "open": int(open_incidents),
        },
        collectors={
            "active_installations": int(active_collectors),
        },
        marketplace={
            "active_offerings": int(active_offerings),
            "completed_purchases": int(completed_purchases),
        },
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]