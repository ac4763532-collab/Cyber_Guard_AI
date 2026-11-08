"""
CyberGuard AI — Alert Endpoints
============================================================================

The user-facing alert lifecycle: list, view, triage, assign, resolve,
dismiss.

Nine endpoints covering the full alert UX:

    GET    /alerts/badge         — sidebar badge counts (fast, cached-friendly)
    GET    /alerts               — list with filters
    GET    /alerts/{id}          — detail with context + recommendations
    POST   /alerts/{id}/seen     — mark seen (badge count drops)
    POST   /alerts/{id}/acknowledge  — NEW → ACKNOWLEDGED
    POST   /alerts/{id}/investigate  — → INVESTIGATING
    PATCH  /alerts/{id}/assign   — assign to analyst
    POST   /alerts/{id}/resolve  — resolve with required notes
    POST   /alerts/{id}/dismiss  — dismiss with required reason

Route ordering
--------------
``GET /alerts/badge`` is declared BEFORE ``GET /alerts/{alert_id}``.
Without this, FastAPI would try to parse the literal string ``"badge"``
as a UUID and return 422. Route ordering is load-bearing here.

No generic ``PATCH /alerts/{id}/status``
----------------------------------------
Unlike findings, alerts have different required fields per transition:
    - ACKNOWLEDGED → no context needed
    - INVESTIGATING → no context needed
    - RESOLVED → resolution_notes required
    - DISMISSED → reason required

We expose dedicated endpoints for each transition so the required fields
are enforced by the endpoint's request body schema. This is more
ergonomic than a single ``PATCH /status`` with conditional body shapes.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import (
    AlertNotFoundError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.enums import (
    AlertStatus,
    EventSeverity,
)
from app.schemas.alert import (
    AlertAssignRequest,
    AlertDismissRequest,
    AlertFilter,
    AlertList,
    AlertRead,
    AlertResolveRequest,
)
from app.schemas.common import (
    PageMeta,
    PaginatedResponse,
)
from app.services import (
    alert_service,
    authorization,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)


# ============================================================================
# INLINE SCHEMA — AlertBadge
# ============================================================================
# Belongs in app/schemas/alert.py — extracted in cleanup pass. Same
# inline-schema pattern used in organizations.py, workspaces.py, and
# sources.py.

class AlertBadge(BaseModel):
    """Lightweight badge counts for the alert sidebar."""
    model_config = ConfigDict(extra="forbid")

    total_open: int = 0
    unassigned_open: int = 0
    critical_open: int = 0
    high_open: int = 0
    sla_breached: int = 0


# ============================================================================
# BADGE (declared FIRST — literal path beats parameterized path)
# ============================================================================

@router.get(
    "/badge",
    response_model=AlertBadge,
    summary="Get alert badge counts",
    description=(
        "Returns aggregated counts for the alert sidebar. Fast — five "
        "indexed COUNT queries scoped to the user's workspaces. "
        "Suitable for polling from the frontend."
    ),
)
def get_alert_badge(
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertBadge:
    workspace_ids = authorization.get_user_workspaces(db, current_user)
    if not workspace_ids:
        return AlertBadge()

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    # Base filter: open alerts (not resolved/dismissed) in user's workspaces
    base_open = (
        SecurityAlert.workspace_id.in_(workspace_ids),
        SecurityAlert.resolved_at.is_(None),
    )

    total_open = db.execute(
        select(func.count()).select_from(SecurityAlert).where(*base_open)
    ).scalar_one()

    unassigned_open = db.execute(
        select(func.count()).select_from(SecurityAlert).where(
            *base_open,
            SecurityAlert.assigned_to_id.is_(None),
        )
    ).scalar_one()

    critical_open = db.execute(
        select(func.count()).select_from(SecurityAlert).where(
            *base_open,
            SecurityAlert.severity == EventSeverity.CRITICAL,
        )
    ).scalar_one()

    high_open = db.execute(
        select(func.count()).select_from(SecurityAlert).where(
            *base_open,
            SecurityAlert.severity == EventSeverity.HIGH,
        )
    ).scalar_one()

    sla_breached = db.execute(
        select(func.count()).select_from(SecurityAlert).where(
            *base_open,
            SecurityAlert.expires_at.is_not(None),
            SecurityAlert.expires_at < now,
        )
    ).scalar_one()

    return AlertBadge(
        total_open=int(total_open),
        unassigned_open=int(unassigned_open),
        critical_open=int(critical_open),
        high_open=int(high_open),
        sla_breached=int(sla_breached),
    )


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[AlertList],
    summary="List alerts",
    description=(
        "Paginated list of alerts across the user's accessible workspaces. "
        "Requires `alert:read` permission on the workspace.\n\n"
        "Returns lightweight `AlertList` rows. Fetch `GET /alerts/{id}` "
        "for the full alert including `context` and `recommended_actions`."
    ),
)
def list_alerts(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: AlertFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[AlertList]:
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "alert:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            return PaginatedResponse[AlertList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    alerts, total = alert_service.list_alerts(
        db,
        workspace_ids=workspace_ids,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[AlertList](
        items=[AlertList.model_validate(a) for a in alerts],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{alert_id}",
    response_model=AlertRead,
    summary="Get an alert by ID",
    description=(
        "Full alert view including `context`, `recommended_actions`, and "
        "`finding_ids`. Requires `alert:read` on the alert's workspace."
    ),
)
def get_alert(
    alert_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)

    authorization.check_permission(
        db, current_user, "alert:read", workspace_id=alert.workspace_id,
    )

    return AlertRead.model_validate(alert)


# ============================================================================
# SEEN
# ============================================================================

@router.post(
    "/{alert_id}/seen",
    response_model=AlertRead,
    summary="Mark an alert as seen",
    description=(
        "Records that the user opened the alert. Idempotent. Reduces the "
        "unread badge count on the frontend. No audit — engagement signal, "
        "not a security action; the alert's `seen_at` field is the record."
    ),
)
def mark_alert_seen(
    alert_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.mark_seen(db, actor=current_user, alert=alert)
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# ACKNOWLEDGE
# ============================================================================

@router.post(
    "/{alert_id}/acknowledge",
    response_model=AlertRead,
    summary="Acknowledge an alert",
    description=(
        "Transitions NEW → ACKNOWLEDGED. Acknowledging means 'I've seen "
        "this and I'm aware' — distinct from 'I'm investigating'. "
        "Requires `alert:acknowledge`. Audited."
    ),
)
def acknowledge_alert(
    alert_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.acknowledge(
        db, actor=current_user, alert=alert,
    )
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# INVESTIGATE
# ============================================================================

@router.post(
    "/{alert_id}/investigate",
    response_model=AlertRead,
    summary="Start investigating an alert",
    description=(
        "Transitions to INVESTIGATING. Requires `alert:acknowledge`. "
        "Valid from NEW or ACKNOWLEDGED. Audited."
    ),
)
def investigate_alert(
    alert_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.start_investigation(
        db, actor=current_user, alert=alert,
    )
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# ASSIGN
# ============================================================================

@router.patch(
    "/{alert_id}/assign",
    response_model=AlertRead,
    summary="Assign an alert to an analyst",
    description=(
        "Assigns the alert to an active workspace member for triage. "
        "Requires `incident:assign` in the workspace. The assignee must "
        "be an active member — cross-workspace assignments are rejected. "
        "Audited. The assignee is notified."
    ),
)
def assign_alert(
    alert_id: uuid.UUID,
    body: AlertAssignRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.assign(
        db,
        actor=current_user,
        alert=alert,
        assigned_to_id=body.assigned_to_id,
        notes=body.notes,
    )
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# RESOLVE
# ============================================================================

@router.post(
    "/{alert_id}/resolve",
    response_model=AlertRead,
    summary="Resolve an alert",
    description=(
        "Marks the alert RESOLVED. `resolution_notes` is required — a "
        "resolve without an explanation is refused at schema level "
        "(min_length=1). Requires `alert:acknowledge`. Audited.\n\n"
        "Cannot resolve a DISMISSED or already-RESOLVED alert."
    ),
)
def resolve_alert(
    alert_id: uuid.UUID,
    body: AlertResolveRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.resolve(
        db,
        actor=current_user,
        alert=alert,
        resolution_notes=body.resolution_notes,
    )
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# DISMISS
# ============================================================================

@router.post(
    "/{alert_id}/dismiss",
    response_model=AlertRead,
    summary="Dismiss an alert",
    description=(
        "Marks the alert DISMISSED (not actionable, duplicate, false "
        "positive). `reason` is required — dismissal without a recorded "
        "reason is a red flag in a security platform, so it's enforced "
        "at the schema level. Requires `alert:acknowledge`. Audited."
    ),
)
def dismiss_alert(
    alert_id: uuid.UUID,
    body: AlertDismissRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> AlertRead:
    alert = alert_service.get_by_id(db, alert_id)
    updated = alert_service.dismiss(
        db,
        actor=current_user,
        alert=alert,
        reason=body.reason,
    )
    db.commit()
    return AlertRead.model_validate(updated)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]