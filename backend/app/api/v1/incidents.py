"""
CyberGuard AI — Incident Endpoints
============================================================================

The NIST SP 800-61 incident lifecycle, exposed over HTTP.

Twelve endpoints covering the full lifecycle:

    GET    /incidents                              — list with filters
    GET    /incidents/{id}                         — detail + status history
    POST   /incidents                              — admin create
    PATCH  /incidents/{id}/status                  — NIST state transition
    PATCH  /incidents/{id}/assign                  — assign analyst
    POST   /incidents/{id}/resolve                 — close (requires root cause)
    POST   /incidents/{id}/close                   — finalize (requires lessons)
    POST   /incidents/{id}/containment-actions     — record a step
    POST   /incidents/{id}/recovery-actions        — record a step
    GET    /incidents/{id}/events                  — list event links
    POST   /incidents/{id}/events                  — link an event
    DELETE /incidents/{id}/events/{link_id}        — unlink

State machine enforcement
-------------------------
Status transitions are validated by
``incident_service.advance_status`` against the NIST state machine:

    OPEN → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY
                                                    → RESOLVED → CLOSED

With branch paths (fast-triage skips containment, regression reopens).
Invalid transitions return ``409 INCIDENT_INVALID_TRANSITION`` with
the list of allowed next states in the error details.

Route ordering
--------------
No literal-path collisions — every path segment after ``/incidents``
is either ``{incident_id}`` (UUID) or a literal segment that follows
it. No ``/badge``-style endpoint needs to be hoisted.

Incident creation
-----------------
``POST /incidents`` is **admin-initiated manual creation**. The primary
creation path is via ``incident_response_agent`` (Phase I) which calls
``incident_service.create_incident`` directly (in-process). This
endpoint exists for:
    - Testing incident workflows before the agent lands
    - Admin override — e.g. creating an incident from external intel
    - Backfilling incidents from pre-platform data

Requires ``incident:create`` permission (granted to workspace EDITOR+
and any role that includes ``_WRITE``). Creation without evidence
(no alerts/findings) is rejected at the service level — an incident
must aggregate something.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
    require_permission,
)
from app.core.exceptions import (
    IncidentNotFoundError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.models.incident import IncidentEventLink
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.incident import (
    IncidentAssignRequest,
    IncidentCloseRequest,
    IncidentContainmentActionCreate,
    IncidentCreateInternal,
    IncidentEventLinkCreate,
    IncidentEventLinkRead,
    IncidentFilter,
    IncidentList,
    IncidentRead,
    IncidentRecoveryActionCreate,
    IncidentResolveRequest,
    IncidentStatusUpdate,
)
from app.services import (
    authorization,
    incident_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/incidents",
    tags=["incidents"],
)


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[IncidentList],
    summary="List incidents",
    description=(
        "Paginated list of incidents across the user's accessible "
        "workspaces. Requires `incident:read` permission.\n\n"
        "Returns lightweight `IncidentList` rows. Fetch "
        "`GET /incidents/{id}` for the full incident including "
        "`status_history`, `containment_actions`, and "
        "`recovery_actions`."
    ),
)
def list_incidents(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: IncidentFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[IncidentList]:
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "incident:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            return PaginatedResponse[IncidentList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    incidents, total = incident_service.list_incidents(
        db,
        workspace_ids=workspace_ids,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[IncidentList](
        items=[IncidentList.model_validate(i) for i in incidents],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Get an incident by ID",
    description=(
        "Full incident view including `status_history` (append-only "
        "transitions), `containment_actions`, `recovery_actions`, and "
        "computed MTTA/MTTR. Requires `incident:read` on the incident's "
        "workspace."
    ),
)
def get_incident(
    incident_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:read",
        workspace_id=incident.workspace_id,
    )

    return IncidentRead.model_validate(incident)


# ============================================================================
# CREATE (admin-initiated)
# ============================================================================

@router.post(
    "",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an incident manually",
    description=(
        "Admin-initiated incident creation. The primary creation path "
        "is via `incident_response_agent` (Phase I) — this endpoint is "
        "for admin override, testing, or backfilling external intel.\n\n"
        "Requires `incident:create` permission. The DTO must include at "
        "least one alert or finding — an incident without evidence is "
        "rejected at the service level.\n\n"
        "If an active incident with the same pattern exists, the DTO is "
        "**merged** into it (occurrence_count++, alert/finding IDs "
        "unioned). Only creates a new row when no matching active "
        "incident exists."
    ),
)
def create_incident(
    body: IncidentCreateInternal,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    # Ensure assigned_by_id is set when the admin pre-assigns
    if body.assigned_to_id is not None and body.assigned_by_id is None:
        body = body.model_copy(update={"assigned_by_id": current_user.id})

    # Workspace permission check
    authorization.check_permission(
        db, current_user, "incident:create",
        workspace_id=body.workspace_id,
    )

    incident = incident_service.create_incident(
        db, dto=body, actor=current_user,
    )
    db.commit()

    logger.info(
        "Incident created via API (manual)",
        extra={
            "incident_id": str(incident.id),
            "workspace_id": str(incident.workspace_id),
            "actor_id": str(current_user.id),
        },
    )

    return IncidentRead.model_validate(incident)


# ============================================================================
# STATUS TRANSITION
# ============================================================================

@router.patch(
    "/{incident_id}/status",
    response_model=IncidentRead,
    summary="Advance an incident's NIST lifecycle status",
    description=(
        "Transitions the incident through the NIST SP 800-61 state "
        "machine. See the module docstring for the full state diagram.\n\n"
        "The phase timestamp (containment_at, eradication_at, etc.) is "
        "set automatically by the service. Every transition is audited "
        "with before/after state, actor, and optional notes."
    ),
    responses={
        200: {"description": "Status updated."},
        403: {"description": "Permission denied (incident:update required)."},
        404: {"description": "Incident not found."},
        409: {"description": "Invalid state transition."},
    },
)
def advance_incident_status(
    incident_id: uuid.UUID,
    body: IncidentStatusUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:update",
        workspace_id=incident.workspace_id,
    )

    updated = incident_service.advance_status(
        db,
        actor=current_user,
        incident=incident,
        new_status=body.status,
        notes=body.notes,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


# ============================================================================
# ASSIGN
# ============================================================================

@router.patch(
    "/{incident_id}/assign",
    response_model=IncidentRead,
    summary="Assign an incident to an analyst",
    description=(
        "Assigns the incident to an active workspace member. Requires "
        "`incident:assign`. The assignee is notified via the "
        "notification system."
    ),
)
def assign_incident(
    incident_id: uuid.UUID,
    body: IncidentAssignRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)
    updated = incident_service.assign(
        db,
        actor=current_user,
        incident=incident,
        assigned_to_id=body.assigned_to_id,
        notes=body.notes,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


# ============================================================================
# RESOLVE
# ============================================================================

@router.post(
    "/{incident_id}/resolve",
    response_model=IncidentRead,
    summary="Resolve an incident",
    description=(
        "Marks the incident RESOLVED. Both `root_cause` and "
        "`resolution_summary` are **required** — enforced at schema "
        "level and again at service level (compliance requirement).\n\n"
        "The incident must be in a resolvable state (INVESTIGATING, "
        "CONTAINMENT, ERADICATION, or RECOVERY). Cannot resolve from "
        "OPEN directly."
    ),
)
def resolve_incident(
    incident_id: uuid.UUID,
    body: IncidentResolveRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)
    updated = incident_service.resolve(
        db,
        actor=current_user,
        incident=incident,
        root_cause=body.root_cause,
        resolution_summary=body.resolution_summary,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


# ============================================================================
# CLOSE
# ============================================================================

@router.post(
    "/{incident_id}/close",
    response_model=IncidentRead,
    summary="Close a resolved incident",
    description=(
        "Finalizes the incident. `lessons_learned` is **required** "
        "(NIST SP 800-61 phase 4 compliance). The incident must already "
        "be in RESOLVED status. Freezes `mttr_seconds_finalized`."
    ),
)
def close_incident(
    incident_id: uuid.UUID,
    body: IncidentCloseRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)
    updated = incident_service.close(
        db,
        actor=current_user,
        incident=incident,
        lessons_learned=body.lessons_learned,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


# ============================================================================
# CONTAINMENT / RECOVERY ACTIONS
# ============================================================================

@router.post(
    "/{incident_id}/containment-actions",
    response_model=IncidentRead,
    summary="Record a containment action",
    description=(
        "Appends a containment step to the incident's "
        "`containment_actions` array. Examples: `block_ip`, "
        "`isolate_device`, `disable_account`.\n\n"
        "Audited — containment actions are security-relevant and "
        "reviewed by compliance teams."
    ),
)
def record_containment_action(
    incident_id: uuid.UUID,
    body: IncidentContainmentActionCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:update",
        workspace_id=incident.workspace_id,
    )

    updated = incident_service.record_containment_action(
        db,
        actor=current_user,
        incident=incident,
        action=body.action,
        target=body.target,
        result=body.result,
        notes=body.notes,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


@router.post(
    "/{incident_id}/recovery-actions",
    response_model=IncidentRead,
    summary="Record a recovery action",
    description=(
        "Appends a recovery step to the incident's `recovery_actions` "
        "array. Examples: `restore_backup`, `rotate_credentials`, "
        "`re_enable_service`.\n\n"
        "Audited."
    ),
)
def record_recovery_action(
    incident_id: uuid.UUID,
    body: IncidentRecoveryActionCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentRead:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:update",
        workspace_id=incident.workspace_id,
    )

    updated = incident_service.record_recovery_action(
        db,
        actor=current_user,
        incident=incident,
        action=body.action,
        target=body.target,
        result=body.result,
        notes=body.notes,
    )
    db.commit()
    return IncidentRead.model_validate(updated)


# ============================================================================
# EVENT LINKS
# ============================================================================

@router.get(
    "/{incident_id}/events",
    response_model=list[IncidentEventLinkRead],
    summary="List events linked to an incident",
    description=(
        "Returns all `IncidentEventLink` rows for this incident — the "
        "typed, scored links between the incident and specific events "
        "(trigger, related, evidence, ioc_match, timeline)."
    ),
)
def list_incident_events(
    incident_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> list[IncidentEventLinkRead]:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:read",
        workspace_id=incident.workspace_id,
    )

    links = list(db.execute(
        select(IncidentEventLink)
        .where(IncidentEventLink.incident_id == incident.id)
        .order_by(IncidentEventLink.created_at.asc())
    ).scalars().all())

    return [IncidentEventLinkRead.model_validate(link) for link in links]


@router.post(
    "/{incident_id}/events",
    response_model=IncidentEventLinkRead,
    status_code=status.HTTP_201_CREATED,
    summary="Link an event to an incident",
    description=(
        "Associates a specific event with the incident. Idempotent by "
        "`(incident, event, link_type)` — re-linking the same triplet "
        "returns the existing link. The event must be in the same "
        "workspace as the incident (cross-workspace links rejected)."
    ),
)
def link_incident_event(
    incident_id: uuid.UUID,
    body: IncidentEventLinkCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> IncidentEventLinkRead:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:update",
        workspace_id=incident.workspace_id,
    )

    link = incident_service.link_event(
        db,
        actor=current_user,
        incident=incident,
        event_id=body.event_id,
        link_type=body.link_type,
        relevance_score=body.relevance_score,
        notes=body.notes,
    )
    db.commit()
    return IncidentEventLinkRead.model_validate(link)


@router.delete(
    "/{incident_id}/events/{link_id}",
    response_model=MessageResponse,
    summary="Unlink an event from an incident",
    description=(
        "Removes the event link. Idempotent (deleting a nonexistent "
        "link returns 404)."
    ),
)
def unlink_incident_event(
    incident_id: uuid.UUID,
    link_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageResponse:
    incident = incident_service.get_by_id(db, incident_id)

    authorization.check_permission(
        db, current_user, "incident:update",
        workspace_id=incident.workspace_id,
    )

    link = db.get(IncidentEventLink, link_id)
    if link is None or link.incident_id != incident.id:
        raise NotFoundError(
            message="Event link not found.",
            code="INCIDENT_EVENT_LINK_NOT_FOUND",
        )

    incident_service.unlink_event(db, actor=current_user, link=link)
    db.commit()
    return MessageResponse(message="Event unlinked.")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]