"""
CyberGuard AI — Security Incident Schemas
============================================================================

Request/response DTOs for the ``security_incidents`` and
``incident_event_links`` tables.

Incidents are the NIST SP 800-61 lifecycle object at the center of
investigation. An incident aggregates alerts, findings, and events
into a managed workflow:

    open → investigating → containment → eradication → recovery → resolved → closed

Design rules
------------
1. **No public create endpoint.** Incidents are created by
   ``incident_service`` — usually called by ``incident_response_agent``
   when a pattern is confirmed, or by an admin for manual creation.
   The DTO for internal creation is ``IncidentCreateInternal``.

2. **Status transitions are validated.**
   ``IncidentStatusUpdate`` accepts the target status, but the service
   enforces the NIST state machine (e.g. cannot go from OPEN straight
   to ERADICATION). ``IncidentRead.status_history`` preserves every
   transition with attribution.

3. **Containment and recovery actions are separate endpoints.**
   ``POST /incidents/{id}/containment-actions`` and
   ``POST /incidents/{id}/recovery-actions``. This makes post-incident
   review simple — the timeline of what was done is directly
   queryable, not buried in free-form notes.

4. **Resolution requires explicit root cause + summary.**
   ``IncidentResolveRequest`` requires both — an incident cannot be
   marked RESOLVED without explaining what happened and what the fix
   was. Enforced at schema level, not just service level.

5. **Closure captures lessons learned.**
   ``IncidentCloseRequest`` requires ``lessons_learned``. NIST SP
   800-61 phase 4 requires it. Compliance teams read this.

6. **Event links are a separate table.**
   ``IncidentEventLinkRead`` and ``IncidentEventLinkCreate`` support
   the many-to-many relation between incidents and events. Links
   carry ``link_type`` (trigger, related, evidence, ioc_match, timeline)
   and optional ``relevance_score``.

7. **``status_history`` is append-only.**
   Read includes the full history array. Updates append to it — never
   modify prior entries.

8. **``mttr_seconds_finalized`` is exposed separately from
   ``mttr_seconds``.** The finalized value is frozen at closure and
   never recomputed. The live value is computed from timestamps until
   then. Both are returned so clients can render "current" vs
   "historical" correctly.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import (
    EventSeverity,
    FindingCategory,
    IncidentSeverity,
    IncidentStatus,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_TITLE_MAX = 255
_DESCRIPTION_MAX = 10_000
_FINGERPRINT_LENGTH = 64
_SUMMARY_MAX = 10_000
_ROOT_CAUSE_MAX = 10_000
_LESSONS_MAX = 10_000
_ALERT_IDS_MAX = 500
_FINDING_IDS_MAX = 1000
_AFFECTED_ITEMS_MAX = 500
_MITRE_MAX = 50
_TAGS_MAX = 30
_NOTES_MAX = 2000
_ACTION_MAX = 128
_TARGET_MAX = 500
_REASON_MAX = 500

_CONTEXT_MAX_BYTES = 128 * 1024
_STATUS_HISTORY_MAX = 100
_ACTIONS_MAX = 100

_LINK_TYPES = frozenset({
    "trigger", "related", "evidence", "ioc_match", "timeline",
})


# ============================================================================
# INTERNAL CREATE (agent / admin → incident_service)
# ============================================================================

class IncidentCreateInternal(CyberGuardBaseSchema):
    """
    Internal DTO for creating an incident.

    Not used by any public endpoint. Two callers:

        - ``incident_response_agent``: when it detects a pattern that
          crosses the auto-create threshold (severity >= settings
          ``INCIDENT_AUTO_CREATE_SEVERITY_THRESHOLD``).
        - Admin manual creation: through an admin-only endpoint that
          wraps this DTO.

    ``fingerprint`` is computed by the service, not supplied here.
    """

    workspace_id: uuid.UUID = Field(...)
    primary_source_id: uuid.UUID | None = Field(default=None)

    title: str = Field(..., min_length=1, max_length=_TITLE_MAX)
    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)

    severity: IncidentSeverity = Field(...)
    category: FindingCategory = Field(default=FindingCategory.OTHER)

    alert_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=_ALERT_IDS_MAX,
    )
    finding_ids: list[uuid.UUID] = Field(
        default_factory=list, max_length=_FINDING_IDS_MAX,
    )

    affected_devices: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    context: dict[str, Any] = Field(default_factory=dict)

    assigned_to_id: uuid.UUID | None = Field(default=None)
    assigned_by_id: uuid.UUID | None = Field(default=None)

    sla_acknowledge_hours: int | None = Field(default=None, ge=1, le=720)
    sla_resolve_hours: int | None = Field(default=None, ge=1, le=720)

    first_seen_at: datetime | None = Field(
        default=None,
        description="Earliest event_time among contributing alerts. Defaults to now.",
    )

    previous_incident_id: uuid.UUID | None = Field(default=None)

    @field_validator("title")
    @classmethod
    def _clean_title(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @field_validator("context")
    @classmethod
    def _validate_context_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(v, default=str).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"context is not JSON-serializable: {exc}")
        if size > _CONTEXT_MAX_BYTES:
            raise ValueError(
                f"context exceeds {_CONTEXT_MAX_BYTES} bytes (got {size})"
            )
        return v


# ============================================================================
# READ
# ============================================================================

class IncidentRead(TimestampedModel):
    """
    Full incident view. Returned by ``GET /incidents/{id}``.

    Includes the full ``status_history``, ``containment_actions``,
    ``recovery_actions``, and both MTTR values (live and finalized).
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    primary_source_id: uuid.UUID | None = None

    severity: IncidentSeverity
    category: FindingCategory
    status: IncidentStatus

    title: str
    description: str | None = None

    alert_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)

    affected_devices: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    fingerprint: str
    previous_incident_id: uuid.UUID | None = None
    occurrence_count: int = 1

    first_seen_at: datetime
    last_seen_at: datetime
    opened_at: datetime
    acknowledged_at: datetime | None = None
    containment_at: datetime | None = None
    eradication_at: datetime | None = None
    recovery_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None

    sla_acknowledge_hours: int | None = None
    sla_resolve_hours: int | None = None
    expires_at: datetime | None = None

    assigned_to_id: uuid.UUID | None = None
    assigned_at: datetime | None = None
    assigned_by_id: uuid.UUID | None = None

    status_history: list[dict[str, Any]] = Field(default_factory=list)
    containment_actions: list[dict[str, Any]] = Field(default_factory=list)
    recovery_actions: list[dict[str, Any]] = Field(default_factory=list)

    root_cause: str | None = None
    resolution_summary: str | None = None
    lessons_learned: str | None = None
    mttr_seconds_finalized: int | None = None

    legal_hold_until: datetime | None = None

    # Computed
    is_open: bool = Field(..., description="True if not RESOLVED or CLOSED.")
    is_closed: bool = Field(..., description="True if CLOSED.")
    is_assigned: bool = Field(..., description="True if assigned to a user.")
    is_sla_breached: bool = Field(
        ..., description="True if open and past expires_at."
    )
    is_under_legal_hold: bool = Field(
        ..., description="True if legal_hold_until is in the future."
    )
    time_to_acknowledge_seconds: int | None = None
    time_to_resolve_seconds: int | None = None
    mtta_seconds: int | None = Field(
        default=None, description="Mean Time To Acknowledge."
    )
    mttr_seconds: int | None = Field(
        default=None,
        description=(
            "Mean Time To Resolve. Frozen value at closure if closed, "
            "live computation otherwise."
        ),
    )
    age_seconds: int = 0


class IncidentList(ORMModel):
    """
    Lightweight incident view for lists and dashboards.

    Omits ``status_history``, ``containment_actions``,
    ``recovery_actions``, and the full ``context`` JSONB — all of which
    can be large. Fetch ``GET /incidents/{id}`` for full details.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    severity: IncidentSeverity
    category: FindingCategory
    status: IncidentStatus
    title: str
    assigned_to_id: uuid.UUID | None = None
    first_seen_at: datetime
    opened_at: datetime
    closed_at: datetime | None = None
    expires_at: datetime | None = None
    occurrence_count: int = 1
    is_sla_breached: bool = False
    mtta_seconds: int | None = None
    mttr_seconds: int | None = None


# ============================================================================
# UPDATE — STATUS
# ============================================================================

class IncidentStatusUpdate(CyberGuardBaseSchema):
    """
    Request body for ``PATCH /incidents/{id}/status``.

    Service enforces NIST state machine transitions. Notes are recorded
    in ``status_history`` (append-only).
    """

    status: IncidentStatus = Field(
        ...,
        description=(
            "Target status. Allowed transitions enforced by "
            "incident_service.advance_status(). See NIST SP 800-61."
        ),
    )

    notes: str | None = Field(
        default=None, max_length=_NOTES_MAX,
    )


# ============================================================================
# UPDATE — ASSIGNMENT
# ============================================================================

class IncidentAssignRequest(CyberGuardBaseSchema):
    """Request body for ``PATCH /incidents/{id}/assign``."""

    assigned_to_id: uuid.UUID = Field(
        ...,
        description="Analyst to assign. Must be verified (analyst profile VERIFIED).",
    )
    notes: str | None = Field(default=None, max_length=_NOTES_MAX)


# ============================================================================
# RESOLUTION / CLOSURE
# ============================================================================

class IncidentResolveRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /incidents/{id}/resolve``.

    Both ``root_cause`` and ``resolution_summary`` are required — an
    incident cannot be resolved without explaining what happened and
    what was done. This is a compliance requirement.
    """

    root_cause: str = Field(
        ...,
        min_length=1,
        max_length=_ROOT_CAUSE_MAX,
        description="Analyst conclusion about the incident's root cause.",
    )
    resolution_summary: str = Field(
        ...,
        min_length=1,
        max_length=_SUMMARY_MAX,
        description="What was done to resolve the incident.",
    )


class IncidentCloseRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /incidents/{id}/close``.

    Requires ``lessons_learned`` (NIST SP 800-61 phase 4). Compliance
    teams read this; it is not optional.
    """

    lessons_learned: str = Field(
        ...,
        min_length=1,
        max_length=_LESSONS_MAX,
        description="Post-incident review notes for future improvement.",
    )


# ============================================================================
# CONTAINMENT / RECOVERY ACTIONS
# ============================================================================

class IncidentContainmentActionCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /incidents/{id}/containment-actions``.

    Records a containment step (e.g. block IP, isolate device,
    disable account) in the incident's ``containment_actions`` array.
    """

    action: str = Field(
        ...,
        min_length=1,
        max_length=_ACTION_MAX,
        description="What was done, e.g. 'block_ip', 'isolate_device', 'disable_account'.",
    )
    target: str | None = Field(
        default=None,
        max_length=_TARGET_MAX,
        description="What the action was applied to (IP, hostname, username).",
    )
    result: str = Field(
        default="success",
        max_length=32,
        description="Outcome: 'success', 'failed', 'partial', 'skipped'.",
    )
    notes: str | None = Field(default=None, max_length=_NOTES_MAX)


class IncidentRecoveryActionCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /incidents/{id}/recovery-actions``.

    Records a recovery step (e.g. restore backup, rotate credentials,
    re-enable service).
    """

    action: str = Field(..., min_length=1, max_length=_ACTION_MAX)
    target: str | None = Field(default=None, max_length=_TARGET_MAX)
    result: str = Field(default="success", max_length=32)
    notes: str | None = Field(default=None, max_length=_NOTES_MAX)


# ============================================================================
# EVENT LINKS
# ============================================================================

class IncidentEventLinkCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /incidents/{id}/events``.

    Links a specific event to the incident with a type and optional
    relevance score.
    """

    event_id: uuid.UUID = Field(...)

    link_type: str = Field(
        default="related",
        description=(
            "trigger | related | evidence | ioc_match | timeline"
        ),
    )
    relevance_score: float | None = Field(
        default=None, ge=0.0, le=1.0,
    )
    notes: str | None = Field(default=None, max_length=_NOTES_MAX)

    @field_validator("link_type")
    @classmethod
    def _validate_link_type(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _LINK_TYPES:
            raise ValueError(
                f"link_type must be one of {sorted(_LINK_TYPES)}"
            )
        return normalized


class IncidentEventLinkRead(ORMModel):
    """Link record returned by ``GET /incidents/{id}/events``."""

    id: uuid.UUID
    incident_id: uuid.UUID
    event_id: uuid.UUID
    link_type: str
    relevance_score: float | None = None
    notes: str | None = None
    added_by_id: uuid.UUID | None = None
    created_at: datetime


# ============================================================================
# FILTER
# ============================================================================

class IncidentFilter(CyberGuardBaseSchema):
    """Query parameters for filtering ``GET /incidents``."""

    severity: IncidentSeverity | None = None
    min_severity: IncidentSeverity | None = None
    category: FindingCategory | None = None
    status: IncidentStatus | None = None

    assigned_to_id: uuid.UUID | None = None
    unassigned_only: bool | None = None
    primary_source_id: uuid.UUID | None = None

    sla_breached: bool | None = None
    under_legal_hold: bool | None = None

    opened_after: datetime | None = None
    opened_before: datetime | None = None
    closed_after: datetime | None = None
    closed_before: datetime | None = None

    title_contains: str | None = Field(
        default=None, max_length=_TITLE_MAX,
    )

    @field_validator("title_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "IncidentCreateInternal",
    "IncidentRead",
    "IncidentList",
    "IncidentStatusUpdate",
    "IncidentAssignRequest",
    "IncidentResolveRequest",
    "IncidentCloseRequest",
    "IncidentContainmentActionCreate",
    "IncidentRecoveryActionCreate",
    "IncidentEventLinkCreate",
    "IncidentEventLinkRead",
    "IncidentFilter",
]