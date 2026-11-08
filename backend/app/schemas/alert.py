"""
CyberGuard AI — Security Alert Schemas
============================================================================

Request/response DTOs for the ``security_alerts`` table.

Alerts are the user-facing layer promoted from findings. Users see
alerts, acknowledge them, dismiss them, or assign them. They never
interact with findings directly (findings are internal agent output).

Design rules
------------
1. **No public create endpoint.** Alerts are created by
   ``alert_service.promote_finding()`` when a finding crosses the
   severity / confidence threshold. Users cannot create alerts
   manually — that would be finding-creation, which is agent-only.

2. **``fingerprint`` is server-computed.** Never accepted from clients.
   ``alert_service`` computes it from (workspace, category, severity,
   scope) to enable pattern-level deduplication.

3. **Status transitions are validated.**
   ``AlertStatusUpdate`` allows setting an explicit status, but the
   service enforces the transition rules (e.g. cannot go from RESOLVED
   back to NEW). Notes are recorded in the audit log, not on the alert.

4. **``assigned_to_id`` uses a dedicated endpoint.**
   ``AlertAssignRequest`` is separate from ``AlertStatusUpdate`` so
   the audit log records assignment actions distinctly from status
   actions. Two different permissions gate them.

5. **Recommendation actions are a structured list.**
   The agent produces ``recommended_actions`` as a list of
   ``{action, target, priority}`` objects. Clients render them as
   one-click buttons.

6. **Read vs List schemas differ on payload size.**
   ``AlertRead`` includes ``context``, ``recommended_actions``,
   ``finding_ids`` — all expensive. ``AlertList`` omits them.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import (
    AlertStatus,
    EventSeverity,
    FindingCategory,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_ALERT_TYPES = frozenset({
    "security", "operational", "compliance", "system",
})

_TITLE_MAX = 255
_DESCRIPTION_MAX = 5000
_FINGERPRINT_LENGTH = 64
_FINDING_IDS_MAX = 500
_RECOMMENDED_ACTIONS_MAX = 10
_MITRE_MAX = 50
_NOTES_MAX = 2000
_REASON_MAX = 500

_CONTEXT_MAX_BYTES = 64 * 1024


# ============================================================================
# READ
# ============================================================================

class AlertRead(TimestampedModel):
    """
    Full alert view. Returned by ``GET /alerts/{id}``.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    source_id: uuid.UUID | None = None

    alert_type: str
    severity: EventSeverity
    category: FindingCategory
    status: AlertStatus

    title: str
    description: str | None = None

    finding_ids: list[str] = Field(
        default_factory=list,
        description="Finding UUIDs aggregated into this alert (as strings).",
    )
    finding_count: int = 0

    fingerprint: str
    previous_alert_id: uuid.UUID | None = None

    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int = 1
    expires_at: datetime | None = None

    resolved_at: datetime | None = None
    resolved_by_id: uuid.UUID | None = None
    resolution_notes: str | None = None

    assigned_to_id: uuid.UUID | None = None
    assigned_at: datetime | None = None

    seen_at: datetime | None = None
    acknowledged_at: datetime | None = None

    notification_sent: bool = False
    notification_channels_sent: list[str] = Field(default_factory=list)
    notification_attempts: int = 0

    context: dict[str, Any] = Field(default_factory=dict)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    incident_id: uuid.UUID | None = None

    # Computed
    is_open: bool = Field(..., description="True if in NEW/ACKNOWLEDGED/INVESTIGATING.")
    is_closed: bool = Field(..., description="True if RESOLVED or DISMISSED.")
    is_assigned: bool = Field(..., description="True if assigned to a user.")
    is_promoted_to_incident: bool = Field(..., description="True if linked to an incident.")
    is_sla_breached: bool = Field(
        ..., description="True if open and past expires_at."
    )
    sla_remaining_seconds: int | None = Field(
        default=None,
        description="Seconds until SLA expiry; negative if breached. None if no SLA.",
    )


class AlertList(ORMModel):
    """
    Lightweight alert view for dashboard lists.

    Omits ``context``, ``recommended_actions``, ``finding_ids`` (which
    can each be 10s of KB), keeping responses small for lists of 25+
    alerts. Fetch ``GET /alerts/{id}`` for full details.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    alert_type: str
    severity: EventSeverity
    category: FindingCategory
    status: AlertStatus
    title: str
    finding_count: int = 0
    occurrence_count: int = 1
    first_seen_at: datetime
    last_seen_at: datetime
    assigned_to_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    notification_sent: bool = False
    is_sla_breached: bool = False


# ============================================================================
# UPDATE — STATUS
# ============================================================================

class AlertStatusUpdate(CyberGuardBaseSchema):
    """
    Request body for ``PATCH /alerts/{id}/status``.

    Status transitions are validated by ``alert_service`` — not all
    target statuses are valid from all current statuses.
    """

    status: AlertStatus = Field(
        ...,
        description=(
            "Target status. Allowed transitions depend on the current "
            "status — see alert_service.advance_status()."
        ),
    )

    notes: str | None = Field(
        default=None,
        max_length=_NOTES_MAX,
        description=(
            "Optional notes explaining the transition. Recorded in the "
            "audit log, not on the alert row itself."
        ),
    )

    @field_validator("notes")
    @classmethod
    def _clean_notes(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# UPDATE — ASSIGNMENT
# ============================================================================

class AlertAssignRequest(CyberGuardBaseSchema):
    """
    Request body for ``PATCH /alerts/{id}/assign``.

    Separated from status updates so audit logs distinguish
    assignment actions. Requires ``alert:acknowledge`` permission.
    """

    assigned_to_id: uuid.UUID = Field(
        ...,
        description="User to assign the alert to. Must be an active member of the workspace.",
    )

    notes: str | None = Field(
        default=None,
        max_length=_NOTES_MAX,
    )


# ============================================================================
# UPDATE — RESOLVE / DISMISS
# ============================================================================

class AlertResolveRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /alerts/{id}/resolve``.

    Marks the alert RESOLVED with mandatory resolution notes. Distinct
    from dismiss — RESOLVED means "we investigated and addressed it",
    DISMISSED means "not actionable".
    """

    resolution_notes: str = Field(
        ...,
        min_length=1,
        max_length=_NOTES_MAX,
        description="What was done to resolve the alert.",
    )


class AlertDismissRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /alerts/{id}/dismiss``.

    Marks the alert DISMISSED. Reason is required — dismissal without
    a recorded reason is a red flag in a security platform.
    """

    reason: str = Field(
        ...,
        min_length=1,
        max_length=_REASON_MAX,
        description="Why the alert is being dismissed (not actionable, duplicate, etc.).",
    )


# ============================================================================
# FILTER
# ============================================================================

class AlertFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /alerts``.
    """

    alert_type: str | None = Field(
        default=None,
        description="security | operational | compliance | system",
    )

    severity: EventSeverity | None = None
    min_severity: EventSeverity | None = None
    category: FindingCategory | None = None
    status: AlertStatus | None = None

    assigned_to_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to alerts assigned to a specific user.",
    )
    unassigned_only: bool | None = Field(
        default=None,
        description="If True, only alerts with no assignee.",
    )

    source_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None

    has_incident: bool | None = Field(
        default=None,
        description="If True, only promoted-to-incident alerts; False, only standalone.",
    )

    sla_breached: bool | None = Field(
        default=None,
        description="If True, only SLA-breached open alerts; False, only within SLA.",
    )

    first_seen_after: datetime | None = None
    first_seen_before: datetime | None = None

    title_contains: str | None = Field(
        default=None,
        max_length=_TITLE_MAX,
        description="Case-insensitive substring match on title.",
    )

    @field_validator("alert_type")
    @classmethod
    def _validate_alert_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _ALERT_TYPES:
            raise ValueError(
                f"alert_type must be one of {sorted(_ALERT_TYPES)}"
            )
        return normalized

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
    "AlertRead",
    "AlertList",
    "AlertStatusUpdate",
    "AlertAssignRequest",
    "AlertResolveRequest",
    "AlertDismissRequest",
    "AlertFilter",
]