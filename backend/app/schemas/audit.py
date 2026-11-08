"""
CyberGuard AI — Audit Log Schemas
============================================================================

Request/response DTOs for the ``security_audit_logs`` table.

The audit log is the append-only, immutable record of every sensitive
action in the platform. It has **no public create endpoint** — audit
rows are written exclusively by ``audit_service.log_*()`` from within
the same transaction as the action they record.

Design rules
------------
1. **Read-only via API.**
   The only endpoint that touches this table is ``GET /admin/audit``
   (admin-only, requires ``admin:audit_read`` permission). There is
   no create, update, or delete endpoint. The retention job is the
   only writer that removes rows (after ``RETENTION_AUDIT_LOGS_DAYS``
   unless under legal hold).

2. **``actor_email`` is the survivor field.**
   Even if the actor user is hard-deleted, the audit row still
   identifies who did the action via the denormalized email. Clients
   querying history years later see the email even when ``actor_id``
   is NULL.

3. **``impersonated_by_id`` tracks super-admin actions.**
   When a super admin acts on behalf of another user (support
   scenarios), the effective actor is ``actor_id`` and the true
   initiator is ``impersonated_by_id``. Both are exposed. Audit
   reviewers rely on this to distinguish "the user did it" from "the
   user's account was accessed by an admin".

4. **State changes capture before/after snapshots.**
   ``AuditLogRead`` exposes ``before_state`` and ``after_state`` as
   JSONB, plus ``changed_fields`` (the diff of keys whose values
   changed). Clients rendering audit detail pages use these to show
   exactly what mutated.

5. **``correlation_id`` links audit to HTTP logs.**
   Every audit row carries the correlation ID from the request that
   caused it. Joining ``security_audit_logs.correlation_id`` with
   application logs produces a complete trace: request → auth →
   authorization → DB write → audit → response.

6. **``is_recognized_action`` exposes canonical-list membership.**
   The action field accepts any non-empty string (so new code paths
   don't fail to write audit rows). But the read schema includes a
   computed ``is_recognized_action`` flag — true if the action is in
   ``app.core.constants.AUDIT_ACTIONS``. Unknown actions are visible
   to admins (potential security review signal) without breaking
   writes.

7. **Internal creation is not in this file.**
   The DTO used by ``audit_service`` to write rows lives in the
   service module itself (``AuditEventInternal``). Keeping the
   internal type near its writer reduces coupling and avoids exposing
   an unused "create" schema to consumers.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.core.constants import AUDIT_ACTIONS
from app.models.enums import AuditOutcome
from app.schemas.common import ORMModel


# ─── Constants ─────────────────────────────────────────────────────────────
_ACTOR_TYPES = frozenset({"user", "collector", "system", "agent"})

_TARGET_TYPES = frozenset({
    "user", "organization", "workspace", "membership",
    "analyst_profile", "source", "source_credential",
    "collector_credential", "enrollment", "event", "finding",
    "alert", "incident", "case", "case_assignment",
    "case_access_grant", "evidence", "conversation", "message",
    "notification", "report", "invitation", "service_offering",
    "service_purchase", "payment_transaction",
    "workspace_membership", "audit_log",
})

_ACTION_MAX = 128
_EMAIL_MAX = 320
_IP_MAX = 45
_USER_AGENT_MAX = 512
_REQUEST_METHOD_MAX = 16
_REQUEST_PATH_MAX = 2048
_CORRELATION_ID_MAX = 128
_NOTES_MAX = 5000


# ============================================================================
# READ
# ============================================================================

class AuditLogRead(ORMModel):
    """
    Full audit log entry. Returned by ``GET /admin/audit/{id}`` and
    list endpoints.

    Note the absence of ``updated_at`` and ``deleted_at`` — audit rows
    are append-only. The only mutation is a super-admin legal-hold
    flag (which itself produces a *new* audit row).
    """

    id: uuid.UUID
    created_at: datetime

    # ── Actor ────────────────────────────────────────────────────────
    actor_id: uuid.UUID | None = None
    actor_email: str | None = None
    actor_type: str
    impersonated_by_id: uuid.UUID | None = None

    # ── Action ───────────────────────────────────────────────────────
    action: str
    outcome: AuditOutcome

    # ── Target ───────────────────────────────────────────────────────
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    target_display: str | None = None

    # ── Tenant scope ─────────────────────────────────────────────────
    workspace_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None

    # ── Request context ──────────────────────────────────────────────
    ip_address: str | None = None
    user_agent: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    correlation_id: str | None = None

    # ── State change ─────────────────────────────────────────────────
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    changed_fields: list[str] = Field(default_factory=list)

    # ── Free-form ────────────────────────────────────────────────────
    notes: str | None = None
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # ── Legal hold ───────────────────────────────────────────────────
    legal_hold_until: datetime | None = None

    # Computed
    is_under_legal_hold: bool = Field(
        ...,
        description="True if legal_hold_until is in the future.",
    )
    is_success: bool = Field(
        ..., description="True if outcome is SUCCESS.",
    )
    is_failure: bool = Field(
        ..., description="True if outcome is FAILURE.",
    )
    has_state_change: bool = Field(
        ...,
        description=(
            "True if the entry recorded before_state and after_state "
            "(i.e. it represents a mutation, not a read)."
        ),
    )
    has_target: bool = Field(
        ..., description="True if target_type and target_id are both set.",
    )
    was_impersonated: bool = Field(
        ...,
        description=(
            "True if impersonated_by_id is set — a super admin "
            "performed this action on behalf of actor_id."
        ),
    )
    is_recognized_action: bool = Field(
        ...,
        description=(
            "True if action is in the canonical AUDIT_ACTIONS list. "
            "False indicates a new code path that wrote an unrecognized "
            "action — worth a security review."
        ),
    )


class AuditLogList(ORMModel):
    """
    Lightweight audit log view for the admin audit list.

    Omits ``before_state``, ``after_state``, ``metadata_json``, and
    ``user_agent`` — which can each be large and aren't needed for
    scanning the list. Fetch ``GET /admin/audit/{id}`` for full
    details including the state delta.
    """

    id: uuid.UUID
    created_at: datetime
    actor_id: uuid.UUID | None = None
    actor_email: str | None = None
    actor_type: str
    action: str
    outcome: AuditOutcome
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    target_display: str | None = None
    workspace_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None
    ip_address: str | None = None
    correlation_id: str | None = None
    is_recognized_action: bool = True


# ============================================================================
# FILTER
# ============================================================================

class AuditLogFilter(ORMModel):
    """
    Query parameters for filtering ``GET /admin/audit``.

    Audit queries are admin-only and can return large volumes — every
    filter clause is important. The service enforces a required time
    range to prevent accidental "give me every audit row ever" queries.
    """

    actor_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to actions by this user.",
    )
    actor_email: str | None = Field(
        default=None,
        max_length=_EMAIL_MAX,
        description="Exact match on actor_email (case-insensitive).",
    )
    actor_type: str | None = Field(
        default=None,
        description="user | collector | system | agent",
    )

    action: str | None = Field(
        default=None,
        max_length=_ACTION_MAX,
        description="Exact match on action (e.g. 'case.assigned').",
    )
    action_prefix: str | None = Field(
        default=None,
        max_length=_ACTION_MAX,
        description=(
            "Prefix match on action — e.g. 'case.' returns all "
            "case-related actions. Faster than substring match."
        ),
    )

    outcome: AuditOutcome | None = None

    target_type: str | None = Field(
        default=None,
        description="Filter to actions on this entity type.",
    )
    target_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to actions on this specific entity.",
    )

    workspace_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None

    correlation_id: str | None = Field(
        default=None,
        max_length=_CORRELATION_ID_MAX,
        description="Filter to actions from this specific request trace.",
    )

    created_after: datetime | None = Field(
        default=None,
        description=(
            "Only entries at or after this timestamp. Strongly recommended "
            "— audit queries without a time bound can scan years of rows."
        ),
    )
    created_before: datetime | None = Field(
        default=None,
        description="Only entries at or before this timestamp.",
    )

    unrecognized_only: bool | None = Field(
        default=None,
        description=(
            "If True, only actions not in the canonical AUDIT_ACTIONS "
            "list. Useful for detecting unauthorized code paths."
        ),
    )

    under_legal_hold: bool | None = Field(
        default=None,
        description="If True, only rows with active legal holds.",
    )

    @field_validator("actor_type")
    @classmethod
    def _validate_actor_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _ACTOR_TYPES:
            raise ValueError(
                f"actor_type must be one of {sorted(_ACTOR_TYPES)}"
            )
        return normalized

    @field_validator("target_type")
    @classmethod
    def _validate_target_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _TARGET_TYPES:
            raise ValueError(
                f"target_type must be one of {sorted(_TARGET_TYPES)}"
            )
        return normalized

    @field_validator("created_before")
    @classmethod
    def _validate_range(cls, v: datetime | None, info) -> datetime | None:
        if v is None:
            return None
        after = info.data.get("created_after")
        if after is not None and v < after:
            raise ValueError("created_before must be >= created_after")
        return v


# ============================================================================
# STATS / SUMMARY
# ============================================================================

class AuditLogStats(ORMModel):
    """
    Aggregate stats returned by ``GET /admin/audit/stats``.

    Provides operators a fast, pre-aggregated view of audit activity
    without requiring them to page through raw rows. All counts are
    scoped to the same filter as the request.
    """

    total_entries: int = Field(..., ge=0)

    by_actor_type: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by actor_type (user, collector, system, agent).",
    )
    by_outcome: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by outcome (success, failure, partial).",
    )
    by_action_top: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Top actions as [{action, count}], sorted descending. "
            "Useful for spotting unusual activity spikes."
        ),
    )

    failure_count: int = Field(..., ge=0)
    unrecognized_action_count: int = Field(..., ge=0)

    earliest_created_at: datetime | None = None
    latest_created_at: datetime | None = None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AuditLogRead",
    "AuditLogList",
    "AuditLogFilter",
    "AuditLogStats",
]