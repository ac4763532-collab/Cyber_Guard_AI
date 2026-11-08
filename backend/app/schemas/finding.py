"""
CyberGuard AI — Agent Finding Schemas
============================================================================

Request/response DTOs for the ``agent_findings`` table.

Findings are produced by the platform's detection agents, not by
clients. There is no HTTP endpoint that accepts a raw finding from an
external caller — findings come from ``finding_service.create_finding``
or similar internal calls. The schemas here cover:

    - Reading findings via the API (``FindingRead``, ``FindingList``)
    - Filtering findings (``FindingFilter``)
    - Status transitions (``FindingStatusUpdate``)
    - The internal DTO used by agent code (``FindingCreateInternal``)

Design rules
------------
1. **No public create endpoint.** Findings are produced by agents
   (via the internal ``FindingCreateInternal`` DTO passed to
   ``finding_service``). If a future requirement needs manual finding
   creation, it will be admin-only and audited — not a public endpoint.

2. **``fingerprint`` is server-computed.** Never accepted from clients
   or agents as raw input. ``event_fingerprint`` (service) computes it
   deterministically.

3. **``agent_name`` and ``rule_id`` are validated at schema level**
   for the internal create path. ``agent_name`` must be one of the 8
   known agent identifiers (from ``app.core.constants.AGENT_NAMES``).
   ``rule_id`` is free-form but length-bounded.

4. **``status`` is not client-settable via PATCH.**
   Status changes go through ``FindingStatusUpdate`` with a validated
   transition, or through ``finding_service`` lifecycle methods.
   Prevents "jump to RESOLVED" from any state.

5. **Confidence and severity are orthogonal.**
   Both must be present. ``confidence`` is a float in [0.0, 1.0].
   ``severity`` is an enum. Collapsing them into one score would hide
   information from investigators.

6. **``evidence`` JSONB is free-form but size-capped.**
   Shape validated by convention (rule_params, matched_count, etc.)
   but the exact keys differ per rule. Size cap prevents accidental
   bloat.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.core.constants import AGENT_NAMES
from app.models.enums import (
    EventSeverity,
    FindingCategory,
    FindingStatus,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_AGENT_NAME_MAX = 32
_RULE_ID_MAX = 128
_TITLE_MAX = 255
_DESCRIPTION_MAX = 5000
_FINGERPRINT_LENGTH = 64
_MITRE_MAX = 20
_EVENT_IDS_MAX = 1000
_TAGS_MAX = 20

_EVIDENCE_MAX_BYTES = 256 * 1024

#: Valid finding categories (mirrors enum, for schema hints).
_KNOWN_CATEGORIES = frozenset(
    c.value for c in FindingCategory
)


# ============================================================================
# INTERNAL CREATE (agents → finding_service)
# ============================================================================

class FindingCreateInternal(CyberGuardBaseSchema):
    """
    Internal DTO for agent → finding_service.

    Not used by any HTTP endpoint. Agents construct this to describe a
    finding, then call ``finding_service.create_finding(db, dto)`` which
    computes the fingerprint, deduplicates, and persists.

    ``fingerprint`` is **not** a field here — the service computes it.
    Agents that know a stable identifier for their reasoning can pass
    it as ``dedup_hint``, which the service incorporates into the
    fingerprint computation.
    """

    workspace_id: uuid.UUID = Field(...)
    source_id: uuid.UUID | None = Field(default=None)

    agent_name: str = Field(
        ...,
        max_length=_AGENT_NAME_MAX,
        description=(
            "One of: " + ", ".join(sorted(AGENT_NAMES))
        ),
    )
    rule_id: str = Field(
        ...,
        min_length=1,
        max_length=_RULE_ID_MAX,
        description="Identifier of the detection rule that fired.",
    )

    severity: EventSeverity = Field(...)
    category: FindingCategory = Field(default=FindingCategory.OTHER)
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "How confident the agent is that this is a true positive. "
            "Distinct from severity: a rule can be very confident about "
            "a low-severity event, or uncertain about a possible critical one."
        ),
    )

    title: str = Field(..., min_length=1, max_length=_TITLE_MAX)
    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)

    primary_event_id: uuid.UUID | None = Field(default=None)
    event_ids: list[uuid.UUID] = Field(
        default_factory=list,
        max_length=_EVENT_IDS_MAX,
    )

    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    dedup_hint: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Optional stable identifier incorporated into the fingerprint. "
            "Used when the agent has a natural grouping key (e.g. the "
            "specific attacker IP for a repeated-failed-logins rule). "
            "Deterministic + rule_id + event_ids alone may not dedupe "
            "correctly when the rule aggregates rolling windows."
        ),
    )

    @field_validator("agent_name")
    @classmethod
    def _validate_agent_name(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in AGENT_NAMES:
            raise ValueError(
                f"agent_name must be one of {sorted(AGENT_NAMES)}"
            )
        return normalized

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("rule_id must not be empty")
        return stripped

    @field_validator("title")
    @classmethod
    def _clean_title(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @field_validator("event_ids")
    @classmethod
    def _dedupe_event_ids(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        # Preserve order, drop duplicates.
        seen: set[uuid.UUID] = set()
        cleaned: list[uuid.UUID] = []
        for item in v:
            if item not in seen:
                seen.add(item)
                cleaned.append(item)
        return cleaned

    @field_validator("evidence")
    @classmethod
    def _validate_evidence_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(v, default=str).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"evidence is not JSON-serializable: {exc}")
        if size > _EVIDENCE_MAX_BYTES:
            raise ValueError(
                f"evidence exceeds {_EVIDENCE_MAX_BYTES} bytes (got {size})"
            )
        return v

    @field_validator("mitre_techniques")
    @classmethod
    def _validate_mitre(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each MITRE technique must be a string")
            normalized = item.strip().upper()
            if not normalized or normalized in seen:
                continue
            if len(normalized) > 32:
                raise ValueError(
                    "each MITRE technique ID must not exceed 32 characters"
                )
            seen.add(normalized)
            cleaned.append(normalized)
        if len(cleaned) > _MITRE_MAX:
            raise ValueError(
                f"mitre_techniques must not exceed {_MITRE_MAX} items"
            )
        return cleaned


# ============================================================================
# READ
# ============================================================================

class FindingRead(TimestampedModel):
    """
    Full finding view. Returned by ``GET /findings/{id}``.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    source_id: uuid.UUID | None = None

    agent_name: str
    rule_id: str

    severity: EventSeverity
    category: FindingCategory
    confidence: float
    status: FindingStatus

    title: str
    description: str | None = None

    primary_event_id: uuid.UUID | None = None
    event_ids: list[str] = Field(
        default_factory=list,
        description="Event UUIDs this finding references (as strings).",
    )
    occurrence_count: int = 1
    first_seen_at: datetime
    last_seen_at: datetime

    fingerprint: str

    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    alert_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None

    # Computed
    is_open: bool = Field(
        ..., description="True if in NEW/ACKNOWLEDGED/INVESTIGATING."
    )
    is_closed: bool = Field(
        ..., description="True if RESOLVED/DISMISSED/FALSE_POSITIVE."
    )
    is_promoted_to_alert: bool = Field(
        ..., description="True if linked to an alert."
    )
    is_linked_to_incident: bool = Field(
        ..., description="True if swept into an incident."
    )
    is_high_or_critical: bool = Field(
        ..., description="True if severity is HIGH or CRITICAL."
    )


class FindingList(ORMModel):
    """
    Lightweight finding view for lists and dashboards.

    Omits ``evidence`` (which can be up to 256 KB) and ``event_ids``
    (which can be up to 1000 UUIDs). Fetch ``GET /findings/{id}`` for
    full details.
    """

    id: uuid.UUID
    agent_name: str
    rule_id: str
    severity: EventSeverity
    category: FindingCategory
    confidence: float
    status: FindingStatus
    title: str
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_high_or_critical: bool = False


# ============================================================================
# UPDATE
# ============================================================================

class FindingStatusUpdate(CyberGuardBaseSchema):
    """
    Request body for ``PATCH /findings/{id}/status``.

    Only the status field is settable through this endpoint. The
    service validates the transition against the finding's current
    state (e.g. cannot go from RESOLVED back to NEW). Notes are
    recorded but not part of the finding itself — they go to the
    audit log.
    """

    status: FindingStatus = Field(
        ...,
        description=(
            "Target status. Allowed transitions depend on current status "
            "— see finding_service.advance_status()."
        ),
    )

    notes: str | None = Field(
        default=None,
        max_length=2000,
        description=(
            "Optional notes explaining the transition. Recorded in the "
            "audit log, not on the finding row itself."
        ),
    )


# ============================================================================
# FILTER
# ============================================================================

class FindingFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /findings``.
    """

    agent_name: str | None = Field(
        default=None,
        max_length=_AGENT_NAME_MAX,
        description="Filter by agent (log_analysis, email_analysis, ...).",
    )

    rule_id: str | None = Field(
        default=None,
        max_length=_RULE_ID_MAX,
        description="Filter by exact rule_id.",
    )

    severity: EventSeverity | None = None
    min_severity: EventSeverity | None = None
    category: FindingCategory | None = None
    status: FindingStatus | None = None

    min_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Only findings with confidence >= this.",
    )

    source_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None

    has_alert: bool | None = Field(
        default=None,
        description="If True, only promoted findings; False, only unpromoted.",
    )
    has_incident: bool | None = Field(
        default=None,
        description="If True, only findings in an incident; False, only standalone.",
    )

    first_seen_after: datetime | None = None
    first_seen_before: datetime | None = None

    title_contains: str | None = Field(
        default=None,
        max_length=_TITLE_MAX,
        description="Case-insensitive substring match on title.",
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
    "FindingCreateInternal",
    "FindingRead",
    "FindingList",
    "FindingStatusUpdate",
    "FindingFilter",
]