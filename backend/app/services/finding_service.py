"""
CyberGuard AI — Agent Finding Service
============================================================================

Business logic for agent-produced findings: creation (with dedup),
retrieval, and lifecycle management.

Findings vs events
------------------
Events are **immutable** rows created by collectors — they never change
after ingestion.

Findings are **mutable** objects created by agents. They go through a
lifecycle:

    NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
                                      → DISMISSED
                                      → FALSE_POSITIVE

The mutable lifecycle is why this service exists — findings are
investigation artifacts, not raw data.

Deduplication
-------------
Findings are deduplicated by fingerprint, same as events. But there's
a subtle difference:

- Event fingerprints are computed deterministically from event fields
  (File 79). Same event → same fingerprint → one row.

- Finding fingerprints are computed by **agents** and supplied in
  ``FindingCreateInternal.dedup_hint``. The agent decides what "the
  same finding" means for its rule.

Examples:
    - A failed-login-burst rule might use the attacker IP as the
      dedup hint — all events from the same attacker collapse into
      one finding that grows in occurrence_count.
    - A port-scan rule might use (attacker_ip, target_host) so that
      the same attacker scanning a different target produces a
      separate finding.

The service combines the dedup hint with agent_name and rule_id to
compute the final fingerprint — so two different rules firing on the
same data produce two different findings, and the same rule firing
on similar data produces one finding that grows.

When a duplicate is detected:
    - The existing finding's ``occurrence_count`` is incremented
    - New event_ids are merged into ``event_ids`` (capped)
    - ``last_seen_at`` is bumped
    - ``confidence`` is raised to the max of (existing, new) — an
      agent that later becomes MORE confident shouldn't have its
      confidence masked by the earlier lower-confidence fire
    - ``severity`` stays at the max of (existing, new) — same reasoning
    - The method returns ``(existing_finding, False)`` indicating
      "not a new finding"

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Audit findings creation? No — findings are agent output, not user
   actions. The event log itself is the "audit" (event_id links).
   User actions on findings (acknowledge, resolve) ARE audited.

Public API
----------
    create_finding(db, *, dto)                  → (AgentFinding, bool)
    get_by_id(db, finding_id)                   → AgentFinding
    list_findings(db, *, page, filters)         → (list, int)
    advance_status(db, *, actor, finding, new_status, notes=None, request=None)
                                                → AgentFinding
    link_to_alert(db, *, finding, alert_id)     → AgentFinding
    link_to_incident(db, *, finding, incident_id) → AgentFinding

Usage
-----
    from app.services import finding_service
    from app.schemas.finding import FindingCreateInternal

    # Called by agents
    dto = FindingCreateInternal(
        workspace_id=workspace.id,
        source_id=source.id,
        agent_name="log_analysis",
        rule_id="log.failed_login_burst",
        severity=EventSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
        confidence=0.95,
        title="Repeated failed logins from 203.0.113.42",
        primary_event_id=first_event.id,
        event_ids=[e.id for e in burst],
        evidence={"threshold": 5, "window_seconds": 600, "count": 6},
        dedup_hint="203.0.113.42",
    )
    finding, was_created = finding_service.create_finding(db, dto=dto)
    db.commit()

    # Called by alert_service when promoting
    finding_service.link_to_alert(db, finding=finding, alert_id=alert.id)

    # Called by user endpoints
    finding_service.advance_status(
        db, actor=analyst, finding=finding,
        new_status=FindingStatus.RESOLVED,
    )
    db.commit()
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    FindingNotFoundError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.enums import (
    EventSeverity,
    FindingStatus,
)
from app.models.finding import AgentFinding
from app.models.user import User
from app.schemas.common import PageParams
from app.schemas.finding import (
    FindingCreateInternal,
    FindingFilter,
)
from app.services import audit_service


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Fingerprint payload version — bump if algorithm changes.
_FP_VERSION = "v1"

#: Severity ordering for max-merge on recurrence.
_SEVERITY_RANK: dict[EventSeverity, int] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}

#: Allowed status transitions. Mirrors the model's lifecycle but
#: enforced here so callers get a clean error before mutating.
_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.NEW: frozenset({
        FindingStatus.ACKNOWLEDGED,
        FindingStatus.DISMISSED,
        FindingStatus.FALSE_POSITIVE,
    }),
    FindingStatus.ACKNOWLEDGED: frozenset({
        FindingStatus.INVESTIGATING,
        FindingStatus.RESOLVED,
        FindingStatus.DISMISSED,
        FindingStatus.FALSE_POSITIVE,
    }),
    FindingStatus.INVESTIGATING: frozenset({
        FindingStatus.RESOLVED,
        FindingStatus.DISMISSED,
        FindingStatus.FALSE_POSITIVE,
    }),
    FindingStatus.RESOLVED: frozenset(),          # terminal
    FindingStatus.DISMISSED: frozenset(),         # terminal
    FindingStatus.FALSE_POSITIVE: frozenset(),    # terminal
}

_TERMINAL_STATUSES = frozenset({
    FindingStatus.RESOLVED,
    FindingStatus.DISMISSED,
    FindingStatus.FALSE_POSITIVE,
})


# ============================================================================
# INTERNAL — fingerprint computation
# ============================================================================

def _compute_finding_fingerprint(
    *,
    workspace_id: uuid.UUID,
    agent_name: str,
    rule_id: str,
    dedup_hint: str | None,
) -> str:
    """
    Compute the finding fingerprint.

    Three-component payload:
        v1|workspace_id|agent_name|rule_id|dedup_hint_or_empty

    The dedup hint is optional — if absent, the finding dedupes on
    (workspace, agent, rule) alone. That means all occurrences of a
    rule in a workspace collapse to a single finding. Useful for
    rules without a natural grouping key.

    Note: this is NOT the same algorithm as event fingerprints (File
    79). Events hash a large set of identifying fields because
    they're immutable data rows. Findings hash a small set of
    agent-supplied keys because they're mutable investigation objects
    where the agent decides what "same finding" means.
    """
    payload = "|".join([
        _FP_VERSION,
        str(workspace_id),
        agent_name.strip().lower(),
        rule_id.strip().lower(),
        (dedup_hint or "").strip(),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ============================================================================
# INTERNAL — state snapshots for audit
# ============================================================================

def _snapshot_state(finding: AgentFinding) -> dict[str, Any]:
    """Capture mutable fields of a finding for audit logging."""
    return {
        "severity": finding.severity.value,
        "status": finding.status.value,
        "confidence": finding.confidence,
        "occurrence_count": finding.occurrence_count,
        "alert_id": str(finding.alert_id) if finding.alert_id else None,
        "incident_id": str(finding.incident_id) if finding.incident_id else None,
    }


# ============================================================================
# CREATE / DEDUP
# ============================================================================

def create_finding(
    db: Session,
    *,
    dto: FindingCreateInternal,
) -> tuple[AgentFinding, bool]:
    """
    Create a finding, or increment an existing one on duplicate.

    Called by the 8 detection agents (Phase I) with a
    ``FindingCreateInternal`` DTO. Returns a tuple of the finding
    and a bool indicating whether it was newly created.

    Parameters
    ----------
    db : Session
    dto : FindingCreateInternal
        Validated agent output. Fingerprint is computed here (not
        supplied by the agent).

    Returns
    -------
    tuple[AgentFinding, bool]
        ``(finding, was_created)``.
        ``was_created=True`` → new row.
        ``was_created=False`` → existing finding, occurrence_count
        incremented and fields merged.

    Raises
    ------
    ValidationError
        If the dto is malformed in a way that Pydantic didn't catch
        (defensive).
    """
    fingerprint = _compute_finding_fingerprint(
        workspace_id=dto.workspace_id,
        agent_name=dto.agent_name,
        rule_id=dto.rule_id,
        dedup_hint=dto.dedup_hint,
    )

    # ── Look for existing finding with the same fingerprint in this workspace
    existing = db.execute(
        select(AgentFinding).where(
            AgentFinding.workspace_id == dto.workspace_id,
            AgentFinding.fingerprint == fingerprint,
        )
    ).scalar_one_or_none()

    if existing is not None:
        # ── Recurrence: merge into existing finding
        _merge_recurrence(existing, dto)
        db.flush()

        logger.debug(
            "Finding recurrence merged",
            extra={
                "finding_id": str(existing.id),
                "occurrence_count": existing.occurrence_count,
                "agent_name": dto.agent_name,
                "rule_id": dto.rule_id,
            },
        )
        return existing, False

    # ── New finding
    event_ids_str = [str(eid) for eid in dto.event_ids]
    now = datetime.now(timezone.utc)

    finding = AgentFinding.build(
        workspace_id=dto.workspace_id,
        source_id=dto.source_id,
        agent_name=dto.agent_name,
        rule_id=dto.rule_id,
        title=dto.title,
        description=dto.description,
        severity=dto.severity,
        category=dto.category,
        confidence=dto.confidence,
        primary_event_id=dto.primary_event_id,
        event_ids=event_ids_str,
        evidence=dto.evidence,
        mitre_techniques=dto.mitre_techniques,
        tags=dto.tags,
        fingerprint=fingerprint,
    )
    db.add(finding)
    db.flush()

    logger.info(
        "Finding created",
        extra={
            "finding_id": str(finding.id),
            "workspace_id": str(finding.workspace_id),
            "source_id": str(finding.source_id) if finding.source_id else None,
            "agent_name": dto.agent_name,
            "rule_id": dto.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
        },
    )

    return finding, True


def _merge_recurrence(
    finding: AgentFinding,
    dto: FindingCreateInternal,
) -> None:
    """
    Merge a recurrence into an existing finding.

    Merge rules:
        - occurrence_count += 1 (via model method)
        - last_seen_at = now (via model method)
        - event_ids: union (capped by model's MAX_EVENT_IDS)
        - confidence: max(existing, new) — agent getting more confident
        - severity: max(existing, new) — finding getting worse
        - title: keep existing (don't rewrite — would churn audit)
        - description: replace only if existing is empty
        - evidence: replace only if new is non-empty (dto.evidence)
        - tags: union
        - mitre_techniques: union
        - status: unchanged (a resolved finding that re-fires stays
                  resolved; analysts can reopen if they care)
    """
    # Model helper handles occurrence_count, last_seen_at, event_ids merge
    finding.record_recurrence([str(eid) for eid in dto.event_ids])

    # Confidence: max (agent got more sure)
    if dto.confidence > finding.confidence:
        finding.confidence = dto.confidence

    # Severity: max (situation worsened)
    existing_rank = _SEVERITY_RANK.get(finding.severity, 0)
    new_rank = _SEVERITY_RANK.get(dto.severity, 0)
    if new_rank > existing_rank:
        finding.severity = dto.severity

    # Description: keep existing unless empty
    if (not finding.description) and dto.description:
        finding.description = dto.description

    # Evidence: prefer new if non-empty (agents may have richer context)
    if dto.evidence:
        finding.evidence = dict(dto.evidence)

    # Tags: union
    if dto.tags:
        merged_tags = list(dict.fromkeys((finding.tags or []) + list(dto.tags)))
        finding.tags = merged_tags[:50]  # cap at 50

    # MITRE: union
    if dto.mitre_techniques:
        merged_mitre = list(dict.fromkeys(
            (finding.mitre_techniques or []) + list(dto.mitre_techniques)
        ))
        finding.mitre_techniques = merged_mitre[:50]  # cap at 50

    # primary_event_id: keep existing (the original root)


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, finding_id: uuid.UUID) -> AgentFinding:
    """
    Fetch a finding by ID. Raises ``FindingNotFoundError`` if missing.
    """
    finding = db.get(AgentFinding, finding_id)
    if finding is None:
        raise FindingNotFoundError(
            message=f"Finding {finding_id} not found.",
            details={"finding_id": str(finding_id)},
        )
    return finding


def list_findings(
    db: Session,
    *,
    workspace_ids: list[uuid.UUID] | None,
    page: PageParams,
    filters: FindingFilter,
) -> tuple[list[AgentFinding], int]:
    """
    List findings with filters and pagination.

    Parameters
    ----------
    db : Session
    workspace_ids : list[UUID] | None
        Restrict results to these workspaces. Callers should pass the
        user's accessible workspaces (personal + org memberships).
        ``None`` means "no filter" — only used by admin scope, and
        the caller is responsible for ensuring the actor has that
        scope.
    page : PageParams
    filters : FindingFilter
        Optional filter fields from the schema.

    Returns
    -------
    tuple[list[AgentFinding], int]
        ``(findings_on_page, total_count)``.
    """
    stmt = select(AgentFinding)

    # ── Workspace scope (multi-tenant isolation)
    if workspace_ids is not None:
        stmt = stmt.where(AgentFinding.workspace_id.in_(workspace_ids))

    # ── Filters
    if filters.agent_name:
        stmt = stmt.where(AgentFinding.agent_name == filters.agent_name.strip().lower())
    if filters.rule_id:
        stmt = stmt.where(AgentFinding.rule_id == filters.rule_id.strip())
    if filters.severity is not None:
        stmt = stmt.where(AgentFinding.severity == filters.severity)
    if filters.min_severity is not None:
        # Severity >= min_severity, computed via rank
        min_rank = _SEVERITY_RANK.get(filters.min_severity, 0)
        accepted = [
            sev for sev, rank in _SEVERITY_RANK.items() if rank >= min_rank
        ]
        if accepted:
            stmt = stmt.where(AgentFinding.severity.in_(accepted))
    if filters.category is not None:
        stmt = stmt.where(AgentFinding.category == filters.category)
    if filters.status is not None:
        stmt = stmt.where(AgentFinding.status == filters.status)
    if filters.min_confidence is not None:
        stmt = stmt.where(AgentFinding.confidence >= filters.min_confidence)
    if filters.source_id is not None:
        stmt = stmt.where(AgentFinding.source_id == filters.source_id)
    if filters.alert_id is not None:
        stmt = stmt.where(AgentFinding.alert_id == filters.alert_id)
    if filters.incident_id is not None:
        stmt = stmt.where(AgentFinding.incident_id == filters.incident_id)
    if filters.has_alert is not None:
        if filters.has_alert:
            stmt = stmt.where(AgentFinding.alert_id.is_not(None))
        else:
            stmt = stmt.where(AgentFinding.alert_id.is_(None))
    if filters.has_incident is not None:
        if filters.has_incident:
            stmt = stmt.where(AgentFinding.incident_id.is_not(None))
        else:
            stmt = stmt.where(AgentFinding.incident_id.is_(None))
    if filters.first_seen_after is not None:
        stmt = stmt.where(AgentFinding.first_seen_at >= filters.first_seen_after)
    if filters.first_seen_before is not None:
        stmt = stmt.where(AgentFinding.first_seen_at <= filters.first_seen_before)
    if filters.title_contains:
        stmt = stmt.where(
            AgentFinding.title.ilike(f"%{filters.title_contains.lower()}%")
        )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            AgentFinding.first_seen_at.desc(),
            AgentFinding.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    findings = list(db.execute(stmt).scalars().all())
    return findings, int(total)


# ============================================================================
# LIFECYCLE
# ============================================================================

def advance_status(
    db: Session,
    *,
    actor: User,
    finding: AgentFinding,
    new_status: FindingStatus,
    notes: str | None = None,
    request: Any | None = None,
) -> AgentFinding:
    """
    Advance a finding's status to ``new_status``.

    Validates the transition against ``_ALLOWED_TRANSITIONS``. Audits
    the change. Returns the (flushed, not committed) finding.

    Terminal statuses (RESOLVED, DISMISSED, FALSE_POSITIVE) cannot
    transition to anything — the finding is closed. New occurrences
    of the same finding do not reopen it (analysts can reopen manually
    via the platform if they need to).

    Raises
    ------
    InvalidStateTransitionError
        If the transition is not allowed from the current status.
    """
    if new_status == finding.status:
        return finding  # idempotent

    if new_status not in _ALLOWED_TRANSITIONS.get(finding.status, frozenset()):
        raise InvalidStateTransitionError(
            message=(
                f"Cannot transition finding from "
                f"{finding.status.value} to {new_status.value}."
            ),
            code="FINDING_INVALID_TRANSITION",
            details={
                "current": finding.status.value,
                "requested": new_status.value,
                "allowed": [
                    s.value
                    for s in _ALLOWED_TRANSITIONS.get(
                        finding.status, frozenset()
                    )
                ],
            },
        )

    before = _snapshot_state(finding)
    finding.status = new_status
    db.flush()
    after = _snapshot_state(finding)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="finding.status_changed",
        target_type="finding",
        target_id=finding.id,
        workspace_id=finding.workspace_id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    logger.info(
        "Finding status changed",
        extra={
            "finding_id": str(finding.id),
            "from": before["status"],
            "to": after["status"],
            "actor_id": str(actor.id),
        },
    )

    return finding


# ============================================================================
# CROSS-MODULE LINKS (called by other services)
# ============================================================================

def link_to_alert(
    db: Session,
    *,
    finding: AgentFinding,
    alert_id: uuid.UUID,
) -> AgentFinding:
    """
    Link a finding to an alert.

    Called by ``alert_service.promote_finding`` — one alert can
    aggregate multiple findings, so this is the forward link from
    finding → alert. Idempotent — re-linking to the same alert is a
    no-op.

    Does NOT audit — the alert creation itself is audited at the
    alert level (``alert_service``).

    Raises
    ------
    ValidationError
        If the finding is already linked to a different alert.
    """
    if finding.alert_id == alert_id:
        return finding  # idempotent

    if finding.alert_id is not None:
        raise ValidationError(
            message=(
                f"Finding {finding.id} is already linked to alert "
                f"{finding.alert_id}. Cannot link to a different alert."
            ),
            code="FINDING_ALREADY_LINKED",
            details={
                "finding_id": str(finding.id),
                "existing_alert_id": str(finding.alert_id),
                "attempted_alert_id": str(alert_id),
            },
        )

    finding.alert_id = alert_id
    db.flush()
    return finding


def link_to_incident(
    db: Session,
    *,
    finding: AgentFinding,
    incident_id: uuid.UUID,
) -> AgentFinding:
    """
    Link a finding to an incident.

    Called by ``incident_service`` when an incident is created or
    when findings are swept into an existing incident.

    Unlike alerts, findings can be linked to an incident AND an
    alert at the same time — the alert represents the user-facing
    notification, the incident represents the investigation. Same
    finding, both layers.

    Idempotent — re-linking to the same incident is a no-op.

    Raises
    ------
    ValidationError
        If the finding is already linked to a different incident.
    """
    if finding.incident_id == incident_id:
        return finding  # idempotent

    if finding.incident_id is not None:
        raise ValidationError(
            message=(
                f"Finding {finding.id} is already linked to incident "
                f"{finding.incident_id}. Cannot link to a different incident."
            ),
            code="FINDING_ALREADY_IN_INCIDENT",
            details={
                "finding_id": str(finding.id),
                "existing_incident_id": str(finding.incident_id),
                "attempted_incident_id": str(incident_id),
            },
        )

    finding.incident_id = incident_id
    db.flush()
    return finding


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "create_finding",
    "get_by_id",
    "list_findings",
    "advance_status",
    "link_to_alert",
    "link_to_incident",
]