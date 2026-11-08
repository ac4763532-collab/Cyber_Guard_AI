"""
CyberGuard AI — Incident Service
============================================================================

The NIST SP 800-61 incident lifecycle engine.

An incident is the **managed investigation container** at the center of
the platform. It aggregates multiple alerts, findings, and events into
a single coherent object with a formal lifecycle:

    OPEN → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY
                                              → RESOLVED → CLOSED

With branch paths:
    INVESTIGATING → RECOVERY   (low-severity; skip containment)
    INVESTIGATING → RESOLVED   (fast triage)
    INVESTIGATING → CLOSED     (false positive)
    RESOLVED → INVESTIGATING   (regression / reopen)

This file owns that lifecycle. Every transition is validated against
the state machine, every transition is audited, and every transition
timestamps the corresponding phase column
(``acknowledged_at``, ``containment_at``, etc.).

Incident vs alert vs case
-------------------------
    Alert       — a notification. "The platform detected something
                  you should look at." Dozens per day.

    Incident    — a managed investigation. "Multiple related alerts
                  suggest a coordinated attack requiring response."
                  Weekly.

    Case        — a specific analyst's work item. "Rahul is
                  investigating this incident." One incident can have
                  multiple cases (different analysts, different angles).

An incident exists to coordinate. It's the object that says "we are
formally responding to this."

Deduplication at the pattern level
----------------------------------
Like alerts, incidents dedupe by **pattern**, not by individual alert
or finding. The incident fingerprint is:

    (workspace_id, category, severity, primary_source_scope)

When a new alert/finding arrives and an incident of the same pattern
is already active, the new data merges into the existing incident
(occurrence_count++, alert_ids/finding_ids union). A resolved
incident doesn't merge — a fresh occurrence creates a new incident
with ``previous_incident_id`` pointing to the resolved one, preserving
the attack-pattern history.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Every state transition audited.
5. Notifications dispatched via ``notification_service`` on creation
   and on assignment.

Public API
----------
    # Creation / lookup
    create_incident(db, *, dto, actor=None)         → SecurityIncident
    get_by_id(db, incident_id)                      → SecurityIncident
    list_incidents(db, *, workspace_ids, page, filters) → (list, int)
    find_incident_candidates(db, *, alert)          → list[SecurityIncident]

    # Lifecycle
    advance_status(db, *, actor, incident, new_status, notes=None, request=None)
                                                    → SecurityIncident
    assign(db, *, actor, incident, assigned_to_id, notes=None, request=None)
                                                    → SecurityIncident
    resolve(db, *, actor, incident, root_cause, resolution_summary, request=None)
                                                    → SecurityIncident
    close(db, *, actor, incident, lessons_learned, request=None)
                                                    → SecurityIncident

    # Structured actions
    record_containment_action(db, *, actor, incident, action, target=None,
                              result="success", notes=None, request=None)
                                                    → SecurityIncident
    record_recovery_action(db, *, actor, incident, action, target=None,
                           result="success", notes=None, request=None)
                                                    → SecurityIncident

    # Event links
    link_event(db, *, actor, incident, event_id, link_type="related",
               relevance_score=None, notes=None, request=None)
                                                    → IncidentEventLink
    unlink_event(db, *, actor, link)                → None

    # SLA
    check_sla_breaches(db, *, limit=100)            → list[SecurityIncident]

Usage
-----
    from app.services import incident_service

    # Agent calls this when promoting an alert to incident
    dto = IncidentCreateInternal(
        workspace_id=workspace.id,
        title="Brute force attack against alice@example.com",
        severity=IncidentSeverity.HIGH,
        category=FindingCategory.BRUTE_FORCE,
        alert_ids=[alert.id],
        finding_ids=[finding.id],
        affected_users=["alice"],
        affected_ips=["203.0.113.42"],
        mitre_techniques=["T1110.001"],
        sla_acknowledge_hours=1,
        sla_resolve_hours=24,
    )
    incident = incident_service.create_incident(db, dto=dto)
    db.commit()

    # Analyst works it
    incident_service.advance_status(
        db, actor=analyst, incident=incident,
        new_status=IncidentStatus.INVESTIGATING,
    )
    incident_service.record_containment_action(
        db, actor=analyst, incident=incident,
        action="block_ip", target="203.0.113.42",
    )
    incident_service.advance_status(
        db, actor=analyst, incident=incident,
        new_status=IncidentStatus.CONTAINMENT,
    )
    ...
    incident_service.resolve(
        db, actor=analyst, incident=incident,
        root_cause="Credential stuffing from compromised ISP account",
        resolution_summary="Blocked attacker IP; reset passwords.",
    )
    incident_service.close(
        db, actor=analyst, incident=incident,
        lessons_learned="Enable MFA for all users in the org.",
    )
    db.commit()
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    IncidentNotFoundError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.enums import (
    FindingCategory,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.incident import (
    IncidentEventLink,
    SecurityIncident,
)
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.schemas.finding import FindingCreateInternal  # noqa: F401 — used in type docs
from app.schemas.incident import (
    IncidentCreateInternal,
    IncidentFilter,
)
from app.services import (
    audit_service,
    notification_service,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

_INCIDENT_FP_VERSION = "v1"

#: NIST state machine — mirrors the model's ``_ALLOWED_TRANSITIONS`` but
#: duplicated here so callers get a clean service-layer error.
_ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.INVESTIGATING: frozenset({
        IncidentStatus.CONTAINMENT,
        IncidentStatus.RECOVERY,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.CONTAINMENT: frozenset({
        IncidentStatus.ERADICATION,
        IncidentStatus.RECOVERY,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.ERADICATION: frozenset({
        IncidentStatus.RECOVERY,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.RECOVERY: frozenset({
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    }),
    IncidentStatus.RESOLVED: frozenset({
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,
    }),
    IncidentStatus.CLOSED: frozenset({
        IncidentStatus.INVESTIGATING,
    }),
}

_SEVERITY_RANK: dict[IncidentSeverity, int] = {
    IncidentSeverity.LOW: 1,
    IncidentSeverity.MEDIUM: 2,
    IncidentSeverity.HIGH: 3,
    IncidentSeverity.CRITICAL: 4,
}

_MAX_LINKED_ITEMS = 500


# ============================================================================
# INTERNAL — fingerprint
# ============================================================================

def _compute_incident_fingerprint(
    *,
    workspace_id: uuid.UUID,
    category: FindingCategory,
    severity: IncidentSeverity,
    primary_source_id: uuid.UUID | None,
) -> str:
    """
    Incident-pattern fingerprint.

    Uses the same components as the alert fingerprint (workspace +
    category + severity + source_scope) — an incident is the same
    *pattern* as the alert it aggregates, just at a higher level of
    management.

    This means: one incident per (workspace, category, severity,
    source_scope) pattern. Multiple alerts of the same pattern funnel
    into one incident.
    """
    source_scope = str(primary_source_id) if primary_source_id else "cross_source"
    payload = "|".join([
        _INCIDENT_FP_VERSION,
        str(workspace_id),
        category.value,
        severity.value,
        source_scope,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ============================================================================
# INTERNAL — snapshot for audit
# ============================================================================

def _snapshot_state(incident: SecurityIncident) -> dict[str, Any]:
    """Capture mutable fields for audit."""
    return {
        "severity": incident.severity.value,
        "status": incident.status.value,
        "assigned_to_id": (
            str(incident.assigned_to_id) if incident.assigned_to_id else None
        ),
        "root_cause": incident.root_cause,
        "resolution_summary": incident.resolution_summary,
        "lessons_learned": incident.lessons_learned,
    }


# ============================================================================
# INTERNAL — context aggregation
# ============================================================================

def _aggregate_affected_from_alerts(
    alerts: list[SecurityAlert],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Build affected_devices / affected_users / affected_ips / mitre
    from a set of alerts. Returns (devices, users, ips, mitre).
    """
    devices: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    mitre: set[str] = set()

    for alert in alerts:
        ctx = alert.context or {}
        for h in ctx.get("hostnames", []) or []:
            if isinstance(h, str) and h:
                devices.add(h)
        for u in ctx.get("usernames", []) or []:
            if isinstance(u, str) and u:
                users.add(u)
        for ip in ctx.get("source_ips", []) or []:
            if isinstance(ip, str) and ip:
                ips.add(ip)
        for m in alert.mitre_techniques or []:
            mitre.add(m)

    return (
        sorted(devices)[:100],
        sorted(users)[:100],
        sorted(ips)[:100],
        sorted(mitre)[:50],
    )


# ============================================================================
# CREATE
# ============================================================================

def create_incident(
    db: Session,
    *,
    dto: IncidentCreateInternal,
    actor: User | None = None,
) -> SecurityIncident:
    """
    Create an incident, or merge into an existing one of the same
    pattern if one is active.

    Called by:
        - ``incident_response_agent`` (Phase I) — when a pattern
          crosses the auto-create threshold
        - Admin endpoint (future) — manual incident creation

    If an active incident with the same pattern already exists in this
    workspace, the DTO is merged into it:
        - ``occurrence_count++``
        - ``alert_ids``/``finding_ids`` unioned
        - affected_* recomputed from the union of alerts
        - ``severity`` max-merged
        - SLA re-extended if severity escalated

    If no active incident exists but a resolved one does, a new
    incident is created with ``previous_incident_id`` set.

    Notification
    ------------
    On creation (not on merge), ``notification_service.create_for_incident``
    is called to fan out to relevant org members.

    Raises
    ------
    ValidationError
        If the DTO has no alerts or findings to aggregate (an incident
        with zero evidence is meaningless).
    """
    if not dto.alert_ids and not dto.finding_ids:
        raise ValidationError(
            message=(
                "Cannot create an incident without at least one alert or "
                "finding. Incidents aggregate evidence; they don't exist "
                "in isolation."
            ),
            code="INCIDENT_REQUIRES_EVIDENCE",
        )

    fingerprint = _compute_incident_fingerprint(
        workspace_id=dto.workspace_id,
        category=dto.category,
        severity=dto.severity,
        primary_source_id=dto.primary_source_id,
    )

    # ── Merge into active incident if one exists
    existing = db.execute(
        select(SecurityIncident).where(
            SecurityIncident.workspace_id == dto.workspace_id,
            SecurityIncident.fingerprint == fingerprint,
            SecurityIncident.closed_at.is_(None),
        )
    ).scalar_one_or_none()

    if existing is not None:
        _merge_into_incident(db, existing, dto)
        db.flush()
        logger.debug(
            "Incident recurrence merged",
            extra={
                "incident_id": str(existing.id),
                "occurrence_count": existing.occurrence_count,
            },
        )
        return existing

    # ── Previous incident chain (resolved incidents with same pattern)
    previous = db.execute(
        select(SecurityIncident)
        .where(
            SecurityIncident.workspace_id == dto.workspace_id,
            SecurityIncident.fingerprint == fingerprint,
            SecurityIncident.closed_at.is_not(None),
        )
        .order_by(SecurityIncident.closed_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    # ── Create new incident
    now = datetime.now(timezone.utc)
    expires_at = (
        now + timedelta(hours=dto.sla_resolve_hours)
        if dto.sla_resolve_hours else None
    )

    incident = SecurityIncident.build(
        workspace_id=dto.workspace_id,
        fingerprint=fingerprint,
        title=dto.title,
        description=dto.description,
        severity=dto.severity,
        category=dto.category,
        primary_source_id=dto.primary_source_id,
        alert_ids=[str(aid) for aid in dto.alert_ids],
        finding_ids=[str(fid) for fid in dto.finding_ids],
        affected_devices=dto.affected_devices or [],
        affected_users=dto.affected_users or [],
        affected_ips=dto.affected_ips or [],
        mitre_techniques=dto.mitre_techniques or [],
        tags=dto.tags or [],
        context=dto.context or {},
        previous_incident_id=previous.id if previous else None,
        assigned_to_id=dto.assigned_to_id,
        assigned_by_id=dto.assigned_by_id,
        sla_acknowledge_hours=dto.sla_acknowledge_hours,
        sla_resolve_hours=dto.sla_resolve_hours,
        first_seen_at=dto.first_seen_at,
    )
    db.add(incident)
    db.flush()

    # Back-link alerts → incident
    for aid in dto.alert_ids:
        alert = db.get(SecurityAlert, aid)
        if alert is not None:
            alert.incident_id = incident.id

    # Back-link findings → incident
    for fid in dto.finding_ids:
        finding = db.get(AgentFinding, fid)
        if finding is not None:
            finding.incident_id = incident.id

    db.flush()

    # Audit — either by actor (manual creation) or system (agent)
    audit_service.log_action(
        db,
        actor=actor,
        actor_type="user" if actor else "agent",
        action="incident.created",
        target_type="incident",
        target_id=incident.id,
        target_display=incident.title[:100],
        workspace_id=incident.workspace_id,
        metadata={
            "alert_count": len(dto.alert_ids),
            "finding_count": len(dto.finding_ids),
            "severity": incident.severity.value,
            "category": incident.category.value,
        },
    )

    logger.info(
        "Incident created",
        extra={
            "incident_id": str(incident.id),
            "workspace_id": str(incident.workspace_id),
            "severity": incident.severity.value,
            "category": incident.category.value,
            "alert_count": len(dto.alert_ids),
            "finding_count": len(dto.finding_ids),
        },
    )

    # Notify org members
    try:
        notification_service.create_for_incident(db, incident=incident)
    except Exception as exc:  # noqa: BLE001 — notification failure shouldn't block
        logger.warning(
            "Failed to create incident notifications",
            extra={
                "incident_id": str(incident.id),
                "error": str(exc)[:200],
            },
        )

    return incident


def _merge_into_incident(
    db: Session,
    incident: SecurityIncident,
    dto: IncidentCreateInternal,
) -> None:
    """
    Merge new alerts/findings into an existing incident.
    """
    incident.record_recurrence(
        new_alert_ids=[str(aid) for aid in dto.alert_ids],
        new_finding_ids=[str(fid) for fid in dto.finding_ids],
    )

    # Severity: max
    existing_rank = _SEVERITY_RANK.get(incident.severity, 0)
    new_rank = _SEVERITY_RANK.get(dto.severity, 0)
    if new_rank > existing_rank:
        incident.severity = dto.severity
        # Extend SLA
        if dto.sla_resolve_hours:
            first = incident.first_seen_at
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            incident.sla_resolve_hours = dto.sla_resolve_hours
            incident.expires_at = first + timedelta(hours=dto.sla_resolve_hours)

    # Back-link new alerts and findings
    for aid in dto.alert_ids:
        alert = db.get(SecurityAlert, aid)
        if alert is not None:
            alert.incident_id = incident.id
    for fid in dto.finding_ids:
        finding = db.get(AgentFinding, fid)
        if finding is not None:
            finding.incident_id = incident.id

    # Aggregate affected_* from all linked alerts
    all_alerts = _load_alerts_for_incident(db, incident)
    devices, users, ips, mitre = _aggregate_affected_from_alerts(all_alerts)
    if devices:
        incident.affected_devices = devices
    if users:
        incident.affected_users = users
    if ips:
        incident.affected_ips = ips
    if mitre:
        incident.mitre_techniques = mitre

    db.flush()


def _load_alerts_for_incident(
    db: Session,
    incident: SecurityIncident,
    *,
    limit: int = 50,
) -> list[SecurityAlert]:
    """Load alerts referenced by the incident, capped at ``limit``."""
    if not incident.alert_ids:
        return []
    try:
        alert_uuids = [uuid.UUID(aid) for aid in incident.alert_ids[:limit]]
    except (ValueError, TypeError):
        return []
    return list(db.execute(
        select(SecurityAlert).where(SecurityAlert.id.in_(alert_uuids))
    ).scalars().all())


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, incident_id: uuid.UUID) -> SecurityIncident:
    """Fetch an incident by ID. Raises ``IncidentNotFoundError`` if missing."""
    incident = db.get(SecurityIncident, incident_id)
    if incident is None:
        raise IncidentNotFoundError(
            message=f"Incident {incident_id} not found.",
            details={"incident_id": str(incident_id)},
        )
    return incident


def list_incidents(
    db: Session,
    *,
    workspace_ids: list[uuid.UUID] | None,
    page: PageParams,
    filters: IncidentFilter,
) -> tuple[list[SecurityIncident], int]:
    """
    List incidents with filters and pagination.

    ``workspace_ids`` restricts to accessible workspaces — multi-tenant
    isolation, same as alerts and findings.
    """
    stmt = select(SecurityIncident)

    if workspace_ids is not None:
        stmt = stmt.where(SecurityIncident.workspace_id.in_(workspace_ids))

    if filters.severity is not None:
        stmt = stmt.where(SecurityIncident.severity == filters.severity)
    if filters.min_severity is not None:
        min_rank = _SEVERITY_RANK.get(filters.min_severity, 0)
        accepted = [
            s for s, r in _SEVERITY_RANK.items() if r >= min_rank
        ]
        if accepted:
            stmt = stmt.where(SecurityIncident.severity.in_(accepted))
    if filters.category is not None:
        stmt = stmt.where(SecurityIncident.category == filters.category)
    if filters.status is not None:
        stmt = stmt.where(SecurityIncident.status == filters.status)
    if filters.assigned_to_id is not None:
        stmt = stmt.where(SecurityIncident.assigned_to_id == filters.assigned_to_id)
    if filters.unassigned_only:
        stmt = stmt.where(SecurityIncident.assigned_to_id.is_(None))
    if filters.primary_source_id is not None:
        stmt = stmt.where(SecurityIncident.primary_source_id == filters.primary_source_id)
    if filters.sla_breached is not None:
        now = datetime.now(timezone.utc)
        if filters.sla_breached:
            stmt = stmt.where(
                SecurityIncident.closed_at.is_(None),
                SecurityIncident.expires_at.is_not(None),
                SecurityIncident.expires_at < now,
            )
        else:
            stmt = stmt.where(
                (SecurityIncident.expires_at.is_(None))
                | (SecurityIncident.expires_at >= now)
            )
    if filters.under_legal_hold is not None:
        now = datetime.now(timezone.utc)
        if filters.under_legal_hold:
            stmt = stmt.where(
                SecurityIncident.legal_hold_until.is_not(None),
                SecurityIncident.legal_hold_until > now,
            )
        else:
            stmt = stmt.where(
                (SecurityIncident.legal_hold_until.is_(None))
                | (SecurityIncident.legal_hold_until <= now)
            )
    if filters.opened_after is not None:
        stmt = stmt.where(SecurityIncident.opened_at >= filters.opened_after)
    if filters.opened_before is not None:
        stmt = stmt.where(SecurityIncident.opened_at <= filters.opened_before)
    if filters.closed_after is not None:
        stmt = stmt.where(SecurityIncident.closed_at >= filters.closed_after)
    if filters.closed_before is not None:
        stmt = stmt.where(SecurityIncident.closed_at <= filters.closed_before)
    if filters.title_contains:
        stmt = stmt.where(
            SecurityIncident.title.ilike(f"%{filters.title_contains.lower()}%")
        )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            SecurityIncident.opened_at.desc(),
            SecurityIncident.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    incidents = list(db.execute(stmt).scalars().all())
    return incidents, int(total)


def find_incident_candidates(
    db: Session,
    *,
    alert: SecurityAlert,
) -> list[SecurityIncident]:
    """
    Find open incidents that might match a new alert.

    Used by ``incident_response_agent`` to decide whether a new alert
    belongs to an existing incident or warrants a new one.

    Match criteria:
        - Same workspace
        - Status not CLOSED
        - Category matches
        - Severity within ±1 rank (a HIGH alert can merge into a
          CRITICAL incident and vice versa — a MEDIUM alert can't
          merge into a CRITICAL one without explicit analyst action)

    Sorted by most recent first. Cap at 5 candidates — if there are
    more, the agent should pick the closest match or create a new one.
    """
    alert_rank = _SEVERITY_RANK.get(
        IncidentSeverity(alert.severity.value), 0
    )
    acceptable_ranks = {alert_rank - 1, alert_rank, alert_rank + 1}
    acceptable_severities = [
        sev for sev, rank in _SEVERITY_RANK.items() if rank in acceptable_ranks
    ]

    return list(db.execute(
        select(SecurityIncident)
        .where(
            SecurityIncident.workspace_id == alert.workspace_id,
            SecurityIncident.status != IncidentStatus.CLOSED,
            SecurityIncident.category == alert.category,
            SecurityIncident.severity.in_(acceptable_severities),
        )
        .order_by(SecurityIncident.opened_at.desc())
        .limit(5)
    ).scalars().all())


# ============================================================================
# LIFECYCLE — STATUS
# ============================================================================

def advance_status(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    new_status: IncidentStatus,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Advance the incident's NIST lifecycle status.

    Validates the transition against ``_ALLOWED_TRANSITIONS``. Updates
    the corresponding phase timestamp (``acknowledged_at``,
    ``containment_at``, etc.) via the model's ``advance_status``
    method. Audits the transition.
    """
    if new_status == incident.status:
        return incident  # idempotent

    if new_status not in _ALLOWED_TRANSITIONS.get(incident.status, frozenset()):
        raise InvalidStateTransitionError(
            message=(
                f"Cannot transition incident from "
                f"{incident.status.value} to {new_status.value}."
            ),
            code="INCIDENT_INVALID_TRANSITION",
            details={
                "current": incident.status.value,
                "requested": new_status.value,
                "allowed": [
                    s.value
                    for s in _ALLOWED_TRANSITIONS.get(
                        incident.status, frozenset()
                    )
                ],
            },
        )

    before = _snapshot_state(incident)
    incident.advance_status(
        new_status, by_user_id=actor.id, notes=notes,
    )
    db.flush()
    after = _snapshot_state(incident)

    audit_service.log_state_change(
        db,
        actor=actor,
        action=f"incident.status.{new_status.value}",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    logger.info(
        "Incident status advanced",
        extra={
            "incident_id": str(incident.id),
            "from": before["status"],
            "to": after["status"],
            "actor_id": str(actor.id),
        },
    )

    return incident


# ============================================================================
# LIFECYCLE — ASSIGN
# ============================================================================

def assign(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    assigned_to_id: uuid.UUID,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Assign the incident to an analyst.

    Verifies the assignee is an active workspace member (delegated to
    ``authorization``). Dispatches a notification via
    ``notification_service``.
    """
    from app.services import authorization

    authorization.check_permission(
        db, actor, "incident:assign", workspace_id=incident.workspace_id,
    )

    # Verify assignee is an active workspace member
    assignee = db.get(User, assigned_to_id)
    if assignee is None or assignee.deleted_at is not None:
        raise ValidationError(
            message="Assignee not found.",
            code="ASSIGNEE_NOT_FOUND",
        )
    role = authorization.get_user_workspace_role(
        db, assignee, incident.workspace_id,
    )
    if role is None:
        raise ValidationError(
            message="Assignee is not an active workspace member.",
            code="ASSIGNEE_NOT_MEMBER",
        )

    before = {
        "assigned_to_id": (
            str(incident.assigned_to_id) if incident.assigned_to_id else None
        ),
    }
    incident.assigned_to_id = assigned_to_id
    incident.assigned_by_id = actor.id
    incident.assigned_at = datetime.now(timezone.utc)
    db.flush()
    after = {"assigned_to_id": str(assigned_to_id)}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="incident.assigned",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    # Notify assignee
    try:
        notification_service.create(
            db,
            recipient_id=assigned_to_id,
            notification_type=notification_service.NotificationType.CASE_ASSIGNED,
            title=f"Incident assigned to you: {incident.title[:100]}",
            body=(
                f"Severity: {incident.severity.value}. "
                f"Status: {incident.status.value}."
            ),
            priority=notification_service._PRIORITY_HIGH
            if incident.severity.value in ("high", "critical")
            else notification_service._PRIORITY_MEDIUM,
            icon="shield-alert",
            link_to_type="incident",
            link_to_id=incident.id,
            related_workspace_id=incident.workspace_id,
            dedup_key_template=f"incident_assigned:{incident.id}:{assigned_to_id}",
            metadata={"incident_id": str(incident.id)},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to notify incident assignee",
            extra={
                "incident_id": str(incident.id),
                "error": str(exc)[:200],
            },
        )

    return incident


# ============================================================================
# LIFECYCLE — RESOLVE / CLOSE
# ============================================================================

def resolve(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    root_cause: str,
    resolution_summary: str,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Mark the incident as resolved. Requires both root cause and
    resolution summary — a compliance requirement.

    Automatically advances the status to RESOLVED if the transition
    is legal from the current status. If the incident is already in a
    status that can't go directly to RESOLVED (e.g. OPEN), the caller
    must advance manually through the intermediate states first.
    """
    if not root_cause or not root_cause.strip():
        raise ValidationError(
            message="Root cause is required when resolving an incident.",
            code="INCIDENT_ROOT_CAUSE_REQUIRED",
        )
    if not resolution_summary or not resolution_summary.strip():
        raise ValidationError(
            message="Resolution summary is required when resolving an incident.",
            code="INCIDENT_RESOLUTION_SUMMARY_REQUIRED",
        )

    # Must be able to transition to RESOLVED
    if IncidentStatus.RESOLVED not in _ALLOWED_TRANSITIONS.get(
        incident.status, frozenset()
    ):
        if incident.status == IncidentStatus.RESOLVED:
            return incident  # already resolved, idempotent
        raise InvalidStateTransitionError(
            message=(
                f"Cannot resolve an incident in status "
                f"{incident.status.value}. Advance to a resolvable state "
                f"first (investigating, containment, eradication, or "
                f"recovery)."
            ),
            code="INCIDENT_NOT_RESOLVABLE",
            details={"status": incident.status.value},
        )

    before = _snapshot_state(incident)
    incident.advance_status(
        IncidentStatus.RESOLVED,
        by_user_id=actor.id,
        notes="Incident resolved",
    )
    incident.root_cause = root_cause.strip()
    incident.resolution_summary = resolution_summary.strip()
    db.flush()
    after = _snapshot_state(incident)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="incident.resolved",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        before_state=before,
        after_state=after,
        notes=resolution_summary.strip(),
        request=request,
    )

    logger.info(
        "Incident resolved",
        extra={
            "incident_id": str(incident.id),
            "actor_id": str(actor.id),
        },
    )

    return incident


def close(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    lessons_learned: str,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Close the incident. Requires ``lessons_learned`` (NIST phase 4).

    Must be in RESOLVED status to close (unless already CLOSED — that's
    idempotent). Freezes ``mttr_seconds_finalized``.
    """
    if not lessons_learned or not lessons_learned.strip():
        raise ValidationError(
            message="Lessons learned is required when closing an incident.",
            code="INCIDENT_LESSONS_REQUIRED",
        )

    if incident.status == IncidentStatus.CLOSED:
        return incident  # idempotent

    if incident.status != IncidentStatus.RESOLVED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot close an incident in status "
                f"{incident.status.value}. Must be RESOLVED first."
            ),
            code="INCIDENT_NOT_RESOLVED",
            details={"status": incident.status.value},
        )

    before = _snapshot_state(incident)
    incident.advance_status(
        IncidentStatus.CLOSED,
        by_user_id=actor.id,
        notes="Incident closed",
    )
    incident.lessons_learned = lessons_learned.strip()
    db.flush()
    after = _snapshot_state(incident)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="incident.closed",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        before_state=before,
        after_state=after,
        notes=lessons_learned.strip(),
        request=request,
    )

    logger.info(
        "Incident closed",
        extra={
            "incident_id": str(incident.id),
            "actor_id": str(actor.id),
            "mttr_seconds": incident.mttr_seconds_finalized,
        },
    )

    return incident


# ============================================================================
# STRUCTURED ACTIONS
# ============================================================================

def record_containment_action(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    action: str,
    target: str | None = None,
    result: str = "success",
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Record a containment action (e.g. block IP, isolate device).

    Appends to the incident's ``containment_actions`` JSONB array.
    Audited because containment actions are security-relevant —
    compliance teams review these.
    """
    if not action or not action.strip():
        raise ValidationError(
            message="Containment action description is required.",
            code="INCIDENT_ACTION_REQUIRED",
        )
    if incident.status in (IncidentStatus.CLOSED,):
        raise InvalidStateTransitionError(
            message="Cannot record containment action on a closed incident.",
            code="INCIDENT_CLOSED",
        )

    incident.record_containment_action(
        action=action.strip(),
        target=target.strip() if target else None,
        by_user_id=actor.id,
        result=result,
        notes=notes.strip() if notes else None,
    )
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="incident.containment_action_recorded",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        request=request,
        metadata={
            "action": action.strip(),
            "target": target,
            "result": result,
        },
    )

    return incident


def record_recovery_action(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    action: str,
    target: str | None = None,
    result: str = "success",
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityIncident:
    """
    Record a recovery action (e.g. restore backup, re-enable service).
    """
    if not action or not action.strip():
        raise ValidationError(
            message="Recovery action description is required.",
            code="INCIDENT_ACTION_REQUIRED",
        )
    if incident.status in (IncidentStatus.CLOSED,):
        raise InvalidStateTransitionError(
            message="Cannot record recovery action on a closed incident.",
            code="INCIDENT_CLOSED",
        )

    incident.record_recovery_action(
        action=action.strip(),
        target=target.strip() if target else None,
        by_user_id=actor.id,
        result=result,
        notes=notes.strip() if notes else None,
    )
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="incident.recovery_action_recorded",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        request=request,
        metadata={
            "action": action.strip(),
            "target": target,
            "result": result,
        },
    )

    return incident


# ============================================================================
# EVENT LINKS
# ============================================================================

def link_event(
    db: Session,
    *,
    actor: User,
    incident: SecurityIncident,
    event_id: uuid.UUID,
    link_type: str = "related",
    relevance_score: float | None = None,
    notes: str | None = None,
    request: Any | None = None,
) -> IncidentEventLink:
    """
    Link a specific event to the incident with a type and optional
    relevance score.

    Idempotent by (incident_id, event_id, link_type) — the DB unique
    constraint enforces this, and the check below gives a clean error.
    """
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise ValidationError(
            message=f"Event {event_id} not found.",
            code="EVENT_NOT_FOUND",
        )
    if event.workspace_id != incident.workspace_id:
        raise ValidationError(
            message="Event and incident must be in the same workspace.",
            code="EVENT_WORKSPACE_MISMATCH",
        )

    existing = db.execute(
        select(IncidentEventLink).where(
            IncidentEventLink.incident_id == incident.id,
            IncidentEventLink.event_id == event_id,
            IncidentEventLink.link_type == link_type,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    link = IncidentEventLink(
        incident_id=incident.id,
        event_id=event_id,
        link_type=link_type,
        relevance_score=relevance_score,
        notes=notes.strip() if notes else None,
        added_by_id=actor.id,
    )
    db.add(link)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="incident.event_linked",
        target_type="incident",
        target_id=incident.id,
        workspace_id=incident.workspace_id,
        request=request,
        metadata={
            "event_id": str(event_id),
            "link_type": link_type,
        },
    )

    return link


def unlink_event(
    db: Session,
    *,
    actor: User,
    link: IncidentEventLink,
    request: Any | None = None,
) -> None:
    """Remove an event link."""
    incident_id = link.incident_id
    workspace_id = None
    inc = db.get(SecurityIncident, incident_id)
    if inc is not None:
        workspace_id = inc.workspace_id

    db.delete(link)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="incident.event_unlinked",
        target_type="incident",
        target_id=incident_id,
        workspace_id=workspace_id,
        request=request,
        metadata={"event_id": str(link.event_id)},
    )


# ============================================================================
# SLA MONITORING
# ============================================================================

def check_sla_breaches(
    db: Session,
    *,
    limit: int = 100,
) -> list[SecurityIncident]:
    """
    Return incidents currently past their ``expires_at`` and not yet
    resolved/closed.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")

    now = datetime.now(timezone.utc)
    return list(db.execute(
        select(SecurityIncident)
        .where(
            SecurityIncident.closed_at.is_(None),
            SecurityIncident.resolved_at.is_(None),
            SecurityIncident.expires_at.is_not(None),
            SecurityIncident.expires_at < now,
        )
        .order_by(SecurityIncident.expires_at.asc())
        .limit(limit)
    ).scalars().all())


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "create_incident",
    "get_by_id",
    "list_incidents",
    "find_incident_candidates",
    "advance_status",
    "assign",
    "resolve",
    "close",
    "record_containment_action",
    "record_recovery_action",
    "link_event",
    "unlink_event",
    "check_sla_breaches",
]