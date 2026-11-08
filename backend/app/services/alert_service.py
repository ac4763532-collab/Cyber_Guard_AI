"""
CyberGuard AI — Alert Service
============================================================================

Where findings become user-facing alerts.

The finding → alert pipeline
----------------------------
Findings (File 81) are internal agent output — potentially hundreds per
hour. Alerts are the user-visible notifications — potentially dozens
per day. The gap between them is a **policy decision**, not a filter:

    severity=CRITICAL or HIGH           → always promote
    severity=MEDIUM + confidence ≥ 0.8  → promote
    severity=MEDIUM + confidence < 0.8  → do not promote (analyst review)
    severity=LOW or INFO                → never auto-promote

The thresholds are enforced here, not in the agent. Agents produce
findings at whatever rate their rules fire. This service decides which
findings are worth interrupting a human about.

Thresholds are configurable via ``settings`` — the values above are the
current defaults.

Pattern-level deduplication
---------------------------
Alerts dedupe differently from findings:

    Finding fingerprint  = (workspace, agent_name, rule_id, dedup_hint)
                            — "the same detection rule fired again"

    Alert fingerprint    = (workspace, alert_type, category, severity,
                            source_scope)
                            — "the same *pattern* of problem keeps firing"

The difference matters. Consider a brute-force attack:

    - Log Analysis Agent fires 3 findings:
        finding-1: "6 failed logins from IP-A in 40s"  (rule=failed_login_burst)
        finding-2: "5 failed logins from IP-B in 30s"  (same rule, different IP)
        finding-3: "12 failed logins from IP-A in 120s" (same rule, same IP, longer window)

    With finding-level dedup:
        finding-1 and finding-3 might merge (same IP). Finding-2 stays separate.
        → 2 findings.

    With alert-level dedup (workspace + brute_force category + high severity):
        All 3 findings aggregate into 1 alert: "Brute force against
        workspace-X from 2 IPs (3 findings, 23 attempts)".
        → 1 alert.

The user sees "one problem", not three related symptoms. This is the
cross-source correlation promise from the project vision, made
concrete at the alert layer.

Alert lifecycle
---------------
    NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
                                      → DISMISSED

Terminal statuses cannot transition. A new occurrence of the same
pattern (new finding promoted while alert is still active) merges
into the existing alert — `occurrence_count++`, `finding_ids` union.
If the alert is already resolved, a new occurrence creates a fresh
alert that chains via ``previous_alert_id``.

SLA tracking
------------
Every alert has an SLA deadline derived from severity:

    CRITICAL  → 1 hour
    HIGH      → 4 hours
    MEDIUM    → 24 hours
    LOW       → 72 hours
    INFO      → no SLA

Alerts past their deadline with status still open are SLA-breach
candidates. The UI surfaces these prominently. A background job
(`check_sla_breaches`) can trigger escalation notifications — not
implemented yet, marked with TODO.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. **User actions** (acknowledge, assign, resolve, dismiss) are audited.
   **System actions** (auto-promotion, recurrence merge) are not — they
   would match the finding volume we're trying to reduce.

Notification delegation
-----------------------
After an alert is created or updated, ``notification_service`` should
be called to create per-recipient notifications. Until that service
exists (File 83), this file marks the notification step with
``# TODO: notify via notification_service`` and logs what it *would*
have done. Once File 83 lands, uncomment one block per method.

Public API
----------
    promote_finding(db, *, finding) → SecurityAlert | None
    promote_batch(db, *, findings)  → list[SecurityAlert]

    get_by_id(db, alert_id)         → SecurityAlert
    list_alerts(db, *, workspace_ids, page, filters) → (list, int)

    mark_seen(db, *, actor, alert, request=None) → SecurityAlert
    acknowledge(db, *, actor, alert, request=None) → SecurityAlert
    assign(db, *, actor, alert, assigned_to_id, notes=None, request=None) → SecurityAlert
    start_investigation(db, *, actor, alert, request=None) → SecurityAlert
    resolve(db, *, actor, alert, resolution_notes, request=None) → SecurityAlert
    dismiss(db, *, actor, alert, reason, request=None) → SecurityAlert

    check_sla_breaches(db, *, limit=100) → list[SecurityAlert]

Usage
-----
    from app.services import alert_service

    # Called by agent runtime after finding_service.create_finding
    finding, was_created = finding_service.create_finding(db, dto=dto)
    if was_created or finding.occurrence_count % 10 == 0:
        alert = alert_service.promote_finding(db, finding=finding)
        if alert is not None:
            # Notification is created by alert_service internally
            ...

    # Called by user via PATCH /alerts/{id}/acknowledge
    alert_service.acknowledge(db, actor=analyst, alert=alert, request=request)

    # Called by user via POST /alerts/{id}/resolve
    alert_service.resolve(
        db, actor=analyst, alert=alert,
        resolution_notes="Confirmed brute force; blocked IP.",
    )
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import (
    PERM_ALERT_ACKNOWLEDGE,
    PERM_ALERT_READ,
    PERM_INCIDENT_ASSIGN,
)
from app.core.exceptions import (
    AlertNotFoundError,
    AuthorizationError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.enums import (
    AlertStatus,
    EventSeverity,
    FindingCategory,
)
from app.models.finding import AgentFinding
from app.models.user import User
from app.schemas.alert import AlertFilter
from app.schemas.common import PageParams
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Fingerprint version — bump if algorithm changes.
_ALERT_FP_VERSION = "v1"

#: Promotion thresholds (in addition to the config-driven settings below)
_MIN_CONFIDENCE_FOR_MEDIUM = 0.8

#: SLA deadlines per severity (hours). If exceeded, ``is_sla_breached``
#: returns True.
_SLA_HOURS: dict[EventSeverity, int | None] = {
    EventSeverity.CRITICAL: 1,
    EventSeverity.HIGH: 4,
    EventSeverity.MEDIUM: 24,
    EventSeverity.LOW: 72,
    EventSeverity.INFO: None,  # no SLA
}

#: Status transitions
_ALLOWED_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset({
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.INVESTIGATING,
        AlertStatus.DISMISSED,
    }),
    AlertStatus.ACKNOWLEDGED: frozenset({
        AlertStatus.INVESTIGATING,
        AlertStatus.RESOLVED,
        AlertStatus.DISMISSED,
    }),
    AlertStatus.INVESTIGATING: frozenset({
        AlertStatus.RESOLVED,
        AlertStatus.DISMISSED,
    }),
    AlertStatus.RESOLVED: frozenset(),  # terminal
    AlertStatus.DISMISSED: frozenset(),  # terminal
}

#: Severity rank for max-merge on recurrence.
_SEVERITY_RANK: dict[EventSeverity, int] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}

#: Max findings to merge into one alert (protects DB row size).
_MAX_FINDING_IDS_PER_ALERT = 500


# ============================================================================
# INTERNAL — promotion policy
# ============================================================================

def _should_promote(finding: AgentFinding) -> bool:
    """
    Apply the promotion policy. Returns True if this finding is worth
    interrupting a human about.

    Policy (defaults, overridable via settings):
        CRITICAL severity  → always
        HIGH severity      → always
        MEDIUM + conf≥0.8  → promote
        MEDIUM + conf<0.8  → skip (analyst-only visibility)
        LOW                → skip
        INFO               → skip

    Findings marked as FALSE_POSITIVE are never promoted — even if
    their severity is HIGH. The analyst has already decided.
    """
    if finding.status.value == "false_positive":
        return False

    severity = finding.severity
    confidence = finding.confidence

    if severity == EventSeverity.CRITICAL:
        return True
    if severity == EventSeverity.HIGH:
        return True
    if severity == EventSeverity.MEDIUM:
        return confidence >= _MIN_CONFIDENCE_FOR_MEDIUM
    if severity == EventSeverity.LOW:
        return False
    return False  # INFO


# ============================================================================
# INTERNAL — fingerprint
# ============================================================================

def _compute_alert_fingerprint(
    *,
    workspace_id: uuid.UUID,
    category: FindingCategory,
    severity: EventSeverity,
    source_id: uuid.UUID | None,
) -> str:
    """
    Pattern-level alert fingerprint.

    Different from finding fingerprint — this one deliberately excludes
    agent_name and rule_id. Multiple agents can contribute to the same
    alert (e.g. Log Analysis Agent and Network Analysis Agent both
    detecting brute-force activity), and the user wants one alert per
    pattern, not one alert per agent.

    The ``source_id`` provides scope isolation: findings on different
    sources (different devices) produce separate alerts, because they
    represent independent attack vectors.

    For cross-source alerts (e.g. IOC Correlation Agent produces a
    finding with source_id=None), the fingerprint uses "cross_source"
    as the scope marker — this aggregates across all sources in the
    workspace into one "attack pattern" alert.
    """
    source_scope = str(source_id) if source_id else "cross_source"
    payload = "|".join([
        _ALERT_FP_VERSION,
        str(workspace_id),
        category.value,
        severity.value,
        source_scope,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _derive_alert_type(finding: AgentFinding) -> str:
    """
    Determine the alert_type from the finding.

    Most findings produce ``security`` alerts. Operational findings
    (source down, credential expiring) would be ``operational`` — but
    those are produced by system health monitoring, not the 8 detection
    agents (which all produce security-related output).

    For now, everything from the 8 agents is ``security``.
    """
    return "security"


def _derive_sla_hours(severity: EventSeverity) -> int | None:
    """Get the SLA deadline for the alert's severity."""
    return _SLA_HOURS.get(severity)


# ============================================================================
# INTERNAL — context aggregation for alert
# ============================================================================

def _aggregate_context(findings: list[AgentFinding]) -> dict[str, Any]:
    """
    Build the ``context`` JSONB for an alert from its source findings.

    Includes the union of usernames, source_ips, and hostnames from
    each finding's event set, plus a summary of the most common event
    types. Bounded to avoid runaway JSONB growth.

    The result is what the UI renders as "this alert is about: users
    Alice, Bob; IPs 203.0.113.42, 198.51.100.7; hosts web-01, db-02".
    """
    usernames: set[str] = set()
    source_ips: set[str] = set()
    hostnames: set[str] = set()
    mitre: set[str] = set()

    for finding in findings:
        evidence = finding.evidence or {}
        # Aggregation by convention — agents put these keys in evidence
        for key in ("usernames", "users"):
            for u in evidence.get(key, []) or []:
                if isinstance(u, str) and u:
                    usernames.add(u)
        for key in ("source_ips", "ips", "attacker_ips"):
            for ip in evidence.get(key, []) or []:
                if isinstance(ip, str) and ip:
                    source_ips.add(ip)
        for key in ("hostnames", "hosts"):
            for h in evidence.get(key, []) or []:
                if isinstance(h, str) and h:
                    hostnames.add(h)
        for m in (finding.mitre_techniques or []):
            mitre.add(m)

    ctx: dict[str, Any] = {
        "usernames": sorted(usernames)[:20],
        "source_ips": sorted(source_ips)[:20],
        "hostnames": sorted(hostnames)[:20],
        "mitre_techniques": sorted(mitre)[:20],
        "finding_count": len(findings),
        "agent_names": sorted({f.agent_name for f in findings}),
    }
    return ctx


def _aggregate_recommended_actions(
    findings: list[AgentFinding],
) -> list[dict[str, Any]]:
    """
    Build ``recommended_actions`` for the alert.

    Currently returns a conservative list based on category. A future
    enhancement (Phase I, AI Analyst) will generate smarter per-alert
    recommendations from the evidence.
    """
    if not findings:
        return []

    category = findings[0].category
    actions: list[dict[str, Any]] = []

    if category == FindingCategory.BRUTE_FORCE:
        actions.append({
            "action": "reset_password",
            "target": "affected_users",
            "priority": "high",
            "description": "Reset passwords for targeted accounts.",
        })
        actions.append({
            "action": "block_ip",
            "target": "attacker_ips",
            "priority": "medium",
            "description": "Block the source IPs at the firewall.",
        })
    elif category == FindingCategory.PHISHING:
        actions.append({
            "action": "isolate_email",
            "target": "affected_users",
            "priority": "high",
            "description": "Quarantine suspicious emails and warn recipients.",
        })
    elif category == FindingCategory.PORT_SCAN:
        actions.append({
            "action": "review_firewall",
            "target": "attacker_ips",
            "priority": "medium",
            "description": "Review firewall logs and consider blocking.",
        })
    elif category == FindingCategory.MALWARE:
        actions.append({
            "action": "isolate_device",
            "target": "affected_hosts",
            "priority": "critical",
            "description": "Isolate affected devices from the network.",
        })

    return actions[:5]


# ============================================================================
# PROMOTION
# ============================================================================

def promote_finding(
    db: Session,
    *,
    finding: AgentFinding,
) -> SecurityAlert | None:
    """
    Promote a finding to an alert, if the policy allows.

    Returns the new or updated alert, or ``None`` if the finding did
    not meet the promotion threshold.

    Deduplication: if an active alert already exists for this pattern
    (same workspace + category + severity + source_scope, status not
    RESOLVED/DISMISSED), the finding merges into it — the existing
    alert's ``occurrence_count`` is incremented, ``finding_ids``
    unioned, and ``context``/``recommended_actions`` regenerated.

    If no active alert exists but a *resolved* one does, a new alert
    is created with ``previous_alert_id`` pointing at the old one —
    preserving the attack-pattern history.

    Returns
    -------
    SecurityAlert | None
        ``None`` if the finding did not meet the promotion threshold.
    """
    if not _should_promote(finding):
        return None

    fingerprint = _compute_alert_fingerprint(
        workspace_id=finding.workspace_id,
        category=finding.category,
        severity=finding.severity,
        source_id=finding.source_id,
    )

    # ── Look for an active alert with this pattern
    existing = db.execute(
        select(SecurityAlert).where(
            SecurityAlert.workspace_id == finding.workspace_id,
            SecurityAlert.fingerprint == fingerprint,
            SecurityAlert.resolved_at.is_(None),
        )
    ).scalar_one_or_none()

    if existing is not None:
        # ── Merge into existing alert
        _merge_into_alert(db, existing, finding)
        db.flush()

        logger.debug(
            "Finding merged into existing alert",
            extra={
                "alert_id": str(existing.id),
                "finding_id": str(finding.id),
                "occurrence_count": existing.occurrence_count,
            },
        )
        return existing

    # ── Check for a resolved prior alert (for chain)
    previous = db.execute(
        select(SecurityAlert)
        .where(
            SecurityAlert.workspace_id == finding.workspace_id,
            SecurityAlert.fingerprint == fingerprint,
            SecurityAlert.resolved_at.is_not(None),
        )
        .order_by(SecurityAlert.resolved_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    # ── Create new alert
    alert = _create_alert_from_finding(
        db,
        finding=finding,
        fingerprint=fingerprint,
        previous_alert_id=previous.id if previous else None,
    )

    return alert


def promote_batch(
    db: Session,
    *,
    findings: list[AgentFinding],
) -> list[SecurityAlert]:
    """
    Promote a batch of findings. Returns the list of alerts that were
    created or updated (deduplicated — one entry per alert, not one
    per finding).
    """
    alerts_by_id: dict[uuid.UUID, SecurityAlert] = {}

    for finding in findings:
        alert = promote_finding(db, finding=finding)
        if alert is not None:
            alerts_by_id[alert.id] = alert

    return list(alerts_by_id.values())


def _create_alert_from_finding(
    db: Session,
    *,
    finding: AgentFinding,
    fingerprint: str,
    previous_alert_id: uuid.UUID | None,
) -> SecurityAlert:
    """
    Build and persist a new alert from an initial finding.
    """
    sla_hours = _derive_sla_hours(finding.severity)
    context = _aggregate_context([finding])
    recommended = _aggregate_recommended_actions([finding])

    alert = SecurityAlert.build(
        workspace_id=finding.workspace_id,
        source_id=finding.source_id,
        fingerprint=fingerprint,
        alert_type=_derive_alert_type(finding),
        severity=finding.severity,
        category=finding.category,
        title=_generate_alert_title(finding),
        description=finding.description,
        finding_ids=[str(finding.id)],
        context=context,
        recommended_actions=recommended,
        mitre_techniques=list(finding.mitre_techniques or []),
        sla_hours=sla_hours,
        previous_alert_id=previous_alert_id,
    )
    db.add(alert)
    db.flush()

    # Link the finding → alert (back-reference)
    finding.alert_id = alert.id
    db.flush()

    logger.info(
        "Alert created",
        extra={
            "alert_id": str(alert.id),
            "workspace_id": str(alert.workspace_id),
            "finding_id": str(finding.id),
            "severity": alert.severity.value,
            "category": alert.category.value,
        },
    )

    # TODO: notify via notification_service once File 83 lands:
    #   notification_service.create_for_alert(db, alert=alert)

    return alert


def _merge_into_alert(
    db: Session,
    alert: SecurityAlert,
    finding: AgentFinding,
) -> None:
    """
    Merge a new finding into an existing alert.

    Merge rules:
        - occurrence_count += 1
        - finding_ids: union (capped at _MAX_FINDING_IDS_PER_ALERT)
        - finding_count: updated
        - last_seen_at: bumped
        - severity: max(existing, new) — situation worsened?
        - context: regenerated from all findings — expensive but
          correct (attack picture may have changed)
        - recommended_actions: regenerated
        - status: unchanged — a RESOLVED alert stays RESOLVED until
          the user explicitly reopens; a NEW alert stays NEW
    """
    # Model helper handles count, last_seen_at, finding_ids union
    alert.record_recurrence([str(finding.id)])

    # Severity: max
    existing_rank = _SEVERITY_RANK.get(alert.severity, 0)
    new_rank = _SEVERITY_RANK.get(finding.severity, 0)
    if new_rank > existing_rank:
        alert.severity = finding.severity
        # Extend SLA if severity went up
        new_sla = _derive_sla_hours(finding.severity)
        if new_sla is not None:
            # Recompute expires_at from first_seen_at + new SLA
            first = alert.first_seen_at
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            alert.expires_at = first + timedelta(hours=new_sla)

    # Back-link the finding
    finding.alert_id = alert.id

    # Regenerate context from all findings currently in the alert
    # (bounded — only fetch up to 50 most recent for the aggregate)
    all_findings = _load_findings_for_alert(db, alert, limit=50)
    alert.context = _aggregate_context(all_findings)
    alert.recommended_actions = _aggregate_recommended_actions(all_findings)

    # MITRE union
    all_mitre = set(alert.mitre_techniques or [])
    all_mitre.update(finding.mitre_techniques or [])
    alert.mitre_techniques = sorted(all_mitre)[:50]

    db.flush()


def _load_findings_for_alert(
    db: Session,
    alert: SecurityAlert,
    *,
    limit: int = 50,
) -> list[AgentFinding]:
    """
    Load the findings that make up an alert, capped at ``limit`` for
    context aggregation. Uses ``finding_ids`` (JSONB array of strings).
    """
    if not alert.finding_ids:
        return []

    try:
        finding_uuids = [uuid.UUID(fid) for fid in alert.finding_ids[:limit]]
    except (ValueError, TypeError):
        return []

    return list(db.execute(
        select(AgentFinding).where(AgentFinding.id.in_(finding_uuids))
    ).scalars().all())


def _generate_alert_title(finding: AgentFinding) -> str:
    """
    Generate a user-facing title from a finding.

    Starts from the finding's title (which is already user-oriented)
    and prefixes with the category in a human-friendly way.
    """
    category_labels = {
        FindingCategory.BRUTE_FORCE: "Brute-force activity",
        FindingCategory.PHISHING: "Phishing attempt",
        FindingCategory.MALWARE: "Malware detected",
        FindingCategory.PORT_SCAN: "Port scanning",
        FindingCategory.PRIVILEGE_ESCALATION: "Privilege escalation",
        FindingCategory.SUSPICIOUS_LOGIN: "Suspicious login",
        FindingCategory.DATA_EXFILTRATION: "Possible data exfiltration",
        FindingCategory.CORRELATED_ACTIVITY: "Correlated threat activity",
        FindingCategory.THREAT_INTEL_HIT: "Threat intelligence match",
        FindingCategory.POLICY_VIOLATION: "Security policy violation",
    }
    label = category_labels.get(finding.category, "Security alert")
    finding_title = (finding.title or "").strip()

    # Avoid redundancy if the finding title already starts with the label
    if finding_title.lower().startswith(label.lower()):
        return finding_title[:255]

    if finding_title:
        return f"{label}: {finding_title}"[:255]
    return label


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, alert_id: uuid.UUID) -> SecurityAlert:
    """
    Fetch an alert by ID. Raises ``AlertNotFoundError`` if missing.
    """
    alert = db.get(SecurityAlert, alert_id)
    if alert is None:
        raise AlertNotFoundError(
            message=f"Alert {alert_id} not found.",
            details={"alert_id": str(alert_id)},
        )
    return alert


def list_alerts(
    db: Session,
    *,
    workspace_ids: list[uuid.UUID] | None,
    page: PageParams,
    filters: AlertFilter,
) -> tuple[list[SecurityAlert], int]:
    """
    List alerts with filters and pagination.

    ``workspace_ids`` restricts results to the user's accessible
    workspaces — the same multi-tenant isolation pattern from
    ``finding_service.list_findings``.
    """
    stmt = select(SecurityAlert)

    if workspace_ids is not None:
        stmt = stmt.where(SecurityAlert.workspace_id.in_(workspace_ids))

    # ── Filters
    if filters.alert_type:
        stmt = stmt.where(SecurityAlert.alert_type == filters.alert_type)
    if filters.severity is not None:
        stmt = stmt.where(SecurityAlert.severity == filters.severity)
    if filters.min_severity is not None:
        min_rank = _SEVERITY_RANK.get(filters.min_severity, 0)
        accepted = [
            s for s, r in _SEVERITY_RANK.items() if r >= min_rank
        ]
        if accepted:
            stmt = stmt.where(SecurityAlert.severity.in_(accepted))
    if filters.category is not None:
        stmt = stmt.where(SecurityAlert.category == filters.category)
    if filters.status is not None:
        stmt = stmt.where(SecurityAlert.status == filters.status)
    if filters.assigned_to_id is not None:
        stmt = stmt.where(SecurityAlert.assigned_to_id == filters.assigned_to_id)
    if filters.unassigned_only:
        stmt = stmt.where(SecurityAlert.assigned_to_id.is_(None))
    if filters.source_id is not None:
        stmt = stmt.where(SecurityAlert.source_id == filters.source_id)
    if filters.incident_id is not None:
        stmt = stmt.where(SecurityAlert.incident_id == filters.incident_id)
    if filters.has_incident is not None:
        if filters.has_incident:
            stmt = stmt.where(SecurityAlert.incident_id.is_not(None))
        else:
            stmt = stmt.where(SecurityAlert.incident_id.is_(None))
    if filters.sla_breached is not None:
        now = datetime.now(timezone.utc)
        if filters.sla_breached:
            stmt = stmt.where(
                SecurityAlert.resolved_at.is_(None),
                SecurityAlert.expires_at.is_not(None),
                SecurityAlert.expires_at < now,
            )
        else:
            stmt = stmt.where(
                (SecurityAlert.expires_at.is_(None))
                | (SecurityAlert.expires_at >= now)
            )
    if filters.first_seen_after is not None:
        stmt = stmt.where(SecurityAlert.first_seen_at >= filters.first_seen_after)
    if filters.first_seen_before is not None:
        stmt = stmt.where(SecurityAlert.first_seen_at <= filters.first_seen_before)
    if filters.title_contains:
        stmt = stmt.where(
            SecurityAlert.title.ilike(f"%{filters.title_contains.lower()}%")
        )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            SecurityAlert.first_seen_at.desc(),
            SecurityAlert.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    alerts = list(db.execute(stmt).scalars().all())
    return alerts, int(total)


# ============================================================================
# USER ACTIONS (audited)
# ============================================================================

def mark_seen(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Record that the user opened the alert.

    Not audited individually — ``mark_seen`` fires on every alert open
    and would flood the audit log. It's an engagement signal, not a
    security action. The alert's own ``seen_at`` field is the durable
    record.
    """
    # Permission — must at least have read access (which the caller
    # has already checked to load the alert)
    authorization.check_permission(
        db, actor, PERM_ALERT_READ, workspace_id=alert.workspace_id,
    )

    if alert.seen_at is None:
        alert.mark_seen()
        db.flush()

    return alert


def acknowledge(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Acknowledge the alert. Transitions NEW → ACKNOWLEDGED.

    Acknowledging means "I've seen this and I'm aware". It does NOT
    mean "I'm investigating" — that's ``start_investigation``.

    Idempotent — acknowledging an already-acknowledged alert returns it
    unchanged.
    """
    authorization.check_permission(
        db, actor, PERM_ALERT_ACKNOWLEDGE, workspace_id=alert.workspace_id,
    )

    if alert.status != AlertStatus.NEW:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot acknowledge an alert in status "
                f"{alert.status.value}. Only NEW alerts can be "
                f"acknowledged."
            ),
            code="ALERT_NOT_NEW",
            details={"status": alert.status.value},
        )

    before = {"status": alert.status.value}
    alert.acknowledge()
    db.flush()
    after = {"status": alert.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="alert.acknowledged",
        target_type="alert",
        target_id=alert.id,
        workspace_id=alert.workspace_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return alert


def start_investigation(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Transition to INVESTIGATING. Requires the alert to be in NEW or
    ACKNOWLEDGED status.
    """
    authorization.check_permission(
        db, actor, PERM_ALERT_ACKNOWLEDGE, workspace_id=alert.workspace_id,
    )

    if AlertStatus.INVESTIGATING not in _ALLOWED_TRANSITIONS.get(
        alert.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=(
                f"Cannot start investigation from status "
                f"{alert.status.value}."
            ),
            code="ALERT_INVALID_TRANSITION",
            details={"status": alert.status.value},
        )

    before = {"status": alert.status.value}
    alert.mark_investigating()
    db.flush()
    after = {"status": alert.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="alert.investigation_started",
        target_type="alert",
        target_id=alert.id,
        workspace_id=alert.workspace_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return alert


def assign(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    assigned_to_id: uuid.UUID,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Assign the alert to a user for triage.

    Requires ``PERM_INCIDENT_ASSIGN`` in the workspace scope. The
    target user must be an active member of the workspace — the service
    checks this before assignment.
    """
    authorization.check_permission(
        db, actor, PERM_INCIDENT_ASSIGN, workspace_id=alert.workspace_id,
    )

    # Verify target is an active member of the workspace
    target_role = authorization.get_user_workspace_role(
        db, db.get(User, assigned_to_id), alert.workspace_id,
    )
    if target_role is None:
        raise ValidationError(
            message=(
                "Cannot assign alert to a user who is not an active "
                "member of the workspace."
            ),
            code="ASSIGNEE_NOT_WORKSPACE_MEMBER",
            details={"assigned_to_id": str(assigned_to_id)},
        )

    before = {
        "assigned_to_id": (
            str(alert.assigned_to_id) if alert.assigned_to_id else None
        ),
    }
    alert.assign_to(assigned_to_id)
    db.flush()
    after = {"assigned_to_id": str(assigned_to_id)}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="alert.assigned",
        target_type="alert",
        target_id=alert.id,
        workspace_id=alert.workspace_id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    # TODO: notify assigned user via notification_service (File 83)

    return alert


def resolve(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    resolution_notes: str,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Resolve the alert. Requires resolution notes.

    Cannot resolve from DISMISSED or already-RESOLVED status.
    """
    if not resolution_notes or not resolution_notes.strip():
        raise ValidationError(
            message="Resolution notes are required when resolving an alert.",
            code="ALERT_RESOLUTION_NOTES_REQUIRED",
        )

    authorization.check_permission(
        db, actor, PERM_ALERT_ACKNOWLEDGE, workspace_id=alert.workspace_id,
    )

    if AlertStatus.RESOLVED not in _ALLOWED_TRANSITIONS.get(
        alert.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=f"Cannot resolve alert in status {alert.status.value}.",
            code="ALERT_INVALID_TRANSITION",
            details={"status": alert.status.value},
        )

    before = {"status": alert.status.value}
    alert.resolve(by_user_id=actor.id, notes=resolution_notes.strip())
    db.flush()
    after = {"status": alert.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="alert.resolved",
        target_type="alert",
        target_id=alert.id,
        workspace_id=alert.workspace_id,
        before_state=before,
        after_state=after,
        notes=resolution_notes.strip(),
        request=request,
    )

    logger.info(
        "Alert resolved",
        extra={
            "alert_id": str(alert.id),
            "actor_id": str(actor.id),
        },
    )

    return alert


def dismiss(
    db: Session,
    *,
    actor: User,
    alert: SecurityAlert,
    reason: str,
    request: Any | None = None,
) -> SecurityAlert:
    """
    Dismiss the alert. Requires a reason.

    Distinct from resolve: DISMISSED means "not actionable / duplicate /
    false positive". RESOLVED means "investigated and addressed".
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A dismissal reason is required.",
            code="ALERT_DISMISSAL_REASON_REQUIRED",
        )

    authorization.check_permission(
        db, actor, PERM_ALERT_ACKNOWLEDGE, workspace_id=alert.workspace_id,
    )

    if AlertStatus.DISMISSED not in _ALLOWED_TRANSITIONS.get(
        alert.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=f"Cannot dismiss alert in status {alert.status.value}.",
            code="ALERT_INVALID_TRANSITION",
            details={"status": alert.status.value},
        )

    before = {"status": alert.status.value}
    alert.dismiss(by_user_id=actor.id, notes=reason.strip())
    db.flush()
    after = {"status": alert.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="alert.dismissed",
        target_type="alert",
        target_id=alert.id,
        workspace_id=alert.workspace_id,
        before_state=before,
        after_state=after,
        notes=reason.strip(),
        request=request,
    )

    return alert


# ============================================================================
# SLA MONITORING — background job
# ============================================================================

def check_sla_breaches(
    db: Session,
    *,
    limit: int = 100,
) -> list[SecurityAlert]:
    """
    Return alerts currently in SLA breach (open, past expires_at).

    Called by:
        - A periodic background job that escalates breached alerts
        - The dashboard API (``GET /alerts?filter=sla_breached``)

    Does not modify alerts — the ``is_sla_breached`` property is
    computed, not stored. The job just needs the list to build
    escalation notifications.

    Returns the first ``limit`` alerts by ``expires_at`` ascending
    (longest-breach first).
    """
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")

    now = datetime.now(timezone.utc)
    alerts = list(db.execute(
        select(SecurityAlert)
        .where(
            SecurityAlert.resolved_at.is_(None),
            SecurityAlert.expires_at.is_not(None),
            SecurityAlert.expires_at < now,
        )
        .order_by(SecurityAlert.expires_at.asc())
        .limit(limit)
    ).scalars().all())

    if alerts:
        logger.info(
            "SLA breaches found",
            extra={"count": len(alerts)},
        )

    return alerts


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Promotion
    "promote_finding",
    "promote_batch",
    # Read
    "get_by_id",
    "list_alerts",
    # User actions
    "mark_seen",
    "acknowledge",
    "start_investigation",
    "assign",
    "resolve",
    "dismiss",
    # SLA
    "check_sla_breaches",
]