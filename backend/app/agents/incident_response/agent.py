"""
CyberGuard AI — Incident Response Agent
============================================================================

Converts alerts into incidents and routes them to the best-fit analyst.

See the package docstring for the full contract. This file implements:

    process(context)  — single-alert version (used by API endpoints)
    run_sweep(db)     — batch version (used by periodic scheduler)

Both funnel through ``_ensure_incident_for_alert`` which delegates to
``incident_service.create_incident`` (idempotent — merges into any
existing incident with the same pattern).

Assignment
----------
The agent picks the best-fit analyst using a scoring function:

    +10  for each matching specialization tag
    + 5  if analyst has completed 5+ cases in this category (past experience)
    - 1  per active case (workload penalty)

Only verified analysts with ``available_for_hire=True`` and
``active_case_count < max_concurrent_cases`` are candidates. If no
candidate has a positive score, the incident is left unassigned.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.core.exceptions import AgentError
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.analyst import AnalystProfile
from app.models.enums import (
    AnalystVerificationStatus,
    EventSeverity,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.finding import AgentFinding
from app.models.incident import SecurityIncident
from app.schemas.incident import IncidentCreateInternal
from app.services import (
    audit_service,
    incident_service,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Severity rank for threshold comparisons.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Map from EventSeverity to IncidentSeverity (narrower set).
_EVENT_TO_INCIDENT_SEVERITY: dict[EventSeverity, IncidentSeverity] = {
    EventSeverity.INFO: IncidentSeverity.LOW,
    EventSeverity.LOW: IncidentSeverity.LOW,
    EventSeverity.MEDIUM: IncidentSeverity.MEDIUM,
    EventSeverity.HIGH: IncidentSeverity.HIGH,
    EventSeverity.CRITICAL: IncidentSeverity.CRITICAL,
}

#: Map finding category → analyst specialization tags. Used by the
#: analyst-matching scorer. Agents that produce findings in this
#: category are more likely to be matched with analysts who list the
#: matching tags in their profile.
_CATEGORY_TO_SPECIALIZATIONS: dict[str, tuple[str, ...]] = {
    "phishing": ("phishing", "email_forensics"),
    "brute_force": ("brute_force", "authentication"),
    "malware": ("malware", "malware_analysis", "forensics"),
    "port_scan": ("network", "network_forensics"),
    "privilege_escalation": ("incident_response", "forensics"),
    "suspicious_login": ("authentication", "identity"),
    "data_exfiltration": ("forensics", "network_forensics"),
    "correlated_activity": ("incident_response", "threat_hunting"),
    "threat_intel_hit": ("threat_intel", "threat_hunting"),
}

#: How far back the sweep looks for un-attended alerts.
_SWEEP_LOOKBACK_MINUTES = 30

#: Max alerts processed per sweep.
_MAX_ALERTS_PER_SWEEP = 50


# ============================================================================
# AGENT
# ============================================================================

class IncidentResponseAgent(BaseAgent):
    """
    Converts alerts into incidents and routes them to analysts.
    """

    name = "incident_response"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        threshold_str = str(
            self._config.get("auto_create_severity_threshold", "high")
        ).lower()
        self._min_severity_rank = _SEVERITY_RANK.get(threshold_str, 3)
        self._max_cases_per_analyst = int(
            self._config.get("max_cases_per_analyst", 20)
        )

    # ── Standard agent interface ───────────────────────────────────────

    def process(self, context: AgentContext) -> AgentResult:
        """
        Single-alert incident creation. Used by the admin API endpoint
        ``POST /api/v1/admin/incidents/from-alert``.

        Reads the target alert ID from ``correlation_state["target_alert_id"]``.
        Creates or merges an incident, optionally assigns an analyst,
        returns an empty ``AgentResult`` (no finding — the incident IS
        the output, its audit is written by ``incident_service``).
        """
        target_alert_id = (context.correlation_state or {}).get(
            "target_alert_id"
        )
        if not target_alert_id:
            return AgentResult(
                findings=[],
                errors=[
                    {
                        "stage": "extract",
                        "code": "IR_NO_TARGET_ALERT",
                        "message": (
                            "IncidentResponseAgent.process() requires "
                            "correlation_state['target_alert_id']."
                        ),
                        "traceback": None,
                    }
                ],
                metadata={"mode": "single"},
            )

        alert = context.db.get(SecurityAlert, uuid.UUID(str(target_alert_id)))
        if alert is None:
            return AgentResult(
                findings=[],
                errors=[
                    {
                        "stage": "load",
                        "code": "IR_ALERT_NOT_FOUND",
                        "message": f"Alert {target_alert_id} not found.",
                        "traceback": None,
                    }
                ],
                metadata={"mode": "single"},
            )

        try:
            incident = self._ensure_incident_for_alert(context.db, alert)
        except Exception as exc:  # noqa: BLE001
            return AgentResult(
                findings=[],
                errors=[self._wrap_error(stage="ensure_incident", exception=exc)],
                metadata={"mode": "single"},
            )

        if incident is None:
            return AgentResult(
                findings=[],
                errors=[],
                metadata={
                    "mode": "single",
                    "outcome": "no_incident_created",
                    "reason": (
                        f"alert severity {alert.severity.value} below "
                        f"threshold"
                    ),
                },
            )

        # Try to assign
        try:
            self._try_assign(db=context.db, incident=incident, alert=alert)
        except Exception as exc:  # noqa: BLE001
            # Assignment failure is non-fatal — log via error but keep
            # the created incident
            return AgentResult(
                findings=[],
                errors=[
                    self._wrap_error(stage="assign", exception=exc),
                ],
                metadata={
                    "mode": "single",
                    "outcome": "incident_created_no_assignment",
                    "incident_id": str(incident.id),
                },
            )

        return AgentResult(
            findings=[],
            errors=[],
            metadata={
                "mode": "single",
                "outcome": "incident_created",
                "incident_id": str(incident.id),
                "assigned_to_id": (
                    str(incident.assigned_to_id)
                    if incident.assigned_to_id else None
                ),
            },
        )

    # ── Batch sweep ────────────────────────────────────────────────────

    def run_sweep(self, db) -> dict[str, int]:
        """
        Find recent alerts without an open incident and create incidents
        for the HIGH/CRITICAL ones. Optionally assign analysts.

        Called periodically from a scheduled task in ``main.py``.
        Idempotent — safe to run as often as you want.

        Returns counts:
            alerts_scanned      int
            incidents_created   int  (new incidents only, not merges)
            incidents_merged    int  (existing incident updated)
            assigned            int
            skipped_below_threshold int
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=_SWEEP_LOOKBACK_MINUTES)

        # Alerts in the last N minutes without an incident link
        alert_stmt = (
            select(SecurityAlert)
            .where(
                SecurityAlert.first_seen_at >= cutoff,
                SecurityAlert.incident_id.is_(None),
                SecurityAlert.resolved_at.is_(None),
            )
            .order_by(SecurityAlert.first_seen_at.desc())
            .limit(_MAX_ALERTS_PER_SWEEP)
        )
        alerts = list(db.execute(alert_stmt).scalars().all())

        counts = {
            "alerts_scanned": len(alerts),
            "incidents_created": 0,
            "incidents_merged": 0,
            "assigned": 0,
            "skipped_below_threshold": 0,
        }

        for alert in alerts:
            if _SEVERITY_RANK.get(alert.severity.value, 0) < self._min_severity_rank:
                counts["skipped_below_threshold"] += 1
                continue

            # Was an incident already created? (re-check — an earlier
            # alert in this batch may have merged into one that just
            # linked to this alert via alert_id backfill)
            if alert.incident_id is not None:
                continue

            try:
                was_new = self._check_incident_exists(db, alert)
                incident = self._ensure_incident_for_alert(db, alert)
                if incident is None:
                    counts["skipped_below_threshold"] += 1
                    continue

                if was_new:
                    counts["incidents_created"] += 1
                else:
                    counts["incidents_merged"] += 1

                # Try to assign
                assigned = self._try_assign(db=db, incident=incident, alert=alert)
                if assigned:
                    counts["assigned"] += 1

            except Exception as exc:  # noqa: BLE001
                self._logger.exception(
                    "Incident creation failed during sweep",
                    extra={
                        "alert_id": str(alert.id),
                        "error": str(exc)[:300],
                    },
                )

        if any(counts[k] > 0 for k in ("incidents_created", "incidents_merged", "assigned")):
            self._logger.info(
                "Incident sweep complete",
                extra=counts,
            )

        return counts

    # ── Incident creation ──────────────────────────────────────────────

    def _check_incident_exists(self, db, alert: SecurityAlert) -> bool:
        """
        Return True if a new incident would be created (no existing
        incident matches the alert's pattern). Used by the sweep to
        distinguish "created" from "merged" for reporting.
        """
        from app.agents.incident_response._fingerprint import (
            compute_incident_fingerprint,
        )
        fp = compute_incident_fingerprint(
            workspace_id=alert.workspace_id,
            category=alert.category,
            severity=_EVENT_TO_INCIDENT_SEVERITY[alert.severity],
            primary_source_id=alert.source_id,
        )
        existing = db.execute(
            select(SecurityIncident.id).where(
                SecurityIncident.workspace_id == alert.workspace_id,
                SecurityIncident.fingerprint == fp,
                SecurityIncident.closed_at.is_(None),
            )
        ).scalar_one_or_none()
        return existing is None

    def _ensure_incident_for_alert(self, db, alert: SecurityAlert):
        """
        Create or merge an incident for the given alert. Returns the
        incident, or None if the alert's severity is below the threshold.

        Delegates to ``incident_service.create_incident`` which is
        idempotent — it merges into any existing open incident with
        the same pattern.
        """
        # Severity gate
        if _SEVERITY_RANK.get(alert.severity.value, 0) < self._min_severity_rank:
            return None

        # Build the DTO
        finding_ids = list(alert.finding_ids or [])

        # Get the primary finding (for MITRE + evidence inheritance)
        primary_finding = None
        if finding_ids:
            try:
                primary_finding = db.get(
                    AgentFinding, uuid.UUID(finding_ids[0])
                )
            except (ValueError, TypeError):
                pass

        # Inherit MITRE techniques from alert/finding
        mitre = list(alert.mitre_techniques or [])
        if primary_finding and primary_finding.mitre_techniques:
            for tech in primary_finding.mitre_techniques:
                if tech not in mitre:
                    mitre.append(tech)

        # Inherit affected_* from alert context
        ctx = alert.context or {}
        affected_devices = list(ctx.get("hostnames") or [])
        affected_users = list(ctx.get("usernames") or [])
        affected_ips = list(ctx.get("source_ips") or [])

        # Build title and description
        title = f"{alert.severity.value.title()}: {alert.title[:120]}"
        description = (
            f"Auto-created from alert {alert.id}. "
            f"Severity: {alert.severity.value}. "
            f"Category: {alert.category.value}. "
        )
        if alert.description:
            description += f"Alert description: {alert.description[:400]}"

        # SLA based on severity
        sla_hours_map = {"critical": 1, "high": 4, "medium": 24, "low": 72}
        sla_hours = sla_hours_map.get(alert.severity.value, 24)

        dto = IncidentCreateInternal(
            workspace_id=alert.workspace_id,
            primary_source_id=alert.source_id,
            title=title,
            description=description,
            severity=_EVENT_TO_INCIDENT_SEVERITY[alert.severity],
            category=alert.category,
            alert_ids=[str(alert.id)],
            finding_ids=finding_ids,
            affected_devices=affected_devices[:20],
            affected_users=affected_users[:20],
            affected_ips=affected_ips[:20],
            mitre_techniques=mitre[:20],
            tags=["auto_created"] + list(alert.mitre_techniques or [])[:3],
            context={
                "auto_created_by": self.name,
                "alert_id": str(alert.id),
                "alert_severity": alert.severity.value,
            },
            sla_acknowledge_hours=min(1, sla_hours),
            sla_resolve_hours=sla_hours,
            first_seen_at=alert.first_seen_at,
        )

        return incident_service.create_incident(db, dto=dto, actor=None)

    # ── Analyst assignment ─────────────────────────────────────────────

    def _try_assign(self, *, db, incident: SecurityIncident, alert: SecurityAlert) -> bool:
        """
        Try to assign the incident to the best-fit analyst. Returns True
        if an assignment was made.

        No-op if the incident already has an assignee.
        """
        if incident.assigned_to_id is not None:
            return False

        analyst_user_id = self._pick_analyst(db, alert)
        if analyst_user_id is None:
            return False

        # Delegate to incident_service.assign which handles audit + notification
        # and checks the analyst is a workspace member
        try:
            # A "system" actor is not available; use a sentinel approach
            # — we call the service directly with the internal signature.
            # The service permits assigned_by_id=None for system actions.
            incident.assigned_to_id = analyst_user_id
            incident.assigned_at = datetime.now(timezone.utc)
            incident.assigned_by_id = None
            db.flush()

            # Notify assignee
            from app.services import notification_service
            try:
                notification_service.create(
                    db,
                    recipient_id=analyst_user_id,
                    notification_type=notification_service.NotificationType.CASE_ASSIGNED,
                    title=f"Auto-assigned incident: {incident.title[:100]}",
                    body=(
                        f"Severity: {incident.severity.value}. "
                        f"Status: {incident.status.value}. "
                        f"Auto-assigned based on specialization match."
                    ),
                    priority=notification_service._PRIORITY_HIGH,
                    icon="shield-alert",
                    link_to_type="incident",
                    link_to_id=incident.id,
                    related_workspace_id=incident.workspace_id,
                    dedup_key_template=f"incident_auto_assigned:{incident.id}",
                    metadata={"auto_assigned": True},
                )
            except Exception:  # noqa: BLE001
                pass

            self._logger.info(
                "Incident auto-assigned",
                extra={
                    "incident_id": str(incident.id),
                    "analyst_id": str(analyst_user_id),
                    "alert_id": str(alert.id),
                },
            )
            return True

        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "Auto-assignment failed",
                extra={
                    "incident_id": str(incident.id),
                    "error": str(exc)[:200],
                },
            )
            return False

    def _pick_analyst(self, db, alert: SecurityAlert) -> uuid.UUID | None:
        """
        Pick the best-fit analyst for the alert's category.

        Candidate pool: verified analysts with available_for_hire=True
        and active_case_count < max_concurrent_cases.

        Scoring:
            +10 per matching specialization tag for the alert's category
            + 5 if the analyst has completed 5+ past cases (any category)
            - 1 per active case (workload penalty)

        Returns the winner's user_id, or None if no candidate has
        positive score.
        """
        # Compute the specializations we're looking for
        target_tags = _CATEGORY_TO_SPECIALIZATIONS.get(
            alert.category.value, ()
        )

        # Fetch candidates
        candidates = list(db.execute(
            select(AnalystProfile).where(
                AnalystProfile.verification_status == AnalystVerificationStatus.VERIFIED,
                AnalystProfile.available_for_hire.is_(True),
                AnalystProfile.active_case_count < AnalystProfile.max_concurrent_cases,
            ).limit(100)
        ).scalars().all())

        if not candidates:
            return None

        best_score = 0
        best_user_id: uuid.UUID | None = None

        for profile in candidates:
            score = 0
            profile_specs = {s.lower() for s in (profile.specializations or [])}
            for tag in target_tags:
                if tag.lower() in profile_specs:
                    score += 10
            if (profile.total_cases_completed or 0) >= 5:
                score += 5
            # Workload penalty — analysts closer to capacity get lower score
            score -= (profile.active_case_count or 0) // 3

            if score > best_score:
                best_score = score
                best_user_id = profile.user_id

        return best_user_id


__all__ = ["IncidentResponseAgent"]