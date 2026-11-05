"""Create or update incidents from qualifying findings, alerts, and correlations; never execute response actions."""

from hashlib import sha256
from typing import Any
from datetime import datetime, timezone

from app.agents.base import AgentResult, AgentType, BaseAgent, Finding as AgentFinding, Severity
from app.database.models.incidents import IncidentCreate, IncidentStatus
from app.database.repositories.findings import get_finding_repository
from app.database.repositories.incidents import get_incident_repository
from app.database.repositories.alerts import get_alert_repository
from app.database.repositories.correlated_activities import CorrelatedActivityRepository
from app.correlation.realtime import CorrelatedActivity

_QUALIFYING_SEVERITIES = {"critical", "high"}
_INCIDENT_STATUSES = {s.value for s in IncidentStatus}


class IncidentResponseAgent(BaseAgent):
    """Create or update incidents from tenant-authorized qualifying findings, alerts, and correlations."""

    agent_type = AgentType.INCIDENT_RESPONSE
    agent_name = "Incident Response Agent"
    agent_version = "1.1.0"

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        # Support multiple input types: finding_id, alert_ids, correlation_ids
        finding_id = data.get("finding_id")
        alert_ids = data.get("alert_ids")
        correlation_ids = data.get("correlation_ids")
        tenant_id = data.get("tenant_id")

        if not isinstance(tenant_id, str) or not tenant_id.strip():
            return False, "tenant_id is required"

        # At least one evidence source must be provided
        if not finding_id and not alert_ids and not correlation_ids:
            return False, "At least one of finding_id, alert_ids, or correlation_ids is required"

        if finding_id and (not isinstance(finding_id, str) or not finding_id.strip()):
            return False, "finding_id must be a non-empty string"
        if alert_ids and (not isinstance(alert_ids, list) or not alert_ids):
            return False, "alert_ids must be a non-empty list"
        if correlation_ids and (not isinstance(correlation_ids, list) or not correlation_ids):
            return False, "correlation_ids must be a non-empty list"

        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        tenant_id = data["tenant_id"].strip()
        finding_id = data.get("finding_id", "").strip() if data.get("finding_id") else None
        alert_ids = data.get("alert_ids", []) if data.get("alert_ids") else []
        correlation_ids = data.get("correlation_ids", []) if data.get("correlation_ids") else []

        finding_repo = get_finding_repository()
        alert_repo = get_alert_repository()
        incident_repo = get_incident_repository()

        # Collect evidence
        evidence_findings: list[Any] = []
        evidence_alerts: list[Any] = []
        evidence_correlations: list[Any] = []
        finding_ids: list[str] = []
        alert_ids_resolved: list[str] = []
        event_ids: list[str] = []
        correlation_ids_resolved: list[str] = []
        recommendations: list[str] = []
        max_severity = "info"
        max_risk_score = 0

        # Load finding if provided
        if finding_id:
            finding = await finding_repo.get(finding_id, tenant_ids=[tenant_id])
            if finding is None:
                return self._create_error_result("Finding was not found in the authorized tenant.")
            evidence_findings.append(finding)
            finding_ids.append(finding.id)
            if finding.event_id:
                event_ids.append(finding.event_id)
            severity = getattr(finding.severity, "value", str(finding.severity)).lower()
            if self._severity_rank(severity) > self._severity_rank(max_severity):
                max_severity = severity
            if finding.risk_score:
                max_risk_score = max(max_risk_score, finding.risk_score)

        # Load alerts if provided
        for aid in alert_ids:
            alert = await alert_repo.get(aid, tenant_ids=[tenant_id])
            if alert is None:
                continue  # Silently skip missing alerts
            evidence_alerts.append(alert)
            alert_ids_resolved.append(alert.id)
            if alert.event_id:
                event_ids.append(alert.event_id)
            for fid in alert.finding_ids:
                if fid not in finding_ids:
                    finding_ids.append(fid)
            severity = getattr(alert.severity, "value", str(alert.severity)).lower()
            if self._severity_rank(severity) > self._severity_rank(max_severity):
                max_severity = severity
            if alert.risk_score:
                max_risk_score = max(max_risk_score, alert.risk_score)

        # Load correlations if provided
        if correlation_ids:
            from app.database.connection import get_database
            repo = CorrelatedActivityRepository(db=get_database())
            for cid in correlation_ids:
                activity = await repo.get_by_correlation_id(cid, tenant_id)
                if activity is None:
                    continue
                evidence_correlations.append(activity)
                correlation_ids_resolved.append(activity["correlation_id"])
                for fid in activity.get("finding_ids", []):
                    if fid not in finding_ids:
                        finding_ids.append(fid)
                for eid in activity.get("event_ids", []):
                    if eid not in event_ids:
                        event_ids.append(eid)
                if activity.get("risk_score", 0) > max_risk_score:
                    max_risk_score = activity["risk_score"]
                corr_severity = self._risk_to_severity(activity.get("risk_score", 0))
                if self._severity_rank(corr_severity) > self._severity_rank(max_severity):
                    max_severity = corr_severity

        if not evidence_findings and not evidence_alerts and not evidence_correlations:
            return self._create_error_result("No valid evidence found in the authorized tenant.")

        # Determine if this qualifies for incident creation
        qualifies = max_severity in _QUALIFYING_SEVERITIES

        if not qualifies:
            return AgentResult(
                agent_type=self.agent_type,
                agent_version=self.agent_version,
                classification="not_qualified",
                severity=Severity.INFO,
                confidence=1.0,
                risk_score=0,
                findings=[],
                indicators=[],
                summary=f"Evidence severity {max_severity} does not meet the incident policy (high or critical).",
                recommendations=["Monitor the evidence; escalate if severity increases."],
                metadata={
                    "finding_ids": finding_ids,
                    "alert_ids": alert_ids_resolved,
                    "correlation_ids": correlation_ids_resolved,
                    "event_ids": event_ids,
                    "policy": "high_or_critical",
                    "max_severity": max_severity,
                },
                data_source="persisted_evidence",
            )

        # Generate fingerprint for deduplication
        fingerprint = self._generate_fingerprint(tenant_id, finding_ids, alert_ids_resolved, correlation_ids_resolved)

        # Generate recommendations
        recommendations = self._generate_recommendations(evidence_findings, evidence_alerts, evidence_correlations)

        # Create or update incident
        incident = await incident_repo.create_or_update_from_finding(
            IncidentCreate(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                title=self._generate_title(evidence_findings, evidence_alerts, evidence_correlations)[:500],
                description=self._generate_description(evidence_findings, evidence_alerts, evidence_correlations),
                severity=max_severity,
                finding_id=finding_ids[0] if finding_ids else (alert_ids_resolved[0] if alert_ids_resolved else correlation_ids_resolved[0]),
                event_id=event_ids[0] if event_ids else finding_ids[0] if finding_ids else "",
                recommendations=recommendations,
                created_by=data.get("actor_id"),
            )
        )

        agent_severity = Severity.CRITICAL if max_severity == "critical" else Severity.HIGH
        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification="incident_open" if incident.status == "open" else incident.status,
            severity=agent_severity,
            confidence=1.0,
            risk_score=100 if max_severity == "critical" else 75,
            findings=[
                AgentFinding(
                    name=f"Incident {incident.status}: {incident.title}",
                    description=f"Incident linked to {len(finding_ids)} finding(s), {len(alert_ids_resolved)} alert(s), {len(correlation_ids_resolved)} correlation(s).",
                    severity=agent_severity,
                    confidence=1.0,
                    evidence=[
                        f"Finding IDs: {', '.join(finding_ids[:5])}" if finding_ids else "",
                        f"Alert IDs: {', '.join(alert_ids_resolved[:5])}" if alert_ids_resolved else "",
                        f"Correlation IDs: {', '.join(correlation_ids_resolved[:5])}" if correlation_ids_resolved else "",
                        f"Max severity: {max_severity}",
                        f"Risk score: {max_risk_score}",
                    ],
                    recommendations=recommendations,
                    metadata={
                        "incident_id": incident.id,
                        "finding_ids": incident.finding_ids,
                        "alert_ids": incident.alert_ids,
                        "event_ids": incident.event_ids,
                        "correlation_ids": incident.correlation_ids,
                        "incident_status": incident.status,
                        "actions_executed": False,
                    },
                )
            ],
            indicators=[],
            summary=f"Evidence linked to incident {incident.id} ({incident.status}).",
            recommendations=recommendations,
            metadata={
                "incident_id": incident.id,
                "finding_ids": incident.finding_ids,
                "alert_ids": incident.alert_ids,
                "event_ids": incident.event_ids,
                "correlation_ids": incident.correlation_ids,
                "incident_status": incident.status,
                "actions_executed": False,
            },
            data_source="persisted_evidence",
        )

    def _severity_rank(self, severity: str) -> int:
        ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return ranks.get(severity.lower(), 0)

    def _risk_to_severity(self, risk_score: int) -> str:
        if risk_score >= 75:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 25:
            return "medium"
        elif risk_score > 0:
            return "low"
        return "info"

    def _generate_fingerprint(
        self,
        tenant_id: str,
        finding_ids: list[str],
        alert_ids: list[str],
        correlation_ids: list[str],
    ) -> str:
        """Generate a deterministic fingerprint for incident deduplication."""
        # Use sorted, stable IDs
        all_ids = sorted(finding_ids) + sorted(alert_ids) + sorted(correlation_ids)
        content = f"{tenant_id}:{':'.join(all_ids)}"
        return sha256(content.encode()).hexdigest()

    def _generate_title(
        self,
        findings: list[Any],
        alerts: list[Any],
        correlations: list[Any],
    ) -> str:
        parts = []
        if findings:
            parts.append(f"{len(findings)} finding(s)")
        if alerts:
            parts.append(f"{len(alerts)} alert(s)")
        if correlations:
            parts.append(f"{len(correlations)} correlation(s)")
        if not parts:
            return "Security Incident"
        return f"Incident from {', '.join(parts)}"

    def _generate_description(
        self,
        findings: list[Any],
        alerts: list[Any],
        correlations: list[Any],
    ) -> str:
        lines = []
        if findings:
            lines.append("Findings:")
            for f in findings[:5]:
                lines.append(f"  - {f.title} ({f.severity})")
            if len(findings) > 5:
                lines.append(f"  ... and {len(findings) - 5} more")
        if alerts:
            lines.append("Alerts:")
            for a in alerts[:5]:
                lines.append(f"  - {a.title} ({a.severity})")
            if len(alerts) > 5:
                lines.append(f"  ... and {len(alerts) - 5} more")
        if correlations:
            lines.append("Correlations:")
            for c in correlations[:3]:
                lines.append(f"  - {c.get('correlation_type', 'unknown')} (risk: {c.get('risk_score', 0)})")
        return "\n".join(lines) if lines else "Security incident created from qualifying evidence."

    def _generate_recommendations(
        self,
        findings: list[Any],
        alerts: list[Any],
        correlations: list[Any],
    ) -> list[str]:
        recommendations = [
            "Review all linked findings, alerts, and correlations for this incident.",
            "Investigate the affected assets, accounts, and indicators.",
            "Validate the evidence and determine the scope of impact.",
        ]

        # Add evidence-specific recommendations
        for f in findings:
            evidence = f.evidence or {}
            if evidence.get("user") or evidence.get("users"):
                recommendations.append("Review related authentication activity for the affected account(s).")
            if evidence.get("host") or evidence.get("hostname"):
                recommendations.append("Inspect the affected host(s) and recent security events.")
            if evidence.get("source_ip") or evidence.get("ips"):
                recommendations.append("Review related network activity for the observed IP indicator(s).")

        for a in alerts:
            if a.mitre_techniques:
                techniques = ", ".join(a.mitre_techniques[:3])
                recommendations.append(f"Review MITRE ATT&CK techniques: {techniques}")

        for c in correlations:
            corr_type = c.get("correlation_type", "")
            if corr_type == "ioc_based":
                recommendations.append("Shared IOCs detected - check for lateral movement.")
            elif corr_type == "cross_source":
                recommendations.append("Cross-source correlation confirmed - investigate attack chain.")
            elif corr_type == "user_based":
                recommendations.append("Same user involved across events - review account compromise indicators.")

        # Deduplicate while preserving order
        seen = set()
        unique_recs = []
        for r in recommendations:
            if r not in seen:
                seen.add(r)
                unique_recs.append(r)

        return unique_recs[:10]
