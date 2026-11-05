"""Generate bounded security reports from persisted, authorized records."""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from app.agents.base import AgentResult, AgentType, BaseAgent, Severity
from app.database.models import FindingQuery, ReportFormat, ReportStatus, Report as DBReport
from app.database.repositories.alerts import get_alert_repository
from app.database.repositories.events import get_event_repository
from app.database.repositories.findings import get_finding_repository
from app.database.repositories.incidents import get_incident_repository
from app.database.repositories.reports import get_report_repository
from app.llm.client import get_llm_client

_REPORT_LIMIT = 1000
_OPEN_ALERT_STATUSES = {"new", "acknowledged", "investigating"}
_VALID_REPORT_TYPES = {
    "summary", "threat_landscape", "incident_investigation", "correlation", "executive"
}


class ReportingAgent(BaseAgent):
    """Dispatcher agent for persisted activity and threat-landscape reports."""

    agent_type = AgentType.REPORTING
    agent_name = "Reporting Agent"
    agent_version = "1.2.0"

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        report_type = data.get("report_type")
        if report_type not in _VALID_REPORT_TYPES:
            return False, f"report_type must be one of: {', '.join(sorted(_VALID_REPORT_TYPES))}"

        tenant_ids = data.get("tenant_ids")
        if tenant_ids is not None and (
            not isinstance(tenant_ids, list)
            or any(not isinstance(tenant_id, str) or not tenant_id.strip() for tenant_id in tenant_ids)
        ):
            return False, "tenant_ids must be a list of non-empty strings or null"

        if report_type == "summary":
            hours = data.get("hours", 24)
            if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 720:
                return False, "hours must be an integer from 1 to 720"

        if report_type == "incident_investigation":
            incident_id = data.get("incident_id")
            if not incident_id or not isinstance(incident_id, str) or not incident_id.strip():
                return False, "incident_id is required for incident_investigation reports"

        if report_type == "correlation":
            correlation_ids = data.get("correlation_ids")
            if not correlation_ids or not isinstance(correlation_ids, list) or len(correlation_ids) < 1:
                return False, "correlation_ids must be a non-empty list for correlation reports"

        export_format = data.get("export_format")
        if export_format and export_format not in {f.value for f in ReportFormat}:
            return False, f"export_format must be one of: {', '.join(f.value for f in ReportFormat)}"

        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        report_type = data["report_type"]
        tenant_ids = data.get("tenant_ids")

        if report_type == "summary":
            report = await self._build_summary(data)
        elif report_type == "threat_landscape":
            report = await self._build_threat_landscape(data)
        elif report_type == "incident_investigation":
            report = await self._build_incident_investigation(data)
        elif report_type == "correlation":
            report = await self._build_correlation_report(data)
        elif report_type == "executive":
            report = await self._build_executive_report(data)
        else:
            report = await self._build_summary(data)

        export_format = data.get("export_format")
        if export_format:
            report["export_format"] = export_format
            if export_format == ReportFormat.PDF.value:
                report["export_data"] = await self._export_pdf(report)
            elif export_format == ReportFormat.CSV.value:
                report["export_data"] = await self._export_csv(report)

        if data.get("persist", False) and tenant_ids:
            await self._persist_report(report, tenant_ids[0], data)

        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification="generated",
            severity=Severity.INFO,
            confidence=0.0,
            risk_score=0,
            findings=[],
            indicators=[],
            summary=(
                "Report generated from persisted records."
                if report["data_complete"]
                else "Report generated from persisted records, but the retrieval limit may have truncated the data."
            ),
            recommendations=[],
            metadata={"report": report, "confidence_applicable": False},
            data_source="postgresql",
        )

    async def _load_records(
        self,
        *,
        tenant_ids: list[str] | None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> tuple[list[Any], list[Any], list[Any]]:
        events = await get_event_repository().list(
            limit=_REPORT_LIMIT,
            start_time=start_time,
            end_time=end_time,
            tenant_ids=tenant_ids,
        )
        alerts = await get_alert_repository().list(
            limit=_REPORT_LIMIT,
            start_time=start_time,
            end_time=end_time,
            tenant_ids=tenant_ids,
        )
        findings = await get_finding_repository().list(
            FindingQuery(
                limit=_REPORT_LIMIT,
                tenant_ids=tenant_ids,
                start_time=start_time,
                end_time=end_time,
            )
        )
        return events, alerts, findings

    async def _build_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(hours=data.get("hours", 24))
        events, alerts, findings = await self._load_records(
            tenant_ids=data.get("tenant_ids"),
            start_time=period_start,
            end_time=now,
        )

        events_by_type: dict[str, int] = {}
        events_by_severity: dict[str, int] = {}
        total_risk = 0
        max_risk = 0
        for event in events:
            event_type = getattr(event.event_type, "value", str(event.event_type))
            severity = getattr(event.severity, "value", str(event.severity))
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
            events_by_severity[severity] = events_by_severity.get(severity, 0) + 1
            risk = event.risk_score or 0
            total_risk += risk
            max_risk = max(max_risk, risk)

        alerts_by_severity: dict[str, int] = {}
        alerts_by_status: dict[str, int] = {}
        for alert in alerts:
            severity = getattr(alert.severity, "value", str(alert.severity))
            status = getattr(alert.status, "value", str(alert.status))
            alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
            alerts_by_status[status] = alerts_by_status.get(status, 0) + 1

        findings_by_severity: dict[str, int] = {}
        rule_matches = 0
        ioc_matches = 0
        anomalies_detected = 0
        for finding in findings:
            severity = getattr(finding.severity, "value", str(finding.severity))
            finding_type = str(finding.finding_type).lower()
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            rule_matches += int(finding.rule_id is not None)
            ioc_matches += int(finding_type in {"ioc", "ioc_match"})
            anomalies_detected += int(finding_type in {"anomaly", "anomalous"})

        mitre_counts: dict[str, int] = {}
        for alert in alerts:
            for technique in alert.mitre_techniques or []:
                mitre_counts[technique] = mitre_counts.get(technique, 0) + 1

        complete = all(len(rows) < _REPORT_LIMIT for rows in (events, alerts, findings))
        limitations = [] if complete else [
            f"At least one source returned {_REPORT_LIMIT} records; additional matching records may be omitted."
        ]
        critical = findings_by_severity.get("critical", 0)
        high = findings_by_severity.get("high", 0)

        if data.get("include_narrative", False):
            narrative = await self._generate_narrative(
                "summary",
                {
                    "period_start": period_start.isoformat(),
                    "period_end": now.isoformat(),
                    "total_events": len(events),
                    "total_findings": len(findings),
                    "total_alerts": len(alerts),
                    "critical_findings": critical,
                    "high_findings": high,
                    "top_mitre_techniques": sorted(
                        ({"technique": key, "count": value} for key, value in mitre_counts.items()),
                        key=lambda item: -item["count"],
                    )[:10],
                }
            )
        else:
            narrative = None

        return {
            "report_id": str(uuid4()),
            "report_type": "summary",
            "generated_at": now.isoformat(),
            "period_start": period_start.isoformat(),
            "period_end": now.isoformat(),
            "total_events": len(events),
            "total_findings": len(findings),
            "events_by_type": events_by_type,
            "events_by_severity": events_by_severity,
            "total_alerts": len(alerts),
            "open_alerts": sum(
                1 for alert in alerts
                if getattr(alert.status, "value", str(alert.status)) in _OPEN_ALERT_STATUSES
            ),
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_status": alerts_by_status,
            "total_detections": len(findings),
            "rule_matches": rule_matches,
            "ioc_matches": ioc_matches,
            "anomalies_detected": anomalies_detected,
            "avg_risk_score": round(total_risk / len(events), 1) if events else 0,
            "max_risk_score": max_risk,
            "critical_findings": critical,
            "high_findings": high,
            "top_mitre_techniques": sorted(
                ({"technique": key, "count": value} for key, value in mitre_counts.items()),
                key=lambda item: -item["count"],
            )[:10],
            "top_iocs": [],
            "data_complete": complete,
            "limitations": limitations,
            "narrative": narrative,
        }

    async def _build_threat_landscape(self, data: dict[str, Any]) -> dict[str, Any]:
        events, alerts, _findings = await self._load_records(tenant_ids=data.get("tenant_ids"))
        attack_vectors: dict[str, int] = {}
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for event in events:
            event_type = getattr(event.event_type, "value", str(event.event_type))
            severity = getattr(event.severity, "value", str(event.severity))
            attack_vectors[event_type] = attack_vectors.get(event_type, 0) + 1
            if severity in severity_dist:
                severity_dist[severity] += 1

        techniques: dict[str, int] = {}
        tactics: dict[str, int] = {}
        for alert in alerts:
            for technique in alert.mitre_techniques or []:
                techniques[technique] = techniques.get(technique, 0) + 1
                if technique.startswith("T1566"):
                    tactics["Initial Access"] = tactics.get("Initial Access", 0) + 1
                elif technique.startswith("T1110"):
                    tactics["Credential Access"] = tactics.get("Credential Access", 0) + 1

        complete = len(events) < _REPORT_LIMIT and len(alerts) < _REPORT_LIMIT

        if data.get("include_narrative", False):
            narrative = await self._generate_narrative(
                "threat_landscape",
                {
                    "attack_vectors": attack_vectors,
                    "severity_distribution": severity_dist,
                    "mitre_tactics": tactics,
                    "mitre_techniques": dict(sorted(techniques.items(), key=lambda item: -item[1])[:10]),
                }
            )
        else:
            narrative = None

        return {
            "report_id": str(uuid4()),
            "report_type": "threat_landscape",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "attack_vectors": attack_vectors,
            "severity_distribution": severity_dist,
            "mitre_tactics": tactics,
            "mitre_techniques": dict(sorted(techniques.items(), key=lambda item: -item[1])[:10]),
            "data_complete": complete,
            "limitations": [] if complete else [
                f"At least one source returned {_REPORT_LIMIT} records; additional matching records may be omitted."
            ],
            "narrative": narrative,
        }

    async def _build_incident_investigation(self, data: dict[str, Any]) -> dict[str, Any]:
        incident_id = data["incident_id"]
        tenant_ids = data.get("tenant_ids")
        incident_repo = get_incident_repository()
        incident = await incident_repo.get(incident_id, tenant_ids)

        if incident is None:
            return {
                "report_id": str(uuid4()),
                "report_type": "incident_investigation",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "error": "Incident not found",
                "data_complete": False,
                "limitations": ["Incident not found or access denied"],
            }

        finding_repo = get_finding_repository()
        event_repo = get_event_repository()
        alert_repo = get_alert_repository()
        correlated_repo = get_report_repository()  # Reuse for correlated activities

        finding_ids = incident.finding_ids or []
        event_ids = incident.event_ids or []
        alert_ids = incident.alert_ids or []
        correlation_ids = incident.correlation_ids or []

        findings = []
        for fid in finding_ids:
            f = await finding_repo.get(fid, tenant_ids)
            if f:
                findings.append(f)

        events = await event_repo.list_by_ids(event_ids, tenant_ids) if event_ids else []
        alerts = []
        for aid in alert_ids:
            a = await alert_repo.get(aid, tenant_ids)
            if a:
                alerts.append(a)

        correlated_activities = []
        for cid in correlation_ids:
            activity = await correlated_repo.get(cid, tenant_ids[0] if tenant_ids else None)
            if activity:
                correlated_activities.append(activity)

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = getattr(f.severity, "value", str(f.severity))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        mitre_techniques: dict[str, int] = {}
        for a in alerts:
            for t in a.mitre_techniques or []:
                mitre_techniques[t] = mitre_techniques.get(t, 0) + 1

        timeline = []
        for e in sorted(events, key=lambda x: x.created_at):
            timeline.append({
                "timestamp": e.created_at.isoformat(),
                "type": "event",
                "source": getattr(e.event_type, "value", str(e.event_type)),
                "description": str(e.raw_data)[:200],
            })
        for a in sorted(alerts, key=lambda x: x.created_at):
            timeline.append({
                "timestamp": a.created_at.isoformat(),
                "type": "alert",
                "source": "alert",
                "description": a.title,
                "severity": getattr(a.severity, "value", str(a.severity)),
            })
        timeline.sort(key=lambda x: x["timestamp"])

        if data.get("include_narrative", False):
            narrative = await self._generate_narrative(
                "incident_investigation",
                {
                    "incident_id": incident.id,
                    "incident_title": incident.title,
                    "incident_status": getattr(incident.status, "value", str(incident.status)),
                    "incident_severity": getattr(incident.severity, "value", str(incident.severity)),
                    "finding_count": len(findings),
                    "event_count": len(events),
                    "alert_count": len(alerts),
                    "correlation_count": len(correlated_activities),
                    "severity_counts": severity_counts,
                    "top_mitre_techniques": sorted(
                        ({"technique": k, "count": v} for k, v in mitre_techniques.items()),
                        key=lambda item: -item["count"],
                    )[:10],
                    "timeline": timeline[:50],
                    "recommendations": incident.recommendations or [],
                }
            )
        else:
            narrative = None

        return {
            "report_id": str(uuid4()),
            "report_type": "incident_investigation",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.id,
            "incident_title": incident.title,
            "incident_status": getattr(incident.status, "value", str(incident.status)),
            "incident_severity": getattr(incident.severity, "value", str(incident.severity)),
            "incident_description": incident.description,
            "finding_count": len(findings),
            "event_count": len(events),
            "alert_count": len(alerts),
            "correlation_count": len(correlated_activities),
            "finding_ids": finding_ids,
            "event_ids": event_ids,
            "alert_ids": alert_ids,
            "correlation_ids": correlation_ids,
            "severity_distribution": severity_counts,
            "top_mitre_techniques": sorted(
                ({"technique": k, "count": v} for k, v in mitre_techniques.items()),
                key=lambda item: -item["count"],
            )[:10],
            "timeline": timeline,
            "recommendations": incident.recommendations or [],
            "actions_taken": incident.actions_taken or [],
            "history": incident.history or [],
            "data_complete": True,
            "limitations": [],
            "narrative": narrative,
        }

    async def _build_correlation_report(self, data: dict[str, Any]) -> dict[str, Any]:
        correlation_ids = data["correlation_ids"]
        tenant_ids = data.get("tenant_ids")
        correlated_repo = get_report_repository()

        activities = []
        for cid in correlation_ids:
            activity = await correlated_repo.get(cid, tenant_ids[0] if tenant_ids else None)
            if activity:
                activities.append(activity)

        if not activities:
            return {
                "report_id": str(uuid4()),
                "report_type": "correlation",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "error": "No correlated activities found",
                "data_complete": False,
                "limitations": ["No valid correlation IDs resolved"],
            }

        total_findings = sum(len(a.finding_ids or []) for a in activities)
        total_events = sum(len(a.event_ids or []) for a in activities)
        all_source_types = set()
        all_shared_ips = set()
        all_shared_domains = set()
        all_shared_users = set()
        mitre_techniques: dict[str, int] = {}
        max_risk = 0

        for a in activities:
            all_source_types.update(a.source_types or [])
            shared = a.shared_entities or {}
            all_shared_ips.update(shared.get("ips", []))
            all_shared_domains.update(shared.get("domains", []))
            all_shared_users.update(shared.get("users", []))
            max_risk = max(max_risk, a.risk_score or 0)

        if data.get("include_narrative", False):
            narrative = await self._generate_narrative(
                "correlation",
                {
                    "correlation_count": len(activities),
                    "total_findings": total_findings,
                    "total_events": total_events,
                    "source_types": list(all_source_types),
                    "shared_ips": list(all_shared_ips)[:20],
                    "shared_domains": list(all_shared_domains)[:20],
                    "shared_users": list(all_shared_users)[:20],
                    "max_risk_score": max_risk,
                    "correlation_types": [a.correlation_type for a in activities],
                }
            )
        else:
            narrative = None

        return {
            "report_id": str(uuid4()),
            "report_type": "correlation",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "correlation_count": len(activities),
            "total_findings": total_findings,
            "total_events": total_events,
            "source_types": list(all_source_types),
            "shared_ips": list(all_shared_ips),
            "shared_domains": list(all_shared_domains),
            "shared_users": list(all_shared_users),
            "max_risk_score": max_risk,
            "correlation_types": [a.correlation_type for a in activities],
            "activities": [
                {
                    "correlation_id": a.correlation_id,
                    "correlation_type": a.correlation_type,
                    "correlation_strength": a.correlation_strength,
                    "risk_score": a.risk_score,
                    "finding_count": len(a.finding_ids or []),
                    "event_count": len(a.event_ids or []),
                    "source_types": a.source_types,
                    "shared_entities": a.shared_entities,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in activities
            ],
            "data_complete": True,
            "limitations": [],
            "narrative": narrative,
        }

    async def _build_executive_report(self, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(hours=data.get("hours", 24))
        events, alerts, findings = await self._load_records(
            tenant_ids=data.get("tenant_ids"),
            start_time=period_start,
            end_time=now,
        )

        critical_findings = sum(1 for f in findings if getattr(f.severity, "value", str(f.severity)) == "critical")
        high_findings = sum(1 for f in findings if getattr(f.severity, "value", str(f.severity)) == "high")
        open_alerts = sum(
            1 for a in alerts
            if getattr(a.status, "value", str(a.status)) in _OPEN_ALERT_STATUSES
        )

        base_score = 100
        deductions = critical_findings * 15 + high_findings * 8 + open_alerts * 3
        security_score = max(0, base_score - deductions)

        if security_score >= 80:
            status = "Good"
            status_color = "green"
        elif security_score >= 60:
            status = "Moderate"
            status_color = "yellow"
        elif security_score >= 40:
            status = "Elevated Risk"
            status_color = "orange"
        else:
            status = "Critical"
            status_color = "red"

        if data.get("include_narrative", False):
            narrative = await self._generate_narrative(
                "executive",
                {
                    "security_score": security_score,
                    "status": status,
                    "period_hours": data.get("hours", 24),
                    "total_events": len(events),
                    "open_alerts": open_alerts,
                    "critical_findings": critical_findings,
                    "high_findings": high_findings,
                }
            )
        else:
            narrative = None

        return {
            "report_id": str(uuid4()),
            "report_type": "executive",
            "generated_at": now.isoformat(),
            "period_start": period_start.isoformat(),
            "period_end": now.isoformat(),
            "security_score": security_score,
            "status": status,
            "status_color": status_color,
            "highlights": {
                "total_events": len(events),
                "open_alerts": open_alerts,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
            },
            "data_complete": all(len(rows) < _REPORT_LIMIT for rows in (events, alerts, findings)),
            "limitations": [],
            "recommendations": self._generate_recommendations(critical_findings, high_findings, open_alerts, len(events)),
            "narrative": narrative,
        }

    @staticmethod
    def _generate_recommendations(
        critical_findings: int, high_findings: int, open_alerts: int, total_events: int
    ) -> list[str]:
        recommendations = []
        if critical_findings > 0:
            recommendations.append(f"URGENT: Address {critical_findings} critical findings immediately")
        if high_findings > 3:
            recommendations.append(f"Review and prioritize {high_findings} high-severity findings")
        if open_alerts > 10:
            recommendations.append("Alert queue backlog detected - consider additional analyst resources")
        if total_events == 0:
            recommendations.append("No events recorded in this time window; no security posture conclusion is available.")
        elif not recommendations:
            recommendations.append("Security posture is healthy - continue monitoring")
        return recommendations

    async def _generate_narrative(self, report_type: str, data: dict[str, Any]) -> str | None:
        try:
            llm_client = get_llm_client()
            if not llm_client.is_available():
                return None

            prompts = {
                "summary": (
                    "You are a cybersecurity analyst writing an executive summary for a security report. "
                    "Given the following metrics, write a concise 3-4 paragraph narrative summarizing the security posture. "
                    "Focus on actionable insights, not raw numbers. Do not mention the metrics directly.\n\n"
                    f"Metrics: {data}"
                ),
                "threat_landscape": (
                    "You are a threat intelligence analyst writing a threat landscape overview. "
                    "Given the attack vectors, severity distribution, and MITRE techniques, "
                    "write a concise narrative describing the current threat landscape. "
                    "Focus on trends and notable techniques. Do not mention raw counts.\n\n"
                    f"Data: {data}"
                ),
                "incident_investigation": (
                    "You are an incident responder writing an investigation summary. "
                    "Given the incident details, timeline, and evidence, write a concise narrative "
                    "describing what happened, the scope, and key findings. "
                    "Focus on the attack chain and impact.\n\n"
                    f"Incident: {data}"
                ),
                "correlation": (
                    "You are a threat hunter writing a correlation analysis summary. "
                    "Given the correlated activities, shared indicators, and risk scores, "
                    "write a concise narrative describing the relationships discovered. "
                    "Focus on the attack campaign or multi-stage activity.\n\n"
                    f"Correlations: {data}"
                ),
                "executive": (
                    "You are a CISO writing an executive briefing. "
                    "Given the security score and key metrics, write a 2-3 paragraph briefing "
                    "for senior leadership. Focus on business risk and recommended actions.\n\n"
                    f"Metrics: {data}"
                ),
            }

            prompt = prompts.get(report_type, prompts["summary"])
            response = await llm_client.generate(prompt, max_tokens=500, temperature=0.3)
            return response.strip() if response else None
        except Exception:
            return None

    async def _export_pdf(self, report: dict[str, Any]) -> bytes:
        try:
            from fpdf import FPDF
        except ImportError:
            return b"PDF export requires fpdf2 package"

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"CyberGuard AI - {report.get('report_type', 'Report').replace('_', ' ').title()}", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {report.get('generated_at', '')}", ln=True, align="C")
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 12)
        for key, value in report.items():
            if key in ("export_data", "export_format", "narrative"):
                continue
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, str(key).replace("_", " ").title(), ln=True)
            pdf.set_font("Helvetica", "", 9)
            if isinstance(value, (dict, list)):
                import json
                pdf.multi_cell(0, 5, json.dumps(value, indent=2, default=str))
            else:
                pdf.multi_cell(0, 5, str(value))
            pdf.ln(3)

        if report.get("narrative"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 6, "Narrative Summary", ln=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 5, report["narrative"])

        return pdf.output(dest="S").encode("latin-1")

    async def _export_csv(self, report: dict[str, Any]) -> bytes:
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["metric", "value"])

        for key, value in report.items():
            if key in ("export_data", "export_format", "narrative"):
                continue
            if isinstance(value, (dict, list)):
                import json
                writer.writerow([key, json.dumps(value, default=str)])
            else:
                writer.writerow([key, str(value)])

        if report.get("narrative"):
            writer.writerow(["narrative", report["narrative"]])

        return output.getvalue().encode("utf-8")

    async def _persist_report(self, report: dict[str, Any], tenant_id: str, request_data: dict[str, Any]) -> None:
        try:
            report_repo = get_report_repository()
            db_report = DBReport(
                tenant_id=tenant_id,
                report_type=request_data["report_type"],
                format=request_data.get("export_format", ReportFormat.JSON),
                status=ReportStatus.COMPLETED,
                title=f"{request_data['report_type'].replace('_', ' ').title()} Report",
                content=report,
                metadata={
                    "request": request_data,
                    "generated_by": "reporting_agent",
                    "agent_version": self.agent_version,
                },
            )
            await report_repo.create(db_report)
        except Exception:
            pass
