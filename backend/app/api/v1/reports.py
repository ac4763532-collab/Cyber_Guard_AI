"""
CyberGuard AI - Reports API Endpoints

Security reporting and export capabilities.
"""

from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.agents.dispatcher import get_dispatcher
from app.agents.base import AgentType
from app.auth.jwt import get_current_active_user
from app.auth.models import User, UserRole
from app.database.repositories.reports import get_report_repository
from app.database.models import ReportFormat, ReportStatus


router = APIRouter(prefix="/reports", tags=["Reports"])


class ReportSummary(BaseModel):
    """Summary report of security posture."""

    report_id: str
    generated_at: str
    period_start: str
    period_end: str

    # Event metrics
    total_events: int = 0
    total_findings: int = 0
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_severity: dict[str, int] = Field(default_factory=dict)

    # Alert metrics
    total_alerts: int = 0
    open_alerts: int = 0
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    alerts_by_status: dict[str, int] = Field(default_factory=dict)

    # Detection metrics
    total_detections: int = 0
    rule_matches: int | None = None
    ioc_matches: int | None = None
    anomalies_detected: int | None = None

    # Risk metrics
    avg_risk_score: float = 0.0
    max_risk_score: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    # Top threats
    top_mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    top_iocs: list[dict[str, Any]] = Field(default_factory=list)
    data_complete: bool = True
    limitations: list[str] = Field(default_factory=list)
    narrative: str | None = None


class ReportListItem(BaseModel):
    """Persisted report list item."""

    report_id: str
    tenant_id: str
    report_type: str
    format: str
    status: str
    title: str
    generated_at: str
    created_at: str


def _authorized_tenant_ids(user: User) -> list[str] | None:
    if user.role == UserRole.ADMIN:
        return None
    if not user.organization_id:
        raise HTTPException(
            status_code=403,
            detail="Your account has no organization assigned; report access is unavailable.",
        )
    return [user.organization_id]


async def _run_reporting_agent(report_type: str, user: User, **filters: Any) -> dict[str, Any]:
    result = await get_dispatcher().dispatch(
        AgentType.REPORTING,
        {
            "report_type": report_type,
            "tenant_ids": _authorized_tenant_ids(user),
            **filters,
        },
    )
    if not result.success:
        raise HTTPException(status_code=503, detail=result.error or "Report generation failed")
    report = (result.metadata or {}).get("report")
    if not isinstance(report, dict):
        raise HTTPException(status_code=503, detail="Reporting agent returned no report data")
    return report


@router.get(
    "/summary",
    response_model=ReportSummary,
    summary="Get Summary Report",
    description="Generate a summary security report.",
)
async def get_summary_report(
    hours: int = Query(24, ge=1, le=720, description="Hours to include in report"),
    include_narrative: bool = Query(False, description="Include LLM-generated narrative"),
    user: User = Depends(get_current_active_user),
) -> ReportSummary:
    """Generate a tenant-scoped summary through the Reporting Agent."""
    report = await _run_reporting_agent("summary", user, hours=hours, include_narrative=include_narrative)
    return ReportSummary(**report)


@router.get(
    "/executive",
    summary="Executive Summary",
    description="Generate executive summary for management.",
)
async def get_executive_summary(
    hours: int = Query(24, ge=1, le=720),
    include_narrative: bool = Query(False, description="Include LLM-generated narrative"),
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Generate executive-level security summary."""
    report = await _run_reporting_agent("executive", user, hours=hours, include_narrative=include_narrative)
    return report


@router.get(
    "/threat-landscape",
    summary="Threat Landscape Report",
    description="Analysis of current threat landscape.",
)
async def get_threat_landscape(
    include_narrative: bool = Query(False, description="Include LLM-generated narrative"),
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Generate a tenant-scoped threat landscape from persisted records."""
    report = await _run_reporting_agent("threat_landscape", user, include_narrative=include_narrative)
    return report


@router.get(
    "/incident-investigation",
    summary="Incident Investigation Report",
    description="Generate detailed investigation report for a specific incident.",
)
async def get_incident_investigation_report(
    incident_id: str = Query(..., description="Incident ID to generate report for"),
    include_narrative: bool = Query(False, description="Include LLM-generated narrative"),
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Generate an incident investigation report with full evidence timeline."""
    report = await _run_reporting_agent(
        "incident_investigation",
        user,
        incident_id=incident_id,
        include_narrative=include_narrative,
    )
    return report


@router.get(
    "/correlation",
    summary="Correlation Report",
    description="Generate correlation analysis report for specified correlated activities.",
)
async def get_correlation_report(
    correlation_ids: str = Query(..., description="Comma-separated correlation IDs"),
    include_narrative: bool = Query(False, description="Include LLM-generated narrative"),
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Generate a correlation report from persisted correlated activities."""
    ids = [cid.strip() for cid in correlation_ids.split(",") if cid.strip()]
    if not ids:
        raise HTTPException(status_code=400, detail="correlation_ids must contain at least one ID")
    report = await _run_reporting_agent(
        "correlation",
        user,
        correlation_ids=ids,
        include_narrative=include_narrative,
    )
    return report


@router.get(
    "/compliance",
    summary="Compliance Report",
    description="Security compliance status report.",
)
async def get_compliance_report(
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Return an explicit unassessed state until controls have evidence."""
    _authorized_tenant_ids(user)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment_status": "not_assessed",
        "compliance_score": None,
        "checks_passed": None,
        "checks_total": None,
        "checks": {},
        "limitations": ["Control evidence is not collected by this application; no compliance score is asserted."],
        "frameworks": {
            "NIST_CSF": "Not assessed",
            "ISO_27001": "Not assessed",
            "SOC2": "Not assessed",
        },
    }


@router.get(
    "",
    response_model=list[ReportListItem],
    summary="List Persisted Reports",
    description="List all persisted reports for the authenticated tenant.",
)
async def list_reports(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    report_type: str | None = Query(None, description="Filter by report type"),
    status: str | None = Query(None, description="Filter by status"),
    user: User = Depends(get_current_active_user),
) -> list[ReportListItem]:
    """List persisted reports for the tenant."""
    tenant_ids = _authorized_tenant_ids(user)
    if not tenant_ids:
        return []

    repo = get_report_repository()
    reports = await repo.list(tenant_ids[0], limit=limit, offset=offset, report_type=report_type, status=status)

    return [
        ReportListItem(
            report_id=r.report_id,
            tenant_id=r.tenant_id,
            report_type=r.report_type,
            format=r.format.value if hasattr(r.format, 'value') else str(r.format),
            status=r.status.value if hasattr(r.status, 'value') else str(r.status),
            title=r.title,
            generated_at=r.metadata.get("generated_at", r.created_at.isoformat()) if r.metadata else r.created_at.isoformat(),
            created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]


@router.get(
    "/{report_id}",
    summary="Get Persisted Report",
    description="Retrieve a specific persisted report by ID.",
)
async def get_persisted_report(
    report_id: str,
    user: User = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Get a persisted report by ID."""
    tenant_ids = _authorized_tenant_ids(user)
    if not tenant_ids:
        raise HTTPException(status_code=403, detail="Access denied")

    repo = get_report_repository()
    report = await repo.get(report_id, tenant_ids[0])
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_id": report.report_id,
        "tenant_id": report.tenant_id,
        "report_type": report.report_type,
        "format": report.format.value if hasattr(report.format, 'value') else str(report.format),
        "status": report.status.value if hasattr(report.status, 'value') else str(report.status),
        "title": report.title,
        "content": report.content,
        "metadata": report.metadata,
        "created_at": report.created_at.isoformat(),
        "updated_at": report.updated_at.isoformat() if report.updated_at else None,
    }


@router.get(
    "/{report_id}/export",
    summary="Export Report",
    description="Export a persisted report in the specified format.",
)
async def export_report(
    report_id: str,
    format: str = Query("json", description="Export format: json, pdf, csv"),
    user: User = Depends(get_current_active_user),
):
    """Export a persisted report."""
    tenant_ids = _authorized_tenant_ids(user)
    if not tenant_ids:
        raise HTTPException(status_code=403, detail="Access denied")

    repo = get_report_repository()
    report = await repo.get(report_id, tenant_ids[0])
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    export_format = format.lower()
    content = report.content

    if export_format == "json":
        import json
        data = json.dumps(content, indent=2, default=str).encode("utf-8")
        filename = f"cyberguard-report-{report_id[:8]}.json"
        media_type = "application/json"
    elif export_format == "pdf":
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"CyberGuard AI - {report.report_type.replace('_', ' ').title()}", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {content.get('generated_at', '')}", ln=True, align="C")
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 12)
        for key, value in content.items():
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

        if content.get("narrative"):
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 6, "Narrative Summary", ln=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 5, content["narrative"])

        data = pdf.output(dest="S").encode("latin-1")
        filename = f"cyberguard-report-{report_id[:8]}.pdf"
        media_type = "application/pdf"
    elif export_format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["metric", "value"])
        for key, value in content.items():
            if key in ("export_data", "export_format", "narrative"):
                continue
            if isinstance(value, (dict, list)):
                import json
                writer.writerow([key, json.dumps(value, default=str)])
            else:
                writer.writerow([key, str(value)])
        if content.get("narrative"):
            writer.writerow(["narrative", content["narrative"]])
        data = output.getvalue().encode("utf-8")
        filename = f"cyberguard-report-{report_id[:8]}.csv"
        media_type = "text/csv"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    return StreamingResponse(
        iter([data]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _generate_recommendations(summary: ReportSummary) -> list[str]:
    """Generate recommendations based on summary."""
    recommendations = []

    if summary.critical_findings > 0:
        recommendations.append(
            f"URGENT: Address {summary.critical_findings} critical findings immediately"
        )

    if summary.high_findings > 3:
        recommendations.append(
            f"Review and prioritize {summary.high_findings} high-severity findings"
        )

    if summary.open_alerts > 10:
        recommendations.append(
            "Alert queue backlog detected - consider additional analyst resources"
        )

    if summary.avg_risk_score > 50:
        recommendations.append(
            "Average risk score elevated - review security controls"
        )

    if summary.total_events == 0 and summary.total_alerts == 0:
        recommendations.append(
            "No events or alerts were recorded in this time window; no security posture conclusion is available."
        )
    elif not recommendations:
        recommendations.append("Security posture is healthy - continue monitoring")

    return recommendations
