"""
CyberGuard AI — Report Service
============================================================================

Report generation, delivery, and lifecycle. Wraps the asynchronously-
generated files that the platform produces for users, admins, and
auditors.

The pipeline
------------
    Client POST /reports
        │
        ▼
    request_report(db, actor, payload)
        │  → creates QUEUED row, returns immediately
        ▼
    Background worker picks up the QUEUED row
        │
        ▼
    generate_report(db, report=report)
        │  → fetch data (DB queries)
        │  → build file (ReportLab / csv / json / html)
        │  → compute hash, write to disk
        │  → transition to READY
        │  → notify requester
        ▼
    Client GET /reports/{id} → sees READY, downloads

Supported formats
-----------------
    pdf     — real PDF via ReportLab (recommended for all report types)
    csv     — comma-separated (per-type schema)
    json    — structured JSON
    html    — self-contained HTML (no external assets)
    xlsx    — not yet supported (requires openpyxl)

The xlsx format is deliberately not implemented — adding it requires
a new dependency (`openpyxl`). Requests for xlsx return a clear error
instead of silently producing a broken file. Add the dependency +
implement `_build_xlsx` when the feature is prioritized.

Report types
------------
The 11 report types supported by ``ReportType`` map to 5 distinct
builders, sharing the same data-fetch layer:

    Incident reports:  INCIDENT, PHISHING, LOG_ANALYSIS, NETWORK,
                       THREAT_INTEL
    Periodic reports:  DAILY, WEEKLY, MONTHLY
    Case reports:      (uses ``scope_type="case"`` with INCIDENT type)
    Org reports:       ORG_RISK
    Analyst reports:   ANALYST_PERFORMANCE
    Custom:            CUSTOM (uses ``parameters`` dict to define
                       sections + queries)

Data fetch layer
----------------
Each report type has its own `_fetch_*_data(db, report) -> dict`
function that returns a plain dict — no ORM objects escape. This
decouples the report rendering from the DB schema, so a future
migration doesn't break all report renderers.

The dict shape is per-type and documented in each fetcher.

Reproducibility
---------------
Every report stores its ``parameters`` dict verbatim. Given the same
parameters, re-running the report produces identical output (modulo
timestamps and auto-increment IDs). This is the compliance
requirement: a regulator asking "how was this decision made" can
regenerate the exact report an analyst saw.

Note: reproducibility across time requires the underlying data to be
unchanged. If events were retained beyond the report period and the
data was deleted, re-running produces a shorter report. This is
documented behavior — the report is a snapshot, not a live query.

File integrity
--------------
- SHA-256 computed at generation
- Re-verified at every download (``prepare_download``)
- Mismatch → ``integrity_verified=False``, audit, but STILL RETURN
  the file (forensic value — the user needs to see what was tampered
  with)

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. **Same-transaction:** request_report, share, unshare, delete
5. **Independent writes:** generate_report — worker owns its own
   transaction so failures don't roll back the request.

Public API
----------
    # Request / lookup
    request_report(db, *, actor, payload, request=None)   → SecurityReport
    get_by_id(db, report_id)                              → SecurityReport
    list_reports(db, *, workspace_ids, page, filters)     → (list, int)

    # Generation (called by background worker)
    generate_report(db, *, report, generated_by=None)     → SecurityReport

    # Download
    prepare_download(db, *, actor, report, request=None)  → ReportDownloadResult

    # Sharing
    share_report(db, *, actor, report, user_id, expires_at=None, request=None)
                                                          → SecurityReport
    unshare_report(db, *, actor, report, user_id, request=None)
                                                          → SecurityReport

    # Deletion
    delete_report(db, *, actor, report, reason, request=None) → SecurityReport

    # Cleanup (background job)
    cleanup_expired(db, *, limit=100)                     → int

Usage
-----
    from app.services import report_service

    # Request a report
    report = report_service.request_report(
        db,
        actor=current_user,
        payload=ReportCreate(
            report_type=ReportType.INCIDENT,
            report_format="pdf",
            title=f"Incident Report — {incident.title}",
            scope_type="incident",
            scope_id=incident.id,
            sections=["executive_summary", "timeline", "findings",
                      "recommendations"],
            parameters={"incident_id": str(incident.id)},
        ),
    )
    db.commit()

    # Worker picks it up:
    report_service.generate_report(db, report=report)
    db.commit()

    # User downloads:
    result = report_service.prepare_download(
        db, actor=current_user, report=report,
    )
    db.commit()
    return Response(content=result.file_bytes, media_type=result.mime_type)
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthorizationError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.case import SecurityCase
from app.models.enums import (
    IncidentSeverity,
    IncidentStatus,
    ReportStatus,
    ReportType,
)
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.incident import SecurityIncident
from app.models.report import SecurityReport
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.schemas.report import ReportCreate, ReportFilter
from app.services import audit_service, authorization, notification_service


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

_SUPPORTED_FORMATS = frozenset({"pdf", "csv", "json", "html"})
_UNSUPPORTED_FORMATS = frozenset({"xlsx"})

_MIME_TYPES = {
    "pdf": "application/pdf",
    "csv": "text/csv",
    "json": "application/json",
    "html": "text/html",
}

#: Report section sets by type. Callers can override via ``sections``.
_DEFAULT_SECTIONS: dict[ReportType, list[str]] = {
    ReportType.INCIDENT: [
        "executive_summary", "timeline", "affected_entities",
        "findings", "evidence", "actions_taken", "recommendations",
    ],
    ReportType.PHISHING: [
        "executive_summary", "timeline", "affected_entities", "recommendations",
    ],
    ReportType.LOG_ANALYSIS: [
        "executive_summary", "findings", "top_events", "recommendations",
    ],
    ReportType.NETWORK: [
        "executive_summary", "findings", "top_events", "recommendations",
    ],
    ReportType.THREAT_INTEL: [
        "executive_summary", "top_indicators", "recommendations",
    ],
    ReportType.DAILY: [
        "summary", "top_categories", "top_sources",
        "open_incidents", "recommendations",
    ],
    ReportType.WEEKLY: [
        "summary", "top_categories", "top_sources",
        "open_incidents", "trends", "recommendations",
    ],
    ReportType.MONTHLY: [
        "summary", "top_categories", "top_sources",
        "open_incidents", "trends", "recommendations",
    ],
    ReportType.ORG_RISK: [
        "summary", "risk_score", "top_threats", "compliance", "recommendations",
    ],
    ReportType.ANALYST_PERFORMANCE: [
        "summary", "cases", "sla", "ratings",
    ],
    ReportType.CUSTOM: [],
}

_MAX_SECTION_ROWS = 500


# ============================================================================
# RESULT DTYPES
# ============================================================================

@dataclass(frozen=True)
class ReportDownloadResult:
    """Result of ``prepare_download``."""
    file_bytes: bytes
    mime_type: str
    content_hash: str
    verified: bool
    title: str
    report_format: str


# ============================================================================
# INTERNAL — request handling
# ============================================================================

def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_sections(report: SecurityReport) -> list[str]:
    """
    Determine which sections to include. Priority:
        1. ``report.sections`` if non-empty (caller-supplied)
        2. ``_DEFAULT_SECTIONS[report.report_type]``
        3. ``[]`` (empty — build nothing, but still produce a file)
    """
    if report.sections:
        return list(report.sections)
    return list(_DEFAULT_SECTIONS.get(report.report_type, []))


# ============================================================================
# REQUEST
# ============================================================================

def request_report(
    db: Session,
    *,
    actor: User | None = None,
    actor_id: Any | None = None,
    payload: ReportCreate,
    request: Any | None = None,
) -> SecurityReport:
    """
    Create a report in QUEUED status. The actual generation happens
    asynchronously — this call returns immediately.

    Validation
    ----------
    - ``report_format`` must be supported
    - ``scope_type`` must match ``scope_id`` presence rules
    - ``scope_id`` (if provided) must exist and be accessible to the
      actor

    Returns
    -------
    SecurityReport
        The queued report (flushed, not committed).
    """
    if payload.report_format not in _SUPPORTED_FORMATS:
        if payload.report_format in _UNSUPPORTED_FORMATS:
            raise ValidationError(
                message=(
                    f"Report format {payload.report_format!r} is not yet "
                    f"supported. Use one of: {sorted(_SUPPORTED_FORMATS)}."
                ),
                code="REPORT_FORMAT_NOT_YET_SUPPORTED",
                details={"format": payload.report_format},
            )
        raise ValidationError(
            message=f"Unknown report format: {payload.report_format!r}.",
            code="REPORT_FORMAT_INVALID",
        )

    # Determine workspace from scope
    workspace_id = _resolve_workspace_for_scope(
        db, actor, scope_type=payload.scope_type, scope_id=payload.scope_id,
    )

    report = SecurityReport.build(
        workspace_id=workspace_id,
        report_type=payload.report_type,
        title=payload.title,
        report_format=payload.report_format,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        requested_by_id=actor.id if actor else None,
        report_group_id=payload.report_group_id,
        regenerated_from_id=payload.regenerated_from_id,
        summary=payload.summary,
        parameters=payload.parameters or {},
        sections=payload.sections or [],
        period_start_at=payload.period_start_at,
        period_end_at=payload.period_end_at,
        is_scheduled=payload.is_scheduled,
        expires_in_days=payload.expires_in_days,
    )
    db.add(report)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        actor_type="user" if actor else "system",
        action="report.requested",
        target_type="report",
        target_id=report.id,
        workspace_id=workspace_id,
        request=request,
        metadata={
            "report_type": payload.report_type.value,
            "report_format": payload.report_format,
            "scope_type": payload.scope_type,
            "scope_id": str(payload.scope_id) if payload.scope_id else None,
        },
    )

    logger.info(
        "Report queued",
        extra={
            "report_id": str(report.id),
            "report_type": payload.report_type.value,
            "report_format": payload.report_format,
            "workspace_id": str(workspace_id),
        },
    )

    # TODO: enqueue via background worker (Redis queue, Celery, etc.) —
    # for now, callers can trigger generation synchronously by calling
    # generate_report() after committing.

    return report


def _resolve_workspace_for_scope(
    db: Session,
    actor: User | None,
    *,
    scope_type: str,
    scope_id: uuid.UUID | None,
) -> uuid.UUID:
    """
    Determine which workspace the report belongs to, based on scope.
    Also verifies the actor has access to the scoped entity (if actor is provided).
    """
    if scope_type in ("workspace", "custom"):
        if scope_id is not None:
            ws = db.get(Workspace, scope_id)
            if ws is None or ws.deleted_at is not None:
                raise NotFoundError(
                    message=f"Workspace {scope_id} not found.",
                    code="WORKSPACE_NOT_FOUND",
                )
            if actor is not None:
                authorization.require_workspace_member(db, actor, ws.id)
            return ws.id
        # No scope_id → use the actor's personal workspace
        if actor is None:
            raise ValidationError(
                message="scope_id is required when requesting report without user context.",
                code="WORKSPACE_CONTEXT_REQUIRED",
            )
        from app.services import workspace_service
        personal_ws = workspace_service.get_personal_workspace_optional(
            db, actor.id,
        )
        if personal_ws is None:
            raise ValidationError(
                message=(
                    "No workspace context. Provide scope_id, or create a "
                    "personal workspace first."
                ),
                code="WORKSPACE_CONTEXT_REQUIRED",
            )
        return personal_ws.id

    if scope_type == "incident":
        if scope_id is None:
            raise ValidationError(
                message="scope_id is required for incident reports.",
                code="SCOPE_ID_REQUIRED",
            )
        incident = db.get(SecurityIncident, scope_id)
        if incident is None:
            raise NotFoundError(
                message=f"Incident {scope_id} not found.",
                code="INCIDENT_NOT_FOUND",
            )
        if actor is not None:
            authorization.require_workspace_member(db, actor, incident.workspace_id)
        return incident.workspace_id

    if scope_type == "case":
        if scope_id is None:
            raise ValidationError(
                message="scope_id is required for case reports.",
                code="SCOPE_ID_REQUIRED",
            )
        case = db.get(SecurityCase, scope_id)
        if case is None:
            raise NotFoundError(
                message=f"Case {scope_id} not found.",
                code="CASE_NOT_FOUND",
            )
        from app.models.enums import AccessGrantScope
        if actor is not None:
            authorization.require_case_access(
                db, actor, case, minimum_scope=AccessGrantScope.CASE_READ,
            )
        return case.workspace_id

    if scope_type == "organization":
        if scope_id is None:
            raise ValidationError(
                message="scope_id is required for organization reports.",
                code="SCOPE_ID_REQUIRED",
            )
        if actor is not None:
            authorization.require_org_member(db, actor, scope_id)
        # Find a default workspace for the org
        from app.models.workspace import Workspace as _WS
        from app.models.enums import WorkspaceType
        ws = db.execute(
            select(_WS).where(
                _WS.organization_id == scope_id,
                _WS.workspace_type == WorkspaceType.ORGANIZATION,
                _WS.deleted_at.is_(None),
            ).limit(1)
        ).scalar_one_or_none()
        if ws is None:
            raise ValidationError(
                message="Organization has no workspaces to report on.",
                code="ORG_NO_WORKSPACES",
            )
        return ws.id

    if scope_type in ("analyst", "source"):
        # Analyst / source reports default to the actor's personal
        # workspace (they're per-user reports)
        from app.services import workspace_service
        personal_ws = workspace_service.get_personal_workspace_optional(
            db, actor.id,
        )
        if personal_ws is None:
            raise ValidationError(
                message="No personal workspace found for this report.",
                code="WORKSPACE_CONTEXT_REQUIRED",
            )
        return personal_ws.id

    raise ValidationError(
        message=f"Unknown scope_type: {scope_type!r}.",
        code="SCOPE_TYPE_INVALID",
    )


# ============================================================================
# GENERATE
# ============================================================================

def generate_report(
    db: Session,
    *,
    report: SecurityReport,
    generated_by: User | None = None,
) -> SecurityReport:
    """
    Generate the report file. Called by the background worker.

    Transition lifecycle:
        QUEUED → GENERATING → READY (success)
                            → FAILED (exception)

    On failure: ``error_code`` and ``error_message`` are populated,
    status is set to FAILED, and the exception is re-raised so the
    worker can log/alert.

    On success: file is written to disk, hash computed, status set to
    READY, requester notified.

    Returns
    -------
    SecurityReport
        The generated report (READY status).
    """
    try:
        report.start_generation()
        db.flush()

        # ── 1. Fetch data
        data = _fetch_report_data(db, report)

        # ── 2. Build the file
        file_bytes = _build_file(report, data)

        # ── 3. Write to disk
        path = report.get_storage_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_bytes(file_bytes)
        tmp_path.replace(path)

        # ── 4. Finalize
        content_hash = _compute_sha256(file_bytes)
        report.finish_generation(
            content_hash=content_hash,
            file_size_bytes=len(file_bytes),
            summary=data.get("summary"),
            page_count=data.get("page_count"),
        )
        db.flush()

        audit_service.log_action(
            db,
            actor=generated_by,
            actor_type="user" if generated_by else "system",
            action="report.generated",
            target_type="report",
            target_id=report.id,
            workspace_id=report.workspace_id,
            metadata={
                "report_type": report.report_type.value,
                "report_format": report.report_format,
                "file_size_bytes": len(file_bytes),
                "page_count": report.page_count,
            },
        )

        logger.info(
            "Report generated",
            extra={
                "report_id": str(report.id),
                "report_type": report.report_type.value,
                "report_format": report.report_format,
                "file_size_bytes": len(file_bytes),
                "page_count": report.page_count,
            },
        )

        # ── 5. Notify requester
        try:
            notification_service.create_for_report(db, report=report)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to notify report requester",
                extra={
                    "report_id": str(report.id),
                    "error": str(exc)[:200],
                },
            )

        return report

    except Exception as exc:
        logger.exception(
            "Report generation failed",
            extra={
                "report_id": str(report.id),
                "report_type": report.report_type.value,
            },
        )
        try:
            report.fail_generation(
                error_code="REPORT_GENERATION_ERROR",
                error_message=f"{type(exc).__name__}: {str(exc)[:450]}",
            )
            db.flush()
        except Exception:  # noqa: BLE001
            pass
        raise


# ============================================================================
# DATA FETCH
# ============================================================================

def _fetch_report_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """Dispatch to the appropriate fetch based on report type."""
    rt = report.report_type

    if rt in (
        ReportType.INCIDENT, ReportType.PHISHING,
        ReportType.LOG_ANALYSIS, ReportType.NETWORK,
        ReportType.THREAT_INTEL,
    ):
        return _fetch_incident_style_data(db, report)

    if rt in (ReportType.DAILY, ReportType.WEEKLY, ReportType.MONTHLY):
        return _fetch_periodic_data(db, report)

    if rt == ReportType.ORG_RISK:
        return _fetch_org_risk_data(db, report)

    if rt == ReportType.ANALYST_PERFORMANCE:
        return _fetch_analyst_data(db, report)

    if rt == ReportType.CUSTOM:
        return _fetch_custom_data(db, report)

    raise ValidationError(
        message=f"Unhandled report_type: {rt.value!r}.",
        code="REPORT_TYPE_UNHANDLED",
    )


def _fetch_incident_style_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """
    Data for incident/phishing/log/network/threat-intel reports —
    all are centered on a specific incident or case scope.
    """
    incident: SecurityIncident | None = None
    case: SecurityCase | None = None

    if report.scope_type == "incident" and report.scope_id:
        incident = db.get(SecurityIncident, report.scope_id)
    elif report.scope_type == "case" and report.scope_id:
        case = db.get(SecurityCase, report.scope_id)
        if case and case.incident_id:
            incident = db.get(SecurityIncident, case.incident_id)

    if incident is None:
        return {
            "summary": "No incident found for this report scope.",
            "title": report.title,
            "sections": {},
        }

    # Alerts related to the incident
    alert_ids = [uuid.UUID(aid) for aid in (incident.alert_ids or []) if _is_uuid(aid)]
    alerts: list[SecurityAlert] = []
    if alert_ids:
        alerts = list(db.execute(
            select(SecurityAlert).where(SecurityAlert.id.in_(alert_ids))
        ).scalars().all())

    # Findings related to the incident
    finding_ids = [uuid.UUID(fid) for fid in (incident.finding_ids or []) if _is_uuid(fid)]
    findings: list[AgentFinding] = []
    if finding_ids:
        findings = list(db.execute(
            select(AgentFinding).where(AgentFinding.id.in_(finding_ids))
        ).scalars().all())

    # Events via the incident's workspace + time window
    events = list(db.execute(
        select(SecurityEvent)
        .where(
            SecurityEvent.workspace_id == incident.workspace_id,
            SecurityEvent.event_time >= incident.first_seen_at,
        )
        .order_by(SecurityEvent.event_time.desc())
        .limit(_MAX_SECTION_ROWS)
    ).scalars().all())

    return {
        "summary": (
            f"{incident.severity.value.title()} severity "
            f"{incident.category.value.replace('_', ' ')} incident — "
            f"{incident.status.value}."
        ),
        "title": report.title,
        "incident": {
            "id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity.value,
            "category": incident.category.value,
            "status": incident.status.value,
            "opened_at": incident.opened_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "description": incident.description,
            "root_cause": incident.root_cause,
            "resolution_summary": incident.resolution_summary,
            "lessons_learned": incident.lessons_learned,
            "affected_devices": list(incident.affected_devices or []),
            "affected_users": list(incident.affected_users or []),
            "affected_ips": list(incident.affected_ips or []),
            "mitre_techniques": list(incident.mitre_techniques or []),
            "status_history": list(incident.status_history or []),
            "containment_actions": list(incident.containment_actions or []),
            "recovery_actions": list(incident.recovery_actions or []),
        },
        "alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "first_seen_at": a.first_seen_at.isoformat(),
            }
            for a in alerts[:50]
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "agent_name": f.agent_name,
                "rule_id": f.rule_id,
                "occurrence_count": f.occurrence_count,
                "first_seen_at": f.first_seen_at.isoformat(),
            }
            for f in findings[:100]
        ],
        "events": [
            {
                "id": str(e.id),
                "event_time": e.event_time.isoformat(),
                "event_type": e.event_type,
                "severity": e.severity.value,
                "username": e.username,
                "source_ip": e.source_ip,
                "hostname": e.hostname,
            }
            for e in events
        ],
    }


def _fetch_periodic_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """
    Data for daily/weekly/monthly reports — aggregate stats over a
    time window for a workspace.
    """
    now = _now()
    if report.period_start_at and report.period_end_at:
        start, end = report.period_start_at, report.period_end_at
    else:
        # Default windows based on report type
        if report.report_type == ReportType.DAILY:
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif report.report_type == ReportType.WEEKLY:
            start = now - timedelta(days=7)
            end = now
        else:  # MONTHLY
            start = now - timedelta(days=30)
            end = now

    ws_id = report.workspace_id

    # Counts
    total_events = db.execute(
        select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.workspace_id == ws_id,
            SecurityEvent.event_time >= start,
            SecurityEvent.event_time <= end,
        )
    ).scalar_one()

    total_findings = db.execute(
        select(func.count()).select_from(AgentFinding).where(
            AgentFinding.workspace_id == ws_id,
            AgentFinding.first_seen_at >= start,
            AgentFinding.first_seen_at <= end,
        )
    ).scalar_one()

    total_alerts = db.execute(
        select(func.count()).select_from(SecurityAlert).where(
            SecurityAlert.workspace_id == ws_id,
            SecurityAlert.first_seen_at >= start,
            SecurityAlert.first_seen_at <= end,
        )
    ).scalar_one()

    total_incidents = db.execute(
        select(func.count()).select_from(SecurityIncident).where(
            SecurityIncident.workspace_id == ws_id,
            SecurityIncident.opened_at >= start,
            SecurityIncident.opened_at <= end,
        )
    ).scalar_one()

    # Top categories — group findings by category
    category_rows = db.execute(
        select(
            AgentFinding.category, func.count(AgentFinding.id).label("c"),
        )
        .where(
            AgentFinding.workspace_id == ws_id,
            AgentFinding.first_seen_at >= start,
            AgentFinding.first_seen_at <= end,
        )
        .group_by(AgentFinding.category)
        .order_by(func.count(AgentFinding.id).desc())
        .limit(10)
    ).all()

    top_categories = [
        {"category": c.value if hasattr(c, "value") else str(c), "count": int(n)}
        for c, n in category_rows
    ]

    # Top sources — count events per source
    source_rows = db.execute(
        select(
            SecurityEvent.source_id, func.count(SecurityEvent.id).label("c"),
        )
        .where(
            SecurityEvent.workspace_id == ws_id,
            SecurityEvent.event_time >= start,
            SecurityEvent.event_time <= end,
        )
        .group_by(SecurityEvent.source_id)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(10)
    ).all()

    top_sources = [
        {"source_id": str(sid) if sid else None, "count": int(n)}
        for sid, n in source_rows
    ]

    # Open incidents
    open_incidents = list(db.execute(
        select(SecurityIncident)
        .where(
            SecurityIncident.workspace_id == ws_id,
            SecurityIncident.closed_at.is_(None),
        )
        .order_by(SecurityIncident.opened_at.desc())
        .limit(20)
    ).scalars().all())

    return {
        "summary": (
            f"{report.report_type.value.title()} report — "
            f"{total_events} events, {total_findings} findings, "
            f"{total_alerts} alerts, {total_incidents} incidents "
            f"during the period."
        ),
        "title": report.title,
        "period": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "counts": {
            "events": int(total_events),
            "findings": int(total_findings),
            "alerts": int(total_alerts),
            "incidents": int(total_incidents),
        },
        "top_categories": top_categories,
        "top_sources": top_sources,
        "open_incidents": [
            {
                "id": str(i.id),
                "title": i.title,
                "severity": i.severity.value,
                "status": i.status.value,
                "opened_at": i.opened_at.isoformat(),
            }
            for i in open_incidents
        ],
    }


def _fetch_org_risk_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """
    Data for organization risk reports. Aggregates across all open
    incidents/cases in the org's workspaces.
    """
    from app.models.workspace import Workspace as _WS
    from app.services import workspace_service

    ws_id = report.workspace_id
    ws = db.get(_WS, ws_id)

    if ws is None:
        return {"summary": "Workspace not found.", "title": report.title}

    org_id = ws.organization_id

    # All workspaces in the org (or just this workspace for personal)
    if org_id is None:
        workspace_ids = [ws_id]
    else:
        workspace_rows = db.execute(
            select(_WS.id).where(
                _WS.organization_id == org_id,
                _WS.deleted_at.is_(None),
            )
        ).scalars().all()
        workspace_ids = list(workspace_rows)

    # Open incidents across all workspaces
    open_incidents = list(db.execute(
        select(SecurityIncident).where(
            SecurityIncident.workspace_id.in_(workspace_ids),
            SecurityIncident.closed_at.is_(None),
        ).order_by(SecurityIncident.opened_at.desc()).limit(50)
    ).scalars().all())

    # Severity breakdown
    severity_rows = db.execute(
        select(
            SecurityIncident.severity, func.count(SecurityIncident.id).label("c"),
        )
        .where(
            SecurityIncident.workspace_id.in_(workspace_ids),
            SecurityIncident.closed_at.is_(None),
        )
        .group_by(SecurityIncident.severity)
    ).all()

    severity_breakdown = {
        (sev.value if hasattr(sev, "value") else str(sev)): int(n)
        for sev, n in severity_rows
    }

    # Risk score: high/medium weights
    risk_score = (
        severity_breakdown.get("critical", 0) * 10
        + severity_breakdown.get("high", 0) * 5
        + severity_breakdown.get("medium", 0) * 2
        + severity_breakdown.get("low", 0) * 1
    )

    return {
        "summary": (
            f"Organization risk report — {len(open_incidents)} open "
            f"incidents across {len(workspace_ids)} workspace(s). "
            f"Risk score: {risk_score}."
        ),
        "title": report.title,
        "org_id": str(org_id) if org_id else None,
        "workspace_count": len(workspace_ids),
        "risk_score": risk_score,
        "severity_breakdown": severity_breakdown,
        "open_incidents": [
            {
                "id": str(i.id),
                "title": i.title,
                "severity": i.severity.value,
                "status": i.status.value,
                "opened_at": i.opened_at.isoformat(),
            }
            for i in open_incidents
        ],
    }


def _fetch_analyst_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """
    Data for analyst performance reports. Aggregates case assignments
    and resolution times.
    """
    from app.models.case import CaseAssignment
    from app.models.enums import CaseStatus

    ws_id = report.workspace_id

    # Analyst stats: count cases by analyst
    rows = db.execute(
        select(
            CaseAssignment.analyst_user_id,
            func.count(CaseAssignment.id).label("total"),
        )
        .join(SecurityCase, SecurityCase.id == CaseAssignment.case_id)
        .where(
            SecurityCase.workspace_id == ws_id,
            CaseAssignment.ended_at.is_(None),
        )
        .group_by(CaseAssignment.analyst_user_id)
        .limit(50)
    ).all()

    analysts: list[dict[str, Any]] = []
    for analyst_id, total in rows:
        # Resolved count
        resolved = db.execute(
            select(func.count()).select_from(SecurityCase).where(
                SecurityCase.workspace_id == ws_id,
                SecurityCase.assigned_to_id == analyst_id,
                SecurityCase.status == CaseStatus.CLOSED,
            )
        ).scalar_one()
        # Average resolution time (from resolved cases)
        avg_rows = db.execute(
            select(SecurityCase.time_to_resolve_seconds)
            .where(
                SecurityCase.workspace_id == ws_id,
                SecurityCase.assigned_to_id == analyst_id,
                SecurityCase.resolved_at.is_not(None),
            )
            .limit(100)
        ).scalars().all()
        avg_seconds = (
            sum(s for s in avg_rows if s is not None) // max(1, len([s for s in avg_rows if s is not None]))
            if any(s is not None for s in avg_rows) else None
        )
        analysts.append({
            "analyst_user_id": str(analyst_id),
            "active_cases": int(total),
            "resolved_cases": int(resolved),
            "avg_resolution_seconds": avg_seconds,
        })

    return {
        "summary": (
            f"Analyst performance report — {len(analysts)} analysts "
            f"with active assignments."
        ),
        "title": report.title,
        "analysts": analysts,
    }


def _fetch_custom_data(
    db: Session,
    report: SecurityReport,
) -> dict[str, Any]:
    """
    Data for custom reports. Uses ``report.parameters`` to define
    what to fetch. Currently supports a minimal "summary" mode —
    a future enhancement adds full query specification.
    """
    ws_id = report.workspace_id

    total_events = db.execute(
        select(func.count()).select_from(SecurityEvent).where(
            SecurityEvent.workspace_id == ws_id,
        )
    ).scalar_one()

    total_findings = db.execute(
        select(func.count()).select_from(AgentFinding).where(
            AgentFinding.workspace_id == ws_id,
        )
    ).scalar_one()

    return {
        "summary": (
            f"Custom report — {total_events} events, {total_findings} "
            f"findings. Parameters: {report.parameters or {}}"
        ),
        "title": report.title,
        "parameters": dict(report.parameters or {}),
        "counts": {
            "events": int(total_events),
            "findings": int(total_findings),
        },
    }


def _is_uuid(value: Any) -> bool:
    """Check if a value parses as UUID."""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


# ============================================================================
# FILE BUILDERS
# ============================================================================

def _build_file(report: SecurityReport, data: dict[str, Any]) -> bytes:
    """Dispatch file building by format."""
    fmt = report.report_format

    if fmt == "pdf":
        return _build_pdf(report, data)
    if fmt == "csv":
        return _build_csv(report, data)
    if fmt == "json":
        return _build_json(report, data)
    if fmt == "html":
        return _build_html(report, data)

    raise ValidationError(
        message=f"Format {fmt!r} not implemented.",
        code="REPORT_FORMAT_NOT_IMPLEMENTED",
    )


def _build_pdf(report: SecurityReport, data: dict[str, Any]) -> bytes:
    """Build a PDF using ReportLab."""
    buffer = io.BytesIO()

    doc = BaseDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=report.title,
        author="CyberGuard AI",
    )

    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        id="main",
    )
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame])])

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CGCoverTitle",
        parent=styles["Title"],
        fontSize=24,
        spaceAfter=20,
        textColor=colors.HexColor("#1e3a8a"),
    ))
    styles.add(ParagraphStyle(
        name="CGHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=6,
        textColor=colors.HexColor("#1e40af"),
    ))
    styles.add(ParagraphStyle(
        name="CGBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        name="CGMeta",
        parent=styles["BodyText"],
        fontSize=9,
        textColor=colors.HexColor("#6b7280"),
        spaceAfter=4,
    ))

    story: list = []

    # Cover
    story.append(Paragraph(report.title, styles["CGCoverTitle"]))
    story.append(Paragraph(
        f"Generated: {_now().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["CGMeta"],
    ))
    story.append(Paragraph(
        f"Report type: {report.report_type.value} | "
        f"Format: {report.report_format}",
        styles["CGMeta"],
    ))
    story.append(Paragraph(
        f"Report ID: {report.id}",
        styles["CGMeta"],
    ))
    if report.period_start_at and report.period_end_at:
        story.append(Paragraph(
            f"Period: {report.period_start_at.strftime('%Y-%m-%d')} "
            f"to {report.period_end_at.strftime('%Y-%m-%d')}",
            styles["CGMeta"],
        ))
    story.append(Spacer(1, 20))

    # Summary
    summary = data.get("summary")
    if summary:
        story.append(Paragraph("Executive Summary", styles["CGHeading"]))
        story.append(Paragraph(_escape_xml(str(summary)), styles["CGBody"]))
        story.append(Spacer(1, 12))

    # Sections (based on type)
    sections = _resolve_sections(report)
    if not sections:
        sections = ["summary"]

    # Dispatch by data shape
    if "incident" in data:
        _pdf_add_incident_sections(story, styles, data, sections)
    elif "counts" in data and "period" in data:
        _pdf_add_periodic_sections(story, styles, data, sections)
    elif "risk_score" in data:
        _pdf_add_org_risk_sections(story, styles, data, sections)
    elif "analysts" in data:
        _pdf_add_analyst_sections(story, styles, data, sections)

    # Footer
    story.append(Spacer(1, 24))
    story.append(Paragraph(
        f"Generated by CyberGuard AI — {_now().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["CGMeta"],
    ))

    doc.build(story)

    page_count = doc.page
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    # Store page count back into data for finish_generation
    data["page_count"] = page_count

    return pdf_bytes


def _pdf_add_incident_sections(
    story: list,
    styles: Any,
    data: dict[str, Any],
    sections: list[str],
) -> None:
    """Add incident-specific sections to the PDF story."""
    inc = data["incident"]

    if "executive_summary" in sections:
        story.append(Paragraph("Incident Overview", styles["CGHeading"]))
        rows = [
            ["Field", "Value"],
            ["Title", inc["title"]],
            ["Severity", inc["severity"].upper()],
            ["Category", inc["category"].replace("_", " ").title()],
            ["Status", inc["status"].replace("_", " ").title()],
            ["Opened", inc["opened_at"]],
            ["Resolved", inc["resolved_at"] or "—"],
            ["Closed", inc["closed_at"] or "—"],
        ]
        _pdf_add_table(story, styles, rows)

    if "affected_entities" in sections:
        if inc["affected_devices"] or inc["affected_users"] or inc["affected_ips"]:
            story.append(Paragraph("Affected Entities", styles["CGHeading"]))
            if inc["affected_devices"]:
                story.append(Paragraph(
                    f"<b>Devices:</b> {_escape_xml(', '.join(inc['affected_devices']))}",
                    styles["CGBody"],
                ))
            if inc["affected_users"]:
                story.append(Paragraph(
                    f"<b>Users:</b> {_escape_xml(', '.join(inc['affected_users']))}",
                    styles["CGBody"],
                ))
            if inc["affected_ips"]:
                story.append(Paragraph(
                    f"<b>IPs:</b> {_escape_xml(', '.join(inc['affected_ips']))}",
                    styles["CGBody"],
                ))
            if inc["mitre_techniques"]:
                story.append(Paragraph(
                    f"<b>MITRE ATT&CK:</b> {_escape_xml(', '.join(inc['mitre_techniques']))}",
                    styles["CGBody"],
                ))
            story.append(Spacer(1, 8))

    if "findings" in sections and data.get("findings"):
        story.append(Paragraph("Detection Findings", styles["CGHeading"]))
        rows = [["Severity", "Finding", "Agent", "Confidence", "Occurrences"]]
        for f in data["findings"][:30]:
            rows.append([
                f["severity"].upper(),
                f["title"][:60],
                f["agent_name"],
                f"{f['confidence']:.2f}",
                str(f["occurrence_count"]),
            ])
        _pdf_add_table(story, styles, rows)

    if "timeline" in sections:
        story.append(Paragraph("Timeline", styles["CGHeading"]))
        for entry in inc.get("status_history", [])[:50]:
            at = entry.get("at", "")
            to_status = entry.get("to", "")
            story.append(Paragraph(
                f"{at} — Status: {to_status}",
                styles["CGBody"],
            ))
        story.append(Spacer(1, 8))

    if "actions_taken" in sections:
        containment = inc.get("containment_actions", [])
        recovery = inc.get("recovery_actions", [])
        if containment or recovery:
            story.append(Paragraph("Actions Taken", styles["CGHeading"]))
            if containment:
                story.append(Paragraph("<b>Containment:</b>", styles["CGBody"]))
                for action in containment[:20]:
                    story.append(Paragraph(
                        f"  • {_escape_xml(str(action.get('action', '')))} "
                        f"→ {_escape_xml(str(action.get('target', '')))} "
                        f"({_escape_xml(str(action.get('result', '')))})",
                        styles["CGBody"],
                    ))
            if recovery:
                story.append(Paragraph("<b>Recovery:</b>", styles["CGBody"]))
                for action in recovery[:20]:
                    story.append(Paragraph(
                        f"  • {_escape_xml(str(action.get('action', '')))} "
                        f"→ {_escape_xml(str(action.get('target', '')))} "
                        f"({_escape_xml(str(action.get('result', '')))})",
                        styles["CGBody"],
                    ))
            story.append(Spacer(1, 8))

    if "recommendations" in sections:
        story.append(Paragraph("Recommendations", styles["CGHeading"]))
        story.append(Paragraph(
            _generate_recommendation_text(inc),
            styles["CGBody"],
        ))


def _pdf_add_periodic_sections(
    story: list,
    styles: Any,
    data: dict[str, Any],
    sections: list[str],
) -> None:
    """Add periodic-report-specific sections."""
    counts = data.get("counts", {})

    if "summary" in sections or "top_categories" in sections:
        story.append(Paragraph("Activity Summary", styles["CGHeading"]))
        rows = [
            ["Metric", "Count"],
            ["Events", str(counts.get("events", 0))],
            ["Findings", str(counts.get("findings", 0))],
            ["Alerts", str(counts.get("alerts", 0))],
            ["Incidents", str(counts.get("incidents", 0))],
        ]
        _pdf_add_table(story, styles, rows)

    if "top_categories" in sections and data.get("top_categories"):
        story.append(Paragraph("Top Categories", styles["CGHeading"]))
        rows = [["Category", "Findings"]]
        for cat in data["top_categories"]:
            rows.append([
                cat["category"].replace("_", " ").title(),
                str(cat["count"]),
            ])
        _pdf_add_table(story, styles, rows)

    if "top_sources" in sections and data.get("top_sources"):
        story.append(Paragraph("Top Sources", styles["CGHeading"]))
        rows = [["Source ID", "Events"]]
        for src in data["top_sources"]:
            rows.append([
                (src["source_id"] or "—")[:20],
                str(src["count"]),
            ])
        _pdf_add_table(story, styles, rows)

    if "open_incidents" in sections and data.get("open_incidents"):
        story.append(Paragraph("Open Incidents", styles["CGHeading"]))
        rows = [["Severity", "Title", "Opened"]]
        for inc in data["open_incidents"][:20]:
            rows.append([
                inc["severity"].upper(),
                inc["title"][:60],
                inc["opened_at"][:10],
            ])
        _pdf_add_table(story, styles, rows)


def _pdf_add_org_risk_sections(
    story: list,
    styles: Any,
    data: dict[str, Any],
    sections: list[str],
) -> None:
    story.append(Paragraph("Risk Overview", styles["CGHeading"]))
    rows = [
        ["Metric", "Value"],
        ["Overall Risk Score", str(data.get("risk_score", 0))],
        ["Workspaces", str(data.get("workspace_count", 0))],
    ]
    _pdf_add_table(story, styles, rows)

    if "severity_breakdown" in sections and data.get("severity_breakdown"):
        story.append(Paragraph("Severity Breakdown", styles["CGHeading"]))
        rows = [["Severity", "Count"]]
        for sev, count in data["severity_breakdown"].items():
            rows.append([sev.upper(), str(count)])
        _pdf_add_table(story, styles, rows)

    if "top_threats" in sections and data.get("open_incidents"):
        story.append(Paragraph("Open Incidents", styles["CGHeading"]))
        rows = [["Severity", "Title", "Opened"]]
        for inc in data["open_incidents"][:30]:
            rows.append([
                inc["severity"].upper(),
                inc["title"][:60],
                inc["opened_at"][:10],
            ])
        _pdf_add_table(story, styles, rows)


def _pdf_add_analyst_sections(
    story: list,
    styles: Any,
    data: dict[str, Any],
    sections: list[str],
) -> None:
    if not data.get("analysts"):
        story.append(Paragraph(
            "No analyst activity in this period.",
            styles["CGBody"],
        ))
        return
    story.append(Paragraph("Analyst Performance", styles["CGHeading"]))
    rows = [["Analyst ID", "Active Cases", "Resolved", "Avg Resolution"]]
    for a in data["analysts"]:
        avg = a.get("avg_resolution_seconds")
        avg_str = (
            f"{avg // 3600}h {(avg % 3600) // 60}m" if avg else "—"
        )
        rows.append([
            a["analyst_user_id"][:12],
            str(a["active_cases"]),
            str(a["resolved_cases"]),
            avg_str,
        ])
    _pdf_add_table(story, styles, rows)


def _pdf_add_table(
    story: list,
    styles: Any,
    rows: list[list[str]],
) -> None:
    """Add a styled table to the PDF story."""
    if not rows:
        return
    table = Table(rows, hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f4f6")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))


def _build_csv(report: SecurityReport, data: dict[str, Any]) -> bytes:
    """Build a CSV. Structure depends on report type."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    # Header
    writer.writerow([report.title])
    writer.writerow([f"Generated: {_now().isoformat()}"])
    writer.writerow([f"Report type: {report.report_type.value}"])
    writer.writerow([])

    # Summary
    if data.get("summary"):
        writer.writerow(["Summary", data["summary"]])
        writer.writerow([])

    # Data rows — depends on shape
    if "incident" in data:
        inc = data["incident"]
        writer.writerow(["Field", "Value"])
        for key in (
            "title", "severity", "category", "status",
            "opened_at", "resolved_at", "closed_at", "root_cause",
            "resolution_summary", "lessons_learned",
        ):
            writer.writerow([key, inc.get(key, "")])
        writer.writerow([])
        writer.writerow([
            "Finding ID", "Severity", "Title", "Agent", "Confidence",
        ])
        for f in data.get("findings", []):
            writer.writerow([
                f["id"], f["severity"], f["title"],
                f["agent_name"], f["confidence"],
            ])

    elif "counts" in data:
        writer.writerow(["Metric", "Count"])
        for k, v in data["counts"].items():
            writer.writerow([k, v])
        writer.writerow([])
        if data.get("top_categories"):
            writer.writerow(["Category", "Findings"])
            for cat in data["top_categories"]:
                writer.writerow([cat["category"], cat["count"]])

    elif "risk_score" in data:
        writer.writerow(["Metric", "Value"])
        writer.writerow(["risk_score", data.get("risk_score", 0)])
        writer.writerow(["workspace_count", data.get("workspace_count", 0)])
        for sev, count in (data.get("severity_breakdown") or {}).items():
            writer.writerow([f"severity_{sev}", count])

    elif "analysts" in data:
        writer.writerow([
            "Analyst ID", "Active Cases", "Resolved", "Avg Resolution (s)",
        ])
        for a in data["analysts"]:
            writer.writerow([
                a["analyst_user_id"],
                a["active_cases"],
                a["resolved_cases"],
                a["avg_resolution_seconds"] or "",
            ])

    return buffer.getvalue().encode("utf-8")


def _build_json(report: SecurityReport, data: dict[str, Any]) -> bytes:
    """Build a structured JSON payload."""
    payload = {
        "report_id": str(report.id),
        "title": report.title,
        "report_type": report.report_type.value,
        "report_format": report.report_format,
        "generated_at": _now().isoformat(),
        "period_start_at": report.period_start_at.isoformat() if report.period_start_at else None,
        "period_end_at": report.period_end_at.isoformat() if report.period_end_at else None,
        "parameters": report.parameters,
        "data": data,
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def _build_html(report: SecurityReport, data: dict[str, Any]) -> bytes:
    """Build a self-contained HTML document."""
    parts: list[str] = []
    parts.append(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{_escape_html(report.title)}</title>"
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;"
        "max-width:900px;margin:2rem auto;padding:1rem;color:#1f2937;"
        "line-height:1.6}"
        "h1{color:#1e3a8a;border-bottom:2px solid #1e3a8a;padding-bottom:.5rem}"
        "h2{color:#1e40af;margin-top:2rem;border-bottom:1px solid #e5e7eb;"
        "padding-bottom:.25rem}"
        ".meta{color:#6b7280;font-size:.875rem}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0}"
        "th{background:#1e40af;color:white;text-align:left;padding:.5rem}"
        "td{padding:.5rem;border-bottom:1px solid #e5e7eb}"
        "tr:nth-child(even){background:#f9fafb}"
        ".footer{margin-top:3rem;color:#9ca3af;font-size:.8rem;"
        "text-align:center}"
        "</style></head><body>"
    )

    parts.append(f"<h1>{_escape_html(report.title)}</h1>")
    parts.append(
        f"<p class='meta'>Generated: {_now().strftime('%Y-%m-%d %H:%M UTC')}"
        f" | Report type: {report.report_type.value}"
        f" | Report ID: {report.id}</p>"
    )

    if data.get("summary"):
        parts.append("<h2>Executive Summary</h2>")
        parts.append(f"<p>{_escape_html(str(data['summary']))}</p>")

    # Section-specific rendering
    if "incident" in data:
        inc = data["incident"]
        parts.append("<h2>Incident Overview</h2>")
        parts.append("<table>")
        for key in (
            "title", "severity", "category", "status",
            "opened_at", "resolved_at", "closed_at",
        ):
            parts.append(
                f"<tr><th>{_escape_html(key)}</th>"
                f"<td>{_escape_html(str(inc.get(key, '—')))}</td></tr>"
            )
        parts.append("</table>")

        if data.get("findings"):
            parts.append("<h2>Findings</h2>")
            parts.append("<table><tr><th>Severity</th><th>Title</th>"
                         "<th>Agent</th><th>Confidence</th></tr>")
            for f in data["findings"][:50]:
                parts.append(
                    f"<tr><td>{_escape_html(f['severity'])}</td>"
                    f"<td>{_escape_html(f['title'])}</td>"
                    f"<td>{_escape_html(f['agent_name'])}</td>"
                    f"<td>{f['confidence']:.2f}</td></tr>"
                )
            parts.append("</table>")

    elif "counts" in data:
        parts.append("<h2>Activity Summary</h2>")
        parts.append("<table><tr><th>Metric</th><th>Count</th></tr>")
        for k, v in data["counts"].items():
            parts.append(
                f"<tr><td>{_escape_html(str(k))}</td>"
                f"<td>{_escape_html(str(v))}</td></tr>"
            )
        parts.append("</table>")
        if data.get("top_categories"):
            parts.append("<h2>Top Categories</h2>")
            parts.append("<table><tr><th>Category</th><th>Count</th></tr>")
            for cat in data["top_categories"]:
                parts.append(
                    f"<tr><td>{_escape_html(cat['category'])}</td>"
                    f"<td>{cat['count']}</td></tr>"
                )
            parts.append("</table>")

    elif "risk_score" in data:
        parts.append("<h2>Risk Overview</h2>")
        parts.append(
            f"<p><strong>Overall Risk Score:</strong> {data['risk_score']}</p>"
        )
        if data.get("severity_breakdown"):
            parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
            for sev, count in data["severity_breakdown"].items():
                parts.append(
                    f"<tr><td>{_escape_html(sev)}</td><td>{count}</td></tr>"
                )
            parts.append("</table>")

    elif "analysts" in data:
        parts.append("<h2>Analyst Performance</h2>")
        parts.append("<table><tr><th>Analyst</th><th>Active</th>"
                     "<th>Resolved</th></tr>")
        for a in data["analysts"]:
            parts.append(
                f"<tr><td>{_escape_html(a['analyst_user_id'][:12])}</td>"
                f"<td>{a['active_cases']}</td>"
                f"<td>{a['resolved_cases']}</td></tr>"
            )
        parts.append("</table>")

    parts.append(
        f"<p class='footer'>Generated by CyberGuard AI — "
        f"{_now().strftime('%Y-%m-%d %H:%M UTC')}</p>"
    )
    parts.append("</body></html>")

    return "".join(parts).encode("utf-8")


def _escape_xml(text: str) -> str:
    """Escape text for ReportLab paragraphs (which parse XML)."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _escape_html(text: str) -> str:
    """Escape text for HTML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _generate_recommendation_text(incident_data: dict[str, Any]) -> str:
    """Generate a short recommendation based on incident category."""
    category = incident_data.get("category", "").lower()
    severity = incident_data.get("severity", "medium").lower()

    if category == "brute_force":
        return (
            "1. Enable account lockout thresholds. "
            "2. Require MFA for all users. "
            "3. Block offending IPs at the firewall. "
            "4. Review authentication logs for successful compromises."
        )
    if category == "phishing":
        return (
            "1. Warn affected users. "
            "2. Quarantine the phishing emails. "
            "3. Block the sender domain. "
            "4. Review any clicked links for credential entry."
        )
    if category == "malware":
        return (
            "1. Isolate affected devices from the network. "
            "2. Run full antivirus/EDR scans. "
            "3. Review outbound connections for exfiltration. "
            "4. Reimage if necessary."
        )
    if category == "port_scan":
        return (
            "1. Review firewall rules for exposed services. "
            "2. Consider blocking the scanning IPs. "
            "3. Ensure no unnecessary services are exposed to the internet."
        )

    if severity == "critical":
        return (
            "Immediate response required. Escalate to senior analyst. "
            "Consider containment actions and client notification."
        )
    return (
        "Review evidence, confirm findings, and document actions taken. "
        "Update incident with root cause and lessons learned before closing."
    )


# ============================================================================
# DOWNLOAD
# ============================================================================

def prepare_download(
    db: Session,
    *,
    actor: User,
    report: SecurityReport,
    request: Any | None = None,
) -> ReportDownloadResult:
    """
    Prepare the file for download. Verifies integrity and records the
    download (via ``record_download``) but does NOT audit — the
    endpoint's ``audit_service.log_action`` call covers it (see
    File 91, reports router).

    Access check: caller must be the requester or have an active
    share (via ``shared_with``).
    """
    # ── Access check
        # ── Access check
    is_requester = (
        report.requested_by_id is not None
        and report.requested_by_id == actor.id
    )
    if not is_requester:
        # Not the requester (or system-generated) — check shared_with
        # or fall back to workspace permission
        if not _is_shared_with(report, actor.id):
            authorization.check_permission(
                db, actor, "report:download", workspace_id=report.workspace_id,
            )

    # ── Status check
    if report.generation_status != ReportStatus.READY:
        raise ValidationError(
            message=(
                f"Report is not ready for download "
                f"(status: {report.generation_status.value})."
            ),
            code="REPORT_NOT_READY",
            details={"status": report.generation_status.value},
        )

    # ── Read file
    path = report.get_storage_path()
    if not path.exists() or not path.is_file():
        raise NotFoundError(
            message="Report file not found on disk.",
            code="REPORT_FILE_MISSING",
            details={"report_id": str(report.id)},
        )
    file_bytes = path.read_bytes()

    # ── Verify integrity
    computed_hash = _compute_sha256(file_bytes)
    verified = computed_hash == report.content_hash

    if not verified:
        logger.warning(
            "Report integrity verification FAILED — returning tampered file",
            extra={
                "report_id": str(report.id),
                "stored_hash_prefix": report.content_hash[:12] if report.content_hash else None,
                "computed_hash_prefix": computed_hash[:12],
            },
        )
        report.integrity_verified = False
        report.last_integrity_check_at = _now()
        audit_service.log_action(
            db,
            actor=actor,
            action="report.integrity_failed",
            outcome=audit_service.AuditOutcome.FAILURE,
            target_type="report",
            target_id=report.id,
            workspace_id=report.workspace_id,
            request=request,
            notes="File content does not match stored hash.",
            metadata={
                "stored_hash_prefix": (report.content_hash or "")[:12],
                "computed_hash_prefix": computed_hash[:12],
            },
        )

    report.record_download()
    db.flush()

    return ReportDownloadResult(
        file_bytes=file_bytes,
        mime_type=_MIME_TYPES.get(report.report_format, "application/octet-stream"),
        content_hash=computed_hash,
        verified=verified,
        title=report.title,
        report_format=report.report_format,
    )


def _is_shared_with(report: SecurityReport, user_id: uuid.UUID) -> bool:
    """Check if the user has an active share of this report."""
    uid = str(user_id)
    for entry in (report.shared_with or []):
        if entry.get("user_id") != uid:
            continue
        exp = entry.get("expires_at")
        if exp is None:
            return True
        try:
            exp_dt = datetime.fromisoformat(exp)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            return exp_dt > _now()
        except (ValueError, TypeError):
            return False
    return False


# ============================================================================
# SHARE / UNSHARE
# ============================================================================

def share_report(
    db: Session,
    *,
    actor: User,
    report: SecurityReport,
    user_id: uuid.UUID,
    expires_at: datetime | None = None,
    request: Any | None = None,
) -> SecurityReport:
    """
    Share a report with a specific user.

    The sharing user must be the report's requester or have a workspace
    owner/admin role. The recipient is granted read access to the file
    even if they're not a workspace member.
    """
    if report.requested_by_id != actor.id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, actor, report.workspace_id,
        )
        if ws_role not in (WorkspaceRole.OWNER, WorkspaceRole.EDITOR):
            raise AuthorizationError(
                message="You cannot share this report.",
                code="REPORT_SHARE_DENIED",
            )

    target = db.get(User, user_id)
    if target is None or target.deleted_at is not None:
        raise NotFoundError(
            message=f"User {user_id} not found.",
            code="USER_NOT_FOUND",
        )

    report.share_with(
        user_id=user_id,
        shared_by_id=actor.id,
        expires_at=expires_at,
    )
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="report.shared",
        target_type="report",
        target_id=report.id,
        workspace_id=report.workspace_id,
        request=request,
        metadata={
            "shared_with_user_id": str(user_id),
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )

    return report


def unshare_report(
    db: Session,
    *,
    actor: User,
    report: SecurityReport,
    user_id: uuid.UUID,
    request: Any | None = None,
) -> SecurityReport:
    """Remove a user's share of a report. Idempotent."""
    if report.requested_by_id != actor.id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, actor, report.workspace_id,
        )
        if ws_role not in (WorkspaceRole.OWNER, WorkspaceRole.EDITOR):
            raise AuthorizationError(
                message="You cannot unshare this report.",
                code="REPORT_UNSHARE_DENIED",
            )

    report.unshare_with(user_id=user_id)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="report.unshared",
        target_type="report",
        target_id=report.id,
        workspace_id=report.workspace_id,
        request=request,
        metadata={"unshared_user_id": str(user_id)},
    )

    return report


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, report_id: uuid.UUID) -> SecurityReport:
    """Fetch a report by ID."""
    report = db.get(SecurityReport, report_id)
    if report is None or report.deleted_at is not None:
        raise NotFoundError(
            message=f"Report {report_id} not found.",
            code="REPORT_NOT_FOUND",
            details={"report_id": str(report_id)},
        )
    return report


def list_reports(
    db: Session,
    *,
    workspace_ids: list[uuid.UUID] | None,
    page: PageParams,
    filters: ReportFilter,
) -> tuple[list[SecurityReport], int]:
    """List reports with filters and pagination."""
    stmt = select(SecurityReport).where(SecurityReport.deleted_at.is_(None))

    if workspace_ids is not None:
        stmt = stmt.where(SecurityReport.workspace_id.in_(workspace_ids))

    if filters.report_type is not None:
        stmt = stmt.where(SecurityReport.report_type == filters.report_type)
    if filters.report_format:
        stmt = stmt.where(SecurityReport.report_format == filters.report_format)
    if filters.generation_status is not None:
        stmt = stmt.where(SecurityReport.generation_status == filters.generation_status)
    if filters.scope_type:
        stmt = stmt.where(SecurityReport.scope_type == filters.scope_type)
    if filters.scope_id is not None:
        stmt = stmt.where(SecurityReport.scope_id == filters.scope_id)
    if filters.report_group_id is not None:
        stmt = stmt.where(SecurityReport.report_group_id == filters.report_group_id)
    if filters.requested_by_id is not None:
        stmt = stmt.where(SecurityReport.requested_by_id == filters.requested_by_id)
    if filters.is_scheduled is not None:
        stmt = stmt.where(SecurityReport.is_scheduled == filters.is_scheduled)
    if filters.created_after is not None:
        stmt = stmt.where(SecurityReport.created_at >= filters.created_after)
    if filters.created_before is not None:
        stmt = stmt.where(SecurityReport.created_at <= filters.created_before)
    if filters.title_contains:
        stmt = stmt.where(
            SecurityReport.title.ilike(f"%{filters.title_contains.lower()}%")
        )
    if filters.has_expired:
        now = _now()
        stmt = stmt.where(
            SecurityReport.expires_at.is_not(None),
            SecurityReport.expires_at < now,
        )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(SecurityReport.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# DELETE
# ============================================================================

def delete_report(
    db: Session,
    *,
    actor: User,
    report: SecurityReport,
    reason: str,
    request: Any | None = None,
) -> SecurityReport:
    """
    Soft-delete a report. Requires the requester or workspace owner.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A deletion reason is required.",
            code="REPORT_DELETE_REASON_REQUIRED",
        )

    if report.deleted_at is not None:
        return report  # idempotent

    if report.requested_by_id != actor.id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, actor, report.workspace_id,
        )
        if ws_role != WorkspaceRole.OWNER:
            raise AuthorizationError(
                message="You cannot delete this report.",
                code="REPORT_DELETE_DENIED",
            )

    report.deleted_at = _now()
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="report.deleted",
        target_type="report",
        target_id=report.id,
        workspace_id=report.workspace_id,
        request=request,
        notes=reason.strip(),
    )

    return report


# ============================================================================
# CLEANUP
# ============================================================================

def cleanup_expired(
    db: Session,
    *,
    limit: int = 100,
) -> int:
    """
    Delete reports whose ``expires_at`` has passed AND that aren't
    under legal hold. Called by a periodic background job.

    Deletes both DB row and disk file. Respects ``legal_hold_until``
    (skips held reports entirely).

    Returns count deleted.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")

    now = _now()
    candidates = db.execute(
        select(SecurityReport)
        .where(
            SecurityReport.expires_at.is_not(None),
            SecurityReport.expires_at < now,
            SecurityReport.deleted_at.is_(None),
            (
                SecurityReport.legal_hold_until.is_(None)
                | (SecurityReport.legal_hold_until <= now)
            ),
        )
        .limit(limit)
    ).scalars().all()

    deleted = 0
    for report in candidates:
        # Delete file from disk
        try:
            path = report.get_storage_path()
            if path.exists():
                path.unlink()
        except OSError as exc:
            logger.warning(
                "Failed to delete report file from disk",
                extra={
                    "report_id": str(report.id),
                    "error": str(exc)[:200],
                },
            )
            continue

        # Hard delete DB row (this is retention cleanup, not soft delete)
        db.delete(report)
        deleted += 1

    if deleted > 0:
        db.flush()
        logger.info(
            "Expired reports cleaned up",
            extra={"count": deleted},
        )

    return deleted


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ReportDownloadResult",
    "request_report",
    "generate_report",
    "prepare_download",
    "share_report",
    "unshare_report",
    "get_by_id",
    "list_reports",
    "delete_report",
    "cleanup_expired",
]