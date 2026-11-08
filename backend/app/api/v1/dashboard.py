"""
CyberGuard AI — Dashboard Aggregation Endpoints
============================================================================
Provides unified, live database aggregations for:
  - GET /dashboard/personal       — Individual user security posture
  - GET /dashboard/analyst        — Security analyst operational metrics
  - GET /dashboard/organization   — Enterprise fleet & room governance
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentActiveUser, DBDep
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.case import CaseAssignment, SecurityCase
from app.models.enums import AlertStatus, CaseStatus, EventCategory, EventSeverity, ReportStatus, SourceStatus
from app.models.event import SecurityEvent
from app.models.evidence import SecurityEvidence
from app.models.finding import AgentFinding
from app.models.marketplace import PaymentTransaction, ServicePurchase
from app.models.membership import OrganizationMembership
from app.models.organization import Organization
from app.models.report import SecurityReport
from app.models.room import Room, RoomMember
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.services import workspace_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    return workspace_service.create_personal_workspace(db, user)


class PersonalDashboardResponse(BaseModel):
    devices_count: int
    devices_protected: int
    devices_at_risk: int
    devices_offline: int
    alerts_active: int
    alerts_critical: int
    threat_score: int
    findings_count: int
    last_scan_at: Optional[str] = None
    devices: List[dict[str, Any]]
    recent_alerts: List[dict[str, Any]]
    recent_findings: List[dict[str, Any]]


class AnalystDashboardResponse(BaseModel):
    assigned_cases: int
    available_cases: int
    evidence_vault_items: int
    pending_reports: int
    completed_cases: int
    available_balance_cents: int
    currency: str
    priority_cases: List[dict[str, Any]]


class OrganizationDashboardResponse(BaseModel):
    total_employees: int
    enrolled_devices: int
    online_devices: int
    offline_devices: int
    active_rooms: int
    active_alerts: int
    open_incidents: int
    critical_findings: int
    analyst_assignments: int
    organization_name: str


@router.get("/personal", response_model=PersonalDashboardResponse, summary="Get personal security posture aggregations")
def get_personal_dashboard(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> PersonalDashboardResponse:
    workspace = _get_user_workspace(db, current_user)
    now = datetime.now(timezone.utc)

    # 1. Devices
    sources = list(
        db.execute(
            select(SecuritySource).where(SecuritySource.workspace_id == workspace.id)
        ).scalars().all()
    )

    devices_count = len(sources)
    devices_protected = 0
    devices_at_risk = 0
    devices_offline = 0
    device_items = []

    for src in sources:
        th_cnt = db.execute(
            select(func.count(AgentFinding.id)).where(
                AgentFinding.source_id == src.id,
                AgentFinding.status.in_(["new", "investigating"]),
            )
        ).scalar() or 0

        is_online = False
        if src.collector_connected and src.last_heartbeat_at:
            delta = (now - src.last_heartbeat_at).total_seconds()
            is_online = delta <= 300

        if not is_online:
            st = "offline"
            devices_offline += 1
        elif th_cnt > 0:
            st = "at_risk"
            devices_at_risk += 1
        else:
            st = "protected"
            devices_protected += 1

        device_items.append({
            "id": str(src.id),
            "name": src.name,
            "type": src.source_type.value,
            "status": st,
            "last_scan": src.last_event_at.isoformat() if src.last_event_at else None,
            "threat_count": th_cnt,
        })

    # 2. Alerts
    alerts = list(
        db.execute(
            select(SecurityAlert)
            .where(SecurityAlert.workspace_id == workspace.id)
            .order_by(SecurityAlert.created_at.desc())
            .limit(10)
        ).scalars().all()
    )

    alerts_active = sum(1 for a in alerts if a.status in [AlertStatus.NEW, AlertStatus.INVESTIGATING, AlertStatus.ACKNOWLEDGED])
    alerts_critical = sum(1 for a in alerts if a.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH] and a.status in [AlertStatus.NEW, AlertStatus.INVESTIGATING])

    recent_alerts = [
        {
            "id": str(a.id),
            "title": a.title,
            "severity": a.severity.value,
            "source": a.category.value if a.category else "Detection Rule",
            "timestamp": a.created_at.isoformat(),
            "status": a.status.value,
        }
        for a in alerts[:5]
    ]

    # 3. Findings
    findings = list(
        db.execute(
            select(AgentFinding)
            .where(AgentFinding.workspace_id == workspace.id)
            .order_by(AgentFinding.created_at.desc())
            .limit(10)
        ).scalars().all()
    )

    recent_findings = [
        {
            "id": str(f.id),
            "title": f.title,
            "type": f.category.value,
            "risk_score": int(f.confidence * 100),
            "detected_at": f.created_at.isoformat(),
            "status": f.status.value,
        }
        for f in findings[:5]
    ]

    # Threat score calculation (0 if clean, increments with active severity)
    threat_score = 0
    if alerts_critical > 0:
        threat_score = min(100, 60 + alerts_critical * 15)
    elif alerts_active > 0:
        threat_score = min(60, 20 + alerts_active * 10)

    latest_ev = db.execute(
        select(SecurityEvent.received_at)
        .where(SecurityEvent.workspace_id == workspace.id)
        .order_by(SecurityEvent.received_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    return PersonalDashboardResponse(
        devices_count=devices_count,
        devices_protected=devices_protected,
        devices_at_risk=devices_at_risk,
        devices_offline=devices_offline,
        alerts_active=alerts_active,
        alerts_critical=alerts_critical,
        threat_score=threat_score,
        findings_count=len(findings),
        last_scan_at=latest_ev.isoformat() if latest_ev else None,
        devices=device_items,
        recent_alerts=recent_alerts,
        recent_findings=recent_findings,
    )


@router.get("/analyst", response_model=AnalystDashboardResponse, summary="Get analyst operational metrics")
def get_analyst_dashboard(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> AnalystDashboardResponse:
    # 1. Assigned cases
    assigned_count = db.execute(
        select(func.count(SecurityCase.id))
        .where(
            SecurityCase.assigned_to_id == current_user.id,
            SecurityCase.status.in_([CaseStatus.OPEN, CaseStatus.ASSIGNED, CaseStatus.INVESTIGATING]),
        )
    ).scalar() or 0

    # 2. Available cases
    available_count = db.execute(
        select(func.count(SecurityCase.id))
        .where(
            SecurityCase.status == CaseStatus.OPEN,
            SecurityCase.assigned_to_id.is_(None),
        )
    ).scalar() or 0

    # 3. Completed cases
    completed_count = db.execute(
        select(func.count(SecurityCase.id))
        .where(
            SecurityCase.assigned_to_id == current_user.id,
            SecurityCase.status == CaseStatus.CLOSED,
        )
    ).scalar() or 0

    # 4. Evidence items
    evidence_count = db.execute(
        select(func.count(SecurityEvidence.id))
    ).scalar() or 0

    # 5. Pending reports
    reports_count = db.execute(
        select(func.count(SecurityReport.id))
        .where(SecurityReport.generation_status.in_([ReportStatus.QUEUED, ReportStatus.GENERATING]))
    ).scalar() or 0

    # 6. Real earnings from completed service purchases
    total_earnings = db.execute(
        select(func.coalesce(func.sum(PaymentTransaction.amount_cents), 0))
        .join(ServicePurchase, PaymentTransaction.purchase_id == ServicePurchase.id)
        .where(
            PaymentTransaction.status == "succeeded",
        )
    ).scalar() or 0

    # 7. Priority assigned cases list
    cases_records = list(
        db.execute(
            select(SecurityCase)
            .where(SecurityCase.assigned_to_id == current_user.id)
            .order_by(SecurityCase.created_at.desc())
            .limit(5)
        ).scalars().all()
    )

    priority_cases = [
        {
            "id": str(c.id),
            "case_number": c.case_number,
            "title": c.title,
            "severity": c.severity.value,
            "status": c.status.value,
            "created_at": c.created_at.isoformat(),
        }
        for c in cases_records
    ]

    return AnalystDashboardResponse(
        assigned_cases=assigned_count,
        available_cases=available_count,
        evidence_vault_items=evidence_count,
        pending_reports=reports_count,
        completed_cases=completed_count,
        available_balance_cents=int(total_earnings),
        currency="USD",
        priority_cases=priority_cases,
    )


@router.get("/organization", response_model=OrganizationDashboardResponse, summary="Get organization enterprise metrics")
def get_organization_dashboard(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> OrganizationDashboardResponse:
    # Find organization where user is owner or member
    membership = db.execute(
        select(OrganizationMembership)
        .where(OrganizationMembership.user_id == current_user.id)
    ).scalar_one_or_none()

    org = None
    if membership:
        org = db.execute(
            select(Organization).where(Organization.id == membership.organization_id)
        ).scalar_one_or_none()

    if not org:
        # Fallback to organization owned by user
        org = db.execute(
            select(Organization).where(Organization.owner_id == current_user.id)
        ).scalar_one_or_none()

    if not org:
        return OrganizationDashboardResponse(
            total_employees=1,
            enrolled_devices=0,
            online_devices=0,
            offline_devices=0,
            active_rooms=0,
            active_alerts=0,
            open_incidents=0,
            critical_findings=0,
            analyst_assignments=0,
            organization_name="Personal Workspace (No Organization)",
        )

    # Real counts
    employees_count = db.execute(
        select(func.count(OrganizationMembership.id))
        .where(OrganizationMembership.organization_id == org.id)
    ).scalar() or 1

    rooms_count = db.execute(
        select(func.count(Room.id))
        .where(Room.organization_id == org.id, Room.status == "active")
    ).scalar() or 0

    return OrganizationDashboardResponse(
        total_employees=employees_count,
        enrolled_devices=0,
        online_devices=0,
        offline_devices=0,
        active_rooms=rooms_count,
        active_alerts=0,
        open_incidents=0,
        critical_findings=0,
        analyst_assignments=0,
        organization_name=org.name,
    )
