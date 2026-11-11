"""
CyberGuard AI — Log Monitoring Endpoints
============================================================================
Provides normalized log telemetry summaries across Windows Event Logs,
Linux syslog/journald, SSH authentication logs, and database audit logs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentActiveUser, DBDep
from app.core.logging import get_logger
from app.models.enums import EventCategory, EventSeverity, SourceType
from app.models.event import SecurityEvent
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.services import windows_event_explainer, workspace_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/logs",
    tags=["logs"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    return workspace_service.create_personal_workspace(db, user)


class LogSummaryResponse(BaseModel):
    total_sources: int
    failed_logins_24h: int
    privilege_escalations_24h: int
    anomalous_events: int
    events: List[dict[str, Any]]
    message: Optional[str] = None


@router.get("/summary", response_model=LogSummaryResponse, summary="Get normalized log monitoring telemetry summary")
def get_log_summary(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> LogSummaryResponse:
    workspace = _get_user_workspace(db, current_user)
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)

    # Count distinct log sources (Windows, Linux, database, web_app)
    sources_count = db.execute(
        select(func.count(SecuritySource.id))
        .where(
            SecuritySource.workspace_id == workspace.id,
            SecuritySource.source_type.in_([
                SourceType.WINDOWS,
                SourceType.LINUX,
                SourceType.DATABASE,
                SourceType.WEB_APP,
            ]),
        )
    ).scalar() or 0

    failed_logins = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.event_time >= since_24h,
            or_(
                SecurityEvent.event_type.ilike("%failed%"),
                SecurityEvent.outcome == "failure",
            ),
        )
    ).scalar() or 0

    priv_escalations = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.event_time >= since_24h,
            or_(
                SecurityEvent.event_type.ilike("%privilege%"),
                SecurityEvent.category == EventCategory.AUTHORIZATION,
            ),
        )
    ).scalar() or 0

    log_categories = [
        EventCategory.AUTHENTICATION,
        EventCategory.PROCESS,
        EventCategory.FILE,
        EventCategory.SYSTEM,
        EventCategory.AUTHORIZATION,
        EventCategory.OTHER,
    ]

    anomalies = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.category.in_(log_categories),
            SecurityEvent.event_time >= since_24h,
            SecurityEvent.severity.in_([EventSeverity.HIGH, EventSeverity.CRITICAL]),
        )
    ).scalar() or 0

    recent_events = list(
        db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.workspace_id == workspace.id,
                SecurityEvent.category.in_(log_categories),
            )
            .order_by(SecurityEvent.received_at.desc())
            .limit(50)
        ).scalars().all()
    )

    ev_list = []
    seen_benign_keys: set[str] = set()

    for ev in recent_events:
        summary_info = windows_event_explainer.get_friendly_event_summary(
            event_type=ev.event_type,
            raw_payload=ev.raw_payload,
            username=ev.username,
            hostname=ev.hostname,
            process_name=ev.process_name,
            category=ev.category.value if hasattr(ev.category, "value") else str(ev.category),
        )

        sev_val = ev.severity.value if hasattr(ev.severity, "value") else str(ev.severity)
        is_threat = sev_val in ("high", "critical", "medium")

        # Noise reduction: Deduplicate only identical recurring benign events for the SAME process/details
        # Ensures all distinct applications and all harmful/suspicious events are permanently visible
        proc_tag = summary_info.get("process_display") or ev.process_name or summary_info.get("event_id") or "sys"
        benign_key = f"{ev.hostname}|{proc_tag}|{summary_info['title']}|{summary_info['friendly_details']}"
        if not is_threat and benign_key in seen_benign_keys:
            continue
        if not is_threat:
            seen_benign_keys.add(benign_key)

        ev_list.append({
            "id": str(ev.id),
            "timestamp": ev.received_at.isoformat(),
            "source": summary_info["friendly_source"],
            "event_type": ev.event_type,
            "title": summary_info["title"],
            "event_id": summary_info["event_id"],
            "plain_english": summary_info["plain_english"],
            "category_label": summary_info["category_label"],
            "process_display": summary_info["process_display"],
            "badge_label": summary_info["badge_label"],
            "severity": sev_val,
            "details": summary_info["friendly_details"],
            "hostname": ev.hostname,
            "username": ev.username,
        })

    msg = None
    if sources_count == 0 and len(ev_list) == 0:
        msg = "No log source is currently reporting events."

    threat_in_feed = sum(1 for e in ev_list if e.get("severity") in ("high", "critical"))
    reported_anomalies = max(anomalies, threat_in_feed)

    return LogSummaryResponse(
        total_sources=sources_count,
        failed_logins_24h=failed_logins,
        privilege_escalations_24h=priv_escalations,
        anomalous_events=reported_anomalies,
        events=ev_list,
        message=msg,
    )


@router.get("/events", summary="List raw and normalized log events")
def list_log_events(
    db: DBDep,
    current_user: CurrentActiveUser,
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
) -> List[dict[str, Any]]:
    workspace = _get_user_workspace(db, current_user)

    query = select(SecurityEvent).where(
        SecurityEvent.workspace_id == workspace.id,
    )
    if severity:
        query = query.where(SecurityEvent.severity == severity.upper())

    events = list(
        db.execute(
            query.order_by(SecurityEvent.received_at.desc()).limit(limit)
        ).scalars().all()
    )

    res_list = []
    for e in events:
        summary_info = windows_event_explainer.get_friendly_event_summary(
            event_type=e.event_type,
            raw_payload=e.raw_payload,
            username=e.username,
            hostname=e.hostname,
            process_name=e.process_name,
            category=e.category.value if hasattr(e.category, "value") else str(e.category),
        )
        res_list.append({
            "id": str(e.id),
            "event_time": e.event_time.isoformat(),
            "received_at": e.received_at.isoformat(),
            "severity": e.severity.value,
            "category": e.category.value,
            "event_type": e.event_type,
            "title": summary_info["title"],
            "event_id": summary_info["event_id"],
            "badge_label": summary_info["badge_label"],
            "plain_english": summary_info["plain_english"],
            "category_label": summary_info["category_label"],
            "process_display": summary_info["process_display"],
            "action": e.action,
            "outcome": e.outcome,
            "username": e.username,
            "hostname": e.hostname,
            "source_ip": e.source_ip,
            "process_name": summary_info["process_display"] or e.process_name,
        })
    return res_list
