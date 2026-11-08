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
from app.services import workspace_service

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

    anomalies = db.execute(
        select(func.count(SecurityEvent.id))
        .where(
            SecurityEvent.workspace_id == workspace.id,
            SecurityEvent.severity.in_([EventSeverity.HIGH, EventSeverity.CRITICAL]),
        )
    ).scalar() or 0

    recent_events = list(
        db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.workspace_id == workspace.id,
                SecurityEvent.category.in_([
                    EventCategory.AUTHENTICATION,
                    EventCategory.PROCESS,
                    EventCategory.FILE,
                    EventCategory.SYSTEM,
                    EventCategory.AUTHORIZATION,
                    EventCategory.OTHER,
                ]),
            )
            .order_by(SecurityEvent.received_at.desc())
            .limit(50)
        ).scalars().all()
    )

    ev_list = []
    for ev in recent_events:
        details_str = f"{ev.event_type} on {ev.hostname or 'host'}"
        if ev.username:
            details_str += f" by {ev.username}"
        if ev.source_ip:
            details_str += f" from {ev.source_ip}"

        ev_list.append({
            "id": str(ev.id),
            "timestamp": ev.received_at.isoformat(),
            "source": f"{ev.category.value.title()} ({ev.hostname or 'unknown'})",
            "event_type": ev.event_type,
            "severity": ev.severity.value,
            "details": details_str,
        })

    msg = None
    if sources_count == 0 and len(ev_list) == 0:
        msg = "No log source is currently reporting events."

    return LogSummaryResponse(
        total_sources=sources_count,
        failed_logins_24h=failed_logins,
        privilege_escalations_24h=priv_escalations,
        anomalous_events=anomalies,
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

    return [
        {
            "id": str(e.id),
            "event_time": e.event_time.isoformat(),
            "received_at": e.received_at.isoformat(),
            "severity": e.severity.value,
            "category": e.category.value,
            "event_type": e.event_type,
            "action": e.action,
            "outcome": e.outcome,
            "username": e.username,
            "hostname": e.hostname,
            "source_ip": e.source_ip,
            "process_name": e.process_name,
        }
        for e in events
    ]
