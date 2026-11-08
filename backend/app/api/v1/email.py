"""
CyberGuard AI — Email Security Endpoints
============================================================================
Handles authenticated email analysis, EML file uploads, RFC 822 parsing,
heuristic detection, IOC correlation, and Gmail synchronization.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.base import AgentContext
from app.agents.email_analysis.agent import EmailAnalysisAgent
from app.api.deps import CurrentActiveUser, DBDep
from app.core.config import settings
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.enums import AlertStatus, EventCategory, EventSeverity
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.user import User
from app.models.workspace import Workspace
from app.services import workspace_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/email",
    tags=["email"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    return workspace_service.create_personal_workspace(db, user)


class EmailListItem(BaseModel):
    id: str
    sender: str
    subject: str
    received_at: str
    verdict: str  # phishing | suspicious | clean
    score: int  # 0 to 100
    status: str  # flagged | verified | analyzing
    source: str = "eml_upload"


class EmailAnalysisDetail(BaseModel):
    id: str
    sender: str
    recipient: Optional[str] = None
    subject: str
    received_at: str
    verdict: str
    score: int
    confidence: float
    status: str
    auth_results: dict[str, Any]
    headers: dict[str, str]
    urls_found: List[str]
    attachments: List[dict[str, Any]]
    triggered_rules: List[dict[str, Any]]
    body_excerpt: str


class GmailStatusResponse(BaseModel):
    configured: bool
    connected: bool
    email_address: Optional[str] = None
    sync_status: str
    last_sync_at: Optional[str] = None
    message: str


def _parse_eml_bytes(file_bytes: bytes) -> dict[str, Any]:
    """Parse RFC 822 EML bytes into structured components."""
    msg = email.message_from_bytes(file_bytes, policy=email.policy.default)

    headers: dict[str, str] = {}
    for k in ["From", "To", "Subject", "Date", "Reply-To", "Return-Path", "Authentication-Results", "Message-ID"]:
        val = msg.get(k)
        if val is not None:
            headers[k] = str(val)

    body_text = ""
    body_html = ""
    attachments: list[dict[str, Any]] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in content_disposition or part.get_filename():
            fn = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": fn,
                "mime": content_type,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        elif content_type == "text/plain":
            payload = part.get_payload(decode=True) or b""
            body_text += payload.decode("utf-8", errors="replace")
        elif content_type == "text/html":
            payload = part.get_payload(decode=True) or b""
            body_html += payload.decode("utf-8", errors="replace")

    # Extract all URLs
    combined_body = body_text + " " + body_html
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    extracted_urls = list(set(url_pattern.findall(combined_body)))

    return {
        "headers": headers,
        "body_text": body_text,
        "body_html": body_html,
        "urls": extracted_urls,
        "attachments": attachments,
    }


@router.post("/uploads", status_code=status.HTTP_201_CREATED, summary="Upload and analyze an .eml file")
async def upload_eml(
    db: DBDep,
    current_user: CurrentActiveUser,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    if not file.filename or not (file.filename.endswith(".eml") or file.filename.endswith(".msg") or file.content_type in ["message/rfc822", "application/octet-stream"]):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Please upload a valid RFC 822 .eml file.",
        )

    content = await file.read()
    if len(content) > 25 * 1024 * 1024:  # 25 MB max
        raise HTTPException(status_code=400, detail="File size exceeds maximum limit of 25MB.")

    parsed = _parse_eml_bytes(content)
    workspace = _get_user_workspace(db, current_user)

    headers = parsed["headers"]
    from_header = headers.get("From", "unknown@unknown.com")
    subject_header = headers.get("Subject", "(No Subject)")

    # Extract domain and email
    email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
    from_addr = email_match.group(0) if email_match else from_header
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else "unknown"

    # Fingerprint
    fp_raw = f"{from_addr}|{subject_header}|{file.filename}|{len(content)}|{datetime.now(timezone.utc).isoformat()}"
    fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

    event = SecurityEvent(
        workspace_id=workspace.id,
        event_time=datetime.now(timezone.utc),
        severity=EventSeverity.INFO,
        category=EventCategory.EMAIL,
        event_type="email_received",
        action="ingest",
        outcome="success",
        fingerprint=fingerprint,
        username=current_user.email,
        email_address=from_addr,
        domain=from_domain,
        raw_payload=parsed,
        normalized_payload={
            "headers": headers,
            "urls": parsed["urls"],
            "attachments_count": len(parsed["attachments"]),
            "sender": from_addr,
            "subject": subject_header,
        },
    )
    db.add(event)
    db.flush()

    # Execute EmailAnalysisAgent with all 6 detection rules
    agent = EmailAnalysisAgent(config={})
    ctx = AgentContext(db=db, event=event, source=None, workspace_id=workspace.id)
    agent_result = agent.process(ctx)

    # Persist findings
    score = 0
    verdict = "clean"
    status_label = "verified"

    if agent_result.findings:
        for f in agent_result.findings:
            f.workspace_id = workspace.id
            f.primary_event_id = event.id
            db.add(f)

        max_sev = max((f.severity for f in agent_result.findings), default=EventSeverity.LOW)
        if max_sev in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
            verdict = "phishing"
            score = 92
            status_label = "flagged"
            event.severity = max_sev

            # Create Alert
            alert = SecurityAlert(
                workspace_id=workspace.id,
                title=f"Phishing Email Detected: {subject_header[:60]}",
                description=f"Automated email defense flagged email from {from_addr}. Triggered rules: {', '.join(f.rule_id for f in agent_result.findings)}",
                severity=max_sev,
                status=AlertStatus.NEW,
                alert_type="security",
                category=EventCategory.EMAIL,
                fingerprint=hashlib.sha256(f"alert-{event.id}".encode("utf-8")).hexdigest(),
            )
            db.add(alert)
        else:
            verdict = "suspicious"
            score = 65
            status_label = "analyzing"
            event.severity = EventSeverity.MEDIUM

    db.commit()

    return {
        "analysis_id": str(event.id),
        "filename": file.filename,
        "sender": from_addr,
        "subject": subject_header,
        "verdict": verdict,
        "score": score,
        "status": status_label,
        "findings_count": len(agent_result.findings),
    }


@router.get("/messages", response_model=List[EmailListItem], summary="List all analyzed emails")
def list_email_messages(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> List[EmailListItem]:
    workspace = _get_user_workspace(db, current_user)

    events = list(
        db.execute(
            select(SecurityEvent)
            .where(
                SecurityEvent.workspace_id == workspace.id,
                SecurityEvent.category == EventCategory.EMAIL,
            )
            .order_by(SecurityEvent.received_at.desc())
            .limit(50)
        ).scalars().all()
    )

    items: List[EmailListItem] = []
    for ev in events:
        findings_count = db.execute(
            select(func.count(AgentFinding.id)).where(AgentFinding.primary_event_id == ev.id)
        ).scalar() or 0

        verdict = "clean"
        score = 5
        status_str = "verified"

        if ev.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
            verdict = "phishing"
            score = 94
            status_str = "flagged"
        elif ev.severity == EventSeverity.MEDIUM or findings_count > 0:
            verdict = "suspicious"
            score = 68
            status_str = "analyzing"

        subject = ev.normalized_payload.get("subject", "(No Subject)") if ev.normalized_payload else "(No Subject)"
        sender = ev.email_address or ev.username or "unknown"

        items.append(
            EmailListItem(
                id=str(ev.id),
                sender=sender,
                subject=subject,
                received_at=ev.received_at.isoformat(),
                verdict=verdict,
                score=score,
                status=status_str,
                source="eml_upload",
            )
        )

    return items


@router.get("/analyses/{event_id}", response_model=EmailAnalysisDetail, summary="Get email forensic analysis details")
def get_email_analysis(
    event_id: uuid.UUID,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> EmailAnalysisDetail:
    ev = db.execute(
        select(SecurityEvent).where(SecurityEvent.id == event_id)
    ).scalar_one_or_none()

    if not ev or ev.category != EventCategory.EMAIL:
        raise HTTPException(status_code=404, detail="Email analysis record not found")

    findings = list(
        db.execute(
            select(AgentFinding).where(AgentFinding.primary_event_id == ev.id)
        ).scalars().all()
    )

    raw = ev.raw_payload or {}
    headers = raw.get("headers", {})
    urls = raw.get("urls", [])
    attachments = raw.get("attachments", [])
    body_text = raw.get("body_text", "")

    verdict = "clean"
    score = 4
    if ev.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
        verdict = "phishing"
        score = 94
    elif findings:
        verdict = "suspicious"
        score = 68

    triggered = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "confidence": f.confidence,
        }
        for f in findings
    ]

    return EmailAnalysisDetail(
        id=str(ev.id),
        sender=ev.email_address or headers.get("From", "unknown"),
        recipient=headers.get("To"),
        subject=headers.get("Subject", "(No Subject)"),
        received_at=ev.received_at.isoformat(),
        verdict=verdict,
        score=score,
        confidence=0.95 if findings else 0.20,
        status="flagged" if verdict == "phishing" else ("analyzing" if verdict == "suspicious" else "verified"),
        auth_results={"raw": headers.get("Authentication-Results", "None")},
        headers=headers,
        urls_found=urls,
        attachments=attachments,
        triggered_rules=triggered,
        body_excerpt=body_text[:500] if body_text else "(No text body found)",
    )


@router.get("/gmail/status", response_model=GmailStatusResponse, summary="Check Gmail OAuth integration status")
def get_gmail_status(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> GmailStatusResponse:
    google_configured = bool(getattr(settings, "GOOGLE_CLIENT_ID", None) and getattr(settings, "GOOGLE_CLIENT_SECRET", None))
    return GmailStatusResponse(
        configured=google_configured,
        connected=False,
        email_address=None,
        sync_status="disconnected",
        last_sync_at=None,
        message="Gmail integration not configured. Provide GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env to enable Gmail synchronization." if not google_configured else "Gmail OAuth configured. Ready to connect account.",
    )


@router.get("/gmail/auth-url", summary="Get Gmail OAuth authorization URL")
def get_gmail_auth_url(
    current_user: CurrentActiveUser,
) -> dict[str, str]:
    google_client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
    if not google_client_id:
        raise HTTPException(
            status_code=400,
            detail="Gmail OAuth is unavailable because GOOGLE_CLIENT_ID is not configured in backend settings.",
        )
    redirect_uri = "http://localhost:5173/personal/email"
    scope = "https://www.googleapis.com/auth/gmail.readonly"
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={google_client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&access_type=offline&prompt=consent"
    return {"auth_url": auth_url}


@router.post("/gmail/sync", summary="Synchronize Gmail inbox")
def sync_gmail(
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    raise HTTPException(
        status_code=400,
        detail="Gmail account is not connected. Please connect your Gmail account via OAuth first.",
    )
