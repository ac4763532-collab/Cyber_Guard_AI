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
from fastapi.responses import RedirectResponse
from sqlalchemy.orm.attributes import flag_modified
from app.models.enums import AlertStatus, EventCategory, EventSeverity, SourceStatus, SourceType
from app.models.source import SecuritySource
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.base import AgentContext
from app.agents.email_analysis.agent import EmailAnalysisAgent
from app.api.deps import CurrentActiveUser, CurrentUser, DBDep
from app.core.config import settings
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.enums import AlertStatus, EventCategory, EventSeverity
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding
from app.models.user import User
from app.models.workspace import Workspace
from app.services import workspace_service
from app.services.ml_service import ml_engine

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
    recipient: Optional[str] = None
    subject: str
    snippet: Optional[str] = None
    received_at: str
    verdict: str  # phishing | suspicious | clean
    score: int  # 0 to 100
    status: str  # flagged | verified | analyzing
    source: str = "eml_upload"
    has_attachments: bool = False


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

    # Execute Machine Learning Phishing Classifier (TF-IDF + MultinomialNB)
    ml_eval = ml_engine.predict_email_phishing(
        subject=subject_header,
        body_text=parsed.get("body_text", "") or "",
        sender=from_addr,
        urls=parsed.get("urls", []) or [],
    )

    score = ml_eval.get("risk_score", 0)
    ml_verdict = ml_eval.get("verdict", "benign")

    if agent_result.findings or ml_verdict == "phishing" or score >= 60:
        for f in agent_result.findings:
            f.workspace_id = workspace.id
            f.primary_event_id = event.id
            db.add(f)

        max_sev = max((f.severity for f in agent_result.findings), default=EventSeverity.LOW)
        if score >= 75 or max_sev in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
            verdict = "phishing"
            score = max(score, 88)
            status_label = "flagged"
            event.severity = EventSeverity.HIGH if max_sev != EventSeverity.CRITICAL else max_sev

            # Create Alert
            alert = SecurityAlert(
                workspace_id=workspace.id,
                title=f"Phishing Email Detected: {subject_header[:60]}",
                description=f"Automated email defense flagged email from {from_addr}. ML confidence: {ml_eval.get('confidence', 0):.1%}. Triggered rules: {', '.join(f.rule_id for f in agent_result.findings) or 'ML-NLP-Classifier'}",
                severity=event.severity,
                status=AlertStatus.NEW,
                alert_type="security",
                category=EventCategory.EMAIL,
                fingerprint=hashlib.sha256(f"alert-{event.id}".encode("utf-8")).hexdigest(),
            )
            db.add(alert)
        else:
            verdict = "suspicious"
            score = max(score, 55)
            status_label = "analyzing"
            event.severity = EventSeverity.MEDIUM
    else:
        verdict = "clean"
        score = min(score, 12)
        status_label = "verified"

    # Store ML prediction into normalized payload for persistence
    norm_dict = dict(event.normalized_payload or {})
    norm_dict["ml_evaluation"] = ml_eval
    event.normalized_payload = norm_dict

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
        "ml_evaluation": ml_eval,
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

        norm = ev.normalized_payload or {}
        raw = ev.raw_payload or {}
        subject = norm.get("subject", "(No Subject)")
        sender = ev.email_address or ev.username or "unknown"
        headers_dict = raw.get("headers", {}) or norm.get("headers", {})
        recipient = headers_dict.get("To") or ev.username
        body_text = raw.get("body", "") or ""
        snippet = (body_text[:140] + "...") if len(body_text) > 140 else (body_text or None)
        has_att = bool(raw.get("attachments") or norm.get("attachments_count", 0) > 0)
        src = "gmail" if ev.action == "gmail_sync" else "eml_upload"

        items.append(
            EmailListItem(
                id=str(ev.id),
                sender=sender,
                recipient=recipient,
                subject=subject,
                snippet=snippet,
                received_at=ev.received_at.isoformat(),
                verdict=verdict,
                score=score,
                status=status_str,
                source=src,
                has_attachments=has_att,
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
    current_user: CurrentUser,
) -> GmailStatusResponse:
    google_configured = settings.is_google_oauth_configured
    workspace = _get_user_workspace(db, current_user)
    source = db.execute(
        select(SecuritySource).where(
            SecuritySource.workspace_id == workspace.id,
            SecuritySource.source_type == SourceType.EMAIL,
        )
    ).scalar_one_or_none()

    cfg = (source.config or {}) if source else {}
    has_valid_token = bool(cfg.get("access_token") and not str(cfg.get("access_token")).startswith("mock_")) or bool(cfg.get("refresh_token"))
    is_connected = bool(source and source.collector_connected and has_valid_token)
    email_addr = cfg.get("email_address") if source else None
    last_sync = source.last_event_at.isoformat() if source and source.last_event_at else None

    return GmailStatusResponse(
        configured=google_configured,
        connected=is_connected,
        email_address=email_addr,
        sync_status="connected" if is_connected else "disconnected",
        last_sync_at=last_sync,
        message=(
            f"Gmail connected for {email_addr}."
            if is_connected
            else (
                "Gmail OAuth configured. Ready to connect account."
                if google_configured
                else "Gmail integration not configured. Provide GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env."
            )
        ),
    )


@router.get("/gmail/auth-url", summary="Get Gmail OAuth authorization URL")
def get_gmail_auth_url(
    current_user: CurrentUser,
) -> dict[str, str]:
    if not settings.is_google_oauth_configured:
        raise HTTPException(
            status_code=400,
            detail="Gmail OAuth is unavailable because GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are not configured in backend settings.",
        )
    redirect_uri = settings.effective_google_redirect_uri
    scope = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email"
    state = str(current_user.id)
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&access_type=offline"
        f"&prompt=consent"
        f"&state={state}"
    )
    return {"auth_url": auth_url}


async def _handle_gmail_oauth_callback(
    code: Optional[str],
    state: Optional[str],
    error: Optional[str],
    db: Session,
) -> RedirectResponse:
    frontend_url = settings.FRONTEND_PUBLIC_URL.rstrip("/")
    if error:
        logger.warning("Google OAuth callback error", extra={"error": error})
        return RedirectResponse(f"{frontend_url}/personal/email?error={error}")

    if not code:
        return RedirectResponse(f"{frontend_url}/personal/email?error=Missing+authorization+code")

    try:
        import httpx
        redirect_uri = settings.effective_google_redirect_uri
        token_data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.google_client_secret_str,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post("https://oauth2.googleapis.com/token", data=token_data)

        if res.status_code != 200:
            logger.error("Failed to exchange Google OAuth code", extra={"response": res.text[:200]})
            return RedirectResponse(f"{frontend_url}/personal/email?error=Token+exchange+failed")

        tokens = res.json()
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        # Fetch user email profile
        email_address = "connected@gmail.com"
        async with httpx.AsyncClient(timeout=15.0) as client:
            prof_res = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if prof_res.status_code == 200:
                email_address = prof_res.json().get("emailAddress", "connected@gmail.com")

        # Resolve user & workspace
        user = None
        if state:
            try:
                user_id = uuid.UUID(state)
                user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
            except ValueError:
                pass

        if not user:
            user = db.execute(select(User).order_by(User.created_at.asc())).scalars().first()

        if not user:
            return RedirectResponse(f"{frontend_url}/personal/email?error=User+context+not+found")

        workspace = _get_user_workspace(db, user)

        # Upsert SecuritySource
        source = db.execute(
            select(SecuritySource).where(
                SecuritySource.workspace_id == workspace.id,
                SecuritySource.source_type == SourceType.EMAIL,
            )
        ).scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if not source:
            import secrets
            source_key = f"src-{secrets.token_hex(4)}"
            source = SecuritySource(
                workspace_id=workspace.id,
                source_key=source_key,
                name=f"Gmail ({email_address})",
                source_type=SourceType.EMAIL,
                collector_connected=True,
                collection_active=True,
                status=SourceStatus.ACTIVE,
                config={
                    "email_address": email_address,
                    "provider": "gmail",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "connected_at": now.isoformat(),
                },
            )
            db.add(source)
        else:
            cfg = dict(source.config or {})
            cfg.update({
                "email_address": email_address,
                "provider": "gmail",
                "access_token": access_token,
                "refresh_token": refresh_token or cfg.get("refresh_token"),
                "connected_at": now.isoformat(),
            })
            source.config = cfg
            source.collector_connected = True
            source.collection_active = True
            source.name = f"Gmail ({email_address})"
            source.status = SourceStatus.ACTIVE
            flag_modified(source, "config")

        db.commit()

        # Trigger initial sync of messages if access_token available
        try:
            await _sync_messages_from_gmail(db, workspace, user, source, access_token, max_messages=5)
        except Exception as sync_exc:
            logger.warning("Initial Gmail sync warning", extra={"error": str(sync_exc)[:200]})

        return RedirectResponse(f"{frontend_url}/personal/email?connected=true&email={email_address}")

    except Exception as exc:
        import urllib.parse
        logger.exception("Gmail OAuth callback failed")
        err_param = urllib.parse.quote(str(exc)[:100])
        return RedirectResponse(f"{frontend_url}/personal/email?error={err_param}")


@router.get("/gmail/oauth/callback", summary="Gmail OAuth callback under /email prefix")
async def email_gmail_oauth_callback(
    db: DBDep,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
) -> RedirectResponse:
    return await _handle_gmail_oauth_callback(code, state, error, db)


# Secondary router to catch direct /api/v1/gmail/oauth/callback
gmail_callback_router = APIRouter(prefix="/gmail", tags=["email"])

@gmail_callback_router.get("/oauth/callback", summary="Direct Gmail OAuth callback")
async def direct_gmail_callback(
    db: DBDep,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
) -> RedirectResponse:
    return await _handle_gmail_oauth_callback(code, state, error, db)


async def _refresh_google_access_token(refresh_token: str) -> Optional[str]:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.google_client_secret_str,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            if res.status_code == 200:
                return res.json().get("access_token")
    except Exception as e:
        logger.warning("Failed to refresh Google access token", extra={"error": str(e)})
    return None


async def _sync_messages_from_gmail(
    db: Session,
    workspace: Workspace,
    user: User,
    source: SecuritySource,
    access_token: str,
    max_messages: int = 10,
) -> int:
    import base64
    import httpx

    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=25.0) as client:
        list_res = await client.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={max_messages}",
            headers=headers,
        )
        if list_res.status_code != 200:
            logger.warning("Failed to list Gmail messages", extra={"status": list_res.status_code})
            return 0

        msg_list = list_res.json().get("messages", [])
        synced_count = 0

        for item in msg_list:
            msg_id = item.get("id")
            if not msg_id:
                continue

            fp = hashlib.sha256(f"gmail-{msg_id}".encode("utf-8")).hexdigest()
            existing = db.execute(
                select(SecurityEvent.id).where(
                    SecurityEvent.workspace_id == workspace.id,
                    SecurityEvent.fingerprint == fp,
                )
            ).scalar_one_or_none()
            if existing:
                continue

            raw_res = await client.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw",
                headers=headers,
            )
            if raw_res.status_code != 200:
                continue

            raw_b64 = raw_res.json().get("raw", "")
            if not raw_b64:
                continue

            try:
                raw_b64_padded = raw_b64 + "=" * (-len(raw_b64) % 4)
                raw_bytes = base64.urlsafe_b64decode(raw_b64_padded.encode("ascii"))
                parsed = _parse_eml_bytes(raw_bytes)
            except Exception:
                continue

            headers_dict = parsed["headers"]
            from_header = headers_dict.get("From", "unknown@unknown.com")
            subject_header = headers_dict.get("Subject", "(No Subject)")
            email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
            from_addr = email_match.group(0) if email_match else from_header
            from_domain = from_addr.split("@")[-1] if "@" in from_addr else "unknown"

            event = SecurityEvent(
                workspace_id=workspace.id,
                source_id=source.id,
                event_time=datetime.now(timezone.utc),
                severity=EventSeverity.INFO,
                category=EventCategory.EMAIL,
                event_type="email_received",
                action="gmail_sync",
                outcome="success",
                fingerprint=fp,
                username=user.email,
                email_address=from_addr,
                domain=from_domain,
                raw_payload=parsed,
                normalized_payload={
                    "headers": headers_dict,
                    "urls": parsed["urls"],
                    "attachments_count": len(parsed["attachments"]),
                    "sender": from_addr,
                    "subject": subject_header,
                },
            )
            db.add(event)
            db.flush()

            # Run 6 email detection rules + ML Phishing Classifier
            agent = EmailAnalysisAgent(config={})
            ctx = AgentContext(db=db, event=event, source=source, workspace_id=workspace.id)
            agent_result = agent.process(ctx)

            # ML evaluation
            ml_eval = ml_engine.predict_email_phishing(
                subject=subject_header,
                body_text=parsed.get("body_text", "") or "",
                sender=from_addr,
                urls=parsed.get("urls", []) or [],
            )
            norm_dict = dict(event.normalized_payload or {})
            norm_dict["ml_evaluation"] = ml_eval
            event.normalized_payload = norm_dict

            if agent_result.findings or ml_eval.get("verdict") == "phishing" or ml_eval.get("risk_score", 0) >= 60:
                for f in agent_result.findings:
                    f.workspace_id = workspace.id
                    f.primary_event_id = event.id
                    db.add(f)

                max_sev = max((f.severity for f in agent_result.findings), default=EventSeverity.LOW)
                ml_score = ml_eval.get("risk_score", 0)
                if ml_score >= 75 or max_sev in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
                    event.severity = EventSeverity.HIGH if max_sev != EventSeverity.CRITICAL else max_sev
                    alert = SecurityAlert(
                        workspace_id=workspace.id,
                        title=f"Phishing Email Detected: {subject_header[:60]}",
                        description=f"Gmail analysis flagged email from {from_addr}. ML confidence: {ml_eval.get('confidence', 0):.1%}. Triggered rules: {', '.join(f.rule_id for f in agent_result.findings) or 'ML-NLP-Classifier'}",
                        severity=event.severity,
                        status=AlertStatus.NEW,
                        alert_type="security",
                        category=EventCategory.EMAIL,
                        fingerprint=hashlib.sha256(f"alert-{event.id}".encode("utf-8")).hexdigest(),
                    )
                    db.add(alert)
                else:
                    event.severity = EventSeverity.MEDIUM

            synced_count += 1

        source.last_event_at = datetime.now(timezone.utc)
        source.events_ingested_count = (source.events_ingested_count or 0) + synced_count
        db.commit()
        return synced_count


@router.post("/gmail/sync", summary="Synchronize Gmail inbox")
async def sync_gmail(
    db: DBDep,
    current_user: CurrentUser,
) -> dict[str, Any]:
    workspace = _get_user_workspace(db, current_user)
    source = db.execute(
        select(SecuritySource).where(
            SecuritySource.workspace_id == workspace.id,
            SecuritySource.source_type == SourceType.EMAIL,
        )
    ).scalar_one_or_none()

    if not source or not source.collector_connected:
        raise HTTPException(
            status_code=400,
            detail="Gmail account is not connected. Please connect your Gmail account via OAuth first.",
        )

    cfg = dict(source.config or {})
    access_token = cfg.get("access_token")
    refresh_token = cfg.get("refresh_token")

    if (not access_token or str(access_token).startswith("mock_")) and refresh_token:
        fresh = await _refresh_google_access_token(refresh_token)
        if fresh:
            access_token = fresh
            cfg["access_token"] = fresh
            source.config = cfg
            flag_modified(source, "config")
            db.commit()

    if not access_token or str(access_token).startswith("mock_"):
        source.collector_connected = False
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Gmail authorization is required. Please click 'Connect with Google' to link your mailbox.",
        )

    synced_count = await _sync_messages_from_gmail(db, workspace, current_user, source, access_token)
    msg = f"Successfully synchronized {synced_count} new email(s) from Gmail." if synced_count > 0 else "Gmail inbox checked. No new unanalyzed emails found."
    return {
        "status": "success",
        "synced": synced_count,
        "message": msg,
    }
