"""
CyberGuard AI - Gmail API Endpoints

API endpoints for Gmail integration:
- OAuth flow (connect/disconnect Gmail)
- List messages
- Get message details
- Analyze Gmail email

Security:
- All endpoints require authentication
- OAuth tokens encrypted and stored in PostgreSQL
- Read-only Gmail access
- Rate limiting: 60 requests/minute
"""

import re
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.agents import get_dispatcher
from app.auth.jwt import get_current_active_user
from app.auth.models import User
from app.config import get_settings
from app.database.repositories.gmail_sync_state import get_gmail_sync_state_repository
from app.middleware.rate_limit import RATE_LIMIT_GMAIL, limiter
from app.schemas.analysis import AnalysisResponse, FindingResponse
from app.services.email_ingestion import publish_email_event
from app.services.email_report_builder import get_report_builder
from app.services.gmail import (
    GmailClient,
    GmailParser,
    get_gmail_oauth_service,
)
from app.services.gmail.oauth import GmailTokens
from app.services.threat_intel import IOCType, get_threat_intel_service
from app.services.url_analysis.service import analyze_urls as _analyze_url_service

router = APIRouter(prefix="/gmail", tags=["Gmail"])
logger = structlog.get_logger(__name__)


# =============================================================================
# Token Storage Helpers
# =============================================================================

def _get_settings():
    return get_settings()


async def _store_tokens(user_id: str, tokens: GmailTokens, gmail_email: str | None = None) -> None:
    """Store OAuth tokens - uses database when DB_ENABLED, otherwise in-memory."""
    settings = _get_settings()

    if settings.db_enabled and settings.token_encryption_key:
        from app.auth import get_user_manager
        from app.database.repositories.oauth_tokens import get_oauth_token_repository

        # Get user's database ID
        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async(user_id)
        if not user:
            logger.error("User not found for token storage", username=user_id)
            raise ValueError("User not found")

        repo = get_oauth_token_repository()
        await repo.store(
            user_id=user.id,
            provider="google",
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            expires_at=tokens.expires_at,
            scopes=tokens.scope,
            provider_account_id=gmail_email,
        )
    else:
        # Fallback to in-memory for development (when no encryption key)
        _user_tokens[user_id] = tokens


async def _get_tokens(user_id: str) -> GmailTokens | None:
    """Get OAuth tokens - uses database when DB_ENABLED, otherwise in-memory."""
    settings = _get_settings()

    if settings.db_enabled and settings.token_encryption_key:
        from app.auth import get_user_manager
        from app.database.repositories.oauth_tokens import get_oauth_token_repository

        # Get user's database ID
        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async(user_id)
        if not user:
            return None

        repo = get_oauth_token_repository()
        result = await repo.get_decrypted_tokens(user.id, "google")

        if not result:
            return None

        access_token, refresh_token, expires_at = result

        return GmailTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer",
            expires_at=expires_at or datetime.now(timezone.utc),
            scope="",
        )
    else:
        # Fallback to in-memory
        return _user_tokens.get(user_id)


async def _delete_tokens(user_id: str) -> None:
    """Delete OAuth tokens."""
    settings = _get_settings()

    if settings.db_enabled and settings.token_encryption_key:
        from app.auth import get_user_manager
        from app.database.repositories.oauth_tokens import get_oauth_token_repository

        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async(user_id)
        if user:
            repo = get_oauth_token_repository()
            await repo.delete(user.id, "google")
    else:
        _user_tokens.pop(user_id, None)


async def _refresh_and_store_tokens(user_id: str, tokens: GmailTokens) -> GmailTokens | None:
    """Refresh tokens if expired and store the new ones."""
    if not tokens.is_expired():
        return tokens

    if not tokens.refresh_token:
        logger.warning("Cannot refresh - no refresh token", user=user_id)
        return None

    try:
        oauth_service = get_gmail_oauth_service()
        new_tokens = await oauth_service.refresh_tokens(tokens.refresh_token)

        # Store refreshed tokens
        await _store_tokens(user_id, new_tokens)

        logger.info("Gmail tokens refreshed and stored", user=user_id)
        return new_tokens
    except Exception as e:
        logger.error("Token refresh failed", user=user_id, error=str(e))
        return None


# In-memory token storage fallback (for development without encryption key)
_user_tokens: dict[str, GmailTokens] = {}


# =============================================================================
# Request/Response Models
# =============================================================================

class GmailConnectResponse(BaseModel):
    """Response for Gmail connect request."""
    auth_url: str
    state: str
    message: str = "Redirect user to auth_url to authorize Gmail access"


class GmailStatusResponse(BaseModel):
    """Gmail connection status."""
    connected: bool
    email: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    # Automatic polling health (app/services/gmail/poller.py), surfaced so
    # the frontend can show an honest "monitoring"/"poll failing" state
    # instead of assuming automatic analysis is working just because
    # OAuth is connected. auto_poll_enabled reflects the actual server
    # setting (gmail_poll_enabled) - never fabricated as "on" when the
    # poller isn't configured to run.
    auto_poll_enabled: bool = False
    last_polled_at: Optional[datetime] = None
    last_poll_error: Optional[str] = None
    last_poll_error_at: Optional[datetime] = None


class GmailMessageListResponse(BaseModel):
    """Response for listing Gmail messages."""
    messages: list[dict[str, Any]] = Field(default_factory=list)
    next_page_token: Optional[str] = None
    total_estimate: int = 0


class GmailMessageResponse(BaseModel):
    """Response for getting a Gmail message."""
    id: str
    thread_id: str
    subject: str
    sender: str
    recipients: list[str] = Field(default_factory=list)
    date: Optional[datetime] = None
    snippet: str = ""
    body_preview: str = ""
    has_attachments: bool = False
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    urls_found: int = 0


class GmailAnalyzeRequest(BaseModel):
    """Request to analyze a Gmail message."""
    include_raw: bool = Field(
        default=True,
        description="Include raw MIME for deep analysis"
    )


class GmailAnalyzeResponse(BaseModel):
    """Response from Gmail email analysis."""
    message_id: str
    analysis: AnalysisResponse
    parsed_email: dict[str, Any]
    authentication: dict[str, Any]
    threat_intel: dict[str, Any] = Field(default_factory=dict, description="Threat intelligence enrichment for IOCs")


# =============================================================================
# OAuth Endpoints
# =============================================================================

@router.get(
    "/oauth/connect",
    response_model=GmailConnectResponse,
    summary="Connect Gmail Account",
    description="""
    Initiate Gmail OAuth flow.

    Returns an authorization URL that the user must visit to grant access.
    Only requests READ-ONLY Gmail permissions for security analysis.

    After authorization, user is redirected to /gmail/oauth/callback.
    """
)
async def gmail_connect(
    current_user: User = Depends(get_current_active_user),
    redirect_after: Optional[str] = Query(None, description="URL to redirect to after OAuth")
):
    """Generate Gmail OAuth authorization URL."""
    oauth_service = get_gmail_oauth_service()

    if not oauth_service.is_configured:
        raise HTTPException(
            status_code=503,
            detail="Gmail integration not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
        )

    try:
        # Use async version for Redis-backed state storage
        auth_url, state = await oauth_service.generate_auth_url_async(
            user_id=current_user.username,
            redirect_after=redirect_after
        )

        logger.info(
            "Gmail OAuth initiated",
            user=current_user.username
        )

        return GmailConnectResponse(
            auth_url=auth_url,
            state=state
        )

    except RuntimeError as e:
        # Redis unavailable - return service error
        logger.error("Gmail OAuth state storage unavailable", error=str(e))
        raise HTTPException(
            status_code=503,
            detail="OAuth service temporarily unavailable. Please try again."
        )
    except Exception as e:
        logger.error("Gmail connect failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/oauth/callback",
    summary="OAuth Callback",
    description="Handles OAuth callback from Google. Do not call directly."
)
async def gmail_oauth_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """Handle OAuth callback from Google."""
    oauth_service = get_gmail_oauth_service()

    # Frontend URL for redirects
    frontend_url = "http://localhost:5173"

    # Handle error from Google
    if error:
        logger.warning(
            "Gmail OAuth error",
            error=error,
            description=error_description
        )
        # Redirect to frontend with error
        return RedirectResponse(
            url=f"{frontend_url}/analysis/email?gmail_error={error}"
        )

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    # Validate state using Redis-backed async method
    oauth_state = await oauth_service.validate_state_async(state)
    if not oauth_state:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    try:
        # Exchange code for tokens
        tokens = await oauth_service.exchange_code(code)

        # Get user email for storage
        user_info = await oauth_service.get_user_info(tokens.access_token)

        # Store tokens (encrypted in DB or in-memory fallback)
        await _store_tokens(oauth_state.user_id, tokens, user_info.email)

        logger.info(
            "Gmail connected successfully",
            user=oauth_state.user_id,
        )

        # Redirect to frontend
        redirect_url = oauth_state.redirect_after or "/analysis/email"
        # Ensure redirect goes to frontend, not backend
        if not redirect_url.startswith("http"):
            redirect_url = f"{frontend_url}{redirect_url}"
        return RedirectResponse(
            url=f"{redirect_url}?gmail_connected=true&email={user_info.email}"
        )

    except Exception as e:
        logger.error("Gmail OAuth callback failed", error=str(e))
        # Include error message in redirect for debugging
        error_msg = str(e).replace(" ", "_")[:100]
        return RedirectResponse(
            url=f"{frontend_url}/analysis/email?gmail_error={error_msg}"
        )


@router.get(
    "/status",
    response_model=GmailStatusResponse,
    summary="Gmail Connection Status",
    description="Check if Gmail is connected for current user."
)
async def gmail_status(
    current_user: User = Depends(get_current_active_user)
):
    """Get Gmail connection status."""
    tokens = await _get_tokens(current_user.username)

    if not tokens:
        return GmailStatusResponse(connected=False)

    # Check if tokens are still valid (and refresh if needed)
    try:
        tokens = await _refresh_and_store_tokens(current_user.username, tokens)
        if not tokens:
            return GmailStatusResponse(connected=False)

        oauth_service = get_gmail_oauth_service()
        user_info = await oauth_service.get_user_info(tokens.access_token)

        # Real poll health, not a fabricated "monitoring" status: reflects
        # the actual gmail_poll_enabled setting plus this account's last
        # recorded poll cycle (gmail_sync_state), so a disabled poller or
        # an account hitting repeated poll errors shows honestly rather
        # than implying automatic analysis is working just because OAuth
        # succeeded.
        settings = get_settings()
        last_polled_at = None
        last_poll_error = None
        last_poll_error_at = None
        try:
            sync_state = await get_gmail_sync_state_repository().get(current_user.id)
            if sync_state:
                last_polled_at = sync_state.last_polled_at
                last_poll_error = sync_state.last_error
                last_poll_error_at = sync_state.last_error_at
        except Exception as e:
            logger.warning("Failed to read Gmail sync state", error=str(e))

        return GmailStatusResponse(
            connected=True,
            email=user_info.email,
            scopes=tokens.scope.split(" ") if tokens.scope else [],
            expires_at=tokens.expires_at,
            auto_poll_enabled=settings.gmail_poll_enabled,
            last_polled_at=last_polled_at,
            last_poll_error=last_poll_error,
            last_poll_error_at=last_poll_error_at,
        )
    except Exception:
        # Token might be expired or revoked
        return GmailStatusResponse(connected=False)


@router.post(
    "/disconnect",
    summary="Disconnect Gmail",
    description="Revoke Gmail access and delete stored tokens."
)
async def gmail_disconnect(
    current_user: User = Depends(get_current_active_user)
):
    """Disconnect Gmail account."""
    tokens = await _get_tokens(current_user.username)

    if tokens:
        try:
            oauth_service = get_gmail_oauth_service()
            await oauth_service.revoke_access(tokens.access_token)
        except Exception as e:
            logger.warning("Token revocation failed", error=str(e))

    # Delete tokens from storage
    await _delete_tokens(current_user.username)

    logger.info("Gmail disconnected", user=current_user.username)

    return {"status": "disconnected", "message": "Gmail access revoked"}


# =============================================================================
# Message Endpoints
# =============================================================================

async def _get_gmail_client(user_id: str) -> GmailClient:
    """Get Gmail client for user, raising if not connected."""
    tokens = await _get_tokens(user_id)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="Gmail not connected. Please connect your Gmail account first."
        )

    # Refresh if needed
    tokens = await _refresh_and_store_tokens(user_id, tokens)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="Gmail session expired. Please reconnect your Gmail account."
        )

    return GmailClient(tokens)


@router.get(
    "/messages",
    response_model=GmailMessageListResponse,
    summary="List Gmail Messages",
    description="""
    List messages from connected Gmail account.

    Supports Gmail search queries:
    - `from:example@domain.com`
    - `subject:urgent`
    - `has:attachment`
    - `is:unread`
    - `after:2024/01/01`
    """
)
@limiter.limit(RATE_LIMIT_GMAIL)
async def list_gmail_messages(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_active_user),
    query: Optional[str] = Query(None, description="Gmail search query"),
    max_results: int = Query(20, ge=1, le=100, description="Max messages to return"),
    page_token: Optional[str] = Query(None, description="Pagination token"),
    label: Optional[str] = Query(None, description="Filter by label (INBOX, UNREAD, etc.)")
):
    """List Gmail messages with optional filtering."""
    try:
        client = await _get_gmail_client(current_user.username)

        label_ids = [label] if label else None

        result = await client.list_messages(
            query=query,
            max_results=max_results,
            page_token=page_token,
            label_ids=label_ids
        )

        return GmailMessageListResponse(
            messages=[msg.model_dump() for msg in result.messages],
            next_page_token=result.next_page_token,
            total_estimate=result.result_size_estimate
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("List messages failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to list messages: {str(e)}")


@router.get(
    "/messages/{message_id}",
    response_model=GmailMessageResponse,
    summary="Get Gmail Message",
    description="Get details of a specific Gmail message."
)
@limiter.limit(RATE_LIMIT_GMAIL)
async def get_gmail_message(
    request: Request,
    response: Response,
    message_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific Gmail message."""
    try:
        client = await _get_gmail_client(current_user.username)

        message = await client.get_message(message_id, include_raw=False)

        # Create preview of body
        body_preview = message.body_plain[:500] if message.body_plain else ""
        if len(message.body_plain) > 500:
            body_preview += "..."

        # Count URLs in body
        import re
        urls_found = len(re.findall(r'https?://[^\s<>"\']+', message.body_plain + message.body_html))

        return GmailMessageResponse(
            id=message.id,
            thread_id=message.thread_id,
            subject=message.subject,
            sender=message.sender,
            recipients=message.to,
            date=message.date,
            snippet=message.snippet,
            body_preview=body_preview,
            has_attachments=bool(message.attachments),
            attachments=message.attachments,
            urls_found=urls_found
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Get message failed", message_id=message_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get message: {str(e)}")


# =============================================================================
# Analysis Endpoints
# =============================================================================

@router.post(
    "/analyze/{message_id}",
    response_model=GmailAnalyzeResponse,
    summary="Analyze Gmail Message",
    description="""
    Analyze a Gmail message for phishing and security threats.

    This endpoint:
    1. Retrieves the Gmail message (with raw MIME if requested)
    2. Parses the email extracting headers, body, URLs, attachments
    3. Runs through the existing Email Security Agent
    4. Returns detailed analysis with findings, IOCs, and risk score
    """
)
@limiter.limit(RATE_LIMIT_GMAIL)
async def analyze_gmail_message(
    request: Request,
    response: Response,
    message_id: str,
    analyze_request: GmailAnalyzeRequest = GmailAnalyzeRequest(),
    current_user: User = Depends(get_current_active_user)
):
    """Analyze a Gmail message for security threats."""
    try:
        # Get Gmail client and message
        client = await _get_gmail_client(current_user.username)

        logger.info(
            "Gmail analysis requested",
            message_id=message_id,
            user=current_user.username
        )

        # Get full message with raw MIME for deep analysis
        message = await client.get_message(message_id, include_raw=analyze_request.include_raw)

        # Parse email
        parser = GmailParser()
        parsed = parser.parse(message)

        # Convert to format expected by existing Email Agent
        analysis_data = parser.to_analysis_request(parsed)

        # Run through existing analysis pipeline
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_email(analysis_data)

        # Also publish onto the event bus so this finding is persisted
        # and runs through the automatic alerting/correlation pipeline
        # (on_finding_created), not just returned in this HTTP response.
        # Best-effort: a publish failure must never affect the
        # synchronous response the user is waiting on.
        try:
            await publish_email_event(
                analysis_data,
                tenant_id=current_user.organization_id or "admin",
                source="gmail",
            )
        except Exception as e:
            logger.warning("Failed to publish email event to bus", error=str(e))

        # Phase 5: Enrich IOCs with threat intelligence
        threat_intel = get_threat_intel_service()
        threat_intel_results = {}

        if threat_intel.is_configured and result.indicators:
            # Classify and lookup IOCs
            ioc_lookups = []
            for ioc in result.indicators[:10]:  # Limit to 10 IOCs
                # Determine IOC type
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
                    ioc_lookups.append((IOCType.IP, ioc))
                elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
                    ioc_lookups.append((IOCType.HASH_MD5, ioc))
                elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
                    ioc_lookups.append((IOCType.HASH_SHA256, ioc))
                elif '://' in ioc:
                    ioc_lookups.append((IOCType.URL, ioc))
                elif '.' in ioc and not ioc.startswith('http'):
                    ioc_lookups.append((IOCType.DOMAIN, ioc))

            if ioc_lookups:
                try:
                    ti_results = await threat_intel.lookup_batch(ioc_lookups)
                    for ti_result in ti_results:
                        # Include ALL results so users see lookups were performed
                        threat_intel_results[ti_result.ioc_value] = {
                            "type": ti_result.ioc_type.value,
                            "is_malicious": ti_result.is_malicious,
                            "risk_score": ti_result.risk_score,
                            "sources": ti_result.sources,
                            "cached": ti_result.cached,
                            "lookup_time_ms": ti_result.lookup_time_ms,
                        }
                except Exception as e:
                    logger.warning("Threat intel lookup failed", error=str(e))

        # Build response
        analysis_response = AnalysisResponse(
            result_id=result.result_id,
            analysis_type=result.agent_type.value,
            agent_version=result.agent_version,
            started_at=result.started_at,
            completed_at=result.completed_at,
            processing_time_ms=result.processing_time_ms,
            classification=result.classification,
            severity=result.severity.value,
            confidence=result.confidence,
            risk_score=result.risk_score,
            findings=[
                FindingResponse(
                    finding_id=f.finding_id,
                    rule_id=f.rule_id,
                    name=f.name,
                    description=f.description,
                    severity=f.severity.value,
                    confidence=f.confidence,
                    evidence=f.evidence,
                    mitre_techniques=f.mitre_techniques,
                    recommendations=f.recommendations,
                )
                for f in result.findings
            ],
            indicators=result.indicators,
            summary=result.summary,
            recommendations=result.recommendations,
            success=result.success,
            error=result.error,
        )

        logger.info(
            "Gmail analysis complete",
            message_id=message_id,
            classification=result.classification,
            risk_score=result.risk_score,
            findings_count=len(result.findings)
        )

        return GmailAnalyzeResponse(
            message_id=message_id,
            analysis=analysis_response,
            parsed_email={
                "sender": parsed.sender,
                "sender_email": parsed.sender_email,
                "sender_name": parsed.sender_name,
                "subject": parsed.subject,
                "date": parsed.date.isoformat() if parsed.date else None,
                "reply_to": parsed.reply_to,
                "reply_to_email": parsed.reply_to_email,
                "return_path": parsed.return_path,
                "return_path_email": parsed.return_path_email,
                "message_id": parsed.message_id,
                "recipients": parsed.recipients,
                "urls_count": len(parsed.urls),
                "attachments_count": len(parsed.attachments),
                "urls": [url.model_dump() for url in parsed.urls],
                "urls_detailed": [url.model_dump() for url in parsed.urls],
                "attachments": [att.model_dump() for att in parsed.attachments],
                "received_chain": parsed.received_chain,
                "authentication": parsed.authentication.model_dump(),
            },
            authentication=parsed.authentication.model_dump(),
            threat_intel=threat_intel_results
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Gmail analysis failed", message_id=message_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post(
    "/investigate/{message_id}",
    summary="Full Email Investigation Report",
    description="""
    Comprehensive email security investigation with professional SOC-style report.

    Returns detailed sections:
    - Verdict with risk score and confidence
    - Executive summary
    - Sender intelligence
    - Authentication analysis (SPF/DKIM/DMARC)
    - URL intelligence
    - Content analysis
    - Attachment analysis
    - Header forensics
    - Threat intelligence
    - IOC inventory
    - Risk breakdown
    - Recommendations
    """
)
@limiter.limit(RATE_LIMIT_GMAIL)
async def investigate_gmail_message(
    request: Request,
    response: Response,
    message_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Full investigation report for a Gmail message."""
    try:
        # Get Gmail client and message
        client = await _get_gmail_client(current_user.username)

        logger.info(
            "Gmail investigation requested",
            message_id=message_id,
            user=current_user.username
        )

        # Get full message with raw MIME for deep analysis
        message = await client.get_message(message_id, include_raw=True)

        # Parse email
        parser = GmailParser()
        parsed = parser.parse(message)

        # Convert to format expected by existing Email Agent
        analysis_data = parser.to_analysis_request(parsed)

        # Run through existing analysis pipeline
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_email(analysis_data)

        # Also publish onto the event bus (see analyze_gmail_message's
        # identical comment above) - best-effort, never affects the
        # synchronous response.
        try:
            await publish_email_event(
                analysis_data,
                tenant_id=current_user.organization_id or "admin",
                source="gmail",
            )
        except Exception as e:
            logger.warning("Failed to publish email event to bus", error=str(e))

        # Enrich IOCs with threat intelligence
        threat_intel = get_threat_intel_service()
        threat_intel_results = {}

        if threat_intel.is_configured and result.indicators:
            ioc_lookups = []
            for ioc in result.indicators[:10]:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
                    ioc_lookups.append((IOCType.IP, ioc))
                elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
                    ioc_lookups.append((IOCType.HASH_MD5, ioc))
                elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
                    ioc_lookups.append((IOCType.HASH_SHA256, ioc))
                elif '://' in ioc:
                    ioc_lookups.append((IOCType.URL, ioc))
                elif '.' in ioc and not ioc.startswith('http'):
                    ioc_lookups.append((IOCType.DOMAIN, ioc))

            if ioc_lookups:
                try:
                    ti_results = await threat_intel.lookup_batch(ioc_lookups)
                    for ti_result in ti_results:
                        # Include ALL results so users see lookups were performed
                        threat_intel_results[ti_result.ioc_value] = {
                            "type": ti_result.ioc_type.value,
                            "is_malicious": ti_result.is_malicious,
                            "risk_score": ti_result.risk_score,
                            "sources": ti_result.sources,
                            "cached": ti_result.cached,
                            "lookup_time_ms": ti_result.lookup_time_ms,
                        }
                except Exception as e:
                    logger.warning("Threat intel lookup failed", error=str(e))

        # Per-URL comprehensive analysis: patterns + Safe Browsing + reputation
        url_service_results: dict[str, dict] = {}
        if parsed.urls:
            try:
                url_strings = [u.url for u in parsed.urls if getattr(u, "url", None)]
                if url_strings:
                    svc_results = await _analyze_url_service(url_strings)
                    for svc_r in svc_results:
                        original = svc_r.get("url", "")
                        if original:
                            url_service_results[original] = svc_r
                    logger.info(
                        "URL analysis service complete",
                        urls_checked=len(url_strings),
                        results=len(url_service_results),
                    )
            except Exception as e:
                logger.warning("URL analysis service failed", error=str(e))

        def _enrich_url(url_dict: dict) -> dict:
            svc = url_service_results.get(url_dict.get("url", ""), {})
            if svc:
                url_dict["url_service_status"] = svc.get("status", "unknown")
                url_dict["url_service_is_malicious"] = bool(svc.get("is_malicious", False))
                url_dict["url_service_risk_score"] = int(svc.get("risk_score", 0) or 0)
                url_dict["url_service_patterns"] = svc.get("patterns", {})
            return url_dict

        # Build enhanced investigation report
        report_builder = get_report_builder()

        parsed_email_data = {
            "sender": parsed.sender,
            "sender_email": parsed.sender_email,
            "sender_name": parsed.sender_name,
            "subject": parsed.subject,
            "date": parsed.date.isoformat() if parsed.date else None,
            "reply_to": parsed.reply_to,
            "reply_to_email": parsed.reply_to_email,
            "return_path": parsed.return_path,
            "return_path_email": parsed.return_path_email,
            "message_id": parsed.message_id,
            "recipients": parsed.recipients,
            "urls_detailed": [_enrich_url(url.model_dump()) for url in parsed.urls],
            "attachments": [att.model_dump() for att in parsed.attachments],
            "received_chain": parsed.received_chain,
            "authentication": parsed.authentication.model_dump(),
        }

        report = report_builder.build_report(
            agent_result=result,
            parsed_email=parsed_email_data,
            authentication=parsed.authentication.model_dump(),
            threat_intel=threat_intel_results,
            email_source="gmail",
            gmail_message_id=message_id,
        )

        logger.info(
            "Gmail investigation complete",
            message_id=message_id,
            report_id=report.report_id,
            classification=report.verdict.classification,
            risk_score=report.verdict.risk_score,
        )

        return report.model_dump()

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Gmail investigation failed", message_id=message_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post(
    "/analyze-batch",
    summary="Analyze Multiple Gmail Messages",
    description="""
    Analyze multiple Gmail messages for campaign detection.

    Analyzes each email and correlates findings to detect:
    - Common sender infrastructure
    - Shared IOCs (domains, IPs, hashes)
    - Phishing campaigns
    - Similar content patterns
    - Temporal clustering
    """
)
@limiter.limit(RATE_LIMIT_GMAIL)
async def analyze_gmail_batch(
    request: Request,
    response: Response,
    message_ids: list[str],
    current_user: User = Depends(get_current_active_user)
):
    """Analyze multiple Gmail messages for correlation."""
    if len(message_ids) > 50:
        raise HTTPException(
            status_code=400,
            detail="Maximum 50 messages per batch"
        )

    try:
        client = await _get_gmail_client(current_user.username)
        parser = GmailParser()
        dispatcher = get_dispatcher()

        results = []
        all_iocs: dict[str, list[str]] = {
            "domains": [],
            "ips": [],
            "urls": [],
            "senders": [],
            "sender_domains": [],
            "subjects": [],
            "reply_to_domains": [],
        }
        all_dates = []
        all_auth_failures = {"spf": 0, "dkim": 0, "dmarc": 0}

        for msg_id in message_ids:
            try:
                message = await client.get_message(msg_id, include_raw=True)
                parsed = parser.parse(message)
                analysis_data = parser.to_analysis_request(parsed)

                result = await dispatcher.dispatch_email(analysis_data)

                # Also publish onto the event bus (see analyze_gmail_message's
                # identical comment above) - best-effort, never affects the
                # synchronous batch response.
                try:
                    await publish_email_event(
                        analysis_data,
                        tenant_id=current_user.organization_id or "admin",
                        source="gmail",
                    )
                except Exception as e:
                    logger.warning("Failed to publish email event to bus", error=str(e))

                # Collect IOCs for correlation
                all_iocs["senders"].append(parsed.sender_email)
                if parsed.sender_email and "@" in parsed.sender_email:
                    all_iocs["sender_domains"].append(parsed.sender_email.split("@")[1].lower())

                for url in parsed.urls:
                    all_iocs["domains"].append(url.domain)
                    all_iocs["urls"].append(url.url)

                all_iocs["domains"].extend(result.indicators)
                all_iocs["subjects"].append(parsed.subject.lower())

                if parsed.reply_to_email and "@" in parsed.reply_to_email:
                    all_iocs["reply_to_domains"].append(parsed.reply_to_email.split("@")[1].lower())

                if parsed.date:
                    all_dates.append(parsed.date)

                # Track authentication failures
                if parsed.authentication.spf == "fail":
                    all_auth_failures["spf"] += 1
                if parsed.authentication.dkim == "fail":
                    all_auth_failures["dkim"] += 1
                if parsed.authentication.dmarc == "fail":
                    all_auth_failures["dmarc"] += 1

                results.append({
                    "message_id": msg_id,
                    "subject": parsed.subject,
                    "sender": parsed.sender,
                    "sender_email": parsed.sender_email,
                    "date": parsed.date.isoformat() if parsed.date else None,
                    "classification": result.classification,
                    "risk_score": result.risk_score,
                    "findings_count": len(result.findings),
                    "authentication": {
                        "spf": parsed.authentication.spf,
                        "dkim": parsed.authentication.dkim,
                        "dmarc": parsed.authentication.dmarc,
                    }
                })

            except Exception as e:
                results.append({
                    "message_id": msg_id,
                    "error": str(e)
                })

        # Enhanced correlation analysis
        import difflib
        from collections import Counter

        shared_domains = [d for d, c in Counter(all_iocs["domains"]).items() if c > 1 and d]
        shared_senders = [s for s, c in Counter(all_iocs["senders"]).items() if c > 1 and s]
        shared_sender_domains = [d for d, c in Counter(all_iocs["sender_domains"]).items() if c > 1 and d]
        shared_reply_domains = [d for d, c in Counter(all_iocs["reply_to_domains"]).items() if c > 1 and d]

        # Subject similarity analysis
        similar_subjects = []
        subjects = [s for s in all_iocs["subjects"] if s]
        for i, s1 in enumerate(subjects):
            for s2 in subjects[i+1:]:
                ratio = difflib.SequenceMatcher(None, s1, s2).ratio()
                if ratio > 0.7:
                    similar_subjects.append({"subject1": s1, "subject2": s2, "similarity": ratio})

        # Temporal analysis
        temporal_cluster = None
        if len(all_dates) >= 2:
            sorted_dates = sorted(all_dates)
            time_span = (sorted_dates[-1] - sorted_dates[0]).total_seconds() / 3600  # hours
            if time_span <= 24:
                temporal_cluster = {
                    "time_span_hours": round(time_span, 2),
                    "first_email": sorted_dates[0].isoformat(),
                    "last_email": sorted_dates[-1].isoformat(),
                    "is_burst": time_span <= 2,  # Multiple emails within 2 hours
                }

        # Campaign scoring
        campaign_score = 0
        campaign_indicators = []

        if len(shared_domains) > 0:
            campaign_score += 20
            campaign_indicators.append(f"Shared domains: {len(shared_domains)}")
        if len(shared_senders) > 1:
            campaign_score += 15
            campaign_indicators.append(f"Repeated senders: {len(shared_senders)}")
        if len(shared_sender_domains) > 1:
            campaign_score += 25
            campaign_indicators.append(f"Shared sender infrastructure: {shared_sender_domains}")
        if len(similar_subjects) > 0:
            campaign_score += 20
            campaign_indicators.append(f"Similar subjects: {len(similar_subjects)}")
        if temporal_cluster and temporal_cluster.get("is_burst"):
            campaign_score += 15
            campaign_indicators.append("Temporal burst pattern")
        if all_auth_failures["dmarc"] > len(results) / 2:
            campaign_score += 20
            campaign_indicators.append("Majority DMARC failures")

        # High-risk classification aggregation
        high_risk_count = sum(1 for r in results if r.get("risk_score", 0) >= 70)
        avg_risk_score = sum(r.get("risk_score", 0) for r in results if "risk_score" in r) / max(len(results), 1)

        is_campaign = campaign_score >= 30

        logger.info(
            "Batch analysis complete",
            message_count=len(message_ids),
            campaign_score=campaign_score,
            is_campaign=is_campaign,
            avg_risk_score=avg_risk_score,
        )

        return {
            "analyzed_count": len(results),
            "results": results,
            "correlation": {
                "is_potential_campaign": is_campaign,
                "campaign_score": campaign_score,
                "campaign_indicators": campaign_indicators,
                "shared_domains": shared_domains[:10],
                "shared_senders": shared_senders[:10],
                "shared_sender_domains": shared_sender_domains[:10],
                "shared_reply_to_domains": shared_reply_domains[:10],
                "similar_subjects": similar_subjects[:5],
                "temporal_cluster": temporal_cluster,
                "unique_senders": len(set(all_iocs["senders"])),
            },
            "summary": {
                "total_analyzed": len(results),
                "high_risk_count": high_risk_count,
                "average_risk_score": round(avg_risk_score, 1),
                "auth_failures": all_auth_failures,
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Batch analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")
