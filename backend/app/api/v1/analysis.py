"""
CyberGuard AI - Analysis API Endpoints

Endpoints for manual security analysis (Mode A).
Rate limited: 30/minute for email analysis, 100/minute for GET endpoints.
"""

import re

import hashlib

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
import structlog

from app.agents import AgentType, get_dispatcher
from app.auth.jwt import get_current_active_user
from app.auth.models import User, UserRole
from app.cache.redis_client import get_redis_client
from app.config import settings
from app.database.models.feedback import AnalysisHistory
from app.database.repositories.feedback import get_analysis_history_repository
from app.middleware.rate_limit import limiter, RATE_LIMIT_GET, RATE_LIMIT_NETWORK_SCAN
from app.schemas.analysis import (
    AnalysisType,
    EmailAnalysisRequest,
    LogAnalysisRequest,
    NetworkAnalysisRequest,
    NetworkLookupRequest,
    AnalysisResponse,
    AnalysisHistoryResponse,
    FindingResponse,
    FeedbackLinks,
    LogFileUploadResponse,
)
from app.services.network_intel import lookup_network_intel, NetworkIntelResult
from app.services.eml_parser import (
    MAX_EML_SIZE_BYTES,
    EmlParseError,
    parse_email_address,
    parse_eml_bytes,
    validate_eml_upload,
)
from app.services.email_ingestion import publish_email_event
from app.services.email_report_builder import get_report_builder
from app.services.log_file_parser import LogFileParseError, parse_log_file
from app.services.threat_intel import IOCType, get_threat_intel_service
from app.services.url_analysis.service import analyze_urls as _analyze_url_service


router = APIRouter(prefix="/analysis", tags=["Analysis"])
logger = structlog.get_logger(__name__)


class _ManualAnalysisLogEvent:
    """
    Minimal log_event-like object for on_finding_created()/correlation when
    an analysis was submitted directly via these synchronous REST endpoints
    (not via the event bus's _create_log_event_from_security_event adapter
    in app/event_bus/dispatcher_integration.py, which these calls intentionally
    bypass). Only the attributes finding_lifecycle._detect_source_type() and
    the correlation context extractor actually read are populated.
    """

    def __init__(self, source_type: str, raw_data: dict | None = None) -> None:
        import uuid
        from datetime import datetime, timezone

        self.event_id = str(uuid.uuid4())
        self.id = self.event_id
        self.source = "manual_analysis"
        self.source_id = None
        self.source_event_id = None
        self.timestamp = datetime.now(timezone.utc)
        self.source_type = source_type
        self.source_ip = (raw_data or {}).get("source_ip")
        self.user = (raw_data or {}).get("user") or (raw_data or {}).get("username")
        self.hostname = (raw_data or {}).get("hostname") or (raw_data or {}).get("host")
        self.session_id = None
        self.raw_data = raw_data or {}
        self.extracted_fields = raw_data or {}


async def _trigger_alerts_for_findings(
    result,
    *,
    source_type: str,
    tenant_id: str | None,
    raw_data: dict | None = None,
) -> None:
    """
    Run every finding in an AgentResult through the common alert/correlation
    lifecycle hook (app.correlation.finding_lifecycle.on_finding_created),
    synchronously, independent of the event bus.

    /analysis/email additionally publishes onto the event bus (see
    publish_email_event below) so it also gets re-processed via the
    Redpanda consumer path - but that leg silently no-ops whenever Redpanda
    isn't running/reachable (fails open, warning-logged only), so email
    findings must not depend on it exclusively either. /analysis/logs and
    /analysis/network have no event-bus leg at all, so this call is the
    *only* way those two ever produce an alert.

    Best-effort: a failure here must never affect the synchronous analysis
    response the caller already got back from the dispatcher.
    """
    if not result.findings:
        return

    effective_tenant_id = tenant_id or "unknown"

    try:
        from app.correlation.finding_lifecycle import on_finding_created

        log_event = _ManualAnalysisLogEvent(source_type=source_type, raw_data=raw_data)

        for finding in result.findings:
            try:
                lifecycle_result = await on_finding_created(
                    log_event=log_event,
                    finding=finding,
                    tenant_id=effective_tenant_id,
                )
                logger.info(
                    "Manual analysis finding processed for alerting",
                    finding_id=finding.finding_id,
                    source_type=source_type,
                    tenant_id=effective_tenant_id,
                    alert_id=lifecycle_result.get("alert_id"),
                    individual_alert_id=lifecycle_result.get("individual_alert_id"),
                    correlation_id=lifecycle_result.get("correlation_id"),
                )
            except Exception as e:
                logger.warning(
                    "Finding lifecycle hook failed for manual analysis finding",
                    finding_id=finding.finding_id,
                    source_type=source_type,
                    error=str(e),
                )
    except ImportError as e:
        logger.debug("Finding lifecycle module not available", error=str(e))


async def _persist_email_analysis_history(result, email_request: EmailAnalysisRequest) -> None:
    """
    Save an AnalysisHistory row keyed on the agent result's result_id.

    The feedback flow (POST /feedback) looks up analysis_id against the
    analysis_history table, and AnalysisResponse.feedback hands the
    frontend links built from result.result_id - so without this write,
    every feedback submission would 404 with "Analysis not found"
    regardless of which email endpoint produced the result_id.

    Best-effort: a history-write failure must not fail the analysis
    response itself, so errors are logged and swallowed. No-ops when the
    database isn't enabled (matches the gating in feedback.py).
    """
    if not settings.db_enabled:
        return

    try:
        history_repo = get_analysis_history_repository()
        await history_repo.save(
            AnalysisHistory(
                id=result.result_id,
                classification=result.classification,
                severity=result.severity.value,
                risk_score=result.risk_score,
                confidence=result.confidence,
                findings=[
                    {
                        "finding_id": f.finding_id,
                        "rule_id": f.rule_id,
                        "name": f.name,
                        "severity": f.severity.value,
                    }
                    for f in result.findings
                ],
                email_sender=email_request.sender,
                email_subject=email_request.subject,
                processing_time_ms=result.processing_time_ms,
            )
        )
    except Exception as e:
        logger.warning(
            "Failed to persist analysis history (feedback submission for this "
            "result will not be possible)",
            result_id=result.result_id,
            error=str(e),
        )


async def _persist_log_analysis_history(
    result, log_request: LogAnalysisRequest, analyzed_by: str | None
) -> None:
    """
    Save an AnalysisHistory row for a log analysis result, generalizing
    the email-only history table above (analysis_type='log') so LogAgent
    findings can receive real analyst feedback (confirmed/false_positive)
    - without this write, POST /feedback would 404 for every log result,
    same as it did before this existed.

    Best-effort, same contract as _persist_email_analysis_history: a
    history-write failure must not fail the analysis response, and this
    no-ops when the database isn't enabled.
    """
    if not settings.db_enabled:
        return

    try:
        history_repo = get_analysis_history_repository()
        await history_repo.save(
            AnalysisHistory(
                id=result.result_id,
                analysis_type=AnalysisType.LOG,
                classification=result.classification,
                severity=result.severity.value,
                risk_score=result.risk_score,
                confidence=result.confidence,
                findings=[
                    {
                        "finding_id": f.finding_id,
                        "rule_id": f.rule_id,
                        "name": f.name,
                        "severity": f.severity.value,
                    }
                    for f in result.findings
                ],
                context={
                    "source": getattr(result, "source", None) or log_request.log_type,
                    "source_host": log_request.source_host,
                    "processed_event_count": getattr(result, "processed_event_count", None),
                },
                processing_time_ms=result.processing_time_ms,
                analyzed_by=analyzed_by,
            )
        )
    except Exception as e:
        logger.warning(
            "Failed to persist log analysis history (feedback submission for "
            "this result will not be possible)",
            result_id=result.result_id,
            error=str(e),
        )


async def _persist_network_analysis_history(
    result, network_request: NetworkAnalysisRequest, analyzed_by: str | None
) -> None:
    """
    Save an AnalysisHistory row for a network analysis result, same
    generalization as _persist_log_analysis_history (analysis_type=
    'network') so NetworkAgent findings can receive real analyst feedback
    (confirmed/false_positive) - without this write, POST /feedback would
    404 for every network result.

    Best-effort, same contract as the email/log helpers above: a
    history-write failure must not fail the analysis response, and this
    no-ops when the database isn't enabled.
    """
    if not settings.db_enabled:
        return

    try:
        history_repo = get_analysis_history_repository()
        await history_repo.save(
            AnalysisHistory(
                id=result.result_id,
                analysis_type=AnalysisType.NETWORK,
                classification=result.classification,
                severity=result.severity.value,
                risk_score=result.risk_score,
                confidence=result.confidence,
                findings=[
                    {
                        "finding_id": f.finding_id,
                        "rule_id": f.rule_id,
                        "name": f.name,
                        "severity": f.severity.value,
                    }
                    for f in result.findings
                ],
                context={
                    "target": network_request.target,
                    "scan_type": network_request.scan_type,
                    "authorized": network_request.authorized,
                },
                processing_time_ms=result.processing_time_ms,
                analyzed_by=analyzed_by,
            )
        )
    except Exception as e:
        logger.warning(
            "Failed to persist network analysis history (feedback submission "
            "for this result will not be possible)",
            result_id=result.result_id,
            error=str(e),
        )


def _convert_to_response(result) -> AnalysisResponse:
    """Convert AgentResult to API response schema."""
    # Build feedback links using the result_id
    feedback_links = FeedbackLinks(
        report_false_positive=f"/api/v1/feedback?analysis_id={result.result_id}&type=false_positive",
        report_missed_threat=f"/api/v1/feedback?analysis_id={result.result_id}&type=false_negative",
    )

    return AnalysisResponse(
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
                metadata=f.metadata,
                source_ip=f.source_ip,
                host=f.host,
                timestamp=f.timestamp,
            )
            for f in result.findings
        ],
        indicators=result.indicators,
        summary=result.summary,
        recommendations=result.recommendations,
        source=getattr(result, "source", None),
        processed_event_count=getattr(result, "processed_event_count", None),
        affected_systems=getattr(result, "affected_systems", None) or [],
        affected_accounts=getattr(result, "affected_accounts", None) or [],
        data_source=getattr(result, "data_source", None),
        scan_warnings=getattr(result, "scan_warnings", None) or [],
        feedback=feedback_links,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/email",
    response_model=AnalysisResponse,
    summary="Analyze Email",
    description="""
Analyze an email for phishing indicators, malicious content, and suspicious patterns.

The Email Security Agent examines:
- Sender characteristics and domain reputation
- Reply-To mismatches
- URL analysis and link safety
- Attachment metadata
- Social engineering indicators
- Header anomalies
- IOC extraction

Returns a detailed analysis with findings, risk score, and recommendations.
    """,
)
@limiter.limit(settings.rate_limit_email_analysis)
async def analyze_email(request: Request, response: Response, email_request: EmailAnalysisRequest) -> AnalysisResponse:
    """Analyze an email for security threats."""
    logger.info(
        "Email analysis requested",
        sender=email_request.sender,
        subject=email_request.subject[:50] if email_request.subject else None,
    )

    try:
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_email(email_request.model_dump())
        await _persist_email_analysis_history(result, email_request)

        # Also publish onto the event bus so this same finding is
        # persisted and runs through the automatic alerting/correlation
        # pipeline (on_finding_created) a second time via the Redpanda
        # consumer. This route has no auth dependency (pre-existing,
        # flagged above `investigate_email`/`upload_email`), so there is
        # no real tenant to scope it to - "unknown" is the same sentinel
        # app/event_bus/dispatcher_integration.py already uses for that
        # case rather than fabricating a "default" tenant. Best-effort:
        # a publish failure must never affect the synchronous response.
        try:
            await publish_email_event(
                email_request.model_dump(), tenant_id="unknown", source="manual"
            )
        except Exception as e:
            logger.warning("Failed to publish email event to bus", error=str(e))

        # Primary alerting path: call the lifecycle hook directly instead
        # of relying solely on the event bus above, which silently no-ops
        # whenever Redpanda isn't running/reachable (fails open at both
        # publish time and consumer startup - see main.py). This is what
        # actually makes "run an email analysis -> get an alert" work in
        # environments without Redpanda up.
        await _trigger_alerts_for_findings(
            result,
            source_type="email",
            tenant_id="unknown",
            raw_data=email_request.model_dump(),
        )

        return _convert_to_response(result)

    except Exception as e:
        logger.error("Email analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


async def _run_email_investigation(
    email_request: EmailAnalysisRequest,
    email_source: str,
    parsed_overrides: dict | None = None,
) -> dict:
    """
    Shared investigation logic for both the manual-paste and upload paths.

    email_source is "manual" or "upload" and is passed through to the report
    builder. parsed_overrides lets the upload path supply real header-derived
    fields (reply_to, return_path, message_id, authentication, received_chain)
    that a hand-pasted email never has - everything else about the pipeline
    (dispatch, history persistence, threat intel, URL enrichment) is identical
    between the two paths, so there is exactly one analysis contract.
    """
    logger.info(
        "Email investigation requested",
        source=email_source,
        sender=email_request.sender,
        subject=email_request.subject[:50] if email_request.subject else None,
    )

    dispatcher = get_dispatcher()
    result = await dispatcher.dispatch_email(email_request.model_dump())
    await _persist_email_analysis_history(result, email_request)

    # Also publish onto the event bus (see analyze_email's identical
    # comment above) - same "unknown" tenant sentinel, same best-effort
    # semantics. email_source is "manual" or "upload"; both map to the
    # same bus "source" label since neither carries real tenant auth.
    try:
        await publish_email_event(
            email_request.model_dump(), tenant_id="unknown", source="manual"
        )
    except Exception as e:
        logger.warning("Failed to publish email event to bus", error=str(e))

    # Enrich IOCs with threat intelligence (same pattern as Gmail investigation)
    threat_intel = get_threat_intel_service()
    threat_intel_results: dict = {}

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
    if email_request.urls:
        try:
            svc_results = await _analyze_url_service(email_request.urls)
            for svc_r in svc_results:
                original = svc_r.get("url", "")
                if original:
                    url_service_results[original] = svc_r
        except Exception as e:
            logger.warning("URL analysis service failed", error=str(e))

    def _enrich_url(url: str) -> dict:
        svc = url_service_results.get(url, {})
        url_dict: dict = {"url": url}
        if svc:
            url_dict["url_service_status"] = svc.get("status", "unknown")
            url_dict["url_service_is_malicious"] = bool(svc.get("is_malicious", False))
            url_dict["url_service_risk_score"] = int(svc.get("risk_score", 0) or 0)
            url_dict["url_service_patterns"] = svc.get("patterns", {})
        return url_dict

    # Base parsed-email shape, equivalent to Gmail's parsed_email_data.
    # For manual input there is no authentication/received_chain data - the
    # report builder renders those sections as "not available" rather than
    # fabricating values (see EmailReportBuilder._build_authentication_section).
    # The upload path overrides these fields with real header-derived data
    # when available (see parsed_overrides).
    parsed_email_data: dict = {
        "sender": email_request.sender,
        "sender_email": email_request.sender,
        "sender_name": None,
        "subject": email_request.subject,
        "date": email_request.received_at.isoformat() if email_request.received_at else None,
        "reply_to": None,
        "reply_to_email": None,
        "return_path": None,
        "return_path_email": None,
        "message_id": None,
        "recipients": [email_request.recipient] if email_request.recipient else [],
        "urls_detailed": [_enrich_url(u) for u in (email_request.urls or [])],
        "attachments": email_request.attachments or [],
        "received_chain": [],
        "authentication": {},
    }
    if parsed_overrides:
        parsed_email_data.update(parsed_overrides)

    report_builder = get_report_builder()
    report = report_builder.build_report(
        agent_result=result,
        parsed_email=parsed_email_data,
        threat_intel=threat_intel_results,
        email_source=email_source,
    )

    logger.info(
        "Email investigation complete",
        source=email_source,
        report_id=report.report_id,
        classification=report.verdict.classification,
        risk_score=report.verdict.risk_score,
    )

    return report.model_dump()


@router.post(
    "/email/investigate",
    summary="Full Email Investigation Report",
    description="""
Comprehensive email security investigation with professional SOC-style report,
for manually-submitted email data (paste-in, not Gmail).

Returns detailed sections:
- Verdict with risk score and confidence
- Executive summary
- Sender intelligence
- Authentication analysis (SPF/DKIM/DMARC, when header data is supplied)
- URL intelligence
- Content analysis
- Attachment analysis
- Header forensics
- Threat intelligence
- IOC inventory
- Risk breakdown
- Recommendations

Authentication results will show as "not available" when the submitted email
has no SPF/DKIM/DMARC header data (expected for hand-pasted email text that
doesn't carry its original headers).
    """,
)
@limiter.limit(settings.rate_limit_email_analysis)
async def investigate_email(
    request: Request, response: Response, email_request: EmailAnalysisRequest
) -> dict:
    """Full investigation report for a manually-submitted email."""
    try:
        return await _run_email_investigation(email_request, email_source="manual")
    except Exception as e:
        logger.error("Email investigation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post(
    "/email/upload",
    summary="Upload and Analyze .eml File",
    description=f"""
Upload a raw `.eml` file for the same full SOC-style investigation as
`/email/investigate`, with real header-derived data (Reply-To, Return-Path,
Message-ID, and SPF/DKIM/DMARC authentication results when present in the
file) instead of the "not available" placeholders used for hand-pasted text.

**Limits:**
- Max file size: {MAX_EML_SIZE_BYTES // (1024 * 1024)}MB
- File must have a `.eml` extension and contain recognizable email headers

Returns the same report shape as `/email/investigate`.
    """,
    responses={
        400: {"description": "Invalid or unparseable .eml file"},
        413: {"description": "File exceeds the maximum upload size"},
    },
)
@limiter.limit(settings.rate_limit_email_analysis)
async def upload_email(
    request: Request, response: Response, file: UploadFile = File(...)
) -> dict:
    """Full investigation report for an uploaded .eml file."""
    # NOTE: like /email and /email/investigate, this route has no auth
    # dependency today - flagged, not fixed, per task scope (no pre-existing
    # auth exists on this router to break).
    raw_bytes = await file.read()

    if len(raw_bytes) > MAX_EML_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_EML_SIZE_BYTES // (1024 * 1024)}MB upload limit",
        )

    try:
        validate_eml_upload(file.filename or "", raw_bytes)
        parsed = parse_eml_bytes(raw_bytes)
    except EmlParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        email_request = EmailAnalysisRequest(
            sender=parsed["sender"],
            recipient=parsed["recipient"],
            subject=parsed["subject"],
            body=parsed["body"],
            headers=parsed["headers"],
            urls=parsed["urls"],
            attachments=parsed["attachments"],
            received_at=parsed["received_at"],
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid email content: {e}")

    headers = parsed["headers"]
    reply_to_raw = headers.get("Reply-To") or headers.get("reply-to", "")
    return_path_raw = headers.get("Return-Path") or headers.get("return-path", "")
    auth_results_raw = headers.get("Authentication-Results") or headers.get(
        "authentication-results", ""
    )

    def _addr(raw: str) -> str | None:
        return parse_email_address(raw) or None

    parsed_overrides = {
        "reply_to": reply_to_raw or None,
        "reply_to_email": _addr(reply_to_raw),
        "return_path": return_path_raw or None,
        "return_path_email": _addr(return_path_raw),
        "message_id": headers.get("Message-ID") or headers.get("message-id"),
        "received_chain": [
            v for k, v in headers.items() if k.lower() == "received"
        ],
        "authentication": {"raw_results": auth_results_raw} if auth_results_raw else {},
    }

    try:
        return await _run_email_investigation(
            email_request, email_source="upload", parsed_overrides=parsed_overrides
        )
    except Exception as e:
        logger.error("Email upload investigation failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.get(
    "/history",
    response_model=list[AnalysisHistoryResponse],
    summary="List Analysis History",
    description="""
List recent email analysis history entries (lightweight summaries, not full
investigation reports - full reports are not persisted).
    """,
)
@limiter.limit(RATE_LIMIT_GET)
async def get_analysis_history(
    request: Request,
    response: Response,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    classification: str | None = Query(None),
    analysis_type: str | None = Query(None, description="Filter by analysis type, e.g. 'email', 'log', 'network'"),
) -> list[AnalysisHistoryResponse]:
    """List recent analysis history entries."""
    # NOTE: no auth dependency and no organization scoping on this route or
    # the underlying AnalysisHistory model today - flagged, not fixed, per
    # task scope (nothing pre-existing to preserve here).
    if not settings.db_enabled:
        return []

    history_repo = get_analysis_history_repository()
    entries = await history_repo.list(
        limit=limit, offset=offset, classification=classification, analysis_type=analysis_type
    )

    return [
        AnalysisHistoryResponse(
            id=entry.id,
            classification=entry.classification,
            severity=entry.severity,
            risk_score=entry.risk_score,
            confidence=entry.confidence,
            analyzed_at=entry.analyzed_at,
            email_sender=entry.email_sender,
            email_subject=entry.email_subject,
            processing_time_ms=entry.processing_time_ms,
            context=entry.context or None,
        )
        for entry in entries
    ]


@router.post(
    "/logs",
    response_model=AnalysisResponse,
    summary="Analyze Logs",
    description="""
Analyze security logs for suspicious patterns and threat indicators.

The Log Analyzer Agent examines:
- Authentication events (success/failure patterns)
- Brute force detection
- Privilege escalation indicators
- Suspicious access patterns
- Anomalous behavior
- IOC extraction from log entries

Supports various log formats:
- Linux auth logs (syslog)
- Windows Security Event logs
- Web server logs (Apache, Nginx)
- Firewall logs
- Application logs

Returns a detailed analysis with findings, timeline, and recommendations.
    """,
)
async def analyze_logs(
    request: LogAnalysisRequest,
    user: User = Depends(get_current_active_user),
) -> AnalysisResponse:
    """Analyze logs for security threats."""
    log_lines = len(request.log_content.strip().split("\n"))
    logger.info(
        "Log analysis requested",
        log_type=request.log_type,
        line_count=log_lines,
    )

    try:
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_log(request.model_dump())
        await _persist_log_analysis_history(result, request, analyzed_by=user.id)

        # This endpoint had no path to the alert/correlation pipeline at
        # all (unlike /analysis/email, which at least publishes onto the
        # event bus) - a MEDIUM+ severity finding from a manual log
        # analysis never produced an alert, regardless of risk score.
        # Call the lifecycle hook directly so it does.
        await _trigger_alerts_for_findings(
            result,
            source_type="log",
            tenant_id=user.organization_id,
            raw_data=request.model_dump(),
        )

        return _convert_to_response(result)

    except Exception as e:
        logger.error("Log analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


async def _check_and_set_upload_dedup(organization_id: str, raw_bytes: bytes) -> None:
    """
    Reject an identical re-submission from the same tenant within the
    dedup TTL window via `SET NX EX` (atomic claim-or-reject).

    Scoped by organization_id + content hash so two different tenants
    uploading identical content never collide with each other.

    Fails open (logs a warning, does not block the upload) if Redis is
    unavailable - this is a UX nicety against accidental double-submits,
    not a security control.
    """
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    key = f"log_upload_dedup:{organization_id}:{content_hash}"
    try:
        redis_client = await get_redis_client()
        # The simplified RedisClient.set() wrapper has no `nx=` support,
        # so the raw client is used directly for this one atomic check.
        claimed = await redis_client.client.set(
            key, "1", nx=True, ex=settings.log_upload_dedup_ttl_seconds
        )
    except Exception as e:
        logger.warning("Upload dedup check unavailable, failing open", error=str(e))
        return

    if not claimed:
        raise HTTPException(
            status_code=409,
            detail=(
                "This file was already submitted in the last "
                f"{settings.log_upload_dedup_ttl_seconds} seconds. "
                "Wait for that analysis to complete or use a different file."
            ),
        )


@router.post(
    "/logs/upload",
    response_model=LogFileUploadResponse,
    summary="Upload and Analyze a Log File",
    description=f"""
Upload a log file (`.log`, `.txt`, `.csv`, `.json`, `.jsonl`) for parsing and
analysis by the same deterministic LogAgent rules used by `/analysis/logs`.

**Supported formats and fidelity:**
- `.log` / `.txt`: parsed line-by-line. For `source_type_hint=linux_ssh` or
  `android`, each line is additionally validated against the real collector
  parser for that source (unparseable lines are still passed through to
  LogAgent's own rules, just flagged as unparsed in `skipped_line_count`).
  For `source_type_hint=windows`, genuine Event Log XML content is parsed
  with full fidelity; otherwise lines are passed through as a best-effort
  generic fallback (`detected_source_type` will read
  `"windows_generic_fallback"` - there is no verified plain-text Windows
  parser).
- `.jsonl`: one JSON object per line.
- `.json`: a JSON array of objects, or an object containing an
  `events`/`logs`/`entries`/`records` list, or genuine Windows Event Log XML
  content with a `.json` extension.
- `.csv`: must have a header row containing a recognizable message column
  (`message`, `msg`, `log`, `description`, `event`, or `text`).

**Limits:**
- Max file size: {settings.log_upload_max_file_size_bytes // (1024 * 1024)}MB
- One file per request
- Identical re-submissions from the same tenant are rejected for
  {settings.log_upload_dedup_ttl_seconds}s

No ML model is used - log analysis is purely the existing deterministic
LogAgent rule engine, same as every other log analysis entry point.
Results are not persisted (ephemeral, matching `/analysis/logs`).
    """,
    responses={
        400: {"description": "Invalid file, unsupported content, or no usable log records"},
        401: {"description": "Authentication required"},
        409: {"description": "Duplicate submission (same file, same tenant, within the TTL window)"},
        413: {"description": "File exceeds the maximum upload size"},
    },
)
@limiter.limit(settings.rate_limit_email_analysis)
async def upload_log_file(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    source_type_hint: str = Form("auto"),
    preview_only: bool = Form(False),
    user: User = Depends(get_current_active_user),
) -> LogFileUploadResponse:
    """Parse and (unless preview_only) analyze an uploaded log file."""
    # Unlike /analysis/logs and /analysis/email/upload (both pre-existing,
    # unauthenticated routes - flagged, not fixed, per task scope), this
    # new endpoint requires auth and enforces tenant scoping, since the
    # feature's own requirements call for it.
    if source_type_hint not in ("windows", "linux_ssh", "android", "auto"):
        raise HTTPException(
            status_code=400,
            detail="source_type_hint must be one of: windows, linux_ssh, android, auto",
        )

    organization_id = user.organization_id
    if user.role != UserRole.ADMIN and not organization_id:
        raise HTTPException(
            status_code=400,
            detail="Your account has no organization_id assigned - contact an administrator",
        )
    # Admins with no organization_id of their own are scoped under a
    # fixed label for dedup purposes only - this never affects analysis
    # results, just which "recent duplicate" bucket is checked.
    dedup_org_id = organization_id or "admin"

    raw_bytes = await file.read()
    filename = file.filename or "upload"

    if len(raw_bytes) > settings.log_upload_max_file_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                "File exceeds the "
                f"{settings.log_upload_max_file_size_bytes // (1024 * 1024)}MB upload limit"
            ),
        )

    if not preview_only:
        await _check_and_set_upload_dedup(dedup_org_id, raw_bytes)

    try:
        parsed = parse_log_file(raw_bytes, filename, source_type_hint=source_type_hint)
    except LogFileParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    base_fields = dict(
        filename=filename,
        size_bytes=len(raw_bytes),
        declared_source_type=source_type_hint,
        detected_source_type=parsed.detected_source_type,
        parsed_event_count=parsed.parsed_event_count,
        skipped_line_count=parsed.skipped_line_count,
        preview_events=parsed.preview_events,
        encoding_fallback_used=parsed.encoding_fallback_used,
        preview_only=preview_only,
    )

    if preview_only:
        return LogFileUploadResponse(**base_fields)

    logger.info(
        "Log file upload analysis requested",
        filename=filename,
        size_bytes=len(raw_bytes),
        source_type_hint=source_type_hint,
        detected_source_type=parsed.detected_source_type,
        parsed_event_count=parsed.parsed_event_count,
        organization_id=dedup_org_id,
    )

    try:
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch(
            AgentType.LOG,
            {
                "log_content": parsed.synthetic_log_content,
                "log_type": source_type_hint if source_type_hint != "auto" else None,
                "source_host": None,
            },
        )
    except Exception as e:
        # Never echo raw file content back in an error - only counts and
        # the exception's own (already-generic) message.
        logger.error("Log file upload analysis failed", filename=filename, error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    analysis_response = _convert_to_response(result)
    return LogFileUploadResponse(
        **base_fields,
        **analysis_response.model_dump(exclude={"metadata"}),
    )


@router.post(
    "/network",
    response_model=AnalysisResponse,
    summary="Analyze Network",
    description="""
Perform authorized network security analysis on a target IP or CIDR range.

⚠️ **IMPORTANT**: Only scan systems you own or have explicit authorization to assess.

The Network Analysis Agent performs:
- Host discovery
- Port scanning
- Service detection
- Version identification
- Vulnerability enrichment (CVE lookup)
- Risk assessment

**Scan Types:**
- `basic`: Host discovery and common ports
- `service`: Service and version detection
- `full`: Comprehensive scan with OS detection

Returns discovered hosts, services, potential vulnerabilities, and recommendations.
    """,
)
@limiter.limit(RATE_LIMIT_NETWORK_SCAN)
async def analyze_network(
    request: Request,
    response: Response,
    network_request: NetworkAnalysisRequest,
    user: User = Depends(get_current_active_user),
) -> AnalysisResponse:
    """Analyze network target for security assessment."""
    logger.info(
        "Network analysis requested",
        target=network_request.target,
        scan_type=network_request.scan_type,
    )

    try:
        dispatcher = get_dispatcher()
        result = await dispatcher.dispatch_network(network_request.model_dump())
        await _persist_network_analysis_history(result, network_request, analyzed_by=user.id)

        # Same gap as /analysis/logs: this endpoint had no path to the
        # alert/correlation pipeline at all. Call the lifecycle hook
        # directly so a MEDIUM+ severity finding from a manual network
        # scan actually produces an alert.
        await _trigger_alerts_for_findings(
            result,
            source_type="network",
            tenant_id=user.organization_id,
            raw_data=network_request.model_dump(),
        )

        return _convert_to_response(result)

    except Exception as e:
        logger.error("Network analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post(
    "/network/lookup",
    response_model=NetworkIntelResult,
    summary="Analyze (lightweight IP/domain lookup)",
    description="""
Passive OSINT lookup for an IP address or domain: DNS resolution, IP
geolocation, RDAP registration info, and threat-intel reputation
(VirusTotal/AbuseIPDB, when configured).

This endpoint only queries public records about the target - it never
scans or connects to the target itself, so it does not require the
authorization confirmation that `POST /analysis/network` requires for an
active port scan.

When VirusTotal/AbuseIPDB API keys are not configured on this server, the
`threat_intel` field explicitly reports `configured: false` rather than a
fabricated "clean" verdict.
    """,
)
@limiter.limit(RATE_LIMIT_GET)
async def lookup_network(
    request: Request,
    response: Response,
    lookup_request: NetworkLookupRequest,
    user: User = Depends(get_current_active_user),
) -> NetworkIntelResult:
    """Lightweight IP/domain OSINT lookup (DNS/geoip/RDAP/threat-intel)."""
    logger.info("Network lookup requested", target=lookup_request.target)

    try:
        return await lookup_network_intel(lookup_request.target)
    except Exception as e:
        logger.error("Network lookup failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")


@router.get(
    "/agents",
    summary="Get Agent Statuses",
    description="Get the status of all analysis agents.",
)
@limiter.limit(RATE_LIMIT_GET)
async def get_agent_statuses(request: Request, response: Response) -> dict:
    """Get status of all analysis agents."""
    dispatcher = get_dispatcher()
    return {
        "agents": dispatcher.get_all_agent_statuses(),
    }



