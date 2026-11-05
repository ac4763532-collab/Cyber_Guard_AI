"""
CyberGuard AI - Threat Intelligence API Endpoints

Exposes the ThreatIntelAgent (which wraps the existing ThreatIntelService -
real VirusTotal + AbuseIPDB calls) for standalone IOC lookups, and reports
whether the underlying providers are configured. No provider API keys are
ever returned to the client.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel, Field

from app.agents.base import AgentType
from app.agents.dispatcher import get_dispatcher
from app.auth.jwt import get_current_active_user
from app.auth.models import User
from app.services.threat_intel.service import IOCType, get_threat_intel_service, normalize_ioc_value


router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

_MAX_BATCH_SIZE = 25


class LookupRequest(BaseModel):
    """Single IOC lookup request."""

    ioc_type: str = Field(..., description="One of: ip, domain, url, email, hash_md5, hash_sha1, hash_sha256")
    ioc_value: str = Field(..., min_length=1, description="The indicator value to look up")


class BatchLookupRequest(BaseModel):
    """Batch IOC lookup request."""

    iocs: list[LookupRequest] = Field(..., min_length=1, max_length=_MAX_BATCH_SIZE)


class ProviderOutcomeResponse(BaseModel):
    """Per-provider execution outcome, surfaced as-is from the agent."""

    name: str
    status: str
    detections: int | None = None
    confidence_score: int | None = None
    last_analysis_at: str | None = None
    detail: str | None = None


class LookupResponse(BaseModel):
    """Response for a single IOC lookup."""

    ioc_type: str
    ioc_value: str
    reputation_status: str
    classification_reason: str
    risk_score: int | None = None
    sources: list[str]
    provider_outcomes: list[ProviderOutcomeResponse]
    recommendations: list[str]
    success: bool
    error: str | None = None


class StatusResponse(BaseModel):
    """Whether threat intel providers are configured. Never exposes keys."""

    virustotal_configured: bool
    abuseipdb_configured: bool
    any_configured: bool


def _agent_result_to_response(agent_result: Any, ioc_type: str, ioc_value: str) -> LookupResponse:
    # Read provider evidence from AgentResult.metadata, which
    # ThreatIntelAgent always populates regardless of classification -
    # unlike agent_result.findings, which is only non-empty for
    # MALICIOUS/SUSPICIOUS. This is what keeps classification_reason from
    # ever outrunning the evidence actually backing it (e.g. a CLEAN result
    # must show the real provider outcomes that led to CLEAN, not an empty
    # list that looks like no providers ran).
    metadata = agent_result.metadata or {}
    provider_outcomes = [
        ProviderOutcomeResponse(**o) for o in metadata.get("provider_outcomes", [])
    ]

    return LookupResponse(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        reputation_status=agent_result.classification,
        classification_reason=agent_result.summary,
        risk_score=agent_result.risk_score if agent_result.classification not in ("unknown", "lookup_failed") else None,
        sources=metadata.get("sources", []),
        provider_outcomes=provider_outcomes,
        recommendations=agent_result.recommendations,
        success=agent_result.success,
        error=agent_result.error,
    )


@router.post(
    "/lookup",
    response_model=LookupResponse,
    summary="Look Up an Indicator",
    description="Enrich a single IOC (IP, domain, URL, email, or file hash) via VirusTotal/AbuseIPDB.",
)
async def lookup_indicator(
    request: LookupRequest,
    user: User = Depends(get_current_active_user),
) -> LookupResponse:
    """Dispatch a single IOC lookup through the Threat Intelligence Agent."""
    if request.ioc_type not in {t.value for t in IOCType}:
        raise HTTPException(status_code=400, detail=f"Invalid ioc_type: {request.ioc_type}")
    try:
        normalize_ioc_value(IOCType(request.ioc_type), request.ioc_value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    dispatcher = get_dispatcher()
    agent_result = await dispatcher.dispatch(
        AgentType.THREAT_INTEL,
        {"ioc_type": request.ioc_type, "ioc_value": request.ioc_value},
    )
    return _agent_result_to_response(agent_result, request.ioc_type, request.ioc_value)


@router.post(
    "/lookup/batch",
    response_model=list[LookupResponse],
    summary="Look Up Multiple Indicators",
    description=f"Enrich up to {_MAX_BATCH_SIZE} IOCs in a single request.",
)
async def lookup_indicators_batch(
    request: BatchLookupRequest,
    user: User = Depends(get_current_active_user),
) -> list[LookupResponse]:
    """Dispatch a batch IOC lookup through the Threat Intelligence Agent."""
    for item in request.iocs:
        if item.ioc_type not in {t.value for t in IOCType}:
            raise HTTPException(status_code=400, detail=f"Invalid ioc_type: {item.ioc_type}")
        try:
            normalize_ioc_value(IOCType(item.ioc_type), item.ioc_value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    dispatcher = get_dispatcher()
    agent = dispatcher.get_agent(AgentType.THREAT_INTEL)

    # PlaceholderAgent (provider not wired yet) has no analyze_batch - fall
    # back to per-item dispatch so batch lookups still work via the
    # placeholder's generic analyze() path.
    if hasattr(agent, "analyze_batch"):
        iocs = [(IOCType(item.ioc_type), item.ioc_value) for item in request.iocs]
        agent_results = await agent.analyze_batch(iocs)
    else:
        agent_results = [
            await dispatcher.dispatch(
                AgentType.THREAT_INTEL,
                {"ioc_type": item.ioc_type, "ioc_value": item.ioc_value},
            )
            for item in request.iocs
        ]

    return [
        _agent_result_to_response(result, item.ioc_type, item.ioc_value)
        for result, item in zip(agent_results, request.iocs)
    ]


@router.get(
    "/status",
    response_model=StatusResponse,
    summary="Threat Intel Provider Status",
    description="Report whether VirusTotal/AbuseIPDB are configured (never returns the keys).",
)
async def get_status(user: User = Depends(get_current_active_user)) -> StatusResponse:
    """Report provider configuration status only - no secrets."""
    service = get_threat_intel_service()
    return StatusResponse(
        virustotal_configured=service.virustotal_configured,
        abuseipdb_configured=service.abuseipdb_configured,
        any_configured=service.is_configured,
    )
