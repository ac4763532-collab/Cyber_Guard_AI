"""
CyberGuard AI - LLM API Endpoints

AI-powered analysis endpoints with enhanced features:
- Threat analysis with structured JSON output
- Streaming responses for real-time display
- Chat interface with conversation history
- Usage statistics and cost tracking
"""

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.llm import get_llm_client, get_prompt_builder


router = APIRouter(prefix="/llm", tags=["LLM Analysis"])


class ThreatAnalysisRequest(BaseModel):
    """Request for threat analysis."""

    findings: list[dict[str, Any]] = Field(
        ...,
        description="Security findings to analyze",
        min_length=1,
    )
    context: dict[str, Any] | None = Field(
        None,
        description="Additional context",
    )
    structured_output: bool = Field(
        False,
        description="Return JSON-structured analysis",
    )


class RemediationRequest(BaseModel):
    """Request for remediation recommendations."""

    incident_data: dict[str, Any] = Field(
        ...,
        description="Incident data for remediation",
    )


class IOCEnrichRequest(BaseModel):
    """Request for IOC enrichment."""

    ioc_type: str = Field(..., description="Type of IOC (ip, domain, hash, etc.)")
    ioc_value: str = Field(..., description="The IOC value")


class MITREMapRequest(BaseModel):
    """Request for MITRE ATT&CK mapping."""

    description: str = Field(..., description="Activity description to map")
    findings: list[dict[str, Any]] | None = Field(None, description="Related findings")


class ChatRequest(BaseModel):
    """Request for chat interaction."""

    message: str = Field(..., description="User message", min_length=1)
    conversation_history: list[dict[str, str]] | None = Field(
        None,
        description="Previous conversation turns [{role: 'user'/'assistant', content: '...'}]",
    )


class StreamRequest(BaseModel):
    """Request for streaming analysis."""

    prompt: str = Field(..., description="Analysis prompt")
    system_prompt: str | None = Field(None, description="Custom system prompt")


class LLMAnalysisResponse(BaseModel):
    """Response from LLM analysis."""

    response_id: str
    content: str
    structured_data: dict[str, Any] | None = None
    model: str
    tokens_used: int
    input_tokens: int = 0
    output_tokens: int = 0
    processing_time_ms: float
    success: bool
    error: str | None = None


class LLMStatusResponse(BaseModel):
    """LLM status and usage statistics."""

    available: bool
    model: str | None
    templates: list[str]
    usage: dict[str, Any] | None = None


@router.get(
    "/status",
    response_model=LLMStatusResponse,
    summary="Get LLM Status",
    description="Check LLM availability and usage statistics.",
)
async def get_status() -> LLMStatusResponse:
    """Check LLM availability and get usage stats."""
    client = get_llm_client()
    prompt_builder = get_prompt_builder()

    usage = None
    if client.is_available:
        stats = client.usage_stats
        usage = {
            "total_requests": stats.total_requests,
            "total_input_tokens": stats.total_input_tokens,
            "total_output_tokens": stats.total_output_tokens,
            "total_cost_usd": round(stats.total_cost_usd, 4),
            "errors": stats.errors,
        }

    return LLMStatusResponse(
        available=client.is_available,
        model=client._settings.llm_model if client.is_available else None,
        templates=prompt_builder.list_templates(),
        usage=usage,
    )


@router.post(
    "/analyze-threat",
    response_model=LLMAnalysisResponse,
    summary="Analyze Threat",
    description="AI-powered threat analysis of security findings.",
)
async def analyze_threat(request: ThreatAnalysisRequest) -> LLMAnalysisResponse:
    """Run AI threat analysis."""
    client = get_llm_client()
    result = await client.analyze_threat(
        findings=request.findings,
        context=request.context,
        structured_output=request.structured_output,
    )

    return LLMAnalysisResponse(
        response_id=result.response_id,
        content=result.content,
        structured_data=result.structured_data,
        model=result.model,
        tokens_used=result.tokens_used,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        processing_time_ms=result.processing_time_ms,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/remediation",
    response_model=LLMAnalysisResponse,
    summary="Generate Remediation",
    description="AI-generated remediation recommendations.",
)
async def generate_remediation(request: RemediationRequest) -> LLMAnalysisResponse:
    """Generate remediation recommendations."""
    client = get_llm_client()
    result = await client.generate_remediation(request.incident_data)

    return LLMAnalysisResponse(
        response_id=result.response_id,
        content=result.content,
        model=result.model,
        tokens_used=result.tokens_used,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        processing_time_ms=result.processing_time_ms,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/enrich-ioc",
    response_model=LLMAnalysisResponse,
    summary="Enrich IOC",
    description="AI-powered IOC context and enrichment.",
)
async def enrich_ioc(request: IOCEnrichRequest) -> LLMAnalysisResponse:
    """Enrich an IOC with AI context."""
    client = get_llm_client()
    result = await client.enrich_ioc(
        ioc_type=request.ioc_type,
        ioc_value=request.ioc_value,
    )

    return LLMAnalysisResponse(
        response_id=result.response_id,
        content=result.content,
        structured_data=result.structured_data,
        model=result.model,
        tokens_used=result.tokens_used,
        input_tokens=getattr(result, 'input_tokens', 0),
        output_tokens=getattr(result, 'output_tokens', 0),
        processing_time_ms=result.processing_time_ms,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/map-mitre",
    response_model=LLMAnalysisResponse,
    summary="Map to MITRE ATT&CK",
    description="Map activity to MITRE ATT&CK framework.",
)
async def map_to_mitre(request: MITREMapRequest) -> LLMAnalysisResponse:
    """Map activity to MITRE ATT&CK."""
    client = get_llm_client()
    result = await client.map_to_mitre(
        description=request.description,
        findings=request.findings,
    )

    return LLMAnalysisResponse(
        response_id=result.response_id,
        content=result.content,
        structured_data=result.structured_data,
        model=result.model,
        tokens_used=result.tokens_used,
        input_tokens=getattr(result, 'input_tokens', 0),
        output_tokens=getattr(result, 'output_tokens', 0),
        processing_time_ms=result.processing_time_ms,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/chat",
    response_model=LLMAnalysisResponse,
    summary="Chat with AI",
    description="General cybersecurity chat with conversation history support.",
)
async def chat(request: ChatRequest) -> LLMAnalysisResponse:
    """Chat with the cybersecurity AI assistant."""
    client = get_llm_client()

    if not client.is_available:
        raise HTTPException(
            status_code=503,
            detail="LLM not available. Configure ANTHROPIC_API_KEY.",
        )

    result = await client.chat(
        message=request.message,
        conversation_history=request.conversation_history,
    )

    return LLMAnalysisResponse(
        response_id=result.response_id,
        content=result.content,
        model=result.model,
        tokens_used=result.tokens_used,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        processing_time_ms=result.processing_time_ms,
        success=result.success,
        error=result.error,
    )


@router.post(
    "/stream",
    summary="Stream Analysis",
    description="Stream AI analysis for real-time display.",
)
async def stream_analysis(request: StreamRequest):
    """Stream AI analysis response."""
    client = get_llm_client()

    if not client.is_available:
        raise HTTPException(
            status_code=503,
            detail="LLM not available. Configure ANTHROPIC_API_KEY.",
        )

    async def generate():
        async for chunk in client.stream_analysis(
            prompt=request.prompt,
            system_prompt=request.system_prompt,
        ):
            yield chunk

    return StreamingResponse(
        generate(),
        media_type="text/plain",
    )
