"""
CyberGuard AI — Event Explanation Endpoint
============================================================================
Provides sub-second, zero-cost plain-English security explanations
using Gemini Flash primary and Groq fallback.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Header, HTTPException, status

from app.api.deps import CurrentUser, DBDep
from app.llm import free_llm
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(
    tags=["explain"],
)


class ExplainRequest(BaseModel):
    event_summary: str = Field(..., description="Summary of the security event or command line.")
    detection_label: Optional[str] = Field("SUSPICIOUS", description="ML or detection label: BENIGN, SUSPICIOUS, MALICIOUS, MINER.")
    confidence: Optional[float] = Field(0.9, ge=0.0, le=1.0, description="Detection confidence score.")
    entity: Optional[str] = Field(None, description="Host, user, or IP address involved.")


class ExplainResponse(BaseModel):
    status: str = "ok"
    explanation: str
    detection_label: str
    confidence: float
    provider: str


@router.post(
    "/explain",
    response_model=ExplainResponse,
    summary="Generate plain-English explanation for a security event",
)
def explain_event(
    body: ExplainRequest,
) -> ExplainResponse:
    """
    Sub-second security event explainer using FreeLLM (Gemini + Groq).
    Outputs ordinary, non-technical plain English explanations.
    """
    system_prompt = (
        "You are CyberGuard AI, an elite security analyst explaining events to ordinary computer users and SOC analysts. "
        "Explain what happened in clear, plain English (2 to 3 sentences maximum). "
        "State why it matters and what immediate action is recommended. Avoid unnecessary filler or greetings."
    )

    user_prompt = (
        f"Security Event: {body.event_summary}\n"
        f"Classification: {body.detection_label} (Confidence: {int(body.confidence * 100)}%)\n"
        f"Involved Entity: {body.entity or 'Unknown'}\n\n"
        "Explain this event in plain English:"
    )

    explanation = free_llm.explain(system_prompt=system_prompt, user_prompt=user_prompt)

    provider_name = "gemini-flash" if free_llm.gemini_key.startswith("AIza") else "groq-qwen"

    return ExplainResponse(
        status="ok",
        explanation=explanation,
        detection_label=body.detection_label or "SUSPICIOUS",
        confidence=body.confidence or 0.9,
        provider=provider_name,
    )
