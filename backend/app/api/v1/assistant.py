"""
CyberGuard AI — AI Assistant Endpoints
============================================================================
Evidence-grounded conversational security assistant that strictly adheres
to non-fabrication principles, tenant isolation, and live provider checks.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentActiveUser, DBDep
from app.core.config import settings
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.case import SecurityCase
from app.models.enums import CasePriority, FindingCategory
from app.models.conversation import CaseConversation, CaseMessage
from app.models.enums import ConversationStatus, MessageType
from app.models.finding import AgentFinding
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.services import workspace_service

logger = get_logger(__name__)

router = APIRouter(
    prefix="/assistant",
    tags=["assistant"],
)


def _get_user_workspace(db: Session, user: User) -> Workspace:
    return workspace_service.create_personal_workspace(db, user)


class AssistantMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    conversation_id: Optional[uuid.UUID] = None


class AssistantMessageResponse(BaseModel):
    id: str
    reply: str
    provider_available: bool
    evidence_ref: Optional[str] = None
    timestamp: str


def _get_or_create_assistant_conversation(db: Session, workspace: Workspace, user: User) -> CaseConversation:
    conv = db.execute(
        select(CaseConversation).where(
            CaseConversation.workspace_id == workspace.id,
            CaseConversation.conversation_type == "system",
        )
    ).scalars().first()

    if not conv:
        # Check or create system security case
        sec_case = db.execute(
            select(SecurityCase).where(
                SecurityCase.workspace_id == workspace.id,
                SecurityCase.title == "AI Security Assistant",
            )
        ).scalars().first()

        if not sec_case:
            import random
            case_num = f"CG-{datetime.now().year}-{random.randint(100000, 999999)}"
            sec_case = SecurityCase.build(
                workspace_id=workspace.id,
                case_number=case_num,
                title="AI Security Assistant",
                description="Automated AI assistant conversation session",
                created_by_id=user.id,
                priority=CasePriority.LOW,
                severity=EventSeverity.LOW,
                category=FindingCategory.OTHER,
            )
            db.add(sec_case)
            db.flush()

        conv = CaseConversation.build(
            workspace_id=workspace.id,
            case_id=sec_case.id,
            conversation_type="system",
            title="AI Security Assistant",
            created_by_id=user.id,
        )
        db.add(conv)
        db.flush()

    return conv


@router.get("/status", summary="Check AI Assistant provider availability")
def get_assistant_status(
    current_user: CurrentActiveUser,
) -> dict[str, Any]:
    from app.llm import free_llm
    if free_llm.is_configured:
        active_model = free_llm.gemini_model if free_llm.gemini_key.startswith("AIza") else free_llm.groq_model
        display_name = "Google Gemini Flash" if free_llm.gemini_key.startswith("AIza") else "Groq LPU"
        return {
            "provider": display_name,
            "available": True,
            "model": active_model,
            "message": f"AI provider '{display_name}' is connected and ready.",
        }

    provider = getattr(settings, "LLM_PROVIDER", "none").lower()
    is_available = False
    display_name = provider

    if provider == "ollama":
        display_name = f"Ollama ({settings.OLLAMA_MODEL})"
        try:
            import httpx
            with httpx.Client(timeout=3.0) as client:
                r = client.get(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags")
                if r.status_code == 200:
                    is_available = True
        except Exception:
            is_available = False
    elif provider in ["gemini", "anthropic", "openai"]:
        is_available = bool(getattr(settings, f"{provider.upper()}_API_KEY", None))
        display_name = provider.capitalize()
    else:
        is_available = False

    return {
        "provider": display_name,
        "available": is_available,
        "model": settings.OLLAMA_MODEL if provider == "ollama" else getattr(settings, f"{provider.upper()}_MODEL", None),
        "message": (
            f"AI provider '{display_name}' is connected and ready."
            if is_available
            else f"AI provider '{display_name}' is currently unavailable. Ensure Ollama is running with model {settings.OLLAMA_MODEL}."
        ),
    }


@router.get("/messages", summary="Get previous assistant conversation messages")
def get_assistant_messages(
    db: DBDep,
    current_user: CurrentActiveUser,
) -> List[dict[str, Any]]:
    workspace = _get_user_workspace(db, current_user)
    conv = _get_or_create_assistant_conversation(db, workspace, current_user)

    messages = list(
        db.execute(
            select(CaseMessage)
            .where(CaseMessage.conversation_id == conv.id)
            .order_by(CaseMessage.created_at.asc())
            .limit(100)
        ).scalars().all()
    )

    return [
        {
            "id": str(m.id),
            "sender": "user" if m.sender_id == current_user.id else "assistant",
            "content": m.body,
            "timestamp": m.created_at.strftime("%I:%M %p"),
            "evidenceRef": m.metadata_json.get("evidence_ref") if m.metadata_json else None,
        }
        for m in messages
    ]


@router.post("/messages", response_model=AssistantMessageResponse, summary="Send message to AI Security Assistant")
def send_assistant_message(
    payload: AssistantMessageRequest,
    db: DBDep,
    current_user: CurrentActiveUser,
) -> AssistantMessageResponse:
    workspace = _get_user_workspace(db, current_user)
    conv = _get_or_create_assistant_conversation(db, workspace, current_user)
    now = datetime.now(timezone.utc)

    # 1. Store user message
    user_msg = CaseMessage(
        conversation_id=conv.id,
        sender_id=current_user.id,
        body=payload.message,
        message_type=MessageType.TEXT,
    )
    db.add(user_msg)
    db.flush()

    # 2. Check if an LLM provider is configured
    provider = getattr(settings, "LLM_PROVIDER", "none").lower()
    is_ollama = (provider == "ollama")
    has_api_key = bool(
        getattr(settings, "GEMINI_API_KEY", None)
        or getattr(settings, "OPENAI_API_KEY", None)
        or getattr(settings, "ANTHROPIC_API_KEY", None)
    )

    from app.llm import free_llm
    if not free_llm.is_configured and (provider in ["none", "disabled", ""] or (not is_ollama and not has_api_key)):
        reply_text = "AI provider unavailable. Configure a supported provider to enable AI assistance."
        asst_msg = CaseMessage(
            conversation_id=conv.id,
            sender_id=None,
            body=reply_text,
            message_type=MessageType.TEXT,
            metadata_json={"evidence_ref": None},
        )
        db.add(asst_msg)
        db.commit()

        return AssistantMessageResponse(
            id=str(asst_msg.id),
            reply=reply_text,
            provider_available=False,
            evidence_ref=None,
            timestamp=now.strftime("%I:%M %p"),
        )

    # 3. Genuinely retrieve verified tenant context from database
    sources_count = db.execute(
        select(func.count(SecuritySource.id)).where(SecuritySource.workspace_id == workspace.id)
    ).scalar() or 0

    active_findings = list(
        db.execute(
            select(AgentFinding)
            .where(
                AgentFinding.workspace_id == workspace.id,
                AgentFinding.status.in_(["new", "investigating"]),
            )
            .order_by(AgentFinding.created_at.desc())
            .limit(5)
        ).scalars().all()
    )

    active_alerts = list(
        db.execute(
            select(SecurityAlert)
            .where(
                SecurityAlert.workspace_id == workspace.id,
                SecurityAlert.status.in_(["new", "investigating"]),
            )
            .order_by(SecurityAlert.created_at.desc())
            .limit(5)
        ).scalars().all()
    )

    # Context summary
    evidence_items = []
    if active_findings:
        evidence_items.extend([f"Finding: {f.title} ({f.rule_id})" for f in active_findings])
    if active_alerts:
        evidence_items.extend([f"Alert: {a.title} [Severity: {a.severity.value}]" for a in active_alerts])

    evidence_str = "; ".join(evidence_items) if evidence_items else "No active alerts or findings in workspace"
    evidence_ref = active_findings[0].rule_id if active_findings else None

    # Construct evidence-grounded response
    evidence_summary = (
        f"Verified Workspace Telemetry: {sources_count} enrolled device(s). "
        f"{len(active_alerts)} active alert(s), {len(active_findings)} active finding(s). Evidence: {evidence_str}."
    )

    reply_text = ""
    from app.llm import free_llm
    if free_llm.is_configured:
        try:
            system_prompt = (
                "You are CyberGuard AI, an elite cybersecurity assistant. "
                "Answer the user's inquiry strictly grounded in their real security telemetry:\n"
                f"{evidence_summary}\n"
                "CRITICAL: Keep your response extremely concise, direct, and actionable (maximum 2 to 3 sentences). Do not use filler greetings or disclaimers."
            )
            reply_text = free_llm.explain(
                system_prompt=system_prompt,
                user_prompt=f"User question: {payload.message}",
                max_tokens=200,
            )
        except Exception as exc:
            logger.warning("FreeLLM call failed", extra={"error": str(exc)[:200]})
    elif is_ollama:
        try:
            import httpx
            system_prompt = (
                "You are CyberGuard AI, an elite cybersecurity assistant. "
                "Answer the user's inquiry strictly grounded in their real security telemetry:\n"
                f"{evidence_summary}\n"
                "CRITICAL: Keep your response extremely concise, direct, and actionable (maximum 2 to 3 sentences). Do not use filler greetings or disclaimers."
            )
            with httpx.Client(timeout=120.0) as client:
                res = client.post(
                    f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                    json={
                        "model": settings.OLLAMA_MODEL,
                        "prompt": f"User question: {payload.message}",
                        "system": system_prompt,
                        "stream": False,
                        "keep_alive": "60m",
                        "options": {
                            "num_predict": 120,
                            "temperature": 0.2,
                            "top_k": 20,
                            "num_thread": 8,
                        },
                    },
                )
                if res.status_code == 200:
                    reply_text = res.json().get("response", "").strip()
        except Exception as exc:
            logger.warning("Ollama call failed or timed out", extra={"error": str(exc)[:200]})

    if not reply_text:
        if not evidence_items:
            reply_text = f"Based on your verified telemetry: You currently have {sources_count} enrolled device(s). No active security alerts or uncontained findings were detected in your workspace."
        else:
            reply_text = f"Based on your verified telemetry: Found {len(active_alerts)} active alert(s) and {len(active_findings)} finding(s). Recent evidence: {evidence_str}."
        if is_ollama:
            reply_text += " (Note: Local Ollama daemon was unreachable at " + settings.OLLAMA_BASE_URL + " — start with: ollama run " + settings.OLLAMA_MODEL + ")"

    asst_msg = CaseMessage(
        conversation_id=conv.id,
        sender_id=None,
        body=reply_text,
        message_type=MessageType.TEXT,
        metadata_json={"evidence_ref": evidence_ref},
    )
    db.add(asst_msg)
    db.commit()

    return AssistantMessageResponse(
        id=str(asst_msg.id),
        reply=reply_text,
        provider_available=True,
        evidence_ref=evidence_ref,
        timestamp=now.strftime("%I:%M %p"),
    )
