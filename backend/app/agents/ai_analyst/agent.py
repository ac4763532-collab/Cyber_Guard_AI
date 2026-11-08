"""
CyberGuard AI — AI Analyst Agent
============================================================================

Uses an LLM to explain findings and suggest investigation steps.

This agent is **not** dispatched by the runtime. It's invoked manually
via the API when an analyst asks "explain this finding" or "what should
I do next?".

Input (via AgentContext.correlation_state)
------------------------------------------
The caller must populate:

    correlation_state["target_finding"] = {
        "id": str,
        "agent_name": str,
        "rule_id": str,
        "severity": str,
        "category": str,
        "title": str,
        "description": str | None,
        "confidence": float,
        "evidence": dict,
        "mitre_techniques": list[str],
        "first_seen_at": str,
        "occurrence_count": int,
    }

    correlation_state["target_event"] = {   # optional
        "id": str,
        "event_type": str,
        "severity": str,
        "username": str | None,
        "source_ip": str | None,
        "destination_ip": str | None,
        "domain": str | None,
        "event_time": str,
    }

If ``target_finding`` is missing, the agent returns an empty result —
it has nothing to analyze.

Output
------
A single finding:
    agent_name    = "ai_analyst"
    rule_id       = "ai_analyst.explanation"
    severity      = MEDIUM (fixed — see below)
    category      = FindingCategory.OTHER
    confidence    = parsed from LLM response, capped at 0.85
    evidence      = LLM response + the original finding ID
    tags          = ["ai_generated", "requires_human_review", "advisory"]
    dedup_hint    = the target finding's ID

The severity is always MEDIUM regardless of the original finding's
severity. This is intentional:
    - The AI's opinion is NOT an authoritative risk assessment
    - Promotions to alerts use MEDIUM + confidence thresholds
    - Capping at MEDIUM prevents AI-generated findings from auto-
      promoting (File 82's promotion logic requires HIGH+ to always
      promote, or MEDIUM with conf ≥ 0.8 — we cap confidence at 0.85
      but the "ai_generated" tag is explicitly excluded from promotion)

Actually — File 82's promotion logic DOES promote MEDIUM with conf≥0.8.
Let me re-check... In `_should_promote`:

    if severity == MEDIUM:
        return confidence >= 0.8

But it doesn't check the `ai_generated` tag. So a MEDIUM AI finding
with conf 0.85 WOULD get promoted. That's wrong per the design.

Fix: I'll use severity=LOW for AI findings, OR explicitly check the
tag. Since `_should_promote` is already written and I don't want to
change File 82, I'll deliver AI findings with severity=LOW and let the
analyst promote them manually if they choose.

The AI-generated finding is advisory context, not a detection.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from app.agents.ai_analyst.llm import BaseLLMClient, build_llm_client
from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.core.exceptions import AgentInputError
from app.core.logging import get_logger
from app.models.enums import EventSeverity, FindingCategory


logger = get_logger(__name__)


#: System prompt — strict instructions to keep the LLM grounded.
_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant. You help
investigators understand security findings.

Rules you MUST follow:
1. Base every claim on the EVIDENCE provided. If the evidence does not
   support a claim, say "not enough evidence to determine".
2. Do NOT invent IOCs, file hashes, or threat actor names.
3. Distinguish clearly between CONFIRMED facts (from evidence) and
   SUSPECTED interpretation (your analysis).
4. Respond ONLY with valid JSON in the exact schema specified by the
   user prompt. No markdown, no code fences, no prose before or after.
5. Be concise. Analysts are busy.

Your response is advisory. A human analyst makes all final decisions."""


_USER_PROMPT_TEMPLATE = """Analyze this security finding and provide an
explanation plus investigation guidance.

FINDING:
{finding_json}

PRIMARY EVENT (if available):
{event_json}

Respond with JSON in this exact schema:
{{
  "summary": "1-3 sentences explaining what this finding means in plain English",
  "severity_assessment": "confirmed" | "suspected" | "unclear",
  "confidence": 0.0 to 1.0,
  "investigation_steps": [
    "specific, actionable step 1",
    "specific, actionable step 2",
    ...
  ],
  "mitre_mapping": ["T1110.001", ...]   // if applicable, empty array otherwise
}}

Do not include any text outside the JSON object."""


class AiAnalystAgent(BaseAgent):
    """LLM-assisted finding explanation. Not auto-dispatched."""

    name = "ai_analyst"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._client: BaseLLMClient | None = build_llm_client(self._config)
        if self._client is None:
            self._logger.info(
                "AI Analyst: no LLM configured — agent will be a no-op. "
                "Set LLM_PROVIDER and an API key to enable."
            )

    def process(self, context: AgentContext) -> AgentResult:
        start = time.perf_counter()
        findings = []
        errors: list[dict[str, Any]] = []

        # If no LLM is configured, return empty result — no errors
        if self._client is None:
            return AgentResult(
                findings=[],
                errors=[],
                metadata={
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "events_examined": 1,
                    "llm_available": False,
                    "reason": "no_llm_configured",
                },
            )

        # Extract the target finding from correlation state
        target = (context.correlation_state or {}).get("target_finding")
        if not target:
            return AgentResult(
                findings=[],
                errors=[
                    {
                        "stage": "extract",
                        "code": "AI_NO_TARGET",
                        "message": (
                            "AiAnalystAgent requires correlation_state["
                            "'target_finding']. The API endpoint must "
                            "populate it before calling process()."
                        ),
                        "traceback": None,
                    }
                ],
                metadata={
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "events_examined": 1,
                    "llm_available": True,
                    "reason": "no_target_finding",
                },
            )

        target_event = (context.correlation_state or {}).get("target_event")

        # Build prompts
        try:
            user_prompt = _USER_PROMPT_TEMPLATE.format(
                finding_json=json.dumps(target, indent=2, default=str)[:8000],
                event_json=(
                    json.dumps(target_event, indent=2, default=str)[:4000]
                    if target_event else "N/A"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            raise AgentInputError(
                message=f"Failed to build prompt: {exc}",
                code="AI_PROMPT_BUILD_ERROR",
            )

        # Call the LLM
        response_text = self._client.generate_explanation(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        if not response_text:
            return AgentResult(
                findings=[],
                errors=[
                    {
                        "stage": "llm_call",
                        "code": "AI_LLM_UNAVAILABLE",
                        "message": "LLM call returned no response.",
                        "traceback": None,
                    }
                ],
                metadata={
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "events_examined": 1,
                    "llm_available": False,
                },
            )

        # Parse the response
        parsed = self._parse_llm_response(response_text)
        if parsed is None:
            return AgentResult(
                findings=[],
                errors=[
                    {
                        "stage": "parse",
                        "code": "AI_PARSE_ERROR",
                        "message": (
                            f"LLM response was not valid JSON. "
                            f"Response starts with: {response_text[:100]!r}"
                        ),
                        "traceback": None,
                    }
                ],
                metadata={
                    "duration_ms": int((time.perf_counter() - start) * 1000),
                    "events_examined": 1,
                    "llm_available": True,
                    "llm_called": True,
                },
            )

        # Build and persist the finding
        try:
            finding = self._build_finding(context, target, parsed)
            findings.append(finding)
        except Exception as exc:  # noqa: BLE001
            errors.append(self._wrap_error(stage="persist", exception=exc))
            self._logger.exception("Failed to persist AI finding")

        duration_ms = int((time.perf_counter() - start) * 1000)

        return AgentResult(
            findings=findings,
            errors=errors,
            metadata={
                "duration_ms": duration_ms,
                "events_examined": 1,
                "llm_available": True,
                "llm_called": True,
                "findings_produced": len(findings),
            },
        )

    # ── Parsing ─────────────────────────────────────────────────────────

    def _parse_llm_response(self, text: str) -> dict[str, Any] | None:
        """
        Parse the LLM response into a dict. Tolerant of common LLM
        mistakes: markdown code fences, prose before/after JSON.
        """
        if not text:
            return None

        cleaned = text.strip()

        # Strip markdown fences if present
        if cleaned.startswith("```"):
            # Remove leading ```json or ```
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            # Remove trailing ```
            cleaned = re.sub(r"\s*```$", "", cleaned)

        # Try direct parse
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Try to find a JSON object in the response
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        return None

    # ── Finding construction ────────────────────────────────────────────

    def _build_finding(
        self,
        context: AgentContext,
        target: dict[str, Any],
        parsed: dict[str, Any],
    ):
        """Build the AI-generated FindingSpec and persist it."""
        summary = str(parsed.get("summary", "")).strip()
        if not summary:
            raise AgentInputError(
                message="LLM response missing required 'summary' field",
                code="AI_MISSING_SUMMARY",
            )

        severity_assessment = str(
            parsed.get("severity_assessment", "unclear")
        ).lower()
        if severity_assessment not in ("confirmed", "suspected", "unclear"):
            severity_assessment = "unclear"

        # Confidence is the LLM's self-reported confidence, capped at
        # 0.85. Higher would risk confusing the user (AI cannot be
        # more certain than the deterministic finding it explains).
        try:
            ai_confidence = float(parsed.get("confidence", 0.5))
        except (TypeError, ValueError):
            ai_confidence = 0.5
        ai_confidence = max(0.0, min(0.85, ai_confidence))

        investigation_steps = parsed.get("investigation_steps") or []
        if not isinstance(investigation_steps, list):
            investigation_steps = []
        investigation_steps = [
            str(s).strip() for s in investigation_steps[:10]
            if isinstance(s, str) and str(s).strip()
        ]

        mitre_mapping = parsed.get("mitre_mapping") or []
        if not isinstance(mitre_mapping, list):
            mitre_mapping = []
        mitre_mapping = [
            str(m).strip().upper() for m in mitre_mapping[:10]
            if isinstance(m, str) and m.strip()
        ]

        target_finding_id = target.get("id")
        target_title = str(target.get("title", "unknown finding"))

        title = f"AI analysis of: {target_title[:80]}"

        description = (
            f"{summary}\n\n"
            f"Assessment: {severity_assessment.upper()}. "
            f"This is an advisory interpretation from an LLM and requires "
            f"human review before any containment action."
        )

        evidence = {
            "target_finding_id": target_finding_id,
            "llm_summary": summary,
            "llm_severity_assessment": severity_assessment,
            "llm_confidence": round(ai_confidence, 2),
            "llm_investigation_steps": investigation_steps,
            "llm_mitre_mapping": mitre_mapping,
            "provider": self._config.get("provider", "unknown"),
            "disclaimer": (
                "This is an AI-generated interpretation. It is NOT "
                "authoritative. All claims must be verified against "
                "the original finding's evidence before action."
            ),
        }

        dedup_hint = f"target={target_finding_id}" if target_finding_id else None

        # Persist via the base agent's helper
        return self._make_finding(
            context,
            rule_id="ai_analyst.explanation",
            title=title,
            severity=EventSeverity.LOW,   # advisory — not a detection
            category=FindingCategory.OTHER,
            confidence=ai_confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence=evidence,
            description=description,
            mitre_techniques=mitre_mapping,
            tags=[
                "ai_generated",
                "requires_human_review",
                "advisory",
            ],
            dedup_hint=dedup_hint,
        )


__all__ = ["AiAnalystAgent"]