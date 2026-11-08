"""
CyberGuard AI — AI Analyst Agent Package

The 6th of 8 agents. Where the platform uses an LLM to help a human
analyst investigate a finding.

Trust model (from the project handover)
---------------------------------------
    "LLMs must assist the detection and investigation system, not
     replace deterministic detection logic or verified evidence."

This means:
    - The AI Analyst is NEVER dispatched automatically by the runtime.
      It runs only when an analyst clicks "Ask AI" in the UI, which
      calls the API endpoint that triggers this agent.
    - Its output is a FindingCategory.OTHER finding tagged
      `ai_generated`. The alert promotion logic (File 82) does NOT
      auto-promote OTHER-category findings — a human must review.
    - Every AI explanation cites the evidence it used. If the evidence
      is insufficient, the AI says so, it does not hallucinate.
    - The LLM is optional. With ``LLM_PROVIDER=none`` (the default),
      this agent is disabled and returns empty results.

Providers supported
-------------------
    anthropic — Claude (claude-3-5-sonnet, claude-3-haiku, ...)
    gemini    — Google Gemini (gemini-1.5-flash, gemini-1.5-pro)
    ollama    — Local LLMs (llama3.1, mistral, ...) via Ollama server
    none      — disabled (the default; no external calls)

Invocation
----------
Unlike the other 7 agents, this one is not triggered by the dispatcher
(File 107). It's invoked from:
    - ``POST /api/v1/ai-analyst/explain`` — analyst asks AI to explain
      a specific finding
    - ``POST /api/v1/ai-analyst/investigate`` — analyst asks AI for
      investigation steps on a case

The API endpoint builds an ``AgentContext`` with:
    - ``correlation_state["target_finding"]`` = serialized finding data
    - ``correlation_state["target_event"]``   = serialized primary event
    - ``config`` = LLM provider settings

Then calls ``AiAnalystAgent().process(context)``.

Public API:
    from app.agents.ai_analyst import AiAnalystAgent
"""

from app.agents.ai_analyst.agent import AiAnalystAgent

__all__ = ["AiAnalystAgent"]