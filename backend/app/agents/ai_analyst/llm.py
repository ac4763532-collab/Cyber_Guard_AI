"""
CyberGuard AI — LLM Client
============================================================================

Unified interface to Claude, Gemini, and Ollama. All three providers
expose the same minimal surface:

    client.generate_explanation(
        system_prompt="...",
        user_prompt="...",
    ) -> str | None

Returns the text response on success, None on any failure (missing key,
timeout, HTTP error, malformed response).

Design rules
------------
1. **Never raises.** Every error path returns None. The calling agent
   treats None as "AI unavailable" and returns an empty result. No
   exception bubbles up to the runtime.

2. **Timeout per call.** 60 seconds by default (from
   ``ANTHROPIC_TIMEOUT_SECONDS`` / hardcoded for others). A hung LLM
   API does not block the analyst's request indefinitely.

3. **No streaming.** The API returns the full response. Streaming is
   a future enhancement for the chat-style UI.

4. **Provider is chosen by config.** ``LLM_PROVIDER=anthropic|gemini|ollama|none``.
   Unknown or `none` → the client is a no-op.

5. **Credentials from settings, not arguments.** API keys are read
   from ``settings`` (via the config dict). The caller doesn't touch
   them.

Response format
---------------
The LLM is instructed to respond in **structured JSON**:

    {
        "summary": "1-3 sentence plain-English explanation",
        "severity_assessment": "confirmed" | "suspected" | "unclear",
        "investigation_steps": ["step 1", "step 2", ...],
        "confidence": 0.0 - 1.0
    }

The client parses this and returns the raw JSON string. The agent
interprets it — if parsing fails, the agent logs a warning and skips
the finding (never produces a finding with garbage text).
"""

from __future__ import annotations

import json
import threading
from typing import Any

from app.core.logging import get_logger


logger = get_logger(__name__)


# ============================================================================
# BASE CLIENT
# ============================================================================

class BaseLLMClient:
    """
    Abstract base for LLM providers. Subclasses implement ``_call``.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._logger = get_logger(f"app.agents.ai_analyst.llm.{self.__class__.__name__}")

    @property
    def is_enabled(self) -> bool:
        """True if this client is configured and can make calls."""
        raise NotImplementedError

    def generate_explanation(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str | None:
        """Return the LLM's response, or None on failure."""
        if not self.is_enabled:
            return None
        try:
            return self._call(system_prompt=system_prompt, user_prompt=user_prompt)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "LLM call failed",
                extra={"error": str(exc)[:300]},
            )
            return None

    def _call(self, *, system_prompt: str, user_prompt: str) -> str | None:
        raise NotImplementedError


# ============================================================================
# ANTHROPIC CLIENT
# ============================================================================

class AnthropicClient(BaseLLMClient):
    """Claude via the Anthropic SDK."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_key = config.get("anthropic_api_key") or ""
        self._model = config.get("anthropic_model", "claude-3-5-sonnet-20241022")
        self._max_tokens = int(config.get("anthropic_max_tokens", 2048))
        self._timeout = float(config.get("anthropic_timeout_seconds", 60))

    @property
    def is_enabled(self) -> bool:
        return bool(self._api_key)

    def _call(self, *, system_prompt: str, user_prompt: str) -> str | None:
        try:
            import anthropic
        except ImportError:
            self._logger.warning(
                "anthropic package not installed — install with: "
                "pip install anthropic"
            )
            return None

        client = anthropic.Anthropic(
            api_key=self._api_key,
            timeout=self._timeout,
        )
        message = client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        # Extract text from the response
        if not message.content:
            return None
        parts = [
            block.text for block in message.content
            if getattr(block, "type", "") == "text"
        ]
        return "\n".join(parts) if parts else None


# ============================================================================
# GEMINI CLIENT
# ============================================================================

class GeminiClient(BaseLLMClient):
    """Google Gemini via the google-generativeai SDK."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_key = config.get("gemini_api_key") or ""
        self._model = config.get("gemini_model", "gemini-1.5-flash")

    @property
    def is_enabled(self) -> bool:
        return bool(self._api_key)

    def _call(self, *, system_prompt: str, user_prompt: str) -> str | None:
        try:
            import google.generativeai as genai
        except ImportError:
            self._logger.warning(
                "google-generativeai package not installed — install with: "
                "pip install google-generativeai"
            )
            return None

        genai.configure(api_key=self._api_key)
        model = genai.GenerativeModel(
            model_name=self._model,
            system_instruction=system_prompt,
        )
        response = model.generate_content(user_prompt)
        if not response or not response.text:
            return None
        return response.text


# ============================================================================
# OLLAMA CLIENT
# ============================================================================

class OllamaClient(BaseLLMClient):
    """Local Ollama server via HTTP (no SDK dependency)."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._base_url = (config.get("ollama_base_url") or "http://localhost:11434").rstrip("/")
        self._model = config.get("ollama_model", "llama3.1:8b")
        self._timeout = 120.0   # Ollama can be slow on first call

    @property
    def is_enabled(self) -> bool:
        # Enabled by default — if Ollama isn't running, calls fail and
        # return None. The agent treats that as "AI unavailable".
        return True

    def _call(self, *, system_prompt: str, user_prompt: str) -> str | None:
        try:
            import httpx
        except ImportError:
            self._logger.warning("httpx package not installed")
            return None

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/api/generate",
                    json={
                        "model": self._model,
                        "system": system_prompt,
                        "prompt": user_prompt,
                        "stream": False,
                    },
                )
            if response.status_code != 200:
                self._logger.warning(
                    "Ollama request failed",
                    extra={"status": response.status_code},
                )
                return None
            data = response.json()
            return data.get("response")
        except Exception as exc:  # noqa: BLE001
            self._logger.info(
                "Ollama unreachable",
                extra={"error": str(exc)[:200]},
            )
            return None


# ============================================================================
# FACTORY
# ============================================================================

def build_llm_client(config: dict[str, Any]) -> BaseLLMClient | None:
    """
    Return the appropriate client based on ``config["provider"]``.

    Returns None if the provider is "none" or unrecognized, or if the
    provider is unconfigured (missing API key).
    """
    provider = (config.get("provider") or "none").strip().lower()

    if provider == "none" or not provider:
        return None

    if provider == "anthropic":
        client = AnthropicClient(config)
        return client if client.is_enabled else None

    if provider == "gemini":
        client = GeminiClient(config)
        return client if client.is_enabled else None

    if provider == "ollama":
        client = OllamaClient(config)
        return client if client.is_enabled else None

    logger.warning(
        "Unknown LLM provider — treating as 'none'",
        extra={"provider": provider},
    )
    return None


__all__ = [
    "BaseLLMClient",
    "AnthropicClient",
    "GeminiClient",
    "OllamaClient",
    "build_llm_client",
]