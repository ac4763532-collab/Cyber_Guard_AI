"""
CyberGuard AI — Zero-Cost Cloud LLM Client
============================================================================
Unified, resilient, dual-provider client for sub-second security explanations
and AI Assistant responses at $0/month.

Architecture:
  - Primary: Google Gemini (gemini-flash-lite-latest via free tier: ~1,500 req/day)
  - Fallback: Groq (Ultra-fast LPU inference via free tier: ~1,000 req/day)
  - Seamless automatic failover with graceful degradation.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)


class FreeLLMClient:
    """
    High-performance zero-cost LLM client utilizing Gemini + Groq.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        groq_api_key: Optional[str] = None,
        gemini_model: str = "gemini-1.5-flash",
        groq_model: str = "openai/gpt-oss-20b",
        timeout: float = 20.0,
    ):
        self.gemini_key = (gemini_api_key or os.getenv("GEMINI_API_KEY", "")).strip().strip('"').strip("'")
        self.groq_key = (groq_api_key or os.getenv("GROQ_API_KEY", "")).strip().strip('"').strip("'")
        self.gemini_model = os.getenv("GEMINI_MODEL", gemini_model)
        self.groq_model = os.getenv("GROQ_MODEL", groq_model)
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        """True if at least one cloud provider has a valid API key configured."""
        has_gemini = bool(self.gemini_key and self.gemini_key.startswith("AIza"))
        has_groq = bool(self.groq_key and self.groq_key.startswith("gsk_"))
        return has_gemini or has_groq

    def explain(self, system_prompt: str, user_prompt: str, max_tokens: int = 600) -> str:
        """
        Produce a concise, grounded security explanation.
        Tries Gemini first (if valid key), falls back to Groq automatically.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return self.chat(messages, max_tokens=max_tokens)

    def chat(self, messages: List[Dict[str, str]], max_tokens: int = 600, temperature: float = 0.2) -> str:
        """
        Executes chat completion with automatic failover across providers.
        """
        # 1. Try Gemini Primary (only if key is real Google AI Studio key)
        if self.gemini_key and self.gemini_key.startswith("AIza"):
            try:
                res = self._call_gemini(messages, max_tokens, temperature)
                if res and not res.startswith("[AI analysis"):
                    return res
            except Exception as exc:
                logger.warning("Gemini primary call failed, triggering Groq fallback", extra={"error": str(exc)[:200]})

        # 2. Try Groq Fallback (ultra-fast LPU)
        if self.groq_key and self.groq_key.startswith("gsk_"):
            try:
                res = self._call_groq(messages, max_tokens, temperature)
                if res and not res.startswith("[AI analysis"):
                    return res
            except Exception as exc:
                logger.error("Groq fallback call failed", extra={"error": str(exc)[:200]})

        return ""

        # 3. Graceful degradation
        return (
            "[AI analysis temporarily unavailable. Live detection engines and security monitoring continue running normally.]"
        )

    def _call_gemini(self, messages: List[Dict[str, str]], max_tokens: int, temperature: float) -> Optional[str]:
        """Call Google Gemini using native REST endpoint with x-goog-api-key."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.gemini_key,
        }

        # Convert chat messages to Gemini contents structure
        contents = []
        system_instruction = None

        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                system_instruction = {"parts": [{"text": content}]}
            elif role == "assistant":
                contents.append({"role": "model", "parts": [{"text": content}]})
            else:
                contents.append({"role": "user", "parts": [{"text": content}]})

        if not contents:
            contents.append({"role": "user", "parts": [{"text": "Hello"}]})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"].strip()
            logger.warning("Gemini API non-200 response", extra={"status": resp.status_code, "text": resp.text[:200]})
            return None

    def _call_groq(self, messages: List[Dict[str, str]], max_tokens: int, temperature: float) -> Optional[str]:
        """Call Groq using their ultra-fast OpenAI-compatible endpoint with automatic model fallback."""
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.groq_key}",
        }
        candidate_models = [self.groq_model, "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
        # Deduplicate while preserving order
        seen_models = set()
        ordered_models = []
        for m in candidate_models:
            if m and m not in seen_models:
                seen_models.add(m)
                ordered_models.append(m)

        with httpx.Client(timeout=self.timeout) as client:
            for model_name in ordered_models:
                try:
                    payload = {
                        "model": model_name,
                        "messages": messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    }
                    resp = client.post(url, headers=headers, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if choices and "message" in choices[0]:
                            return choices[0]["message"]["content"].strip()
                    logger.warning("Groq API non-200 response", extra={"model": model_name, "status": resp.status_code, "text": resp.text[:200]})
                except Exception as exc:
                    logger.warning("Groq model attempt failed", extra={"model": model_name, "error": str(exc)[:200]})

            return None


# Global singleton instance
free_llm = FreeLLMClient()
