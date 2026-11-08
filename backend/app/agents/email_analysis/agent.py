"""
CyberGuard AI — Email Analysis Agent
============================================================================

Detects phishing/spam/malicious email activity. Inherits ``BaseAgent``
and orchestrates six deterministic rules.

Rules are in ``rules.py``. The agent just:
    - Extracts the email payload from the event
    - Iterates the rules
    - Persists findings via ``self._make_finding()``
    - Isolates per-rule failures

Event payload shape
-------------------
Email events are ingested by the collector with ``event.category=EMAIL``
and a ``raw_payload`` that carries the email content. Expected keys
(extracted from IMAP/webhook payloads by the collector):

    raw_payload = {
        "headers": {
            "From": "Sender Name <sender@example.com>",
            "Reply-To": "...",
            "Return-Path": "...",
            "Subject": "...",
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
            "Received": ["...", "..."]
        },
        "body_text": "...",
        "body_html": "...",
        "urls": ["https://...", ...],   # extracted by collector, or by this agent
        "attachments": [
            {"filename": "invoice.pdf.exe", "mime": "application/octet-stream",
             "size_bytes": 12345, "sha256": "..."}
        ]
    }

The agent does not parse raw RFC 822 — that's the collector's job. If
the collector failed to extract a field, the rule that needs it
returns None (skips). This makes the agent tolerant of partial data.
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.email_analysis.rules import (
    AttachmentAnomalyRule,
    BaseRule,
    PhishingLanguageRule,
    ReplyToMismatchRule,
    SenderImpersonationRule,
    SpoofedAuthRule,
    SuspiciousUrlRule,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger


logger = get_logger(__name__)


class EmailAnalysisAgent(BaseAgent):
    """Detects phishing, spam, and malicious email activity."""

    name = "email_analysis"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._rules = self._build_rules()

    def _build_rules(self) -> list[BaseRule]:
        return [
            SpoofedAuthRule(),
            SuspiciousUrlRule(
                suspicious_tld_score=int(
                    self._config.get("suspicious_tld_score", 40)
                ),
            ),
            AttachmentAnomalyRule(
                max_attachment_size_bytes=int(
                    self._config.get("max_attachment_size_bytes", 26214400)
                ),
            ),
            SenderImpersonationRule(),
            PhishingLanguageRule(),
            ReplyToMismatchRule(),
        ]

    def process(self, context: AgentContext) -> AgentResult:
        """
        Run all email rules against the event.

        If the event isn't an email event at all (shouldn't happen —
        dispatcher gates by category), return empty result.
        """
        start = time.perf_counter()
        findings = []
        errors: list[dict[str, Any]] = []
        rules_run = 0

        # Extract payload once for all rules
        payload = self._extract_payload(context)

        for rule in self._rules:
            rules_run += 1
            try:
                spec = rule.evaluate(context, payload)
                if spec is None:
                    continue
                finding = self._make_finding(context, **spec.as_kwargs())
                findings.append(finding)
            except AgentError as exc:
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.warning(
                    "Email rule failed (expected)",
                    extra={
                        "rule_id": rule.name,
                        "event_id": str(context.event.id),
                        "code": getattr(exc, "code", "AGENT_ERROR"),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.exception(
                    "Email rule failed (unexpected)",
                    extra={
                        "rule_id": rule.name,
                        "event_id": str(context.event.id),
                    },
                )

        duration_ms = int((time.perf_counter() - start) * 1000)

        return AgentResult(
            findings=findings,
            errors=errors,
            metadata={
                "duration_ms": duration_ms,
                "events_examined": 1,
                "rules_run": rules_run,
                "findings_produced": len(findings),
                "payload_complete": bool(payload),
            },
        )

    def _extract_payload(self, context: AgentContext) -> dict[str, Any]:
        """
        Extract the email structure from the event's raw_payload.

        Uses normalized_payload as fallback. If neither has email fields,
        returns a minimal dict with whatever entity fields exist — most
        rules will then skip (they need headers/URLs/attachments to fire).

        Best-effort — malformed payloads become empty dicts, not exceptions.
        """
        raw = context.event.raw_payload or {}
        normalized = context.event.normalized_payload or {}

        payload = dict(normalized) if isinstance(normalized, dict) else {}
        for k, v in (raw.items() if isinstance(raw, dict) else []):
            payload.setdefault(k, v)

        # Augment with entity fields — some rules can fire from these alone
        if context.event.email_address and "from" not in payload:
            payload["from"] = context.event.email_address
        if context.event.domain and "domain" not in payload:
            payload["domain"] = context.event.domain
        if context.event.url and "urls" not in payload:
            payload["urls"] = [context.event.url]

        return payload


__all__ = ["EmailAnalysisAgent"]