"""
CyberGuard AI — Log Analysis Agent
============================================================================

The first concrete agent. Inherits ``BaseAgent`` (File 106) and
implements ``process()`` as a loop over detection rules.

Design
------
The agent is deliberately thin:

    - It holds rules (instantiated once with config from settings)
    - For each event, it iterates rules and calls ``rule.evaluate()``
    - Each rule returns a ``FindingSpec`` (or None)
    - The agent persists findings via ``self._make_finding()``
    - Per-rule failures are isolated — one rule crashing doesn't stop
      the others

The detection logic lives in ``rules.py``. The agent just orchestrates.

Rules instantiated (5, matching the log analysis use cases):
    1. ``log.failed_login_burst``       — repeated failed logins
    2. ``log.privilege_escalation``     — sudo, role changes, setuid
    3. ``log.account_modification``     — user created/deleted/modified
    4. ``log.suspicious_file_access``   — sensitive file access
    5. ``log.unusual_login``            — successful login from new IP

The agent runs all 5 rules against every applicable event. Each rule
independently decides whether the event is relevant (most rules will
return None for most events — the cost is a field check).

Config (from ``settings`` in the runtime, File 108)
---------------------------------------------------
    failed_login_threshold: int (default 5)
    failed_login_window_minutes: int (default 10)
    privilege_escalation_enabled: bool (default True)
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.log_analysis.rules import (
    AccountModificationRule,
    BaseRule,
    FailedLoginBurstRule,
    PrivilegeEscalationRule,
    SuspiciousFileAccessRule,
    UnusualLoginRule,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger


logger = get_logger(__name__)


class LogAnalysisAgent(BaseAgent):
    """
    Detects suspicious activity in OS/application/database logs.
    """

    name = "log_analysis"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._rules = self._build_rules()

    def _build_rules(self) -> list[BaseRule]:
        """
        Construct the rule instances from config.

        Config keys (from ``_build_log_agent_config`` in runtime.py):

            failed_login_threshold      (default 5)
            failed_login_window_minutes (default 10)
            privilege_escalation_enabled (default True)
        """
        return [
            FailedLoginBurstRule(
                threshold=int(self._config.get("failed_login_threshold", 5)),
                window_minutes=int(
                    self._config.get("failed_login_window_minutes", 10)
                ),
            ),
            PrivilegeEscalationRule(
                enabled=bool(
                    self._config.get("privilege_escalation_enabled", True)
                ),
            ),
            AccountModificationRule(),
            SuspiciousFileAccessRule(),
            UnusualLoginRule(),
        ]

    def process(self, context: AgentContext) -> AgentResult:
        """
        Run all rules against the event, produce findings.

        Rules that don't apply return None (fast path). Rules that
        raise are caught and recorded in ``errors`` — the loop
        continues.

        Never raises. Never commits. Findings are persisted via
        ``_make_finding`` (which flushes) and committed by the runtime.
        """
        start = time.perf_counter()
        findings = []
        errors: list[dict[str, Any]] = []
        rules_run = 0

        for rule in self._rules:
            rules_run += 1
            try:
                spec = rule.evaluate(context)
                if spec is None:
                    continue

                finding = self._make_finding(context, **spec.as_kwargs())
                findings.append(finding)

            except AgentError as exc:
                # Expected rule failure — log and continue
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.warning(
                    "Rule failed (expected)",
                    extra={
                        "rule_id": rule.name,
                        "event_id": str(context.event.id),
                        "code": getattr(exc, "code", "AGENT_ERROR"),
                    },
                )
            except Exception as exc:  # noqa: BLE001 — isolate per-rule failures
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.exception(
                    "Rule failed (unexpected)",
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
            },
        )


__all__ = ["LogAnalysisAgent"]