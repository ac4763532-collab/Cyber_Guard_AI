"""
CyberGuard AI — IOC Correlation Agent
============================================================================

Cross-source finding correlation. Runs on the current event's IOCs,
scans recent findings in the workspace, and produces a correlated
finding when a cluster of findings shares enough indicators.

The agent runs a single correlation rule (``CorrelatedActivityRule``)
that encapsulates the whole matching algorithm. Keeping it in
``rules.py`` means the agent is a thin orchestrator, consistent with
every other agent.

Performance
-----------
The agent caps the number of findings it examines per event (50) and
the number of IOCs it considers per finding (10). This bounds the
worst-case cost to ~500 set-intersection operations per event —
sub-millisecond in practice.

The 30-minute time window (from ``IOC_CORRELATION_TIME_WINDOW_MINUTES``)
prevents correlating findings from yesterday with findings from today.

Config (from settings via runtime)
----------------------------------
    time_window_minutes: int       (default 30)
    min_indicators: int            (default 2)
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.ioc_correlation.rules import (
    BaseRule,
    CorrelatedActivityRule,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger


logger = get_logger(__name__)


class IocCorrelationAgent(BaseAgent):
    """Correlates findings across agents when they share IOCs."""

    name = "ioc_correlation"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._rules = self._build_rules()

    def _build_rules(self) -> list[BaseRule]:
        return [
            CorrelatedActivityRule(
                time_window_minutes=int(
                    self._config.get("time_window_minutes", 30)
                ),
                min_indicators=int(self._config.get("min_indicators", 2)),
            ),
        ]

    def process(self, context: AgentContext) -> AgentResult:
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

                logger.info(
                    "Correlation finding produced",
                    extra={
                        "finding_id": str(finding.id),
                        "event_id": str(context.event.id),
                        "workspace_id": str(context.workspace_id),
                        "contributing_findings": spec.evidence.get(
                            "contributing_finding_count", 0
                        ),
                        "shared_indicators": len(
                            spec.evidence.get("shared_indicators", [])
                        ),
                    },
                )

            except AgentError as exc:
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.warning(
                    "Correlation rule failed (expected)",
                    extra={
                        "rule_id": rule.name,
                        "event_id": str(context.event.id),
                        "code": getattr(exc, "code", "AGENT_ERROR"),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.exception(
                    "Correlation rule failed (unexpected)",
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


__all__ = ["IocCorrelationAgent"]