"""
CyberGuard AI — Network Analysis Agent
============================================================================

Detects port scans, C2 beaconing, DNS anomalies, and suspicious outbound
connections in network events.

The agent runs five rules against every network event. Each rule queries
the DB for related network events in a bounded window, evaluates the
pattern, and returns a ``FindingSpec`` or None.

Config (from ``settings`` via runtime)
--------------------------------------
    port_scan_threshold: int       (default 20)
    port_scan_window_seconds: int  (default 60)
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.network_analysis.rules import (
    BaseRule,
    BeaconingRule,
    ConnectionFloodRule,
    DnsAnomalyRule,
    PortScanRule,
    SuspiciousOutboundRule,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger


logger = get_logger(__name__)


class NetworkAnalysisAgent(BaseAgent):
    """Detects port scans, beaconing, DNS anomalies, suspicious outbound."""

    name = "network_analysis"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._rules = self._build_rules()

    def _build_rules(self) -> list[BaseRule]:
        return [
            PortScanRule(
                threshold=int(self._config.get("port_scan_threshold", 20)),
                window_seconds=int(
                    self._config.get("port_scan_window_seconds", 60)
                ),
            ),
            BeaconingRule(),
            DnsAnomalyRule(),
            SuspiciousOutboundRule(),
            ConnectionFloodRule(),
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
            except AgentError as exc:
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.warning(
                    "Network rule failed (expected)",
                    extra={
                        "rule_id": rule.name,
                        "event_id": str(context.event.id),
                        "code": getattr(exc, "code", "AGENT_ERROR"),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(self._wrap_error(stage=rule.name, exception=exc))
                logger.exception(
                    "Network rule failed (unexpected)",
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


__all__ = ["NetworkAnalysisAgent"]