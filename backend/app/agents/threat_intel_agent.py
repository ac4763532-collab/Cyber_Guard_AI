"""
CyberGuard AI - Threat Intelligence Agent

Thin BaseAgent wrapper around the existing ThreatIntelService (VirusTotal +
AbuseIPDB) so IOC lookups can be dispatched through TaskDispatcher like any
other agent. This agent does not implement any provider logic itself - it
only calls ThreatIntelService.lookup()/lookup_batch() and maps the result
onto the shared AgentResult/Finding contract.

Classification mapping (see ThreatIntelService.ReputationStatus for the
authoritative policy):
    MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN, LOOKUP_FAILED

AgentResult.classification is set to the exact ReputationStatus value
(lowercase string) - never upgraded, downgraded, or re-derived here. In
particular LOOKUP_FAILED and UNKNOWN are never reported as CLEAN; a
Finding is only created for MALICIOUS/SUSPICIOUS results, since CLEAN/
UNKNOWN/LOOKUP_FAILED do not represent a confirmed threat worth recording
as a finding.
"""

from typing import Any

from app.agents.base import AgentResult, AgentType, BaseAgent, Finding, Severity
from app.services.threat_intel.service import (
    IOCType,
    ReputationStatus,
    ThreatIntelResult,
    get_threat_intel_service,
    normalize_ioc_value,
)


# Map IOCType -> AgentResult.severity. Only MALICIOUS/SUSPICIOUS reach the
# HIGH/MEDIUM tiers; everything else is INFO, since there is no confirmed
# threat to escalate.
_REPUTATION_TO_SEVERITY = {
    ReputationStatus.MALICIOUS: Severity.HIGH,
    ReputationStatus.SUSPICIOUS: Severity.MEDIUM,
    ReputationStatus.CLEAN: Severity.INFO,
    ReputationStatus.UNKNOWN: Severity.INFO,
    ReputationStatus.LOOKUP_FAILED: Severity.INFO,
}

_VALID_IOC_TYPES = {t.value for t in IOCType}


class ThreatIntelAgent(BaseAgent):
    """Dispatchable agent for IOC threat-intelligence enrichment."""

    agent_type = AgentType.THREAT_INTEL
    agent_name = "Threat Intelligence Agent"
    agent_version = "1.0.0"

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        ioc_type = data.get("ioc_type")
        ioc_value = data.get("ioc_value")

        if not ioc_type or ioc_type not in _VALID_IOC_TYPES:
            return False, f"ioc_type must be one of: {', '.join(sorted(_VALID_IOC_TYPES))}"

        if not ioc_value or not isinstance(ioc_value, str) or not ioc_value.strip():
            return False, "ioc_value is required and must be a non-empty string"

        try:
            normalize_ioc_value(IOCType(ioc_type), ioc_value)
        except ValueError as exc:
            return False, str(exc)

        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        ioc_type = IOCType(data["ioc_type"])
        ioc_value = data["ioc_value"].strip()

        service = get_threat_intel_service()
        result = await service.lookup(ioc_type, ioc_value)

        return self._result_to_agent_result(result)

    async def analyze_batch(self, iocs: list[tuple[IOCType, str]]) -> list[AgentResult]:
        """Look up multiple IOCs in parallel, reusing the service's own
        batching (which runs the individual lookups concurrently)."""
        service = get_threat_intel_service()
        results = await service.lookup_batch(iocs)
        return [self._result_to_agent_result(r) for r in results]

    def _result_to_agent_result(self, result: ThreatIntelResult) -> AgentResult:
        severity = _REPUTATION_TO_SEVERITY.get(result.reputation_status, Severity.INFO)

        # Per-provider evidence must survive regardless of classification -
        # a CLEAN/UNKNOWN/LOOKUP_FAILED result still ran (or attempted to
        # run) real provider calls, and the API layer needs that evidence to
        # back whatever classification_reason sentence it renders. This is
        # therefore on AgentResult.metadata (always present), not gated
        # behind Finding creation below (which stays reserved for confirmed
        # threats worth recording as findings).
        provider_outcomes_dump = [o.model_dump() for o in result.provider_outcomes]

        findings: list[Finding] = []
        if result.reputation_status in (ReputationStatus.MALICIOUS, ReputationStatus.SUSPICIOUS):
            findings.append(
                Finding(
                    name=f"{result.reputation_status.value.capitalize()} indicator: {result.ioc_type.value}",
                    description=result.classification_reason,
                    severity=severity,
                    confidence=(result.risk_score or 0) / 100.0,
                    evidence=[
                        f"{o.name}: {o.status.value}"
                        + (f" (detections={o.detections})" if o.detections is not None else "")
                        + (f" (confidence_score={o.confidence_score})" if o.confidence_score is not None else "")
                        for o in result.provider_outcomes
                    ],
                    metadata={
                        "ioc_type": result.ioc_type.value,
                        "ioc_value": result.ioc_value,
                        "sources": result.sources,
                        "provider_outcomes": provider_outcomes_dump,
                    },
                )
            )

        return AgentResult(
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            classification=result.reputation_status.value,
            metadata={
                "ioc_type": result.ioc_type.value,
                "ioc_value": result.ioc_value,
                "sources": result.sources,
                "provider_outcomes": provider_outcomes_dump,
            },
            severity=severity,
            confidence=(result.risk_score or 0) / 100.0 if result.risk_score is not None else 0.0,
            risk_score=result.risk_score or 0,
            findings=findings,
            indicators=[result.ioc_value],
            summary=result.classification_reason,
            recommendations=self._recommendations_for(result),
            success=result.reputation_status != ReputationStatus.LOOKUP_FAILED,
            error=result.error,
            data_source="threat_intel_service",
            scan_warnings=(
                [f"{o.name} did not complete: {o.detail or o.status.value}"
                 for o in result.provider_outcomes if o.status.value != "success"]
            ),
        )

    @staticmethod
    def _recommendations_for(result: ThreatIntelResult) -> list[str]:
        if result.reputation_status == ReputationStatus.MALICIOUS:
            return ["Treat this indicator as confirmed malicious.", "Review related events and findings for this indicator."]
        if result.reputation_status == ReputationStatus.SUSPICIOUS:
            return ["Investigate further before taking action - evidence is suggestive, not conclusive."]
        if result.reputation_status == ReputationStatus.LOOKUP_FAILED:
            return ["Retry the lookup later - one or more providers could not complete the check."]
        if result.reputation_status == ReputationStatus.UNKNOWN:
            return ["No provider is configured for this indicator type - no evidence is available."]
        return []
