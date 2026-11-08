"""
CyberGuard AI — Threat Intelligence Verdict Rules
============================================================================

Five verdict rules that combine multi-provider results into a single
finding per IOC.

Each rule receives:
    - the AgentContext
    - the IOC value (e.g. "203.0.113.42")
    - a list of ``ProviderResult`` from all providers that responded

The rule decides whether the aggregate signal warrants a finding, and
if so, what severity/confidence to assign.

Verdict thresholds
------------------
For IP/domain/URL/hash:
    - 1 provider says malicious with confidence ≥ 0.85 AND score ≥ 70 → MEDIUM
    - 1 provider says malicious (score 50-70)                        → skip (weak)
    - 2 providers say malicious                                       → HIGH
    - 3+ providers say malicious                                      → HIGH (confidence 0.95)

For CVE:
    - NVD says CVSS ≥ 7.0                                             → HIGH
    - NVD says CVSS 4.0-6.9                                           → MEDIUM
    - NVD says CVSS < 4.0                                             → skip

Severity is capped at HIGH for all threat-intel findings. CRITICAL is
reserved for direct evidence (e.g. suspicious activity observed on
the network) — threat-intel enrichment is corroborating context, not
the primary signal.

Deduplication
-------------
Every rule uses a stable dedup_hint tied to the IOC value:
    ip=203.0.113.42
    domain=evil.example.com
    url=https://evil.example.com/payload
    hash=a1b2c3...
    cve=CVE-2024-1234

An IP that appears in 100 events merges into ONE finding with
occurrence_count=100. This is the correct UX — the user sees
"1 alert: malicious IP seen 100 times", not "100 alerts".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.agents.base import AgentContext
from app.agents.threat_intelligence.providers.base import ProviderResult
from app.models.enums import EventSeverity, FindingCategory


# ============================================================================
# FINDING SPEC
# ============================================================================

@dataclass(frozen=True)
class FindingSpec:
    rule_id: str
    title: str
    severity: EventSeverity
    category: FindingCategory
    confidence: float
    event_ids: list[uuid.UUID]
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str | None = None
    primary_event_id: uuid.UUID | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    dedup_hint: str | None = None

    def as_kwargs(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
            "event_ids": self.event_ids,
            "evidence": self.evidence,
            "description": self.description,
            "primary_event_id": self.primary_event_id,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "dedup_hint": self.dedup_hint,
        }


# ============================================================================
# BASE VERDICT RULE
# ============================================================================

class BaseVerdictRule:
    """
    Verdict rules take a list of ProviderResults and decide whether
    to fire a finding. Not the same signature as the ``BaseRule`` in
    other agents — the IOC is already extracted by the agent, and the
    provider results are the input, not the event.
    """
    name: str = ""

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        raise NotImplementedError


# ============================================================================
# SHARED VERDICT LOGIC
# ============================================================================

def _aggregate_verdict(
    provider_results: list[ProviderResult],
) -> tuple[int, int, float, list[ProviderResult]]:
    """
    Aggregate provider verdicts.

    Returns
    -------
    (malicious_count, max_score, max_confidence, malicious_providers)
    """
    malicious_providers = [r for r in provider_results if r.malicious]
    malicious_count = len(malicious_providers)
    max_score = max((r.score for r in malicious_providers), default=0)
    max_confidence = max((r.confidence for r in malicious_providers), default=0.0)
    return malicious_count, max_score, max_confidence, malicious_providers


def _should_fire(
    malicious_count: int,
    max_score: int,
    max_confidence: float,
) -> bool:
    """
    Decide whether the aggregate signal is strong enough to fire.

    - 2+ providers say malicious → always fire
    - 1 provider says malicious with high confidence (≥0.85) and
      score (≥70) → fire
    - Otherwise → not strong enough
    """
    if malicious_count >= 2:
        return True
    if malicious_count == 1 and max_confidence >= 0.85 and max_score >= 70:
        return True
    return False


def _severity_for(
    malicious_count: int,
    max_score: int,
) -> EventSeverity:
    """
    Severity based on provider consensus and score.
    """
    if malicious_count >= 2:
        return EventSeverity.HIGH
    if max_score >= 85:
        return EventSeverity.HIGH
    return EventSeverity.MEDIUM


def _confidence_for(
    malicious_count: int,
    max_confidence: float,
) -> float:
    if malicious_count >= 3:
        return 0.95
    if malicious_count == 2:
        return 0.90
    return max(0.75, max_confidence)


def _build_evidence(
    ioc_value: str,
    ioc_label: str,
    provider_results: list[ProviderResult],
) -> dict[str, Any]:
    """Compact evidence dict summarizing all provider responses."""
    return {
        ioc_label: ioc_value,
        "providers_queried": len(provider_results),
        "providers_flagged": sum(1 for r in provider_results if r.malicious),
        "provider_details": [
            r.to_evidence_dict() for r in provider_results
        ],
    }


# ============================================================================
# RULE 1 — Malicious IP
# ============================================================================

class MaliciousIpRule(BaseVerdictRule):
    """
    Fires when an IP is flagged as malicious by threat intel.

    Sources: VirusTotal, AbuseIPDB.
    Dedup: one finding per IP address.

    MITRE: T1071 (Application Layer Protocol) — the IP is a C2 endpoint
    """
    name = "threat_intel.malicious_ip"

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        malicious_count, max_score, max_confidence, malicious_providers = _aggregate_verdict(
            provider_results,
        )
        if not _should_fire(malicious_count, max_score, max_confidence):
            return None

        provider_names = [r.provider for r in malicious_providers]
        severity = _severity_for(malicious_count, max_score)
        confidence = _confidence_for(malicious_count, max_confidence)

        return FindingSpec(
            rule_id=self.name,
            title=f"Malicious IP: {ioc_value}",
            severity=severity,
            category=FindingCategory.THREAT_INTEL_HIT,
            confidence=confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence=_build_evidence(ioc_value, "ip", provider_results),
            description=(
                f"IP address {ioc_value} flagged by "
                f"{malicious_count} provider(s): {', '.join(provider_names)}."
            ),
            mitre_techniques=["T1071"],
            tags=["threat_intel", "malicious_ip"],
            dedup_hint=f"ip={ioc_value}",
        )


# ============================================================================
# RULE 2 — Malicious Domain
# ============================================================================

class MaliciousDomainRule(BaseVerdictRule):
    """
    Fires when a domain is flagged as malicious.

    Sources: VirusTotal.
    Dedup: one finding per domain.

    MITRE: T1583.001 (Acquire Infrastructure: Domains)
    """
    name = "threat_intel.malicious_domain"

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        malicious_count, max_score, max_confidence, malicious_providers = _aggregate_verdict(
            provider_results,
        )
        if not _should_fire(malicious_count, max_score, max_confidence):
            return None

        provider_names = [r.provider for r in malicious_providers]
        severity = _severity_for(malicious_count, max_score)
        confidence = _confidence_for(malicious_count, max_confidence)

        return FindingSpec(
            rule_id=self.name,
            title=f"Malicious domain: {ioc_value}",
            severity=severity,
            category=FindingCategory.THREAT_INTEL_HIT,
            confidence=confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence=_build_evidence(ioc_value, "domain", provider_results),
            description=(
                f"Domain {ioc_value} flagged by "
                f"{malicious_count} provider(s): {', '.join(provider_names)}."
            ),
            mitre_techniques=["T1583.001"],
            tags=["threat_intel", "malicious_domain"],
            dedup_hint=f"domain={ioc_value}",
        )


# ============================================================================
# RULE 3 — Malicious URL
# ============================================================================

class MaliciousUrlRule(BaseVerdictRule):
    """
    Fires when a URL is flagged as malicious.

    Sources: URLhaus, VirusTotal.
    Dedup: one finding per URL.

    MITRE: T1566.002 (Phishing: Spearphishing Link), T1204.001
    """
    name = "threat_intel.malicious_url"

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        malicious_count, max_score, max_confidence, malicious_providers = _aggregate_verdict(
            provider_results,
        )
        if not _should_fire(malicious_count, max_score, max_confidence):
            return None

        provider_names = [r.provider for r in malicious_providers]
        severity = _severity_for(malicious_count, max_score)
        confidence = _confidence_for(malicious_count, max_confidence)

        return FindingSpec(
            rule_id=self.name,
            title=f"Malicious URL: {ioc_value[:80]}",
            severity=severity,
            category=FindingCategory.THREAT_INTEL_HIT,
            confidence=confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence=_build_evidence(ioc_value, "url", provider_results),
            description=(
                f"URL flagged by {malicious_count} provider(s): "
                f"{', '.join(provider_names)}."
            ),
            mitre_techniques=["T1566.002", "T1204.001"],
            tags=["threat_intel", "malicious_url"],
            dedup_hint=f"url={ioc_value}",
        )


# ============================================================================
# RULE 4 — Malicious File Hash
# ============================================================================

class MaliciousHashRule(BaseVerdictRule):
    """
    Fires when a file hash is flagged as malicious.

    Sources: VirusTotal.
    Dedup: one finding per hash.

    MITRE: T1204.002 (Malicious File), T1105 (Ingress Tool Transfer)
    """
    name = "threat_intel.malicious_hash"

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        malicious_count, max_score, max_confidence, malicious_providers = _aggregate_verdict(
            provider_results,
        )
        if not _should_fire(malicious_count, max_score, max_confidence):
            return None

        provider_names = [r.provider for r in malicious_providers]
        severity = _severity_for(malicious_count, max_score)
        confidence = _confidence_for(malicious_count, max_confidence)

        return FindingSpec(
            rule_id=self.name,
            title=f"Malicious file hash: {ioc_value[:16]}...",
            severity=severity,
            category=FindingCategory.MALWARE,
            confidence=confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence=_build_evidence(ioc_value, "hash", provider_results),
            description=(
                f"File hash {ioc_value} flagged by "
                f"{malicious_count} provider(s): {', '.join(provider_names)}."
            ),
            mitre_techniques=["T1204.002", "T1105"],
            tags=["threat_intel", "malicious_hash", "malware"],
            dedup_hint=f"hash={ioc_value}",
        )


# ============================================================================
# RULE 5 — Known CVE (with CVSS assessment)
# ============================================================================

class KnownCveRule(BaseVerdictRule):
    """
    Fires when an event references a CVE that NVD scores as HIGH or
    CRITICAL. High-CVSS CVEs in your environment are active threats —
    even if no exploit has been observed yet, they warrant patching
    attention.

    Source: NVD only.
    Dedup: one finding per CVE.

    MITRE: T1190 (Exploit Public-Facing Application)
    """
    name = "threat_intel.known_cve"

    def evaluate(
        self,
        context: AgentContext,
        ioc_value: str,
        provider_results: list[ProviderResult],
    ) -> FindingSpec | None:
        # Look for the NVD result specifically
        nvd_result: ProviderResult | None = None
        for r in provider_results:
            if r.provider == "nvd":
                nvd_result = r
                break

        if nvd_result is None:
            return None

        cvss_score = None
        severity_label = None
        if nvd_result.raw:
            cvss_score = nvd_result.raw.get("cvss_score")
            severity_label = nvd_result.raw.get("severity_label")

        # Rule logic
        if nvd_result.score >= 80:  # CVSS >= 7.0
            severity = EventSeverity.HIGH
            confidence = 0.95
        elif nvd_result.score >= 50:  # CVSS 4.0-6.9
            severity = EventSeverity.MEDIUM
            confidence = 0.90
        else:
            return None  # CVSS < 4.0 — informational, not worth a finding

        description = nvd_result.details
        if nvd_result.raw and nvd_result.raw.get("description"):
            description = f"{nvd_result.details}. {nvd_result.raw['description']}"

        return FindingSpec(
            rule_id=self.name,
            title=f"{severity_label or 'Elevated'} CVE: {ioc_value}",
            severity=severity,
            category=FindingCategory.OTHER,
            confidence=confidence,
            event_ids=[context.event.id],
            primary_event_id=context.event.id,
            evidence={
                "cve_id": ioc_value,
                "cvss_score": cvss_score,
                "severity_label": severity_label,
                "cwe_ids": (nvd_result.raw or {}).get("cwe_ids", []),
                "cvss_vector": (nvd_result.raw or {}).get("cvss_vector"),
            },
            description=description,
            mitre_techniques=["T1190"],
            tags=["threat_intel", "cve", severity_label.lower() if severity_label else "unknown"],
            dedup_hint=f"cve={ioc_value}",
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FindingSpec",
    "BaseVerdictRule",
    "MaliciousIpRule",
    "MaliciousDomainRule",
    "MaliciousUrlRule",
    "MaliciousHashRule",
    "KnownCveRule",
]