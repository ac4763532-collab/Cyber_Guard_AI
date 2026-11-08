"""
CyberGuard AI — IOC Correlation Rules
============================================================================

The correlation logic: given the current event's IOCs, find recent
findings whose primary event shares indicators with the seed. When
enough indicators overlap across enough findings, produce a
correlated-activity finding.

Algorithm
---------
1. Extract IOCs from the current event (seed set).
   If empty → return None (nothing to correlate).

2. Query recent findings in the same workspace, excluding
   ioc_correlation's own findings (avoid self-correlation):
       - workspace_id = current event's workspace
       - first_seen_at >= (event_time - time_window_minutes)
       - agent_name != "ioc_correlation"
       - limit 50

3. For each candidate finding, extract IOCs from its primary event.

4. Compute overlap: candidate_iocs ∩ seed_iocs.

5. Track:
       - matched_findings: list of (finding, overlap_set)
       - shared_iocs: union of all overlap sets

6. Fire if:
       - len(shared_iocs) >= min_indicators (default 2), AND
       - len(matched_findings) >= 2 (or >= 1 plus a currently-produced
         finding for this event — the current event may not yet have
         its own finding, so this is a heuristic threshold)

The min_indicators threshold prevents correlating findings that share
only ONE indicator. Example: two findings about the same user "alice"
might not represent the same attack — alice could be doing unrelated
things. But two findings sharing alice AND 203.0.113.42 → almost
certainly one attack.

Output
------
A single finding:
    agent_name   = "ioc_correlation"
    rule_id      = "ioc_correlation.correlated_activity"
    severity     = HIGH (aggregation of the contributing findings)
    category     = CORRELATED_ACTIVITY
    dedup_hint   = sorted shared IOCs (top 5)
    event_ids    = the contributing findings' primary event ids + this event
    evidence     = contributing findings, agents, shared indicators, time range

The HIGH severity is intentional — a coordinated attack warrants
attention even if each individual component finding was MEDIUM.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from app.agents.base import AgentContext
from app.core.logging import get_logger
from app.models.enums import (
    EventSeverity,
    FindingCategory,
    FindingStatus,
)
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding


logger = get_logger(__name__)


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


class BaseRule:
    name: str = ""

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        raise NotImplementedError


# ============================================================================
# IOC EXTRACTION
# ============================================================================

#: Fields on the SecurityEvent model that carry IOCs.
_EVENT_IOC_FIELDS = (
    "source_ip",
    "destination_ip",
    "domain",
    "url",
    "hash_md5",
    "hash_sha256",
    "username",
    "hostname",
    "email_address",
)

#: Keys inside a finding's ``evidence`` JSONB where agents commonly
#: place additional IOCs (lists of usernames, IPs, etc.).
_EVIDENCE_IOC_KEYS = (
    "source_ip",
    "source_ips",
    "ips",
    "username",
    "usernames",
    "domain",
    "domains",
    "url",
    "urls",
    "hash_sha256",
    "hashes",
    "hostname",
    "hostnames",
)


def _extract_iocs_from_event(event: SecurityEvent | None) -> set[str]:
    """
    Return all IOC values present on an event, normalized.

    Normalization: strip + lowercase. This means "203.0.113.42" and
    "203.0.113.42 " are treated the same, "Alice" and "alice" match,
    "EVIL.COM" and "evil.com" match.
    """
    if event is None:
        return set()
    iocs: set[str] = set()
    for field in _EVENT_IOC_FIELDS:
        v = getattr(event, field, None)
        if v and isinstance(v, str):
            normalized = v.strip().lower()
            if normalized:
                iocs.add(normalized)
    return iocs


def _extract_iocs_from_evidence(evidence: dict | None) -> set[str]:
    """
    Return additional IOCs from a finding's evidence dict.

    Agents use the evidence JSONB to store IOCs they found but that
    aren't on the primary event (e.g. "the email had 3 URLs" or "the
    port scan targeted 20 ports"). This catches those.
    """
    if not evidence or not isinstance(evidence, dict):
        return set()
    iocs: set[str] = set()
    for key in _EVIDENCE_IOC_KEYS:
        v = evidence.get(key)
        if isinstance(v, str):
            normalized = v.strip().lower()
            if normalized:
                iocs.add(normalized)
        elif isinstance(v, list):
            for item in v[:10]:  # cap to prevent payload amplification
                if isinstance(item, str):
                    normalized = item.strip().lower()
                    if normalized:
                        iocs.add(normalized)
    return iocs


def _extract_iocs_from_finding(
    finding: AgentFinding,
    db,
) -> set[str]:
    """
    Return IOCs referenced by a finding: from its primary event AND
    from its evidence JSONB.
    """
    iocs: set[str] = set()

    # From primary event
    if finding.primary_event_id:
        event = db.get(SecurityEvent, finding.primary_event_id)
        iocs |= _extract_iocs_from_event(event)

    # From evidence
    iocs |= _extract_iocs_from_evidence(finding.evidence)

    return iocs


# ============================================================================
# CORRELATED ACTIVITY RULE
# ============================================================================

class CorrelatedActivityRule(BaseRule):
    """
    Fires when the current event's IOCs overlap with 2+ recent findings
    by 2+ distinct indicators.

    See module docstring for the algorithm.
    """
    name = "ioc_correlation.correlated_activity"

    _MAX_CANDIDATE_FINDINGS = 50
    _MAX_IOCS_TO_REPORT = 10
    _MAX_FINDINGS_IN_EVIDENCE = 20

    def __init__(
        self,
        time_window_minutes: int = 30,
        min_indicators: int = 2,
    ) -> None:
        self._window_minutes = max(1, time_window_minutes)
        self._min_indicators = max(2, min_indicators)

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        # ── Seed: the current event's IOCs
        seed_iocs = _extract_iocs_from_event(context.event)
        if not seed_iocs:
            return None

        # ── Candidates: recent findings in this workspace
        cutoff = context.event.event_time - timedelta(
            minutes=self._window_minutes
        )

        candidate_stmt = (
            select(AgentFinding)
            .where(
                AgentFinding.workspace_id == context.workspace_id,
                AgentFinding.first_seen_at >= cutoff,
                AgentFinding.agent_name != "ioc_correlation",
                AgentFinding.status.notin_(
                    (
                        FindingStatus.DISMISSED.value,
                        FindingStatus.FALSE_POSITIVE.value,
                    )
                ),
            )
            .order_by(AgentFinding.first_seen_at.desc())
            .limit(self._MAX_CANDIDATE_FINDINGS)
        )

        candidates = list(context.db.execute(candidate_stmt).scalars().all())
        if not candidates:
            return None

        # ── Match: findings sharing IOCs with the seed
        matched: list[tuple[AgentFinding, set[str]]] = []
        shared_iocs: set[str] = set()

        for cand in candidates:
            cand_iocs = _extract_iocs_from_finding(cand, context.db)
            overlap = cand_iocs & seed_iocs
            if not overlap:
                continue
            matched.append((cand, overlap))
            shared_iocs |= overlap

        # ── Gate: need enough distinct shared IOCs
        if len(shared_iocs) < self._min_indicators:
            return None

        # ── Gate: need enough findings. The current event may or may
        # not have its own finding yet. If it has 0 matched findings
        # but shares IOCs with the seed, we can't correlate anything.
        #
        # Threshold: 2+ matched findings OR (1 finding + multi-IOC overlap).
        # The latter case catches "one prior finding shares 2 indicators
        # with this event" — still a strong signal.
        if len(matched) < 2 and not (
            len(matched) == 1 and len(shared_iocs) >= self._min_indicators
        ):
            return None

        # ── Build the finding
        return self._build_finding(context, seed_iocs, matched, shared_iocs)

    def _build_finding(
        self,
        context: AgentContext,
        seed_iocs: set[str],
        matched: list[tuple[AgentFinding, set[str]]],
        shared_iocs: set[str],
    ) -> FindingSpec:
        """Build the correlated-activity FindingSpec."""
        contributing_findings = [f for f, _ in matched]

        # Aggregate MITRE techniques from contributing findings
        mitre_set: set[str] = set()
        for f in contributing_findings:
            for tech in (f.mitre_techniques or []):
                mitre_set.add(tech)

        # Aggregate agent names (deduplicated)
        agent_names = sorted({f.agent_name for f in contributing_findings})

        # Categories represented (deduplicated)
        category_values = sorted(
            {f.category.value for f in contributing_findings}
        )

        # Time range
        times = [f.first_seen_at for f in contributing_findings]
        if times:
            earliest = min(times)
            latest = max(times)
        else:
            earliest = context.event.event_time
            latest = context.event.event_time

        # Event IDs — union of contributing findings' primary events + the current event
        event_ids: list[uuid.UUID] = [context.event.id]
        for f in contributing_findings:
            if f.primary_event_id and f.primary_event_id not in event_ids:
                event_ids.append(f.primary_event_id)

        # Sort IOCs for a stable dedup hint. Cap to prevent giant hints.
        sorted_iocs = sorted(shared_iocs)
        dedup_hint = "|".join(sorted_iocs[:5])[:200]

        # Confidence: base on number of findings, shared IOCs, and diversity
        # of agent sources. Three different agents agreeing on 3 IOCs is
        # much stronger than two findings from the same agent.
        diversity_bonus = min(0.10, 0.03 * (len(agent_names) - 1))
        finding_bonus = min(0.10, 0.02 * (len(matched) - 1))
        ioc_bonus = min(0.10, 0.02 * (len(shared_iocs) - self._min_indicators))
        confidence = min(
            0.98,
            0.70 + diversity_bonus + finding_bonus + ioc_bonus,
        )

        # Description
        desc = (
            f"{len(matched)} finding(s) share {len(shared_iocs)} indicator(s) "
            f"from {len(agent_names)} agent(s): {', '.join(agent_names)}. "
            f"This pattern often indicates a coordinated attack spanning "
            f"multiple channels."
        )

        # Evidence
        evidence: dict[str, Any] = {
            "shared_indicators": sorted_iocs[: self._MAX_IOCS_TO_REPORT],
            "shared_indicator_count": len(shared_iocs),
            "contributing_finding_count": len(contributing_findings),
            "contributing_finding_ids": [
                str(f.id) for f in contributing_findings[: self._MAX_FINDINGS_IN_EVIDENCE]
            ],
            "contributing_agent_names": agent_names,
            "contributing_categories": category_values,
            "time_range": {
                "earliest": earliest.isoformat(),
                "latest": latest.isoformat(),
                "window_minutes": self._window_minutes,
            },
            "current_event_id": str(context.event.id),
        }

        title = (
            f"Correlated activity: {len(matched)} findings share "
            f"{len(shared_iocs)} indicators"
        )

        return FindingSpec(
            rule_id=self.name,
            title=title,
            severity=EventSeverity.HIGH,
            category=FindingCategory.CORRELATED_ACTIVITY,
            confidence=confidence,
            event_ids=event_ids,
            primary_event_id=context.event.id,
            evidence=evidence,
            description=desc,
            mitre_techniques=sorted(mitre_set)[:20],
            tags=["correlation", "cross_source"] + agent_names[:5],
            dedup_hint=dedup_hint,
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FindingSpec",
    "BaseRule",
    "CorrelatedActivityRule",
]