"""
CyberGuard AI - Correlation Engine

Cross-domain threat correlation for connecting related security events
across email, log, and network domains.

Correlation is based on:
1. Common IOCs (IPs, domains, hashes)
2. Temporal proximity
3. User/asset overlap
4. Attack pattern matching (MITRE ATT&CK chains)
"""

from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4
from enum import Enum

from pydantic import BaseModel, Field
import structlog

from app.agents.base import AgentResult, Finding


logger = structlog.get_logger(__name__)


class CorrelationType(str, Enum):
    """Types of correlation relationships."""
    IOC_MATCH = "ioc_match"           # Same IOC in multiple events
    TEMPORAL = "temporal"              # Events in close time proximity
    USER = "user"                      # Same user involved
    ASSET = "asset"                    # Same asset involved
    ATTACK_CHAIN = "attack_chain"      # MITRE ATT&CK sequence
    CAMPAIGN = "campaign"              # Part of same attack campaign


class CorrelationStrength(str, Enum):
    """Strength of correlation."""
    STRONG = "strong"      # High confidence link
    MODERATE = "moderate"  # Likely related
    WEAK = "weak"          # Possibly related


class Correlation(BaseModel):
    """A correlation link between two events."""

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    source_event_id: str
    target_event_id: str
    correlation_type: CorrelationType
    strength: CorrelationStrength
    evidence: list[str] = Field(default_factory=list)
    score: float = 0.0  # 0-1 confidence
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelatedGroup(BaseModel):
    """A group of correlated events forming a potential incident."""

    group_id: str = Field(default_factory=lambda: str(uuid4()))
    event_ids: list[str] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)

    # Aggregated info
    domains: list[str] = Field(default_factory=list)  # email, log, network
    risk_score: int = 0
    severity: str = "info"

    # Common indicators
    shared_iocs: list[dict[str, Any]] = Field(default_factory=list)
    shared_users: list[str] = Field(default_factory=list)
    shared_assets: list[str] = Field(default_factory=list)

    # MITRE mapping
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    potential_attack_chain: list[str] = Field(default_factory=list)

    # Metadata
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelationResult(BaseModel):
    """Result of correlation analysis."""

    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Input events
    event_count: int = 0

    # Correlation output
    groups: list[CorrelatedGroup] = Field(default_factory=list)
    total_correlations: int = 0

    # Summary
    cross_domain_groups: int = 0  # Groups spanning multiple domains
    potential_incidents: int = 0  # High-severity groups

    processing_time_ms: float = 0.0


class EventData(BaseModel):
    """Normalized event data for correlation."""

    event_id: str
    domain: str  # email, log, network
    timestamp: datetime

    # IOCs extracted
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)

    # Context
    users: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)

    # Findings
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    severity: str = "info"

    # MITRE
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)


class CorrelationEngine:
    """
    Cross-domain correlation engine.

    Analyzes events from multiple domains (email, log, network) to find
    relationships and group related security events into potential incidents.

    Correlation methods:
    1. IOC-based: Common IPs, domains, hashes across events
    2. Temporal: Events occurring within a time window
    3. User/Asset: Events involving same users or systems
    4. Attack chain: MITRE ATT&CK technique sequences
    """

    def __init__(self):
        self.correlation_window = timedelta(hours=24)  # Default time window
        self.min_correlation_score = 0.3  # Minimum to consider correlated

        # Attack chain patterns (MITRE ATT&CK sequences)
        self.attack_chains = self._load_attack_chains()

        logger.info("CorrelationEngine initialized")

    def _load_attack_chains(self) -> list[dict[str, Any]]:
        """Load known attack chain patterns."""
        return [
            {
                "name": "Phishing to Credential Theft",
                "techniques": ["T1566.001", "T1204", "T1110"],
                "description": "Phishing email → User execution → Credential access",
            },
            {
                "name": "Initial Access to Lateral Movement",
                "techniques": ["T1566", "T1078", "T1021"],
                "description": "Phishing → Valid accounts → Remote services",
            },
            {
                "name": "Reconnaissance to Exploitation",
                "techniques": ["T1595", "T1046", "T1190"],
                "description": "Scanning → Port discovery → Exploit public app",
            },
            {
                "name": "Credential Stuffing Attack",
                "techniques": ["T1110.004", "T1078", "T1136"],
                "description": "Credential stuffing → Valid accounts → Account creation",
            },
        ]

    def correlate(
        self,
        events: list[EventData],
        time_window: timedelta | None = None,
    ) -> CorrelationResult:
        """
        Correlate a list of events.

        Args:
            events: List of normalized events to correlate
            time_window: Custom time window for temporal correlation

        Returns:
            CorrelationResult with groups and links
        """
        start_time = datetime.now(timezone.utc)
        window = time_window or self.correlation_window

        correlations: list[Correlation] = []

        # Time proximity constrains evidence-backed relationships; it is
        # not independently sufficient to link unrelated activity.
        ioc_correlations = self._correlate_by_ioc(events, window)
        correlations.extend(ioc_correlations)

        # Shared user/asset context is meaningful only inside the same
        # configured time window.
        context_correlations = self._correlate_by_context(events, window)
        correlations.extend(context_correlations)

        chain_correlations = self._correlate_by_attack_chain(events, window)
        correlations.extend(chain_correlations)

        # Group correlated events
        groups = self._build_groups(events, correlations)

        # Calculate metrics
        cross_domain = sum(1 for g in groups if len(g.domains) > 1)
        potential_incidents = sum(1 for g in groups if g.severity in ["critical", "high"])

        end_time = datetime.now(timezone.utc)

        result = CorrelationResult(
            event_count=len(events),
            groups=groups,
            total_correlations=len(correlations),
            cross_domain_groups=cross_domain,
            potential_incidents=potential_incidents,
            processing_time_ms=(end_time - start_time).total_seconds() * 1000,
        )

        logger.info(
            "Correlation complete",
            events=len(events),
            correlations=len(correlations),
            groups=len(groups),
            cross_domain=cross_domain,
            potential_incidents=potential_incidents,
        )

        return result

    def correlate_agent_results(
        self,
        results: list[AgentResult],
    ) -> CorrelationResult:
        """
        Correlate results from multiple agents.

        Convenience method that normalizes AgentResult objects
        into EventData for correlation.
        """
        events = []
        for result in results:
            event = self._agent_result_to_event(result)
            events.append(event)

        return self.correlate(events)

    def _agent_result_to_event(self, result: AgentResult) -> EventData:
        """Convert AgentResult to EventData for correlation."""
        # Extract IOCs from findings
        ips = []
        domains = []
        urls = []
        hashes = []
        emails = []
        techniques = []
        tactics = []
        users = []

        for finding in result.findings:
            # Collect MITRE info
            techniques.extend(finding.mitre_techniques)
            tactics.extend(finding.mitre_tactics)

            # Extract IOCs from evidence
            evidence = finding.evidence or {}
            if "ips" in evidence:
                ips.extend(evidence["ips"])
            if "domains" in evidence:
                domains.extend(evidence["domains"])
            if "urls" in evidence:
                urls.extend(evidence["urls"])
            if "source_ip" in evidence:
                ips.append(evidence["source_ip"])
            if "user" in evidence:
                users.append(evidence["user"])

        # Also extract from raw IOCs if present
        for ioc in result.iocs:
            if ioc.get("type") == "ip":
                ips.append(ioc.get("value", ""))
            elif ioc.get("type") == "domain":
                domains.append(ioc.get("value", ""))
            elif ioc.get("type") == "url":
                urls.append(ioc.get("value", ""))

        return EventData(
            event_id=result.analysis_id,
            domain=result.agent_type.value,
            timestamp=result.timestamp,
            ips=list(set(ips)),
            domains=list(set(domains)),
            urls=list(set(urls)),
            hashes=list(set(hashes)),
            emails=list(set(emails)),
            users=list(set(users)),
            findings=result.findings,
            risk_score=result.risk_score,
            severity=result.severity.value if result.severity else "info",
            mitre_techniques=list(set(techniques)),
            mitre_tactics=list(set(tactics)),
        )

    def _correlate_by_ioc(
        self,
        events: list[EventData],
        window: timedelta,
    ) -> list[Correlation]:
        """Find correlations based on shared IOCs."""
        correlations = []

        # Build IOC index
        ioc_index: dict[str, list[str]] = {}  # ioc_value -> [event_ids]

        for event in events:
            for ip in event.ips:
                ioc_index.setdefault(f"ip:{ip.lower()}", []).append(event.event_id)
            for domain in event.domains:
                ioc_index.setdefault(f"domain:{domain.lower()}", []).append(event.event_id)
            for url in event.urls:
                ioc_index.setdefault(f"url:{url}", []).append(event.event_id)
            for h in event.hashes:
                ioc_index.setdefault(f"hash:{h}", []).append(event.event_id)

        # Find shared IOCs
        event_map = {event.event_id: event for event in events}
        for ioc, indexed_ids in ioc_index.items():
            event_ids = list(dict.fromkeys(indexed_ids))
            if len(event_ids) > 1:
                for i, src in enumerate(event_ids):
                    for tgt in event_ids[i+1:]:
                        if not self._within_window(event_map[src], event_map[tgt], window):
                            continue
                        correlations.append(Correlation(
                            source_event_id=src,
                            target_event_id=tgt,
                            correlation_type=CorrelationType.IOC_MATCH,
                            strength=CorrelationStrength.STRONG,
                            evidence=[f"Shared IOC: {ioc}"],
                            score=0.9,
                        ))

        return correlations

    def _correlate_by_context(
        self,
        events: list[EventData],
        window: timedelta,
    ) -> list[Correlation]:
        """Find correlations based on shared users/assets."""
        correlations = []

        # Build user index
        user_index: dict[str, list[str]] = {}
        asset_index: dict[str, list[str]] = {}

        for event in events:
            for user in event.users:
                user_index.setdefault(user.lower(), []).append(event.event_id)
            for asset in event.assets:
                asset_index.setdefault(asset.lower(), []).append(event.event_id)

        event_map = {event.event_id: event for event in events}

        # Find shared users
        for user, event_ids in user_index.items():
            if len(event_ids) > 1:
                for i, src in enumerate(event_ids):
                    for tgt in event_ids[i+1:]:
                        if not self._within_window(event_map[src], event_map[tgt], window):
                            continue
                        correlations.append(Correlation(
                            source_event_id=src,
                            target_event_id=tgt,
                            correlation_type=CorrelationType.USER,
                            strength=CorrelationStrength.STRONG,
                            evidence=[f"Shared user: {user}"],
                            score=0.85,
                        ))

        # Find shared assets
        for asset, event_ids in asset_index.items():
            if len(event_ids) > 1:
                for i, src in enumerate(event_ids):
                    for tgt in event_ids[i+1:]:
                        if not self._within_window(event_map[src], event_map[tgt], window):
                            continue
                        correlations.append(Correlation(
                            source_event_id=src,
                            target_event_id=tgt,
                            correlation_type=CorrelationType.ASSET,
                            strength=CorrelationStrength.STRONG,
                            evidence=[f"Shared asset: {asset}"],
                            score=0.85,
                        ))

        return correlations

    def _correlate_by_attack_chain(
        self,
        events: list[EventData],
        window: timedelta,
    ) -> list[Correlation]:
        """Find correlations based on MITRE ATT&CK chains."""
        correlations = []

        # Collect all techniques from events
        event_techniques: dict[str, list[str]] = {}  # event_id -> techniques
        for event in events:
            if event.mitre_techniques:
                event_techniques[event.event_id] = event.mitre_techniques

        event_map = {event.event_id: event for event in events}

        # Check for attack chain patterns
        for chain in self.attack_chains:
            chain_techniques = set(chain["techniques"])
            matching_events: list[str] = []

            for event_id, techniques in event_techniques.items():
                if set(techniques) & chain_techniques:
                    matching_events.append(event_id)

            # If multiple events match the same chain
            if len(matching_events) > 1:
                for i, src in enumerate(matching_events):
                    for tgt in matching_events[i+1:]:
                        if not self._within_window(event_map[src], event_map[tgt], window):
                            continue
                        shared_chain_techniques = (
                            set(event_map[src].mitre_techniques)
                            | set(event_map[tgt].mitre_techniques)
                        ) & chain_techniques
                        if len(shared_chain_techniques) < 2:
                            continue
                        correlations.append(Correlation(
                            source_event_id=src,
                            target_event_id=tgt,
                            correlation_type=CorrelationType.ATTACK_CHAIN,
                            strength=CorrelationStrength.STRONG,
                            evidence=[f"Attack chain: {chain['name']}"],
                            score=0.95,
                        ))

        return correlations

    @staticmethod
    def _within_window(first: EventData, second: EventData, window: timedelta) -> bool:
        return abs((second.timestamp - first.timestamp).total_seconds()) <= window.total_seconds()

    def _build_groups(
        self,
        events: list[EventData],
        correlations: list[Correlation],
    ) -> list[CorrelatedGroup]:
        """Build correlated groups using union-find."""
        if not events:
            return []

        # Union-Find for grouping
        parent: dict[str, str] = {e.event_id: e.event_id for e in events}

        def find(x: str) -> str:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: str, y: str) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Union correlated events
        for corr in correlations:
            if corr.score >= self.min_correlation_score:
                if corr.source_event_id in parent and corr.target_event_id in parent:
                    union(corr.source_event_id, corr.target_event_id)

        # Build groups
        group_events: dict[str, list[EventData]] = {}
        group_correlations: dict[str, list[Correlation]] = {}

        event_map = {e.event_id: e for e in events}

        for event in events:
            root = find(event.event_id)
            group_events.setdefault(root, []).append(event)

        for corr in correlations:
            if corr.source_event_id in parent:
                root = find(corr.source_event_id)
                group_correlations.setdefault(root, []).append(corr)

        # Create CorrelatedGroup objects
        groups = []
        for root, evts in group_events.items():
            if len(evts) < 2:
                continue  # Single events don't form a group

            # Aggregate info
            domains = list(set(e.domain for e in evts))
            shared_ips = self._find_shared(evts, "ips")
            shared_domains = self._find_shared(evts, "domains")
            shared_urls = self._find_shared(evts, "urls")
            shared_hashes = self._find_shared(evts, "hashes")
            shared_users = self._find_shared(evts, "users")
            techniques = list(set(t for e in evts for t in e.mitre_techniques))
            tactics = list(set(t for e in evts for t in e.mitre_tactics))

            # Calculate group risk
            max_risk = max(e.risk_score for e in evts)
            severities = [e.severity for e in evts]
            severity_order = ["critical", "high", "medium", "low", "info"]
            highest_severity = min(severities, key=lambda s: severity_order.index(s) if s in severity_order else 99)

            # Build shared IOCs list
            shared_iocs = []
            for ip in shared_ips:
                shared_iocs.append({"type": "ip", "value": ip})
            for domain in shared_domains:
                shared_iocs.append({"type": "domain", "value": domain})
            for url in shared_urls:
                shared_iocs.append({"type": "url", "value": url})
            for file_hash in shared_hashes:
                shared_iocs.append({"type": "hash", "value": file_hash})

            timestamps = [e.timestamp for e in evts]

            groups.append(CorrelatedGroup(
                event_ids=[e.event_id for e in evts],
                correlations=group_correlations.get(root, []),
                domains=domains,
                risk_score=max_risk,
                severity=highest_severity,
                shared_iocs=shared_iocs,
                shared_users=list(shared_users),
                attack_techniques=techniques,
                attack_tactics=tactics,
                first_seen=min(timestamps),
                last_seen=max(timestamps),
            ))

        # Sort by severity and risk
        groups.sort(key=lambda g: (
            severity_order.index(g.severity) if g.severity in severity_order else 99,
            -g.risk_score
        ))

        return groups

    def _find_shared(self, events: list[EventData], field: str) -> set[str]:
        """Find values that appear in multiple events."""
        counts: dict[str, int] = {}
        for event in events:
            for value in getattr(event, field, []):
                counts[value] = counts.get(value, 0) + 1
        return {v for v, c in counts.items() if c > 1}

    def get_statistics(self) -> dict[str, Any]:
        """Get correlation engine statistics."""
        return {
            "correlation_window_hours": self.correlation_window.total_seconds() / 3600,
            "min_correlation_score": self.min_correlation_score,
            "attack_chains_loaded": len(self.attack_chains),
        }


# Singleton
_correlation_engine: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    """Get the global correlation engine."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine
