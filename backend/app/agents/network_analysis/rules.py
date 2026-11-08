"""
CyberGuard AI — Network Analysis Detection Rules
============================================================================

Five deterministic rules for the Network Analysis Agent.

Rules aggregate over the ``security_events`` table to detect patterns:
port scans (many ports from one source), beaconing (regular intervals),
DNS anomalies (entropy), suspicious outbound (raw IPs / bad TLDs),
connection floods (volume).
"""

from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from app.agents.base import AgentContext
from app.models.enums import EventSeverity, FindingCategory
from app.models.event import SecurityEvent


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
# HELPERS
# ============================================================================

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_raw_ip(host: str | None) -> bool:
    """True if the string looks like an IPv4/IPv6 literal."""
    if not host:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return True
    if ":" in host and re.match(r"^[0-9a-fA-F:]+$", host):
        return True
    return False


# ============================================================================
# RULE 1 — Port Scan
# ============================================================================

class PortScanRule(BaseRule):
    """
    Detects a source IP connecting to many distinct destination ports
    in a short window. Classic port-scanning reconnaissance.

    MITRE: T1046 (Network Service Discovery)
    """
    name = "network.port_scan"

    def __init__(self, threshold: int = 20, window_seconds: int = 60) -> None:
        self._threshold = max(5, threshold)
        self._window_seconds = max(10, window_seconds)

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        # Only network events with a source IP and destination port
        if not event.source_ip or event.destination_port is None:
            return None

        cutoff = event.event_time - timedelta(seconds=self._window_seconds)

        # Distinct (source_ip, destination_port) pairs from this source
        stmt = (
            select(
                SecurityEvent.destination_port,
                func.count(SecurityEvent.id).label("attempts"),
            )
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.destination_port.is_not(None),
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
            .group_by(SecurityEvent.destination_port)
        )
        rows = context.db.execute(stmt).all()

        distinct_ports = [r[0] for r in rows if r[0] is not None]
        if len(distinct_ports) < self._threshold:
            return None

        confidence = min(0.98, 0.75 + 0.03 * (len(distinct_ports) - self._threshold))

        # Sample ports for evidence (first 30)
        port_sample = sorted(distinct_ports)[:30]

        # Get event IDs for evidence
        ids_stmt = (
            select(SecurityEvent.id)
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.destination_port.in_(distinct_ports),
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
            .limit(100)
        )
        event_ids = [r[0] for r in context.db.execute(ids_stmt).all()]
        if not event_ids:
            event_ids = [event.id]

        return FindingSpec(
            rule_id=self.name,
            title=f"Port scan from {event.source_ip} ({len(distinct_ports)} ports)",
            severity=EventSeverity.HIGH,
            category=FindingCategory.PORT_SCAN,
            confidence=confidence,
            event_ids=event_ids,
            primary_event_id=event.id,
            evidence={
                "source_ip": event.source_ip,
                "distinct_port_count": len(distinct_ports),
                "sample_ports": port_sample,
                "window_seconds": self._window_seconds,
                "threshold": self._threshold,
            },
            description=(
                f"{len(distinct_ports)} distinct ports targeted from "
                f"{event.source_ip} within {self._window_seconds}s. "
                f"Indicative of automated port scanning."
            ),
            mitre_techniques=["T1046"],
            dedup_hint=f"src={event.source_ip}",
        )


# ============================================================================
# RULE 2 — Beaconing (C2 callback)
# ============================================================================

class BeaconingRule(BaseRule):
    """
    Detects regular-interval connections to the same destination —
    the classic C2 callback pattern. Malware "phones home" every N
    seconds/minutes.

    Heuristic: at least 5 connections to the same destination IP,
    with standard deviation of inter-arrival times under 15% of the
    mean (very regular intervals).

    MITRE: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
    """
    name = "network.beaconing"

    _MIN_CONNECTIONS = 5
    _STDDEV_RATIO_THRESHOLD = 0.15
    _WINDOW_MINUTES = 30

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        if not event.destination_ip:
            return None

        cutoff = event.event_time - timedelta(minutes=self._WINDOW_MINUTES)

        stmt = (
            select(SecurityEvent.event_time, SecurityEvent.id)
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.destination_ip == event.destination_ip,
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
            .order_by(SecurityEvent.event_time.asc())
            .limit(100)
        )
        rows = list(context.db.execute(stmt).all())

        if len(rows) < self._MIN_CONNECTIONS:
            return None

        # Compute inter-arrival times (seconds)
        times = [r[0] for r in rows]
        deltas = [
            (times[i + 1] - times[i]).total_seconds()
            for i in range(len(times) - 1)
        ]
        if not deltas:
            return None

        mean = sum(deltas) / len(deltas)
        variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        stddev = math.sqrt(variance)

        if mean <= 0:
            return None
        ratio = stddev / mean
        if ratio > self._STDDEV_RATIO_THRESHOLD:
            return None  # irregular — normal traffic

        confidence = min(0.95, 0.70 + (self._STDDEV_RATIO_THRESHOLD - ratio) * 2)

        return FindingSpec(
            rule_id=self.name,
            title=f"Beaconing pattern to {event.destination_ip}",
            severity=EventSeverity.HIGH,
            category=FindingCategory.MALWARE,
            confidence=confidence,
            event_ids=[r[1] for r in rows[:50]],
            primary_event_id=event.id,
            evidence={
                "destination_ip": event.destination_ip,
                "connection_count": len(rows),
                "mean_interval_seconds": round(mean, 2),
                "stddev_seconds": round(stddev, 2),
                "stddev_ratio": round(ratio, 3),
                "window_minutes": self._WINDOW_MINUTES,
            },
            description=(
                f"{len(rows)} connections to {event.destination_ip} at "
                f"~{int(mean)}s intervals (stddev {int(stddev)}s). "
                f"Regularity is consistent with C2 beaconing."
            ),
            mitre_techniques=["T1071", "T1571"],
            dedup_hint=f"dst={event.destination_ip}",
        )


# ============================================================================
# RULE 3 — DNS Anomaly (DGA / tunneling)
# ============================================================================

class DnsAnomalyRule(BaseRule):
    """
    Detects suspicious DNS patterns:

        - High-entropy domain labels (DGA / exfiltration via DNS)
        - Unusually long domain names (DNS tunneling)
        - Subdomain labels that look like base32/base64 (tunneling)

    MITRE: T1071.004 (DNS), T1568.002 (Domain Generation Algorithms),
           T1048.003 (Exfiltration Over DNS)
    """
    name = "network.dns_anomaly"

    _HIGH_ENTROPY_THRESHOLD = 3.8
    _LONG_LABEL_THRESHOLD = 40
    _LONG_DOMAIN_THRESHOLD = 100

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        domain = event.domain
        if not domain:
            return None

        reasons: list[str] = []

        # Entropy of the leftmost label (before first dot)
        leftmost = domain.split(".", 1)[0]
        if len(leftmost) >= 12:
            entropy = _shannon_entropy(leftmost)
            if entropy >= self._HIGH_ENTROPY_THRESHOLD:
                reasons.append(f"high_entropy:{round(entropy, 2)}")

        # Unusually long labels / domains (tunneling)
        for label in domain.split("."):
            if len(label) > self._LONG_LABEL_THRESHOLD:
                reasons.append(f"long_label:{len(label)}")
                break
        if len(domain) > self._LONG_DOMAIN_THRESHOLD:
            reasons.append(f"long_domain:{len(domain)}")

        # Base32/base64-looking subdomain
        if re.match(r"^[a-z2-7]{20,}$", leftmost) or re.match(r"^[a-z0-9+/=]{20,}$", leftmost):
            reasons.append("encoded_subdomain")

        if not reasons:
            return None

        severity = EventSeverity.MEDIUM
        if any(r.startswith("high_entropy") or r.startswith("long_domain") for r in reasons):
            severity = EventSeverity.HIGH

        return FindingSpec(
            rule_id=self.name,
            title=f"DNS anomaly: {domain[:60]}",
            severity=severity,
            category=FindingCategory.OTHER,
            confidence=0.70,
            event_ids=[event.id],
            evidence={
                "domain": domain,
                "reasons": reasons,
                "leftmost_label": leftmost[:80],
                "leftmost_entropy": round(_shannon_entropy(leftmost), 3),
            },
            description=(
                f"Domain '{domain[:80]}' matched DNS anomaly indicators: "
                + ", ".join(reasons) + "."
            ),
            mitre_techniques=["T1071.004", "T1568.002"],
            dedup_hint=f"domain={domain}",
        )


# ============================================================================
# RULE 4 — Suspicious Outbound
# ============================================================================

#: Ports that are common, expected outbound from an office network.
_COMMON_PORTS = frozenset({80, 443, 22, 53, 25, 587, 993, 465, 587})

#: Ports that are rarely legitimate outbound and often C2.
_SUSPICIOUS_PORTS = frozenset({
    23,      # telnet
    2323,    # telnet alt
    4444,    # Metasploit default
    5555,    # Android ADB default
    6667,    # IRC
    6666,    # IRC alt
    9001,    # Tor
    9030,    # Tor
    31337,   # classic backdoor
    12345,   # NetBus
    54321,   # classic backdoor
    1080,    # SOCKS
    3389,    # RDP — suspicious if outbound
})

#: TLDs that are heavily abused.
_ABUSED_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".work",
    ".date", ".loan", ".win", ".bid", ".stream", ".men",
})


class SuspiciousOutboundRule(BaseRule):
    """
    Fires when an outbound network connection is suspicious:

        - Destination is a raw IP (no hostname resolution)
        - Destination port is uncommon for outbound (e.g. 23, 4444)
        - Destination domain uses an abused TLD
        - Connection to a Tor exit / known anonymous proxy port

    MITRE: T1071 (Application Layer Protocol), T1095 (Non-Application
           Layer Protocol), T1571 (Non-Standard Port)
    """
    name = "network.suspicious_outbound"

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        reasons: list[str] = []

        # Destination raw IP
        if event.destination_ip and not event.domain:
            if _is_raw_ip(event.destination_ip):
                reasons.append("raw_ip_destination")

        # Suspicious port
        port = event.destination_port
        if port is not None:
            if port in _SUSPICIOUS_PORTS:
                reasons.append(f"suspicious_port:{port}")

        # Abused TLD
        if event.domain:
            domain_lower = event.domain.lower()
            for tld in _ABUSED_TLDS:
                if domain_lower.endswith(tld):
                    reasons.append(f"abused_tld:{tld}")
                    break

        if not reasons:
            return None

        # Severity: raw IP + bad port = HIGH; single signal = MEDIUM
        severity = (
            EventSeverity.HIGH if len(reasons) >= 2
            else EventSeverity.MEDIUM
        )
        confidence = min(0.90, 0.60 + 0.10 * len(reasons))

        return FindingSpec(
            rule_id=self.name,
            title=f"Suspicious outbound connection ({', '.join(reasons[:2])})",
            severity=severity,
            category=FindingCategory.OTHER,
            confidence=confidence,
            event_ids=[event.id],
            evidence={
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "domain": event.domain,
                "reasons": reasons,
                "process_name": event.process_name,
                "hostname": event.hostname,
            },
            description=(
                "Outbound connection flagged: " + ", ".join(reasons)
                + f". Destination: {event.destination_ip or '?'}"
                + (f":{event.destination_port}" if event.destination_port else "")
                + (f" ({event.domain})" if event.domain else "")
                + "."
            ),
            mitre_techniques=["T1071", "T1095", "T1571"],
            dedup_hint=(
                f"dst={event.destination_ip or '?'}"
                f"|port={event.destination_port or '?'}"
            ),
        )


# ============================================================================
# RULE 5 — Connection Flood
# ============================================================================

class ConnectionFloodRule(BaseRule):
    """
    Detects an unusually high volume of connections from the same
    source host/user within a short window. This is the "outbound
    scanning" or "DDoS amplification from a compromised host" signal.

    Different from PortScanRule:
        PortScanRule  → one source hitting MANY PORTS on one or many hosts
        ConnectionFloodRule → one source hitting MANY HOSTS in a burst

    MITRE: T1071 (Application Layer Protocol), T1498 (Network DoS),
           T1046 (Network Service Discovery)
    """
    name = "network.connection_flood"

    _CONNECTION_THRESHOLD = 100
    _WINDOW_MINUTES = 5

    def evaluate(self, context: AgentContext) -> FindingSpec | None:
        event = context.event

        if not event.source_ip:
            return None

        cutoff = event.event_time - timedelta(minutes=self._WINDOW_MINUTES)

        # Count all network connections from this source in the window
        stmt = (
            select(
                func.count(SecurityEvent.id),
                func.count(func.distinct(SecurityEvent.destination_ip)),
            )
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
        )
        row = context.db.execute(stmt).one()
        connection_count = int(row[0])
        distinct_targets = int(row[1])

        if connection_count < self._CONNECTION_THRESHOLD:
            return None

        # Higher severity if the source is hitting many distinct targets
        if distinct_targets >= 20:
            severity = EventSeverity.HIGH
            confidence = 0.85
            desc_extra = f"across {distinct_targets} distinct targets"
        else:
            severity = EventSeverity.MEDIUM
            confidence = 0.70
            desc_extra = ""

        # Sample event ids
        ids_stmt = (
            select(SecurityEvent.id)
            .where(
                SecurityEvent.workspace_id == context.workspace_id,
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.event_time >= cutoff,
                SecurityEvent.event_time <= event.event_time,
            )
            .limit(100)
        )
        event_ids = [r[0] for r in context.db.execute(ids_stmt).all()]

        return FindingSpec(
            rule_id=self.name,
            title=f"Connection flood from {event.source_ip} ({connection_count} connections)",
            severity=severity,
            category=FindingCategory.OTHER,
            confidence=confidence,
            event_ids=event_ids or [event.id],
            primary_event_id=event.id,
            evidence={
                "source_ip": event.source_ip,
                "connection_count": connection_count,
                "distinct_targets": distinct_targets,
                "window_minutes": self._WINDOW_MINUTES,
                "hostname": event.hostname,
                "username": event.username,
            },
            description=(
                f"{connection_count} connections from {event.source_ip} "
                f"within {self._WINDOW_MINUTES} minutes"
                + (f" {desc_extra}" if desc_extra else "")
                + ". Host may be compromised and performing outbound scanning."
            ),
            mitre_techniques=["T1071", "T1046"],
            dedup_hint=f"src={event.source_ip}",
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FindingSpec",
    "BaseRule",
    "PortScanRule",
    "BeaconingRule",
    "DnsAnomalyRule",
    "SuspiciousOutboundRule",
    "ConnectionFloodRule",
]