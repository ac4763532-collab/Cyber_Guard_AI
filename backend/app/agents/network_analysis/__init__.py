"""
CyberGuard AI — Network Analysis Agent Package

Detects suspicious network activity: port scans, C2 beaconing, DNS
anomalies (DGA/tunneling), unusual outbound connections.

Consumes events with ``event.category=NETWORK``. The agent runs five
deterministic rules against each network event:

    1. Port scanning    — many distinct destination ports from one source
    2. Beaconing         — regular-interval connections to the same target
    3. DNS anomaly       — high-entropy or unusually long domains
    4. Suspicious outbound — raw IP, unusual port, or blocked TLD
    5. Connection flood  — high connection volume from one host/user

Same structural contract as the log and email agents — thin orchestrator
+ isolated rules returning ``FindingSpec``.

Public API:
    from app.agents.network_analysis import NetworkAnalysisAgent
"""

from app.agents.network_analysis.agent import NetworkAnalysisAgent

__all__ = ["NetworkAnalysisAgent"]