"""
CyberGuard AI — IOC Correlation Agent Package

Connects findings across agents when they share indicators of
compromise (IOCs). When 2+ findings reference the same 2+ IOCs within
a time window, they likely represent one coordinated attack that was
seen through different lenses.

Example: an attacker sends a phishing email (Email Agent finding),
logs in from a suspicious IP (Log Agent finding), and connects out
to a C2 domain (Network Agent finding). Three findings, three agents,
one attack. The correlation agent produces a fourth finding:

    "Correlated activity: 3 findings share 4 indicators — likely
     one attack spanning email, authentication, and network channels."

This correlated finding is HIGH severity and typically triggers
incident creation via `alert_service`.

The agent runs on the current event's IOCs against recent findings in
the workspace. It does NOT scan all findings for all correlations —
that would be O(n²) per event. Instead:

    Seed:       the current event's IOCs
    Candidates: findings in the workspace from the last N minutes
    Match:      findings whose primary event shares 2+ IOCs with seed

MITRE mapping: the correlated finding carries MITRE tags aggregated
from the contributing findings.

Public API:
    from app.agents.ioc_correlation import IocCorrelationAgent
"""

from app.agents.ioc_correlation.agent import IocCorrelationAgent

__all__ = ["IocCorrelationAgent"]