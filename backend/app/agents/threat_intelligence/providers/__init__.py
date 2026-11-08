"""
CyberGuard AI — Threat Intelligence Providers

External reputation and enrichment APIs. Each provider inherits
`ThreatIntelProvider` and implements whichever `lookup_*` methods it
supports.

All providers:
    - Enforce per-provider rate limits (token bucket)
    - Cache results in Redis if REDIS_URL is set (default 1h TTL)
    - Time out at 10s (configurable per-provider)
    - Return None on failure — never raise
"""

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)
from app.agents.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.agents.threat_intelligence.providers.virustotal import VirusTotalProvider

__all__ = [
    "ProviderResult",
    "ThreatIntelProvider",
    "AbuseIPDBProvider",
    "VirusTotalProvider",
    # The following are imported lazily by the agent to avoid hard
    # dependencies on optional modules during incremental delivery:
    #   URLhausProvider, NVDProvider, MitreAttackProvider
]