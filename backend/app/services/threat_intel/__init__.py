"""
CyberGuard AI - Threat Intelligence Service

Provides IOC enrichment via external threat intelligence APIs:
- VirusTotal: URL, domain, IP, file hash reputation
- AbuseIPDB: IP abuse reports

All lookups are cached to reduce API calls.
"""

from app.services.threat_intel.service import (
    ThreatIntelService,
    get_threat_intel_service,
    IOCType,
    ThreatIntelResult,
)

__all__ = [
    "ThreatIntelService",
    "get_threat_intel_service",
    "IOCType",
    "ThreatIntelResult",
]
