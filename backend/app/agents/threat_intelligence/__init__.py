"""
CyberGuard AI — Threat Intelligence Agent Package

Enriches security events with external threat intelligence. Consumes
any event that carries an indicator of compromise (IOC) — IPs, domains,
URLs, file hashes — and cross-references those against external
reputation services.

Providers (all optional — the agent runs with whatever is configured):

    VirusTotal      — IP/domain/URL/hash reputation  (API key required)
    AbuseIPDB       — IP abuse report database       (API key required)
    URLhaus         — Malicious URL database         (free, no key)
    NVD             — CVE details                    (free, no key)
    MITRE ATT&CK    — Technique lookup               (bundled, no network)

The agent's design is fail-safe:
    - Missing keys → provider disabled, agent still runs
    - Rate limits → provider skipped for this event
    - Network errors → logged, agent continues
    - All providers unavailable → agent produces no findings (not an error)

Public API:
    from app.agents.threat_intelligence import ThreatIntelligenceAgent
"""

from app.agents.threat_intelligence.agent import ThreatIntelligenceAgent

__all__ = ["ThreatIntelligenceAgent"]