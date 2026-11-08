"""
CyberGuard AI — MITRE ATT&CK Provider
============================================================================

MITRE ATT&CK technique lookup. Local, no network — ships with a small
bundled dataset of the most common techniques.

No API key required. No rate limit. Works offline.

Used by:
    - ThreatIntel agent: annotate technique IDs with names and tactics.
    - Reporting agent: MITRE ATT&CK coverage sections in reports.
    - IOC correlation agent: group findings by tactic.
"""

from __future__ import annotations

from typing import Any

from app.agents.threat_intelligence.providers.base import (
    ProviderResult,
    ThreatIntelProvider,
)


# ============================================================================
# BUNDLED TECHNIQUE DATA
# ============================================================================
# Curated subset — the techniques that actually appear in the 8 agents'
# findings. A Phase 13 enhancement can load the full ATT&CK dataset.

_TECHNIQUES: dict[str, dict[str, str]] = {
    # Initial Access
    "T1566": {"name": "Phishing", "tactic": "initial_access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial_access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "initial_access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access"},
    "T1133": {"name": "External Remote Services", "tactic": "initial_access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "execution"},
    # Persistence
    "T1136": {"name": "Create Account", "tactic": "persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation"},
    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "defense_evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "defense_evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense_evasion"},
    # Credential Access
    "T1110": {"name": "Brute Force", "tactic": "credential_access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential_access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential_access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access"},
    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "lateral_movement"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    # Command & Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "command_and_control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "command_and_control"},
    "T1071.004": {"name": "DNS", "tactic": "command_and_control"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "command_and_control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "command_and_control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command_and_control"},
    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "exfiltration"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1489": {"name": "Service Stop", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
    "T1498": {"name": "Network Denial of Service", "tactic": "impact"},
    # Misc
    "T1568": {"name": "Dynamic Resolution", "tactic": "command_and_control"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "command_and_control"},
    "T1656": {"name": "Impersonation", "tactic": "defense_evasion"},
}


class MitreAttackProvider(ThreatIntelProvider):
    """
    MITRE ATT&CK technique lookup. Local, no network, no rate limit.

    Exposes ``lookup_technique`` (not part of the base interface). The
    base ``lookup_*`` methods return None — this provider enriches
    technique references, not IOCs.
    """

    name = "mitre"
    requires_api_key = False
    _default_rate_limit_rpm = 100000

    def lookup_technique(self, technique_id: str) -> ProviderResult | None:
        """
        Look up a MITRE technique by ID (e.g. ``T1110.001``).
        """
        tech = (technique_id or "").strip().upper()
        if not tech.startswith("T"):
            return None

        cache_key = self._cache_key("technique", tech)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        info = _TECHNIQUES.get(tech)
        if info is None:
            if "." in tech:
                parent_id = tech.split(".", 1)[0]
                parent_info = _TECHNIQUES.get(parent_id)
                if parent_info is not None:
                    result = ProviderResult(
                        provider=self.name,
                        indicator=tech,
                        indicator_type="technique",
                        malicious=False,
                        score=0,
                        confidence=0.60,
                        details=(
                            f"{tech}: Unknown sub-technique; parent is "
                            f"{parent_info['name']} ({parent_info['tactic']})"
                        ),
                        raw={"parent_id": parent_id, **parent_info},
                    )
                    self._cache_set(cache_key, result)
                    return result
            return None

        result = ProviderResult(
            provider=self.name,
            indicator=tech,
            indicator_type="technique",
            malicious=False,
            score=0,
            confidence=1.0,
            details=f"{tech}: {info['name']} ({info['tactic']})",
            raw={
                "name": info["name"],
                "tactic": info["tactic"],
            },
        )
        self._cache_set(cache_key, result)
        return result

    def describe(self, technique_id: str) -> dict[str, Any] | None:
        """Return technique metadata as a plain dict (for reporting)."""
        tech = (technique_id or "").strip().upper()
        info = _TECHNIQUES.get(tech)
        if info is None:
            return None
        return {
            "id": tech,
            "name": info["name"],
            "tactic": info["tactic"],
        }


__all__ = ["MitreAttackProvider", "_TECHNIQUES"]