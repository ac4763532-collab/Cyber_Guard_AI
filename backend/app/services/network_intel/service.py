"""
CyberGuard AI - Network Intelligence Service (façade)

Combines free DNS, geolocation, and RDAP lookups with the existing
ThreatIntelService (VirusTotal/AbuseIPDB) into one result for the Network
Analysis "Analyze" tab.

This is a passive, read-only enrichment lookup on public records - not a
scan of the target's live systems - so it does not go through the
BaseAgent/AgentResult framework (no classification/severity/risk_score of
the scanning kind). It mirrors how `url_analysis.service` returns a plain
result without the agent framework.

Honesty contract: when neither VirusTotal nor AbuseIPDB is configured, the
`threat_intel` field is an explicit `{"configured": False, "reputation_
status": "unknown", ...}` sentinel - never a default/fabricated "clean"
verdict. Likewise, a private/loopback/reserved target never reaches a
public provider at all - it gets an explicit `not_applicable` status
instead of a silently-empty or fabricated "clean" result.
"""

import asyncio
import ipaddress
import re

from pydantic import BaseModel, Field

from app.services.network_intel.dns_lookup import resolve_dns
from app.services.network_intel.geoip import lookup_geoip
from app.services.network_intel.rdap import lookup_rdap
from app.services.threat_intel.service import IOCType, ReputationStatus, get_threat_intel_service
from app.utils.network import is_ip_address

# Matches the *shape* of an IPv4 address (four dot-separated groups of 1-3
# digits) regardless of whether each octet is actually in the valid 0-255
# range. Used only to distinguish "this was clearly an attempt at an IPv4
# address with an invalid octet" (e.g. "999.999.999.999") from "this is a
# genuine domain name" - is_ip_address() already rejects the former, but
# without this check it would silently fall through to the domain-lookup
# path (DNS/RDAP/VirusTotal-as-domain) instead of being rejected outright.
_IPV4_SHAPED_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _looks_like_malformed_ip(target: str) -> bool:
    """True if `target` has the shape of an IPv4 address but is not a
    valid one (e.g. an octet > 255, like "999.999.999.999"). A genuine
    domain name never matches this dotted-quad-of-digits shape, so this
    can't misfire on a real hostname."""
    return bool(_IPV4_SHAPED_PATTERN.match(target)) and not is_ip_address(target)


class NetworkIntelResult(BaseModel):
    """Combined result for a single Analyze-tab lookup."""

    target: str
    target_classification: str = "public"
    dns: dict = Field(default_factory=dict)
    geoip: dict = Field(default_factory=dict)
    rdap: dict = Field(default_factory=dict)
    threat_intel: dict = Field(default_factory=dict)


_NOT_CONFIGURED_THREAT_INTEL = {
    "configured": False,
    "reputation_status": ReputationStatus.UNKNOWN.value,
    "classification_reason": "No threat intelligence sources configured (VirusTotal/AbuseIPDB API keys not set).",
    "sources": [],
    "provider_outcomes": [],
    "is_malicious": None,
    "risk_score": None,
    "error": "No threat intelligence sources configured (VirusTotal/AbuseIPDB API keys not set)",
}


def _classify_target_address(target: str) -> str | None:
    """
    Return a human-readable reason the target is a private/loopback/
    link-local/reserved address not appropriate for public reputation
    lookups, or None if it's a public address (or not a parseable IP at
    all, e.g. a domain name - callers should treat that as "public").

    Uses Python's `ipaddress` module directly, rather than relying on a
    third-party provider's own classification of the address (as the
    previous implementation did implicitly, only inside geoip.py).
    """
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return None  # Not a bare IP - treat as a public domain target.

    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_private:
        return "private (RFC1918/RFC4193) address"
    if addr.is_reserved:
        return "reserved address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_unspecified:
        return "unspecified address"
    return None


def _not_applicable_result(reason: str) -> dict:
    return {
        "configured": True,
        "available": False,
        "error": f"Not applicable: {reason}. Public reputation/geolocation/registration checks don't apply to this address.",
    }


async def lookup_network_intel(target: str) -> NetworkIntelResult:
    """Run DNS, geolocation, RDAP, and threat-intel lookups for `target`."""
    target = target.strip()
    target_is_ip = is_ip_address(target)

    # Reject a string shaped like an IPv4 address but with an out-of-range
    # octet (e.g. "999.999.999.999") outright, instead of silently treating
    # it as a domain name and sending it to DNS/RDAP/VirusTotal-as-domain.
    # Per the required IP-validation policy, a malformed address must be
    # rejected before any external call is made - not reclassified as a
    # different kind of target.
    if _looks_like_malformed_ip(target):
        error_msg = f"'{target}' is not a valid IP address (each octet must be 0-255)."
        not_applicable = {
            "configured": True,
            "available": False,
            "error": error_msg,
        }
        return NetworkIntelResult(
            target=target,
            target_classification="malformed",
            dns=not_applicable,
            geoip=not_applicable,
            rdap=not_applicable,
            threat_intel={
                "configured": True,
                "reputation_status": ReputationStatus.UNKNOWN.value,
                "classification_reason": (
                    f"{error_msg} No lookups were performed - this is a rejected input, not a result."
                ),
                "sources": [],
                "provider_outcomes": [],
                "is_malicious": None,
                "risk_score": None,
                "error": error_msg,
            },
        )

    # Reject sending a private/loopback/link-local/reserved IP to external
    # public threat-intel/geolocation/RDAP providers. DNS (reverse lookup)
    # is still safe and useful for these addresses, so it's the only check
    # that still runs normally.
    private_reason = _classify_target_address(target) if target_is_ip else None

    dns_task = resolve_dns(target)

    if private_reason:
        dns_result = await dns_task
        rdap_result = _not_applicable_result(private_reason)
        geoip_result = _not_applicable_result(private_reason)
        threat_intel = {
            "configured": True,
            "reputation_status": ReputationStatus.UNKNOWN.value,
            "classification_reason": (
                f"This is a {private_reason} ({target}). Public threat-intelligence providers were not "
                "queried - a private/internal address cannot have a meaningful public reputation."
            ),
            "sources": [],
            "provider_outcomes": [],
            "is_malicious": None,
            "risk_score": None,
            "error": None,
        }

        return NetworkIntelResult(
            target=target,
            target_classification=private_reason,
            dns=dns_result,
            geoip=geoip_result,
            rdap=rdap_result,
            threat_intel=threat_intel,
        )

    rdap_task = lookup_rdap(target)

    if target_is_ip:
        geoip_task = lookup_geoip(target)
        dns_result, rdap_result, geoip_result = await asyncio.gather(
            dns_task, rdap_task, geoip_task
        )
    else:
        dns_result, rdap_result = await asyncio.gather(dns_task, rdap_task)
        resolved_ips = dns_result.get("resolved_ips") or []
        # If the domain resolved to a private IP (e.g. internal DNS,
        # split-horizon, or a misconfigured public record), geolocation
        # against that private IP is equally not applicable.
        resolved_private_reason = (
            _classify_target_address(resolved_ips[0]) if resolved_ips else None
        )
        if resolved_ips and not resolved_private_reason:
            geoip_result = await lookup_geoip(resolved_ips[0])
        elif resolved_private_reason:
            geoip_result = _not_applicable_result(
                f"resolved to a {resolved_private_reason} ({resolved_ips[0]})"
            )
        else:
            geoip_result = {
                "configured": True,
                "available": False,
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "lat": None,
                "lon": None,
                "isp": None,
                "org": None,
                "asn": None,
                "error": "Could not resolve target to an IP for geolocation",
            }

    threat_intel = await _lookup_threat_intel(target, target_is_ip)

    return NetworkIntelResult(
        target=target,
        target_classification="public",
        dns=dns_result,
        geoip=geoip_result,
        rdap=rdap_result,
        threat_intel=threat_intel,
    )


async def _lookup_threat_intel(target: str, target_is_ip: bool) -> dict:
    service = get_threat_intel_service()

    if not service.is_configured:
        return dict(_NOT_CONFIGURED_THREAT_INTEL)

    ioc_type = IOCType.IP if target_is_ip else IOCType.DOMAIN
    result = await service.lookup(ioc_type, target)

    return {
        "configured": True,
        "reputation_status": result.reputation_status.value,
        "classification_reason": result.classification_reason,
        "sources": result.sources,
        "provider_outcomes": [o.model_dump() for o in result.provider_outcomes],
        # Deprecated boolean/int mirrors, kept for any caller still reading
        # the old shape - derived from reputation_status, never the other
        # way around. LOOKUP_FAILED and UNKNOWN both report None here, so a
        # consumer that only checks this field still can't mistake a
        # failed/unknown check for a confirmed-clean one.
        "is_malicious": result.is_malicious,
        "risk_score": result.risk_score,
        "error": result.error,
    }
