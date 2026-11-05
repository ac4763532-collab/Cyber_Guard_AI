"""
CyberGuard AI - Shared Network Utilities

Small helpers used by both the NetworkAgent (port scanning) and the
network_intel service (DNS/geoip/RDAP lookups) so there is one definition
of "what counts as an IP address" instead of duplicated regexes drifting
apart.
"""

import re

_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def is_ip_address(target: str) -> bool:
    """
    Return True if `target` looks like an IPv4 address (not a CIDR range,
    not a hostname/domain).

    This is a plain syntactic check (correct octet ranges), not a DNS or
    socket-level validation - callers that need CIDR support (e.g. the
    network scan agent) should strip any "/mask" suffix before calling,
    or match on their own CIDR-aware pattern instead.
    """
    target = target.strip()
    if not _IPV4_PATTERN.match(target):
        return False
    return all(0 <= int(octet) <= 255 for octet in target.split("."))
