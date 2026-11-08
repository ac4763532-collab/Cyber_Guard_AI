"""
CyberGuard AI — Security Validation Utilities
============================================================================
Input sanitation and format validators for threat indicators (IPs, hashes,
domains, URLs) and user attributes.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

# Regex definitions
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def is_valid_ip(val: str) -> bool:
    """Return True if val is a valid IPv4 or IPv6 address."""
    if not val or not isinstance(val, str):
        return False
    try:
        ipaddress.ip_address(val.strip())
        return True
    except ValueError:
        return False


def is_valid_cidr(val: str) -> bool:
    """Return True if val is a valid IPv4 or IPv6 CIDR network."""
    if not val or not isinstance(val, str):
        return False
    try:
        ipaddress.ip_network(val.strip(), strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(val: str) -> bool:
    """Return True if val is a valid domain name."""
    if not val or not isinstance(val, str):
        return False
    val = val.strip().lower()
    return bool(DOMAIN_REGEX.match(val))


def is_valid_hash(val: str) -> bool:
    """Return True if val is a valid MD5, SHA1, or SHA256 hash."""
    if not val or not isinstance(val, str):
        return False
    val = val.strip()
    return bool(SHA256_REGEX.match(val) or SHA1_REGEX.match(val) or MD5_REGEX.match(val))


def is_valid_email(val: str) -> bool:
    """Return True if val is a valid email string."""
    if not val or not isinstance(val, str):
        return False
    return bool(EMAIL_REGEX.match(val.strip()))


def is_valid_port(val: int | str) -> bool:
    """Return True if port is an integer in 1..65535."""
    try:
        p = int(val)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def sanitize_input(val: Optional[str], max_len: int = 1000) -> str:
    """Strip dangerous characters and truncate excessive length."""
    if val is None:
        return ""
    # Strip null bytes and normalize whitespace
    cleaned = val.replace("\x00", "").strip()
    return cleaned[:max_len]
