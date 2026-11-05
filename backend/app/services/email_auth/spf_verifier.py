"""
Direct SPF verification for raw email messages.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import dns.resolver


SPF_RESULTS = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}


def extract_sender_domain(sender: str) -> str | None:
    """Extract the domain from an email address."""
    if not sender:
        return None

    match = re.search(
        r"<\s*[^<>@\s]+@([^<>\s]+)\s*>",
        sender,
    )

    if not match:
        match = re.search(
            r"\b[^@\s<>]+@([^@\s<>]+)\b",
            sender,
        )

    if not match:
        return None

    return match.group(1).strip().lower().rstrip(".")


def extract_sending_ip(headers: str | dict[str, Any]) -> str | None:
    """Extract a public IP from the first Received header."""

    if isinstance(headers, dict):
        received_values = []

        for key, value in headers.items():
            if key.lower() == "received":
                if isinstance(value, list):
                    received_values.extend(str(v) for v in value)
                else:
                    received_values.append(str(value))

        header_text = "\n".join(received_values)

    else:
        header_text = headers or ""

    if not header_text:
        return None

    first_received = re.split(
        r"\n(?=\s*Received\s*:)",
        header_text,
        flags=re.IGNORECASE,
    )[0]

    candidates = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        r"|(?<![A-Za-z0-9:])"
        r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
        r"(?![A-Za-z0-9:])",
        first_received,
    )

    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)

            if not (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
            ):
                return str(ip)

        except ValueError:
            continue

    return None


def get_spf_record(domain: str) -> str | None:
    """Retrieve the SPF TXT record for a domain."""

    try:
        answers = dns.resolver.resolve(domain, "TXT")

        records = []

        for answer in answers:
            try:
                text = "".join(
                    part.decode("utf-8", errors="replace")
                    if isinstance(part, bytes)
                    else str(part)
                    for part in answer.strings
                )
            except AttributeError:
                text = str(answer).strip('"')

            if text.lower().startswith("v=spf1"):
                records.append(text)

        if len(records) == 0:
            return None

        if len(records) > 1:
            return None

        return records[0]

    except dns.resolver.NoAnswer:
        return None

    except dns.resolver.NXDOMAIN:
        return None

    except dns.resolver.Timeout:
        return None

    except dns.resolver.NoNameservers:
        return None

    except Exception:
        return None


def _ip_matches_cidr(ip: str, network: str) -> bool:
    """Check whether an IP belongs to a network."""

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            network,
            strict=False,
        )
    except ValueError:
        return False


def _resolve_a(domain: str) -> list[str]:
    """Resolve A records."""

    try:
        return [
            str(r.address)
            for r in dns.resolver.resolve(domain, "A")
        ]
    except Exception:
        return []


def _resolve_aaaa(domain: str) -> list[str]:
    """Resolve AAAA records."""

    try:
        return [
            str(r.address)
            for r in dns.resolver.resolve(domain, "AAAA")
        ]
    except Exception:
        return []


def _resolve_mx_hosts(domain: str) -> list[str]:
    """Resolve MX hosts."""

    try:
        return [
            str(r.exchange).rstrip(".")
            for r in dns.resolver.resolve(domain, "MX")
        ]
    except Exception:
        return []


def _mechanism_matches(
    mechanism: str,
    domain: str,
    sending_ip: str,
) -> bool:
    """Evaluate common SPF mechanisms."""

    mechanism = mechanism.strip()

    mechanism = mechanism.lstrip("+-~?")

    if not mechanism:
        return False

    if mechanism.startswith("ip4:"):
        return _ip_matches_cidr(
            sending_ip,
            mechanism[4:],
        )

    if mechanism.startswith("ip6:"):
        return _ip_matches_cidr(
            sending_ip,
            mechanism[4:],
        )

    if mechanism == "a" or mechanism.startswith("a:"):
        target = (
            domain
            if mechanism == "a"
            else mechanism[2:]
        )

        return sending_ip in (
            _resolve_a(target)
            + _resolve_aaaa(target)
        )

    if mechanism == "mx" or mechanism.startswith("mx:"):
        target = (
            domain
            if mechanism == "mx"
            else mechanism[3:]
        )

        for host in _resolve_mx_hosts(target):
            if sending_ip in (
                _resolve_a(host)
                + _resolve_aaaa(host)
            ):
                return True

    return False


def _evaluate_record(
    record: str,
    domain: str,
    sending_ip: str,
    depth: int = 0,
    visited: set[str] | None = None,
) -> str:
    """
    Evaluate an SPF record.

    Supports:
    - ip4
    - ip6
    - a
    - mx
    - include
    - redirect
    - all

    A recursion limit protects against DNS loops.
    """

    if depth > 10:
        return "permerror"

    if visited is None:
        visited = set()

    domain = domain.lower().rstrip(".")

    if domain in visited:
        return "permerror"

    visited.add(domain)

    if not record or not record.lower().startswith("v=spf1"):
        return "none"

    mechanisms = record.split()[1:]

    for mechanism in mechanisms:
        mechanism = mechanism.strip()

        if not mechanism:
            continue

        qualifier = "+"

        if mechanism[0] in "+-~?":
            qualifier = mechanism[0]
            mechanism_body = mechanism[1:]
        else:
            mechanism_body = mechanism

        if mechanism_body == "all":
            return SPF_RESULTS[qualifier]

        if mechanism_body.startswith("include:"):
            include_domain = mechanism_body[8:].strip().lower()

            include_record = get_spf_record(include_domain)

            if not include_record:
                continue

            include_result = _evaluate_record(
                include_record,
                include_domain,
                sending_ip,
                depth + 1,
                visited.copy(),
            )

            # SPF include matches only when the nested
            # SPF evaluation returns PASS.
            if include_result == "pass":
                return SPF_RESULTS[qualifier]

            continue

        if _mechanism_matches(
            mechanism,
            domain,
            sending_ip,
        ):
            return SPF_RESULTS[qualifier]

    # SPF redirect applies when no mechanism matched.
    redirect_match = re.search(
        r"(?:^|\s)redirect=([^\s]+)",
        record,
        flags=re.IGNORECASE,
    )

    if redirect_match:
        redirect_domain = (
            redirect_match.group(1)
            .strip()
            .lower()
            .rstrip(".")
        )

        redirect_record = get_spf_record(
            redirect_domain
        )

        if not redirect_record:
            return "permerror"

        return _evaluate_record(
            redirect_record,
            redirect_domain,
            sending_ip,
            depth + 1,
            visited.copy(),
        )

    return "neutral"


def evaluate_spf(
    spf_record: str,
    domain: str,
    sending_ip: str,
) -> str:
    """Evaluate an SPF record."""

    return _evaluate_record(
        spf_record,
        domain,
        sending_ip,
    )


def verify_spf(
    sender: str,
    headers: str | dict[str, Any],
) -> dict[str, Any]:
    """
    Perform direct SPF verification.

    Returns a unified result dictionary.
    """

    domain = extract_sender_domain(sender)

    sending_ip = extract_sending_ip(headers)

    result: dict[str, Any] = {
        "result": "none",
        "domain": domain,
        "sending_ip": sending_ip,
        "record": None,
        "method": "direct_dns",
        "error": None,
    }

    if not domain:
        result["error"] = (
            "Unable to extract sender domain."
        )
        return result

    if not sending_ip:
        result["error"] = (
            "Unable to determine public sending IP."
        )
        return result

    record = get_spf_record(domain)

    if not record:
        result["error"] = (
            "No valid SPF TXT record found."
        )
        return result

    result["record"] = record

    result["result"] = evaluate_spf(
        record,
        domain,
        sending_ip,
    )

    return result