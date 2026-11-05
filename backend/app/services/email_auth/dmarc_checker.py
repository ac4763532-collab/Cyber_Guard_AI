"""
Direct DMARC verification for email authentication.

This module:
- retrieves the DMARC policy from DNS
- parses the published policy
- checks SPF/DKIM domain alignment
- calculates an effective DMARC result
"""

from __future__ import annotations

import re
from typing import Any

import dns.resolver


DMARC_RESULTS = {
    "pass": "pass",
    "fail": "fail",
    "none": "none",
}


def extract_domain_from_email(email_address: str) -> str | None:
    """Extract a normalized domain from an email address."""

    if not email_address:
        return None

    match = re.search(
        r"<\s*[^<>@\s]+@([^<>\s]+)\s*>",
        email_address,
    )

    if not match:
        match = re.search(
            r"\b[^@\s<>]+@([^@\s<>]+)\b",
            email_address,
        )

    if not match:
        return None

    return match.group(1).strip().lower().rstrip(".")


def get_dmarc_record(domain: str) -> str | None:
    """Retrieve the DMARC TXT record for a domain."""

    if not domain:
        return None

    try:
        answers = dns.resolver.resolve(
            f"_dmarc.{domain}",
            "TXT",
        )

        records: list[str] = []

        for answer in answers:
            try:
                text = "".join(
                    part.decode(
                        "utf-8",
                        errors="replace",
                    )
                    if isinstance(part, bytes)
                    else str(part)
                    for part in answer.strings
                )
            except AttributeError:
                text = str(answer).strip('"')

            if text.lower().startswith("v=dmarc1"):
                records.append(text)

        if not records:
            return None

        if len(records) > 1:
            # Multiple DMARC records are invalid.
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


def parse_dmarc_record(record: str) -> dict[str, Any]:
    """
    Parse a DMARC record into a dictionary.

    Important fields:
    - p: policy
    - sp: subdomain policy
    - adkim: DKIM alignment mode
    - aspf: SPF alignment mode
    """

    parsed: dict[str, Any] = {
        "version": None,
        "policy": None,
        "subdomain_policy": None,
        "dkim_alignment": "r",
        "spf_alignment": "r",
        "percentage": 100,
    }

    if not record:
        return parsed

    parts = record.split(";")

    for part in parts:
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        key = key.strip().lower()
        value = value.strip()

        if key == "v":
            parsed["version"] = value

        elif key == "p":
            policy = value.lower()

            if policy in {"none", "quarantine", "reject"}:
                parsed["policy"] = policy

        elif key == "sp":
            policy = value.lower()

            if policy in {"none", "quarantine", "reject"}:
                parsed["subdomain_policy"] = policy

        elif key == "adkim":
            if value.lower() in {"r", "s"}:
                parsed["dkim_alignment"] = value.lower()

        elif key == "aspf":
            if value.lower() in {"r", "s"}:
                parsed["spf_alignment"] = value.lower()

        elif key == "pct":
            try:
                percentage = int(value)

                if 0 <= percentage <= 100:
                    parsed["percentage"] = percentage

            except ValueError:
                pass

    return parsed


def _organizational_domain(domain: str) -> str:
    """
    Conservative organizational-domain approximation.

    Full Public Suffix List handling is outside this module.
    """

    domain = domain.lower().rstrip(".")

    parts = domain.split(".")

    if len(parts) <= 2:
        return domain

    return ".".join(parts[-2:])


def domains_align(
    from_domain: str | None,
    auth_domain: str | None,
    mode: str = "r",
) -> bool:
    """
    Check DMARC domain alignment.

    Relaxed alignment:
        same organizational domain

    Strict alignment:
        exact domain match
    """

    if not from_domain or not auth_domain:
        return False

    from_domain = from_domain.lower().rstrip(".")
    auth_domain = auth_domain.lower().rstrip(".")

    if mode == "s":
        return from_domain == auth_domain

    return (
        _organizational_domain(from_domain)
        == _organizational_domain(auth_domain)
    )


def evaluate_dmarc(
    from_domain: str | None,
    dmarc_record: str | None,
    spf_result: str | None,
    spf_domain: str | None,
    dkim_result: str | None,
    dkim_domain: str | None,
) -> dict[str, Any]:
    """
    Calculate the effective DMARC result.

    DMARC passes when:
        aligned SPF passes
        OR
        aligned DKIM passes
    """

    result: dict[str, Any] = {
        "result": "none",
        "policy": None,
        "spf_aligned": False,
        "dkim_aligned": False,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "domain": from_domain,
        "record": dmarc_record,
        "method": "direct_dns",
        "error": None,
    }

    if not from_domain:
        result["error"] = (
            "Unable to determine From domain."
        )
        return result

    if not dmarc_record:
        result["error"] = (
            "No DMARC record found."
        )
        return result

    policy = parse_dmarc_record(
        dmarc_record
    )

    result["policy"] = policy["policy"]

    if policy["version"] != "DMARC1":
        result["error"] = (
            "Invalid DMARC record version."
        )
        return result

    spf_aligned = (
        spf_result == "pass"
        and domains_align(
            from_domain,
            spf_domain,
            policy["spf_alignment"],
        )
    )

    dkim_aligned = (
        dkim_result == "pass"
        and domains_align(
            from_domain,
            dkim_domain,
            policy["dkim_alignment"],
        )
    )

    result["spf_aligned"] = spf_aligned
    result["dkim_aligned"] = dkim_aligned

    if spf_aligned or dkim_aligned:
        result["result"] = "pass"
    else:
        result["result"] = "fail"

    return result


def verify_dmarc(
    sender: str,
    spf_result: str | None = None,
    spf_domain: str | None = None,
    dkim_result: str | None = None,
    dkim_domain: str | None = None,
) -> dict[str, Any]:
    """
    Perform direct DMARC verification.
    """

    from_domain = extract_domain_from_email(
        sender
    )

    result: dict[str, Any] = {
        "result": "none",
        "policy": None,
        "spf_aligned": False,
        "dkim_aligned": False,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "domain": from_domain,
        "record": None,
        "method": "direct_dns",
        "error": None,
    }

    if not from_domain:
        result["error"] = (
            "Unable to extract From domain."
        )
        return result

    record = get_dmarc_record(
        from_domain
    )

    result["record"] = record

    return evaluate_dmarc(
        from_domain=from_domain,
        dmarc_record=record,
        spf_result=spf_result,
        spf_domain=spf_domain,
        dkim_result=dkim_result,
        dkim_domain=dkim_domain,
    )