"""
Direct DKIM verification for raw email messages.

Uses dkimpy to validate the DKIM-Signature against the
public key published in DNS.
"""

from __future__ import annotations

import re
from typing import Any

import dkim


def _header_value(
    headers: str | bytes | dict[str, Any],
    name: str,
) -> str | None:
    """Extract the first matching header value."""

    if isinstance(headers, dict):
        for key, value in headers.items():
            if key.lower() == name.lower():
                if isinstance(value, list):
                    return str(value[0]) if value else None
                return str(value)

        return None

    if isinstance(headers, bytes):
        text = headers.decode("utf-8", errors="replace")
    else:
        text = headers or ""

    pattern = rf"(?im)^{re.escape(name)}\s*:\s*(.+?)(?=\r?\n[!-9;-~]+\s*:|\r?\n\r?\n|$)"

    match = re.search(pattern, text, flags=re.DOTALL)

    if not match:
        return None

    return re.sub(
        r"\r?\n[ \t]+",
        " ",
        match.group(1),
    ).strip()


def parse_dkim_signature(
    headers: str | bytes | dict[str, Any],
) -> dict[str, str] | None:
    """Extract important DKIM-Signature tags."""

    value = _header_value(
        headers,
        "DKIM-Signature",
    )

    if not value:
        return None

    tags: dict[str, str] = {}

    for part in value.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        key = key.strip().lower()
        value = value.strip()

        if key:
            tags[key] = value

    if not tags:
        return None

    return tags


def extract_dkim_identity(
    headers: str | bytes | dict[str, Any],
) -> dict[str, str | None]:
    """
    Extract DKIM selector and signing domain.
    """

    signature = parse_dkim_signature(headers)

    if not signature:
        return {
            "domain": None,
            "selector": None,
            "algorithm": None,
        }

    return {
        "domain": signature.get("d"),
        "selector": signature.get("s"),
        "algorithm": signature.get("a"),
    }


def verify_dkim(
    raw_email: bytes | str,
) -> dict[str, Any]:
    """
    Verify DKIM signature using dkimpy.

    raw_email must contain the complete raw RFC 5322 message,
    including headers and body.
    """

    if isinstance(raw_email, str):
        raw_email = raw_email.encode(
            "utf-8",
            errors="replace",
        )

    result: dict[str, Any] = {
        "result": "none",
        "domain": None,
        "selector": None,
        "algorithm": None,
        "method": "dkimpy_dns",
        "error": None,
    }

    try:
        signature_headers = raw_email.split(
            b"\r\n\r\n",
            1,
        )[0]

        identity = extract_dkim_identity(
            signature_headers,
        )

        result["domain"] = identity["domain"]
        result["selector"] = identity["selector"]
        result["algorithm"] = identity["algorithm"]

        if not identity["domain"]:
            result["error"] = (
                "DKIM signature does not contain a signing domain."
            )
            return result

        if not identity["selector"]:
            result["error"] = (
                "DKIM signature does not contain a selector."
            )
            return result

        has_signature = dkim.verify(raw_email)

        result["result"] = (
            "pass"
            if has_signature
            else "fail"
        )

        if not has_signature:
            result["error"] = (
                "DKIM signature verification failed."
            )

        return result

    except Exception as exc:
        result["result"] = "temperror"
        result["error"] = str(exc)
        return result


def check_dkim_signature(
    raw_email: bytes | str,
) -> dict[str, Any]:
    """
    Compatibility wrapper for callers that prefer
    check_dkim_signature().
    """

    return verify_dkim(raw_email)