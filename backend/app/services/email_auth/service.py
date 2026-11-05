"""
Unified email authentication service.

Authentication flow:
1. Use Authentication-Results headers when available.
2. Otherwise perform direct SPF/DKIM/DMARC verification when raw
   email data is available.
3. Return one consistent authentication result.
"""

from __future__ import annotations

from typing import Any

from .dmarc_checker import verify_dmarc
from .dkim_verifier import (
    extract_dkim_identity,
    verify_dkim,
)
from .spf_verifier import (
    extract_sender_domain,
    verify_spf,
)


def _normalize_result(value: Any) -> str:
    """Normalize an authentication result."""

    if isinstance(value, dict):
        value = value.get("result")

    if value is None:
        return "none"

    value = str(value).strip().lower()

    valid = {
        "pass",
        "fail",
        "softfail",
        "neutral",
        "none",
        "temperror",
        "permerror",
    }

    return value if value in valid else "none"


def _has_authentication_results(
    headers: dict[str, Any] | str | None,
) -> bool:
    """Check whether Authentication-Results exists."""

    if not headers:
        return False

    if isinstance(headers, dict):
        for key in headers:
            if key.lower() == "authentication-results":
                return True

        return False

    text = str(headers)

    return "authentication-results:" in text.lower()


def parse_authentication_results(
    headers: dict[str, Any] | str | None,
) -> dict[str, Any]:
    """
    Parse Authentication-Results headers.

    Supports common:
        spf=pass
        dkim=pass
        dmarc=pass
        header.from=example.com
        header.d=example.com
    """

    result: dict[str, Any] = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "spf_domain": None,
        "dkim_domain": None,
        "from_domain": None,
        "method": "authentication_results",
    }

    if not headers:
        return result

    if isinstance(headers, dict):
        values: list[str] = []

        for key, value in headers.items():
            if key.lower() == "authentication-results":
                if isinstance(value, list):
                    values.extend(str(v) for v in value)
                else:
                    values.append(str(value))

        text = "\n".join(values)

    else:
        text = str(headers)

    if not text:
        return result

    # SPF result.
    import re

    match = re.search(
        r"\bspf\s*=\s*([a-zA-Z]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["spf"] = _normalize_result(
            match.group(1)
        )

    # DKIM result.
    match = re.search(
        r"\bdkim\s*=\s*([a-zA-Z]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["dkim"] = _normalize_result(
            match.group(1)
        )

    # DMARC result.
    match = re.search(
        r"\bdmarc\s*=\s*([a-zA-Z]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["dmarc"] = _normalize_result(
            match.group(1)
        )

    # SPF authentication domain.
    match = re.search(
        r"\bspf\s*=\s*[a-zA-Z]+"
        r"(?:\s+\([^)]+\))?"
        r"(?:\s+smtp\.mailfrom=|\s+mailfrom=)"
        r"([^\s;]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["spf_domain"] = (
            extract_sender_domain(
                match.group(1)
            )
            or match.group(1).strip().lower().rstrip(".")
        )

    # DKIM signing domain.
    match = re.search(
        r"\bdkim\s*=\s*[a-zA-Z]+"
        r"(?:\s+header\.d=|\s+d=)"
        r"([^\s;]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["dkim_domain"] = (
            match.group(1)
            .strip()
            .lower()
            .rstrip(".")
        )

    # From domain used for DMARC alignment.
    match = re.search(
        r"\bheader\.from\s*=\s*([^\s;]+)",
        text,
        flags=re.IGNORECASE,
    )

    if match:
        result["from_domain"] = (
            match.group(1)
            .strip()
            .lower()
            .rstrip(".")
        )

    return result


def authenticate_email(
    sender: str,
    headers: dict[str, Any] | str | None = None,
    raw_email: bytes | str | None = None,
    authentication: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform unified SPF, DKIM and DMARC authentication.

    Priority:
        1. Explicit authentication data
        2. Authentication-Results header
        3. Direct DNS/raw-email verification
    """

    result: dict[str, Any] = {
        "spf": {
            "result": "none",
            "method": None,
            "domain": None,
        },
        "dkim": {
            "result": "none",
            "method": None,
            "domain": None,
            "selector": None,
        },
        "dmarc": {
            "result": "none",
            "method": None,
            "domain": None,
            "policy": None,
            "spf_aligned": False,
            "dkim_aligned": False,
        },
        "source": "none",
        "errors": [],
    }

    # ---------------------------------------------------------
    # 1. Explicit authentication data supplied by Gmail/API.
    # ---------------------------------------------------------
    if authentication:
        parsed = authentication

        spf_data = parsed.get("spf", "none")
        dkim_data = parsed.get("dkim", "none")
        dmarc_data = parsed.get("dmarc", "none")

        result["spf"]["result"] = _normalize_result(
            spf_data
        )
        result["dkim"]["result"] = _normalize_result(
            dkim_data
        )
        result["dmarc"]["result"] = _normalize_result(
            dmarc_data
        )

        if isinstance(spf_data, dict):
            result["spf"]["domain"] = spf_data.get(
                "domain"
            )

        if isinstance(dkim_data, dict):
            result["dkim"]["domain"] = dkim_data.get(
                "domain"
            )
            result["dkim"]["selector"] = dkim_data.get(
                "selector"
            )

        if isinstance(dmarc_data, dict):
            result["dmarc"]["domain"] = dmarc_data.get(
                "domain"
            )
            result["dmarc"]["policy"] = dmarc_data.get(
                "policy"
            )

        result["source"] = "provided_authentication"

        return result

    # ---------------------------------------------------------
    # 2. Authentication-Results header.
    # ---------------------------------------------------------
    if _has_authentication_results(headers):
        parsed = parse_authentication_results(
            headers
        )

        result["spf"]["result"] = parsed["spf"]
        result["spf"]["domain"] = parsed["spf_domain"]
        result["spf"]["method"] = (
            "authentication_results"
        )

        result["dkim"]["result"] = parsed["dkim"]
        result["dkim"]["domain"] = parsed["dkim_domain"]
        result["dkim"]["method"] = (
            "authentication_results"
        )

        result["dmarc"]["result"] = parsed["dmarc"]
        result["dmarc"]["domain"] = parsed["from_domain"]
        result["dmarc"]["method"] = (
            "authentication_results"
        )

        result["source"] = "authentication_results"

        return result

    # ---------------------------------------------------------
    # 3. Direct SPF verification.
    # ---------------------------------------------------------
    spf = verify_spf(
        sender=sender,
        headers=headers or "",
    )

    result["spf"] = {
        "result": spf.get("result", "none"),
        "method": spf.get("method"),
        "domain": spf.get("domain"),
        "sending_ip": spf.get("sending_ip"),
        "record": spf.get("record"),
    }

    if spf.get("error"):
        result["errors"].append(
            f"SPF: {spf['error']}"
        )

    # ---------------------------------------------------------
    # 4. Direct DKIM verification.
    # ---------------------------------------------------------
    dkim_result: dict[str, Any]

    if raw_email:
        dkim_result = verify_dkim(
            raw_email
        )
    else:
        dkim_result = {
            "result": "none",
            "domain": None,
            "selector": None,
            "algorithm": None,
            "method": "dkimpy_dns",
            "error": (
                "Raw email unavailable for DKIM verification."
            ),
        }

    result["dkim"] = {
        "result": dkim_result.get(
            "result",
            "none",
        ),
        "method": dkim_result.get(
            "method"
        ),
        "domain": dkim_result.get(
            "domain"
        ),
        "selector": dkim_result.get(
            "selector"
        ),
        "algorithm": dkim_result.get(
            "algorithm"
        ),
    }

    if dkim_result.get("error"):
        result["errors"].append(
            f"DKIM: {dkim_result['error']}"
        )

    # ---------------------------------------------------------
    # 5. Direct DMARC verification.
    # ---------------------------------------------------------
    dkim_identity = extract_dkim_identity(
        raw_email or ""
    )

    dkim_domain = (
        dkim_result.get("domain")
        or dkim_identity.get("domain")
    )

    dmarc = verify_dmarc(
        sender=sender,
        spf_result=spf.get("result"),
        spf_domain=spf.get("domain"),
        dkim_result=dkim_result.get(
            "result"
        ),
        dkim_domain=dkim_domain,
    )

    result["dmarc"] = {
        "result": dmarc.get(
            "result",
            "none",
        ),
        "method": dmarc.get(
            "method"
        ),
        "domain": dmarc.get(
            "domain"
        ),
        "policy": dmarc.get(
            "policy"
        ),
        "spf_aligned": dmarc.get(
            "spf_aligned",
            False,
        ),
        "dkim_aligned": dmarc.get(
            "dkim_aligned",
            False,
        ),
    }

    if dmarc.get("error"):
        result["errors"].append(
            f"DMARC: {dmarc['error']}"
        )

    result["source"] = "direct_verification"

    return result