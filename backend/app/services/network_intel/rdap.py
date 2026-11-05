"""
CyberGuard AI - RDAP Lookup (free, no API key)

Uses rdap.org's free bootstrap redirector, which forwards the request to
the authoritative RDAP server for the queried domain or IP. No key
required.

Honesty contract: a 404 (no record) or any transport failure sets
`available: False` + a plain `error` message - fields are never left
blank in a way that could be mistaken for "we found an empty record."
"""

import httpx
import structlog

from app.services.circuit_breaker import get_circuit_breaker
from app.utils.network import is_ip_address

logger = structlog.get_logger(__name__)

RDAP_BASE_URL = "https://rdap.org"
RDAP_TIMEOUT_SECONDS = 8.0


def _unavailable(error: str) -> dict:
    return {
        "configured": True,
        "available": False,
        "registrar": None,
        "created_date": None,
        "updated_date": None,
        "status": [],
        "nameservers": [],
        "raw_handle": None,
        "error": error,
    }


async def lookup_rdap(target: str) -> dict:
    """
    Look up RDAP registration info for a domain or IP via rdap.org's
    bootstrap redirector.
    """
    circuit = get_circuit_breaker("rdap", failure_threshold=5, recovery_timeout_seconds=60)

    if not await circuit.allow_request():
        return _unavailable("RDAP service temporarily unavailable (circuit open)")

    path = f"/ip/{target}" if is_ip_address(target) else f"/domain/{target}"

    try:
        async with httpx.AsyncClient(timeout=RDAP_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = await client.get(f"{RDAP_BASE_URL}{path}")
            if response.status_code == 404:
                await circuit.record_success()
                return _unavailable("No RDAP record found")
            response.raise_for_status()
            data = response.json()
            await circuit.record_success()
    except httpx.TimeoutException:
        await circuit.record_failure()
        return _unavailable("RDAP lookup timed out")
    except Exception as e:
        await circuit.record_failure()
        logger.warning("RDAP lookup failed", target=target[:60], error=str(e))
        return _unavailable(f"RDAP lookup failed: {e}")

    return _parse_rdap(data)


def _parse_rdap(data: dict) -> dict:
    """Normalize an RDAP response down to the small subset we display."""
    registrar = None
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        registrar = field[3]
                        break
            if not registrar:
                registrar = entity.get("handle")
            break

    created_date = None
    updated_date = None
    for event in data.get("events", []):
        action = event.get("eventAction")
        if action == "registration":
            created_date = event.get("eventDate")
        elif action == "last changed":
            updated_date = event.get("eventDate")

    nameservers = [
        ns.get("ldhName")
        for ns in data.get("nameservers", [])
        if ns.get("ldhName")
    ]

    return {
        "configured": True,
        "available": True,
        "registrar": registrar,
        "created_date": created_date,
        "updated_date": updated_date,
        "status": data.get("status", []),
        "nameservers": nameservers,
        "raw_handle": data.get("handle"),
        "error": None,
    }
