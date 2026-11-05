"""
CyberGuard AI - IP Geolocation (free, no API key)

Uses ip-api.com's free JSON endpoint. No key required, but note this is
plain HTTP on the free tier (no HTTPS without a paid key) - only the IP
being looked up is sent, no other data.

Honesty contract: geolocation is always "configured" (no key gate exists
for a free service), but a given lookup can still be "unavailable" (private
IP, rate limited, bad target, network error) - those two concepts are
represented separately so the frontend never mistakes "we didn't check"
for "we checked and found nothing."
"""

import httpx
import structlog

from app.services.circuit_breaker import get_circuit_breaker

logger = structlog.get_logger(__name__)

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"
GEOIP_TIMEOUT_SECONDS = 5.0


def _unavailable(error: str) -> dict:
    return {
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
        "error": error,
    }


async def lookup_geoip(ip: str) -> dict:
    """
    Look up geolocation info for an IPv4 address via ip-api.com.

    Returns a dict with `configured: True` always (no key needed), and
    `available: False` + `error` set whenever the lookup didn't produce
    usable data (private/reserved IP, timeout, rate limit, transport error).
    """
    circuit = get_circuit_breaker("ip_api", failure_threshold=5, recovery_timeout_seconds=60)

    if not await circuit.allow_request():
        return _unavailable("Geolocation service temporarily unavailable (circuit open)")

    try:
        async with httpx.AsyncClient(timeout=GEOIP_TIMEOUT_SECONDS) as client:
            response = await client.get(
                IP_API_URL.format(ip=ip),
                params={"fields": IP_API_FIELDS},
            )
            response.raise_for_status()
            data = response.json()
            await circuit.record_success()
    except httpx.TimeoutException:
        await circuit.record_failure()
        return _unavailable("Geolocation lookup timed out")
    except Exception as e:
        await circuit.record_failure()
        logger.warning("GeoIP lookup failed", ip=ip[:45], error=str(e))
        return _unavailable(f"Geolocation lookup failed: {e}")

    if data.get("status") != "success":
        message = data.get("message", "lookup failed")
        if message == "private range":
            return _unavailable("Geolocation unavailable (private/internal IP address)")
        if message == "reserved range":
            return _unavailable("Geolocation unavailable (reserved IP address)")
        return _unavailable(f"Geolocation unavailable: {message}")

    return {
        "configured": True,
        "available": True,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "error": None,
    }
