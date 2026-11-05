"""
CyberGuard AI - DNS Lookup (free, no API key)

Forward (domain -> IP) and reverse (IP -> hostname) DNS lookups using the
Python standard library's `socket` module. No new dependency, no API key,
no quota to manage.

Honesty contract: a lookup that finds nothing sets `error` and leaves the
other fields empty - it never fabricates a hostname or IP.
"""

import asyncio
import socket

from app.utils.network import is_ip_address

DNS_TIMEOUT_SECONDS = 5.0


async def resolve_dns(target: str) -> dict:
    """
    Resolve `target` via DNS.

    - If `target` is an IP address, performs a reverse (PTR-style) lookup
      to find its hostname.
    - If `target` is a domain, performs a forward lookup to find its IP(s).

    Returns a dict:
        {
            "query_type": "forward" | "reverse",
            "hostname": str | None,
            "resolved_ips": list[str],
            "aliases": list[str],
            "error": str | None,
        }
    """
    target = target.strip()
    loop = asyncio.get_event_loop()

    if is_ip_address(target):
        return await _reverse_lookup(target, loop)
    return await _forward_lookup(target, loop)


async def _forward_lookup(domain: str, loop: asyncio.AbstractEventLoop) -> dict:
    try:
        hostname, aliases, ips = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname_ex, domain),
            timeout=DNS_TIMEOUT_SECONDS,
        )
        return {
            "query_type": "forward",
            "hostname": hostname,
            "resolved_ips": ips,
            "aliases": aliases,
            "error": None,
        }
    except asyncio.TimeoutError:
        return _empty_result("forward", "DNS lookup timed out")
    except socket.gaierror:
        return _empty_result("forward", "No DNS record found for this domain")
    except Exception as e:
        return _empty_result("forward", f"DNS lookup failed: {e}")


async def _reverse_lookup(ip: str, loop: asyncio.AbstractEventLoop) -> dict:
    try:
        hostname, aliases, _ips = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=DNS_TIMEOUT_SECONDS,
        )
        return {
            "query_type": "reverse",
            "hostname": hostname,
            "resolved_ips": [ip],
            "aliases": aliases,
            "error": None,
        }
    except asyncio.TimeoutError:
        return _empty_result("reverse", "DNS lookup timed out")
    except socket.herror:
        return _empty_result("reverse", "No reverse DNS record for this IP")
    except Exception as e:
        return _empty_result("reverse", f"DNS lookup failed: {e}")


def _empty_result(query_type: str, error: str) -> dict:
    return {
        "query_type": query_type,
        "hostname": None,
        "resolved_ips": [],
        "aliases": [],
        "error": error,
    }
