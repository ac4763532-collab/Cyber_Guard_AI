"""URL expansion utilities for Safe Link Analysis."""

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from app.cache.redis_client import get_redis_client


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------
# URLs analyzed here are extracted from untrusted, attacker-controlled email
# content (that's the whole point of phishing/URL analysis). Without a
# destination check, a malicious email could point expand_url() at an
# internal service or a cloud metadata endpoint (e.g. http://169.254.169.254/
# ...) and the backend server itself would make that request on the
# attacker's behalf. is_safe_destination() rejects any hostname that
# resolves to a private, loopback, link-local, multicast, or otherwise
# reserved IP address before an outbound request is made, and the same
# check is re-applied after redirects are followed (see expand_url) so a
# URL that looks external at first but redirects to an internal address is
# still caught.

ALLOWED_SCHEMES = {"http", "https"}


def is_safe_destination(url: str) -> tuple[bool, str | None]:
    """Return (True, None) if url's scheme/host are safe to request, else
    (False, reason). Resolves the hostname and rejects private/loopback/
    link-local/reserved/multicast addresses to prevent SSRF."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Could not parse URL"

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme: {parsed.scheme!r}"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    try:
        # getaddrinfo resolves the hostname the same way the HTTP client
        # would (including literal IPs, which parse through unchanged).
        addrinfos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"Could not resolve host: {exc}"

    if not addrinfos:
        return False, "Host did not resolve to any address"

    for family, _, _, _, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Resolved address is not valid: {ip_str}"

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, f"Host resolves to a non-public address ({ip_str})"

    return True, None


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "t.ly",
    "v.gd",
    "qr.ae",
}

CACHE_TTL = 86400


def is_shortened(url: str) -> bool:
    """Return True when the URL belongs to a known URL-shortening service."""
    try:
        hostname = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return False

    return hostname in SHORTENERS or any(
        hostname.endswith(f".{domain}") for domain in SHORTENERS
    )


async def expand_url(url: str, max_redirects: int = 5) -> dict:
    """Follow redirects and return the final destination of a URL."""
    if not isinstance(url, str) or not url.strip():
        return {
            "original": url,
            "final": url,
            "redirect_count": 0,
            "expanded": False,
            "error": "Invalid URL",
            "cache_hit": False,
        }

    url = url.strip()
    cache_key = f"url_expansion:{url}"

    # Try Redis cache first.
    redis_client = None
    try:
        redis_client = await get_redis_client()
        cached = await redis_client.get_json(cache_key)

        if cached is not None:
            cached["cache_hit"] = True
            return cached
    except Exception:
        redis_client = None

    # SSRF guard: reject the starting URL up front if it already resolves
    # to a non-public address. Redirect hops are re-checked below (with
    # follow_redirects disabled) since a safe-looking URL can still
    # redirect into an internal address.
    safe, reason = is_safe_destination(url)
    if not safe:
        return {
            "original": url,
            "final": url,
            "redirect_count": 0,
            "expanded": False,
            "error": f"Blocked for safety: {reason}",
            "cache_hit": False,
        }

    try:
        timeout = httpx.Timeout(5.0)
        current_url = url
        redirect_count = 0
        response = None

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "CyberGuard-AI/1.0 URL Analyzer",
            },
        ) as client:
            while True:
                # HEAD is cheaper than downloading the page body.
                response = await client.head(current_url)

                # Some servers do not support HEAD correctly.
                if response.status_code in {405, 501}:
                    response = await client.get(current_url)

                if response.is_redirect:
                    if redirect_count >= max_redirects:
                        return {
                            "original": url,
                            "final": current_url,
                            "redirect_count": redirect_count,
                            "expanded": False,
                            "error": f"Maximum redirects exceeded ({max_redirects})",
                            "cache_hit": False,
                        }

                    next_url = str(
                        response.next_request.url
                        if response.next_request is not None
                        else response.headers.get("location", current_url)
                    )

                    safe, reason = is_safe_destination(next_url)
                    if not safe:
                        return {
                            "original": url,
                            "final": current_url,
                            "redirect_count": redirect_count,
                            "expanded": False,
                            "error": f"Blocked for safety: redirect target - {reason}",
                            "cache_hit": False,
                        }

                    current_url = next_url
                    redirect_count += 1
                    continue

                break

            final_url = str(response.url)

            result = {
                "original": url,
                "final": final_url,
                "redirect_count": redirect_count,
                "expanded": url != final_url,
                "status_code": response.status_code,
                "error": None,
                "cache_hit": False,
            }

            # Cache successful expansion for 24 hours.
            if redis_client is not None:
                try:
                    await redis_client.set_json(
                        cache_key,
                        result,
                        ttl=CACHE_TTL,
                    )
                except Exception:
                    pass

            return result

    except httpx.TooManyRedirects:
        return {
            "original": url,
            "final": url,
            "redirect_count": max_redirects,
            "expanded": False,
            "error": f"Maximum redirects exceeded ({max_redirects})",
            "cache_hit": False,
        }

    except httpx.TimeoutException:
        return {
            "original": url,
            "final": url,
            "redirect_count": 0,
            "expanded": False,
            "error": "URL expansion timed out",
            "cache_hit": False,
        }

    except Exception as exc:
        return {
            "original": url,
            "final": url,
            "redirect_count": 0,
            "expanded": False,
            "error": str(exc),
            "cache_hit": False,
        }


async def expand_all(
    urls: list[str],
    max_redirects: int = 5,
) -> list[dict]:
    """Expand multiple URLs sequentially and return their results."""
    results = []

    for url in urls:
        results.append(
            await expand_url(
                url,
                max_redirects=max_redirects,
            )
        )

    return results
