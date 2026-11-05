"""Attachment hash computation and VirusTotal reputation."""

from __future__ import annotations

import hashlib

from app.cache.redis_client import get_redis_client
from app.services.threat_intel.service import IOCType, ThreatIntelService


MALICIOUS_CACHE_TTL = 3600
CLEAN_CACHE_TTL = 86400


def compute_hashes(file_bytes: bytes) -> dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes for file bytes."""
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")

    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


async def check_hash_virustotal(file_hash: str) -> dict:
    """Look up a file hash using the existing VirusTotal integration."""
    if not isinstance(file_hash, str) or not file_hash.strip():
        return {
            "hash": file_hash,
            "detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "threat_names": [],
            "error": "Invalid file hash",
        }

    file_hash = file_hash.strip().lower()

    service = ThreatIntelService()

    if not service.settings.virustotal_api_key:
        return {
            "hash": file_hash,
            "detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "threat_names": [],
            "error": None,
        }

    try:
        result = await service.lookup(IOCType.HASH_SHA256, file_hash)
        vt = result.details.get("virustotal", {})

        if vt.get("not_found"):
            return {
                "hash": file_hash,
                "detected": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "verdict": "unknown",
                "threat_names": [],
                "error": None,
            }

        malicious_count = int(vt.get("malicious_count", 0))
        suspicious_count = int(vt.get("suspicious_count", 0))
        total_engines = int(vt.get("total_engines", 0))

        if malicious_count > 0:
            verdict = "malicious"
        elif suspicious_count > 0:
            verdict = "suspicious"
        elif total_engines > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        return {
            "hash": file_hash,
            "detected": malicious_count > 0,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines": total_engines,
            "verdict": verdict,
            "threat_names": vt.get("names", []),
            "type_description": vt.get("type_description", ""),
            "type_tag": vt.get("type_tag", ""),
            "size": vt.get("size", 0),
            "error": result.error,
        }

    except Exception as exc:
        return {
            "hash": file_hash,
            "detected": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "threat_names": [],
            "error": str(exc),
        }


async def check_hash_reputation(file_bytes: bytes) -> dict:
    """Compute hashes and check the SHA256 reputation with Redis caching."""
    hashes = compute_hashes(file_bytes)
    sha256 = hashes["sha256"]
    cache_key = f"attachment:hash:{sha256}"

    redis_client = None

    # Try Redis cache first.
    try:
        redis_client = await get_redis_client()
        cached = await redis_client.get_json(cache_key)

        if cached is not None:
            cached["cache_hit"] = True
            return {
                "hashes": hashes,
                "reputation": cached,
                "cache_hit": True,
            }
    except Exception:
        redis_client = None

    reputation = await check_hash_virustotal(sha256)

    # Cache malicious/suspicious results for 1 hour.
    # Cache clean/unknown results for 24 hours.
    ttl = (
        MALICIOUS_CACHE_TTL
        if reputation.get("verdict") in {"malicious", "suspicious"}
        else CLEAN_CACHE_TTL
    )

    if redis_client is not None:
        try:
            await redis_client.set_json(
                cache_key,
                reputation,
                ttl=ttl,
            )
        except Exception:
            pass

    return {
        "hashes": hashes,
        "reputation": reputation,
        "cache_hit": False,
    }

