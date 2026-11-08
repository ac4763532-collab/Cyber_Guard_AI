"""
CyberGuard AI — Datetime Utilities
============================================================================
Timezone-aware UTC datetime helpers used throughout the platform.
Enforces UTC correctness across models, schemas, and services.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional


def utcnow() -> datetime:
    """Return the current time in UTC with explicit timezone awareness."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Ensure a datetime is timezone-aware and converted to UTC.
    If naive, assume UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso_z(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime as ISO 8601 string ending with 'Z'."""
    if dt is None:
        return None
    utc_dt = ensure_utc(dt)
    return utc_dt.isoformat().replace("+00:00", "Z")


def from_iso(iso_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 string into a timezone-aware UTC datetime."""
    if not iso_str:
        return None
    cleaned = iso_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    return ensure_utc(dt)


def format_human(dt: Optional[datetime]) -> str:
    """Format datetime into human-readable string (e.g., 'Nov 08, 2026 02:45 UTC')."""
    if dt is None:
        return "Never"
    utc_dt = ensure_utc(dt)
    return utc_dt.strftime("%b %d, %Y %H:%M UTC")


def is_stale(dt: Optional[datetime], threshold_minutes: int = 15) -> bool:
    """Return True if dt is older than threshold_minutes ago or None."""
    if dt is None:
        return True
    utc_dt = ensure_utc(dt)
    return (utcnow() - utc_dt) > timedelta(minutes=threshold_minutes)
