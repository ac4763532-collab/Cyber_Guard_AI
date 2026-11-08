"""
CyberGuard AI — ID Generator Utilities
============================================================================
Generates human-readable, typed, collision-resistant identifiers for
CyberGuard entities (Users, Analysts, Alerts, Incidents, Cases, Rooms).
"""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import datetime, timezone


def generate_uuid() -> uuid.UUID:
    """Generate a standard UUIDv4."""
    return uuid.uuid4()


def generate_uuid_str() -> str:
    """Generate a standard UUIDv4 as a string."""
    return str(uuid.uuid4())


def generate_user_id(role: str = "individual") -> str:
    """
    Generate CyberGuard unique ID for user personas:
    - Normal User:  CGU-XXXXX
    - Security Analyst: CGU-AN-XXXXX
    - Org Admin: CGU-ORG-XXXXX
    """
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(5))
    norm_role = role.lower() if role else "individual"
    if "analyst" in norm_role:
        return f"CGU-AN-{suffix}"
    if "org" in norm_role or "company" in norm_role:
        return f"CGU-ORG-{suffix}"
    return f"CGU-{suffix}"


def generate_incident_id() -> str:
    """Generate incident ID: INC-YYYYMMDD-XXXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(4))
    return f"INC-{date_str}-{suffix}"


def generate_alert_id() -> str:
    """Generate alert ID: ALT-YYYYMMDD-XXXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(4))
    return f"ALT-{date_str}-{suffix}"


def generate_case_id() -> str:
    """Generate case ID: CASE-YYYY-XXXX."""
    year_str = datetime.now(timezone.utc).strftime("%Y")
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(4))
    return f"CASE-{year_str}-{suffix}"


def generate_enrollment_token() -> str:
    """Generate secure 32-character hexadecimal enrollment token."""
    return secrets.token_hex(16)


def generate_room_code() -> str:
    """Generate human-readable room join/reference code (e.g., ROOM-7X9B)."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(4))
    return f"ROOM-{suffix}"


def generate_public_slug(name_or_email: str | None = None, role: str = "individual") -> str:
    """
    Generate globally unique human-readable public slug alias:
    - Individual: <name>-user-000184
    - Analyst: <name>-analyst-000042
    - Organizer: <name>-organizer-000012
    """
    import re
    norm_role = role.lower() if role else "individual"
    if "analyst" in norm_role:
        role_tag = "analyst"
    elif "org" in norm_role or "company" in norm_role:
        role_tag = "organizer"
    else:
        role_tag = "user"

    base_name = "user"
    if name_or_email:
        raw = name_or_email.split("@")[0].strip().lower()
        cleaned = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
        if cleaned:
            base_name = cleaned[:24]

    num_suffix = f"{secrets.randbelow(900000) + 100000:06d}"
    return f"{base_name}-{role_tag}-{num_suffix}"
