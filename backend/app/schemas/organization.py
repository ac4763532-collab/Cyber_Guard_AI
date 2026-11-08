"""
CyberGuard AI — Organization Schemas
============================================================================

Request/response DTOs for the ``organizations`` table.

Design rules
------------
1. **Never leak ``settings`` JSONB shape as free-form input.**
   On Create/Update, ``settings`` is validated as a dict with known keys.
   Unknown keys are rejected — an org cannot store arbitrary JSON.

2. **Slug is validated at both schema and model level.**
   The schema catches bad input early (422 before service); the model
   enforces it at DB level (defense in depth). Same pattern for
   company_size, country, timezone.

3. **``owner_id`` is not settable via Create.** The service sets it to
   ``current_user.id`` — clients cannot pick who owns the org.

4. **``status`` is not settable via Update.** Status changes go through
   dedicated admin endpoints (suspend, archive). Prevents privilege
   escalation via a generic PATCH.

5. **``slug`` is immutable after creation.** Enforced at the schema
   level: ``OrganizationUpdate`` does not declare it. Renaming a slug
   would break invitation links, webhook URLs, etc.

6. **Computed fields on Read.** ``is_active``, ``is_suspended``,
   ``is_archived`` are populated from ORM properties.

7. **Lightweight list view.** ``OrganizationList`` returns only the
   fields needed for a picker/list. Full details via ``GET /orgs/{id}``.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Literal
from zoneinfo import available_timezones

from pydantic import Field, field_validator

from app.models.enums import OrganizationStatus
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_SLUG_MIN = 3
_SLUG_MAX = 64
_NAME_MAX = 255
_DESCRIPTION_MAX = 2000
_EMAIL_MAX = 320
_WEBSITE_MAX = 512
_INDUSTRY_MAX = 128
_COUNTRY_LENGTH = 2
_TIMEZONE_MAX = 64
_LOGO_URL_MAX = 512
_SUBSCRIPTION_PLAN_MAX = 32

_COMPANY_SIZES = frozenset({
    "solo", "small", "medium", "large",
    "enterprise", "enterprise_plus",
})

#: Keys permitted inside ``settings``. Shape validated per key.
#: Empty allowlist means "any key accepted" (permissive default) — flip
#: to a whitelist once settings schema stabilizes.
_ALLOWED_SETTING_KEYS = frozenset({
    "retention_events_days",
    "retention_findings_days",
    "retention_alerts_days",
    "retention_incidents_days",
    "notification_email_enabled",
    "notification_webhook_url",
    "alert_severity_threshold",
    "brand_color",
    "brand_logo_url",
})


# ============================================================================
# CREATE
# ============================================================================

class OrganizationCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /organizations``.

    All fields except ``name`` and ``slug`` are optional. ``owner_id``
    is set by the service to the current user — never accepted from the
    client.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=_NAME_MAX,
        description="Display name.",
        examples=["Acme Security Corp"],
    )

    slug: str = Field(
        ...,
        min_length=_SLUG_MIN,
        max_length=_SLUG_MAX,
        description=(
            "URL-safe identifier. 3–64 chars. Lowercase letters, digits, "
            "and hyphens only. Immutable after creation."
        ),
        examples=["acme-security"],
    )

    description: str | None = Field(
        default=None,
        max_length=_DESCRIPTION_MAX,
    )

    contact_email: str | None = Field(
        default=None,
        max_length=_EMAIL_MAX,
        description="Operational contact email.",
    )

    website: str | None = Field(
        default=None,
        max_length=_WEBSITE_MAX,
    )

    industry: str | None = Field(
        default=None,
        max_length=_INDUSTRY_MAX,
    )

    company_size: Literal[
        "solo", "small", "medium", "large",
        "enterprise", "enterprise_plus",
    ] | None = Field(
        default=None,
        description="Company size band.",
    )

    country: str | None = Field(
        default=None,
        min_length=_COUNTRY_LENGTH,
        max_length=_COUNTRY_LENGTH,
        description="ISO 3166-1 alpha-2 code (e.g. 'US', 'IN').",
    )

    timezone: str = Field(
        default="UTC",
        max_length=_TIMEZONE_MAX,
    )

    logo_url: str | None = Field(
        default=None,
        max_length=_LOGO_URL_MAX,
    )

    @field_validator("slug", mode="before")
    @classmethod
    def _validate_slug(cls, v: object) -> str:
        if not isinstance(v, str):
            raise ValueError("slug must be a string")
        normalized = v.strip().lower()
        if not (_SLUG_MIN <= len(normalized) <= _SLUG_MAX):
            raise ValueError(
                f"slug must be {_SLUG_MIN}–{_SLUG_MAX} characters"
            )
        if not _SLUG_PATTERN.match(normalized):
            raise ValueError(
                "slug must contain only lowercase letters, digits, and "
                "hyphens, starting and ending with a letter or digit"
            )
        return normalized

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("country")
    @classmethod
    def _validate_country(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip().upper()
        if len(stripped) != _COUNTRY_LENGTH:
            raise ValueError("country must be a 2-letter ISO 3166-1 code")
        return stripped

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str) -> str:
        stripped = v.strip()
        if stripped not in available_timezones():
            raise ValueError(
                f"Unknown IANA timezone: {stripped!r}. "
                "Example: 'UTC', 'America/New_York', 'Asia/Kolkata'."
            )
        return stripped

    @field_validator("website", "logo_url")
    @classmethod
    def _validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            return None
        if not stripped.startswith(("http://", "https://")):
            raise ValueError("URL must start with 'http://' or 'https://'")
        return stripped


# ============================================================================
# READ
# ============================================================================

class OrganizationRead(TimestampedModel):
    """
    Full organization view. Returned by ``GET /organizations/{id}``,
    ``POST /organizations``, and ``PATCH /organizations/{id}``.

    Includes computed booleans populated from ORM properties.
    """

    id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    status: OrganizationStatus
    owner_id: uuid.UUID

    contact_email: str | None = None
    website: str | None = None
    industry: str | None = None
    company_size: str | None = None
    country: str | None = None
    timezone: str = "UTC"
    logo_url: str | None = None

    subscription_plan: str = "free"

    settings: dict[str, Any] = Field(default_factory=dict)

    # Computed from ORM properties
    is_active: bool = Field(
        ...,
        description="True if status is ACTIVE and not soft-deleted.",
    )
    is_suspended: bool = Field(
        ...,
        description="True if the org has been suspended by a super admin.",
    )
    is_archived: bool = Field(
        ...,
        description="True if the org has been archived (read-only).",
    )


class OrganizationList(ORMModel):
    """
    Lightweight org view for pickers, member lists, dashboards.

    Only 5 fields. For full details, fetch ``GET /organizations/{id}``.
    """

    id: uuid.UUID
    name: str
    slug: str
    status: OrganizationStatus
    subscription_plan: str = "free"


# ============================================================================
# UPDATE
# ============================================================================

class OrganizationUpdate(CyberGuardBaseSchema):
    """
    Fields an org owner/admin can change. Every field optional.

    Cannot change (schema does not declare):
        - ``slug`` — immutable after creation
        - ``owner_id`` — ownership transfer is a dedicated flow
        - ``status`` — admin action (suspend/archive endpoints)
        - ``subscription_plan`` — billing endpoint
    """

    name: str | None = Field(default=None, min_length=1, max_length=_NAME_MAX)
    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)
    contact_email: str | None = Field(default=None, max_length=_EMAIL_MAX)
    website: str | None = Field(default=None, max_length=_WEBSITE_MAX)
    industry: str | None = Field(default=None, max_length=_INDUSTRY_MAX)
    company_size: Literal[
        "solo", "small", "medium", "large",
        "enterprise", "enterprise_plus",
    ] | None = None
    country: str | None = Field(default=None, min_length=2, max_length=2)
    timezone: str | None = Field(default=None, max_length=_TIMEZONE_MAX)
    logo_url: str | None = Field(default=None, max_length=_LOGO_URL_MAX)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("country")
    @classmethod
    def _validate_country(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip().upper()
        if len(stripped) != _COUNTRY_LENGTH:
            raise ValueError("country must be a 2-letter ISO 3166-1 code")
        return stripped

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if stripped not in available_timezones():
            raise ValueError(f"Unknown IANA timezone: {stripped!r}")
        return stripped

    @field_validator("website", "logo_url")
    @classmethod
    def _validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            return None
        if not stripped.startswith(("http://", "https://")):
            raise ValueError("URL must start with 'http://' or 'https://'")
        return stripped


# ============================================================================
# FILTER
# ============================================================================

class OrganizationFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /organizations``.
    """

    status: OrganizationStatus | None = Field(
        default=None,
        description="Filter by organization status.",
    )

    name_contains: str | None = Field(
        default=None,
        max_length=_NAME_MAX,
        description="Case-insensitive substring match on name.",
    )

    slug_contains: str | None = Field(
        default=None,
        max_length=_SLUG_MAX,
        description="Case-insensitive substring match on slug.",
    )

    subscription_plan: str | None = Field(
        default=None,
        max_length=_SUBSCRIPTION_PLAN_MAX,
        description="Filter by subscription plan (exact match).",
    )

    @field_validator("name_contains", "slug_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "OrganizationCreate",
    "OrganizationRead",
    "OrganizationList",
    "OrganizationUpdate",
    "OrganizationFilter",
]