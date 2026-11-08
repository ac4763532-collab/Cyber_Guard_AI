"""
CyberGuard AI — Analyst Profile Schemas
============================================================================

Request/response DTOs for analyst profiles.

Three schemas:
    - AnalystProfileApply    — new application (initial submission)
    - AnalystProfileUpdate   — self-service update (all fields optional)
    - AnalystProfileRead     — read view (used by admin endpoints)

Note on AnalystProfileRead
--------------------------
`AnalystProfileRead` includes `verification_notes`, which is
**admin-only** (never shown to the analyst themselves). This is fine
while the only consumer is `admin.py` (super-admin only).

If a user-facing analyst profile endpoint is added later (e.g. an
analyst viewing their own application status), create a separate
`AnalystProfilePublicRead` that omits:
    - verification_notes
    - verified_by_id
Or introduce field-level permissions. Do NOT reuse this schema for
user-facing responses.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from zoneinfo import available_timezones

from pydantic import Field, field_validator

from app.models.enums import AnalystVerificationStatus
from app.schemas.common import (
    CyberGuardBaseSchema,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_SPECIALIZATION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_MAX_CERTIFICATIONS = 50
_MAX_VERIFICATION_DOCUMENTS = 20
_MAX_SPECIALIZATIONS = 20
_MAX_LANGUAGES = 20


# ============================================================================
# INTERNAL VALIDATORS (shared between Apply and Update)
# ============================================================================

def _clean_specializations(v: list[str]) -> list[str]:
    """Deduplicate, lowercase, validate tag format."""
    if len(v) > _MAX_SPECIALIZATIONS:
        raise ValueError(f"too many specializations (max {_MAX_SPECIALIZATIONS})")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in v:
        if not isinstance(item, str):
            raise ValueError("each specialization must be a string")
        normalized = item.strip().lower()
        if not normalized or normalized in seen:
            continue
        if not _SPECIALIZATION_PATTERN.match(normalized):
            raise ValueError(
                f"Invalid specialization tag: {normalized!r}. "
                f"Must be lowercase letters, digits, dashes, or underscores, "
                f"starting with a letter or digit."
            )
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def _clean_certifications(v: list[dict]) -> list[dict]:
    """Validate certification objects."""
    if len(v) > _MAX_CERTIFICATIONS:
        raise ValueError(f"too many certifications (max {_MAX_CERTIFICATIONS})")
    cleaned: list[dict] = []
    for item in v:
        if not isinstance(item, dict):
            raise ValueError("each certification must be an object")
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError("each certification must have a non-empty 'name'")
        cleaned.append({
            "name": name,
            "issuer": str(item.get("issuer", "")).strip() or None,
            "issued_year": item.get("issued_year"),
            "credential_url": str(item.get("credential_url", "")).strip() or None,
        })
    return cleaned


def _clean_verification_documents(v: list[dict]) -> list[dict]:
    """Validate verification document objects."""
    if len(v) > _MAX_VERIFICATION_DOCUMENTS:
        raise ValueError(
            f"too many verification documents (max {_MAX_VERIFICATION_DOCUMENTS})"
        )
    cleaned: list[dict] = []
    for item in v:
        if not isinstance(item, dict):
            raise ValueError("each verification document must be an object")
        doc_type = str(item.get("type", "")).strip()
        url = str(item.get("url", "")).strip()
        if not doc_type or not url:
            raise ValueError(
                "each verification document must have 'type' and 'url'"
            )
        cleaned.append({
            "type": doc_type,
            "url": url,
            "uploaded_at": item.get("uploaded_at"),
        })
    return cleaned


def _clean_languages(v: list[str]) -> list[str]:
    """Validate BCP 47 language tags."""
    if len(v) > _MAX_LANGUAGES:
        raise ValueError(f"too many languages (max {_MAX_LANGUAGES})")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in v:
        if not isinstance(item, str):
            raise ValueError("each language must be a string")
        normalized = item.strip().lower()
        if not normalized or normalized in seen:
            continue
        if not (2 <= len(normalized) <= 8):
            raise ValueError(
                f"language tag {normalized!r} must be 2–8 characters"
            )
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def _validate_currency(v: str | None) -> str | None:
    if v is None:
        return None
    normalized = v.strip().upper()
    if len(normalized) != 3:
        raise ValueError("currency must be a 3-letter ISO 4217 code")
    return normalized


def _validate_timezone(v: str) -> str:
    stripped = v.strip()
    if stripped not in available_timezones():
        raise ValueError(
            f"Unknown IANA timezone: {stripped!r}. "
            f"Example: 'UTC', 'America/New_York', 'Asia/Kolkata'."
        )
    return stripped


# ============================================================================
# APPLY
# ============================================================================

class AnalystProfileApply(CyberGuardBaseSchema):
    """
    Request body for a **new** analyst application.

    Submitted once. Can be re-submitted after a rejection (30-day
    cooldown) — the service resets the row to PENDING with new data.
    """

    display_name: str = Field(
        ...,
        min_length=1,
        max_length=120,
        description="Public display name for marketplace and case cards.",
    )
    headline: str | None = Field(
        default=None, max_length=200,
        description="One-line tagline (e.g. 'Phishing & email-forensics specialist').",
    )
    bio: str | None = Field(
        default=None, max_length=5000,
        description="Long-form bio shown on the analyst's public profile page.",
    )

    specializations: list[str] = Field(
        default_factory=list,
        description="Specialization tags (e.g. phishing, malware, network_forensics).",
    )
    certifications: list[dict] = Field(
        default_factory=list,
        description="List of {name, issuer, issued_year, credential_url} objects.",
    )
    languages: list[str] = Field(
        default_factory=list,
        description="BCP 47 language tags (e.g. ['en', 'hi']).",
    )

    years_of_experience: int | None = Field(default=None, ge=0, le=60)
    hourly_rate_cents: int | None = Field(
        default=None, ge=0, le=100_000_000_00,
        description="Hourly rate in cents. Null if only fixed-price offerings.",
    )
    currency: str | None = Field(
        default=None, min_length=3, max_length=3,
        description="ISO 4217 currency code for hourly_rate_cents.",
    )
    working_timezone: str = Field(
        default="UTC", max_length=64,
        description="IANA timezone the analyst works in.",
    )

    verification_documents: list[dict] = Field(
        default_factory=list,
        description=(
            "Verification document references. URLs must be under "
            "/static/uploads/verification/{user_id}/ — enforced by the service."
        ),
    )

    @field_validator("specializations")
    @classmethod
    def _v_specializations(cls, v: list[str]) -> list[str]:
        return _clean_specializations(v)

    @field_validator("certifications")
    @classmethod
    def _v_certifications(cls, v: list[dict]) -> list[dict]:
        return _clean_certifications(v)

    @field_validator("languages")
    @classmethod
    def _v_languages(cls, v: list[str]) -> list[str]:
        return _clean_languages(v)

    @field_validator("verification_documents")
    @classmethod
    def _v_docs(cls, v: list[dict]) -> list[dict]:
        return _clean_verification_documents(v)

    @field_validator("currency")
    @classmethod
    def _v_currency(cls, v: str | None) -> str | None:
        return _validate_currency(v)

    @field_validator("working_timezone")
    @classmethod
    def _v_timezone(cls, v: str) -> str:
        return _validate_timezone(v)


# ============================================================================
# UPDATE
# ============================================================================

class AnalystProfileUpdate(CyberGuardBaseSchema):
    """
    Self-service update. Every field is optional — only provided fields
    are applied.

    Cannot change (schema does not declare):
        - ``verification_status`` — workflow-managed
        - ``verified_by_id`` / ``verification_completed_at`` — admin-only
        - ``available_for_hire`` — dedicated endpoint
        - ``active_case_count`` / ``total_cases_completed`` /
          ``rating_average`` / ``rating_count`` / ``purchase_count`` —
          computed by other services

    **Editing ``verification_documents`` while VERIFIED resets the
    profile to IN_REVIEW** — admin must re-approve. This is enforced by
    the service layer.
    """

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    headline: str | None = Field(default=None, max_length=200)
    bio: str | None = Field(default=None, max_length=5000)

    specializations: list[str] | None = None
    certifications: list[dict] | None = None
    languages: list[str] | None = None

    years_of_experience: int | None = Field(default=None, ge=0, le=60)
    hourly_rate_cents: int | None = Field(default=None, ge=0, le=100_000_000_00)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    working_timezone: str | None = Field(default=None, max_length=64)

    verification_documents: list[dict] | None = None

    @field_validator("specializations")
    @classmethod
    def _v_specializations(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _clean_specializations(v)

    @field_validator("certifications")
    @classmethod
    def _v_certifications(cls, v: list[dict] | None) -> list[dict] | None:
        if v is None:
            return None
        return _clean_certifications(v)

    @field_validator("languages")
    @classmethod
    def _v_languages(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _clean_languages(v)

    @field_validator("verification_documents")
    @classmethod
    def _v_docs(cls, v: list[dict] | None) -> list[dict] | None:
        if v is None:
            return None
        return _clean_verification_documents(v)

    @field_validator("currency")
    @classmethod
    def _v_currency(cls, v: str | None) -> str | None:
        return _validate_currency(v)

    @field_validator("working_timezone")
    @classmethod
    def _v_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_timezone(v)


# ============================================================================
# READ
# ============================================================================

class AnalystProfileRead(TimestampedModel):
    """
    Full analyst profile view. **Used only by admin endpoints** (File 103).

    Includes ``verification_notes`` — which is admin-only and must not
    be exposed to the analyst themselves. If a public-facing endpoint is
    added later, use a separate ``AnalystProfilePublicRead`` schema that
    omits ``verification_notes`` and ``verified_by_id``.

    All computed fields (``is_verified``, ``can_accept_cases``, etc.)
    are populated from ORM properties via ``from_attributes=True``.
    """

    id: uuid.UUID
    user_id: uuid.UUID

    display_name: str
    headline: str | None = None
    bio: str | None = None

    specializations: list[str] = Field(default_factory=list)
    certifications: list[dict] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)

    years_of_experience: int | None = None
    hourly_rate_cents: int | None = None
    currency: str | None = None
    working_timezone: str = "UTC"

    available_for_hire: bool = False

    verification_status: AnalystVerificationStatus
    verification_submitted_at: datetime
    verification_completed_at: datetime | None = None
    verified_by_id: uuid.UUID | None = None
    verification_notes: str | None = Field(
        default=None,
        description=(
            "ADMIN-ONLY. Never shown to the analyst themselves. "
            "Preserved for compliance and internal review."
        ),
    )
    rejection_reason: str | None = Field(
        default=None,
        description="Surfaced to the applicant when REJECTED.",
    )
    verification_documents: list[dict] = Field(default_factory=list)

    max_concurrent_cases: int = 10
    active_case_count: int = 0
    total_cases_completed: int = 0

    rating_average: float | None = None
    rating_count: int = 0
    purchase_count: int = 0

    # ── Computed from ORM properties (see AnalystProfile model) ────────
    is_verified: bool = Field(
        ..., description="True if verification_status == VERIFIED.",
    )
    is_pending_review: bool = Field(
        ..., description="True if verification_status is PENDING or IN_REVIEW.",
    )
    is_rejected: bool = Field(
        ..., description="True if verification_status == REJECTED.",
    )
    is_suspended: bool = Field(
        ..., description="True if verification_status == SUSPENDED.",
    )
    is_expired: bool = Field(
        ..., description="True if verification_status == EXPIRED.",
    )
    has_capacity: bool = Field(
        ...,
        description="True if active_case_count < max_concurrent_cases.",
    )
    can_accept_cases: bool = Field(
        ...,
        description=(
            "True iff verified AND available_for_hire AND has_capacity. "
            "The single condition every assignment check consults."
        ),
    )
    hourly_rate_display: str | None = Field(
        default=None,
        description="Human-readable rate (e.g. 'USD 499.00'). NULL if not set.",
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AnalystProfileApply",
    "AnalystProfileUpdate",
    "AnalystProfileRead",
]