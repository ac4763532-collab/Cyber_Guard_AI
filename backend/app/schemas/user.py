"""
CyberGuard AI — User Schemas
============================================================================

Request/response schemas for the ``users`` table.

Design rules
------------
1. **Never leak secrets.** ``UserRead`` does NOT declare
   ``password_hash``, ``mfa_secret``, or any credential field. Fields
   not declared cannot be serialized.

2. **Computed booleans from ORM properties.** ``is_active``,
   ``is_locked``, ``has_password`` are declared as regular fields and
   populated from ORM properties via ``from_attributes=True``.

3. **No ``password`` field in ``UserUpdate``.** Password changes go
   through dedicated endpoints (``PasswordChangeRequest`` or a reset
   flow). Mixing password into generic PATCH is a source of accidental
   leaks.

4. **Role-specific update schemas.** ``UserSelfUpdate`` (self-service)
   and ``UserAdminUpdate`` (admin-only) express who is allowed to
   change what in the type itself. The service enforces the actual
   rule, but the schema is the first line of defense.

5. **Timezone validated against ``zoneinfo``.** A bad timezone breaks
   every scheduled notification, report, and SLA calculation.

6. **Email normalized to lowercase.** Same normalization as
   ``User.email`` ORM validator — defense in depth.

Usage
-----
    from app.schemas.user import (
        UserCreate, UserRead, UserUpdate,
        UserSelfUpdate, UserAdminUpdate, UserList, UserFilter,
    )

    @router.get("/me", response_model=UserRead)
    def get_me(current: User = Depends(get_current_active_user)) -> UserRead:
        return UserRead.model_validate(current)

    @router.patch("/me", response_model=UserRead)
    def update_me(
        body: UserSelfUpdate,
        current: User = Depends(get_current_active_user),
        db: Session = Depends(get_db),
    ) -> UserRead:
        user = user_service.self_update(db, current, body)
        return UserRead.model_validate(user)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal
from zoneinfo import available_timezones

from pydantic import EmailStr, Field, field_validator

from app.models.enums import UserStatus
from app.schemas.common import (
    CyberGuardBaseSchema,
    TimestampedModel,
)


# ── Constants ──────────────────────────────────────────────────────────────
_MIN_PASSWORD_BYTES = 8
_MAX_PASSWORD_BYTES = 72   # bcrypt hard limit
_MAX_EMAIL_CHARS = 320
_MAX_FULL_NAME_CHARS = 255
_MAX_LANGUAGE_LENGTH = 16
_MAX_TIMEZONE_LENGTH = 64
_MAX_EMAIL_CONTAINS_LENGTH = 100

#: Basic BCP 47 pattern: language[-REGION]. Covers en, en-US, pt-BR, zh-CN.
_LANG_PATTERN = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")


# ============================================================================
# CREATE
# ============================================================================

class UserCreate(CyberGuardBaseSchema):
    """
    Request body for admin/script-driven user creation.

    For self-service registration, see ``app.schemas.auth.RegisterRequest``
    — that flow always creates a ``pending_verification`` user with
    fewer configurable fields.
    """

    email: EmailStr = Field(
        ...,
        max_length=_MAX_EMAIL_CHARS,
        description="Account email. Normalized to lowercase.",
    )

    password: str = Field(
        ...,
        min_length=_MIN_PASSWORD_BYTES,
        max_length=_MAX_PASSWORD_BYTES,
        description=(
            f"Password, {_MIN_PASSWORD_BYTES}–{_MAX_PASSWORD_BYTES} bytes when "
            "UTF-8 encoded. At least one letter and one digit required."
        ),
    )

    full_name: str | None = Field(
        default=None,
        max_length=_MAX_FULL_NAME_CHARS,
    )

    status: UserStatus = Field(
        default=UserStatus.PENDING_VERIFICATION,
        description="Initial account status.",
    )

    email_verified_at: datetime | None = Field(
        default=None,
        description=(
            "Set to backdate verification (admin-created pre-verified users). "
            "Leave as null to require email verification."
        ),
    )

    preferred_language: str = Field(
        default="en",
        max_length=_MAX_LANGUAGE_LENGTH,
        description="BCP 47 language tag (e.g. 'en', 'en-US').",
    )

    timezone: str = Field(
        default="UTC",
        max_length=_MAX_TIMEZONE_LENGTH,
        description="IANA timezone name (e.g. 'America/New_York').",
    )

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, v: object) -> str:
        if not isinstance(v, str):
            raise ValueError("email must be a string")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: str) -> str:
        byte_len = len(v.encode("utf-8"))
        if byte_len < _MIN_PASSWORD_BYTES:
            raise ValueError(
                f"Password must be at least {_MIN_PASSWORD_BYTES} bytes "
                f"when UTF-8 encoded (got {byte_len})."
            )
        if byte_len > _MAX_PASSWORD_BYTES:
            raise ValueError(
                f"Password must not exceed {_MAX_PASSWORD_BYTES} bytes "
                f"when UTF-8 encoded (got {byte_len})."
            )
        if not any(c.isalpha() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError(
                "Password must contain at least one letter and one digit."
            )
        return v

    @field_validator("full_name")
    @classmethod
    def _clean_full_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None

    @field_validator("preferred_language")
    @classmethod
    def _validate_language(cls, v: str) -> str:
        stripped = v.strip()
        if not _LANG_PATTERN.match(stripped):
            raise ValueError(
                "preferred_language must match BCP 47 basic form "
                "(e.g. 'en', 'en-US')."
            )
        return stripped

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str) -> str:
        stripped = v.strip()
        if stripped not in available_timezones():
            raise ValueError(
                f"Unknown IANA timezone: {stripped!r}. "
                f"Example valid values: 'UTC', 'America/New_York', "
                f"'Europe/Berlin', 'Asia/Kolkata'."
            )
        return stripped


# ============================================================================
# READ
# ============================================================================

class UserRead(TimestampedModel):
    """
    Full user view returned by ``GET /users/{id}``, ``GET /me``, etc.

    Deliberately does NOT declare:
        - ``password_hash`` (would leak credentials)
        - ``mfa_secret`` (would leak 2FA secret)
        - ``deleted_at`` (soft-delete state is internal)
        - ``failed_login_attempts`` (attack-timing signal)

    Includes computed booleans (``is_active``, ``is_locked``,
    ``has_password``) that populate from ORM properties.
    """

    id: uuid.UUID
    public_user_id: str = Field(
        default="",
        description="Public human-readable user ID / slug (e.g. riya-user-000184).",
    )
    role: str = Field(
        default="individual",
        description="User persona: 'individual', 'analyst', 'organizer', 'admin'.",
    )
    email: EmailStr
    full_name: str | None = None
    status: UserStatus

    email_verified_at: datetime | None = None
    last_login_at: datetime | None = None

    mfa_enabled: bool = False

    preferred_language: str = "en"
    timezone: str = "UTC"

    locked_until: datetime | None = None

    # ── Computed from ORM properties ───────────────────────────────────
    is_active: bool = Field(
        ...,
        description="True if status is ACTIVE and not soft-deleted.",
    )
    is_locked: bool = Field(
        ...,
        description="True if currently locked out (locked_until in the future).",
    )
    has_password: bool = Field(
        ...,
        description="True if a local password is set (False for OAuth-only accounts).",
    )


# ============================================================================
# UPDATE — GENERIC
# ============================================================================

class UserUpdate(CyberGuardBaseSchema):
    """
    Generic update schema — every field is optional.

    Used by admin flows or service-level operations. For role-specific
    updates, prefer ``UserSelfUpdate`` (self-service) or
    ``UserAdminUpdate`` (admin) so the intent is expressed in the type.

    Does NOT include ``password`` — password changes go through
    ``PasswordChangeRequest`` or a dedicated reset flow.
    """

    email: EmailStr | None = Field(default=None, max_length=_MAX_EMAIL_CHARS)
    full_name: str | None = Field(default=None, max_length=_MAX_FULL_NAME_CHARS)
    status: UserStatus | None = None
    preferred_language: str | None = Field(default=None, max_length=_MAX_LANGUAGE_LENGTH)
    timezone: str | None = Field(default=None, max_length=_MAX_TIMEZONE_LENGTH)

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, v: object) -> object:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("email must be a string")
        return v.strip().lower()

    @field_validator("preferred_language")
    @classmethod
    def _validate_language(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not _LANG_PATTERN.match(stripped):
            raise ValueError(
                "preferred_language must match BCP 47 basic form."
            )
        return stripped

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if stripped not in available_timezones():
            raise ValueError(f"Unknown IANA timezone: {stripped!r}.")
        return stripped


# ============================================================================
# UPDATE — SELF-SERVICE
# ============================================================================

class UserSelfUpdate(CyberGuardBaseSchema):
    """
    Fields a user can change about themselves via ``PATCH /users/me``.

    Intentionally excludes:
        - ``email`` (requires a verification flow)
        - ``status`` (admin-only)
        - ``mfa_enabled`` (has a dedicated endpoint with TOTP verification)
        - ``email_verified_at`` (verification endpoint sets this)

    Every field is optional. Only provided fields are updated.
    """

    full_name: str | None = Field(default=None, max_length=_MAX_FULL_NAME_CHARS)
    preferred_language: str | None = Field(default=None, max_length=_MAX_LANGUAGE_LENGTH)
    timezone: str | None = Field(default=None, max_length=_MAX_TIMEZONE_LENGTH)

    @field_validator("full_name")
    @classmethod
    def _clean_full_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None

    @field_validator("preferred_language")
    @classmethod
    def _validate_language(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not _LANG_PATTERN.match(stripped):
            raise ValueError("preferred_language must match BCP 47 basic form.")
        return stripped

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if stripped not in available_timezones():
            raise ValueError(f"Unknown IANA timezone: {stripped!r}.")
        return stripped


# ============================================================================
# UPDATE — ADMIN
# ============================================================================

class UserAdminUpdate(CyberGuardBaseSchema):
    """
    Fields an admin can change about a user via ``PATCH /users/{id}``.

    Excludes:
        - ``password`` (admin should use the reset flow, not set passwords)
        - ``full_name`` / ``timezone`` / ``preferred_language`` (user's own)
        - ``email_verified_at`` (use the verify endpoint — preserves audit)
    """

    status: UserStatus | None = Field(
        default=None,
        description="Change account status (e.g. suspend, reactivate).",
    )

    locked_until: datetime | None = Field(
        default=None,
        description=(
            "Set lock expiry (must be future). To clear a lock, use the "
            "dedicated unlock endpoint rather than passing null."
        ),
    )

    mfa_enabled: bool | None = Field(
        default=None,
        description=(
            "Force MFA on/off. Disabling MFA should trigger an audit entry "
            "and usually requires re-authentication in the service layer."
        ),
    )

    @field_validator("locked_until")
    @classmethod
    def _validate_locked_until(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        from datetime import timezone as _tz
        now = datetime.now(_tz.utc)
        # Accept naive as UTC for lenient parsing, but must be future.
        if v.tzinfo is None:
            v = v.replace(tzinfo=_tz.utc)
        if v <= now:
            raise ValueError(
                "locked_until must be in the future. "
                "To unlock a user, use the unlock endpoint."
            )
        return v


# ============================================================================
# LIST (lightweight)
# ============================================================================

class UserList(CyberGuardBaseSchema):
    """
    Lightweight user view for pickers, autocomplete, member lists.

    Only 4 fields — enough to render a row. For full details, clients
    fetch ``GET /users/{id}`` which returns ``UserRead``.
    """

    id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    status: UserStatus


# ============================================================================
# FILTER (query params for GET /users)
# ============================================================================

class UserFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /users``.

    Consumed by services as a set of optional filters combined with AND.
    """

    status: UserStatus | None = Field(
        default=None,
        description="Filter by account status.",
    )

    email_contains: str | None = Field(
        default=None,
        max_length=_MAX_EMAIL_CONTAINS_LENGTH,
        description=(
            "Case-insensitive substring search on email. "
            "Capped at 100 chars to bound LIKE scan cost."
        ),
    )

    full_name_contains: str | None = Field(
        default=None,
        max_length=_MAX_FULL_NAME_CHARS,
        description="Case-insensitive substring search on full_name.",
    )

    is_email_verified: bool | None = Field(
        default=None,
        description="If set, require email_verified_at (True) or missing (False).",
    )

    is_locked: bool | None = Field(
        default=None,
        description="If set, require an active lock (True) or no active lock (False).",
    )

    created_after: datetime | None = Field(
        default=None,
        description="Only users created at or after this timestamp.",
    )

    created_before: datetime | None = Field(
        default=None,
        description="Only users created at or before this timestamp.",
    )

    @field_validator("email_contains", "full_name_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None

    @field_validator("created_before")
    @classmethod
    def _validate_range(cls, v: datetime | None, info) -> datetime | None:
        if v is None:
            return None
        after = info.data.get("created_after")
        if after is not None and v < after:
            raise ValueError("created_before must be >= created_after.")
        return v


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "UserCreate",
    "UserRead",
    "UserUpdate",
    "UserSelfUpdate",
    "UserAdminUpdate",
    "UserList",
    "UserFilter",
]