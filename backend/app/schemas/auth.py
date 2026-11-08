"""
CyberGuard AI — Authentication Schemas
============================================================================

Request/response schemas for registration, login, token refresh, and
password change. These are the first schemas any user encounters — they
define the API contract for account creation and session management.

Design rules
------------
1. **Password validation matches core.security exactly.** Min 8 bytes,
   max 72 bytes (bcrypt's hard limit). Validated in the schema for a
   fast 422 before hashing; validated again in `hash_password` for
   defense in depth.

2. **Byte-length, not char-length, for password validation.** bcrypt
   operates on bytes. A 4-char emoji password is 16 bytes. Char-length
   would let users set passwords that later fail at hash time.

3. **Email normalized to lowercase in schema.** Matches `User.email`
   normalization. The API response reflects the normalized form.

4. **Minimal password strength rules.** Length + at least one letter
   and one digit. Prevents obvious weak passwords (`aaaaaaaa`, `12345678`).
   Real production would layer complexity requirements — this is the
   foundation.

5. **`TokenResponse` never includes the user object.** Avoids circular
   imports. Client calls `GET /me` for the user after login.

6. **`TokenPayload` is internal.** Typed view of decoded JWT claims.
   Used by `get_current_user` dependency. Not returned to any client.

7. **`extra="forbid"` inherited from CyberGuardBaseSchema.** Client
   typos return 422, not silent 200.

Usage
-----
    from app.schemas.auth import (
        RegisterRequest, LoginRequest, RefreshRequest,
        TokenResponse, TokenPayload, PasswordChangeRequest,
    )

    @router.post("/register")
    def register(body: RegisterRequest) -> TokenResponse:
        ...

    @router.post("/login")
    def login(body: LoginRequest) -> TokenResponse:
        ...
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import EmailStr, Field, field_validator

from app.schemas.common import CyberGuardBaseSchema


# ─── Constants mirroring app.core.security ────────────────────────────────
_MIN_PASSWORD_BYTES = 8
_MAX_PASSWORD_BYTES = 72   # bcrypt hard limit
_MAX_EMAIL_CHARS = 320     # RFC 5322 max
_MAX_FULL_NAME_CHARS = 255


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================

class RegisterRequest(CyberGuardBaseSchema):
    """
    Request body for POST /api/v1/auth/register.

    Creates a new user account in `pending_verification` state. The user
    must verify their email before full access is granted.
    """

    email: EmailStr = Field(
        ...,
        max_length=_MAX_EMAIL_CHARS,
        description="Account email. Normalized to lowercase.",
        examples=["user@example.com"],
    )

    password: str = Field(
        ...,
        min_length=_MIN_PASSWORD_BYTES,
        max_length=_MAX_PASSWORD_BYTES,
        description=(
            f"Password, {_MIN_PASSWORD_BYTES}–{_MAX_PASSWORD_BYTES} bytes when "
            "UTF-8 encoded. At least one letter and one digit required."
        ),
        examples=["correct-horse-battery-staple-42"],
    )

    full_name: str | None = Field(
        default=None,
        max_length=_MAX_FULL_NAME_CHARS,
        description="Display name (optional).",
        examples=["Priya Sharma"],
    )

    role: str = Field(
        default="individual",
        description="User workspace role intent: 'individual', 'analyst', or 'organizer'.",
        examples=["individual"],
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
        # Byte length is what bcrypt sees; char length would be misleading.
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
        # Minimal strength: at least one letter and one digit.
        has_letter = any(c.isalpha() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not has_letter or not has_digit:
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


class LoginRequest(CyberGuardBaseSchema):
    """
    Request body for POST /api/v1/auth/login.

    The password field has no min_length — a wrong password can be any
    length; the service returns a uniform "invalid credentials" error
    regardless.
    """

    email: EmailStr = Field(
        ...,
        max_length=_MAX_EMAIL_CHARS,
        description="Account email. Normalized to lowercase.",
    )

    password: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_PASSWORD_BYTES,
        description="Plaintext password.",
    )

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, v: object) -> str:
        if not isinstance(v, str):
            raise ValueError("email must be a string")
        return v.strip().lower()


class RefreshRequest(CyberGuardBaseSchema):
    """
    Request body for POST /api/v1/auth/refresh.

    Exchanges a refresh token for a new access token. The refresh token
    itself is valid for `settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS` and can
    be rotated on each refresh if configured.
    """

    refresh_token: str = Field(
        ...,
        min_length=20,
        max_length=1024,
        description="Refresh token previously issued by /login or /register.",
    )


class PasswordChangeRequest(CyberGuardBaseSchema):
    """
    Request body for POST /api/v1/auth/change-password.

    Requires the current password (proof of identity) and a new password.
    The new password must differ from the old one.
    """

    old_password: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_PASSWORD_BYTES,
        description="Current password (proof of identity).",
    )

    new_password: str = Field(
        ...,
        min_length=_MIN_PASSWORD_BYTES,
        max_length=_MAX_PASSWORD_BYTES,
        description=(
            f"New password, {_MIN_PASSWORD_BYTES}–{_MAX_PASSWORD_BYTES} bytes "
            "when UTF-8 encoded."
        ),
    )

    @field_validator("new_password")
    @classmethod
    def _validate_new_password(cls, v: str) -> str:
        byte_len = len(v.encode("utf-8"))
        if byte_len < _MIN_PASSWORD_BYTES:
            raise ValueError(
                f"New password must be at least {_MIN_PASSWORD_BYTES} bytes "
                f"when UTF-8 encoded (got {byte_len})."
            )
        if byte_len > _MAX_PASSWORD_BYTES:
            raise ValueError(
                f"New password must not exceed {_MAX_PASSWORD_BYTES} bytes "
                f"when UTF-8 encoded (got {byte_len})."
            )
        has_letter = any(c.isalpha() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if not has_letter or not has_digit:
            raise ValueError(
                "New password must contain at least one letter and one digit."
            )
        return v

    @field_validator("new_password")
    @classmethod
    def _require_different_password(cls, v: str, info) -> str:
        # `info.data` contains previously-validated fields in the same model.
        old = info.data.get("old_password")
        if old and old == v:
            raise ValueError("New password must differ from old password.")
        return v


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================

class TokenResponse(CyberGuardBaseSchema):
    """
    Response body for /register, /login, and /refresh.

    Standard OAuth2 bearer token response. The client sends
    `Authorization: Bearer <access_token>` on subsequent requests.

    Note: does **not** include the user object — the client calls
    `GET /me` to fetch the user. This avoids a circular schema dependency
    between auth and user modules.
    """

    access_token: str = Field(
        ...,
        description="Short-lived JWT access token.",
    )

    refresh_token: str = Field(
        ...,
        description="Long-lived JWT refresh token. Store securely.",
    )

    token_type: Literal["bearer"] = Field(
        default="bearer",
        description="Token scheme. Always 'bearer'.",
    )

    expires_in: int = Field(
        ...,
        ge=1,
        description="Access token lifetime in seconds.",
    )


# ============================================================================
# INTERNAL SCHEMAS (not returned to clients)
# ============================================================================

class TokenPayload(CyberGuardBaseSchema):
    """
    Decoded JWT claims. Internal use only — not returned to any client.

    Populated by `app.auth.dependencies.get_current_user` after calling
    `app.core.security.decode_access_token`. The `sub` (subject) is the
    user's UUID string; `type` distinguishes access from refresh tokens.
    """

    sub: str = Field(
        ...,
        description="Subject claim — the user's UUID as a string.",
    )

    type: Literal["access", "refresh"] = Field(
        ...,
        description="Token type. Access vs refresh.",
    )

    exp: int = Field(
        ...,
        description="Expiration as Unix timestamp (seconds).",
    )

    iat: int = Field(
        ...,
        description="Issued-at as Unix timestamp (seconds).",
    )

    jti: str = Field(
        ...,
        description="Unique token ID. Used for revocation in a future blocklist.",
    )

    # Allow extra claims (e.g. org_id, permissions scoped to a request)
    model_config = {
        "extra": "allow",
        "str_strip_whitespace": True,
        "from_attributes": False,
    }

    @property
    def user_id(self) -> uuid.UUID:
        """
        Parse `sub` as UUID. Raises ValueError if malformed — callers
        should treat that as an authentication failure.
        """
        return uuid.UUID(self.sub)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Requests
    "RegisterRequest",
    "LoginRequest",
    "RefreshRequest",
    "PasswordChangeRequest",
    # Responses
    "TokenResponse",
    # Internal
    "TokenPayload",
]