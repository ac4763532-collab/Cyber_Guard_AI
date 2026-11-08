"""
CyberGuard AI — JWT Helpers for Authentication Flows
============================================================================

Thin wrappers around ``app.core.security`` for JWT operations specific to
authentication flows. This file handles the parts ``core.security``
deliberately does not:

    - Parsing the ``Authorization: Bearer <token>`` header
    - Extracting the raw token from that header (case-insensitive scheme)
    - Enforcing token type (access vs refresh)
    - Building the standard ``TokenResponse`` for login/register endpoints

Crypto (sign, verify signature, validate exp/nbf/type claims) lives in
``app.core.security``. This module never imports ``jose`` directly, so the
JWT algorithm, secret, and validation rules are defined in exactly one
place.

Public API
----------
Header parsing:
    parse_authorization_header(header_value) -> str
        Extract the raw token from "Bearer <token>".

Token verification:
    decode_bearer_token(header_value) -> dict
        Parse the header AND verify the token in one step.

    verify_access_token(token) -> dict
        Decode a raw token, requiring type == "access".

    verify_refresh_token(token) -> dict
        Decode a raw token, requiring type == "refresh".

    extract_user_id_from_token(token) -> uuid.UUID
        Decode an access token and return the ``sub`` claim as a UUID.

Token building:
    build_token_response(*, user_id, extra_claims=None) -> TokenResponse
        Build the standard login/register response.

Design rules
------------
1. **Parsing, not crypto.** ``core.security`` does the crypto. This
   module parses headers and enforces type, then delegates.

2. **Case-insensitive scheme.** ``Bearer``, ``bearer``, ``BEARER`` all
   accepted. Only ``Bearer`` is supported — ``Basic`` raises with a
   clear message.

3. **Whitespace tolerance.** Leading/trailing whitespace and multiple
   internal spaces are normalized. Browsers and HTTP libraries vary;
   being tolerant costs nothing.

4. **Malformed header → AuthenticationError.** Missing header, empty
   header, or wrong scheme is an *authentication* failure ("who are
   you?"), not a *token validation* failure ("your token is bad").
   The distinction matters for audit logs.

5. **Type enforcement at this layer.** ``verify_access_token`` and
   ``verify_refresh_token`` make the intent explicit. ``core.security``
   already enforces the type, but calling the type-specific wrapper
   is clearer at the call site.

6. **No DB, no ORM imports.** This file imports from
   ``app.core.config``, ``app.core.exceptions``, ``app.core.security``,
   and ``app.schemas.auth``. Nothing else.

7. **``expires_in`` is derived from settings**, matching the actual TTL
   signed into the token. Clients use it to schedule silent refresh.

8. **``extra_claims`` for forward compatibility.** Tokens may carry
   future claims (``org_id``, ``workspace_id``) without changing the
   function signature.

Usage
-----
    from fastapi import Header
    from app.auth.jwt import decode_bearer_token

    def some_endpoint(authorization: str = Header(...)) -> ...:
        payload = decode_bearer_token(authorization)
        user_id = uuid.UUID(payload["sub"])
        ...
"""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    InvalidTokenError,
)
from app.core.security import (
    create_token_pair,
    decode_access_token,
    decode_refresh_token,
    extract_jti,
    extract_subject,
)
from app.schemas.auth import TokenResponse


# ── Constants ──────────────────────────────────────────────────────────────
_BEARER_SCHEME = "bearer"

#: Maximum length for the entire Authorization header value.
#: Real bearer JWTs are < 2 KB; 4 KB is a defensive cap.
_MAX_HEADER_LENGTH = 4096


# ============================================================================
# HEADER PARSING
# ============================================================================

def parse_authorization_header(header_value: str | None) -> str:
    """
    Extract the raw JWT from an ``Authorization: Bearer <token>`` header.

    Parameters
    ----------
    header_value:
        The full header value (``"Bearer eyJ..."``), or ``None`` if the
        header was absent.

    Returns
    -------
    str
        The raw token, without the ``Bearer`` prefix or surrounding
        whitespace.

    Raises
    ------
    AuthenticationError
        If the header is missing, empty, or not in the ``Bearer <token>``
        format. The error code distinguishes each case:

            AUTH_HEADER_MISSING   — no Authorization header sent
            AUTH_HEADER_EMPTY     — header sent but empty
            AUTH_HEADER_TOO_LONG  — header > 4 KB (defensive)
            AUTH_HEADER_MALFORMED — not "<scheme> <token>"
            AUTH_HEADER_WRONG_SCHEME — scheme is not "Bearer"
            AUTH_HEADER_NO_TOKEN  — "Bearer " with nothing after
    """
    if header_value is None:
        raise AuthenticationError(
            message="Authorization header is required.",
            code="AUTH_HEADER_MISSING",
        )

    if not isinstance(header_value, str):
        raise AuthenticationError(
            message="Authorization header must be a string.",
            code="AUTH_HEADER_MALFORMED",
        )

    if not header_value.strip():
        raise AuthenticationError(
            message="Authorization header is empty.",
            code="AUTH_HEADER_EMPTY",
        )

    if len(header_value) > _MAX_HEADER_LENGTH:
        raise AuthenticationError(
            message=(
                f"Authorization header exceeds {_MAX_HEADER_LENGTH} "
                "characters. This is not a valid bearer token."
            ),
            code="AUTH_HEADER_TOO_LONG",
        )

    # Split on first whitespace; scheme is case-insensitive.
    # `maxsplit=1` handles headers with multiple spaces after the scheme.
    parts = header_value.strip().split(None, 1)
    if len(parts) != 2:
        raise AuthenticationError(
            message=(
                "Authorization header must be in the format "
                "'Bearer <token>'."
            ),
            code="AUTH_HEADER_MALFORMED",
        )

    scheme, token = parts[0], parts[1].strip()

    if scheme.lower() != _BEARER_SCHEME:
        raise AuthenticationError(
            message=(
                f"Authorization scheme {scheme!r} is not supported. "
                "Only 'Bearer' is accepted."
            ),
            code="AUTH_HEADER_WRONG_SCHEME",
            details={"scheme": scheme},
        )

    if not token:
        raise AuthenticationError(
            message="Authorization header has 'Bearer' but no token.",
            code="AUTH_HEADER_NO_TOKEN",
        )

    return token


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_access_token(token: str) -> dict[str, Any]:
    """
    Decode a raw JWT and require it to be an access token.

    Thin wrapper over ``core.security.decode_access_token``. Exists so
    call sites are explicit about which token type they expect.

    Raises
    ------
    TokenExpiredError
        If the token has expired.
    InvalidTokenError
        If the signature is invalid, ``sub`` is missing, or the type
        is not ``"access"``.
    """
    return decode_access_token(token)


def verify_refresh_token(token: str) -> dict[str, Any]:
    """
    Decode a raw JWT and require it to be a refresh token.

    Raises
    ------
    TokenExpiredError
        If the token has expired.
    InvalidTokenError
        If the signature is invalid, ``sub`` is missing, or the type
        is not ``"refresh"``.
    """
    return decode_refresh_token(token)


def decode_bearer_token(header_value: str | None) -> dict[str, Any]:
    """
    Parse an ``Authorization: Bearer <token>`` header and verify the
    token as an access token.

    One-shot helper for endpoints that accept the header directly.
    Equivalent to::

        token = parse_authorization_header(header_value)
        return verify_access_token(token)

    Parameters
    ----------
    header_value:
        The full header value, or ``None``.

    Returns
    -------
    dict
        The decoded JWT claims (``sub``, ``type``, ``exp``, ``iat``,
        ``jti``, plus any extra claims).

    Raises
    ------
    AuthenticationError  — for header problems
    InvalidTokenError    — for token problems
    TokenExpiredError    — for expired tokens
    """
    token = parse_authorization_header(header_value)
    return verify_access_token(token)


def extract_user_id_from_token(token: str) -> uuid.UUID:
    """
    Decode an access token and return the ``sub`` claim as a UUID.

    The ``sub`` claim is a string containing the user's UUID. This
    helper combines decoding + parsing + UUID conversion into one call.

    Raises
    ------
    TokenExpiredError
        If the token has expired.
    InvalidTokenError
        If the signature is invalid, the token type is wrong, the ``sub``
        claim is missing, or the ``sub`` value is not a valid UUID.
    """
    payload = verify_access_token(token)
    sub = extract_subject(payload)
    try:
        return uuid.UUID(sub)
    except (ValueError, TypeError) as exc:
        raise InvalidTokenError(
            message="Token 'sub' claim is not a valid UUID.",
            code="JWT_INVALID_SUBJECT_FORMAT",
            details={"sub_prefix": sub[:8] if isinstance(sub, str) else None},
        ) from exc


def extract_jti_from_token(token: str) -> str:
    """
    Decode an access token and return its ``jti`` (unique token ID).

    Useful for building a revocation blocklist keyed on token IDs.
    """
    payload = verify_access_token(token)
    return extract_jti(payload)


# ============================================================================
# TOKEN BUILDING (for login/register endpoints)
# ============================================================================

def build_token_response(
    *,
    user_id: uuid.UUID | str,
    extra_claims: dict[str, Any] | None = None,
) -> TokenResponse:
    """
    Build the standard ``TokenResponse`` returned by /register, /login,
    and /refresh.

    Parameters
    ----------
    user_id:
        The authenticated user's ID. Passed as the JWT ``sub`` claim.
        Accepts either a ``uuid.UUID`` or a string — both are converted
        to a string for signing.
    extra_claims:
        Optional additional JWT claims. Reserved claims (``sub``,
        ``type``, ``iat``, ``exp``, ``jti``) cannot be overridden —
        ``core.security`` raises if they are.

    Returns
    -------
    TokenResponse
        Populated with ``access_token``, ``refresh_token``,
        ``token_type="bearer"``, and ``expires_in`` (in seconds).

    Raises
    ------
    ValidationError
        If ``user_id`` is empty, or ``extra_claims`` overrides a
        reserved claim.
    """
    if user_id is None:
        raise AuthenticationError(
            message="Cannot build token without a user_id.",
            code="AUTH_TOKEN_NO_SUBJECT",
        )

    subject = str(user_id).strip()
    if not subject:
        raise AuthenticationError(
            message="Cannot build token: user_id is empty.",
            code="AUTH_TOKEN_NO_SUBJECT",
        )

    access, refresh = create_token_pair(
        subject=subject,
        extra_claims=extra_claims,
    )

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "parse_authorization_header",
    "verify_access_token",
    "verify_refresh_token",
    "decode_bearer_token",
    "extract_user_id_from_token",
    "extract_jti_from_token",
    "build_token_response",
]