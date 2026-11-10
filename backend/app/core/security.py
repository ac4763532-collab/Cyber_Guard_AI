"""
CyberGuard AI — Security Primitives
============================================================================

Password hashing (bcrypt via passlib) and JWT encode/decode primitives.

This module has **no business logic**. It exposes pure cryptographic
operations and nothing else. Auth flows, registration endpoints, and token
verification dependencies all call into these functions.

Public API
----------
Passwords:
    hash_password(plain: str) -> str
    verify_password(plain: str, hashed: str) -> bool
    needs_rehash(hashed: str) -> bool

JWT:
    create_access_token(subject, extra_claims=None) -> str
    create_refresh_token(subject, extra_claims=None) -> str
    create_token_pair(subject, extra_claims=None) -> (access, refresh)

    decode_access_token(token) -> dict
    decode_refresh_token(token) -> dict
    decode_token(token, expected_type) -> dict

    extract_subject(payload) -> str
    extract_jti(payload) -> str

Utilities:
    generate_secure_token(length: int = 32) -> str

    reset_password_context_for_tests() -> None

Security design decisions
-------------------------
1. **bcrypt 72-byte limit is explicit.** bcrypt truncates passwords longer
   than 72 bytes (UTF-8). Silently relying on that truncation means two
   passwords sharing the first 72 bytes authenticate each other. We reject
   passwords outside the [MIN_PASSWORD_BYTES, MAX_PASSWORD_BYTES] range at
   hash time. Schema-level validation should also enforce this range, so
   users get a friendly 422 instead of a 500.

2. **JWT ``type`` claim prevents token confusion.** An access token cannot
   be used where a refresh token is required, and vice versa. Each decode
   function asserts the expected type.

3. **JWT ``jti`` claim supports future revocation.** A blocklist table keyed
   on ``jti`` can be checked in the auth dependency when needed.

4. **Algorithm is allow-listed.** Only HS256/HS384/HS512 are accepted.
   The classic "alg: none" attack vector is impossible.

5. **No logging of token or password values.** Only the *outcome* of a
   verification is logged, never the input.

Threat model notes
------------------
- bcrypt with cost ≥ 12 is required for production (enforced in config.py).
- JWT secrets must be ≥ 32 bytes and randomized (enforced in config.py).
- This module does **not** handle token revocation or blocklist checks —
  those belong to a token service that stores ``jti`` values in Redis or
  PostgreSQL.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

try:
    import bcrypt
    if not hasattr(bcrypt, "__about__"):
        bcrypt.__about__ = type("About", (), {"__version__": getattr(bcrypt, "__version__", "4.0.1")})()
except Exception:
    pass

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError as JoseExpiredSignatureError
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    ValidationError,
)
from app.core.logging import get_logger

logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Minimum password length in UTF-8 bytes. Lower bound is a policy choice —
#: raise it if compliance requirements demand more.
MIN_PASSWORD_BYTES: int = 8

#: Maximum password length in UTF-8 bytes. This is a hard limit imposed by
#: the bcrypt algorithm itself. We enforce it explicitly instead of silently
#: truncating, because silent truncation is a known footgun.
MAX_PASSWORD_BYTES: int = 72

#: Token types this module knows how to sign and verify.
TokenType = Literal["access", "refresh"]

#: JWT algorithms we are willing to accept. Must be a subset of what
#: ``settings.JWT_ALGORITHM`` allows (config.py is stricter still).
_ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})


# ============================================================================
# PASSWORD HASHING (bcrypt via passlib)
# ============================================================================

_pwd_context: CryptContext | None = None


def _get_pwd_context() -> CryptContext:
    """
    Lazily construct the passlib CryptContext.

    Lazy construction lets tests lower ``BCRYPT_ROUNDS`` before first use,
    avoiding 300ms per-hash test suites. Once built, the context is a
    process-wide singleton.
    """
    global _pwd_context
    if _pwd_context is None:
        _pwd_context = CryptContext(
            schemes=["bcrypt"],
            bcrypt__rounds=settings.BCRYPT_ROUNDS,
            deprecated="auto",
        )
    return _pwd_context


def reset_password_context_for_tests() -> None:
    """
    Tear down the cached CryptContext. Call this in test setup/teardown
    after overriding ``BCRYPT_ROUNDS`` via environment variables.
    """
    global _pwd_context
    _pwd_context = None


def _validate_password_length(plain: str) -> None:
    """Enforce the [MIN_PASSWORD_BYTES, MAX_PASSWORD_BYTES] range."""
    if not isinstance(plain, str):
        raise ValidationError(
            message="Password must be a string",
            code="PASSWORD_INVALID_TYPE",
        )

    byte_len = len(plain.encode("utf-8"))

    if byte_len < MIN_PASSWORD_BYTES:
        raise ValidationError(
            message=f"Password must be at least {MIN_PASSWORD_BYTES} bytes when UTF-8 encoded",
            code="PASSWORD_TOO_SHORT",
            details={"min_bytes": MIN_PASSWORD_BYTES, "actual_bytes": byte_len},
        )

    if byte_len > MAX_PASSWORD_BYTES:
        raise ValidationError(
            message=(
                f"Password must not exceed {MAX_PASSWORD_BYTES} bytes when UTF-8 "
                "encoded. This is a hard limit imposed by the bcrypt algorithm."
            ),
            code="PASSWORD_TOO_LONG",
            details={"max_bytes": MAX_PASSWORD_BYTES, "actual_bytes": byte_len},
        )


def hash_password(plain: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Raises ``ValidationError`` if the password is empty, too short, or
    longer than 72 UTF-8 bytes. The returned hash string is bcrypt format
    (``$2b$<cost>$<salt><digest>``) and safe to store directly.
    """
    _validate_password_length(plain)
    return _get_pwd_context().hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    Returns ``True`` on match, ``False`` otherwise. Never raises — any
    internal failure is treated as a non-match. This prevents timing leaks
    via distinct exception paths and keeps the auth layer simple.
    """
    if not isinstance(plain, str) or not isinstance(hashed, str):
        return False

    if not hashed or not plain:
        return False

    try:
        return _get_pwd_context().verify(plain, hashed)
    except Exception:
        # Malformed hash, unsupported scheme, etc.
        return False


def needs_rehash(hashed: str) -> bool:
    """
    Return ``True`` if the stored hash uses a weaker cost factor or an
    outdated scheme than the current configuration.

    Call this after successful ``verify_password``; if it returns True,
    rehash the plaintext and update the stored value. This is how cost
    factors are upgraded without forcing users to reset passwords.
    """
    if not isinstance(hashed, str) or not hashed:
        return True
    try:
        return _get_pwd_context().needs_update(hashed)
    except Exception:
        return True


# ============================================================================
# JWT — SHARED INTERNALS
# ============================================================================

def _get_jwt_secret() -> str:
    """Return the JWT secret or raise if it is missing at runtime."""
    secret = settings.JWT_SECRET_KEY.get_secret_value()
    if not secret:
        # This should be caught by config.py at startup. If we ever reach
        # here it means someone bypassed Settings — fail loudly.
        raise ValidationError(
            message="JWT secret is not configured",
            code="JWT_SECRET_NOT_CONFIGURED",
            status_code=500,
        )
    return secret


def _get_jwt_algorithm() -> str:
    """Return the configured algorithm after verifying it is permitted."""
    alg = settings.JWT_ALGORITHM
    if alg not in _ALLOWED_JWT_ALGORITHMS:
        raise ValidationError(
            message=f"JWT algorithm {alg!r} is not permitted",
            code="JWT_ALGORITHM_NOT_PERMITTED",
            status_code=500,
        )
    return alg


def _build_token(
    subject: str,
    token_type: TokenType,
    ttl: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Construct and sign a JWT.

    Reserved claims (``sub``, ``type``, ``iat``, ``exp``, ``jti``) may not
    be overridden via ``extra_claims`` — doing so raises ``ValidationError``.
    """
    if not isinstance(subject, str) or not subject:
        raise ValidationError(
            message="Token subject must be a non-empty string",
            code="JWT_INVALID_SUBJECT",
        )

    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    if extra_claims:
        for key, value in extra_claims.items():
            if key in payload:
                raise ValidationError(
                    message=f"Reserved JWT claim {key!r} cannot be overridden",
                    code="JWT_RESERVED_CLAIM",
                    details={"claim": key},
                )
            payload[key] = value

    return jwt.encode(payload, _get_jwt_secret(), algorithm=_get_jwt_algorithm())


# ============================================================================
# JWT — TOKEN CREATION
# ============================================================================

def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a short-lived access token.

    ``subject`` is normally the user's UUID (as a string). ``extra_claims``
    may include non-reserved claims such as ``{"org_id": str(...)}`` —
    useful for multi-tenant scoping. Never put secrets in ``extra_claims``.
    """
    return _build_token(
        subject=subject,
        token_type="access",
        ttl=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims=extra_claims,
    )


def create_refresh_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a long-lived refresh token.

    Refresh tokens should be stored client-side in an HTTP-only cookie or
    a secure storage mechanism. They are single-purpose: exchanging them
    for a new access token. They must **not** be accepted anywhere else.
    """
    return _build_token(
        subject=subject,
        token_type="refresh",
        ttl=timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        extra_claims=extra_claims,
    )


def create_token_pair(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """
    Convenience helper: return ``(access_token, refresh_token)`` for the
    same subject with the same extra claims. Used by login and register
    endpoints.
    """
    access = create_access_token(subject, extra_claims)
    refresh = create_refresh_token(subject, extra_claims)
    return access, refresh


# ============================================================================
# JWT — TOKEN DECODING
# ============================================================================

def decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    """
    Decode and validate a JWT.

    Validation performed:
        - Signature is valid for the configured algorithm and secret
        - ``exp`` has not passed
        - ``nbf`` (if present) has passed
        - ``type`` equals ``expected_type``

    Raises:
        TokenExpiredError   — token has expired
        InvalidTokenError   — any other validation failure
    """
    if not isinstance(token, str) or not token:
        raise InvalidTokenError(
            message="Token must be a non-empty string",
            code="JWT_INVALID_INPUT",
        )

    try:
        payload = jwt.decode(
            token,
            _get_jwt_secret(),
            algorithms=[_get_jwt_algorithm()],
            options={"verify_aud": False},  # aud is per-deployment; not used yet
        )
    except JoseExpiredSignatureError as exc:
        raise TokenExpiredError(
            message="Token has expired",
            code="JWT_EXPIRED",
        ) from exc
    except JWTError as exc:
        raise InvalidTokenError(
            message="Token is invalid",
            code="JWT_INVALID",
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidTokenError(
            message="Decoded token payload is not an object",
            code="JWT_INVALID_PAYLOAD",
        )

    actual_type = payload.get("type")
    if actual_type != expected_type:
        raise InvalidTokenError(
            message=f"Expected token type {expected_type!r}",
            code="JWT_WRONG_TYPE",
            details={"expected": expected_type, "actual": actual_type},
        )

    return payload


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode an access token. Raises if the token is any other type."""
    return decode_token(token, "access")


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Decode a refresh token. Raises if the token is any other type."""
    return decode_token(token, "refresh")


# ============================================================================
# JWT — CLAIM EXTRACTION
# ============================================================================

def extract_subject(payload: dict[str, Any]) -> str:
    """Return the ``sub`` claim as a non-empty string, or raise."""
    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise InvalidTokenError(
            message="Token has no valid 'sub' claim",
            code="JWT_NO_SUBJECT",
        )
    return sub


def extract_jti(payload: dict[str, Any]) -> str:
    """
    Return the ``jti`` claim (unique token ID), or raise.

    Useful for building a revocation blocklist keyed on token IDs.
    """
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidTokenError(
            message="Token has no valid 'jti' claim",
            code="JWT_NO_JTI",
        )
    return jti


# ============================================================================
# UTILITIES
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure URL-safe random token.

    The output string is longer than ``length`` (``token_urlsafe`` encodes
    3 bytes per 4 characters). Used for enrollment tokens, password reset
    tokens, and API keys.
    """
    if length < 16:
        raise ValueError("Secure token length must be at least 16 bytes")
    return secrets.token_urlsafe(length)


__all__ = [
    # Constants
    "MIN_PASSWORD_BYTES",
    "MAX_PASSWORD_BYTES",
    "TokenType",
    # Passwords
    "hash_password",
    "verify_password",
    "needs_rehash",
    "reset_password_context_for_tests",
    # Token creation
    "create_access_token",
    "create_refresh_token",
    "create_token_pair",
    # Token decoding
    "decode_token",
    "decode_access_token",
    "decode_refresh_token",
    # Claim extraction
    "extract_subject",
    "extract_jti",
    # Utilities
    "generate_secure_token",
]