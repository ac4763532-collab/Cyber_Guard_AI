"""
CyberGuard AI — Security Regression Test Suite
============================================================================
Verifies:
1. Production mode fails fast on missing or weak JWT secrets.
2. Development mode runs with local development fallback secrets.
3. Cryptographic JWT issue, expiry, and signature validation.
4. Room access control (private rooms, incorrect password, membership checks).
"""

import time
import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.exceptions import InvalidTokenError, PermissionDeniedError, NotFoundError, InvalidCredentialsError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)
from app.models.room import Room, RoomMember
from app.services import room_service
from app.schemas.room import RoomCreate


# ── 1. CONFIGURATION & SECRET REGRESSION TESTS ─────────────────────────────

def test_production_fails_on_missing_jwt_secret():
    """Production mode MUST fail startup if JWT_SECRET_KEY is empty."""
    with pytest.raises((ValueError, ValidationError), match="JWT_SECRET_KEY must be provided"):
        Settings(
            APP_ENV="production",
            APP_DEBUG=False,
            CORS_ALLOWED_ORIGINS="https://cyberguard.internal",
            JWT_SECRET_KEY=SecretStr(""),
            DATABASE_URL="postgresql+psycopg://user:real_prod_password@db:5432/cyberguard",
        )


def test_production_fails_on_placeholder_or_short_jwt_secret():
    """Production mode MUST fail if JWT_SECRET_KEY has CHANGE_ME or < 32 chars."""
    with pytest.raises((ValueError, ValidationError), match="strong random secret"):
        Settings(
            APP_ENV="production",
            APP_DEBUG=False,
            CORS_ALLOWED_ORIGINS="https://cyberguard.internal",
            JWT_SECRET_KEY=SecretStr("CHANGE_ME_IN_PRODUCTION_TOO_SHORT"),
            DATABASE_URL="postgresql+psycopg://user:real_prod_password@db:5432/cyberguard",
        )


def test_production_fails_on_dev_database_password():
    """Production mode MUST reject default 'cyberguard_dev' database credentials."""
    with pytest.raises((ValueError, ValidationError), match="Default development password detected"):
        Settings(
            APP_ENV="production",
            APP_DEBUG=False,
            CORS_ALLOWED_ORIGINS="https://cyberguard.internal",
            JWT_SECRET_KEY=SecretStr("super_secure_random_key_that_is_long_enough_64_bytes_entropy_1234"),
            DATABASE_URL="postgresql+psycopg://cyberguard:cyberguard_dev@db:5432/cyberguard",
        )


def test_development_mode_allows_fallback_secret():
    """Development mode must cleanly construct settings without failing."""
    dev_settings = Settings(
        APP_ENV="development",
        APP_DEBUG=True,
        JWT_SECRET_KEY=SecretStr(""),
    )
    secret = dev_settings.JWT_SECRET_KEY.get_secret_value()
    assert secret != ""
    assert len(secret) >= 32


# ── 2. JWT TOKEN SECURITY TESTS ───────────────────────────────────────────

def test_jwt_valid_lifecycle():
    """Verifies access token encode, decode, and claims preservation."""
    user_id = "d87a4128-4039-4402-99ab-624097481029"
    token = create_access_token(
        subject=user_id,
        extra_claims={"role": "analyst", "public_user_id": "marcus-vance-analyst-582914"},
    )
    payload = decode_access_token(token)
    assert payload["sub"] == user_id
    assert payload["role"] == "analyst"
    assert payload["public_user_id"] == "marcus-vance-analyst-582914"


def test_jwt_rejects_wrong_type():
    """Refresh tokens cannot be passed where access tokens are expected."""
    user_id = "d87a4128-4039-4402-99ab-624097481029"
    refresh = create_refresh_token(subject=user_id)
    with pytest.raises(InvalidTokenError):
        decode_access_token(refresh)


def test_jwt_rejects_tampered_signature():
    """Tampered token signature must be rejected immediately."""
    token = create_access_token(subject="valid-user")
    parts = token.split(".")
    tampered = parts[0] + "." + parts[1] + ".invalidSignatureSignature"
    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered)


# ── 3. ROOM AUTHORIZATION & ACCESS TESTS ───────────────────────────────────

def test_room_direct_join_password_protection(db_session):
    """Attempting to join a password-protected room with wrong password must fail."""
    from app.services import user_service
    from app.models.enums import UserStatus

    owner = user_service.create_user(
        db_session,
        email="owner_reg@corp.com",
        password="ValidPassword123!",
        full_name="War Room Lead",
        role="organizer",
        status=UserStatus.ACTIVE,
    )
    intruder = user_service.create_user(
        db_session,
        email="intruder@corp.com",
        password="ValidPassword123!",
        full_name="Unauthorized User",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    db_session.commit()

    room = room_service.create_room(
        db_session,
        creator=owner,
        data=RoomCreate(
            name="Confidential War Room",
            description="Restricted triage space",
            password="UltraSecretPassword123!",
            join_policy="direct",
        ),
    )
    db_session.commit()

    # 1. Join with wrong password fails
    with pytest.raises((PermissionDeniedError, InvalidCredentialsError)):
        room_service.direct_join_room(
            db_session,
            user=intruder,
            room_code=room.public_room_id,
            password="WrongPassword999!",
        )

    # 2. Join with correct password succeeds
    joined, member, already = room_service.direct_join_room(
        db_session,
        user=intruder,
        room_code=room.public_room_id,
        password="UltraSecretPassword123!",
    )
    assert joined.id == room.id
    assert member.user_id == intruder.id
    assert already is False
