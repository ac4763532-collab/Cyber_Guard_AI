"""
CyberGuard AI — Authentication Endpoints
============================================================================

The four endpoints every user encounters first:

    POST /api/v1/auth/register   — create account, return token pair
    POST /api/v1/auth/login      — verify credentials, return token pair
    POST /api/v1/auth/refresh    — exchange refresh token for new pair
    GET  /api/v1/auth/me         — return current user's profile

Design rules
------------
1. **Register commits AFTER token building.** A token-building failure
   rolls back account creation. No orphaned accounts.

2. **Login commits AFTER token building.** `authenticate_user` on the
   success path flushes `last_login_at` but does not commit (service
   contract rule 2). The endpoint commits — order matters.

3. **Refresh re-verifies the user.** A refresh token for a suspended or
   deleted user must not grant new access tokens. Without this check, a
   stolen refresh token would work until its 30-day expiry even after
   the account is disabled.

4. **Login failure is deliberately vague.** `AUTH_INVALID_CREDENTIALS`
   with "Invalid email or password." — identical for unknown-email,
   wrong-password, and OAuth-only cases. Combined with the timing-safe
   dummy check in `authenticate_user`, zero information leaks.

5. **`/auth/me` uses `get_current_user`, not
   `get_current_active_user`.** A `PENDING_VERIFICATION` user can see
   their own account status so the frontend can render "verify your
   email" prompts.

6. **No rate limiting yet.** `# TODO` marker notes where the future
   rate-limit dependency plugs in — no endpoint body changes required.

7. **No correlation ID propagation here.** Middleware in `main.py`
   handles it for every request — one place, applied uniformly.

Endpoints
---------
    POST /register
        Body:    RegisterRequest
        Returns: 201 TokenResponse
        Errors:  409 EMAIL_ALREADY_EXISTS
                 422 validation failure

    POST /login
        Body:    LoginRequest
        Returns: 200 TokenResponse
        Errors:  401 AUTH_INVALID_CREDENTIALS
                 403 ACCOUNT_NOT_ACTIVE / ACCOUNT_LOCKED

    POST /refresh
        Body:    RefreshRequest
        Returns: 200 TokenResponse
        Errors:  401 JWT_EXPIRED / JWT_INVALID / JWT_WRONG_TYPE
                 / AUTH_USER_NOT_FOUND
                 403 ACCOUNT_NOT_ACTIVE

    GET /me
        Auth:    Bearer
        Returns: 200 UserRead
        Errors:  401 AUTH_HEADER_MISSING / JWT_EXPIRED / JWT_INVALID
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.auth.jwt import (
    build_token_response,
    verify_refresh_token,
)
from app.core.exceptions import (
    AccountDisabledError,
    InvalidTokenError,
)
from app.core.logging import get_logger
from app.core.security import extract_subject
from app.models.enums import UserStatus
from app.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services.user_service import (
    authenticate_user,
    create_user,
    get_by_id,
)


logger = get_logger(__name__)


# ============================================================================
# ROUTER
# ============================================================================

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={
        401: {"description": "Authentication required or token invalid"},
        422: {"description": "Request body failed schema validation"},
    },
)


# ============================================================================
# POST /register
# ============================================================================

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account",
    description=(
        "Creates a new user account in `pending_verification` status and "
        "returns a fresh token pair.\n\n"
        "The response is `TokenResponse` — the client should then call "
        "`GET /auth/me` to fetch the user profile. Token response does "
        "not include the user object to avoid a circular schema "
        "dependency."
    ),
    # TODO: apply login rate-limit dependency once rate_limit_service exists
)
def register(
    body: RegisterRequest,
    db: DBDep,
) -> TokenResponse:
    """
    Create account → return token pair.

    Order matters:
      1. `create_user` flushes the new row (in transaction)
      2. `build_token_response` builds JWTs (pure, no DB)
      3. `db.commit` persists the user

    If step 2 fails for any reason, the transaction rolls back and no
    account is created — no orphaned user, no password reset needed.
    """
    from datetime import datetime, timezone
    initial_status = (
        UserStatus.ACTIVE
        if getattr(settings, "AUTO_ACTIVATE_USERS", True) or settings.APP_ENV == "development"
        else UserStatus.PENDING_VERIFICATION
    )
    user = create_user(
        db,
        email=body.email,
        password=body.password,
        full_name=body.full_name,
        role=body.role,
        status=initial_status,
    )
    if initial_status == UserStatus.ACTIVE:
        user.email_verified = True
        user.email_verified_at = datetime.now(timezone.utc)

    tokens = build_token_response(
        user_id=user.id,
        extra_claims={"role": user.role, "public_user_id": user.public_user_id},
    )
    db.commit()

    logger.info(
        "User registered",
        extra={"user_id": str(user.id)},
    )

    return tokens


# ============================================================================
# POST /login
# ============================================================================

@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Log in with email and password",
    description=(
        "Verifies credentials and returns a fresh token pair.\n\n"
        "**Failure modes** (all return identical error body for unknown "
        "email, wrong password, and OAuth-only accounts):\n\n"
        "- `401 AUTH_INVALID_CREDENTIALS` — wrong credentials\n"
        "- `403 ACCOUNT_LOCKED` — too many failed attempts\n"
        "- `403 ACCOUNT_NOT_ACTIVE` — account suspended or not yet verified\n\n"
        "Response time is equalized via a dummy bcrypt check in the "
        "service layer — user enumeration is not possible via timing."
    ),
    # TODO: apply auth rate-limit dependency once rate_limit_service exists
)
def login(
    body: LoginRequest,
    db: DBDep,
) -> TokenResponse:
    """
    Verify credentials → return token pair.

    `authenticate_user` commits on failure paths (documented service
    contract exception). On success it returns without committing — the
    endpoint commits after building tokens so a token-build failure
    doesn't record a login that didn't complete.
    """
    user = authenticate_user(
        db,
        email=body.email,
        password=body.password,
    )

    tokens = build_token_response(
        user_id=user.id,
        extra_claims={"role": user.role, "public_user_id": user.public_user_id},
    )
    db.commit()

    logger.info(
        "User logged in",
        extra={"user_id": str(user.id)},
    )

    return tokens


# ============================================================================
# POST /refresh
# ============================================================================

@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Exchange a refresh token for a new token pair",
    description=(
        "Accepts a refresh token in the request body (not the "
        "Authorization header) and returns a new access/refresh pair.\n\n"
        "The endpoint re-verifies the user: suspended or soft-deleted "
        "users cannot refresh. This prevents stolen refresh tokens from "
        "granting access after the account has been disabled."
    ),
)
def refresh(
    body: RefreshRequest,
    db: DBDep,
) -> TokenResponse:
    """
    Exchange refresh token → new token pair.

    No commit — this is a pure token exchange with no DB writes.
    """
    payload = verify_refresh_token(body.refresh_token)

    sub = extract_subject(payload)
    try:
        user_id = uuid.UUID(sub)
    except (ValueError, TypeError) as exc:
        raise InvalidTokenError(
            message="Refresh token 'sub' claim is not a valid UUID.",
            code="JWT_INVALID_SUBJECT_FORMAT",
        ) from exc

    user = get_by_id(db, user_id)

    if user.status != UserStatus.ACTIVE:
        raise AccountDisabledError(
            message=f"Account is not active: {user.status.value}.",
            code="ACCOUNT_NOT_ACTIVE",
            details={"status": user.status.value},
        )

    tokens = build_token_response(
        user_id=user.id,
        extra_claims={"role": user.role, "public_user_id": user.public_user_id},
    )

    logger.info(
        "Token refreshed",
        extra={"user_id": str(user.id)},
    )

    return tokens


# ============================================================================
# GET /me
# ============================================================================

@router.get(
    "/me",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Get the current user's profile",
    description=(
        "Returns the authenticated user's profile as `UserRead`. Never "
        "includes `password_hash`, `mfa_secret`, or any sensitive field "
        "— those are not declared on `UserRead` and cannot be serialized."
    ),
)
def get_me(
    current_user: CurrentUser,
) -> UserRead:
    """
    Return the authenticated user's profile.

    `current_user` is the ORM instance. `UserRead.model_validate` reads
    its attributes (including ORM properties like `is_active`,
    `is_locked`, `has_password`) and produces a sanitized DTO. Fields
    not declared on `UserRead` are silently dropped.
    """
    return UserRead.model_validate(current_user)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]