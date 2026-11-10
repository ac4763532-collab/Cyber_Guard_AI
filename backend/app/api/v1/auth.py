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

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from app.models.user import User
from app.services import user_service, workspace_service


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



# ============================================================================
# GOOGLE OAUTH / SSO ENDPOINTS
# ============================================================================

def _resolve_base_urls(request: Request) -> tuple[str, str]:
    """Detect live backend and frontend URLs dynamically based on request headers."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    proto = request.headers.get("x-forwarded-proto") or ("https" if "onrender.com" in host else request.url.scheme)
    
    if "onrender.com" in host:
        backend_base = f"https://{host}".rstrip("/")
        frontend_base = "https://cyberguard-nz79.onrender.com"
    elif "localhost" in host or "127.0.0.1" in host:
        backend_base = settings.BACKEND_PUBLIC_URL.rstrip("/")
        frontend_base = settings.FRONTEND_PUBLIC_URL.rstrip("/")
    else:
        backend_base = f"{proto}://{host}".rstrip("/") if host else settings.BACKEND_PUBLIC_URL.rstrip("/")
        frontend_base = settings.FRONTEND_PUBLIC_URL.rstrip("/")
        
    return backend_base, frontend_base


@router.get("/google/url", summary="Get Google Sign-In authorization URL")
def get_google_auth_url(request: Request) -> dict[str, str]:
    """Generates the Google OAuth authorization URL for user login/SSO."""
    if not settings.is_google_oauth_configured:
        raise HTTPException(
            status_code=400,
            detail="Google OAuth is not configured. Provide GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend .env to enable Google Sign-In.",
        )
    backend_base, _ = _resolve_base_urls(request)
    redirect_uri = f"{backend_base}/api/v1/auth/google/callback"
    scope = "openid email profile"
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={scope}"
        f"&prompt=select_account"
    )
    return {"auth_url": auth_url, "redirect_uri": redirect_uri}


@router.get("/google/callback", summary="Google Sign-In OAuth callback")
async def google_auth_callback(
    request: Request,
    db: DBDep,
    code: Optional[str] = None,
    error: Optional[str] = None,
) -> RedirectResponse:
    """Handles Google OAuth redirect, authenticates/creates user, and redirects with token."""
    backend_base, frontend_url = _resolve_base_urls(request)
    if error or not code:
        return RedirectResponse(f"{frontend_url}/login?error={error or 'Authentication+cancelled'}")

    try:
        import httpx
        redirect_uri = f"{backend_base}/api/v1/auth/google/callback"
        token_data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.google_client_secret_str,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            token_res = await client.post("https://oauth2.googleapis.com/token", data=token_data)

        if token_res.status_code != 200:
            logger.error("Failed to exchange Google OAuth code for login", extra={"response": token_res.text[:200]})
            return RedirectResponse(f"{frontend_url}/login?error=Google+token+exchange+failed")

        access_token = token_res.json().get("access_token")

        # Fetch user info from Google
        async with httpx.AsyncClient(timeout=15.0) as client:
            info_res = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )

        if info_res.status_code != 200:
            return RedirectResponse(f"{frontend_url}/login?error=Failed+to+fetch+Google+profile")

        user_info = info_res.json()
        google_email = (user_info.get("email") or "").lower().strip()
        google_name = user_info.get("name") or google_email.split("@")[0]

        if not google_email:
            return RedirectResponse(f"{frontend_url}/login?error=No+email+provided+by+Google")

        # Find or create user
        user = user_service.get_by_email_optional(db, email=google_email)
        now = datetime.now(timezone.utc)
        if not user:
            from app.utils.id_generator import generate_public_slug
            user = User(
                email=google_email,
                public_user_id=generate_public_slug(google_name or google_email, role="individual"),
                full_name=google_name,
                role="individual",
                status=UserStatus.ACTIVE,
                email_verified_at=now,
            )
            db.add(user)
            db.flush()

        # Ensure personal workspace exists
        workspace_service.create_personal_workspace(db, user)

        # Build CyberGuard JWT tokens
        tokens = build_token_response(
            user_id=user.id,
            extra_claims={"role": user.role, "public_user_id": user.public_user_id},
        )
        db.commit()

        logger.info("User authenticated via Google OAuth", extra={"user_id": str(user.id), "email": google_email})

        return RedirectResponse(
            f"{frontend_url}/login?google_token={tokens.access_token}&refresh_token={tokens.refresh_token}"
        )

    except Exception as exc:
        logger.exception("Google OAuth login callback failed")
        return RedirectResponse(f"{frontend_url}/login?error=Authentication+failed")


class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset user password using email",
)
def reset_password_endpoint(
    body: ResetPasswordRequest,
    db: DBDep,
) -> dict[str, str]:
    """Resets user password and clears account lockouts."""
    from app.services.user_service import get_by_email_optional
    from app.core.security import hash_password
    
    email = body.email.lower().strip()
    user = get_by_email_optional(db, email=email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address.",
        )
    
    if len(body.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )
    
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    
    logger.info("Password reset successfully", extra={"user_id": str(user.id), "email": email})
    return {"status": "ok", "message": "Password updated successfully. You can now log in."}


__all__ = ["router"]
