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

import os
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional
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
# STRICT 3-STEP REGISTRATION VERIFICATION
# ============================================================================

_registration_verification_store: dict[str, dict[str, Any]] = {}


def _send_email_via_http(to_email: str, subject: str, html_content: str, text_content: str) -> tuple[bool, str]:
    """Dispatches email via HTTPS REST API (Port 443) which is never blocked by cloud firewalls like Render."""
    import httpx

    # 1. Resend (https://resend.com)
    resend_key = (
        os.getenv("RESEND_API_KEY")
        or os.getenv("RESEND_KEY")
        or (settings.RESEND_API_KEY.get_secret_value() if hasattr(settings.RESEND_API_KEY, "get_secret_value") else str(settings.RESEND_API_KEY))
        or ""
    ).strip().strip("\"'").strip()
    if resend_key:
        try:
            custom_from = (settings.EMAIL_FROM_ADDRESS or "").strip().strip("\"'")
            if custom_from and "@" in custom_from and not any(custom_from.lower().endswith(d) for d in [".local", "gmail.com", "googlemail.com", "cyberguard.ai", "cyberguard.local"]):
                from_addr = custom_from
            else:
                from_addr = "onboarding@resend.dev"
            payload = {
                "from": f"{settings.EMAIL_FROM_NAME or 'CyberGuard AI'} <{from_addr}>",
                "to": [to_email],
                "subject": subject,
                "html": html_content,
                "text": text_content,
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                if res.status_code in [200, 201]:
                    logger.info("Email dispatched successfully via Resend HTTPS API to %s", to_email)
                    return True, "Email dispatched via Resend HTTPS API"
                else:
                    err_snippet = res.text[:200]
                    logger.warning("Resend API rejected email to %s (HTTP %s): %s", to_email, res.status_code, err_snippet)
                    return False, f"Resend API ({res.status_code}): {err_snippet}"
        except Exception as e:
            logger.error("Resend HTTP request failed for %s: %s", to_email, e)
            return False, f"Resend HTTP request failed: {str(e)}"

    # 2. Brevo (https://brevo.com)
    brevo_key = os.getenv("BREVO_API_KEY") or (
        settings.BREVO_API_KEY.get_secret_value() if hasattr(settings.BREVO_API_KEY, "get_secret_value") else str(settings.BREVO_API_KEY)
    ) or ""
    brevo_key = brevo_key.strip().strip("\"'")
    if brevo_key:
        try:
            payload = {
                "sender": {"name": settings.EMAIL_FROM_NAME or "CyberGuard AI", "email": settings.EMAIL_FROM_ADDRESS or "security@cyberguard.ai"},
                "to": [{"email": to_email}],
                "subject": subject,
                "htmlContent": html_content,
                "textContent": text_content,
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.post(
                    "https://api.brevo.com/v3/smtp/email",
                    headers={"api-key": brevo_key, "Content-Type": "application/json"},
                    json=payload,
                )
                if res.status_code in [200, 201]:
                    logger.info("Email dispatched successfully via Brevo HTTPS API to %s", to_email)
                    return True, "Email dispatched via Brevo HTTPS API"
                else:
                    return False, f"Brevo API ({res.status_code}): {res.text[:120]}"
        except Exception as e:
            return False, f"Brevo HTTP request failed: {str(e)}"

    return False, "NO_HTTP_PROVIDER"

def _send_registration_email(to_email: str, code: str, user_name: str | None = None) -> tuple[bool, str]:
    """Dispatches a secure 6-digit registration verification OTP code via SMTP / Gmail."""
    smtp_host = (settings.SMTP_HOST or "").strip().strip("\"'").strip()
    smtp_port = settings.SMTP_PORT
    smtp_user = (settings.SMTP_USERNAME or "").strip().strip("\"'").strip()
    raw_pass = (
        settings.SMTP_PASSWORD.get_secret_value()
        if hasattr(settings.SMTP_PASSWORD, "get_secret_value")
        else str(settings.SMTP_PASSWORD)
    ) or ""
    smtp_pass = raw_pass.strip().strip("\"'").strip().replace(" ", "")

    from_addr = settings.EMAIL_FROM_ADDRESS or (smtp_user if smtp_user else "security@cyberguard.ai")
    from_name = settings.EMAIL_FROM_NAME or "CyberGuard AI Security"

    display_name = user_name or "Security Operator"

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 24px;">
  <div style="max-width: 520px; margin: 0 auto; background-color: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);">
    <div style="text-align: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 24px; letter-spacing: -0.5px;">🛡️ CyberGuard AI</h2>
      <p style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Account Registration &amp; Email Verification</p>
    </div>
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
      Welcome to CyberGuard AI, <strong>{display_name}</strong>!
    </p>
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
      To verify your email address and activate your security workspace, enter the 6-digit verification code below:
    </p>
    <div style="text-align: center; margin: 28px 0;">
      <span style="display: inline-block; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #38bdf8; background: #0f172a; border: 1px solid #0284c7; padding: 12px 28px; border-radius: 8px; font-family: monospace;">
        {code}
      </span>
    </div>
    <p style="font-size: 12px; color: #94a3b8; text-align: center;">
      This verification code is valid for <strong>15 minutes</strong>. If you did not create an account with CyberGuard AI, please ignore this email.
    </p>
  </div>
</body>
</html>"""

    # 1. Try HTTPS email provider (never blocked by Render firewall)
    sent_http, msg_http = _send_email_via_http(to_email, f"CyberGuard AI — Your Registration Verification Code: {code}", html_content, f"Your CyberGuard AI verification code is {code}. Valid for 15 minutes.")
    if sent_http:
        return True, msg_http
    if msg_http != "NO_HTTP_PROVIDER":
        return False, msg_http

    # 2. Try SMTP
    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"CyberGuard AI — Your Registration Verification Code: {code}"
            msg["From"] = f"{from_name} <{from_addr}>"
            msg["To"] = to_email
            msg.attach(MIMEText(f"Your CyberGuard AI verification code is {code}. Valid for 15 minutes.", "plain"))
            msg.attach(MIMEText(html_content, "html"))

            if settings.SMTP_USE_TLS:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)

            logger.info("Registration OTP code successfully dispatched via SMTP to %s", to_email)
            return True, "Email dispatched successfully via SMTP"
        except Exception as exc:
            err_str = str(exc)
            if "101" in err_str or "unreachable" in err_str.lower():
                err_msg = "Render blocks outbound SMTP port 587. For real emails, use RESEND_API_KEY (HTTPS Port 443), or use the test code shown on screen."
            else:
                err_msg = f"SMTP error ({type(exc).__name__}): {err_str}"
            logger.error("Failed to dispatch SMTP email to %s: %s", to_email, exc)
            return False, err_msg
    else:
        missing = []
        if not smtp_host: missing.append("SMTP_HOST")
        if not smtp_user: missing.append("SMTP_USERNAME")
        if not smtp_pass: missing.append("SMTP_PASSWORD")
        missing_str = ", ".join(missing)
        logger.info(
            "SMTP credentials incomplete (%s); generated registration OTP for %s: %s",
            missing_str, to_email, code,
        )
        return False, f"Missing SMTP settings on Render: {missing_str} (Do not use quotes like SMTP_HOST=\"\")" 


class RegisterInitiateRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = "individual"


class RegisterVerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post(
    "/register/initiate",
    status_code=status.HTTP_200_OK,
    summary="Step 1: Initiate registration and dispatch 6-digit email OTP",
)
def register_initiate_endpoint(
    body: RegisterInitiateRequest,
    db: DBDep,
) -> dict[str, Any]:
    """Validates registration payload, checks email uniqueness, and dispatches 6-digit OTP code."""
    from app.services.user_service import get_by_email_optional

    email = body.email.lower().strip()
    existing = get_by_email_optional(db, email=email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    pwd = body.password
    if len(pwd) < 8 or not any(c.isalpha() for c in pwd) or not any(c.isdigit() for c in pwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long and contain both letters and numbers.",
        )

    # Clean up expired codes
    now = datetime.now(timezone.utc)
    for k in list(_registration_verification_store.keys()):
        if _registration_verification_store[k]["expires_at"] < now:
            _registration_verification_store.pop(k, None)

    code = f"{secrets.randbelow(1000000):06d}"
    expires_at = now + timedelta(minutes=15)

    _registration_verification_store[email] = {
        "code": code,
        "full_name": body.full_name,
        "role": body.role,
        "expires_at": expires_at,
        "attempts": 0,
        "verified": False,
        "registration_token": None,
    }

    email_sent, status_desc = _send_registration_email(email, code, user_name=body.full_name)

    resp_data = {
        "status": "ok",
        "message": f"A 6-digit verification code has been dispatched to {email}." if email_sent else f"Verification code generated for {email}.",
        "expires_in_minutes": 15,
        "email_dispatched": email_sent,
    }
    if not email_sent:
        resp_data["preview_code"] = code
        resp_data["dev_hint"] = status_desc

    return resp_data


@router.post(
    "/register/verify-code",
    status_code=status.HTTP_200_OK,
    summary="Step 2: Verify registration 6-digit OTP code",
)
def register_verify_code_endpoint(
    body: RegisterVerifyCodeRequest,
) -> dict[str, str]:
    """Validates the 6-digit registration OTP code and authorizes account completion."""
    email = body.email.lower().strip()
    code = body.code.strip()

    entry = _registration_verification_store.get(email)
    now = datetime.now(timezone.utc)

    if not entry or entry["expires_at"] < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired or was not requested. Please restart registration.",
        )

    if entry["attempts"] >= 5:
        _registration_verification_store.pop(email, None)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect verification attempts. Please restart registration.",
        )

    if not secrets.compare_digest(entry["code"], code):
        entry["attempts"] += 1
        remaining = 5 - entry["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification code. {remaining} attempt(s) remaining.",
        )

    entry["verified"] = True
    registration_token = secrets.token_urlsafe(32)
    entry["registration_token"] = registration_token

    return {
        "status": "ok",
        "message": "Email verified successfully! You can now activate your account.",
        "registration_token": registration_token,
    }


# ============================================================================
# POST /register (Step 3: Complete & Activate Account)
# ============================================================================

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Step 3: Complete registration and activate account",
    description=(
        "Finalizes user account creation after verifying the 6-digit email OTP. "
        "Returns authentication tokens and initializes workspace."
    ),
)
def register(
    body: RegisterRequest,
    db: DBDep,
) -> TokenResponse:
    email = body.email.lower().strip()
    reg_entry = _registration_verification_store.get(email)

    # Strict security check: Step 2 verification must be complete
    if not reg_entry or not reg_entry.get("verified"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verification required: Please verify your email with the 6-digit code before completing registration.",
        )

    user = create_user(
        db,
        email=body.email,
        password=body.password,
        full_name=body.full_name or reg_entry.get("full_name"),
        role=body.role or reg_entry.get("role", "individual"),
        status=UserStatus.ACTIVE,
    )
    user.email_verified = True
    user.email_verified_at = datetime.now(timezone.utc)

    # Initialize user's dedicated personal workspace
    workspace_service.create_personal_workspace(db, user)

    tokens = build_token_response(
        user_id=user.id,
        extra_claims={"role": user.role, "public_user_id": user.public_user_id},
    )
    db.commit()

    # Clean up verification entry
    _registration_verification_store.pop(email, None)

    logger.info(
        "User registered and verified via 3-step authentication",
        extra={"user_id": str(user.id), "email": email},
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


# ============================================================================
# STRICT PASSWORD RECOVERY & EMAIL VERIFICATION
# ============================================================================

_reset_verification_store: dict[str, dict[str, Any]] = {}


def _send_recovery_email(to_email: str, code: str, user_name: str | None = None) -> tuple[bool, str]:
    """Dispatches a secure 6-digit recovery OTP code via SMTP / Gmail."""
    smtp_host = (settings.SMTP_HOST or "").strip().strip("\"'").strip()
    smtp_port = settings.SMTP_PORT
    smtp_user = (settings.SMTP_USERNAME or "").strip().strip("\"'").strip()
    raw_pass = (
        settings.SMTP_PASSWORD.get_secret_value()
        if hasattr(settings.SMTP_PASSWORD, "get_secret_value")
        else str(settings.SMTP_PASSWORD)
    ) or ""
    smtp_pass = raw_pass.strip().strip("\"'").strip().replace(" ", "")

    from_addr = settings.EMAIL_FROM_ADDRESS or (smtp_user if smtp_user else "security@cyberguard.ai")
    from_name = settings.EMAIL_FROM_NAME or "CyberGuard AI Security"

    display_name = user_name or "Security Operator"

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f1f5f9; padding: 24px;">
  <div style="max-width: 520px; margin: 0 auto; background-color: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);">
    <div style="text-align: center; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 24px; letter-spacing: -0.5px;">🛡️ CyberGuard AI</h2>
      <p style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Account Security &amp; Password Recovery</p>
    </div>
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
      Hello <strong>{display_name}</strong>,
    </p>
    <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
      A request was received to reset your CyberGuard AI account password. Enter the verification code below to authorize this recovery:
    </p>
    <div style="text-align: center; margin: 28px 0;">
      <span style="display: inline-block; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #38bdf8; background: #0f172a; border: 1px solid #0284c7; padding: 12px 28px; border-radius: 8px; font-family: monospace;">
        {code}
      </span>
    </div>
    <p style="font-size: 12px; color: #94a3b8; text-align: center;">
      This code is valid for <strong>15 minutes</strong>. If you did not request this, ignore this email or alert your security team immediately.
    </p>
  </div>
</body>
</html>"""

    # 1. Try HTTPS email provider (never blocked by Render firewall)
    sent_http, msg_http = _send_email_via_http(to_email, f"CyberGuard AI — Your Recovery Code: {code}", html_content, f"Your CyberGuard AI recovery code is {code}. Valid for 15 minutes.")
    if sent_http:
        return True, msg_http
    if msg_http != "NO_HTTP_PROVIDER":
        return False, msg_http

    # 2. Try SMTP
    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"CyberGuard AI — Your Recovery Code: {code}"
            msg["From"] = f"{from_name} <{from_addr}>"
            msg["To"] = to_email
            msg.attach(MIMEText(f"Your CyberGuard AI recovery code is {code}. Valid for 15 minutes.", "plain"))
            msg.attach(MIMEText(html_content, "html"))

            if settings.SMTP_USE_TLS:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)

            logger.info("Security recovery code dispatched via SMTP to %s", to_email)
            return True, "Recovery email dispatched successfully via SMTP"
        except Exception as exc:
            err_str = str(exc)
            if "101" in err_str or "unreachable" in err_str.lower():
                err_msg = "Render blocks outbound SMTP port 587. For real emails, use RESEND_API_KEY (HTTPS Port 443), or use the test code shown on screen."
            else:
                err_msg = f"SMTP error ({type(exc).__name__}): {err_str}"
            logger.error("Failed to dispatch SMTP recovery email to %s: %s", to_email, exc)
            return False, err_msg
    else:
        missing = []
        if not smtp_host: missing.append("SMTP_HOST")
        if not smtp_user: missing.append("SMTP_USERNAME")
        if not smtp_pass: missing.append("SMTP_PASSWORD")
        missing_str = ", ".join(missing)
        logger.info(
            "SMTP credentials incomplete (%s); generated security OTP for %s: %s",
            missing_str, to_email, code,
        )
        return False, f"Missing SMTP settings on Render: {missing_str} (Do not use quotes like SMTP_HOST=\"\")" 


class ForgotPasswordRequest(BaseModel):
    email: str


class VerifyResetCodeRequest(BaseModel):
    email: str
    code: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: Optional[str] = None
    reset_token: Optional[str] = None
    new_password: str


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    summary="Request a password recovery verification code via email",
)
def forgot_password_endpoint(
    body: ForgotPasswordRequest,
    db: DBDep,
) -> dict[str, Any]:
    """Generates a secure 6-digit OTP code and dispatches it via email/Gmail."""
    from app.services.user_service import get_by_email_optional

    email = body.email.lower().strip()
    user = get_by_email_optional(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address.",
        )

    # Clean up expired codes
    now = datetime.now(timezone.utc)
    for k in list(_reset_verification_store.keys()):
        if _reset_verification_store[k]["expires_at"] < now:
            _reset_verification_store.pop(k, None)

    code = f"{secrets.randbelow(1000000):06d}"
    expires_at = now + timedelta(minutes=15)

    _reset_verification_store[email] = {
        "code": code,
        "expires_at": expires_at,
        "attempts": 0,
        "verified": False,
        "reset_token": None,
    }

    email_sent, status_desc = _send_recovery_email(email, code, user_name=user.full_name)

    resp_data = {
        "status": "ok",
        "message": f"A 6-digit verification code has been dispatched to {email}." if email_sent else f"Verification code generated for {email}.",
        "expires_in_minutes": 15,
        "email_dispatched": email_sent,
    }
    if not email_sent:
        resp_data["preview_code"] = code
        resp_data["dev_hint"] = status_desc

    return resp_data


@router.post(
    "/verify-reset-code",
    status_code=status.HTTP_200_OK,
    summary="Verify the 6-digit recovery code sent via email",
)
def verify_reset_code_endpoint(
    body: VerifyResetCodeRequest,
) -> dict[str, str]:
    """Validates the 6-digit code and issues a temporary single-use reset authorization token."""
    email = body.email.lower().strip()
    code = body.code.strip()

    entry = _reset_verification_store.get(email)
    now = datetime.now(timezone.utc)

    if not entry or entry["expires_at"] < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired or was not requested. Please request a new code.",
        )

    if entry["attempts"] >= 5:
        _reset_verification_store.pop(email, None)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect verification attempts. Please request a new code.",
        )

    if not secrets.compare_digest(entry["code"], code):
        entry["attempts"] += 1
        remaining = 5 - entry["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification code. {remaining} attempt(s) remaining.",
        )

    entry["verified"] = True
    reset_token = secrets.token_urlsafe(32)
    entry["reset_token"] = reset_token

    return {
        "status": "ok",
        "message": "Verification code accepted. Please enter your new password.",
        "reset_token": reset_token,
    }


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset user password after email verification",
)
def reset_password_endpoint(
    body: ResetPasswordRequest,
    db: DBDep,
) -> dict[str, str]:
    """Strictly updates user password only after verifying email code or reset token."""
    from app.services.user_service import get_by_email_optional
    from app.core.security import hash_password

    email = body.email.lower().strip()
    entry = _reset_verification_store.get(email)
    now = datetime.now(timezone.utc)

    if not entry or entry["expires_at"] < now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verification required: Please request and verify your email recovery code first.",
        )

    # Check verification: either pre-verified via token, or verified directly via code
    is_authorized = False
    if body.reset_token and entry.get("reset_token"):
        if secrets.compare_digest(entry["reset_token"], body.reset_token.strip()) and entry.get("verified"):
            is_authorized = True
    elif body.code:
        if secrets.compare_digest(entry["code"], body.code.strip()):
            is_authorized = True

    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unverified recovery credentials. Please verify your code.",
        )

    user = get_by_email_optional(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address.",
        )

    new_pwd = body.new_password
    if len(new_pwd) < 8 or not any(c.isalpha() for c in new_pwd) or not any(c.isdigit() for c in new_pwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long and contain both letters and numbers.",
        )

    user.password_hash = hash_password(new_pwd)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    # Clear recovery session
    _reset_verification_store.pop(email, None)

    logger.info("Password successfully recovered and updated", extra={"user_id": str(user.id), "email": email})
    return {"status": "ok", "message": "Password updated successfully. You can now log in with your new password."}


# ============================================================================
# EMAIL DIAGNOSTICS & TEST ENDPOINTS
# ============================================================================

@router.get("/email/status", summary="Check email delivery configuration status")
def email_status_endpoint() -> dict[str, Any]:
    resend_key = (
        os.getenv("RESEND_API_KEY")
        or os.getenv("RESEND_KEY")
        or (settings.RESEND_API_KEY.get_secret_value() if hasattr(settings.RESEND_API_KEY, "get_secret_value") else str(settings.RESEND_API_KEY))
        or ""
    ).strip().strip("\"'").strip()
    
    brevo_key = (
        os.getenv("BREVO_API_KEY")
        or (settings.BREVO_API_KEY.get_secret_value() if hasattr(settings.BREVO_API_KEY, "get_secret_value") else str(settings.BREVO_API_KEY))
        or ""
    ).strip().strip("\"'").strip()

    smtp_host = (settings.SMTP_HOST or "").strip().strip("\"'").strip()
    smtp_user = (settings.SMTP_USERNAME or "").strip().strip("\"'").strip()

    return {
        "status": "ok",
        "resend_configured": bool(resend_key),
        "resend_key_prefix": f"{resend_key[:6]}..." if len(resend_key) > 6 else ("empty" if not resend_key else "set"),
        "brevo_configured": bool(brevo_key),
        "smtp_configured": bool(smtp_host and smtp_user),
        "smtp_host": smtp_host,
        "smtp_user": smtp_user,
        "email_from_address": settings.EMAIL_FROM_ADDRESS,
        "active_provider": "resend" if resend_key else ("brevo" if brevo_key else ("smtp" if smtp_host else "none")),
    }


class EmailTestRequest(BaseModel):
    email: str


@router.post("/email/test", summary="Send a test email to verify live delivery")
def email_test_endpoint(body: EmailTestRequest) -> dict[str, Any]:
    test_code = f"{secrets.randbelow(1000000):06d}"
    sent, detail = _send_recovery_email(body.email.lower().strip(), test_code, user_name="Security Admin")
    return {
        "success": sent,
        "detail": detail,
        "recipient": body.email.lower().strip(),
        "test_code": test_code,
    }


__all__ = ["router"]
