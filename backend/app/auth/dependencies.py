"""
CyberGuard AI — FastAPI Authentication Dependencies
============================================================================

The concrete FastAPI dependencies that resolve "who is making this
request" and enforce "are they allowed to do this".

Dependency chain
----------------
    get_current_user                    (base — valid token + user exists)
        └── get_current_active_user     (+ status == ACTIVE)
                └── get_current_verified_user  (+ email verified)
                └── get_current_analyst        (+ analyst profile + verified)
                └── get_current_super_admin    (+ super admin role)
                └── require_permission(perm)   (+ REAL permission check)
                └── require_any_permission(*perms)  (+ REAL OR check)

    get_current_user_optional           (parallel — no failure, returns None)

Because each layer builds on the previous, FastAPI's dependency cache
ensures the base `get_current_user` runs exactly once per request,
regardless of how many child dependencies are used.

What changed from the original stub
-----------------------------------
`require_permission` and `require_any_permission` used to log a WARNING
and always return the user. They now call into
`app.services.authorization.check_permission` / `has_permission` —
the full RBAC + resource-grant engine delivered in File 69.

Scope semantics
---------------
These dependency-level checks are **coarse "any scope" gates**:
"does this user hold this permission in *some* org or workspace
they belong to?" They are the fast-fail gate that runs before the
endpoint handler executes.

The **fine-grained, resource-scoped** check happens inside the
endpoint or service, using the full `check_permission(db, user,
permission, resource=case)` API from `authorization.py`. That is
where tenant isolation, case access grants, and evidence scopes are
enforced.

Why both?
    - The dependency gate rejects obviously-unauthorized users early
      (no DB writes, no side effects, no log noise from "correct
      shape but wrong permissions" requests).
    - The endpoint check enforces "this specific user, on this
      specific resource". A user can have PERM_CASE_READ in
      workspace A and be legitimately forbidden from a case in
      workspace B.

Design rules
------------
1. **Failures raise `CyberGuardError` subclasses.** No bare
   `HTTPException`. The exception handler in `main.py` produces the
   `ErrorResponse` body consistently.

2. **Soft-deleted users are rejected at `get_current_user`.** A
   soft-deleted user must never resolve to a `User` instance anywhere
   downstream.

3. **`require_permission` now ENFORCES, not just logs.**
   The WARNING log is gone. Denials raise `AuthorizationError` with
   code `PERMISSION_DENIED`.

4. **`get_current_super_admin` still fails closed.** Until a super
   admin column or role exists, admin endpoints return 403.

5. **`get_current_analyst` is a real check.**

6. **`get_current_user_optional` returns None on any auth failure.**

7. **No business logic.** Identity + permission enforcement only.
   Resource-specific authorization (case grants, evidence scope) is
   the endpoint's responsibility via `authorization.check_permission`.

8. **Correlation ID propagation.** If `X-Correlation-ID` is present
   in the request headers, it's set in the log context here.

Usage
-----
    from fastapi import Depends
    from app.auth.dependencies import (
        get_current_active_user, require_permission, require_any_permission,
    )
    from app.models import User

    # Basic authentication:
    @router.get("/me")
    def get_me(user: User = Depends(get_current_active_user)) -> UserRead:
        ...

    # Authentication + coarse permission check (returns the User):
    @router.get("/cases")
    def list_cases(
        user: User = Depends(require_permission("case:read")),
    ) -> list[CaseRead]:
        ...

    # Authentication + coarse OR permission check:
    @router.get(
        "/incidents",
        dependencies=[
            Depends(require_any_permission("incident:read", "case:read")),
        ],
    )
    def list_incidents(...): ...

    # Fine-grained resource check inside the endpoint:
    @router.get("/cases/{id}")
    def get_case(
        id: UUID,
        user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db),
    ) -> CaseRead:
        case = case_service.get_by_id(db, id)
        # This enforces "this user, this case, at this scope":
        authorization.require_case_access(db, user, case)
        return CaseRead.model_validate(case)
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.jwt import (
    extract_user_id_from_token,
    parse_authorization_header,
)
from app.core.constants import ALL_PERMISSIONS, HEADER_CORRELATION_ID
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    TokenExpiredError,
)
from app.core.logging import get_logger, set_correlation_id
from app.db.session import get_db
from app.models.analyst import AnalystProfile
from app.models.enums import AnalystVerificationStatus, UserStatus
from app.models.user import User

# ── Authorization engine (File 69) ─────────────────────────────────────────
from app.services.authorization import (
    ORG_ROLE_PERMISSIONS,
    WORKSPACE_ROLE_PERMISSIONS,
    check_permission,
    get_user_org_role,
    get_user_organizations,
    get_user_workspace_role,
    get_user_workspaces,
    has_permission,
    is_super_admin,
)


logger = get_logger(__name__)


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _propagate_correlation_id(request: Request) -> None:
    """
    Copy the incoming ``X-Correlation-ID`` header into the log context.
    """
    header_value = request.headers.get(HEADER_CORRELATION_ID)
    if header_value:
        stripped = header_value.strip()
        if stripped:
            set_correlation_id(stripped)


def _resolve_user_from_header(
    authorization: str | None,
    db: Session,
    *,
    log_failure: bool = True,
) -> User | None:
    """
    Shared implementation: parse header → decode token → load user.
    """
    token = parse_authorization_header(authorization)
    user_id = extract_user_id_from_token(token)

    user = db.get(User, user_id)
    if user is None:
        if log_failure:
            logger.debug(
                "Token references a user that no longer exists",
                extra={"user_id": str(user_id)},
            )
        return None

    if user.deleted_at is not None:
        if log_failure:
            logger.debug(
                "Token references a soft-deleted user",
                extra={"user_id": str(user_id)},
            )
        return None

    return user


def _user_has_permission_anywhere(
    db: Session,
    user: User,
    permission: str,
) -> bool:
    """
    Coarse permission check: does this user hold ``permission`` in
    *any* of their org or workspace scopes?

    This is a fast-fail gate for `require_permission`. It answers
    "is there any legitimate context where this user could exercise
    this permission?" — not "can they exercise it on the specific
    resource the endpoint is about to touch."

    The endpoint is responsible for the fine-grained check via
    ``authorization.check_permission(..., resource=...)``.

    Performance note
    ----------------
    For a typical user (1 org + 1 personal workspace), this runs
    2–4 indexed queries. For users in many workspaces, it is O(N)
    per permission check. If profiling shows this as a bottleneck,
    a request-scoped cache or a pre-computed ``user_permission_set``
    view will fix it. Do not optimize preemptively.
    """
    # ── Fast path 1: self-service permissions (checked via the engine's
    #    no-scope path, which handles _SELF and platform-permissions)
    if has_permission(db, user, permission):
        return True

    # ── Fast path 2: platform permissions (super admin)
    if permission.startswith("admin:"):
        return is_super_admin(user)

    # ── Iterate every org membership
    for org_id in get_user_organizations(db, user):
        role = get_user_org_role(db, user, org_id)
        if role is None:
            continue
        if permission in ORG_ROLE_PERMISSIONS.get(role, frozenset()):
            return True

    # ── Iterate every workspace membership
    for ws_id in get_user_workspaces(db, user):
        role = get_user_workspace_role(db, user, ws_id)
        if role is None:
            continue
        if permission in WORKSPACE_ROLE_PERMISSIONS.get(role, frozenset()):
            return True

    return False


# ============================================================================
# BASE DEPENDENCY — GET CURRENT USER
# ============================================================================

def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """
    Resolve the authenticated user from the ``Authorization: Bearer``
    header.

    Checks
    ------
    - Header is present and in ``Bearer <token>`` format
    - Token signature is valid and not expired
    - Token type is ``access``
    - ``sub`` claim is a valid UUID
    - User exists in the database
    - User is not soft-deleted

    Raises
    ------
    AuthenticationError, InvalidTokenError, TokenExpiredError
    """
    _propagate_correlation_id(request)

    user = _resolve_user_from_header(authorization, db)
    if user is None:
        raise AuthenticationError(
            message="User account no longer exists.",
            code="AUTH_USER_NOT_FOUND",
        )

    return user


# ============================================================================
# STATUS-CHECKED DEPENDENCIES
# ============================================================================

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Like ``get_current_user`` but additionally requires
    ``status == ACTIVE``.
    """
    if not current_user.is_active:
        raise AuthorizationError(
            message=(
                "Account is not active. "
                f"Current status: {current_user.status.value}."
            ),
            code="ACCOUNT_NOT_ACTIVE",
            details={
                "status": current_user.status.value,
                "email_verified": current_user.is_email_verified,
            },
        )
    return current_user


def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Requires the user's email to be verified.
    """
    if not current_user.is_email_verified:
        raise AuthorizationError(
            message=(
                "Email address must be verified before performing this action."
            ),
            code="EMAIL_NOT_VERIFIED",
        )
    return current_user


# ============================================================================
# OPTIONAL AUTH — ANONYMOUS ALLOWED
# ============================================================================

def get_current_user_optional(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User | None:
    """
    Resolve the authenticated user if a valid token is present; return
    ``None`` otherwise.
    """
    _propagate_correlation_id(request)

    if authorization is None:
        return None

    if isinstance(authorization, str) and not authorization.strip():
        return None

    try:
        user = _resolve_user_from_header(authorization, db, log_failure=False)
    except (AuthenticationError, InvalidTokenError, TokenExpiredError) as exc:
        logger.debug(
            "Optional auth failed; treating as anonymous",
            extra={
                "error_code": getattr(exc, "code", "unknown"),
                "error_type": type(exc).__name__,
            },
        )
        return None

    return user


# ============================================================================
# ANALYST
# ============================================================================

def get_current_analyst(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> AnalystProfile:
    """
    Requires the user to have a **verified** analyst profile.
    """
    profile = db.execute(
        select(AnalystProfile).where(AnalystProfile.user_id == current_user.id)
    ).scalar_one_or_none()

    if profile is None:
        raise AuthorizationError(
            message="An analyst profile is required for this action.",
            code="ANALYST_PROFILE_NOT_FOUND",
        )

    if profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise AuthorizationError(
            message=(
                "Analyst account is not verified. "
                f"Current verification status: {profile.verification_status.value}."
            ),
            code="ANALYST_NOT_VERIFIED",
            details={"verification_status": profile.verification_status.value},
        )

    return profile


# ============================================================================
# SUPER ADMIN
# ============================================================================

def get_current_super_admin(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Requires the user to be a **platform** super admin.

    Fails closed — no user has this role until a dedicated
    ``is_super_admin`` column is added via migration.
    """
    if not is_super_admin(current_user):
        raise AuthorizationError(
            message=(
                "Super admin access required. The super admin role "
                "is not yet configured on this deployment."
            ),
            code="SUPER_ADMIN_REQUIRED",
        )
    return current_user


# ============================================================================
# PERMISSION FACTORIES — REAL ENFORCEMENT
# ============================================================================

def require_permission(permission: str) -> Callable[..., User]:
    """
    Return a FastAPI dependency that requires the current user to hold
    ``permission`` in at least one of their scopes.

    Behavior
    --------
    1. Validates ``permission`` against ``ALL_PERMISSIONS`` at
       dependency construction time. A typo crashes the app at import,
       not at request time.
    2. On every request, calls
       ``_user_has_permission_anywhere(db, user, permission)``.
    3. If False → raises ``AuthorizationError(PERMISSION_DENIED)``.
    4. If True → returns the ``User`` so the endpoint can use it.

    This is a **coarse gate**. It answers "does this user have this
    permission somewhere?". The endpoint is responsible for
    enforcing "on this specific resource" via
    ``authorization.check_permission(..., resource=...)``.

    Usage
    -----
        # As a parameter — returns the authenticated User:
        @router.get("/cases")
        def list_cases(
            user: User = Depends(require_permission("case:read")),
        ) -> ...:
            ...

        # As a decorative dependency — no return value used:
        @router.delete(
            "/cases/{id}",
            dependencies=[Depends(require_permission("case:close"))],
        )
        def close_case(id: UUID) -> None:
            ...

    Raises
    ------
    ValueError
        If ``permission`` is not in ``ALL_PERMISSIONS`` — at dependency
        construction time.
    AuthorizationError
        Per request, if the user lacks the permission.
    """
    if permission not in ALL_PERMISSIONS:
        raise ValueError(
            f"Unknown permission: {permission!r}. "
            f"Valid permissions are defined in "
            f"app.core.constants.ALL_PERMISSIONS."
        )

    def dependency(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db),
    ) -> User:
        if not _user_has_permission_anywhere(db, current_user, permission):
            logger.info(
                "Permission denied at dependency gate",
                extra={
                    "permission": permission,
                    "user_id": str(current_user.id),
                },
            )
            raise AuthorizationError(
                message=f"Permission denied: {permission}",
                code="PERMISSION_DENIED",
                details={"permission": permission},
            )
        return current_user

    return dependency


def require_any_permission(*permissions: str) -> Callable[..., User]:
    """
    Return a FastAPI dependency that requires the current user to hold
    **at least one** of ``permissions`` in any of their scopes.

    Usage
    -----
        @router.get(
            "/incidents",
            dependencies=[
                Depends(require_any_permission("incident:read", "case:read")),
            ],
        )
        def list_incidents(...): ...

    Raises
    ------
    ValueError
        If zero permissions are provided, or any argument is not in
        ``ALL_PERMISSIONS``.
    AuthorizationError
        Per request, if the user has none of the permissions.
    """
    if not permissions:
        raise ValueError(
            "require_any_permission() must be called with at least one permission."
        )

    for perm in permissions:
        if perm not in ALL_PERMISSIONS:
            raise ValueError(
                f"Unknown permission: {perm!r}. "
                f"Valid permissions are defined in "
                f"app.core.constants.ALL_PERMISSIONS."
            )

    def dependency(
        current_user: User = Depends(get_current_active_user),
        db: Session = Depends(get_db),
    ) -> User:
        for perm in permissions:
            if _user_has_permission_anywhere(db, current_user, perm):
                return current_user

        logger.info(
            "Permission (any-of) denied at dependency gate",
            extra={
                "required_any": list(permissions),
                "user_id": str(current_user.id),
            },
        )
        raise AuthorizationError(
            message=(
                "Permission denied: requires at least one of "
                f"{list(permissions)}"
            ),
            code="PERMISSION_DENIED",
            details={"required_any": list(permissions)},
        )

    return dependency


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Base
    "get_current_user",
    "get_current_active_user",
    "get_current_verified_user",
    "get_current_user_optional",
    # Role-specific
    "get_current_analyst",
    "get_current_super_admin",
    # Permission factories (now real)
    "require_permission",
    "require_any_permission",
]