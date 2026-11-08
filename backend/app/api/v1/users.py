"""
CyberGuard AI — User Profile and Management Endpoints
============================================================================

Two groups of endpoints:

    Self-service (any authenticated user):
        GET    /users/me              — full profile
        PATCH  /users/me              — update own full_name / timezone / language

    Admin (requires user management permissions):
        GET    /users                 — paginated list with filters
        GET    /users/{user_id}       — view any user
        PATCH  /users/{user_id}       — admin update (status, lockout, MFA)
        POST   /users/{user_id}/unlock — clear lockout

Design rules
------------
1. **`/users/me` is distinct from `/auth/me`.**
   Today both return `UserRead` (same fields). But the *contract* differs:
   ``/auth/me`` is a session check (fast, minimal, always available).
   ``/users/me`` is a profile fetch (can grow to include preferences,
   stats, activity). Clients use ``/auth/me`` on app startup and
   ``/users/me`` when opening settings. When schemas diverge, no client
   changes needed.

2. **Route order matters.**
   ``GET /users/me`` is registered BEFORE ``GET /users/{user_id}``.
   Otherwise FastAPI tries to parse ``"me"`` as a UUID and returns 422.
   FastAPI matches routes in declaration order.

3. **Admins cannot use ``/users/{id}`` on themselves.**
   The admin update endpoint rejects ``user_id == current_user.id``.
   Self-service is ``/users/me``. Prevents accidental privilege changes
   through the admin path.

4. **Admin endpoints use ``require_permission(...)`` — currently a stub.**
   See ``app.auth.dependencies.require_permission``. Until
   ``authorization_service`` lands, the stub logs a WARNING on every
   call. The endpoints work today (no permission enforcement yet) but
   every call is traced. When authz service lands, no endpoint change.

5. **List returns ``UserList`` (4 fields) not ``UserRead`` (15 fields).**
   List views return the lightest possible payload — a paginated list of
   200 users × 15 fields is 3x the bytes of 4-field rows.

6. **Audit markers on every write.**
   ``admin_update_user`` and ``unlock_user`` have ``# TODO: audit``
   markers. These are exactly the operations that MUST be audited —
   an admin changing a status or clearing a lockout is a security event.

Endpoint summary
----------------
    Self-service:
        GET    /users/me              CurrentActiveUser → UserRead
        PATCH  /users/me              UserSelfUpdate    → UserRead

    Admin:
        GET    /users                 filters + page    → PaginatedResponse[UserList]
        GET    /users/{user_id}                         → UserRead
        PATCH  /users/{user_id}       UserAdminUpdate   → UserRead
        POST   /users/{user_id}/unlock                  → UserRead
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
    require_permission,
)
from app.core.exceptions import ValidationError
from app.core.logging import get_logger
from app.models.enums import UserStatus
from app.models.user import User
from app.schemas.common import PageMeta, PaginatedResponse
from app.schemas.user import (
    UserAdminUpdate,
    UserFilter,
    UserList,
    UserRead,
    UserSelfUpdate,
)
from app.services import user_service


logger = get_logger(__name__)


router = APIRouter(
    prefix="/users",
    tags=["users"],
)


# ============================================================================
# SELF-SERVICE ENDPOINTS
# ============================================================================
# Registered FIRST, so /users/me matches before /users/{user_id}.
# ============================================================================


@router.get(
    "/me",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Get the current user's full profile",
    description=(
        "Returns the full profile of the authenticated user. Distinct from "
        "`GET /auth/me` — that endpoint is a lightweight session check, "
        "while this returns the full profile (preferences, verification "
        "state, lockout state, etc).\n\n"
        "Both return `UserRead` today; they may diverge as `/auth/me` stays "
        "lean for session startup and `/users/me` gains profile-specific "
        "fields."
    ),
    responses={
        200: {"description": "The authenticated user's profile."},
        401: {"description": "Missing or invalid bearer token."},
        403: {"description": "Account is not active."},
    },
)
def get_me(current_user: CurrentActiveUser) -> UserRead:
    """Return the current user's full profile."""
    return UserRead.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Update the current user's profile",
    description=(
        "Update fields a user is allowed to change about themselves: "
        "`full_name`, `preferred_language`, `timezone`.\n\n"
        "Cannot change: `email` (uses a verification flow), `status` "
        "(admin only), `mfa_enabled` (dedicated endpoint), `password` "
        "(dedicated change-password endpoint).\n\n"
        "All fields optional — only provided fields are updated."
    ),
    responses={
        200: {"description": "Profile updated."},
        401: {"description": "Missing or invalid bearer token."},
        403: {"description": "Account is not active."},
        422: {"description": "Invalid timezone or language format."},
    },
)
def update_me(
    body: UserSelfUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> UserRead:
    """
    Update the authenticated user's own profile.

    The service method applies only fields set in ``body``
    (``exclude_unset=True``). The endpoint commits and returns the
    updated user.
    """
    updated = user_service.self_update(db, current_user, body)
    db.commit()

    logger.info(
        "User self-updated profile",
        extra={
            "user_id": str(updated.id),
            "fields_changed": list(
                body.model_dump(exclude_unset=True).keys()
            ),
        },
    )

    return UserRead.model_validate(updated)


# ============================================================================
# ADMIN: LIST USERS
# ============================================================================


@router.get(
    "",
    response_model=PaginatedResponse[UserList],
    status_code=status.HTTP_200_OK,
    summary="List users (admin)",
    description=(
        "Paginated list of users with optional filters. Requires "
        "`user:read:any` permission. Returns `UserList` (4 fields) — "
        "for full details fetch `GET /users/{id}`.\n\n"
        "Excludes soft-deleted users. Sorted by `created_at DESC`."
    ),
    responses={
        200: {"description": "Users on this page."},
        403: {"description": "Permission denied (user:read:any required)."},
    },
)
def list_users_endpoint(
    db: DBDep,
    page: PageDep,
    current_user: User = Depends(require_permission("user:read:any")),
    filters: UserFilter = Depends(),
) -> PaginatedResponse[UserList]:
    """
    List users with pagination and filters.

    ``filters: UserFilter = Depends()`` tells FastAPI to treat each field
    of ``UserFilter`` as an optional query parameter. All fields
    optional, so an unfiltered request returns everything (paginated).
    """
    users, total = user_service.list_users(db, page=page, filters=filters)

    meta = PageMeta.build(total=total, params=page)
    items = [
        # UserList inherits CyberGuardBaseSchema (from_attributes=False)
        # because File 42 defined it as a request-base subclass. That's
        # technically wrong for a response schema. We override at the
        # call site until File 42 is cleaned up.
        UserList.model_validate(u, from_attributes=True)
        for u in users
    ]

    return PaginatedResponse[UserList](items=items, meta=meta)


# ============================================================================
# ADMIN: GET ONE USER
# ============================================================================


@router.get(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Get a user by ID (admin)",
    description=(
        "Return any user's profile. Requires `user:read:any` permission. "
        "Does NOT enforce tenant scoping yet — once authorization service "
        "lands, this will additionally check that the admin has access "
        "to the target user."
    ),
    responses={
        200: {"description": "The user."},
        403: {"description": "Permission denied."},
        404: {"description": "User not found."},
    },
)
def get_user(
    user_id: uuid.UUID,
    db: DBDep,
    current_user: User = Depends(require_permission("user:read:any")),
) -> UserRead:
    """
    Fetch a user by ID.

    # TODO: enforce resource scoping once authorization_service exists
    #       (admin cannot view users outside their org without super admin)
    """
    user = user_service.get_by_id(db, user_id)
    return UserRead.model_validate(user)


# ============================================================================
# ADMIN: UPDATE ONE USER
# ============================================================================


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Admin-update a user",
    description=(
        "Update fields an admin controls: `status`, `locked_until`, "
        "`mfa_enabled`. Requires `user:update:any` permission.\n\n"
        "Cannot be used on your own account — use `PATCH /users/me` for "
        "self-service updates (full_name, timezone, language). "
        "Password changes use `/auth/change-password`."
    ),
    responses={
        200: {"description": "User updated."},
        403: {"description": "Permission denied."},
        404: {"description": "User not found."},
        422: {"description": "Invalid field values (e.g. locked_until in past)."},
    },
)
def admin_update_user(
    user_id: uuid.UUID,
    body: UserAdminUpdate,
    db: DBDep,
    current_user: User = Depends(require_permission("user:update:any")),
) -> UserRead:
    """
    Admin-update another user's account.

    Self-modification is blocked: admins use ``/users/me`` for their own
    account. This prevents accidental (or malicious) self-escalation
    through the admin path.

    # TODO: audit via app.services.audit_service
    #       action="user.admin_updated"
    #       before_state / after_state snapshot
    # TODO: enforce tenant scoping (admin can only update users in
    #       their org once authorization_service exists)
    # TODO: prevent suspending the last active admin in an org
    """
    if user_id == current_user.id:
        raise ValidationError(
            message=(
                "Use PATCH /users/me for self-service updates. "
                "Admin endpoints cannot modify your own account."
            ),
            code="CANNOT_ADMIN_UPDATE_SELF",
        )

    target = user_service.get_by_id(db, user_id)
    updated = user_service.admin_update(db, target, body)
    db.commit()

    logger.info(
        "Admin updated user",
        extra={
            "actor_id": str(current_user.id),
            "target_user_id": str(target.id),
            "fields_changed": list(body.model_dump(exclude_unset=True).keys()),
        },
    )

    return UserRead.model_validate(updated)


# ============================================================================
# ADMIN: UNLOCK
# ============================================================================


@router.post(
    "/{user_id}/unlock",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Unlock a locked-out user (admin)",
    description=(
        "Clear a user's lockout state (reset failed_login_attempts to 0, "
        "clear locked_until). Requires `user:suspend` permission.\n\n"
        "Lockouts happen automatically after 5 consecutive failed logins. "
        "This endpoint lets an admin manually clear a lockout for a "
        "legitimate user who got locked out by accident — or for a "
        "security incident response where lockout needs to be reversed."
    ),
    responses={
        200: {"description": "User unlocked."},
        403: {"description": "Permission denied."},
        404: {"description": "User not found."},
    },
)
def unlock_user_endpoint(
    user_id: uuid.UUID,
    db: DBDep,
    current_user: User = Depends(require_permission("user:suspend")),
) -> UserRead:
    """
    Unlock a locked-out user.

    Uses ``user:suspend`` permission — the ability to unlock is paired
    with the ability to suspend. Same trust level.

    # TODO: audit via app.services.audit_service
    #       action="user.unlocked"
    """
    target = user_service.get_by_id(db, user_id)
    unlocked = user_service.unlock_user(db, target)
    db.commit()

    logger.info(
        "Admin unlocked user",
        extra={
            "actor_id": str(current_user.id),
            "target_user_id": str(target.id),
        },
    )

    return UserRead.model_validate(unlocked)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]