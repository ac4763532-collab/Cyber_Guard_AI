"""
CyberGuard AI — User Service
============================================================================

Business logic for user accounts: creation, authentication, updates,
lockout management, and listing.

Every other service in Phase F (organization, workspace, source, case,
evidence, ...) follows the patterns established here. Read the patterns
in the module docstring, apply them everywhere.

Public API
----------
    create_user(db, *, email, password, full_name=None, ...)   → User
    authenticate_user(db, *, email, password)                  → User
    get_by_id(db, user_id)                                     → User
    get_by_email(db, email)                                    → User
    get_by_email_optional(db, email)                           → User | None
    self_update(db, user, update)                              → User
    admin_update(db, user, update)                             → User
    change_password(db, user, *, old_password, new_password)   → User
    unlock_user(db, user)                                      → User
    list_users(db, *, page, filters)                           → (list[User], int)

Design rules (see app/services/__init__.py for the full contract)
-----------------------------------------------------------------
1. Receive ``Session`` from the caller. Never create one.
2. Never commit — **with one documented exception**:
   ``authenticate_user`` commits on failure so the failure record
   persists despite the endpoint rolling back on the raised error.
3. Raise ``CyberGuardError`` subclasses on failure.
4. Return ORM instances — not Pydantic DTOs.
5. No HTTP awareness — no ``Request``, no ``Response``, no status codes.
6. No imports from ``app.api`` or ``app.main``.

Lockout policy
--------------
    Threshold:  5 consecutive failed attempts → lock
    Duration:   15 minutes
    Reset:      Only on successful login (NOT on lockout expiry)

    After a lockout expires, ``failed_login_attempts`` remains at its
    high value. The next failed attempt immediately re-locks the
    account. This blocks "wait, retry, wait, retry" attacks from ever
    making progress.

Timing safety
-------------
    ``authenticate_user`` runs a **dummy bcrypt verification** when the
    account doesn't exist, is soft-deleted, or is OAuth-only. This
    equalizes response time across all failure paths, preventing
    user-enumeration via timing.

    The dummy hash is a real bcrypt hash computed once at module import
    with the same cost factor as production hashes. Without this,
    attackers could distinguish "user doesn't exist" (fast) from "wrong
    password" (slow, ~100ms bcrypt work) and enumerate valid emails.

Usage
-----
    from app.services.user_service import (
        create_user, authenticate_user, get_by_id, self_update,
    )

    # In an endpoint (POST /auth/register):
    user = create_user(db, email=body.email, password=body.password,
                       full_name=body.full_name)

    # In an endpoint (POST /auth/login):
    user = authenticate_user(db, email=body.email, password=body.password)

    # In an endpoint (GET /users/me):
    user = get_by_id(db, current_user_id)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AccountDisabledError,
    ConflictError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    UserNotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.enums import UserStatus
from app.models.user import User
from app.utils.id_generator import generate_public_slug
from app.schemas.common import PageParams
from app.schemas.user import (
    UserAdminUpdate,
    UserCreate,
    UserFilter,
    UserSelfUpdate,
    UserUpdate,
)


logger = get_logger(__name__)


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================
# These could be moved to Settings. Kept as module constants for now to
# avoid modifying app/core/config.py mid-build. When a "security policy"
# settings section is added, move these.

#: Number of consecutive failed attempts before lockout.
MAX_FAILED_LOGIN_ATTEMPTS: int = 5

#: Lockout duration in minutes once the threshold is crossed.
LOCKOUT_DURATION_MINUTES: int = 15

#: Dummy bcrypt hash for timing-safe authentication paths.
#: Computed once at import — cost is identical to production hashes, so
#: verify_password runs the same ~100ms bcrypt work whether or not the
#: real user exists.
_TIMING_DUMMY_HASH: str = hash_password("cyberguard_timing_dummy_v1")


# ============================================================================
# INTERNAL HELPERS
# ============================================================================



def get_by_public_user_id(db: Session, public_user_id: str) -> User | None:
    """Fetch a user by their unique public User ID (slug)."""
    return db.execute(
        select(User).where(User.public_user_id == public_user_id.strip())
    ).scalar_one_or_none()

def _get_by_email_optional(db: Session, email: str) -> User | None:
    """
    Fetch a user by email (normalized) without raising if missing.

    Returns the ORM instance even if soft-deleted — callers must check
    ``deleted_at`` themselves if that matters. ``get_by_email`` (below)
    wraps this with a raise.

    Not exported — internal use only.
    """
    normalized = email.strip().lower()
    return db.execute(
        select(User).where(User.email == normalized)
    ).scalar_one_or_none()


def _timing_dummy_check(password: str) -> None:
    """
    Run a full bcrypt verification against a dummy hash to equalize
    timing across authentication failure paths.

    Never raises — the dummy hash is a valid bcrypt hash with the same
    cost factor as production hashes, so ``verify_password`` returns
    False after the full ~100ms bcrypt work.

    Called when:
      - The account doesn't exist
      - The account is soft-deleted
      - The account has no password (OAuth-only)
    """
    try:
        verify_password(password, _TIMING_DUMMY_HASH)
    except Exception:  # noqa: BLE001 — timing helper must never raise
        pass


def _record_login_success(db: Session, user: User) -> None:
    """
    Record a successful login: reset the failure counter, clear any
    lockout, and update ``last_login_at``.

    Called by ``authenticate_user`` only after the password has been
    verified. No commit — the endpoint owns the transaction boundary.
    """
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.flush()


def _record_login_failure(db: Session, user: User) -> None:
    """
    Record a failed login attempt. Increments the counter, and locks
    the account if the threshold has been reached.

    Called by ``authenticate_user`` on every failure path where the
    user was actually resolved (wrong password, locked, not active,
    OAuth-only).

    **Does NOT commit** — the caller (``authenticate_user``) commits
    after calling this, so the failure record persists even though the
    endpoint's transaction will roll back on the raised error.

    Lockout logic:
      - ``failed_login_attempts`` incremented
      - If count >= threshold AND not currently locked → set
        ``locked_until`` to now + duration
      - If already locked → do not extend (prevents amplification via
        repeated requests; a background job or admin can extend if
        needed for an active incident)
    """
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

    if (
        user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS
        and not user.is_locked
    ):
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=LOCKOUT_DURATION_MINUTES
        )

    db.flush()


# ============================================================================
# CREATE
# ============================================================================

def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str | None = None,
    role: str = "individual",
    public_user_id: str | None = None,
    status: UserStatus = UserStatus.PENDING_VERIFICATION,
    email_verified_at: datetime | None = None,
    preferred_language: str = "en",
    timezone_name: str = "UTC",
) -> User:
    """
    Create a new user account.

    Checks email uniqueness explicitly (returns a clean
    ``EmailAlreadyExistsError`` instead of an ``IntegrityError`` with a
    driver-generated message). Hashes the password with the configured
    bcrypt cost factor.

    The user is added to the session and flushed so ``user.id`` is
    populated — but **not committed**. The caller (the endpoint) commits
    when the full request succeeds.

    Parameters
    ----------
    db : Session
    email : str
        Email address. Normalized to lowercase.
    password : str
        Plaintext password. Already validated for byte length and
        strength by the schema layer (``RegisterRequest`` or
        ``UserCreate``). The service trusts that validation and does
        not re-validate — but hashing will raise ``ValidationError``
        if the password somehow violates the byte-length bounds.
    full_name : str | None
    status : UserStatus
        Defaults to PENDING_VERIFICATION. Admin-created accounts can
        pass ACTIVE for pre-verified users.
    email_verified_at : datetime | None
        Set to backdate verification (admin-created pre-verified users).
    preferred_language : str
        BCP 47 tag. Already validated by schema.
    timezone_name : str
        IANA timezone name. Already validated by schema. Named
        ``timezone_name`` to avoid shadowing the ``timezone`` module.

    Returns
    -------
    User
        The created user (flushed, has an ``id``).

    Raises
    ------
    EmailAlreadyExistsError
        If any row (including soft-deleted) already uses this email.
    ValidationError
        If the password violates byte-length bounds (should not happen
        if callers go through the schemas).
    """
    normalized_email = email.strip().lower()

    # Explicit uniqueness check → clean error instead of IntegrityError.
    # Note: this catches soft-deleted users too. Their email is still
    # locked until the retention job hard-deletes them. This is
    # intentional — prevents "delete account, re-register same email"
    # account-takeover vectors.
    existing = _get_by_email_optional(db, normalized_email)
    if existing is not None:
        raise EmailAlreadyExistsError(
            message="An account with this email address already exists.",
            code="EMAIL_ALREADY_EXISTS",
            details={"email": normalized_email},
        )

    # Hash password — this can raise ValidationError if the input
    # violates byte-length bounds. That should have been caught by the
    # schema layer, but defense in depth.
    password_hash = hash_password(password)

    # Generate automatic public slug if not provided
    if not public_user_id:
        for _ in range(10):
            candidate = generate_public_slug(full_name or normalized_email, role=role)
            exists_slug = db.execute(select(User.id).where(User.public_user_id == candidate)).scalar_one_or_none()
            if not exists_slug:
                public_user_id = candidate
                break
        if not public_user_id:
            public_user_id = generate_public_slug(full_name or normalized_email, role=role)

    user = User(
        email=normalized_email,
        public_user_id=public_user_id,
        role=role,
        password_hash=password_hash,
        full_name=full_name.strip() if full_name else None,
        status=status,
        email_verified_at=email_verified_at,
        preferred_language=preferred_language,
        timezone=timezone_name,
    )

    db.add(user)
    db.flush()

    logger.info(
        "User created",
        extra={"user_id": str(user.id), "status": status.value},
    )

    return user


# ============================================================================
# AUTHENTICATE
# ============================================================================

def authenticate_user(
    db: Session,
    *,
    email: str,
    password: str,
) -> User:
    """
    Verify credentials and return the authenticated user.

    **Exception to the "no commits" rule.**
    On every failure path where the user was resolved (wrong password,
    locked, not active, OAuth-only), this method commits the failure
    record before raising. Security reasoning: ``failed_login_attempts``
    must be incremented even though the endpoint's transaction will roll
    back on the raised error. Without this commit, an attacker could
    brute-force a password and leave no trace in the DB.

    On success, **no commit** — the endpoint commits after generating
    tokens so ``last_login_at`` and the token issue are in the same
    transaction.

    Failure paths (in order)
    ------------------------
    1. User not found → dummy check + InvalidCredentialsError (no commit)
    2. User soft-deleted → dummy check + InvalidCredentialsError (no commit)
    3. User locked → record failure + commit + AccountDisabledError(ACCOUNT_LOCKED)
    4. User not ACTIVE → dummy check + AccountDisabledError(ACCOUNT_NOT_ACTIVE)
    5. User OAuth-only (password_hash is None) → dummy check + record
       failure + commit + InvalidCredentialsError
    6. Wrong password → record failure + commit + InvalidCredentialsError

    Success path
    ------------
    7. Correct password → reset failure counter, clear lockout, update
       last_login_at, upgrade hash if needs_rehash, return user (no
       commit).

    Timing safety
    -------------
    Paths 1, 2, 4, 5 run ``_timing_dummy_check`` to equalize response
    time with paths that do full bcrypt verification. Without this,
    attackers could distinguish "user doesn't exist" from "wrong
    password" via response timing — classic user-enumeration.

    Returns
    -------
    User
        The authenticated user (only on success).

    Raises
    ------
    InvalidCredentialsError
        Wrong password, unknown email, soft-deleted account, OAuth-only
        account.
    AccountDisabledError
        With ``code="ACCOUNT_LOCKED"`` if locked, or
        ``code="ACCOUNT_NOT_ACTIVE"`` if suspended/inactive.
    """
    user = _get_by_email_optional(db, email)

    # ── Path 1 & 2: not found or soft-deleted ────────────────────────
    if user is None or user.deleted_at is not None:
        _timing_dummy_check(password)
        raise InvalidCredentialsError(
            message="Invalid email or password.",
            code="AUTH_INVALID_CREDENTIALS",
        )

    # ── Path 3: locked ───────────────────────────────────────────────
    if user.is_locked:
        _record_login_failure(db, user)
        db.commit()  # security exception — failure must persist
        locked_until = user.locked_until
        raise AccountDisabledError(
            message="Account is temporarily locked. Try again later.",
            code="ACCOUNT_LOCKED",
            details={
                "locked_until": locked_until.isoformat()
                if locked_until is not None
                else None,
            },
        )

    # ── Path 4: not active ───────────────────────────────────────────
    if user.status != UserStatus.ACTIVE:
        _timing_dummy_check(password)
        raise AccountDisabledError(
            message=f"Account is not active: {user.status.value}.",
            code="ACCOUNT_NOT_ACTIVE",
            details={"status": user.status.value},
        )

    # ── Path 5: OAuth-only (no local password) ───────────────────────
    if user.password_hash is None:
        _timing_dummy_check(password)
        _record_login_failure(db, user)
        db.commit()
        raise InvalidCredentialsError(
            message="Invalid email or password.",
            code="AUTH_INVALID_CREDENTIALS",
        )

    # ── Path 6: wrong password ───────────────────────────────────────
    if not verify_password(password, user.password_hash):
        _record_login_failure(db, user)
        db.commit()
        raise InvalidCredentialsError(
            message="Invalid email or password.",
            code="AUTH_INVALID_CREDENTIALS",
        )

    # ── Path 7: success ──────────────────────────────────────────────
    # Hash upgrade: if the stored hash uses a weaker cost factor than
    # current settings (e.g. BCRYPT_ROUNDS was increased in production),
    # upgrade it transparently on this successful login.
    if needs_rehash(user.password_hash):
        try:
            user.password_hash = hash_password(password)
            logger.info(
                "Password hash upgraded to current cost factor",
                extra={"user_id": str(user.id)},
            )
        except Exception:
            # Never fail login due to a rehash failure — log and continue.
            logger.warning(
                "Password hash upgrade failed; continuing with old hash",
                extra={"user_id": str(user.id)},
            )

    _record_login_success(db, user)

    logger.info(
        "User authenticated",
        extra={"user_id": str(user.id)},
    )

    return user


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, user_id: uuid.UUID) -> User:
    """
    Fetch a user by ID.

    Raises
    ------
    UserNotFoundError
        If the user does not exist or is soft-deleted.
    """
    user = db.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise UserNotFoundError(
            message=f"User {user_id} not found.",
            details={"user_id": str(user_id)},
        )
    return user


def get_by_email(db: Session, email: str) -> User:
    """
    Fetch a user by email.

    Raises
    ------
    UserNotFoundError
        If no user with this email exists, or the account is
        soft-deleted.
    """
    user = _get_by_email_optional(db, email)
    if user is None or user.deleted_at is not None:
        raise UserNotFoundError(
            message=f"User with email {email!r} not found.",
            details={"email": email.strip().lower()},
        )
    return user


def get_by_email_optional(db: Session, email: str) -> User | None:
    """
    Public wrapper around ``_get_by_email_optional``. Returns ``None``
    if the user doesn't exist — including soft-deleted accounts.

    Use this only where the caller expects ``None`` to be a normal
    return value (e.g. invitation flows, uniqueness checks). Everywhere
    else use ``get_by_email``.
    """
    return _get_by_email_optional(db, email)


# ============================================================================
# UPDATE
# ============================================================================

def self_update(
    db: Session,
    user: User,
    update: UserSelfUpdate,
) -> User:
    """
    Apply a ``UserSelfUpdate`` to the given user. Only fields that are
    explicitly set in the update are changed (``exclude_unset=True``).

    Allowed fields:
      - full_name
      - preferred_language
      - timezone

    Not allowed through this method: email, status, mfa_enabled,
    password. Those have dedicated flows.

    Returns
    -------
    User
        The updated user (flushed, not committed).
    """
    data = update.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(user, field, value)
    db.flush()
    return user


def admin_update(
    db: Session,
    user: User,
    update: UserAdminUpdate,
) -> User:
    """
    Apply a ``UserAdminUpdate`` to the given user. Admin-only.

    Allowed fields:
      - status
      - locked_until (must be future — enforced by schema)
      - mfa_enabled

    The caller (the endpoint) must require admin permission. This
    method does not check authorization itself — that's the endpoint's
    job via ``require_permission("user:update:any")``.

    # TODO: write an audit log entry once app.services.audit_service
    # exists. Currently this method is silent for admin actions —
    # which is a known gap.

    Returns
    -------
    User
        The updated user (flushed, not committed).
    """
    data = update.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(user, field, value)
    db.flush()

    logger.info(
        "User admin-updated",
        extra={
            "user_id": str(user.id),
            "fields_changed": list(data.keys()),
        },
    )

    return user


def change_password(
    db: Session,
    user: User,
    *,
    old_password: str,
    new_password: str,
) -> User:
    """
    Change a user's password after verifying the current one.

    Steps:
      1. Verify ``old_password`` against the stored hash (constant-time
         via bcrypt)
      2. Verify the account has a local password (OAuth-only accounts
         cannot use this endpoint)
      3. Hash and store the new password
      4. Update ``password_changed_at``

    # TODO: invalidate existing sessions on password change once a JWT
    # blocklist exists. Today, an attacker with a stolen access token
    # keeps it until natural expiry even after the victim changes
    # their password.

    Raises
    ------
    ValidationError
        If the user has no local password (OAuth-only account).
    InvalidCredentialsError
        If ``old_password`` does not match.
    """
    if user.password_hash is None:
        raise ValidationError(
            message=(
                "This account has no local password to change. "
                "Sign in with your linked OAuth provider."
            ),
            code="PASSWORD_NOT_SET",
        )

    if not verify_password(old_password, user.password_hash):
        # Timing-safe path — verify_password already did the bcrypt work.
        logger.warning(
            "Password change failed: old password mismatch",
            extra={"user_id": str(user.id)},
        )
        raise InvalidCredentialsError(
            message="Current password is incorrect.",
            code="AUTH_INVALID_OLD_PASSWORD",
        )

    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    db.flush()

    logger.info(
        "Password changed",
        extra={"user_id": str(user.id)},
    )

    return user


def unlock_user(db: Session, user: User) -> User:
    """
    Clear a user's lockout state. Admin action.

    Resets ``failed_login_attempts`` to 0 and clears ``locked_until``.
    The next failed login will start a fresh counter (threshold from
    zero).

    # TODO: audit this once audit_service exists.

    Returns
    -------
    User
        The updated user (flushed, not committed).
    """
    user.locked_until = None
    user.failed_login_attempts = 0
    db.flush()

    logger.info(
        "User unlocked",
        extra={"user_id": str(user.id)},
    )

    return user


# ============================================================================
# LIST
# ============================================================================

def list_users(
    db: Session,
    *,
    page: PageParams,
    filters: UserFilter,
) -> tuple[list[User], int]:
    """
    List users with pagination and filters. Returns ``(users, total)``
    where ``total`` is the count of matching rows ignoring pagination.

    Always excludes soft-deleted users. Applies filters from
    ``UserFilter`` in the order they're most selective (status, email
    match, name match, verification state, lock state, date range) —
    the SQL planner will reorder as it sees fit, but the WHERE clause
    is built in a readable order for logging.

    Returns
    -------
    tuple[list[User], int]
        (users on this page, total matching count across all pages)
    """
    stmt = select(User).where(User.deleted_at.is_(None))

    # ── Status filter ────────────────────────────────────────────────
    if filters.status is not None:
        stmt = stmt.where(User.status == filters.status)

    # ── Email substring (case-insensitive) ───────────────────────────
    if filters.email_contains:
        pattern = f"%{filters.email_contains.strip().lower()}%"
        stmt = stmt.where(User.email.ilike(pattern))

    # ── Full name substring (case-insensitive) ───────────────────────
    if filters.full_name_contains:
        pattern = f"%{filters.full_name_contains.strip()}%"
        stmt = stmt.where(User.full_name.ilike(pattern))

    # ── Verified filter ──────────────────────────────────────────────
    if filters.is_email_verified is not None:
        if filters.is_email_verified:
            stmt = stmt.where(User.email_verified_at.is_not(None))
        else:
            stmt = stmt.where(User.email_verified_at.is_(None))

    # ── Locked filter ────────────────────────────────────────────────
    if filters.is_locked is not None:
        now = datetime.now(timezone.utc)
        if filters.is_locked:
            stmt = stmt.where(
                User.locked_until.is_not(None),
                User.locked_until > now,
            )
        else:
            stmt = stmt.where(
                or_(User.locked_until.is_(None), User.locked_until <= now)
            )

    # ── Date range ───────────────────────────────────────────────────
    if filters.created_after is not None:
        stmt = stmt.where(User.created_at >= filters.created_after)

    if filters.created_before is not None:
        stmt = stmt.where(User.created_at <= filters.created_before)

    # ── Total count (before pagination) ──────────────────────────────
    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    # ── Page (most recent first) ─────────────────────────────────────
    stmt = (
        stmt.order_by(User.created_at.desc(), User.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )

    users = list(db.execute(stmt).scalars().all())

    return users, int(total)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Constants
    "MAX_FAILED_LOGIN_ATTEMPTS",
    "LOCKOUT_DURATION_MINUTES",
    # Create
    "create_user",
    # Authenticate
    "authenticate_user",
    # Read
    "get_by_id",
    "get_by_email",
    "get_by_email_optional",
    # Update
    "self_update",
    "admin_update",
    "change_password",
    "unlock_user",
    # List
    "list_users",
]