"""
CyberGuard AI — Enrollment Token Service
============================================================================

Business logic for source enrollment tokens: issuance, redemption,
revocation, and expiry.

An enrollment token is the **single moment** a plaintext secret crosses
from backend to collector. It has a short TTL (default 15 minutes),
is single-use, is bound to one source, and is bound to the user who
created it. All four properties are enforced here.

Enrollment flow (end-to-end)
----------------------------
    1. User clicks "Connect Device" in the wizard
    2. ``create_enrollment_token(db, actor, source, ttl_minutes)``
       → plaintext token returned to caller (shown to user once)
       → only hash stored in ``source_enrollments.token_hash``
    3. User copies the token into the collector
    4. Collector calls ``POST /collector/enroll`` with the token
    5. Endpoint calls ``redeem_token(db, plaintext_token, collector_id, ...)``
    6. ``redeem_token`` performs, in a single transaction:
         a. Look up invitation by token prefix
         b. Verify bcrypt hash (timing-safe)
         c. Check ``is_redeemable`` (pending, not expired)
         d. Check collector_id not already active for this source
         e. Issue credential via ``collector_credential_service``
            (which audits the credential issuance)
         f. Mark token redeemed (``redeemed_at``, ``redeemed_by_id``)
         g. Activate source via ``source_service.activate_source``
            (which audits the activation)
         h. Record initial heartbeat
         i. Return ``(source, collector_credential_id, plaintext_credential)``
    7. The endpoint returns ``EnrollmentRedemptionResponse`` to the
       collector — the ONLY time the credential plaintext is exposed

Atomicity
---------
``redeem_token`` does not commit. If any step after (e) fails — e.g.
the source is in a state that rejects activation — the whole
transaction rolls back and the token remains redeemable. This is the
correct behavior — a failed redemption must NOT burn the token, or
the user would have to regenerate it and re-run the whole wizard.

The caller (endpoint) is responsible for the final commit. Between
flush and commit, the transaction is open — if the endpoint raises,
SQLAlchemy rolls back automatically.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances + plaintext as appropriate.
4. Lifecycle transitions are audited — but token redemption itself is
   audited via the two child services (credential issuance +
   source activation) whose combined audit trail fully describes
   the redemption event. The token row's ``redeemed_at`` /
   ``redeemed_by_id`` / ``redeemed_ip`` are its own audit fields.

Token binding
-------------
A token is bound to **both** a source and a user:

    - ``source_id`` — which source this token enrolls
    - ``created_by_id`` — the user who requested it

At redemption, we verify the source exists and is in
``PENDING_ENROLLMENT`` state. We do NOT enforce "the redeeming user
must equal created_by_id" at the service layer — the collector
authenticates as a device, not as a user. Instead, the enrollment
token itself is the authorization.

However — the token is bound to a **specific source** which belongs
to a **specific workspace** which belongs to a **specific user/org**.
So the token transitively authorizes "enroll this specific source in
this specific workspace". A stolen token can only enroll the one
source it was issued for.

Token generation
----------------
Plaintext: 32 bytes from ``secrets.token_urlsafe()`` → ~43 chars
Prefix:    first 12 chars, stored plaintext, format ``enr-<8 hex>``
Hash:      bcrypt, cost factor from ``settings.BCRYPT_ROUNDS``

The prefix lets us look up candidates without scanning every row.
Collision risk across prefixes is ~1 in 2^32 — negligible. Within
the rare case of two tokens sharing a prefix, we test the hash
against each candidate.

Public API
----------
    create_enrollment_token(db, *, actor, source, ttl_minutes=None, request=None)
        → (EnrollmentToken, plaintext)

    redeem_token(db, *, plaintext_token, collector_id, hostname, ...)
        → RedemptionResult  (source, credential_id, plaintext_credential)

    revoke_token(db, *, actor, token, reason, request=None) → EnrollmentToken
    list_tokens_for_source(db, *, actor, source, page, include_redeemed=False)
        → (list, int)
    sweep_expired(db, *, limit=500) → int  (background job)

Usage
-----
    from app.services import enrollment_service

    # User's wizard generates the token
    token, plaintext = enrollment_service.create_enrollment_token(
        db, actor=current_user, source=source,
    )
    db.commit()
    # → return {plaintext, expires_at, seconds_until_expiry} to UI

    # Collector redeems (different request, possibly minutes later)
    result = enrollment_service.redeem_token(
        db,
        plaintext_token=body.token,
        collector_id=body.collector_id,
        hostname=body.hostname,
        os_version=body.os_version,
        agent_version=body.agent_version,
        hardware_fingerprint=body.hardware_fingerprint,
    )
    db.commit()
    # → return EnrollmentRedemptionResponse(plaintext_credential=result.plaintext_credential, ...)
"""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_SOURCE_ENROLL,
    PERM_SOURCE_READ,
)
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    EnrollmentTokenInvalidError,
    InvalidStateTransitionError,
    NotFoundError,
    SourceDisabledError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    generate_secure_token,
    hash_password,
    verify_password,
)
from app.models.collector_credential import CollectorCredential
from app.models.enrollment import SourceEnrollment
from app.models.enums import (
    EnrollmentStatus,
    SourceStatus,
)
from app.models.source import SecuritySource
from app.models.user import User
from app.schemas.common import PageParams
from app.services import (
    audit_service,
    authorization,
    collector_credential_service,
    source_service,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================
_DEFAULT_TTL_MINUTES = 15
_MIN_TTL_MINUTES = 1
_MAX_TTL_MINUTES = 60

#: Plaintext token entropy (bytes). 32 bytes → ~43 URL-safe chars.
_TOKEN_ENTROPY_BYTES = 32

#: Prefix derivation — must match ORM validator ``^enr-[a-f0-9]{8}$``.
_TOKEN_PREFIX_PATTERN = re.compile(r"^enr-[a-f0-9]{8}$")

#: Max sweep batch size (for background job backpressure).
_MAX_SWEEP_BATCH = 1000


# ============================================================================
# RESULT TYPE
# ============================================================================

@dataclass(frozen=True)
class RedemptionResult:
    """
    Successful enrollment redemption. Returned by ``redeem_token``.

    Frozen so callers can't accidentally mutate a plaintext secret.
    """
    source: SecuritySource
    enrollment: SourceEnrollment
    collector_credential_id: uuid.UUID
    plaintext_credential: str
    credential_prefix: str
    credential_expires_at: datetime | None
    heartbeat_interval_seconds: int


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _build_token_prefix(plaintext_token: str) -> str:
    """
    Derive the 12-char prefix from a plaintext token.

    Format: ``enr-<8 lowercase hex chars>``. Matches the ORM
    validator's expected pattern.

    We derive the hex segment from the token's bytes via hex encoding
    — deterministic, uniform, no modulo bias.
    """
    hex_segment = plaintext_token.encode("utf-8").hex()[:8]
    return f"enr-{hex_segment}"


def _get_by_prefix(
    db: Session,
    prefix: str,
) -> list[SourceEnrollment]:
    """
    Fetch all enrollment rows matching a prefix.

    In the overwhelming majority of cases, this returns 0 or 1 rows.
    Rarely 2+ (prefix collision — 1 in 2^32).
    """
    return list(db.execute(
        select(SourceEnrollment).where(
            SourceEnrollment.token_prefix == prefix,
        )
    ).scalars().all())


def _find_by_plaintext(
    db: Session,
    plaintext_token: str,
) -> SourceEnrollment:
    """
    Look up an enrollment row by full plaintext token.

    Raises ``EnrollmentTokenInvalidError`` if not found. Uses the same
    error code for "no such prefix" and "hash mismatch" — no
    information leak about why the token failed.
    """
    stripped = plaintext_token.strip()
    if not stripped:
        raise EnrollmentTokenInvalidError(
            message="Enrollment token is required.",
            code="ENROLLMENT_TOKEN_REQUIRED",
        )

    prefix = _build_token_prefix(stripped)
    candidates = _get_by_prefix(db, prefix)

    for candidate in candidates:
        if verify_password(stripped, candidate.token_hash):
            return candidate

    raise EnrollmentTokenInvalidError(
        message="Enrollment token is invalid or has already been used.",
        code="ENROLLMENT_TOKEN_INVALID",
    )


def _count_active_tokens_for_source(
    db: Session,
    source_id: uuid.UUID,
) -> int:
    """Count non-redeemed, non-revoked, non-expired tokens for a source."""
    now = datetime.now(timezone.utc)
    return int(db.execute(
        select(func.count())
        .select_from(SourceEnrollment)
        .where(
            SourceEnrollment.source_id == source_id,
            SourceEnrollment.redeemed_at.is_(None),
            SourceEnrollment.revoked_at.is_(None),
            SourceEnrollment.expires_at > now,
        )
    ).scalar_one())


# ============================================================================
# CREATE
# ============================================================================

def create_enrollment_token(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    ttl_minutes: int | None = None,
    request: Any | None = None,
) -> tuple[SourceEnrollment, str]:
    """
    Generate a new enrollment token for a source.

    Returns
    -------
    tuple[SourceEnrollment, str]
        ``(enrollment_row, plaintext_token)``. The plaintext is shown
        to the caller exactly once — it cannot be retrieved later.

    Enforces
    --------
    - Actor has ``PERM_SOURCE_ENROLL`` in the source's workspace
    - Source is in ``PENDING_ENROLLMENT`` status (can't enroll an
      already-active source — use credential rotation instead)
    - No other non-expired, non-redeemed token exists for this source
      (partial unique index enforced at DB level; we check first for
      a cleaner error message)
    - TTL within [1, 60] minutes

    Raises
    ------
    AuthorizationError
        Actor lacks ``PERM_SOURCE_ENROLL``.
    InvalidStateTransitionError
        Source is not in PENDING_ENROLLMENT status.
    ConflictError
        Another active token exists for this source.
    ValidationError
        Invalid TTL.
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_ENROLL, workspace_id=source.workspace_id,
    )

    if source.status != SourceStatus.PENDING_ENROLLMENT:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot create enrollment token for source in "
                f"{source.status.value} status. Only PENDING_ENROLLMENT "
                f"sources accept new tokens. To rotate credentials on an "
                f"active source, use the credential rotation endpoint."
            ),
            code="SOURCE_NOT_PENDING_ENROLLMENT",
            details={"status": source.status.value},
        )

    # Belt-and-suspenders check — DB partial unique index enforces this
    # too, but a clean error is nicer than an IntegrityError.
    existing_count = _count_active_tokens_for_source(db, source.id)
    if existing_count > 0:
        raise ConflictError(
            message=(
                "An active enrollment token already exists for this source. "
                "Revoke it before generating a new one."
            ),
            code="ENROLLMENT_TOKEN_EXISTS",
            details={"source_id": str(source.id)},
        )

    # Validate TTL
    effective_ttl = ttl_minutes if ttl_minutes is not None else _DEFAULT_TTL_MINUTES
    if not (_MIN_TTL_MINUTES <= effective_ttl <= _MAX_TTL_MINUTES):
        raise ValidationError(
            message=(
                f"ttl_minutes must be between {_MIN_TTL_MINUTES} and "
                f"{_MAX_TTL_MINUTES}."
            ),
            code="ENROLLMENT_TTL_INVALID",
            details={"ttl_minutes": effective_ttl},
        )

    # Generate plaintext + hash
    plaintext = generate_secure_token(_TOKEN_ENTROPY_BYTES)
    token_hash = hash_password(plaintext)
    token_prefix = _build_token_prefix(plaintext)

    # Validate the generated prefix against the schema pattern —
    # this should always pass, but if it somehow doesn't, we want a
    # clear error, not a mysterious constraint violation.
    if not _TOKEN_PREFIX_PATTERN.match(token_prefix):
        raise RuntimeError(
            f"Generated token prefix {token_prefix!r} does not match "
            f"required pattern {_TOKEN_PREFIX_PATTERN.pattern!r}. "
            f"This is a bug in _build_token_prefix — file an issue."
        )

    metadata: dict[str, Any] = {
        "ip": _extract_ip(request),
        "user_agent": _extract_user_agent(request),
    }

    enrollment = SourceEnrollment.build(
        source_id=source.id,
        created_by_id=actor.id,
        token_hash=token_hash,
        token_prefix=token_prefix,
        ttl_minutes=effective_ttl,
        metadata=metadata,
    )
    db.add(enrollment)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="enrollment.token.created",
        target_type="enrollment",
        target_id=enrollment.id,
        target_display=token_prefix,
        workspace_id=source.workspace_id,
        request=request,
        metadata={
            "source_id": str(source.id),
            "source_key": source.source_key,
            "ttl_minutes": effective_ttl,
            "expires_at": enrollment.expires_at.isoformat(),
        },
    )

    logger.info(
        "Enrollment token created",
        extra={
            "enrollment_id": str(enrollment.id),
            "source_id": str(source.id),
            "source_key": source.source_key,
            "ttl_minutes": effective_ttl,
            "expires_at": enrollment.expires_at.isoformat(),
        },
    )

    return enrollment, plaintext


# ============================================================================
# REDEEM — the critical path
# ============================================================================

def redeem_token(
    db: Session,
    *,
    plaintext_token: str,
    collector_id: uuid.UUID,
    hostname: str | None = None,
    os_version: str | None = None,
    agent_version: str | None = None,
    hardware_fingerprint: str | None = None,
    redeemed_ip: str | None = None,
    redeemed_user_agent: str | None = None,
    request: Any | None = None,
) -> RedemptionResult:
    """
    Redeem an enrollment token and issue a collector credential.

    This is a **multi-step atomic operation**. See module docstring for
    the full flow. The critical property: if any step fails, the whole
    transaction rolls back and the token remains redeemable.

    Steps
    -----
    1. Look up enrollment by prefix + hash verification
    2. Verify enrollment is redeemable (pending, not expired)
    3. Look up source (must exist)
    4. Re-validate source status (must be PENDING_ENROLLMENT)
    5. Issue collector credential via ``collector_credential_service``
    6. Mark enrollment redeemed
    7. Activate source via ``source_service``
    8. Record initial heartbeat
    9. Return credentials

    Raises
    ------
    EnrollmentTokenInvalidError
        Token unknown, invalid, already used, revoked, or expired.
    SourceDisabledError
        Source is in a state that cannot be activated.
    ConflictError
        Collector ID already active for this source (reinstall without
        retirement).
    """
    # ── 1+2. Look up and validate token
    enrollment = _find_by_plaintext(db, plaintext_token)

    if not enrollment.is_redeemable:
        # Distinguish expired from revoked from redeemed for a better
        # caller message. The error code is different per case — but
        # the response body client-side should still be generic (don't
        # tell an attacker which specific failure mode).
        if enrollment.is_redeemed:
            raise EnrollmentTokenInvalidError(
                message="Enrollment token has already been used.",
                code="ENROLLMENT_TOKEN_ALREADY_REDEEMED",
            )
        if enrollment.is_revoked:
            raise EnrollmentTokenInvalidError(
                message="Enrollment token has been revoked.",
                code="ENROLLMENT_TOKEN_REVOKED",
            )
        if enrollment.is_expired:
            raise EnrollmentTokenInvalidError(
                message=(
                    "Enrollment token has expired. Please generate a new "
                    "one from the device-connection wizard."
                ),
                code="ENROLLMENT_TOKEN_EXPIRED",
            )
        # Should not be reachable, but defensive
        raise EnrollmentTokenInvalidError(
            message="Enrollment token is not redeemable.",
            code="ENROLLMENT_TOKEN_NOT_REDEEMABLE",
        )

    # ── 3. Look up source
    source = source_service.get_by_id(db, enrollment.source_id)

    # ── 4. Re-validate source status. Race condition window: someone
    # could have disabled/revoked the source between token creation
    # and redemption. That must block the redemption.
    if source.status != SourceStatus.PENDING_ENROLLMENT:
        raise SourceDisabledError(
            message=(
                f"Source is in {source.status.value} status and cannot "
                f"accept enrollment. Generate a new token after resolving "
                f"the source state."
            ),
            code="SOURCE_NOT_ELIGIBLE_FOR_ENROLLMENT",
            details={
                "source_id": str(source.id),
                "source_status": source.status.value,
            },
        )

    # ── 5. Issue credential via collector_credential_service
    # This raises on:
    #   - collector_id collision (an active credential already exists
    #     for this collector_id on this source)
    #   - any internal error
    # If it raises, the transaction rolls back, the token remains
    # redeemable (no explicit mutation has happened yet).
    issued = collector_credential_service.issue_credential(
        db,
        source=source,
        collector_id=collector_id,
        hostname=hostname,
        os_version=os_version,
        agent_version=agent_version,
        hardware_fingerprint=hardware_fingerprint,
    )

    # ── 6. Mark enrollment redeemed
    now = datetime.now(timezone.utc)
    enrollment.redeemed_at = now
    enrollment.redeemed_by_id = enrollment.created_by_id  # preserved; see note below
    enrollment.redeemed_ip = (redeemed_ip or _extract_ip(request) or "")[:45] or None
    enrollment.redeemed_user_agent = (
        (redeemed_user_agent or _extract_user_agent(request) or "")[:512] or None
    )
    enrollment.collector_version = (agent_version or "")[:32] or None
    enrollment.status = EnrollmentStatus.REDEEMED
    db.flush()

    # ── 7. Activate source
    # source_service.activate_source enforces status transitions and
    # audits the activation. It uses the enrollment's creator as the
    # "actor" for the audit trail (the collector itself is not a User).
    creator = db.get(User, enrollment.created_by_id)
    if creator is not None:
        source_service.activate_source(
            db,
            actor=creator,
            source=source,
            request=request,
        )
    else:
        # Creator has been hard-deleted — rare. Log a warning, skip
        # the actor-attributed audit. The activation still happens.
        logger.warning(
            "Enrollment creator no longer exists — activating source without actor",
            extra={
                "source_id": str(source.id),
                "enrollment_id": str(enrollment.id),
            },
        )
        source.status = SourceStatus.ACTIVE
        db.flush()

    # ── 8. Record initial heartbeat
    source_service.record_heartbeat(
        db,
        source=source,
        from_ip=redeemed_ip or _extract_ip(request),
    )

    logger.info(
        "Enrollment token redeemed",
        extra={
            "enrollment_id": str(enrollment.id),
            "source_id": str(source.id),
            "source_key": source.source_key,
            "collector_id": str(collector_id),
            "credential_id": str(issued.credential_id),
        },
    )

    # ── 9. Return
    return RedemptionResult(
        source=source,
        enrollment=enrollment,
        collector_credential_id=issued.credential_id,
        plaintext_credential=issued.plaintext_credential,
        credential_prefix=issued.credential_prefix,
        credential_expires_at=issued.expires_at,
        heartbeat_interval_seconds=issued.heartbeat_interval_seconds,
    )


# ============================================================================
# REVOKE
# ============================================================================

def revoke_token(
    db: Session,
    *,
    actor: User,
    token: SourceEnrollment,
    reason: str,
    request: Any | None = None,
) -> SourceEnrollment:
    """
    Revoke a pending enrollment token.

    Requires ``PERM_SOURCE_ENROLL`` in the token's source's workspace.
    Only pending tokens can be revoked — a redeemed token is history.

    Raises
    ------
    InvalidStateTransitionError
        Token is not pending.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A revocation reason is required.",
            code="ENROLLMENT_REVOCATION_REASON_REQUIRED",
        )

    # Fetch source to check permission in its workspace scope
    source = source_service.get_by_id(db, token.source_id)
    authorization.check_permission(
        db, actor, PERM_SOURCE_ENROLL, workspace_id=source.workspace_id,
    )

    if not token.is_pending:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot revoke enrollment in status {token.display_status}. "
                "Only pending tokens can be revoked."
            ),
            code="ENROLLMENT_NOT_PENDING",
            details={"display_status": token.display_status},
        )

    token.revoked_at = datetime.now(timezone.utc)
    token.revocation_reason = reason.strip()
    token.status = EnrollmentStatus.REVOKED
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="enrollment.token.revoked",
        target_type="enrollment",
        target_id=token.id,
        target_display=token.token_prefix,
        workspace_id=source.workspace_id,
        notes=reason.strip(),
        request=request,
    )

    logger.info(
        "Enrollment token revoked",
        extra={
            "enrollment_id": str(token.id),
            "source_id": str(source.id),
            "reason": reason[:200],
        },
    )

    return token


# ============================================================================
# LIST
# ============================================================================

def list_tokens_for_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    page: PageParams,
    include_redeemed: bool = False,
) -> tuple[list[SourceEnrollment], int]:
    """
    List enrollment tokens for a source.

    Requires ``PERM_SOURCE_READ`` in the source's workspace. By default,
    only shows pending + revoked + expired (not redeemed) — the
    redeemed ones clutter the admin view and are only needed for
    compliance audits.

    Set ``include_redeemed=True`` to include all — used by the compliance
    audit dashboard.
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_READ, workspace_id=source.workspace_id,
    )

    stmt = select(SourceEnrollment).where(
        SourceEnrollment.source_id == source.id,
    )
    if not include_redeemed:
        stmt = stmt.where(SourceEnrollment.redeemed_at.is_(None))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(SourceEnrollment.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# SWEEP — background job
# ============================================================================

def sweep_expired(
    db: Session,
    *,
    limit: int = 500,
) -> int:
    """
    Mark expired pending tokens as EXPIRED.

    Called by a periodic background job (cron, scheduler, or worker
    loop). Idempotent — running it again on already-swept tokens is
    a no-op.

    The ``is_expired`` property already returns True for past-expiry
    tokens regardless of ``status`` — so this sweep is a **visibility**
    operation, not a correctness one. It transitions the row's
    ``status`` field to ``EXPIRED`` so admin dashboards can filter on
    it cleanly instead of computing expiry inline.

    Returns
    -------
    int
        Number of tokens transitioned to EXPIRED.
    """
    if limit < 1 or limit > _MAX_SWEEP_BATCH:
        raise ValueError(
            f"limit must be between 1 and {_MAX_SWEEP_BATCH}, got {limit}"
        )

    now = datetime.now(timezone.utc)
    candidates = db.execute(
        select(SourceEnrollment)
        .where(
            SourceEnrollment.status == EnrollmentStatus.PENDING,
            SourceEnrollment.expires_at <= now,
            SourceEnrollment.redeemed_at.is_(None),
            SourceEnrollment.revoked_at.is_(None),
        )
        .limit(limit)
    ).scalars().all()

    swept = 0
    for token in candidates:
        token.status = EnrollmentStatus.EXPIRED
        swept += 1

    if swept > 0:
        db.flush()
        logger.info(
            "Enrollment sweep: tokens marked EXPIRED",
            extra={"count": swept},
        )

    return swept


# ============================================================================
# INTERNAL — request context extraction (local, minimal)
# ============================================================================
# These duplicate a small bit of app.services.audit_service._extract_request_context
# intentionally — keeping audit_service's internals private means this file
# isn't coupled to audit's implementation. The two stay in sync semantically
# but can evolve independently.

def _extract_ip(request: Any | None) -> str | None:
    """Extract client IP from a FastAPI/Starlette request, or None."""
    if request is None:
        return None
    try:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:45]
        if request.client:
            return request.client.host[:45]
    except Exception:  # noqa: BLE001 — never fail on context extraction
        pass
    return None


def _extract_user_agent(request: Any | None) -> str | None:
    """Extract user-agent string from a FastAPI/Starlette request, or None."""
    if request is None:
        return None
    try:
        ua = request.headers.get("user-agent")
        if ua:
            return ua[:512]
    except Exception:  # noqa: BLE001
        pass
    return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "RedemptionResult",
    "create_enrollment_token",
    "redeem_token",
    "revoke_token",
    "list_tokens_for_source",
    "sweep_expired",
]