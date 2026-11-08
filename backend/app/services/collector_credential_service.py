"""
CyberGuard AI — Collector Credential Service
============================================================================

Credential issuance, rotation, revocation, and verification for device
collectors.

Two-table model
---------------
This service writes to **two** related tables:

    collector_credentials  — installation lifecycle record (one per
                             physical collector install)
    source_credentials     — actual auth tokens (one per active or
                             historical token on an installation)

Why two tables?
    A single installation can have many credentials over its lifetime
    due to rotation. The installation record persists; individual
    credentials come and go. This separation means:

    - ``verify_credential`` (hot path) queries only ``source_credentials``
      — small indexed table, fast.
    - ``rotate_credential`` preserves installation history
      (``rotation_count``, ``last_rotated_at``).
    - ``retire_installation`` can cascade-revoke all credentials on a
      device without orphan rows.

Credential format
-----------------
    cgc_<8 hex><32-byte URL-safe body>

    Prefix: ``cgc_XXXXXXXX`` — the first 12 chars, stored plaintext,
            format ``^cgc_[a-f0-9]{8}$``, indexed
    Hash:   bcrypt hash of the full credential
    Length: ~55 chars total

The prefix enables O(1) lookup on the hot path without scanning every
row. Full hash verification (bcrypt, timing-safe) confirms the
credential is authentic.

Reinstall handling
------------------
The DB unique constraint ``(source_id, collector_id)`` allows one
installation row per (source, collector_id) pair, including retired
ones. This means:

    Same collector_id + retired → reactivate the existing installation
    Same collector_id + active  → reuse as-is (rotation, not reinstall)
    New collector_id             → create a new installation row

For a physical device replacement, the collector generates a **new**
collector_id on install — a new installation row is created.

Hot-path performance
--------------------
``verify_credential`` runs on every collector request (event
ingestion, heartbeat, batch). Two optimizations:

1. **Prefix-first lookup** — no bcrypt work until we have candidates.
2. **Debounced ``last_used_at`` update** — only writes when the
   previous update is >60s old. Prevents write amplification under
   high ingestion volume.

Known limitation: bcrypt verify costs ~100ms per call. At high
ingestion rates (1000+ req/min across all sources), this becomes a
CPU bottleneck. The fix is a Redis cache of verified credential
prefixes with a short TTL — planned for Phase 13. For Phase F
(correctness-first), we accept the cost.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return DTOs (``IssuedCredential`` / ``VerifiedCredential``) for
   the public API, ORM instances for internal-only data.
4. Lifecycle transitions are audited.
5. ``verify_credential`` is **read-mostly** — it does not audit (would
   flood the log on every request). State is observable from
   ``last_used_at`` timestamps.

Public API
----------
    issue_credential(db, *, source, collector_id, ...)       → IssuedCredential
    rotate_credential(db, *, actor, credential, ...)         → IssuedCredential
    revoke_credential(db, *, actor, credential, reason, ...) → SourceCredential
    retire_installation(db, *, actor, installation, ...)     → CollectorCredential
    verify_credential(db, plaintext)                         → VerifiedCredential
    verify_credential_optional(db, plaintext)                → VerifiedCredential | None
    list_credentials_for_source(db, *, actor, source, page, ...) → (list, int)
    list_installations_for_source(db, *, actor, source, page, ...) → (list, int)
    rotate_stale_credentials(db, *, limit=500)               → int
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

from app.core.config import settings
from app.core.constants import (
    PERM_SOURCE_READ,
    PERM_SOURCE_REVOKE,
    PERM_SOURCE_UPDATE,
)
from app.core.exceptions import (
    CollectorAuthError,
    CollectorRevokedError,
    InvalidStateTransitionError,
    SourceDisabledError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    hash_password,
    verify_password,
)
from app.models.collector_credential import (
    CollectorCredential,
    _STATUS_ACTIVE,
    _STATUS_RETIRED,
    _STATUS_REVOKED,
)
from app.models.enums import (
    CredentialStatus,
    SourceStatus,
)
from app.models.source import (
    SecuritySource,
    SourceCredential,
)
from app.models.user import User
from app.schemas.common import PageParams
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================
_CREDENTIAL_SCHEME = "cgc_"
_CREDENTIAL_PREFIX_LEN = 12  # "cgc_" (4) + 8 hex chars

_CREDENTIAL_PREFIX_PATTERN = re.compile(r"^cgc_[a-f0-9]{8}$")

#: Prefix hex bytes — 4 bytes → 8 hex chars.
_PREFIX_HEX_BYTES = 4

#: Body entropy — 32 bytes → ~43 URL-safe chars.
_BODY_ENTROPY_BYTES = 32

#: Grace period added to rotation cadence before hard expiry.
#: Rotation sweep should fire first; expiry is the fallback.
_EXPIRY_GRACE_DAYS = 7

#: Debounce window for ``last_used_at`` updates on the hot path.
_LAST_USED_DEBOUNCE_SECONDS = 60

#: Max batch size for the rotation sweep.
_MAX_SWEEP_BATCH = 1000


# ============================================================================
# RESULT DTYPES
# ============================================================================

@dataclass(frozen=True)
class IssuedCredential:
    """
    A freshly-issued credential.

    The ``plaintext_credential`` field is the **only time** the full
    credential is exposed. It must be captured immediately and never
    expected to be retrievable.
    """
    credential_id: uuid.UUID
    installation_id: uuid.UUID
    plaintext_credential: str
    credential_prefix: str
    expires_at: datetime | None
    heartbeat_interval_seconds: int


@dataclass(frozen=True)
class VerifiedCredential:
    """
    Result of a successful credential verification. Returned by
    ``verify_credential``. Carries everything the caller needs to
    authorize the request:

        - ``source`` — the source row (for workspace_id, permissions)
        - ``credential`` — the auth token (for last_used_at tracking)
        - ``installation`` — the installation record (may be None if
          the credential predates installation tracking)
    """
    source: SecuritySource
    credential: SourceCredential
    installation: CollectorCredential | None


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _derive_plaintext() -> tuple[str, str]:
    """
    Generate a fresh (plaintext_credential, credential_prefix) pair.

    Format: ``cgc_<8 hex><43 URL-safe chars>``

    The prefix is exactly the first 12 chars and matches
    ``^cgc_[a-f0-9]{8}$``.
    """
    prefix_hex = secrets.token_hex(_PREFIX_HEX_BYTES)  # 8 hex chars
    body = secrets.token_urlsafe(_BODY_ENTROPY_BYTES)  # ~43 chars
    prefix = f"{_CREDENTIAL_SCHEME}{prefix_hex}"
    plaintext = f"{prefix}{body}"
    return plaintext, prefix


def _extract_prefix(plaintext: str) -> str | None:
    """
    Extract the 12-char prefix from a plaintext credential. Returns
    None if the input doesn't match the expected format — callers
    treat None as "invalid credential".
    """
    if not isinstance(plaintext, str):
        return None
    stripped = plaintext.strip()
    if len(stripped) < _CREDENTIAL_PREFIX_LEN:
        return None
    prefix = stripped[:_CREDENTIAL_PREFIX_LEN]
    if not _CREDENTIAL_PREFIX_PATTERN.match(prefix):
        return None
    return prefix


def _get_active_installation_optional(
    db: Session,
    *,
    source_id: uuid.UUID,
    collector_id: uuid.UUID,
) -> CollectorCredential | None:
    """Fetch the installation for (source, collector_id), if any."""
    return db.execute(
        select(CollectorCredential).where(
            CollectorCredential.source_id == source_id,
            CollectorCredential.collector_id == collector_id,
        )
    ).scalar_one_or_none()


def _now() -> datetime:
    """UTC now. Wrapped for testability."""
    return datetime.now(timezone.utc)


def _heartbeat_interval() -> int:
    return int(settings.COLLECTOR_HEARTBEAT_INTERVAL_SECONDS)


def _rotation_expiry(now: datetime) -> datetime:
    """Return the hard expiry for a newly-issued credential."""
    return now + timedelta(
        days=settings.COLLECTOR_CREDENTIAL_ROTATION_DAYS + _EXPIRY_GRACE_DAYS
    )


# ============================================================================
# ISSUE
# ============================================================================

def issue_credential(
    db: Session,
    *,
    source: SecuritySource,
    collector_id: uuid.UUID,
    hostname: str | None = None,
    os_version: str | None = None,
    agent_version: str | None = None,
    hardware_fingerprint: str | None = None,
    actor: User | None = None,
    request: Any | None = None,
) -> IssuedCredential:
    """
    Issue a fresh credential for a collector installation.

    Called by:
        - ``enrollment_service.redeem_token`` (initial enrollment)
        - Admin "reinstall" flow if the device was replaced

    Handles reinstall:
        - If an installation for this (source, collector_id) exists
          **retired**, reactivate it in place.
        - If it exists **active**, reuse it (caller probably wanted
          ``rotate_credential`` — log a warning but proceed).
        - If it doesn't exist, create a new installation row.

    Then issues a new ``SourceCredential`` token and returns the
    plaintext to the caller.

    Not audited here — the parent operation (enrollment redemption,
    admin reinstall) is responsible for the audit. This is a
    deliberate design: one logical operation, one audit entry.

    Returns
    -------
    IssuedCredential
    """
    now = _now()

    # ── 1. Find or create installation
    installation = _get_active_installation_optional(
        db,
        source_id=source.id,
        collector_id=collector_id,
    )

    if installation is not None and installation.is_active:
        # Reuse — caller should have called rotate_credential instead
        logger.warning(
            "issue_credential called on an active installation — "
            "reusing it. Consider rotate_credential for this case.",
            extra={
                "source_id": str(source.id),
                "collector_id": str(collector_id),
                "installation_id": str(installation.id),
            },
        )
    elif installation is not None and installation.is_retired:
        # Reactivate in place
        installation.status = _STATUS_ACTIVE
        installation.retired_at = None
        installation.retirement_reason = None
        if hostname is not None:
            installation.hostname = hostname
        if os_version is not None:
            installation.os_version = os_version
        if hardware_fingerprint is not None:
            installation.hardware_fingerprint = hardware_fingerprint
        db.flush()
        logger.info(
            "Retired installation reactivated",
            extra={"installation_id": str(installation.id)},
        )
    elif installation is not None and installation.is_revoked:
        # Cannot reactivate a revoked installation — terminal
        raise CollectorRevokedError(
            message=(
                "This device installation has been permanently revoked. "
                "The collector must generate a new collector_id and "
                "re-enroll via the device-connection wizard."
            ),
            code="COLLECTOR_REVOKED",
            details={"collector_id": str(collector_id)},
        )
    else:
        # Create new installation
        installation = CollectorCredential.build(
            source_id=source.id,
            collector_id=collector_id,
            hostname=hostname,
            os_version=os_version,
            hardware_fingerprint=hardware_fingerprint,
            installer_version=agent_version,
        )
        db.add(installation)
        db.flush()

    # ── 2. Generate credential
    plaintext, prefix = _derive_plaintext()
    expires_at = _rotation_expiry(now)

    credential = SourceCredential(
        source_id=source.id,
        credential_prefix=prefix,
        secret_hash=hash_password(plaintext),
        status=CredentialStatus.ACTIVE,
        description=(
            f"Issued during enrollment for installation "
            f"{installation.id}"
        ),
        expires_at=expires_at,
    )
    db.add(credential)
    db.flush()

    # ── 3. Return
    logger.info(
        "Credential issued",
        extra={
            "source_id": str(source.id),
            "installation_id": str(installation.id),
            "credential_id": str(credential.id),
            "credential_prefix": prefix,
            "expires_at": expires_at.isoformat(),
        },
    )

    return IssuedCredential(
        credential_id=credential.id,
        installation_id=installation.id,
        plaintext_credential=plaintext,
        credential_prefix=prefix,
        expires_at=expires_at,
        heartbeat_interval_seconds=_heartbeat_interval(),
    )


# ============================================================================
# ROTATE
# ============================================================================

def rotate_credential(
    db: Session,
    *,
    actor: User,
    credential: SourceCredential,
    reason: str | None = None,
    request: Any | None = None,
) -> IssuedCredential:
    """
    Rotate an existing credential. Issues a new token and marks the
    old one ROTATED.

    Requires ``PERM_SOURCE_UPDATE`` in the source's workspace.

    The rotation is a single transaction:
        1. Mark old credential ROTATED (with ``rotated_at``)
        2. Issue new credential via ``issue_credential``-equivalent
        3. Increment ``installation.rotation_count``
        4. Update ``installation.last_rotated_at``
        5. Audit

    The new token is returned in plaintext (shown once to caller).
    The old token remains valid until its ``rotated_at`` transition
    completes — but since we're in the same transaction, there's no
    window where both are valid.

    Raises
    ------
    InvalidStateTransitionError
        Old credential isn't ACTIVE.
    """
    if credential.status != CredentialStatus.ACTIVE:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot rotate a credential in status "
                f"{credential.status.value}."
            ),
            code="CREDENTIAL_NOT_ACTIVE",
            details={"credential_id": str(credential.id)},
        )

    source = db.get(SecuritySource, credential.source_id)
    if source is None:
        raise InvalidStateTransitionError(
            message="Credential references a source that no longer exists.",
            code="CREDENTIAL_ORPHANED",
        )

    authorization.check_permission(
        db, actor, PERM_SOURCE_UPDATE, workspace_id=source.workspace_id,
    )

    # ── 1. Find the installation (should always exist for active credentials)
    installation = db.execute(
        select(CollectorCredential)
        .join(SourceCredential, SourceCredential.source_id == CollectorCredential.source_id)
        .where(
            CollectorCredential.source_id == source.id,
            CollectorCredential.status == _STATUS_ACTIVE,
        )
    ).scalars().first()

    # ── 2. Mark old credential ROTATED
    now = _now()
    credential.status = CredentialStatus.ROTATED
    credential.rotated_at = now
    db.flush()

    # ── 3. Issue new credential (reuse installation, or create if missing)
    plaintext, prefix = _derive_plaintext()
    expires_at = _rotation_expiry(now)

    new_credential = SourceCredential(
        source_id=source.id,
        credential_prefix=prefix,
        secret_hash=hash_password(plaintext),
        status=CredentialStatus.ACTIVE,
        description=f"Rotated from credential {credential.id}",
        expires_at=expires_at,
    )
    db.add(new_credential)
    db.flush()

    # ── 4. Update installation counters
    if installation is not None:
        installation.record_rotation()
        installation_id = installation.id
    else:
        # Credential predates installation tracking — this shouldn't
        # normally happen but we handle it defensively.
        installation_id = new_credential.id
        logger.warning(
            "Rotation without an installation record",
            extra={"credential_id": str(credential.id)},
        )

    # ── 5. Audit
    audit_service.log_action(
        db,
        actor=actor,
        action="collector.credential.rotated",
        target_type="source_credential",
        target_id=new_credential.id,
        target_display=prefix,
        workspace_id=source.workspace_id,
        request=request,
        notes=reason,
        metadata={
            "source_id": str(source.id),
            "old_credential_id": str(credential.id),
            "new_credential_id": str(new_credential.id),
            "new_credential_prefix": prefix,
        },
    )

    logger.info(
        "Credential rotated",
        extra={
            "source_id": str(source.id),
            "old_credential_id": str(credential.id),
            "new_credential_id": str(new_credential.id),
            "actor_id": str(actor.id),
        },
    )

    return IssuedCredential(
        credential_id=new_credential.id,
        installation_id=installation_id,
        plaintext_credential=plaintext,
        credential_prefix=prefix,
        expires_at=expires_at,
        heartbeat_interval_seconds=_heartbeat_interval(),
    )


# ============================================================================
# REVOKE
# ============================================================================

def revoke_credential(
    db: Session,
    *,
    actor: User,
    credential: SourceCredential,
    reason: str,
    request: Any | None = None,
) -> SourceCredential:
    """
    Revoke a single credential.

    Requires ``PERM_SOURCE_REVOKE`` in the source's workspace.

    Does **not** retire the installation — other credentials on the
    same installation remain active. To revoke all credentials on a
    device, use ``retire_installation``.

    Use case: revoking a single leaked credential during rotation
    without disrupting the device entirely.

    Raises
    ------
    InvalidStateTransitionError
        Credential is already REVOKED.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A revocation reason is required.",
            code="CREDENTIAL_REVOCATION_REASON_REQUIRED",
        )

    if credential.status == CredentialStatus.REVOKED:
        raise InvalidStateTransitionError(
            message="Credential is already revoked.",
            code="CREDENTIAL_ALREADY_REVOKED",
            details={"credential_id": str(credential.id)},
        )

    source = db.get(SecuritySource, credential.source_id)
    if source is None:
        raise InvalidStateTransitionError(
            message="Credential references a source that no longer exists.",
            code="CREDENTIAL_ORPHANED",
        )

    authorization.check_permission(
        db, actor, PERM_SOURCE_REVOKE, workspace_id=source.workspace_id,
    )

    credential.status = CredentialStatus.REVOKED
    credential.revoked_at = _now()
    credential.revocation_reason = reason.strip()
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="collector.credential.revoked",
        target_type="source_credential",
        target_id=credential.id,
        target_display=credential.credential_prefix,
        workspace_id=source.workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={"source_id": str(source.id)},
    )

    logger.warning(
        "Credential revoked",
        extra={
            "credential_id": str(credential.id),
            "source_id": str(source.id),
            "reason": reason[:200],
        },
    )

    return credential


# ============================================================================
# RETIRE INSTALLATION
# ============================================================================

def retire_installation(
    db: Session,
    *,
    actor: User,
    installation: CollectorCredential,
    reason: str,
    request: Any | None = None,
) -> CollectorCredential:
    """
    Retire an entire installation (device decommission, reinstall).

    Requires ``PERM_SOURCE_REVOKE`` in the source's workspace.

    Cascades: revokes all **active** credentials on the installation.
    Historical credentials (already ROTATED, REVOKED, or EXPIRED)
    keep their own status — only ACTIVE ones are revoked.

    The installation record itself is preserved for audit trail
    (status=retired), not deleted.

    Cannot retire a REVOKED installation — that's terminal.

    Raises
    ------
    InvalidStateTransitionError
        Installation is already retired or revoked.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A retirement reason is required.",
            code="INSTALLATION_RETIREMENT_REASON_REQUIRED",
        )

    if installation.status == _STATUS_RETIRED:
        return installation  # idempotent
    if installation.status == _STATUS_REVOKED:
        raise InvalidStateTransitionError(
            message="Cannot retire a revoked installation.",
            code="INSTALLATION_REVOKED",
            details={"installation_id": str(installation.id)},
        )

    source = db.get(SecuritySource, installation.source_id)
    if source is None:
        raise InvalidStateTransitionError(
            message="Installation references a source that no longer exists.",
            code="INSTALLATION_ORPHANED",
        )

    authorization.check_permission(
        db, actor, PERM_SOURCE_REVOKE, workspace_id=source.workspace_id,
    )

    # ── Revoke all active credentials on this installation
    active_creds = db.execute(
        select(SourceCredential).where(
            SourceCredential.source_id == installation.source_id,
            SourceCredential.status == CredentialStatus.ACTIVE,
        )
    ).scalars().all()

    now = _now()
    for cred in active_creds:
        cred.status = CredentialStatus.REVOKED
        cred.revoked_at = now
        cred.revocation_reason = f"Installation retired: {reason.strip()[:400]}"

    # ── Retire installation
    installation.retire(reason=reason.strip())
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="collector.installation.retired",
        target_type="collector_credential",
        target_id=installation.id,
        workspace_id=source.workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={
            "source_id": str(source.id),
            "collector_id": str(installation.collector_id),
            "revoked_credential_count": len(active_creds),
        },
    )

    logger.info(
        "Installation retired",
        extra={
            "installation_id": str(installation.id),
            "source_id": str(source.id),
            "revoked_credentials": len(active_creds),
        },
    )

    return installation


# ============================================================================
# VERIFY — hot path
# ============================================================================

def verify_credential(
    db: Session,
    plaintext: str,
    *,
    from_ip: str | None = None,
) -> VerifiedCredential:
    """
    Verify a plaintext credential. Returns the source and credential
    on success; raises on failure.

    Called on **every** collector request (ingestion, heartbeat, batch).
    This is the hottest path in the platform.

    Steps
    -----
    1. Extract prefix from plaintext
    2. Look up candidates by prefix
    3. Verify bcrypt hash
    4. Check credential status is ACTIVE and not expired
    5. Check installation status (if one exists) is active
    6. Check source status is ACTIVE
    7. Debounced update of ``last_used_at`` on credential + installation
    8. Return VerifiedCredential

    Raises
    ------
    CollectorAuthError
        Credential invalid, revoked, expired, or the source doesn't exist.
    SourceDisabledError
        Source is disabled or revoked (valid credentials but blocked).
    """
    # ── 1. Extract prefix
    prefix = _extract_prefix(plaintext)
    if prefix is None:
        raise CollectorAuthError(
            message="Invalid collector credential format.",
            code="COLLECTOR_AUTH_ERROR",
        )

    stripped = plaintext.strip()

    # ── 2. Look up candidates by prefix (indexed — fast)
    candidates = db.execute(
        select(SourceCredential).where(
            SourceCredential.credential_prefix == prefix,
        )
    ).scalars().all()

    # ── 3. Verify bcrypt against each candidate
    credential: SourceCredential | None = None
    for candidate in candidates:
        if verify_password(stripped, candidate.secret_hash):
            credential = candidate
            break

    if credential is None:
        raise CollectorAuthError(
            message="Invalid collector credential.",
            code="COLLECTOR_AUTH_ERROR",
        )

    # ── 4. Check credential status
    if credential.status == CredentialStatus.ROTATED:
        raise CollectorAuthError(
            message="This credential has been rotated. Use the new credential.",
            code="COLLECTOR_CREDENTIAL_ROTATED",
        )
    if credential.status == CredentialStatus.REVOKED:
        raise CollectorRevokedError(
            message="This collector credential has been revoked.",
            code="COLLECTOR_REVOKED",
        )
    if credential.status == CredentialStatus.EXPIRED:
        raise CollectorAuthError(
            message="This collector credential has expired.",
            code="COLLECTOR_CREDENTIAL_EXPIRED",
        )

    now = _now()
    if credential.expires_at is not None:
        exp = credential.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            raise CollectorAuthError(
                message="This collector credential has expired.",
                code="COLLECTOR_CREDENTIAL_EXPIRED",
            )

    # ── 5. Check installation status
    installation = db.execute(
        select(CollectorCredential).where(
            CollectorCredential.source_id == credential.source_id,
        )
    ).scalar_one_or_none()

    if installation is not None:
        if installation.is_revoked:
            raise CollectorRevokedError(
                message="This device installation has been revoked.",
                code="COLLECTOR_REVOKED",
            )
        if installation.is_retired:
            raise CollectorAuthError(
                message="This device installation has been retired.",
                code="COLLECTOR_RETIRED",
            )

    # ── 6. Check source status
    source = db.get(SecuritySource, credential.source_id)
    if source is None:
        raise CollectorAuthError(
            message="The source for this credential no longer exists.",
            code="COLLECTOR_SOURCE_DELETED",
        )
    if source.status == SourceStatus.REVOKED:
        raise SourceDisabledError(
            message="The source has been revoked.",
            code="SOURCE_REVOKED",
        )
    if source.status == SourceStatus.DISABLED:
        raise SourceDisabledError(
            message="The source is disabled.",
            code="SOURCE_DISABLED",
        )
    if source.status != SourceStatus.ACTIVE:
        raise SourceDisabledError(
            message=f"The source is in {source.status.value} status.",
            code="SOURCE_NOT_ACTIVE",
            details={"status": source.status.value},
        )

    # ── 7. Debounced last_used_at update
    should_update = (
        credential.last_used_at is None
        or (now - _as_utc(credential.last_used_at)).total_seconds()
        > _LAST_USED_DEBOUNCE_SECONDS
    )
    if should_update:
        credential.last_used_at = now
        if installation is not None:
            installation.record_auth(from_ip=from_ip)
        db.flush()

    # ── 8. Return
    return VerifiedCredential(
        source=source,
        credential=credential,
        installation=installation,
    )


def verify_credential_optional(
    db: Session,
    plaintext: str,
    *,
    from_ip: str | None = None,
) -> VerifiedCredential | None:
    """
    Non-raising variant. Returns None on any auth failure.

    Useful for endpoints where collector auth is optional (rare —
    some testing/debug endpoints).
    """
    try:
        return verify_credential(db, plaintext, from_ip=from_ip)
    except (CollectorAuthError, CollectorRevokedError, SourceDisabledError):
        return None


# ============================================================================
# LIST
# ============================================================================

def list_credentials_for_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    page: PageParams,
    include_inactive: bool = False,
) -> tuple[list[SourceCredential], int]:
    """
    List credentials for a source. Requires ``PERM_SOURCE_READ``.

    By default, only active credentials are returned. Set
    ``include_inactive=True`` to see the full history (audits).
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_READ, workspace_id=source.workspace_id,
    )

    stmt = select(SourceCredential).where(
        SourceCredential.source_id == source.id,
    )
    if not include_inactive:
        stmt = stmt.where(SourceCredential.status == CredentialStatus.ACTIVE)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(SourceCredential.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


def list_installations_for_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    page: PageParams,
    include_inactive: bool = False,
) -> tuple[list[CollectorCredential], int]:
    """
    List installations for a source. Requires ``PERM_SOURCE_READ``.
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_READ, workspace_id=source.workspace_id,
    )

    stmt = select(CollectorCredential).where(
        CollectorCredential.source_id == source.id,
    )
    if not include_inactive:
        stmt = stmt.where(CollectorCredential.status == _STATUS_ACTIVE)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(CollectorCredential.enrolled_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# ROTATION SWEEP — background job
# ============================================================================

def rotate_stale_credentials(
    db: Session,
    *,
    limit: int = 500,
) -> int:
    """
    Rotate credentials that have exceeded the rotation cadence.

    Called by a periodic background job. A credential is "stale" if:

        - status is ACTIVE
        - its installation is ACTIVE (skip retired/revoked installs)
        - AND
            - ``last_used_at`` is older than the rotation window, OR
            - ``last_used_at IS NULL`` AND ``created_at`` is older than
              the rotation window

    For each stale credential:
        - Issue a new one (via ``rotate_credential`` with actor=None,
          treated as a system action)
        - Mark old as ROTATED
        - Log a WARNING (the collector will fail its next request
          until it picks up the new credential — the platform's
          integration is expected to handle this out-of-band)

    Returns
    -------
    int
        Number of credentials rotated.
    """
    if limit < 1 or limit > _MAX_SWEEP_BATCH:
        raise ValueError(f"limit must be between 1 and {_MAX_SWEEP_BATCH}")

    rotation_cutoff = _now() - timedelta(
        days=settings.COLLECTOR_CREDENTIAL_ROTATION_DAYS
    )

    # Find candidates: active credentials on active installations,
    # unused for the rotation window
    candidates = db.execute(
        select(SourceCredential)
        .join(
            CollectorCredential,
            CollectorCredential.source_id == SourceCredential.source_id,
        )
        .where(
            SourceCredential.status == CredentialStatus.ACTIVE,
            CollectorCredential.status == _STATUS_ACTIVE,
            (
                (SourceCredential.last_used_at.is_(None)
                 & (SourceCredential.created_at < rotation_cutoff))
                | (SourceCredential.last_used_at < rotation_cutoff)
            ),
        )
        .limit(limit)
    ).scalars().all()

    rotated = 0
    for credential in candidates:
        try:
            # Rotate with a "system" actor context — we don't have a
            # real User here. Directly perform the two-step rotation
            # (mark old, issue new) without going through the public
            # ``rotate_credential`` which requires a User.
            now = _now()
            credential.status = CredentialStatus.ROTATED
            credential.rotated_at = now

            plaintext, prefix = _derive_plaintext()
            new_credential = SourceCredential(
                source_id=credential.source_id,
                credential_prefix=prefix,
                secret_hash=hash_password(plaintext),
                status=CredentialStatus.ACTIVE,
                description=f"Auto-rotated from credential {credential.id}",
                expires_at=_rotation_expiry(now),
            )
            db.add(new_credential)
            db.flush()
            rotated += 1

            logger.warning(
                "Stale credential auto-rotated",
                extra={
                    "old_credential_id": str(credential.id),
                    "new_credential_id": str(new_credential.id),
                    "source_id": str(credential.source_id),
                },
            )
        except Exception as exc:  # noqa: BLE001 — sweep must not abort on one failure
            logger.error(
                "Failed to rotate stale credential",
                extra={
                    "credential_id": str(credential.id),
                    "error": str(exc)[:200],
                },
            )

    if rotated > 0:
        logger.info(
            "Rotation sweep complete",
            extra={"rotated": rotated},
        )

    return rotated


# ============================================================================
# INTERNAL — datetime helper
# ============================================================================

def _as_utc(dt: datetime) -> datetime:
    """Normalize a datetime to UTC-aware. Assumes naive = UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "IssuedCredential",
    "VerifiedCredential",
    "issue_credential",
    "rotate_credential",
    "revoke_credential",
    "retire_installation",
    "verify_credential",
    "verify_credential_optional",
    "list_credentials_for_source",
    "list_installations_for_source",
    "rotate_stale_credentials",
]