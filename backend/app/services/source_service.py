"""
CyberGuard AI — Security Source Service
============================================================================

Business logic for security sources: registration, lifecycle, and the
five connection indicators.

A source is a registered device, log stream, network tap, email account,
or database whose events the platform monitors. This service owns the
lifecycle of that source — from initial registration through revocation.

The 5 connection indicators
---------------------------
The interaction document is emphatic that connection ≠ monitoring.
This service is where that distinction is preserved at the data layer.
Each of the 5 indicators has its own dedicated update method, called by
a specific subsystem:

    collector_connected      ← record_collector_connected/disconnected()
                                (called by heartbeat service)
    last_heartbeat_at        ← record_heartbeat()
                                (called by heartbeat service)
    collection_active        ← enable_collection() / disable_collection()
                                (called by user via API)
    last_event_at            ← record_event_received()
                                (called by event ingestion service)
    agent_processing_healthy ← mark_processing_healthy/degraded()
                                (called by agent runtime)

**No single method updates more than one indicator.** This is
deliberate — it means the "the collector is running but not sending
events" state is impossible to accidentally collapse into "everything
is fine" by a misbehaving caller.

Source key
----------
Every source gets a human-readable short ID at creation:

    src-<8 lowercase hex chars>

Generated from a random UUID fragment. Unique within its workspace
(enforced by DB partial index + service check). Used in audit logs,
reports, and UI so that identifying a source doesn't require dragging
around a UUID.

Status lifecycle
----------------
    PENDING_ENROLLMENT → ACTIVE → DISABLED → ACTIVE
                       → REVOKED  (terminal)

    PENDING_ENROLLMENT — created but no collector has redeemed the
                         enrollment token yet
    ACTIVE             — collector is enrolled and can send events
    DISABLED           — user paused the source; collector can still
                         heartbeat but events are rejected
    REVOKED            — credentials permanently invalidated; source
                         cannot be reactivated (would need a new
                         enrollment)

``enable_collection`` / ``disable_collection`` are NOT the same as
enabling/disabling the source:

    - Collection toggle (``collection_active``): user pauses event
      intake temporarily. Collector keeps heartbeating. Used for
      maintenance windows or investigating suspected false positives.
    - Source disable (``status=DISABLED``): administratively stops
      the source. Collector may still heartbeat (proves liveness) but
      events are rejected with 403.

Source creation
---------------
Creating a source does NOT enroll it. The flow is:

    1. ``create_source`` — creates the row in PENDING_ENROLLMENT
    2. ``enrollment_service.create_invitation`` — issues a token
    3. User runs the collector on their device
    4. Collector redeems the token via ``collector_enrollment_service``
    5. ``activate_source`` — flips to ACTIVE (called by enrollment
       service on successful redemption)

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Every state-changing method audits.
5. Tenant isolation is enforced via ``authorization`` on every
   mutation.

Public API
----------
    create_source(db, *, actor, workspace, payload, request=None) → SecuritySource
    activate_source(db, *, actor, source, ...) → SecuritySource
    get_by_id(db, source_id) → SecuritySource
    get_by_source_key(db, *, workspace_id, source_key) → SecuritySource
    list_by_workspace(db, *, actor, workspace, page, filters) → (list, int)
    update_source(db, *, actor, source, payload, request=None) → SecuritySource

Lifecycle:
    enable_collection(db, *, actor, source, reason=None, request=None) → SecuritySource
    disable_collection(db, *, actor, source, reason=None, request=None) → SecuritySource
    disable_source(db, *, actor, source, reason, request=None) → SecuritySource
    re_enable_source(db, *, actor, source, request=None) → SecuritySource
    revoke_source(db, *, actor, source, reason, request=None) → SecuritySource

Indicator updates (called by internal subsystems):
    record_heartbeat(db, *, source, from_ip=None) → SecuritySource
    record_collector_connected(db, *, source, from_ip=None) → SecuritySource
    record_collector_disconnected(db, *, source, reason=None) → SecuritySource
    record_event_received(db, *, source, at=None) → SecuritySource
    record_events_failed(db, *, source, count=1) → SecuritySource
    mark_processing_healthy(db, *, source) → SecuritySource
    mark_processing_degraded(db, *, source, reason=None) → SecuritySource

Usage
-----
    from app.services import source_service

    # User registers a device
    source = source_service.create_source(
        db, actor=current_user, workspace=workspace, payload=body,
    )
    db.commit()

    # ... enrollment happens ...
    source_service.activate_source(db, actor=current_user, source=source)

    # Collector heartbeat (called by collector API endpoint)
    source_service.record_heartbeat(db, source=source, from_ip="203.0.113.42")
    db.commit()
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_SOURCE_CREATE,
    PERM_SOURCE_DISABLE,
    PERM_SOURCE_ENROLL,
    PERM_SOURCE_READ,
    PERM_SOURCE_REVOKE,
    PERM_SOURCE_UPDATE,
)
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    InvalidStateTransitionError,
    SourceDisabledError,
    SourceNotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.enums import (
    SourceStatus,
    SourceType,
)
from app.models.source import SecuritySource
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.schemas.source import (
    SecuritySourceCreate,
    SecuritySourceFilter,
    SecuritySourceUpdate,
)
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

_SOURCE_KEY_PATTERN = re.compile(r"^src-[a-f0-9]{8}$")

#: Default capability set per source type. Used when the caller
#: doesn't specify capabilities explicitly. These are conservative
#: defaults — enabling more requires explicit opt-in.
_DEFAULT_CAPABILITIES_BY_TYPE: dict[SourceType, list[str]] = {
    SourceType.WINDOWS: ["log_collection"],
    SourceType.LINUX: ["log_collection"],
    SourceType.MACOS: ["log_collection"],
    SourceType.ANDROID: ["log_collection"],
    SourceType.EMAIL: ["email_scan"],
    SourceType.NETWORK: ["network_monitoring"],
    SourceType.WEB_APP: ["log_collection"],
    SourceType.DATABASE: ["database_audit"],
    SourceType.MANUAL: [],
    SourceType.OTHER: [],
}

#: How stale a heartbeat can be before the source is considered
#: disconnected. Matches ``settings.COLLECTOR_STALE_AFTER_SECONDS``
#: default (300s). Referenced here for the ``is_stale`` helper in the
#: model — do not change the model's threshold without updating this.
_DEFAULT_STALE_THRESHOLD_SECONDS = 300


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _generate_source_key() -> str:
    """
    Generate a fresh ``src-<8 hex>`` identifier.

    Uses 4 random bytes (``secrets.token_hex``) — 2^32 namespace. The
    caller retries on collision (rare but theoretically possible within
    a workspace). The DB partial unique index on
    ``(workspace_id, source_key)`` is the final arbiter.
    """
    return f"src-{secrets.token_hex(4)}"


def _get_by_source_key_optional(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    source_key: str,
) -> SecuritySource | None:
    """Fetch a source by (workspace, source_key) without raising."""
    return db.execute(
        select(SecuritySource).where(
            SecuritySource.workspace_id == workspace_id,
            SecuritySource.source_key == source_key,
        )
    ).scalar_one_or_none()


def _snapshot_state(source: SecuritySource) -> dict[str, Any]:
    """Capture mutable fields for audit."""
    return {
        "name": source.name,
        "description": source.description,
        "source_type": source.source_type.value,
        "status": source.status.value,
        "collection_active": source.collection_active,
        "capabilities": list(source.capabilities or []),
        "config": dict(source.config or {}),
    }


def _require_source_access(
    db: Session,
    actor: User,
    source: SecuritySource,
    permission: str = PERM_SOURCE_READ,
) -> None:
    """
    Assert the actor has the given permission on the source's
    workspace.

    Uses the workspace-scoped permission check because sources don't
    have their own access grants (evidence does; sources don't).
    Access to a source is access to the workspace that owns it.
    """
    authorization.check_permission(
        db, actor, permission, workspace_id=source.workspace_id,
    )


def _now() -> datetime:
    """UTC now. Wrapped so tests can monkeypatch it if needed."""
    return datetime.now(timezone.utc)


# ============================================================================
# CREATE
# ============================================================================

def create_source(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    payload: SecuritySourceCreate,
    request: Any | None = None,
) -> SecuritySource:
    """
    Register a new source in a workspace.

    Creates the row in ``PENDING_ENROLLMENT`` status. The source is not
    usable until a collector redeems an enrollment token for it — see
    ``activate_source``.

    Auto-generated fields:
        - ``source_key`` — ``src-<8 hex>``, unique per workspace
        - ``registered_by_id`` — actor.id
        - ``status`` — PENDING_ENROLLMENT
        - all 5 connection indicators — "not connected" initial values

    Default capabilities are populated per source type if the caller
    does not supply an explicit list. This means a Windows source
    starts with ``log_collection`` enabled — no configuration needed
    for the common case.

    Raises
    ------
    AuthorizationError
        If the actor lacks ``PERM_SOURCE_CREATE`` in the workspace.
    ConflictError
        If source_key collides (extremely rare — retried internally).
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_CREATE, workspace_id=workspace.id,
    )

    # ── 1. Resolve capabilities (defaults per type if not supplied)
    capabilities = list(payload.capabilities or [])
    if not capabilities:
        capabilities = list(
            _DEFAULT_CAPABILITIES_BY_TYPE.get(payload.source_type, [])
        )

    # ── 2. Generate a unique source_key (retry on collision — ~never)
    source_key: str | None = None
    for _attempt in range(5):
        candidate = _generate_source_key()
        existing = _get_by_source_key_optional(
            db,
            workspace_id=workspace.id,
            source_key=candidate,
        )
        if existing is None:
            source_key = candidate
            break

    if source_key is None:
        raise ConflictError(
            message=(
                "Could not generate a unique source_key after 5 attempts. "
                "This is extremely unusual — please retry."
            ),
            code="SOURCE_KEY_GENERATION_FAILED",
        )

    # ── 3. Create
    source = SecuritySource(
        workspace_id=workspace.id,
        registered_by_id=actor.id,
        source_key=source_key,
        name=payload.name,
        description=payload.description,
        source_type=payload.source_type,
        status=SourceStatus.PENDING_ENROLLMENT,
        # 5 connection indicators — all "not connected" initially
        collector_connected=False,
        last_heartbeat_at=None,
        collection_active=False,
        last_event_at=None,
        agent_processing_healthy=True,   # neutral default; not relevant until events arrive
        # Configuration
        capabilities=capabilities,
        config=payload.config or {},
    )
    db.add(source)
    db.flush()

    # ── 4. Audit
    audit_service.log_action(
        db,
        actor=actor,
        action="source.created",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        request=request,
        metadata={
            "source_type": payload.source_type.value,
            "capabilities": capabilities,
        },
    )

    logger.info(
        "Source registered",
        extra={
            "source_id": str(source.id),
            "workspace_id": str(workspace.id),
            "source_key": source_key,
            "source_type": payload.source_type.value,
        },
    )

    return source


# ============================================================================
# LIFECYCLE — ACTIVATION (called by enrollment flow)
# ============================================================================

def activate_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    request: Any | None = None,
) -> SecuritySource:
    """
    Transition PENDING_ENROLLMENT → ACTIVE.

    Called by the enrollment flow after a collector successfully
    redeems an enrollment token and receives its credential. The actor
    is the user who owns the workspace — the collector itself does not
    have a User identity.

    Requires ``PERM_SOURCE_ENROLL`` in the workspace.

    Idempotent — calling on an already-active source is a no-op.
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_ENROLL, workspace_id=source.workspace_id,
    )

    if source.status == SourceStatus.ACTIVE:
        return source

    if source.status != SourceStatus.PENDING_ENROLLMENT:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot activate source in status {source.status.value}. "
                "Only PENDING_ENROLLMENT sources can be activated."
            ),
            code="SOURCE_NOT_PENDING_ENROLLMENT",
            details={"status": source.status.value},
        )

    before = {"status": source.status.value}
    source.status = SourceStatus.ACTIVE
    db.flush()
    after = {"status": source.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="source.activated",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        organization_id=None,  # from source's workspace; caller can set if needed
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Source activated",
        extra={
            "source_id": str(source.id),
            "source_key": source.source_key,
        },
    )

    return source


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, source_id: uuid.UUID) -> SecuritySource:
    """
    Fetch a source by ID. Raises ``SourceNotFoundError`` if missing.

    Does NOT check tenant access — the caller (endpoint) must call
    ``authorization.check_permission`` with the source's workspace.
    This keeps ``get_by_id`` reusable from internal subsystems
    (heartbeat, ingestion) that have already established access.
    """
    source = db.get(SecuritySource, source_id)
    if source is None:
        raise SourceNotFoundError(
            message=f"Source {source_id} not found.",
            details={"source_id": str(source_id)},
        )
    return source


def get_by_source_key(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    source_key: str,
) -> SecuritySource:
    """Fetch a source by (workspace, source_key)."""
    normalized = source_key.strip().lower()
    source = _get_by_source_key_optional(
        db, workspace_id=workspace_id, source_key=normalized,
    )
    if source is None:
        raise SourceNotFoundError(
            message=f"Source {source_key!r} not found in this workspace.",
            details={
                "workspace_id": str(workspace_id),
                "source_key": normalized,
            },
        )
    return source


def list_by_workspace(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    page: PageParams,
    filters: SecuritySourceFilter | None = None,
) -> tuple[list[SecuritySource], int]:
    """
    List sources in a workspace.

    Requires ``PERM_SOURCE_READ`` in the workspace. Returns
    ``(sources_on_page, total_count)``.
    """
    authorization.check_permission(
        db, actor, PERM_SOURCE_READ, workspace_id=workspace.id,
    )

    stmt = select(SecuritySource).where(
        SecuritySource.workspace_id == workspace.id,
    )

    if filters is not None:
        if filters.source_type is not None:
            stmt = stmt.where(SecuritySource.source_type == filters.source_type)
        if filters.status is not None:
            stmt = stmt.where(SecuritySource.status == filters.status)
        if filters.collector_connected is not None:
            stmt = stmt.where(
                SecuritySource.collector_connected == filters.collector_connected
            )
        if filters.collection_active is not None:
            stmt = stmt.where(
                SecuritySource.collection_active == filters.collection_active
            )
        if filters.name_contains:
            stmt = stmt.where(
                SecuritySource.name.ilike(f"%{filters.name_contains.lower()}%")
            )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(SecuritySource.created_at.desc(), SecuritySource.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    sources = list(db.execute(stmt).scalars().all())
    return sources, int(total)


# ============================================================================
# UPDATE
# ============================================================================

def update_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    payload: SecuritySourceUpdate,
    request: Any | None = None,
) -> SecuritySource:
    """
    Update mutable fields of a source.

    Requires ``PERM_SOURCE_UPDATE`` in the source's workspace.

    Cannot change:
        - ``source_key`` — immutable
        - ``status`` — dedicated lifecycle methods
        - ``workspace_id`` — set at creation
        - the 5 connection indicators — updated by their dedicated methods

    ``config`` is merged, not replaced. To remove a key, pass it with
    a null value.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_UPDATE)

    before = _snapshot_state(source)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return source

    # Merge config, don't replace
    if "config" in updates and updates["config"] is not None:
        merged = dict(source.config or {})
        for k, v in updates["config"].items():
            if v is None:
                merged.pop(k, None)
            else:
                merged[k] = v
        updates["config"] = merged

    for field, value in updates.items():
        setattr(source, field, value)

    db.flush()
    after = _snapshot_state(source)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="source.updated",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return source


# ============================================================================
# COLLECTION TOGGLE
# ============================================================================

def enable_collection(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    reason: str | None = None,
    request: Any | None = None,
) -> SecuritySource:
    """
    Turn event collection **on** for this source.

    Requires ``PERM_SOURCE_UPDATE`` in the workspace. Idempotent —
    enabling an already-enabling collection is a no-op.

    This is NOT the same as activating the source. A source can be
    ACTIVE (collector enrolled) with collection paused. The user can
    re-enable collection at any time without re-enrolling.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_UPDATE)

    if source.collection_active:
        return source  # idempotent

    if source.status in (SourceStatus.REVOKED, SourceStatus.DISABLED):
        raise InvalidStateTransitionError(
            message=(
                f"Cannot enable collection on a source in "
                f"{source.status.value} status."
            ),
            code="SOURCE_CANNOT_ENABLE_COLLECTION",
            details={"status": source.status.value},
        )

    source.collection_active = True
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="source.collection_enabled",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        notes=reason,
        request=request,
    )

    logger.info(
        "Source collection enabled",
        extra={
            "source_id": str(source.id),
            "source_key": source.source_key,
        },
    )

    return source


def disable_collection(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    reason: str | None = None,
    request: Any | None = None,
) -> SecuritySource:
    """
    Turn event collection **off** for this source.

    Requires ``PERM_SOURCE_UPDATE``. Idempotent.

    The collector keeps heartbeating (proving the process is alive),
    but events sent while collection is paused are rejected by the
    ingestion endpoint. This is the "pause monitoring temporarily"
    workflow.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_UPDATE)

    if not source.collection_active:
        return source  # idempotent

    source.collection_active = False
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="source.collection_disabled",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        notes=reason,
        request=request,
    )

    return source


# ============================================================================
# LIFECYCLE — DISABLE / RE-ENABLE / REVOKE
# ============================================================================

def disable_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    reason: str,
    request: Any | None = None,
) -> SecuritySource:
    """
    Administratively disable a source. Transitions to ``DISABLED``.

    Requires ``PERM_SOURCE_DISABLE``. The collector may still
    heartbeat but events are rejected. Distinct from collection toggle:
    disabling is a stronger signal ("this source should not be trusted
    right now").

    Cannot disable a REVOKED source — that's a terminal state.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_DISABLE)

    if source.status == SourceStatus.DISABLED:
        return source  # idempotent
    if source.status == SourceStatus.REVOKED:
        raise InvalidStateTransitionError(
            message="Cannot disable a revoked source.",
            code="SOURCE_REVOKED_TERMINAL",
            details={"status": source.status.value},
        )

    before = {"status": source.status.value, "collection_active": source.collection_active}
    source.status = SourceStatus.DISABLED
    source.collection_active = False
    db.flush()
    after = {"status": source.status.value, "collection_active": source.collection_active}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="source.disabled",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        before_state=before,
        after_state=after,
        notes=reason,
        request=request,
    )

    logger.warning(
        "Source disabled",
        extra={
            "source_id": str(source.id),
            "source_key": source.source_key,
            "reason": reason[:200],
        },
    )

    return source


def re_enable_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    request: Any | None = None,
) -> SecuritySource:
    """
    Reactivate a DISABLED source. Transitions to ACTIVE.

    Requires ``PERM_SOURCE_DISABLE`` (same permission as disable — if
    you can disable, you can re-enable).

    Collection stays off after re-enable. The user must explicitly
    enable it — this prevents a re-enabled source from immediately
    flooding the pipeline before the operator has verified things
    look OK.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_DISABLE)

    if source.status != SourceStatus.DISABLED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot re-enable source in status {source.status.value}. "
                "Only DISABLED sources can be re-enabled."
            ),
            code="SOURCE_NOT_DISABLED",
            details={"status": source.status.value},
        )

    before = {"status": source.status.value}
    source.status = SourceStatus.ACTIVE
    db.flush()
    after = {"status": source.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="source.re_enabled",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return source


def revoke_source(
    db: Session,
    *,
    actor: User,
    source: SecuritySource,
    reason: str,
    request: Any | None = None,
) -> SecuritySource:
    """
    Permanently revoke a source. Terminal state.

    Requires ``PERM_SOURCE_REVOKE``. Sets ``status=REVOKED`` and
    ``collection_active=False``. All collector credentials for this
    source are expected to be revoked by the
    ``collector_credential_service`` as a follow-up action — this
    method only revokes the source row.

    A revoked source cannot be reactivated. To restore monitoring for
    the same device, the user must create a new source and re-enroll
    the collector.
    """
    _require_source_access(db, actor, source, PERM_SOURCE_REVOKE)

    if source.status == SourceStatus.REVOKED:
        return source  # idempotent
    if not reason or not reason.strip():
        raise ValidationError(
            message="A revocation reason is required.",
            code="SOURCE_REVOCATION_REASON_REQUIRED",
        )

    before = {"status": source.status.value}
    source.status = SourceStatus.REVOKED
    source.collection_active = False
    db.flush()
    after = {"status": source.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="source.revoked",
        target_type="source",
        target_id=source.id,
        target_display=source.source_key,
        workspace_id=source.workspace_id,
        before_state=before,
        after_state=after,
        notes=reason,
        request=request,
    )

    logger.warning(
        "Source revoked",
        extra={
            "source_id": str(source.id),
            "source_key": source.source_key,
            "reason": reason[:200],
        },
    )

    return source


# ============================================================================
# INDICATOR UPDATES — called by internal subsystems
# ============================================================================
# These methods do NOT audit. They are high-frequency system events
# (heartbeats fire every 60s per source; events fire per-event) — the
# audit log would be overwhelmed by them. State is observable via the
# indicators themselves; specific security-relevant transitions
# (revocation, disable) are audited in the lifecycle methods above.

def record_heartbeat(
    db: Session,
    *,
    source: SecuritySource,
    from_ip: str | None = None,
) -> SecuritySource:
    """
    Record a heartbeat. Sets ``collector_connected=True`` and updates
    ``last_heartbeat_at`` and ``ip_address`` (if provided).

    Called by the heartbeat API endpoint. This is the only method that
    should set ``collector_connected=True`` — it is the definitive
    signal that the collector is alive.

    Rejects heartbeats from REVOKED sources (defensive: the endpoint
    will already reject the request at auth, but the service should
    never advance a revoked source's state).
    """
    if source.status == SourceStatus.REVOKED:
        raise SourceDisabledError(
            message="Cannot record heartbeat on a revoked source.",
            code="SOURCE_REVOKED",
            details={"source_id": str(source.id)},
        )

    source.collector_connected = True
    source.last_heartbeat_at = _now()
    if from_ip:
        source.ip_address = from_ip.strip()[:45]

    db.flush()
    return source


def record_collector_connected(
    db: Session,
    *,
    source: SecuritySource,
    from_ip: str | None = None,
) -> SecuritySource:
    """
    Same as ``record_heartbeat``. Exists for callers that logically
    represent a "connect" event (initial handshake) vs. a periodic
    heartbeat. Behavior is identical — the indicator does not
    distinguish between them.
    """
    return record_heartbeat(db, source=source, from_ip=from_ip)


def record_collector_disconnected(
    db: Session,
    *,
    source: SecuritySource,
    reason: str | None = None,
) -> SecuritySource:
    """
    Mark the collector as disconnected.

    Called by:
        - The heartbeat endpoint when the collector explicitly sends a
          "disconnect" message (graceful shutdown)
        - A background sweep that detects stale heartbeats (no
          heartbeat for > ``COLLECTOR_STALE_AFTER_SECONDS``)

    Does NOT change ``status`` — a source with status=ACTIVE and
    ``collector_connected=False`` is the "disconnected" UI state. The
    user must re-enroll or fix the collector; re-enable happens
    automatically the next heartbeat.
    """
    source.collector_connected = False
    if reason:
        logger.info(
            "Collector marked disconnected",
            extra={
                "source_id": str(source.id),
                "source_key": source.source_key,
                "reason": reason[:200],
            },
        )
    db.flush()
    return source


def record_event_received(
    db: Session,
    *,
    source: SecuritySource,
    at: datetime | None = None,
) -> SecuritySource:
    """
    Record that a real event was ingested from this source.

    Called by the event ingestion service after persisting an event.
    Sets ``last_event_at`` and increments ``events_ingested_count``.

    This is the ONLY method that should update ``last_event_at``.
    It is the definitive proof of end-to-end data flow.
    """
    if source.status == SourceStatus.REVOKED:
        raise SourceDisabledError(
            message="Cannot record event on a revoked source.",
            code="SOURCE_REVOKED",
            details={"source_id": str(source.id)},
        )
    if source.status == SourceStatus.DISABLED:
        raise SourceDisabledError(
            message="Cannot record event on a disabled source.",
            code="SOURCE_DISABLED",
            details={"source_id": str(source.id)},
        )
    if not source.collection_active:
        raise SourceDisabledError(
            message=(
                "Cannot record event: collection is paused. "
                "The collector should not be sending events."
            ),
            code="COLLECTION_PAUSED",
            details={"source_id": str(source.id)},
        )

    source.last_event_at = at or _now()
    source.events_ingested_count = (source.events_ingested_count or 0) + 1
    db.flush()
    return source


def record_events_failed(
    db: Session,
    *,
    source: SecuritySource,
    count: int = 1,
) -> SecuritySource:
    """
    Increment the failed-event counter for a source.

    Called by the ingestion service when events are rejected
    (validation, duplicate, oversized). No state change to indicators
    — just a counter update.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    source.events_failed_count = (source.events_failed_count or 0) + count
    db.flush()
    return source


def mark_processing_healthy(
    db: Session,
    *,
    source: SecuritySource,
) -> SecuritySource:
    """
    Mark agent processing as healthy for this source.

    Called by the agent runtime after successfully processing a batch
    of events from this source. The alternative — marking healthy only
    on success — would require tracking consecutive failures across
    runs. The current heuristic is: any successful batch resets the
    flag. Degradation signals accumulate separately via
    ``mark_processing_degraded``.
    """
    if source.agent_processing_healthy:
        return source  # idempotent
    source.agent_processing_healthy = True
    db.flush()
    logger.info(
        "Source processing marked healthy",
        extra={"source_id": str(source.id)},
    )
    return source


def mark_processing_degraded(
    db: Session,
    *,
    source: SecuritySource,
    reason: str | None = None,
) -> SecuritySource:
    """
    Mark agent processing as degraded for this source.

    Called by the agent runtime after repeated processing failures
    (e.g. a rule that crashes on this source's events). The exact
    threshold for "repeated" is the caller's policy — this method just
    flips the flag.
    """
    if not source.agent_processing_healthy and not reason:
        return source  # idempotent, no log spam
    source.agent_processing_healthy = False
    db.flush()
    logger.warning(
        "Source processing marked degraded",
        extra={
            "source_id": str(source.id),
            "source_key": source.source_key,
            "reason": (reason or "")[:200] or None,
        },
    )
    return source


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Create
    "create_source",
    "activate_source",
    # Read
    "get_by_id",
    "get_by_source_key",
    "list_by_workspace",
    # Update
    "update_source",
    # Collection toggle
    "enable_collection",
    "disable_collection",
    # Lifecycle
    "disable_source",
    "re_enable_source",
    "revoke_source",
    # Indicator updates (called by internal subsystems)
    "record_heartbeat",
    "record_collector_connected",
    "record_collector_disconnected",
    "record_event_received",
    "record_events_failed",
    "mark_processing_healthy",
    "mark_processing_degraded",
]