"""
CyberGuard AI — Audit Service
============================================================================

The **only** writer of ``security_audit_logs``. Every state-changing
service method in the platform calls into this file to record what
happened, who did it, and what changed.

Design rules
------------
1. **Append-only.**
   There is no update or delete API here. Audit rows are written once
   and never modified. The retention job deletes rows after
   ``RETENTION_AUDIT_LOGS_DAYS`` (unless under legal hold) — that
   deletion is a scheduled maintenance action, not an in-request
   operation.

2. **Same-transaction semantics (default).**
   ``log_action(db, ...)`` writes to the caller's session and does
   **not** commit. This is deliberate: an action's audit row and the
   action's state change should commit or roll back together. If the
   state change fails, the audit row rolls back too — which is
   correct, because the action never happened.

3. **Independent-commit escape hatch.**
   ``log_action_independent(...)`` writes to a **fresh session** that
   commits immediately. Used only for cases where the audit row must
   persist even if the caller's transaction rolls back:

       - Failed login attempts (before raising AuthenticationError)
       - Denied permission checks (before raising AuthorizationError)
       - Integrity verification failures (before raising ValidationError)
       - Tampering / suspicious activity detection

   Callers who need this MUST opt in explicitly. The default is
   same-transaction.

4. **Never raise on unknown actions.**
   The action string is validated for length and format, but **not**
   for membership in ``AUDIT_ACTIONS``. If new code paths write an
   action string that isn't in the canonical list, the audit row
   still succeeds — with ``is_recognized_action=False`` (a computed
   property visible to admins). Blocking the write would mean losing
   the very signal we're trying to capture.

5. **Optional ``request`` auto-extraction.**
   Callers in the API layer pass ``request=request``. The service
   pulls correlation ID, IP address, user-agent, method, and path
   from the Request object. Callers in background jobs or agent code
   omit it — those fields are set to None.

6. **Structured logging.**
   Every audit write is also logged to the app's structured logger at
   INFO with the same correlation ID. This means an operator watching
   the logs in real time sees the same events that land in the DB —
   useful for live monitoring and debugging.

7. **No PII beyond what's strictly necessary.**
   The ``before_state`` and ``after_state`` dicts are caller-supplied
   and include only fields the caller decides are relevant. This
   service does **not** snapshot entire ORM models automatically —
   that would risk leaking sensitive fields (``password_hash``,
   ``mfa_secret``, etc.). Callers construct minimal state dicts.

8. **Denials are audit-worthy.**
   ``log_denied_action()`` records every authorization failure. Failed
   privilege-escalation attempts are often the leading indicator of a
   live attack. These go through ``log_action_independent`` because
   the caller is about to raise an exception that rolls back.

9. **Distinguishes actor types.**
   - ``user`` — a real User row (``actor_id`` + ``actor_email``)
   - ``collector`` — a ``SecuritySource`` (``actor_id`` = source.id)
   - ``system`` — cron jobs, migrations, housekeeping (no id)
   - ``agent`` — the platform's own agents (no id, ``metadata_json``
     carries the agent name)

10. **No business logic.**
    This file writes audit rows. It does not decide what to audit —
    that's the caller's responsibility. It does not enforce retention
    — that's a background job. It does not enforce access — the
    caller's authorization check ensures the actor is allowed to
    attempt the action.

Public API
----------
Write (same-transaction):
    log_action(db, ...)
    log_state_change(db, ...)
    bulk_log(db, events)

Write (independent commit — use sparingly):
    log_action_independent(...)
    log_denied_action(...)

High-value convenience wrappers:
    log_login_success, log_login_failed, log_logout
    log_evidence_accessed, log_evidence_uploaded
    log_case_assigned, log_case_closed
    log_incident_severity_changed, log_incident_closed
    log_analyst_access_granted, log_analyst_access_revoked

Read (admin):
    query_audit_logs(db, filters, page)
    compute_stats(db, filters)

Internal DTO:
    AuditEventInternal

Usage
-----
    from app.services import audit_service

    # Simple action
    audit_service.log_action(
        db,
        actor=current_user,
        action="case.read",
        target_type="case",
        target_id=case.id,
        target_display=case.case_number,
    )

    # State change with before/after
    audit_service.log_state_change(
        db,
        actor=current_user,
        action="incident.severity.changed",
        target_type="incident",
        target_id=incident.id,
        before_state={"severity": "medium"},
        after_state={"severity": "high"},
    )

    # Denied attempt (independent commit — persists even if caller rolls back)
    audit_service.log_denied_action(
        actor=current_user,
        action="evidence.accessed",
        target_type="evidence",
        target_id=evidence.id,
        reason="no matching grant",
        request=request,
    )

    # Convenience wrapper
    audit_service.log_login_success(db, user=current_user, request=request)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import (
    AUDIT_ACTIONS,
    AUDIT_CASE_ASSIGNED,
    AUDIT_CASE_CLOSED,
    AUDIT_EVIDENCE_ACCESSED,
    AUDIT_EVIDENCE_UPLOADED,
    AUDIT_INCIDENT_CLOSED,
    AUDIT_INCIDENT_SEVERITY_CHANGED,
    AUDIT_LOGIN_FAILED,
    AUDIT_LOGIN_SUCCESS,
    AUDIT_LOGOUT,
)
from app.core.exceptions import CyberGuardError
from app.core.logging import get_correlation_id, get_logger, set_correlation_id
from app.db.session import session_scope
from app.models.audit import SecurityAuditLog
from app.models.enums import AuditOutcome
from app.models.user import User
from app.schemas.audit import (
    AuditLogFilter,
    AuditLogRead,
    AuditLogStats,
)
from app.schemas.common import PageParams


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================
_MAX_ACTION_LENGTH = 128
_MAX_CHANGED_FIELDS = 50
_MAX_STATE_BYTES = 64 * 1024

_VALID_ACTOR_TYPES = frozenset({"user", "collector", "system", "agent"})

#: Target types that can appear in the ``target_type`` column.
#: Mirrors ``app.models.audit._VALID_TARGET_TYPES``. Duplicated here
#: so this file fails fast with a clear error rather than a DB error.
_VALID_TARGET_TYPES = frozenset({
    "user", "organization", "workspace", "membership",
    "analyst_profile", "source", "source_credential",
    "collector_credential", "enrollment", "event", "finding",
    "alert", "incident", "case", "case_assignment",
    "case_access_grant", "evidence", "conversation", "message",
    "notification", "report", "invitation", "service_offering",
    "service_purchase", "payment_transaction",
    "workspace_membership", "audit_log",
})


# ============================================================================
# INTERNAL DTO
# ============================================================================

class AuditEventInternal:
    """
    Internal DTO representing one audit event to be written.

    Not a Pydantic model — this is a plain dataclass-like object used
    only between ``log_action`` / ``bulk_log`` and the actual row
    construction. Keeping it lightweight avoids validation overhead
    on the hot path (audit writes should be fast).

    Callers outside this module should call ``log_action`` /
    ``log_state_change`` / etc. — not construct this directly.
    """

    __slots__ = (
        "actor_id", "actor_email", "actor_type", "impersonated_by_id",
        "action", "outcome",
        "target_type", "target_id", "target_display",
        "workspace_id", "organization_id",
        "ip_address", "user_agent", "request_method", "request_path",
        "correlation_id",
        "before_state", "after_state", "changed_fields",
        "notes", "metadata_json", "legal_hold_until",
    )

    def __init__(
        self,
        *,
        actor_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        actor_type: str = "user",
        impersonated_by_id: uuid.UUID | None = None,
        action: str = "",
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        target_type: str | None = None,
        target_id: uuid.UUID | None = None,
        target_display: str | None = None,
        workspace_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        correlation_id: str | None = None,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        changed_fields: list[str] | None = None,
        notes: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        legal_hold_until: datetime | None = None,
    ) -> None:
        self.actor_id = actor_id
        self.actor_email = actor_email
        self.actor_type = actor_type
        self.impersonated_by_id = impersonated_by_id
        self.action = action
        self.outcome = outcome
        self.target_type = target_type
        self.target_id = target_id
        self.target_display = target_display
        self.workspace_id = workspace_id
        self.organization_id = organization_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_method = request_method
        self.request_path = request_path
        self.correlation_id = correlation_id
        self.before_state = before_state
        self.after_state = after_state
        self.changed_fields = changed_fields
        self.notes = notes
        self.metadata_json = metadata_json
        self.legal_hold_until = legal_hold_until


# ============================================================================
# INTERNAL VALIDATION HELPERS
# ============================================================================

def _validate_action(action: str) -> str:
    """Validate the action string is a non-empty, bounded string."""
    if not isinstance(action, str):
        raise ValueError("action must be a string")
    stripped = action.strip()
    if not stripped:
        raise ValueError("action must not be empty")
    if len(stripped) > _MAX_ACTION_LENGTH:
        raise ValueError(
            f"action must not exceed {_MAX_ACTION_LENGTH} characters"
        )
    return stripped


def _validate_target_type(target_type: str | None) -> str | None:
    """Validate target_type against the known set (or None)."""
    if target_type is None:
        return None
    normalized = target_type.strip().lower()
    if not normalized:
        return None
    if normalized not in _VALID_TARGET_TYPES:
        raise ValueError(
            f"Unknown target_type: {normalized!r}. "
            f"Valid: {sorted(_VALID_TARGET_TYPES)}"
        )
    return normalized


def _validate_actor_type(actor_type: str) -> str:
    normalized = actor_type.strip().lower()
    if normalized not in _VALID_ACTOR_TYPES:
        raise ValueError(
            f"Unknown actor_type: {normalized!r}. "
            f"Valid: {sorted(_VALID_ACTOR_TYPES)}"
        )
    return normalized


def _compute_changed_fields(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> list[str]:
    """
    Compute the list of keys whose values differ between before and
    after. Returns an empty list if either is None.
    """
    if before is None or after is None:
        return []
    keys = set(before.keys()) | set(after.keys())
    changed: list[str] = []
    for k in sorted(keys):
        if before.get(k) != after.get(k):
            changed.append(k)
    return changed[:_MAX_CHANGED_FIELDS]


def _check_state_size(state: dict[str, Any] | None, label: str) -> None:
    """Enforce the per-state-snapshot size limit."""
    if state is None:
        return
    try:
        size = len(json.dumps(state, default=str).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not JSON-serializable: {exc}")
    if size > _MAX_STATE_BYTES:
        raise ValueError(
            f"{label} exceeds {_MAX_STATE_BYTES} bytes when serialized "
            f"(got {size}). Store a minimal snapshot, not the full model."
        )


def _extract_request_context(request: Any) -> dict[str, Any]:
    """
    Pull IP, user-agent, method, and path from a Starlette/FastAPI
    Request. Returns empty strings on failure — audit writes should
    never fail because the request object was odd.
    """
    ctx: dict[str, Any] = {
        "ip_address": None,
        "user_agent": None,
        "request_method": None,
        "request_path": None,
    }
    if request is None:
        return ctx

    try:
        # Client IP — respect X-Forwarded-For if behind a trusted proxy.
        # Note: trusting X-Forwarded-For blindly is a security issue if
        # not behind a proxy. The proxy configuration is the deployment
        # engineer's responsibility.
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ctx["ip_address"] = forwarded.split(",")[0].strip()[:45]
        elif request.client:
            ctx["ip_address"] = request.client.host[:45]

        ua = request.headers.get("user-agent")
        if ua:
            ctx["user_agent"] = ua[:512]

        ctx["request_method"] = request.method[:16]
        ctx["request_path"] = str(request.url.path)[:2048]
    except Exception as exc:  # noqa: BLE001 — never fail on context extraction
        logger.debug(
            "Failed to extract request context for audit",
            extra={"error": str(exc)[:100]},
        )

    return ctx


def _resolve_actor(
    actor: User | None,
    *,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    actor_type: str,
    impersonated_by_id: uuid.UUID | None,
) -> tuple[uuid.UUID | None, str | None, uuid.UUID | None]:
    """
    Normalize actor identity from either a ``User`` ORM instance or
    explicit (actor_id, actor_email, actor_type) arguments.

    Returns ``(actor_id, actor_email, impersonated_by_id)``.
    """
    if actor is not None:
        return actor.id, actor.email, impersonated_by_id

    # Explicit arguments (used for system/agent/collector events)
    return actor_id, actor_email, impersonated_by_id


# ============================================================================
# CORE WRITE — SAME TRANSACTION
# ============================================================================

def log_action(
    db: Session,
    *,
    actor: User | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_type: str = "user",
    impersonated_by_id: uuid.UUID | None = None,
    action: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    target_display: str | None = None,
    workspace_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    request: Any | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    changed_fields: list[str] | None = None,
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    """
    Write one audit log entry. **Does not commit** — the caller's
    transaction commits or rolls back the audit row along with the
    state change it represents.

    Parameters
    ----------
    db : Session
    actor : User | None
        The acting user. If provided, takes precedence over explicit
        ``actor_id`` / ``actor_email``.
    actor_id, actor_email : optional
        Explicit actor identity. Required when ``actor`` is None and
        ``actor_type`` is ``"user"`` or ``"collector"``.
    actor_type : str
        ``user`` | ``collector`` | ``system`` | ``agent``.
    impersonated_by_id : UUID | None
        Set when a super admin is acting on behalf of another user.
    action : str
        Structured action verb (e.g. ``"case.assigned"``). Must be a
        non-empty string ≤ 128 chars. Membership in ``AUDIT_ACTIONS``
        is **not** required — new actions pass through with
        ``is_recognized_action=False`` visible to admins.
    outcome : AuditOutcome
        ``SUCCESS`` | ``FAILURE`` | ``PARTIAL``.
    target_type, target_id, target_display : optional
        What the action targeted. ``target_type`` must be a known value.
    workspace_id, organization_id : optional
        Scope. Both may be present.
    request : Request | None
        If provided, auto-extracts IP, user-agent, method, path, and
        correlation ID.
    before_state, after_state : optional
        State snapshots. Must be JSON-serializable, ≤ 64 KB each.
        Only include fields the caller decides are relevant — this
        service does not snapshot ORM models.
    changed_fields : optional
        Explicit diff of changed keys. If omitted, computed from
        before/after via value comparison.
    notes : optional
        Free-text context.
    metadata : optional
        Structured extra context. Use for agent names, feature flags,
        or non-sensitive caller context.

    Returns
    -------
    SecurityAuditLog
        The persisted (flushed, not committed) audit row.
    """
    # ── Validation
    validated_action = _validate_action(action)
    validated_target_type = _validate_target_type(target_type)
    normalized_actor_type = _validate_actor_type(actor_type)
    _check_state_size(before_state, "before_state")
    _check_state_size(after_state, "after_state")

    # ── Actor resolution
    resolved_actor_id, resolved_actor_email, resolved_impersonator = _resolve_actor(
        actor,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=normalized_actor_type,
        impersonated_by_id=impersonated_by_id,
    )

    # ── Correlation ID
    correlation_id = get_correlation_id()
    if correlation_id:
        set_correlation_id(correlation_id)  # ensure it's set for downstream logs

    # ── Request context
    request_ctx = _extract_request_context(request)
    if request is None and correlation_id is None:
        # No request — read from the log context anyway
        pass

    # ── Changed fields
    resolved_changed = changed_fields
    if resolved_changed is None and (before_state is not None or after_state is not None):
        resolved_changed = _compute_changed_fields(before_state, after_state)

    # ── Persist
    audit_row = SecurityAuditLog(
        actor_id=resolved_actor_id,
        actor_email=resolved_actor_email,
        actor_type=normalized_actor_type,
        impersonated_by_id=resolved_impersonator,
        action=validated_action,
        outcome=outcome,
        target_type=validated_target_type,
        target_id=target_id,
        target_display=target_display,
        workspace_id=workspace_id,
        organization_id=organization_id,
        ip_address=request_ctx.get("ip_address"),
        user_agent=request_ctx.get("user_agent"),
        request_method=request_ctx.get("request_method"),
        request_path=request_ctx.get("request_path"),
        correlation_id=correlation_id,
        before_state=before_state,
        after_state=after_state,
        changed_fields=resolved_changed or [],
        notes=notes,
        metadata_json=metadata or {},
    )

    db.add(audit_row)
    db.flush()

    # ── Structured log (INFO — visible in the app's JSON logs)
    logger.info(
        "Audit",
        extra={
            "audit_action": validated_action,
            "audit_outcome": outcome.value,
            "actor_id": str(resolved_actor_id) if resolved_actor_id else None,
            "target_type": validated_target_type,
            "target_id": str(target_id) if target_id else None,
            "correlation_id": correlation_id,
        },
    )

    return audit_row


# ============================================================================
# CORE WRITE — STATE CHANGE
# ============================================================================

def log_state_change(
    db: Session,
    *,
    actor: User | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_type: str = "user",
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    target_display: str | None = None,
    workspace_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    changed_fields: list[str] | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    request: Any | None = None,
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    """
    Convenience wrapper for ``log_action`` when both ``before_state``
    and ``after_state`` are provided. Computes ``changed_fields``
    automatically (unless explicitly provided).
    """
    return log_action(
        db,
        actor=actor,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=actor_type,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        target_display=target_display,
        workspace_id=workspace_id,
        organization_id=organization_id,
        request=request,
        before_state=before_state,
        after_state=after_state,
        changed_fields=changed_fields,
        notes=notes,
        metadata=metadata,
    )


# ============================================================================
# CORE WRITE — INDEPENDENT COMMIT
# ============================================================================

def log_action_independent(
    *,
    actor: User | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_type: str = "user",
    impersonated_by_id: uuid.UUID | None = None,
    action: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    target_display: str | None = None,
    workspace_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    request: Any | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    changed_fields: list[str] | None = None,
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    """
    Write one audit log entry in an **independent session that commits
    immediately**.

    Use sparingly. Reserved for cases where the audit row must persist
    even though the caller's transaction will roll back:

        - Failed logins (before raising AuthenticationError)
        - Denied permission checks (before raising AuthorizationError)
        - Integrity verification failures
        - Tampering / suspicious activity detection

    This function creates a fresh session via ``session_scope()``,
    writes the row, and lets ``session_scope`` commit. The caller's
    session is not touched.

    If the independent session fails for any reason (DB down, etc.),
    the audit write is lost — but the caller's transaction proceeds
    unaffected. That's the trade-off of independence: the audit row
    is best-effort when the caller is failing anyway.

    For the denial/failure path, prefer ``log_denied_action`` — it
    does exactly this and adds the "denied" phrasing to the notes.
    """
    try:
        with session_scope() as independent_db:
            return log_action(
                independent_db,
                actor=actor,
                actor_id=actor_id,
                actor_email=actor_email,
                actor_type=actor_type,
                impersonated_by_id=impersonated_by_id,
                action=action,
                outcome=outcome,
                target_type=target_type,
                target_id=target_id,
                target_display=target_display,
                workspace_id=workspace_id,
                organization_id=organization_id,
                request=request,
                before_state=before_state,
                after_state=after_state,
                changed_fields=changed_fields,
                notes=notes,
                metadata=metadata,
            )
    except Exception as exc:  # noqa: BLE001 — independent audit never blocks caller
        logger.warning(
            "Independent audit write failed",
            extra={
                "audit_action": action,
                "error": str(exc)[:200],
            },
        )
        # Return a non-persisted stub so callers who don't use the
        # result don't crash. Callers who DO use the result must
        # handle the case where .id is None.
        stub = SecurityAuditLog(
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            outcome=outcome,
        )
        return stub


def log_denied_action(
    *,
    actor: User | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    actor_type: str = "user",
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    target_display: str | None = None,
    workspace_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    request: Any | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    """
    Log a **denied** authorization attempt. Writes independently so
    the row persists even though the caller is about to raise.

    The ``action`` should be the action the user *attempted* — e.g.
    ``"evidence.accessed"`` (past tense of attempt = future of the
    base action). ``outcome`` is automatically ``FAILURE``.
    """
    notes = f"DENIED: {reason}" if reason else "DENIED"
    return log_action_independent(
        actor=actor,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=actor_type,
        action=action,
        outcome=AuditOutcome.FAILURE,
        target_type=target_type,
        target_id=target_id,
        target_display=target_display,
        workspace_id=workspace_id,
        organization_id=organization_id,
        request=request,
        notes=notes,
        metadata=metadata,
    )


# ============================================================================
# BULK WRITE
# ============================================================================

def bulk_log(db: Session, events: Iterable[AuditEventInternal]) -> int:
    """
    Write multiple audit events in one round trip.

    Used by retention jobs, batch state transitions, and any other
    case where many audit rows are created together. Each event in
    ``events`` is passed through ``log_action`` — validation is per-
    event, and a bad event raises immediately (partial writes within
    a transaction are automatically rolled back by SQLAlchemy if the
    caller commits a failure).

    Returns
    -------
    int
        Number of rows written.
    """
    count = 0
    for event in events:
        log_action(
            db,
            actor_id=event.actor_id,
            actor_email=event.actor_email,
            actor_type=event.actor_type,
            impersonated_by_id=event.impersonated_by_id,
            action=event.action,
            outcome=event.outcome,
            target_type=event.target_type,
            target_id=event.target_id,
            target_display=event.target_display,
            workspace_id=event.workspace_id,
            organization_id=event.organization_id,
            before_state=event.before_state,
            after_state=event.after_state,
            changed_fields=event.changed_fields,
            notes=event.notes,
            metadata=event.metadata_json,
        )
        count += 1
    return count


# ============================================================================
# CONVENIENCE WRAPPERS — auth events
# ============================================================================

def log_login_success(
    db: Session,
    *,
    user: User,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record a successful login."""
    return log_action(
        db,
        actor=user,
        action=AUDIT_LOGIN_SUCCESS,
        target_type="user",
        target_id=user.id,
        target_display=user.email,
        request=request,
    )


def log_login_failed(
    *,
    email: str,
    request: Any | None = None,
    reason: str | None = None,
    user: User | None = None,
) -> SecurityAuditLog:
    """
    Record a failed login attempt. **Independent commit** — the caller
    is about to raise AuthenticationError, and this row must survive.

    Does not leak ``email`` into ``actor_email`` when ``user`` is None
    (the user doesn't exist — the email was whatever the attacker
    typed). Use ``actor_email=None`` and put the attempted email in
    ``notes`` if it's needed for pattern detection.
    """
    return log_action_independent(
        actor=user,
        actor_email=user.email if user else None,
        action=AUDIT_LOGIN_FAILED,
        outcome=AuditOutcome.FAILURE,
        target_type="user" if user else None,
        target_id=user.id if user else None,
        target_display=None,  # do not leak attempted email in target
        request=request,
        notes=(
            f"Login failed: {reason}" if reason else "Login failed"
        ),
        metadata=(
            {"attempted_email": email.lower()[:320]}
            if user is None
            else None
        ),
    )


def log_logout(
    db: Session,
    *,
    user: User,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record a user logout. If a token blocklist exists, add the
    token's jti here when implementing that feature."""
    return log_action(
        db,
        actor=user,
        action=AUDIT_LOGOUT,
        target_type="user",
        target_id=user.id,
        request=request,
    )


# ============================================================================
# CONVENIENCE WRAPPERS — evidence
# ============================================================================

def log_evidence_accessed(
    db: Session,
    *,
    user: User,
    evidence_id: uuid.UUID,
    case_id: uuid.UUID,
    workspace_id: uuid.UUID,
    request: Any | None = None,
    sensitivity: str | None = None,
) -> SecurityAuditLog:
    """
    Record that a user accessed a piece of evidence.

    Called by the evidence download endpoint. This is one of the most
    frequently audited actions in the platform — evidence access is
    the primary thing compliance teams ask about.
    """
    return log_action(
        db,
        actor=user,
        action=AUDIT_EVIDENCE_ACCESSED,
        target_type="evidence",
        target_id=evidence_id,
        workspace_id=workspace_id,
        request=request,
        metadata=(
            {"case_id": str(case_id), "sensitivity": sensitivity}
            if sensitivity or case_id
            else None
        ),
    )


def log_evidence_uploaded(
    db: Session,
    *,
    user: User,
    evidence_id: uuid.UUID,
    case_id: uuid.UUID,
    workspace_id: uuid.UUID,
    file_name: str | None = None,
    file_size_bytes: int | None = None,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record evidence upload. Fires once per file."""
    return log_action(
        db,
        actor=user,
        action=AUDIT_EVIDENCE_UPLOADED,
        target_type="evidence",
        target_id=evidence_id,
        workspace_id=workspace_id,
        request=request,
        metadata={
            "case_id": str(case_id),
            "file_name": file_name,
            "file_size_bytes": file_size_bytes,
        },
    )


# ============================================================================
# CONVENIENCE WRAPPERS — case
# ============================================================================

def log_case_assigned(
    db: Session,
    *,
    user: User,
    case_id: uuid.UUID,
    case_number: str,
    workspace_id: uuid.UUID,
    assigned_to_id: uuid.UUID,
    previous_assignee_id: uuid.UUID | None = None,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record a case assignment (initial or reassignment)."""
    return log_state_change(
        db,
        actor=user,
        action=AUDIT_CASE_ASSIGNED,
        target_type="case",
        target_id=case_id,
        target_display=case_number,
        workspace_id=workspace_id,
        request=request,
        before_state={"assigned_to_id": str(previous_assignee_id) if previous_assignee_id else None},
        after_state={"assigned_to_id": str(assigned_to_id)},
    )


def log_case_closed(
    db: Session,
    *,
    user: User,
    case_id: uuid.UUID,
    case_number: str,
    workspace_id: uuid.UUID,
    previous_status: str,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record a case closure."""
    return log_state_change(
        db,
        actor=user,
        action=AUDIT_CASE_CLOSED,
        target_type="case",
        target_id=case_id,
        target_display=case_number,
        workspace_id=workspace_id,
        request=request,
        before_state={"status": previous_status},
        after_state={"status": "closed"},
    )


# ============================================================================
# CONVENIENCE WRAPPERS — incident
# ============================================================================

def log_incident_severity_changed(
    db: Session,
    *,
    user: User,
    incident_id: uuid.UUID,
    workspace_id: uuid.UUID,
    previous_severity: str,
    new_severity: str,
    reason: str | None = None,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record an incident severity change. High-signal event for
    post-incident review — "when did someone decide this got worse?" """
    return log_state_change(
        db,
        actor=user,
        action=AUDIT_INCIDENT_SEVERITY_CHANGED,
        target_type="incident",
        target_id=incident_id,
        workspace_id=workspace_id,
        request=request,
        before_state={"severity": previous_severity},
        after_state={"severity": new_severity},
        notes=reason,
    )


def log_incident_closed(
    db: Session,
    *,
    user: User,
    incident_id: uuid.UUID,
    workspace_id: uuid.UUID,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record an incident closure."""
    return log_action(
        db,
        actor=user,
        action=AUDIT_INCIDENT_CLOSED,
        target_type="incident",
        target_id=incident_id,
        workspace_id=workspace_id,
        request=request,
    )


# ============================================================================
# CONVENIENCE WRAPPERS — analyst access grants
# ============================================================================

def log_analyst_access_granted(
    db: Session,
    *,
    granted_by: User,
    grantee_user_id: uuid.UUID,
    case_id: uuid.UUID,
    workspace_id: uuid.UUID,
    scope: str,
    purpose: str,
    expires_at: datetime | None = None,
    request: Any | None = None,
) -> SecurityAuditLog:
    """
    Record that a case access grant was issued. This is one of the
    highest-value audit events — every grant is exactly the kind of
    thing a compliance team needs to see ("why did this analyst see
    this client's evidence?").
    """
    return log_action(
        db,
        actor=granted_by,
        action="analyst.access.granted",
        target_type="case",
        target_id=case_id,
        workspace_id=workspace_id,
        request=request,
        after_state={
            "grantee_user_id": str(grantee_user_id),
            "scope": scope,
            "purpose": purpose,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )


def log_analyst_access_revoked(
    db: Session,
    *,
    revoked_by: User,
    grantee_user_id: uuid.UUID,
    case_id: uuid.UUID,
    workspace_id: uuid.UUID,
    reason: str,
    request: Any | None = None,
) -> SecurityAuditLog:
    """Record that a case access grant was revoked."""
    return log_action(
        db,
        actor=revoked_by,
        action="analyst.access.revoked",
        target_type="case",
        target_id=case_id,
        workspace_id=workspace_id,
        request=request,
        before_state={"grantee_user_id": str(grantee_user_id)},
        after_state={"revoked": True, "reason": reason},
    )


# ============================================================================
# READ HELPERS — for admin endpoints
# ============================================================================

def query_audit_logs(
    db: Session,
    *,
    page: PageParams,
    filters: AuditLogFilter,
) -> tuple[list[SecurityAuditLog], int]:
    """
    Query audit logs with filters and pagination. Admin use only —
    access is enforced by ``require_permission("admin:audit_read")``
    at the endpoint.

    Returns ``(rows_on_page, total_count)``.
    """
    stmt = select(SecurityAuditLog)

    if filters.actor_id is not None:
        stmt = stmt.where(SecurityAuditLog.actor_id == filters.actor_id)
    if filters.actor_email is not None:
        stmt = stmt.where(SecurityAuditLog.actor_email == filters.actor_email.lower())
    if filters.actor_type is not None:
        stmt = stmt.where(SecurityAuditLog.actor_type == filters.actor_type)
    if filters.action is not None:
        stmt = stmt.where(SecurityAuditLog.action == filters.action)
    if filters.action_prefix is not None:
        stmt = stmt.where(SecurityAuditLog.action.like(f"{filters.action_prefix}%"))
    if filters.outcome is not None:
        stmt = stmt.where(SecurityAuditLog.outcome == filters.outcome)
    if filters.target_type is not None:
        stmt = stmt.where(SecurityAuditLog.target_type == filters.target_type)
    if filters.target_id is not None:
        stmt = stmt.where(SecurityAuditLog.target_id == filters.target_id)
    if filters.workspace_id is not None:
        stmt = stmt.where(SecurityAuditLog.workspace_id == filters.workspace_id)
    if filters.organization_id is not None:
        stmt = stmt.where(SecurityAuditLog.organization_id == filters.organization_id)
    if filters.correlation_id is not None:
        stmt = stmt.where(SecurityAuditLog.correlation_id == filters.correlation_id)
    if filters.created_after is not None:
        stmt = stmt.where(SecurityAuditLog.created_at >= filters.created_after)
    if filters.created_before is not None:
        stmt = stmt.where(SecurityAuditLog.created_at <= filters.created_before)
    if filters.unrecognized_only:
        # Filter for rows whose action is NOT in the canonical set.
        stmt = stmt.where(SecurityAuditLog.action.notin_(AUDIT_ACTIONS))
    if filters.under_legal_hold:
        now = datetime.now(timezone.utc)
        stmt = stmt.where(
            SecurityAuditLog.legal_hold_until.isnot(None),
            SecurityAuditLog.legal_hold_until > now,
        )

    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    stmt = (
        stmt.order_by(SecurityAuditLog.created_at.desc(), SecurityAuditLog.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )

    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


def compute_stats(
    db: Session,
    *,
    filters: AuditLogFilter,
) -> AuditLogStats:
    """
    Compute aggregate stats over audit logs matching the filter. Used
    by the admin dashboard — counts by actor type, outcome, top actions,
    and time range.
    """
    # Base filtered subquery — reuse the same filter logic
    stmt = select(SecurityAuditLog)
    if filters.actor_id is not None:
        stmt = stmt.where(SecurityAuditLog.actor_id == filters.actor_id)
    if filters.actor_type is not None:
        stmt = stmt.where(SecurityAuditLog.actor_type == filters.actor_type)
    if filters.action_prefix is not None:
        stmt = stmt.where(SecurityAuditLog.action.like(f"{filters.action_prefix}%"))
    if filters.workspace_id is not None:
        stmt = stmt.where(SecurityAuditLog.workspace_id == filters.workspace_id)
    if filters.organization_id is not None:
        stmt = stmt.where(SecurityAuditLog.organization_id == filters.organization_id)
    if filters.created_after is not None:
        stmt = stmt.where(SecurityAuditLog.created_at >= filters.created_after)
    if filters.created_before is not None:
        stmt = stmt.where(SecurityAuditLog.created_at <= filters.created_before)

    subq = stmt.subquery()

    total = db.execute(
        select(func.count()).select_from(subq)
    ).scalar_one()

    by_actor_type = dict(
        db.execute(
            select(subq.c.actor_type, func.count())
            .group_by(subq.c.actor_type)
        ).all()
    )
    by_outcome = dict(
        db.execute(
            select(subq.c.outcome, func.count())
            .group_by(subq.c.outcome)
        ).all()
    )
    top_actions = [
        {"action": a, "count": c}
        for a, c in db.execute(
            select(subq.c.action, func.count().label("c"))
            .group_by(subq.c.action)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]

    failure_count = by_outcome.get(AuditOutcome.FAILURE, 0)
    # Unrecognized = rows whose action is not in the canonical set.
    unrecognized_count = db.execute(
        select(func.count())
        .select_from(subq)
        .where(subq.c.action.notin_(AUDIT_ACTIONS))
    ).scalar_one()

    min_max = db.execute(
        select(func.min(subq.c.created_at), func.max(subq.c.created_at))
    ).one()

    return AuditLogStats(
        total_entries=int(total),
        by_actor_type={k: int(v) for k, v in by_actor_type.items()},
        by_outcome={
            (k.value if hasattr(k, "value") else str(k)): int(v)
            for k, v in by_outcome.items()
        },
        by_action_top=top_actions,
        failure_count=int(failure_count),
        unrecognized_action_count=int(unrecognized_count),
        earliest_created_at=min_max[0],
        latest_created_at=min_max[1],
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Internal DTO
    "AuditEventInternal",
    # Core writers
    "log_action",
    "log_state_change",
    "log_action_independent",
    "log_denied_action",
    "bulk_log",
    # Convenience: auth
    "log_login_success",
    "log_login_failed",
    "log_logout",
    # Convenience: evidence
    "log_evidence_accessed",
    "log_evidence_uploaded",
    # Convenience: case
    "log_case_assigned",
    "log_case_closed",
    # Convenience: incident
    "log_incident_severity_changed",
    "log_incident_closed",
    # Convenience: analyst access
    "log_analyst_access_granted",
    "log_analyst_access_revoked",
    # Read helpers
    "query_audit_logs",
    "compute_stats",
]