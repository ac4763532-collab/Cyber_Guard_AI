"""
CyberGuard AI — Security Audit Log
============================================================================

The ``security_audit_logs`` table: the immutable, append-only record of
every sensitive action in the platform.

Purpose
-------
Answer, months or years later, with certainty:

    "Who accessed this evidence on 2026-03-14 at 14:23 UTC, from which IP,
     as part of which request, and what changed?"

Without a trustworthy audit trail, the platform's claims of "explicit
scoped access" and "full traceability" are marketing. With it, they're
enforced facts.

Design rules
------------
1. **Append-only in spirit.**
   No ``updated_at``, no ``SoftDeleteMixin``. Rows are never modified by
   the application, only hard-deleted by retention after
   ``RETENTION_AUDIT_LOGS_DAYS`` (default 5 years) unless under legal hold.

2. **``actor_email`` denormalized.**
   If a user is deleted (``actor_id`` → SET NULL), the audit row still
   records who did it. The email at the time of the action is preserved
   forever. This makes the audit trail survive GDPR erasure without
   breaking.

3. **``impersonated_by_id`` for super-admin actions.**
   When a Super Admin acts "as" another user (support scenarios), both
   identities are recorded. The ``actor_id`` is the effective user;
   ``impersonated_by_id`` is the true initiator. Prevents "the super
   admin was never here" claims.

4. **Polymorphic target (``target_type`` + ``target_id``).**
   Same pattern as notifications and reports. A single audit table logs
   actions on users, orgs, cases, evidence, sources, payments — everything.

5. **``action`` is a validated string but NOT a strict enum.**
   Length and format are enforced; membership in ``AUDIT_ACTIONS`` is not.
   Why? Because new actions are added faster than migrations. The audit
   log must accept a new action name *immediately* — an audit row that
   fails to write is worse than one with an unrecognized action string.
   The ``AUDIT_ACTIONS`` constant remains the canonical list; a background
   job can flag unknown actions.

6. **``outcome`` uses ``AuditOutcome`` enum.**
   ``success``, ``failure``, ``partial``. Closed, stable set — appropriate
   for enum enforcement.

7. **``before_state`` + ``after_state`` + ``changed_fields`` for state changes.**
   When logging "severity changed from medium to high", the API records
   the full pre/post snapshots. The ``changed_fields`` array is the delta.
   Auditable, replayable, diffable.

8. **``correlation_id`` matches the request's correlation ID.**
   Joining with application logs gives the complete picture — request →
   auth → authorization → DB write → audit → response.

9. **``request_method`` + ``request_path`` captured.**
   Full HTTP context. "What endpoint triggered this?" is in the row.

10. **``workspace_id`` + ``organization_id`` denormalized.**
    Both scopes present, even when ``target_type`` is something else.
    Enables fast "all audit activity in this workspace" queries.

11. **``legal_hold_until``.**
    Independent of the target's legal hold. An audit record can be pinned
    even when its subject is deleted.

12. **``workspace_id`` / ``organization_id`` use ``ON DELETE SET NULL``.**
    If a workspace is deleted, we still want the audit row to say *which*
    workspace it referred to — but the row must survive the deletion.

13. **No free-text ``description`` field.**
    Structured ``action`` + ``before/after`` + ``metadata`` replaces it.
    Free text in audit logs is unsearchable and untrustworthy.

14. **Timezone correctness everywhere.**

Typical audit actions
---------------------
See ``app.core.constants.AUDIT_ACTIONS`` for the full set. Examples:

    auth.login.success             auth.login.failed
    evidence.accessed              evidence.uploaded
    case.assigned                  case.reassigned
    incident.severity.changed      incident.closed
    analyst.verified               analyst.access.granted
    collector.credential.revoked   report.downloaded
    admin.platform_config.changed

Usage
-----
    from app.models import SecurityAuditLog
    from app.models.enums import AuditOutcome

    # Simple action log
    SecurityAuditLog.build(
        workspace_id=ws.id,
        actor_id=user.id,
        actor_email=user.email,
        actor_type="user",
        action="auth.login.success",
        target_type="user",
        target_id=user.id,
        outcome=AuditOutcome.SUCCESS,
        ip_address="203.0.113.42",
        user_agent="Mozilla/5.0 ...",
        correlation_id=get_correlation_id(),
        request_method="POST",
        request_path="/api/v1/auth/login",
    )

    # State-changing action
    SecurityAuditLog.build_state_change(
        workspace_id=ws.id,
        actor_id=admin.id,
        actor_email=admin.email,
        actor_type="user",
        action="incident.severity.changed",
        target_type="incident",
        target_id=incident.id,
        before_state={"severity": "medium"},
        after_state={"severity": "high"},
        outcome=AuditOutcome.SUCCESS,
    )
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.constants import AUDIT_ACTIONS
from app.core.exceptions import ValidationError
from app.db.base import Base, UUIDPrimaryKeyMixin
from app.models.enums import AuditOutcome, enum_column_type


# ── Actor types ────────────────────────────────────────────────────────────
_ACTOR_TYPE_USER = "user"
_ACTOR_TYPE_COLLECTOR = "collector"
_ACTOR_TYPE_SYSTEM = "system"
_ACTOR_TYPE_AGENT = "agent"
_VALID_ACTOR_TYPES = frozenset({
    _ACTOR_TYPE_USER,
    _ACTOR_TYPE_COLLECTOR,
    _ACTOR_TYPE_SYSTEM,
    _ACTOR_TYPE_AGENT,
})

# ── Target types ───────────────────────────────────────────────────────────
#: Valid values for ``target_type``. Matches the entity kinds across the
#: platform. NULL is allowed for actions with no specific target (e.g.
#: "system started").
_VALID_TARGET_TYPES = frozenset({
    "user",
    "organization",
    "workspace",
    "membership",
    "analyst_profile",
    "source",
    "source_credential",
    "collector_credential",
    "enrollment",
    "event",
    "finding",
    "alert",
    "incident",
    "case",
    "case_assignment",
    "case_access_grant",
    "evidence",
    "conversation",
    "message",
    "notification",
    "report",
    "invitation",
    "service_offering",
    "service_purchase",
    "payment_transaction",
    "workspace_membership",
    "audit_log",
})

# ── Limits ─────────────────────────────────────────────────────────────────
_MAX_ACTION_LENGTH = 128
_MAX_ACTOR_TYPE_LENGTH = 16
_MAX_TARGET_TYPE_LENGTH = 32
_MAX_EMAIL_LENGTH = 320
_MAX_IP_ADDRESS_LENGTH = 45
_MAX_USER_AGENT_LENGTH = 512
_MAX_REQUEST_METHOD_LENGTH = 16
_MAX_REQUEST_PATH_LENGTH = 2048
_MAX_CORRELATION_ID_LENGTH = 128
_MAX_NOTES_LENGTH = 5000
_MAX_CHANGED_FIELDS = 50
_MAX_STATE_BYTES = 64 * 1024  # 64 KB cap per state snapshot
_MAX_METADATA_BYTES = 32 * 1024


class SecurityAuditLog(Base, UUIDPrimaryKeyMixin):
    """
    An immutable audit log entry.

    Not a regular model — no TimestampMixin (no ``updated_at``) and no
    SoftDeleteMixin. Rows have only ``created_at``. See module docstring
    for the full rationale.
    """

    __tablename__ = "security_audit_logs"

    __table_args__ = (
        # Actor type must be a known value.
        CheckConstraint(
            "actor_type IN ('user', 'collector', 'system', 'agent')",
            name="actor_type_values",
        ),
        # Target type must be NULL or a known value.
        CheckConstraint(
            "target_type IS NULL OR target_type IN ("
            "'user', 'organization', 'workspace', 'membership', "
            "'analyst_profile', 'source', 'source_credential', "
            "'collector_credential', 'enrollment', 'event', 'finding', "
            "'alert', 'incident', 'case', 'case_assignment', "
            "'case_access_grant', 'evidence', 'conversation', 'message', "
            "'notification', 'report', 'invitation', 'service_offering', "
            "'service_purchase', 'payment_transaction', "
            "'workspace_membership', 'audit_log'"
            ")",
            name="target_type_values",
        ),
        # Action: non-empty, bounded.
        CheckConstraint(
            "char_length(action) > 0 AND char_length(action) <= 128",
            name="action_length",
        ),
        # Primary workspace view: all audit activity in a workspace.
        Index(
            "ix_audit_workspace_created",
            "workspace_id",
            "created_at",
        ),
        # Per-actor query: "what did this user do?"
        Index(
            "ix_audit_actor_created",
            "actor_id",
            "created_at",
        ),
        # Per-action query: "all logins today".
        Index(
            "ix_audit_action_created",
            "action",
            "created_at",
        ),
        # Per-target query: "history of this case".
        Index(
            "ix_audit_target",
            "target_type",
            "target_id",
        ),
        # Correlation join: "everything from this request".
        Index(
            "ix_audit_correlation_id",
            "correlation_id",
        ),
        # Org-scoped query.
        Index(
            "ix_audit_org_created",
            "organization_id",
            "created_at",
        ),
        # Retention sweep: "rows older than X without a legal hold".
        Index(
            "ix_audit_created_hold",
            "created_at",
            "legal_hold_until",
        ),
        # Legal hold lookup.
        Index(
            "ix_audit_legal_hold",
            "legal_hold_until",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Timestamps (created_at only — no updated_at)
    # ────────────────────────────────────────────────────────────────────

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
        comment="When the action occurred. Immutable. No updated_at exists.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Actor (who)
    # ────────────────────────────────────────────────────────────────────

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "ID of the actor. For actor_type=user or super_admin, this is a "
            "users.id. For collector, this is a security_sources.id. For "
            "system/agent, this is NULL."
        ),
    )

    actor_email: Mapped[str | None] = mapped_column(
        String(_MAX_EMAIL_LENGTH),
        nullable=True,
        comment=(
            "Email of the actor at the time of the action. Denormalized so "
            "the audit trail survives user deletion. Never NULL for "
            "actor_type=user."
        ),
    )

    actor_type: Mapped[str] = mapped_column(
        String(_MAX_ACTOR_TYPE_LENGTH),
        nullable=False,
        default=_ACTOR_TYPE_USER,
        server_default=_ACTOR_TYPE_USER,
        index=True,
        comment="user | collector | system | agent.",
    )

    impersonated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "If a super admin was impersonating actor_id, this is their id. "
            "NULL when no impersonation is in effect."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Action (what)
    # ────────────────────────────────────────────────────────────────────

    action: Mapped[str] = mapped_column(
        String(_MAX_ACTION_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Structured action verb. Examples: 'auth.login.success', "
            "'case.assigned', 'incident.severity.changed'. See "
            "app.core.constants.AUDIT_ACTIONS for the canonical list. "
            "Validation accepts any non-empty string ≤ 128 chars."
        ),
    )

    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_column_type(AuditOutcome),
        nullable=False,
        default=AuditOutcome.SUCCESS,
        server_default=AuditOutcome.SUCCESS.value,
        index=True,
        comment="success | failure | partial.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Target (on what)
    # ────────────────────────────────────────────────────────────────────

    target_type: Mapped[str | None] = mapped_column(
        String(_MAX_TARGET_TYPE_LENGTH),
        nullable=True,
        index=True,
        comment="Polymorphic target kind. NULL for actions with no target.",
    )

    target_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        index=True,
        comment="UUID of the target entity. Paired with target_type.",
    )

    target_display: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment=(
            "Human-readable identifier at time of action "
            "(e.g. case number 'CG-2026-001042', user email)."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Tenant scope
    # ────────────────────────────────────────────────────────────────────

    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Tenant scope. SET NULL if the workspace is deleted.",
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Org scope. SET NULL if the organization is deleted.",
    )

    # ────────────────────────────────────────────────────────────────────
    # HTTP / request context
    # ────────────────────────────────────────────────────────────────────

    ip_address: Mapped[str | None] = mapped_column(
        String(_MAX_IP_ADDRESS_LENGTH),
        nullable=True,
        comment="Client IP address (IPv4 or IPv6). NULL for system/agent.",
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(_MAX_USER_AGENT_LENGTH),
        nullable=True,
        comment="User-Agent header. NULL for system/agent.",
    )

    request_method: Mapped[str | None] = mapped_column(
        String(_MAX_REQUEST_METHOD_LENGTH),
        nullable=True,
        comment="HTTP method: GET, POST, PUT, DELETE, PATCH.",
    )

    request_path: Mapped[str | None] = mapped_column(
        String(_MAX_REQUEST_PATH_LENGTH),
        nullable=True,
        comment="Request path (e.g. /api/v1/cases/abc123/evidence).",
    )

    correlation_id: Mapped[str | None] = mapped_column(
        String(_MAX_CORRELATION_ID_LENGTH),
        nullable=True,
        index=True,
        comment=(
            "Matches the correlation ID used in application logs. Enables "
            "joining audit + logs by request."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # State change (for auditable mutations)
    # ────────────────────────────────────────────────────────────────────

    before_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Snapshot of the target's state before the action. NULL for read-only actions.",
    )

    after_state: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Snapshot of the target's state after the action. NULL for read-only actions.",
    )

    changed_fields: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Field names that changed between before_state and after_state. "
            "Computed by the service, not by the model."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Free-form
    # ────────────────────────────────────────────────────────────────────

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional human-readable notes recorded by the actor or service.",
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Additional structured context (agent name, feature flag, etc.).",
    )

    # ────────────────────────────────────────────────────────────────────
    # Legal hold
    # ────────────────────────────────────────────────────────────────────

    legal_hold_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment=(
            "If set and in the future, retention cleanup skips this row. "
            "Independent of the target's own legal hold."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("actor_type")
    def _validate_actor_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="actor_type must be a string",
                code="AUDIT_ACTOR_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_ACTOR_TYPES:
            raise ValidationError(
                message=f"actor_type must be one of {sorted(_VALID_ACTOR_TYPES)}",
                code="AUDIT_ACTOR_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_ACTOR_TYPES),
                },
            )
        return normalized

    @validates("target_type")
    def _validate_target_type(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="target_type must be a string or None",
                code="AUDIT_TARGET_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized not in _VALID_TARGET_TYPES:
            raise ValidationError(
                message=f"target_type must be one of {sorted(_VALID_TARGET_TYPES)}",
                code="AUDIT_TARGET_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_TARGET_TYPES),
                },
            )
        return normalized

    @validates("action")
    def _validate_action(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="action must be a string",
                code="AUDIT_ACTION_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="action must not be empty",
                code="AUDIT_ACTION_EMPTY",
            )
        if len(stripped) > _MAX_ACTION_LENGTH:
            raise ValidationError(
                message=f"action must not exceed {_MAX_ACTION_LENGTH} characters",
                code="AUDIT_ACTION_TOO_LONG",
            )
        return stripped

    @validates("outcome")
    def _validate_outcome(
        self, _key: str, value: AuditOutcome | str
    ) -> AuditOutcome:
        if isinstance(value, AuditOutcome):
            return value
        if isinstance(value, str):
            try:
                return AuditOutcome(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid outcome {value!r}",
                    code="AUDIT_OUTCOME_INVALID",
                    details={"allowed": list(AuditOutcome.values())},
                ) from exc
        raise ValidationError(
            message="outcome must be an AuditOutcome or string",
            code="AUDIT_OUTCOME_INVALID_TYPE",
        )

    @validates("actor_email")
    def _validate_actor_email(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="actor_email must be a string or None",
                code="AUDIT_EMAIL_INVALID_TYPE",
            )
        stripped = value.strip().lower()
        if not stripped:
            return None
        if len(stripped) > _MAX_EMAIL_LENGTH:
            raise ValidationError(
                message=f"actor_email must not exceed {_MAX_EMAIL_LENGTH} characters",
                code="AUDIT_EMAIL_TOO_LONG",
            )
        return stripped

    @validates("changed_fields")
    def _validate_changed_fields(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="changed_fields must be a list of strings",
                code="AUDIT_CHANGED_FIELDS_INVALID_TYPE",
            )
        if len(value) > _MAX_CHANGED_FIELDS:
            raise ValidationError(
                message=f"changed_fields must not exceed {_MAX_CHANGED_FIELDS} items",
                code="AUDIT_CHANGED_FIELDS_TOO_MANY",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each changed field must be a string",
                    code="AUDIT_CHANGED_FIELD_INVALID_TYPE",
                )
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 128:
                raise ValidationError(
                    message="each changed field must not exceed 128 characters",
                    code="AUDIT_CHANGED_FIELD_TOO_LONG",
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        action: str,
        actor_type: str = _ACTOR_TYPE_USER,
        actor_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        impersonated_by_id: uuid.UUID | None = None,
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
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
        legal_hold_until: datetime | None = None,
    ) -> "SecurityAuditLog":
        """
        Construct a read-only-action audit log entry.

        For state-changing actions, prefer ``build_state_change`` which
        also captures ``before_state`` and ``after_state``.
        """
        return cls(
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
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path,
            correlation_id=correlation_id,
            notes=notes,
            metadata_json=metadata or {},
            legal_hold_until=legal_hold_until,
        )

    @classmethod
    def build_state_change(
        cls,
        *,
        action: str,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
        changed_fields: list[str] | None = None,
        actor_type: str = _ACTOR_TYPE_USER,
        actor_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        impersonated_by_id: uuid.UUID | None = None,
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
        notes: str | None = None,
        metadata: dict[str, Any] | None = None,
        legal_hold_until: datetime | None = None,
    ) -> "SecurityAuditLog":
        """
        Construct a state-changing audit entry with full before/after
        snapshots.

        ``changed_fields`` — if not provided, computed from the keys of
        ``before_state`` and ``after_state`` whose values differ. If
        provided, used as-is (useful when the service has custom diff
        logic).
        """
        if changed_fields is None:
            computed: set[str] = set()
            all_keys = set(before_state.keys()) | set(after_state.keys())
            for key in all_keys:
                if before_state.get(key) != after_state.get(key):
                    computed.add(key)
            changed_fields = sorted(computed)

        return cls(
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
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path,
            correlation_id=correlation_id,
            before_state=before_state,
            after_state=after_state,
            changed_fields=changed_fields,
            notes=notes,
            metadata_json=metadata or {},
            legal_hold_until=legal_hold_until,
        )

    # ====================================================================
    # LEGAL HOLD
    # ====================================================================

    def apply_legal_hold(
        self,
        *,
        until: datetime,
        reason: str | None = None,
    ) -> None:
        """
        Apply a legal hold. Note: even this is a modification of the row,
        so the caller must record a *separate* audit entry for this action
        (action='admin.legal_hold.applied'). The audit of the audit.
        """
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        if until <= datetime.now(timezone.utc):
            raise ValidationError(
                message="legal_hold_until must be in the future",
                code="AUDIT_LEGAL_HOLD_IN_PAST",
            )
        self.legal_hold_until = until
        if reason:
            existing_meta = dict(self.metadata_json or {})
            existing_meta["legal_hold_reason"] = reason
            self.metadata_json = existing_meta

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_under_legal_hold(self) -> bool:
        """True if the audit row is currently under legal hold."""
        if self.legal_hold_until is None:
            return False
        hold = self.legal_hold_until
        if hold.tzinfo is None:
            hold = hold.replace(tzinfo=timezone.utc)
        return hold > datetime.now(timezone.utc)

    @property
    def is_success(self) -> bool:
        """True if the outcome is SUCCESS."""
        return self.outcome == AuditOutcome.SUCCESS

    @property
    def is_failure(self) -> bool:
        """True if the outcome is FAILURE."""
        return self.outcome == AuditOutcome.FAILURE

    @property
    def has_state_change(self) -> bool:
        """True if this entry recorded a before/after state change."""
        return self.before_state is not None and self.after_state is not None

    @property
    def has_target(self) -> bool:
        """True if this entry has a resolved target."""
        return self.target_type is not None and self.target_id is not None

    @property
    def was_impersonated(self) -> bool:
        """True if this action was performed by a super admin impersonating."""
        return self.impersonated_by_id is not None

    @property
    def is_recognized_action(self) -> bool:
        """
        True if the action string is in the canonical ``AUDIT_ACTIONS``
        list. Unrecognized actions should still be logged (they may
        indicate new code paths or unsanctioned operations).
        """
        return self.action in AUDIT_ACTIONS

    @property
    def age_seconds(self) -> int:
        """Seconds since the audit entry was written."""
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - created).total_seconds())


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.user import User
#     from app.models.workspace import Workspace
#     from app.models.organization import Organization
#
# class SecurityAuditLog(...):
#     ...
#     actor: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[actor_id]
#     )
#     impersonated_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[impersonated_by_id]
#     )
#     workspace: Mapped["Workspace | None"] = relationship("Workspace")
#     organization: Mapped["Organization | None"] = relationship(
#         "Organization"
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityAuditLog",
    "_ACTOR_TYPE_USER",
    "_ACTOR_TYPE_COLLECTOR",
    "_ACTOR_TYPE_SYSTEM",
    "_ACTOR_TYPE_AGENT",
    "_VALID_ACTOR_TYPES",
    "_VALID_TARGET_TYPES",
    "_MAX_ACTION_LENGTH",
    "_MAX_ACTOR_TYPE_LENGTH",
    "_MAX_TARGET_TYPE_LENGTH",
    "_MAX_EMAIL_LENGTH",
    "_MAX_IP_ADDRESS_LENGTH",
    "_MAX_USER_AGENT_LENGTH",
    "_MAX_REQUEST_METHOD_LENGTH",
    "_MAX_REQUEST_PATH_LENGTH",
    "_MAX_CORRELATION_ID_LENGTH",
    "_MAX_NOTES_LENGTH",
    "_MAX_CHANGED_FIELDS",
    "_MAX_STATE_BYTES",
    "_MAX_METADATA_BYTES",
]