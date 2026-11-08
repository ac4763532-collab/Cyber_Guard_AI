"""
CyberGuard AI — Organization and Workspace Memberships
============================================================================

Two tables that encode "who belongs to what, with which role":

    organization_memberships — user ∈ org, with OrganizationRole
    workspace_memberships    — user ∈ workspace, with WorkspaceRole

Every authorization decision in the platform reduces to: "does this user
have an *active* membership in the scope that owns this resource, with a
role that grants the required permission?"

Design decisions
----------------
1. **No SoftDeleteMixin — lifecycle via timestamps.**
   A membership is *removed*, not *deleted*. The row stays for audit even
   after removal. The lifecycle is encoded in:

       invited_at        set when the membership is created (pending)
       joined_at         set when the user accepts / is added directly
       suspended_at      set when temporarily disabled
       suspended_until   set alongside suspended_at; enforced future value
       removed_at        set when the user leaves or is removed

   This is more precise than an enum, and every transition is auditable.

2. **One active/pending membership per (user, scope) — DB-enforced.**
   A partial unique index `WHERE removed_at IS NULL` guarantees this.
   Without it, a user could be added twice with different roles, and
   authorization checks that iterate over "the user's memberships" would
   find conflicting answers. Removed memberships do not count, so
   re-inviting a previously removed member works cleanly.

3. **CASCADE on the parent FKs; SET NULL on the audit FKs.**

       user_id          → users.id        ON DELETE CASCADE
       organization_id  → organizations.id ON DELETE CASCADE
       workspace_id     → workspaces.id   ON DELETE CASCADE
       invited_by_id    → users.id        ON DELETE SET NULL
       removed_by_id    → users.id        ON DELETE SET NULL

   Memberships are join records — they vanish when the parent vanishes
   (after hard delete, which only happens after the retention period).
   Audit FKs go to NULL because the audit log is the source of truth for
   attribution.

4. **Suspension is time-bounded and enforced.**
   ``suspended_until`` must be > ``suspended_at``. Both fields must be
   set together. This makes "temporarily suspend" a first-class concept
   and prevents the "I forgot to unsuspend" bug — after ``suspended_until``,
   ``is_suspended`` automatically returns ``False``.

5. **``removed_at`` implies ``joined_at``.** A ``CHECK`` constraint
   prevents the impossible state "removed but never joined". Catches
   service-layer bugs in the invite flow.

6. **No query methods here.** ``find_active_membership(user_id, org_id, db)``
   lives in ``app/services/authorization.py``. Models are pure data,
   validation, and derived state properties.

7. **Roles are validated against the enum at assignment time.** Passing
   ``"superuser"`` raises a ``ValidationError`` before the flush, not a
   cryptic integrity error from the DB.

Usage
-----
    from datetime import datetime, timedelta, timezone
    from app.models import OrganizationMembership, WorkspaceMembership
    from app.models.enums import OrganizationRole, WorkspaceRole

    # Invite a new employee (pending until they accept)
    membership = OrganizationMembership.build_invited(
        user_id=user.id,
        organization_id=org.id,
        role=OrganizationRole.EMPLOYEE,
        invited_by_id=admin.id,
    )

    # Add the workspace owner directly (active immediately)
    owner_ws = WorkspaceMembership.build_direct(
        user_id=user.id,
        workspace_id=workspace.id,
        role=WorkspaceRole.OWNER,
        invited_by_id=admin.id,
    )

    # Temporarily suspend a member during investigation
    membership.suspended_at = datetime.now(timezone.utc)
    membership.suspended_until = datetime.now(timezone.utc) + timedelta(hours=24)
    membership.suspension_reason = "Under investigation"

    # Remove the member
    membership.removed_at = datetime.now(timezone.utc)
    membership.removed_by_id = admin.id
    membership.removal_reason = "Left the company"
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    OrganizationRole,
    WorkspaceRole,
    enum_column_type,
)


# ============================================================================
# ORGANIZATION MEMBERSHIP
# ============================================================================

class OrganizationMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A user's membership in an organization.

    The user is considered an active member of the org iff:

        joined_at IS NOT NULL
        AND removed_at IS NULL
        AND (suspended_until IS NULL OR suspended_until < now())

    Every organization authorization check reduces to this condition plus
    a role-permission lookup.
    """

    __tablename__ = "organization_memberships"

    __table_args__ = (
        # One active or pending membership per (user, organization).
        # Removed memberships do not count — re-invite works cleanly.
        Index(
            "uq_organization_membership_active",
            "user_id",
            "organization_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
        # Cannot be removed without having joined.
        CheckConstraint(
            "removed_at IS NULL OR joined_at IS NOT NULL",
            name="removed_implies_joined",
        ),
        # Suspension fields come in pairs.
        CheckConstraint(
            "(suspended_at IS NULL AND suspended_until IS NULL) OR "
            "(suspended_at IS NOT NULL AND suspended_until IS NOT NULL)",
            name="suspension_pair",
        ),
        # Suspension must be forward-facing in time.
        CheckConstraint(
            "suspended_until IS NULL OR suspended_until > suspended_at",
            name="suspension_window_valid",
        ),
    )

    # ── Identity ────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Member user. CASCADE — membership vanishes when user is hard-deleted.",
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning organization.",
    )

    role: Mapped[OrganizationRole] = mapped_column(
        enum_column_type(OrganizationRole),
        nullable=False,
        index=True,
        comment="Member's role within the organization.",
    )

    # ── Invitation & join ───────────────────────────────────────────────
    invited_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the invitation was created. NULL for direct-add memberships.",
    )

    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who extended the invitation. NULL after that user is hard-deleted.",
    )

    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the membership became active. NULL = pending.",
    )

    # ── Suspension ──────────────────────────────────────────────────────
    suspended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the membership was temporarily suspended.",
    )

    suspended_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the suspension expires. Auto-effective — no cleanup needed.",
    )

    suspension_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text reason shown to the suspended user and in audit log.",
    )

    # ── Removal ─────────────────────────────────────────────────────────
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When the membership ended. NULL = still a member (active or pending).",
    )

    removed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who removed the member (or NULL for voluntary leave).",
    )

    removal_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text reason for removal.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("role")
    def _validate_role(self, _key: str, value: OrganizationRole | str) -> OrganizationRole:
        """
        Accept either an ``OrganizationRole`` member or a valid string
        value. Reject anything else with a clear error.
        """
        if isinstance(value, OrganizationRole):
            return value
        if isinstance(value, str):
            try:
                return OrganizationRole(value)
            except ValueError as exc:
                raise ValidationError(
                    message=(
                        f"Invalid organization role {value!r}. "
                        f"Allowed: {list(OrganizationRole.values())}"
                    ),
                    code="MEMBERSHIP_ORG_ROLE_INVALID",
                    details={
                        "received": value,
                        "allowed": list(OrganizationRole.values()),
                    },
                ) from exc
        raise ValidationError(
            message="role must be an OrganizationRole or its string value",
            code="MEMBERSHIP_ORG_ROLE_INVALID_TYPE",
            details={"received_type": type(value).__name__},
        )

    @validates("suspension_reason", "removal_reason")
    def _validate_reason(self, key: str, value: str | None) -> str | None:
        """Enforce a sane length bound on free-text reasons."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string or None",
                code="MEMBERSHIP_REASON_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > 2000:
            raise ValidationError(
                message=f"{key} must not exceed 2000 characters",
                code="MEMBERSHIP_REASON_TOO_LONG",
                details={"max_length": 2000, "actual_length": len(stripped)},
            )
        return stripped

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @classmethod
    def build_invited(
        cls,
        *,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        role: OrganizationRole,
        invited_by_id: uuid.UUID,
    ) -> "OrganizationMembership":
        """
        Create a membership in the ``pending`` state: ``invited_at`` set,
        ``joined_at`` still NULL. The invitee must accept before becoming
        an active member.
        """
        return cls(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            invited_at=datetime.now(timezone.utc),
            invited_by_id=invited_by_id,
            joined_at=None,
        )

    @classmethod
    def build_direct(
        cls,
        *,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        role: OrganizationRole,
        invited_by_id: uuid.UUID | None = None,
    ) -> "OrganizationMembership":
        """
        Create a membership in the ``active`` state immediately. Used for
        the founding owner when an organization is created, and for
        admin-initiated "add member without invitation" flows.
        """
        now = datetime.now(timezone.utc)
        return cls(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            invited_at=now,
            invited_by_id=invited_by_id,
            joined_at=now,
        )

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_pending(self) -> bool:
        """True if the invite exists but has not yet been accepted."""
        return self.invited_at is not None and self.joined_at is None and self.removed_at is None

    @property
    def is_active(self) -> bool:
        """
        True if the user is an active, non-suspended, non-removed member.

        This is the single condition that every authorization check in
        the platform should consult when asking "is this user a member of
        the organization?".
        """
        return (
            self.joined_at is not None
            and self.removed_at is None
            and not self.is_suspended
        )

    @property
    def is_removed(self) -> bool:
        """True if the membership has ended."""
        return self.removed_at is not None

    @property
    def is_suspended(self) -> bool:
        """
        True if the membership is currently suspended (suspended_until in
        the future). A suspension whose window has expired no longer
        counts.
        """
        if self.suspended_at is None or self.suspended_until is None:
            return False
        until = self.suspended_until
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > datetime.now(timezone.utc)

    @property
    def effective_role(self) -> OrganizationRole | None:
        """
        Return the role if the membership is active, else ``None``.

        Use this rather than ``self.role`` when making authorization
        decisions — a removed or suspended membership's role should not
        grant any permission.
        """
        return self.role if self.is_active else None


# ============================================================================
# WORKSPACE MEMBERSHIP
# ============================================================================

class WorkspaceMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A user's membership in a single workspace.

    Same lifecycle as ``OrganizationMembership`` but scoped to a workspace
    and with ``WorkspaceRole`` as the role.

    Note: membership in a workspace does **not** require membership in the
    owning organization. Cross-org analyst access is a real use case
    (marketplace analysts with scoped case access), and it is enforced by
    the authorization service, not by the DB. This table records the fact
    of membership; the service decides whether that membership is
    legitimate.
    """

    __tablename__ = "workspace_memberships"

    __table_args__ = (
        Index(
            "uq_workspace_membership_active",
            "user_id",
            "workspace_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
        CheckConstraint(
            "removed_at IS NULL OR joined_at IS NOT NULL",
            name="removed_implies_joined",
        ),
        CheckConstraint(
            "(suspended_at IS NULL AND suspended_until IS NULL) OR "
            "(suspended_at IS NOT NULL AND suspended_until IS NOT NULL)",
            name="suspension_pair",
        ),
        CheckConstraint(
            "suspended_until IS NULL OR suspended_until > suspended_at",
            name="suspension_window_valid",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    role: Mapped[WorkspaceRole] = mapped_column(
        enum_column_type(WorkspaceRole),
        nullable=False,
        index=True,
        comment="Member's role within the workspace.",
    )

    invited_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    joined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    suspended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    suspended_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    suspension_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True,
    )
    removed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    removal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Validators (identical semantics to OrganizationMembership) ──────

    @validates("role")
    def _validate_role(self, _key: str, value: WorkspaceRole | str) -> WorkspaceRole:
        if isinstance(value, WorkspaceRole):
            return value
        if isinstance(value, str):
            try:
                return WorkspaceRole(value)
            except ValueError as exc:
                raise ValidationError(
                    message=(
                        f"Invalid workspace role {value!r}. "
                        f"Allowed: {list(WorkspaceRole.values())}"
                    ),
                    code="MEMBERSHIP_WORKSPACE_ROLE_INVALID",
                    details={
                        "received": value,
                        "allowed": list(WorkspaceRole.values()),
                    },
                ) from exc
        raise ValidationError(
            message="role must be a WorkspaceRole or its string value",
            code="MEMBERSHIP_WORKSPACE_ROLE_INVALID_TYPE",
        )

    @validates("suspension_reason", "removal_reason")
    def _validate_reason(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string or None",
                code="MEMBERSHIP_REASON_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > 2000:
            raise ValidationError(
                message=f"{key} must not exceed 2000 characters",
                code="MEMBERSHIP_REASON_TOO_LONG",
            )
        return stripped

    # ── Construction helpers ────────────────────────────────────────────

    @classmethod
    def build_invited(
        cls,
        *,
        user_id: uuid.UUID,
        workspace_id: uuid.UUID,
        role: WorkspaceRole,
        invited_by_id: uuid.UUID,
    ) -> "WorkspaceMembership":
        return cls(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            invited_at=datetime.now(timezone.utc),
            invited_by_id=invited_by_id,
            joined_at=None,
        )

    @classmethod
    def build_direct(
        cls,
        *,
        user_id: uuid.UUID,
        workspace_id: uuid.UUID,
        role: WorkspaceRole,
        invited_by_id: uuid.UUID | None = None,
    ) -> "WorkspaceMembership":
        now = datetime.now(timezone.utc)
        return cls(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            invited_at=now,
            invited_by_id=invited_by_id,
            joined_at=now,
        )

    # ── State properties ────────────────────────────────────────────────

    @property
    def is_pending(self) -> bool:
        return self.invited_at is not None and self.joined_at is None and self.removed_at is None

    @property
    def is_active(self) -> bool:
        return (
            self.joined_at is not None
            and self.removed_at is None
            and not self.is_suspended
        )

    @property
    def is_removed(self) -> bool:
        return self.removed_at is not None

    @property
    def is_suspended(self) -> bool:
        if self.suspended_at is None or self.suspended_until is None:
            return False
        until = self.suspended_until
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > datetime.now(timezone.utc)

    @property
    def effective_role(self) -> WorkspaceRole | None:
        return self.role if self.is_active else None


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# Do not uncomment until referenced models exist and are imported in
# app/models/__init__.py.
#
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.user import User
#     from app.models.organization import Organization
#     from app.models.workspace import Workspace
#
# class OrganizationMembership(...):
#     ...
#     user: Mapped["User"] = relationship(
#         "User",
#         back_populates="organization_memberships",
#         foreign_keys=[user_id],
#     )
#     organization: Mapped["Organization"] = relationship(
#         "Organization",
#         back_populates="memberships",
#     )
#     invited_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[invited_by_id],
#     )
#     removed_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[removed_by_id],
#     )
#
# class WorkspaceMembership(...):
#     ...
#     user: Mapped["User"] = relationship(
#         "User",
#         back_populates="workspace_memberships",
#         foreign_keys=[user_id],
#     )
#     workspace: Mapped["Workspace"] = relationship(
#         "Workspace",
#         back_populates="memberships",
#     )
#     invited_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[invited_by_id],
#     )
#     removed_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[removed_by_id],
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["OrganizationMembership", "WorkspaceMembership"]