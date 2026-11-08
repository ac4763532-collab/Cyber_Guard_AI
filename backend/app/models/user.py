"""
CyberGuard AI — User Model
============================================================================

The ``users`` table: the identity anchor for every person in the platform.

Every other table either references ``users.id`` directly (memberships,
analyst profiles, cases, findings, evidence, audit logs, messages, reports)
or transitively (through memberships, cases, etc.). Get this table right
and the rest of the schema composes cleanly.

Design decisions
----------------
1. **Email is the unique identifier for local login.** Stored normalized
   to lowercase (via ``@validates``) and enforced at the DB layer with a
   ``CHECK (email = lower(email))`` constraint. This is defense in depth:
   if any writer bypasses the ORM, the insert fails loudly instead of
   silently creating a duplicate account.

2. **``password_hash`` is nullable.** OAuth-only accounts (Google sign-in)
   have no local password. Login flows must check ``user.has_password``
   before calling ``verify_password``. The account takeover protection
   here is that an OAuth-only account with ``password_hash = None`` cannot
   be brute-forced — there is nothing to brute force.

3. **``status`` is a database enum, not a boolean ``is_active``.**
   Distinguishing ``pending_verification``, ``active``, ``inactive``, and
   ``suspended`` lets the login flow respond precisely (e.g. "verify your
   email" vs "contact your admin") and lets audit logs record the exact
   state at any point in time.

4. **``email_verified_at`` is a timestamp, not a boolean.**
   A boolean can't answer "was this user verified when the alert at 14:23
   UTC fired?" A timestamp can. Same reasoning for ``password_changed_at``
   and ``last_login_at`` — all timestamps, all timezone-aware, all UTC.

5. **Account lockout lives in the model.** ``failed_login_attempts`` and
   ``locked_until`` are columns, not in-memory state. This means lockout
   survives a service restart, works across multiple API worker processes,
   and is automatically part of every backup.

6. **Soft delete via ``SoftDeleteMixin``.** A soft-deleted user's row stays
   for audit and evidence integrity, but is excluded from queries via the
   service layer. The retention background task hard-deletes soft-deleted
   accounts after ``RETENTION_EVENTS_DAYS``, freeing the email address for
   re-registration.

7. **No relationships in this file yet.** SQLAlchemy resolves
   ``relationship("OrganizationMembership")`` by looking up the class in
   the shared registry. If the class doesn't exist at mapper-configure time,
   the entire ORM crashes. Since the child models haven't been written yet,
   relationships live in their owning model files and will be added back
   here — one per turn — as Files 17+ land.

Example usage
-------------
    from app.core.security import hash_password
    from app.models import User
    from app.models.enums import UserStatus

    user = User(
        email="User@Example.com",          # auto-normalized to "user@example.com"
        password_hash=hash_password("s3cr3t-pa55word"),
        full_name="Priya Sharma",
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import UserStatus, enum_column_type


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A user account.

    Inherits from ``UUIDPrimaryKeyMixin`` (id: UUID), ``TimestampMixin``
    (created_at, updated_at), and ``SoftDeleteMixin`` (deleted_at).
    """

    __tablename__ = "users"

    __table_args__ = (
        # Enforce lowercase at the DB layer. Combined with @validates below,
        # this guarantees normalization regardless of write path.
        CheckConstraint(
            "email = lower(email)",
            name="email_lowercase",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Identity
    # ────────────────────────────────────────────────────────────────────

    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        index=True,
        nullable=False,
        comment="Lowercase-normalized email address. 320 = RFC 5322 max.",
    )

    public_user_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
        comment="Human-readable unique public slug alias (e.g. riya-user-000184).",
    )

    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="individual",
        server_default="individual",
        index=True,
        comment="Primary user persona: 'individual', 'analyst', 'organizer', 'admin'.",
    )

    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="bcrypt hash. NULL for OAuth-only accounts.",
    )

    full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Display name. NULL for OAuth accounts without a name claim.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Status
    # ────────────────────────────────────────────────────────────────────

    status: Mapped[UserStatus] = mapped_column(
        enum_column_type(UserStatus),
        nullable=False,
        default=UserStatus.PENDING_VERIFICATION,
        server_default=UserStatus.PENDING_VERIFICATION.value,
        index=True,
        comment="Account lifecycle state.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Timestamps of significance
    # ────────────────────────────────────────────────────────────────────

    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Set when email verification succeeds. NULL = not yet verified.",
    )

    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Set when password is set or changed. Invalidates old sessions.",
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Updated on each successful login. Used for stale-account cleanup.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Account lockout
    # ────────────────────────────────────────────────────────────────────

    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Consecutive failed login counter. Reset to 0 on success.",
    )

    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="If set and in the future, all logins are refused.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Multi-factor authentication
    # ────────────────────────────────────────────────────────────────────

    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="Whether TOTP MFA is required at login.",
    )

    mfa_secret: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Encrypted TOTP shared secret. NULL when MFA is disabled.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Profile preferences
    # ────────────────────────────────────────────────────────────────────

    preferred_language: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="en",
        server_default="en",
        comment="BCP 47 language tag (e.g. 'en-US').",
    )

    timezone: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="UTC",
        server_default="UTC",
        comment="IANA timezone name (e.g. 'America/New_York').",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("email")
    def _normalize_email(self, _key: str, value: str) -> str:
        """
        Normalize email to lowercase and strip whitespace on assignment.

        Runs for every ORM assignment (constructor, attribute set, bulk
        update via ORM). Raises ``ValidationError`` (not ``ValueError``)
        so the API layer's exception handler turns it into a 422 response
        automatically. If a schema layer already validated, this should
        never fire — it's defense in depth.
        """
        if not isinstance(value, str):
            raise ValidationError(
                message="email must be a string",
                code="USER_EMAIL_INVALID_TYPE",
            )

        normalized = value.strip().lower()

        if not normalized:
            raise ValidationError(
                message="email must not be empty",
                code="USER_EMAIL_EMPTY",
            )

        if len(normalized) > 320:
            raise ValidationError(
                message="email must not exceed 320 characters",
                code="USER_EMAIL_TOO_LONG",
                details={"max_length": 320, "actual_length": len(normalized)},
            )

        # Minimal shape check — full format validation is Pydantic's job.
        if "@" not in normalized:
            raise ValidationError(
                message="email must contain an '@' character",
                code="USER_EMAIL_MALFORMED",
            )

        return normalized

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================
    # These are pure functions of the model's fields. They never hit the
    # database. Safe to use in schemas, templates, and business logic.

    @property
    def is_active(self) -> bool:
        """True if the account is active and not soft-deleted."""
        return self.status == UserStatus.ACTIVE and self.deleted_at is None

    @property
    def is_locked(self) -> bool:
        """
        True if the account is currently locked out.

        The comparison is timezone-aware. If ``locked_until`` is naive
        (should never happen with this schema), it's treated as UTC.
        """
        if self.locked_until is None:
            return False
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return locked_until > datetime.now(timezone.utc)

    @property
    def is_email_verified(self) -> bool:
        """True if email verification has completed."""
        return self.email_verified_at is not None

    @property
    def has_password(self) -> bool:
        """
        True if the account has a local password set.

        ``False`` means OAuth-only — login must go through the linked
        OAuth provider, not through the password field.
        """
        return self.password_hash is not None


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# Do not uncomment these until the referenced model file exists AND has been
# imported by app/models/__init__.py. SQLAlchemy resolves the string name at
# mapper-configure time, which happens on first query — not on class
# definition. This file is the single place where User's forward relationships
# are declared; child models declare back_populates="<name>" in their own file.
#
# Each relationship will be delivered here as a commented-out block, and you
# will uncomment it when I tell you (once the child model is saved).
#
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.membership import (
#         OrganizationMembership,
#         WorkspaceMembership,
#     )
#     from app.models.analyst import AnalystProfile
#     from app.models.case import CaseAssignment, CaseAccessGrant
#     from app.models.notification import Notification
#     from app.models.audit import SecurityAuditLog
#
# class User(...):
#     ...  # columns + validators + properties above
#
#     # ─── Organization & workspace memberships ───────────────────────
#     organization_memberships: Mapped[list["OrganizationMembership"]] = relationship(
#         "OrganizationMembership",
#         back_populates="user",
#         cascade="all, delete-orphan",
#     )
#
#     workspace_memberships: Mapped[list["WorkspaceMembership"]] = relationship(
#         "WorkspaceMembership",
#         back_populates="user",
#         cascade="all, delete-orphan",
#     )
#
#     # ─── Analyst profile (optional — user may not be an analyst) ────
#     analyst_profile: Mapped["AnalystProfile | None"] = relationship(
#         "AnalystProfile",
#         back_populates="user",
#         uselist=False,
#     )
#
#     # ─── Case assignments (as assignee) ─────────────────────────────
#     case_assignments: Mapped[list["CaseAssignment"]] = relationship(
#         "CaseAssignment",
#         back_populates="analyst",
#         foreign_keys="CaseAssignment.analyst_id",
#     )
#
#     # ─── Evidence access grants ─────────────────────────────────────
#     case_access_grants: Mapped[list["CaseAccessGrant"]] = relationship(
#         "CaseAccessGrant",
#         back_populates="grantee",
#         foreign_keys="CaseAccessGrant.grantee_id",
#     )
#
#     # ─── Notifications ──────────────────────────────────────────────
#     notifications: Mapped[list["Notification"]] = relationship(
#         "Notification",
#         back_populates="user",
#         cascade="all, delete-orphan",
#     )
#
#     # ─── Audit logs (as actor) ──────────────────────────────────────
#     audit_logs: Mapped[list["SecurityAuditLog"]] = relationship(
#         "SecurityAuditLog",
#         back_populates="actor",
#         foreign_keys="SecurityAuditLog.actor_id",
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["User"]