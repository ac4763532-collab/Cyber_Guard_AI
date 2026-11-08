"""
CyberGuard AI — Organization Invitations
============================================================================

The ``organization_invitations`` table: the **only legitimate path** to
add a member to an organization (except the founding owner, who is added
automatically at org creation).

A leaked invitation token grants the ability to join an organization with
a specific role. This table is designed to minimize the blast radius of
that leak and to make every invitation auditable.

Threat model
------------
    Stolen token replayed later         — TTL enforced (default 7 days)
    Stolen token used by different email — Email binding enforced
    Email spoofed at acceptance          — Email verification required
    Admin invite spam                    — Partial unique index prevents duplicates
    Silent role escalation               — Role frozen at invite time
    Inviter later demoted                — Permission checked at send time
    Compromised token still active       — Explicit revocation with audit
    Replay after org archived            — Org status checked by service

Design decisions
----------------
1. **Only the token hash is stored.**
   Same pattern as enrollment tokens (File 22). The plaintext token goes
   in the invitation email URL. If the DB leaks, no live invitations exist.

2. **Email bound to the invitation.**
   The invite is for a specific email. Only that email can accept. This
   is the only way to prevent "invite forwarded to attacker" attacks.

3. **Email verification required at acceptance.**
   A user can register with any email; we require that they prove
   ownership of the invited email before accepting. Otherwise an attacker
   who knows the target email could pre-register with it and hijack the
   invite.

4. **Default TTL is 7 days.**
   Configurable per-invitation via ``expires_at`` override. Long enough
   for the recipient to see the email; short enough that old invites
   don't linger.

5. **Role is frozen at invite time.**
   The inviter chose the role when sending. The recipient accepts that
   role or declines. Prevents "invite as Employee, accept as Admin" bugs.

6. **Inviter permissions checked at send time, not accept time.**
   The audit trail records the inviter; if a revoked invitation is
   desired, admins explicitly revoke it.

7. **Partial unique index prevents duplicates.**
   One active invitation per (org, email). A second attempt fails at DB
   level; service converts to a friendly error.

8. **Workspace memberships can be included.**
   ``workspace_ids`` JSONB — optional list of workspaces the invitee
   should also be added to upon acceptance. Enables "invite alice as
   Employee and add her to the Finance workspace" in one step.

9. **Email normalization.**
   Lowercased at model level + CHECK constraint at DB level.

10. **Three terminal states tracked separately.**
    - ``accepted_at`` — invitation succeeded; user joined
    - ``declined_at`` — user explicitly declined
    - ``revoked_at`` — admin cancelled the invite
    Each has its own actor, timestamp, and optional reason.

11. **``accepted_user_id`` may differ from the invite email's owner.**
    Records the actual user who accepted. Email verification prevents
    hijacking, so this is almost always the invited person.

12. **``status`` stored for indexing.**
    Derived from timestamps but stored to make "list my pending invitations"
    fast without ORM-level computation. Kept in sync by lifecycle methods.

13. **``personal_message`` for context.**
    Optional free text from the inviter. Shown in the invitation email.

14. **No ``SoftDeleteMixin``.**
    Invitations have explicit terminal states. A "deleted" invitation is
    meaningless — the audit trail must persist.

15. **``token_prefix`` for log identification.**
    First 12 chars, plaintext, format ``inv-<8 hex>``. Enables tracing
    "invitation ``inv-a1b2c3d4`` was accepted by alice@example.com".

16. **Timezone correctness everywhere.**

Lifecycle
---------
    PENDING  (created)
        ├── accepted_at set   → ACCEPTED  (terminal, success)
        ├── declined_at set   → DECLINED  (terminal, failure)
        ├── revoked_at set    → REVOKED   (terminal, admin action)
        └── expires_at passes → EXPIRED   (terminal, timeout)

Usage
-----
    from app.core.security import generate_secure_token, hash_password
    from app.models import OrganizationInvitation
    from app.models.enums import OrganizationRole

    # Admin sends an invitation
    plaintext = generate_secure_token(32)  # ~43 chars URL-safe
    invitation = OrganizationInvitation.build(
        organization_id=org.id,
        email="alice@example.com",
        role=OrganizationRole.EMPLOYEE,
        invited_by_id=admin.id,
        token_hash=hash_password(plaintext),
        token_prefix=f"inv-{plaintext[:8].lower()}",
        ttl_days=7,
        personal_message="Welcome to the team!",
        workspace_ids=[finance_ws.id],
    )
    db.add(invitation)
    db.commit()
    # ... send email with URL: {FRONTEND}/invite/accept?token={plaintext}

    # Alice clicks the link
    if not invitation.is_redeemable:
        raise ValueError("Invitation is no longer valid")
    if invitation.email != alice_user.email:
        raise ValueError("Email mismatch")
    if alice_user.email_verified_at is None:
        raise ValueError("Please verify your email first")

    if verify_password(presented_token, invitation.token_hash):
        invitation.accept(accepted_by_id=alice_user.id)
        db.commit()
        # Service creates OrganizationMembership + WorkspaceMembership rows
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

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

from app.core.exceptions import (
    InvalidStateTransitionError,
    ValidationError,
)
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    InvitationStatus,
    OrganizationRole,
    enum_column_type,
)


# ── Constants ──────────────────────────────────────────────────────────────
_TOKEN_PREFIX_PATTERN = re.compile(r"^inv-[a-f0-9]{8}$")

#: Default TTL for an invitation. Can be overridden per-invitation.
_DEFAULT_TTL_DAYS = 7

#: Absolute maximum TTL — prevents "lifetime invitations" from being created
#: accidentally. If a longer window is truly needed, extend this constant.
_MAX_TTL_DAYS = 30

_MAX_EMAIL_LENGTH = 320
_MAX_TOKEN_PREFIX_LENGTH = 12
_MAX_PERSONAL_MESSAGE_LENGTH = 1000
_MAX_REVOCATION_REASON_LENGTH = 500
_MAX_DECLINE_REASON_LENGTH = 500
_MAX_WORKSPACE_IDS = 20

#: Status values mirrored in the CHECK constraint.
_STATUS_PENDING = "pending"
_STATUS_ACCEPTED = "accepted"
_STATUS_DECLINED = "declined"
_STATUS_REVOKED = "revoked"
_STATUS_EXPIRED = "expired"
_VALID_STATUSES = frozenset({
    _STATUS_PENDING,
    _STATUS_ACCEPTED,
    _STATUS_DECLINED,
    _STATUS_REVOKED,
    _STATUS_EXPIRED,
})


class OrganizationInvitation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A pending invitation for a user to join an organization with a specific
    role.

    See the module docstring for the full lifecycle and threat model.
    """

    __tablename__ = "organization_invitations"

    __table_args__ = (
        # Token prefix format
        CheckConstraint(
            r"token_prefix ~ '^inv-[a-f0-9]{8}$'",
            name="token_prefix_format",
        ),
        # Email must be lowercase
        CheckConstraint(
            "email = lower(email)",
            name="email_lowercase",
        ),
        # Status must be one of the documented values
        CheckConstraint(
            "status IN ('pending', 'accepted', 'declined', 'revoked', 'expired')",
            name="status_values",
        ),
        # Terminal state timestamps must be consistent with status
        CheckConstraint(
            "status <> 'accepted' OR accepted_at IS NOT NULL",
            name="accepted_requires_timestamp",
        ),
        CheckConstraint(
            "status <> 'declined' OR declined_at IS NOT NULL",
            name="declined_requires_timestamp",
        ),
        CheckConstraint(
            "status <> 'revoked' OR revoked_at IS NOT NULL",
            name="revoked_requires_timestamp",
        ),
        CheckConstraint(
            "status <> 'expired' OR expires_at <= now()",
            name="expired_requires_past_expiry",
        ),
        # Expiry must be after creation
        CheckConstraint(
            "expires_at > created_at",
            name="expires_after_created",
        ),
        # At most one active invitation per (org, email).
        # Pending is the only non-terminal state.
        Index(
            "uq_invitation_active_per_email",
            "organization_id",
            "email",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        # Fast lookup by token prefix (during acceptance flow)
        Index(
            "ix_invitations_token_prefix",
            "token_prefix",
        ),
        # Org's pending invitations
        Index(
            "ix_invitations_org_status_created",
            "organization_id",
            "status",
            "created_at",
        ),
        # Lookup: what invitations have been sent to this email?
        Index(
            "ix_invitations_email_status",
            "email",
            "status",
        ),
        # Lookup: what invitations has this admin sent?
        Index(
            "ix_invitations_invited_by_created",
            "invited_by_id",
            "created_at",
        ),
        # Expiry sweep query
        Index(
            "ix_invitations_expires_at_status",
            "expires_at",
            "status",
        ),
    )

    # ─── Bindings ───────────────────────────────────────────────────────
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Organization being invited to. CASCADE on org delete.",
    )

    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Admin who sent the invitation. SET NULL after hard-delete.",
    )

    # ─── Target ─────────────────────────────────────────────────────────
    email: Mapped[str] = mapped_column(
        String(_MAX_EMAIL_LENGTH),
        nullable=False,
        index=True,
        comment="Invited email address. Lowercased. Only this email can accept.",
    )

    role: Mapped[OrganizationRole] = mapped_column(
        enum_column_type(OrganizationRole),
        nullable=False,
        index=True,
        comment="Role the invitee will receive upon acceptance. Frozen at invite time.",
    )

    # ─── Token ──────────────────────────────────────────────────────────
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt hash of the plaintext invitation token. Never the plaintext.",
    )

    token_prefix: Mapped[str] = mapped_column(
        String(_MAX_TOKEN_PREFIX_LENGTH),
        nullable=False,
        index=True,
        comment="First 12 chars of the token (e.g. 'inv-a1b2c3d4'), plaintext, for logs.",
    )

    # ─── Optional extras ────────────────────────────────────────────────
    personal_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional message from the inviter, shown in the invitation email.",
    )

    workspace_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Optional list of workspace UUIDs (as strings) to also add the "
            "invitee to upon acceptance. Enables one-step org + workspace "
            "invitations."
        ),
    )

    # ─── Lifecycle ──────────────────────────────────────────────────────
    status: Mapped[InvitationStatus] = mapped_column(
        enum_column_type(InvitationStatus),
        nullable=False,
        default=InvitationStatus.PENDING,
        server_default=InvitationStatus.PENDING.value,
        index=True,
        comment="Derived from terminal-state timestamps. Stored for indexing.",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Server-computed TTL boundary (created_at + ttl_days).",
    )

    # ─── Acceptance ─────────────────────────────────────────────────────
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    accepted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment=(
            "User who accepted. Must be the owner of ``email``. FK to the "
            "resulting User record, which may have been created during "
            "acceptance if the invitee was not yet registered."
        ),
    )

    # ─── Decline ────────────────────────────────────────────────────────
    declined_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    declined_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    decline_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional reason from the decliner, shown to the inviter.",
    )

    # ─── Revocation ─────────────────────────────────────────────────────
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    revocation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason recorded when an admin revoked the invitation.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("email")
    def _validate_email(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="email must be a string",
                code="INVITATION_EMAIL_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not normalized:
            raise ValidationError(
                message="email must not be empty",
                code="INVITATION_EMAIL_EMPTY",
            )
        if len(normalized) > _MAX_EMAIL_LENGTH:
            raise ValidationError(
                message=f"email must not exceed {_MAX_EMAIL_LENGTH} characters",
                code="INVITATION_EMAIL_TOO_LONG",
            )
        if "@" not in normalized:
            raise ValidationError(
                message="email must contain an '@' character",
                code="INVITATION_EMAIL_MALFORMED",
            )
        return normalized

    @validates("token_prefix")
    def _validate_token_prefix(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="token_prefix must be a string",
                code="INVITATION_PREFIX_INVALID_TYPE",
            )
        stripped = value.strip().lower()
        if not _TOKEN_PREFIX_PATTERN.match(stripped):
            raise ValidationError(
                message=(
                    "token_prefix must match the format "
                    "'inv-<8 lowercase hex chars>' (e.g. 'inv-a1b2c3d4')"
                ),
                code="INVITATION_PREFIX_INVALID_FORMAT",
                details={"received": stripped},
            )
        return stripped

    @validates("role")
    def _validate_role(
        self, _key: str, value: OrganizationRole | str
    ) -> OrganizationRole:
        if isinstance(value, OrganizationRole):
            return value
        if isinstance(value, str):
            try:
                return OrganizationRole(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid organization role {value!r}",
                    code="INVITATION_ROLE_INVALID",
                    details={"allowed": list(OrganizationRole.values())},
                ) from exc
        raise ValidationError(
            message="role must be an OrganizationRole or string",
            code="INVITATION_ROLE_INVALID_TYPE",
        )

    @validates("status")
    def _validate_status(
        self, _key: str, value: InvitationStatus | str
    ) -> InvitationStatus:
        if isinstance(value, InvitationStatus):
            return value
        if isinstance(value, str):
            try:
                return InvitationStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid invitation status {value!r}",
                    code="INVITATION_STATUS_INVALID",
                    details={"allowed": list(InvitationStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be an InvitationStatus or string",
            code="INVITATION_STATUS_INVALID_TYPE",
        )

    @validates("personal_message")
    def _validate_personal_message(
        self, _key: str, value: str | None
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="personal_message must be a string or None",
                code="INVITATION_MESSAGE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_PERSONAL_MESSAGE_LENGTH:
            raise ValidationError(
                message=(
                    f"personal_message must not exceed "
                    f"{_MAX_PERSONAL_MESSAGE_LENGTH} characters"
                ),
                code="INVITATION_MESSAGE_TOO_LONG",
            )
        return stripped

    @validates("workspace_ids")
    def _validate_workspace_ids(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="workspace_ids must be a list of strings",
                code="INVITATION_WORKSPACE_IDS_INVALID_TYPE",
            )
        if len(value) > _MAX_WORKSPACE_IDS:
            raise ValidationError(
                message=(
                    f"workspace_ids must not exceed "
                    f"{_MAX_WORKSPACE_IDS} items"
                ),
                code="INVITATION_WORKSPACE_IDS_TOO_MANY",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each workspace_id must be a string",
                    code="INVITATION_WORKSPACE_ID_INVALID_TYPE",
                )
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("revocation_reason", "decline_reason")
    def _validate_reason(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string or None",
                code="INVITATION_REASON_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        max_len = (
            _MAX_REVOCATION_REASON_LENGTH
            if key == "revocation_reason"
            else _MAX_DECLINE_REASON_LENGTH
        )
        if len(stripped) > max_len:
            raise ValidationError(
                message=f"{key} must not exceed {max_len} characters",
                code="INVITATION_REASON_TOO_LONG",
            )
        return stripped

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        organization_id: uuid.UUID,
        email: str,
        role: OrganizationRole,
        invited_by_id: uuid.UUID,
        token_hash: str,
        token_prefix: str,
        ttl_days: int = _DEFAULT_TTL_DAYS,
        personal_message: str | None = None,
        workspace_ids: list[uuid.UUID] | None = None,
    ) -> "OrganizationInvitation":
        """
        Construct a new invitation in the PENDING state.

        The caller is responsible for:

            - generating the plaintext token via ``generate_secure_token``
            - hashing it via ``hash_password``
            - passing the hash and prefix
            - composing the acceptance URL with the plaintext token
            - sending the email

        ``workspace_ids`` are stored as strings (UUIDs serialized) for JSONB.
        """
        if ttl_days <= 0:
            raise ValidationError(
                message="ttl_days must be positive",
                code="INVITATION_TTL_INVALID",
                details={"ttl_days": ttl_days},
            )
        if ttl_days > _MAX_TTL_DAYS:
            raise ValidationError(
                message=f"ttl_days must not exceed {_MAX_TTL_DAYS}",
                code="INVITATION_TTL_TOO_LONG",
                details={"ttl_days": ttl_days, "max": _MAX_TTL_DAYS},
            )

        now = datetime.now(timezone.utc)

        return cls(
            organization_id=organization_id,
            invited_by_id=invited_by_id,
            email=email,
            role=role,
            token_hash=token_hash,
            token_prefix=token_prefix,
            personal_message=personal_message,
            workspace_ids=[str(w) for w in (workspace_ids or [])],
            status=InvitationStatus.PENDING,
            expires_at=now + timedelta(days=ttl_days),
        )

    # ====================================================================
    # TERMINAL STATE TRANSITIONS
    # ====================================================================

    def accept(self, *, accepted_by_id: uuid.UUID) -> None:
        """
        Transition to ACCEPTED. Requires the invitation to be redeemable.

        The caller must verify:

            - ``is_redeemable`` is True
            - the accepting user's email matches ``self.email``
            - the accepting user's email is verified

        This method does not perform those checks — it only enforces the
        state machine. Business rules live in ``invitation_service``.
        """
        if not self.is_redeemable:
            raise InvalidStateTransitionError(
                message="Invitation is no longer redeemable",
                code="INVITATION_NOT_REDEEMABLE",
                details={
                    "status": self.status.value,
                    "is_expired": self.is_expired,
                },
            )
        now = datetime.now(timezone.utc)
        self.status = InvitationStatus.ACCEPTED
        self.accepted_at = now
        self.accepted_by_id = accepted_by_id

    def decline(
        self,
        *,
        declined_by_id: uuid.UUID,
        reason: str | None = None,
    ) -> None:
        """Transition to DECLINED."""
        if not self.is_pending:
            raise InvalidStateTransitionError(
                message="Only pending invitations can be declined",
                code="INVITATION_NOT_PENDING",
                details={"status": self.status.value},
            )
        now = datetime.now(timezone.utc)
        self.status = InvitationStatus.DECLINED
        self.declined_at = now
        self.declined_by_id = declined_by_id
        if reason:
            self.decline_reason = reason

    def revoke(
        self,
        *,
        revoked_by_id: uuid.UUID,
        reason: str | None = None,
    ) -> None:
        """Transition to REVOKED (admin action)."""
        if self.status == InvitationStatus.REVOKED:
            return
        if not self.is_pending:
            raise InvalidStateTransitionError(
                message="Only pending invitations can be revoked",
                code="INVITATION_NOT_PENDING",
                details={"status": self.status.value},
            )
        now = datetime.now(timezone.utc)
        self.status = InvitationStatus.REVOKED
        self.revoked_at = now
        self.revoked_by_id = revoked_by_id
        if reason:
            self.revocation_reason = reason

    def mark_expired(self) -> None:
        """
        Transition to EXPIRED. Called by a background job that sweeps
        pending invitations past their ``expires_at``.
        """
        if self.status != InvitationStatus.PENDING:
            return
        if not self.is_expired:
            raise InvalidStateTransitionError(
                message="Cannot mark as expired before expires_at has passed",
                code="INVITATION_NOT_YET_EXPIRED",
                details={"expires_at": self.expires_at.isoformat()},
            )
        self.status = InvitationStatus.EXPIRED

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_pending(self) -> bool:
        """True if the invitation is in the PENDING state."""
        return self.status == InvitationStatus.PENDING

    @property
    def is_accepted(self) -> bool:
        """True if the invitation was accepted."""
        return self.status == InvitationStatus.ACCEPTED

    @property
    def is_declined(self) -> bool:
        """True if the invitation was declined."""
        return self.status == InvitationStatus.DECLINED

    @property
    def is_revoked(self) -> bool:
        """True if the invitation was revoked by an admin."""
        return self.status == InvitationStatus.REVOKED

    @property
    def is_expired(self) -> bool:
        """True if ``expires_at`` has passed (regardless of status)."""
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    @property
    def is_redeemable(self) -> bool:
        """
        The single gate every acceptance check must consult.

        True iff:
          - status is PENDING
          - not expired
        """
        return self.is_pending and not self.is_expired

    @property
    def seconds_until_expiry(self) -> int:
        """
        Seconds remaining before expiry. Negative if already expired.
        Useful for the UI countdown on the invitation page.
        """
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return int((exp - datetime.now(timezone.utc)).total_seconds())

    @property
    def is_terminal(self) -> bool:
        """True if the invitation is in a terminal state."""
        return self.status in (
            InvitationStatus.ACCEPTED,
            InvitationStatus.DECLINED,
            InvitationStatus.REVOKED,
            InvitationStatus.EXPIRED,
        )


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.organization import Organization
#     from app.models.user import User
#
# class OrganizationInvitation(...):
#     ...
#     organization: Mapped["Organization"] = relationship(
#         "Organization", back_populates="invitations"
#     )
#     invited_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[invited_by_id]
#     )
#     accepted_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[accepted_by_id]
#     )
#     declined_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[declined_by_id]
#     )
#     revoked_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[revoked_by_id]
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "OrganizationInvitation",
    "_TOKEN_PREFIX_PATTERN",
    "_DEFAULT_TTL_DAYS",
    "_MAX_TTL_DAYS",
    "_MAX_EMAIL_LENGTH",
    "_MAX_TOKEN_PREFIX_LENGTH",
    "_MAX_PERSONAL_MESSAGE_LENGTH",
    "_MAX_REVOCATION_REASON_LENGTH",
    "_MAX_DECLINE_REASON_LENGTH",
    "_MAX_WORKSPACE_IDS",
    "_STATUS_PENDING",
    "_STATUS_ACCEPTED",
    "_STATUS_DECLINED",
    "_STATUS_REVOKED",
    "_STATUS_EXPIRED",
    "_VALID_STATUSES",
]