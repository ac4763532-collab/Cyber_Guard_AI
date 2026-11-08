"""
CyberGuard AI — Membership Service
============================================================================

The membership service is the **single most security-critical** business
logic file in the platform. It governs who can join an organization,
who can be promoted, who can be removed, and how these operations are
audited.

Two membership domains
----------------------
    organization_memberships — user ∈ org, with OrganizationRole
    workspace_memberships    — user ∈ workspace, with WorkspaceRole

Every authorization decision reduces to "does this user have an active
membership in the scope that owns this resource, with a role that grants
the required permission?" This service owns the write side of that
question.

Invitation flow
---------------
    1. Admin calls ``create_invitation`` → email sent with a token
    2. Recipient registers (if new) and verifies their email
    3. Recipient calls ``accept_invitation`` with the token
    4. Service:
         - verifies the token hash
         - verifies the accepting user's email matches
         - verifies the accepting user's email is verified
         - creates the membership row
         - optionally creates workspace memberships
         - audits the acceptance
    5. Or ``decline_invitation`` with a reason

Security invariants (the "why" behind the checks)
-------------------------------------------------
The following invariants are enforced here. They are the *reason* this
service exists as its own file — every check is here so no endpoint or
other service can accidentally bypass them:

    INVARIANT 1 — Email binding
        An invitation is for a specific email address. Only a user with
        that email can accept. Prevents "invite forwarded to attacker".

    INVARIANT 2 — Email verification required
        The accepting user must have a verified email. Prevents
        "attacker registers target@example.com before target does".

    INVARIANT 3 — Role ceiling
        An actor cannot invite/promote someone to a role higher than
        their own. Prevents ADMIN inviting a second OWNER without
        owner consent.

    INVARIANT 4 — Cannot exceed own role
        Only an OWNER can grant OWNER. Only ADMIN+ can grant ADMIN.
        Same principle as INVARIANT 3 but for direct role changes.

    INVARIANT 5 — Cannot remove last OWNER
        Prevents organizational lockout. At least one active OWNER
        must exist at all times.

    INVARIANT 6 — Cannot demote last OWNER
        Same as INVARIANT 5, but for role changes rather than removals.

    INVARIANT 7 — Cannot remove/alter self if last OWNER
        Self-demotion and self-removal are allowed for non-last-owners,
        but blocked for the last owner.

    INVARIANT 8 — Cannot remove a superior
        A user cannot remove or demote someone whose role outranks
        theirs. Prevents ADMIN from removing OWNER.

    INVARIANT 9 — One active membership per (user, scope)
        Enforced by the DB partial unique index. This service produces
        clean errors before that constraint fires.

    INVARIANT 10 — Removed members can be re-invited
        Removed membership rows are kept for audit trail, but do not
        block a new invitation. The (user, org) pair is unique only
        when ``removed_at IS NULL``.

Role hierarchies
----------------
Organization (higher = more authority):

    OWNER > ADMIN > SECURITY_MANAGER > ANALYST > EMPLOYEE > VIEWER

Workspace (higher = more authority):

    OWNER > EDITOR > VIEWER

Public API — Invitations
------------------------
    create_invitation(db, *, actor, organization, email, role, ...) → (invitation, plaintext_token)
    accept_invitation(db, *, user, plaintext_token, ...) → OrganizationMembership
    decline_invitation(db, *, user, plaintext_token, reason, ...) → OrganizationInvitation
    revoke_invitation(db, *, actor, invitation, reason, ...) → OrganizationInvitation
    list_pending_invitations(db, *, actor, organization, page) → (list, int)

Public API — Direct membership (no invitation)
----------------------------------------------
    add_member_directly(db, *, actor, organization, user, role, ...) → OrganizationMembership
    add_workspace_member_directly(db, *, actor, workspace, user, role, ...) → WorkspaceMembership

Public API — Role changes
-------------------------
    change_org_role(db, *, actor, membership, new_role, ...) → OrganizationMembership
    change_workspace_role(db, *, actor, membership, new_role, ...) → WorkspaceMembership

Public API — Suspension / removal
---------------------------------
    suspend_org_member(db, *, actor, membership, until, reason, ...) → OrganizationMembership
    unsuspend_org_member(db, *, actor, membership, ...) → OrganizationMembership
    remove_org_member(db, *, actor, membership, reason, ...) → OrganizationMembership
    remove_workspace_member(db, *, actor, membership, reason, ...) → WorkspaceMembership

Public API — Queries
--------------------
    get_active_org_member(db, *, user_id, organization_id) → OrganizationMembership | None
    get_active_workspace_member(db, *, user_id, workspace_id) → WorkspaceMembership | None
    list_org_members(db, *, actor, organization, page, include_removed=False) → (list, int)
    list_workspace_members(db, *, actor, workspace, page, include_removed=False) → (list, int)

Usage
-----
    from app.services import membership_service

    # Admin invites alice@example.com
    invitation, token = membership_service.create_invitation(
        db,
        actor=admin_user,
        organization=org,
        email="alice@example.com",
        role=OrganizationRole.EMPLOYEE,
        personal_message="Welcome to the team!",
    )
    # → send email with `token` (plaintext only appears here)

    # Alice accepts after registering + verifying email
    membership = membership_service.accept_invitation(
        db,
        user=alice_user,
        plaintext_token=token_from_url,
    )
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_ORG_INVITE_MEMBER,
    PERM_ORG_MANAGE_ROLES,
    PERM_ORG_REMOVE_MEMBER,
    PERM_WORKSPACE_UPDATE,
)
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    TenantIsolationError,
    TokenExpiredValidationError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.security import (
    generate_secure_token,
    hash_password,
    verify_password,
)
from app.models.enums import (
    InvitationStatus,
    OrganizationRole,
    WorkspaceRole,
)
from app.models.invitation import OrganizationInvitation
from app.models.membership import (
    OrganizationMembership,
    WorkspaceMembership,
)
from app.models.organization import Organization
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Role hierarchies. Higher number = more authority. Used by every
#: check that compares two roles.
_ORG_ROLE_RANK: dict[OrganizationRole, int] = {
    OrganizationRole.VIEWER: 1,
    OrganizationRole.EMPLOYEE: 2,
    OrganizationRole.ANALYST: 3,
    OrganizationRole.SECURITY_MANAGER: 4,
    OrganizationRole.ADMIN: 5,
    OrganizationRole.OWNER: 6,
}

_WORKSPACE_ROLE_RANK: dict[WorkspaceRole, int] = {
    WorkspaceRole.VIEWER: 1,
    WorkspaceRole.EDITOR: 2,
    WorkspaceRole.OWNER: 3,
}

#: Default invitation TTL (days).
_DEFAULT_INVITATION_TTL_DAYS = 7
_MAX_INVITATION_TTL_DAYS = 30

#: Plaintext token length (bytes) — 32 bytes → ~43 URL-safe chars.
_TOKEN_ENTROPY_BYTES = 32

#: Token prefix length (chars) for log identification.
_TOKEN_PREFIX_LEN = 12

#: Max time a member can be suspended for (days).
_MAX_SUSPENSION_DAYS = 365


# ============================================================================
# INTERNAL HELPERS — role rank and permission
# ============================================================================

def _org_rank(role: OrganizationRole) -> int:
    return _ORG_ROLE_RANK.get(role, 0)


def _ws_rank(role: WorkspaceRole) -> int:
    return _WORKSPACE_ROLE_RANK.get(role, 0)


def _require_actor_outranks(
    *,
    actor_role: OrganizationRole,
    target_role: OrganizationRole,
    action: str,
    allow_equal: bool = False,
) -> None:
    """
    Enforce that ``actor_role`` outranks ``target_role`` (or equals,
    if ``allow_equal``). Raises ``AuthorizationError`` with a specific
    message describing the requirement.

    Used to implement INVARIANT 4 (cannot exceed own role) and
    INVARIANT 8 (cannot remove a superior). The ``action`` string is
    interpolated into the error message so the client sees
    "cannot <action> a user with role X".
    """
    actor_rank = _org_rank(actor_role)
    target_rank = _org_rank(target_role)
    allowed = actor_rank > target_rank or (allow_equal and actor_rank == target_rank)
    if not allowed:
        raise AuthorizationError(
            message=(
                f"You cannot {action} a user with role "
                f"{target_role.value} (your role: {actor_role.value})."
            ),
            code="INSUFFICIENT_ROLE_AUTHORITY",
            details={
                "actor_role": actor_role.value,
                "target_role": target_role.value,
                "action": action,
            },
        )


def _count_active_owners(db: Session, organization_id: uuid.UUID) -> int:
    """
    Count active OWNER memberships in the org. Used by INVARIANT 5
    and INVARIANT 6.
    """
    return int(
        db.execute(
            select(func.count())
            .select_from(OrganizationMembership)
            .where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.OWNER,
                OrganizationMembership.removed_at.is_(None),
                OrganizationMembership.joined_at.isnot(None),
            )
        ).scalar_one()
    )


def _get_actor_org_role(
    db: Session,
    actor: User,
    organization_id: uuid.UUID,
) -> OrganizationRole:
    """
    Return the actor's role in the org, or raise
    ``TenantIsolationError``. Used at the start of every mutation on
    an org member.
    """
    role = authorization.get_user_org_role(db, actor, organization_id)
    if role is None:
        raise TenantIsolationError(
            message="You are not a member of this organization.",
            code="ORGANIZATION_ACCESS_DENIED",
            details={"organization_id": str(organization_id)},
        )
    return role


# ============================================================================
# INTERNAL HELPERS — invitation token format
# ============================================================================

def _build_token_prefix(plaintext_token: str) -> str:
    """
    Return the 12-char prefix (with ``inv-`` scheme). Must match the
    ORM validator's expected format: ``inv-<8 lowercase hex>``.

    We derive the hex from the token's first 8 URL-safe chars, which
    are effectively random. Collisions across prefixes are possible in
    theory but irrelevant — the prefix is only for log/UI identification.
    """
    first = plaintext_token[:8].lower()
    # Ensure hex-only by taking the first 8 chars and falling back to
    # hex-encoding if any character is not hex. Rare but possible
    # since URL-safe base64 includes '-' and '_'.
    import re
    if not re.match(r"^[a-f0-9]{8}$", first):
        # Encode to hex and truncate
        first = plaintext_token.encode("utf-8").hex()[:8]
    return f"inv-{first}"


# ============================================================================
# INVITATIONS — CREATE
# ============================================================================

def create_invitation(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    email: str,
    role: OrganizationRole,
    personal_message: str | None = None,
    workspace_ids: list[uuid.UUID] | None = None,
    ttl_days: int = _DEFAULT_INVITATION_TTL_DAYS,
    request: Any | None = None,
) -> tuple[OrganizationInvitation, str]:
    """
    Create a pending invitation for ``email`` to join ``organization``
    with the given role.

    Returns
    -------
    tuple[OrganizationInvitation, str]
        ``(invitation_row, plaintext_token)``. The **plaintext token is
        shown to the caller exactly once** — it must be placed in the
        invitation email URL. It cannot be retrieved again.

    Security checks
    ---------------
    - Actor has ``PERM_ORG_INVITE_MEMBER`` in the org
    - Actor's role outranks ``role`` (INVARIANT 3 — no upsell)
    - Only OWNER can invite another OWNER
    - Email is not already an active member
    - No pending invitation already exists for this email

    Raises
    ------
    AuthorizationError
        If the actor lacks permission or tries to invite to a higher
        role.
    ConflictError
        If the email is already an active member, or has a pending
        invitation.
    ValidationError
        For invalid inputs (role, ttl, workspace_ids that don't belong
        to the org).
    """
    # ── 1. Actor permission
    authorization.check_permission(
        db, actor, PERM_ORG_INVITE_MEMBER, organization_id=organization.id,
    )
    actor_role = _get_actor_org_role(db, actor, organization.id)

    # ── 2. Role ceiling (INVARIANT 3)
    if role == OrganizationRole.OWNER:
        if actor_role != OrganizationRole.OWNER:
            raise AuthorizationError(
                message="Only an OWNER can invite a new OWNER.",
                code="CANNOT_INVITE_OWNER",
                details={"actor_role": actor_role.value},
            )
    else:
        _require_actor_outranks(
            actor_role=actor_role,
            target_role=role,
            action="invite",
        )

    # ── 3. Already an active member?
    normalized_email = email.strip().lower()
    active_user = db.execute(
        select(User).where(User.email == normalized_email)
    ).scalar_one_or_none()

    if active_user is not None:
        existing_membership = db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id == active_user.id,
                OrganizationMembership.removed_at.is_(None),
            )
        ).scalar_one_or_none()
        if existing_membership is not None:
            raise ConflictError(
                message=(
                    f"{normalized_email} is already an active member of this "
                    f"organization."
                ),
                code="ALREADY_ORG_MEMBER",
                details={"email": normalized_email},
            )

    # ── 4. Pending invitation exists?
    pending = db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.organization_id == organization.id,
            OrganizationInvitation.email == normalized_email,
            OrganizationInvitation.status == InvitationStatus.PENDING,
        )
    ).scalar_one_or_none()
    if pending is not None:
        raise ConflictError(
            message=(
                f"A pending invitation for {normalized_email} already exists."
            ),
            code="INVITATION_PENDING",
            details={
                "email": normalized_email,
                "invitation_id": str(pending.id),
                "expires_at": pending.expires_at.isoformat(),
            },
        )

    # ── 5. Workspace IDs must belong to this org
    ws_uuids: list[uuid.UUID] = []
    if workspace_ids:
        for ws_id in workspace_ids:
            ws = db.get(Workspace, ws_id)
            if ws is None or ws.deleted_at is not None:
                raise ValidationError(
                    message=f"Workspace {ws_id} not found.",
                    code="WORKSPACE_NOT_FOUND",
                )
            if ws.organization_id != organization.id:
                raise ValidationError(
                    message=(
                        f"Workspace {ws_id} does not belong to this "
                        f"organization."
                    ),
                    code="WORKSPACE_NOT_IN_ORG",
                )
            ws_uuids.append(ws_id)

    # ── 6. Validate ttl
    if not (1 <= ttl_days <= _MAX_INVITATION_TTL_DAYS):
        raise ValidationError(
            message=f"ttl_days must be between 1 and {_MAX_INVITATION_TTL_DAYS}.",
            code="INVITATION_TTL_INVALID",
            details={"ttl_days": ttl_days},
        )

    # ── 7. Generate token (plaintext returned to caller; only hash stored)
    plaintext = generate_secure_token(_TOKEN_ENTROPY_BYTES)
    token_hash = hash_password(plaintext)
    token_prefix = _build_token_prefix(plaintext)

    invitation = OrganizationInvitation.build(
        organization_id=organization.id,
        email=normalized_email,
        role=role,
        invited_by_id=actor.id,
        token_hash=token_hash,
        token_prefix=token_prefix,
        ttl_days=ttl_days,
        personal_message=personal_message,
        workspace_ids=ws_uuids,
    )
    db.add(invitation)
    db.flush()

    # ── 8. Audit
    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.invited",
        target_type="invitation",
        target_id=invitation.id,
        target_display=normalized_email,
        organization_id=organization.id,
        request=request,
        metadata={
            "role": role.value,
            "workspace_ids": [str(w) for w in ws_uuids],
            "ttl_days": ttl_days,
            "invitation_prefix": token_prefix,
        },
    )

    logger.info(
        "Invitation created",
        extra={
            "invitation_id": str(invitation.id),
            "organization_id": str(organization.id),
            "target_email": normalized_email,
            "role": role.value,
            "actor_id": str(actor.id),
        },
    )

    return invitation, plaintext


# ============================================================================
# INVITATIONS — ACCEPT
# ============================================================================

def accept_invitation(
    db: Session,
    *,
    user: User,
    plaintext_token: str,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Accept a pending invitation.

    Security checks (in order — the order matters)
    ----------------------------------------------
    1. Lookup by token prefix — no DB scan, no timing leak on bad prefix.
    2. Verify the full token hash (bcrypt — timing-safe).
    3. Verify invitation is still pending (not redeemed/revoked/expired).
    4. Verify accepting user's email matches the invited email (INVARIANT 1).
    5. Verify accepting user's email is verified (INVARIANT 2).
    6. No active membership already exists in the target org (INVARIANT 9).

    Then:
    7. Create OrganizationMembership (active immediately).
    8. Create any workspace memberships the invitation listed.
    9. Mark invitation ACCEPTED.
    10. Audit.

    Raises
    ------
    NotFoundError
        If the token doesn't match any invitation (deliberately not
        distinguishing "token not found" from "wrong prefix" — both
        return the same error).
    TokenExpiredValidationError
        If the invitation has expired.
    AuthorizationError
        If the accepting user's email doesn't match or isn't verified.
    ConflictError
        If the user already has an active membership in the org.
    """
    stripped = plaintext_token.strip()
    if not stripped:
        raise ValidationError(
            message="Invitation token is required.",
            code="INVITATION_TOKEN_REQUIRED",
        )

    # ── 1. Derive prefix and find candidate invitations.
    # Multiple invitations can theoretically share a prefix, so we
    # fetch all with the prefix and verify the hash against each.
    prefix = _build_token_prefix(stripped)
    candidates = db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.token_prefix == prefix,
        )
    ).scalars().all()

    if not candidates:
        raise NotFoundError(
            message="Invitation not found.",
            code="INVITATION_NOT_FOUND",
        )

    # ── 2. Verify hash against candidates
    invitation: OrganizationInvitation | None = None
    for cand in candidates:
        if verify_password(stripped, cand.token_hash):
            invitation = cand
            break

    if invitation is None:
        raise NotFoundError(
            message="Invitation not found.",
            code="INVITATION_NOT_FOUND",
        )

    # ── 3. Status
    if not invitation.is_redeemable:
        if invitation.is_expired:
            raise TokenExpiredValidationError(
                message="Invitation has expired.",
                code="INVITATION_EXPIRED",
                details={
                    "invitation_id": str(invitation.id),
                    "expired_at": invitation.expires_at.isoformat(),
                },
            )
        raise InvalidStateTransitionError(
            message=(
                f"Invitation is no longer redeemable "
                f"(status: {invitation.status.value})."
            ),
            code="INVITATION_NOT_REDEEMABLE",
            details={"status": invitation.status.value},
        )

    # ── 4. Email match (INVARIANT 1)
    if user.email != invitation.email:
        logger.warning(
            "Invitation email mismatch — possible forwarding attack",
            extra={
                "invitation_id": str(invitation.id),
                "invited_email": invitation.email,
                "accepting_email": user.email,
                "user_id": str(user.id),
            },
        )
        raise AuthorizationError(
            message=(
                "This invitation was issued to a different email address. "
                "Sign in with the invited email to accept."
            ),
            code="INVITATION_EMAIL_MISMATCH",
        )

    # ── 5. Email verified (INVARIANT 2)
    if not user.is_email_verified:
        raise AuthorizationError(
            message=(
                "Please verify your email address before accepting the "
                "invitation."
            ),
            code="EMAIL_NOT_VERIFIED",
        )

    # ── 6. Not already a member (INVARIANT 9)
    existing = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == invitation.organization_id,
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            message="You are already an active member of this organization.",
            code="ALREADY_ORG_MEMBER",
            details={"organization_id": str(invitation.organization_id)},
        )

    # ── 7. Create membership (direct — no re-invite dance)
    membership = OrganizationMembership.build_direct(
        user_id=user.id,
        organization_id=invitation.organization_id,
        role=invitation.role,
        invited_by_id=invitation.invited_by_id,
    )
    db.add(membership)
    db.flush()

    # ── 8. Workspace memberships from the invitation
    for ws_id_str in (invitation.workspace_ids or []):
        try:
            ws_id = uuid.UUID(ws_id_str)
        except (ValueError, TypeError):
            continue
        ws = db.get(Workspace, ws_id)
        if ws is None or ws.deleted_at is not None:
            continue
        ws_member = WorkspaceMembership.build_direct(
            user_id=user.id,
            workspace_id=ws.id,
            role=WorkspaceRole.EDITOR,
            invited_by_id=invitation.invited_by_id,
        )
        db.add(ws_member)
    db.flush()

    # ── 9. Mark invitation accepted
    invitation.accept(accepted_by_id=user.id)
    db.flush()

    # ── 10. Audit
    audit_service.log_action(
        db,
        actor=user,
        action="organization.member.accepted",
        target_type="invitation",
        target_id=invitation.id,
        target_display=invitation.email,
        organization_id=invitation.organization_id,
        request=request,
        metadata={
            "role": invitation.role.value,
            "workspace_count": len(invitation.workspace_ids or []),
        },
    )

    logger.info(
        "Invitation accepted",
        extra={
            "invitation_id": str(invitation.id),
            "organization_id": str(invitation.organization_id),
            "user_id": str(user.id),
            "role": invitation.role.value,
        },
    )

    return membership


# ============================================================================
# INVITATIONS — DECLINE / REVOKE
# ============================================================================

def decline_invitation(
    db: Session,
    *,
    user: User,
    plaintext_token: str,
    reason: str | None = None,
    request: Any | None = None,
) -> OrganizationInvitation:
    """
    Decline a pending invitation.

    Same lookup + hash verification as ``accept_invitation``. Only the
    invited email can decline — a forwarded invitation cannot be
    declined on the invitee's behalf.
    """
    invitation = _lookup_invitation_by_token(db, plaintext_token)

    if invitation.email != user.email:
        raise AuthorizationError(
            message="You are not the intended recipient of this invitation.",
            code="INVITATION_EMAIL_MISMATCH",
        )

    if not invitation.is_pending:
        raise InvalidStateTransitionError(
            message=f"Invitation is not pending (status: {invitation.status.value}).",
            code="INVITATION_NOT_PENDING",
        )

    invitation.decline(declined_by_id=user.id, reason=reason)
    db.flush()

    audit_service.log_action(
        db,
        actor=user,
        action="organization.member.declined",
        target_type="invitation",
        target_id=invitation.id,
        target_display=invitation.email,
        organization_id=invitation.organization_id,
        request=request,
        notes=reason,
    )

    return invitation


def revoke_invitation(
    db: Session,
    *,
    actor: User,
    invitation: OrganizationInvitation,
    reason: str,
    request: Any | None = None,
) -> OrganizationInvitation:
    """
    Revoke a pending invitation (admin action).

    Requires ``PERM_ORG_INVITE_MEMBER`` — same permission as creating.
    Revocation is a terminal action; the token can never be redeemed
    again.

    Also checks INVARIANT 4: the actor's role must outrank the role
    the invitation offers (an ADMIN cannot revoke an OWNER invitation).
    """
    authorization.check_permission(
        db,
        actor,
        PERM_ORG_INVITE_MEMBER,
        organization_id=invitation.organization_id,
    )
    actor_role = _get_actor_org_role(db, actor, invitation.organization_id)

    if invitation.role == OrganizationRole.OWNER and actor_role != OrganizationRole.OWNER:
        raise AuthorizationError(
            message="Only an OWNER can revoke an OWNER invitation.",
            code="CANNOT_REVOKE_OWNER_INVITATION",
        )
    if invitation.role != OrganizationRole.OWNER:
        _require_actor_outranks(
            actor_role=actor_role,
            target_role=invitation.role,
            action="revoke invitation to",
            allow_equal=True,
        )

    if not invitation.is_pending:
        raise InvalidStateTransitionError(
            message=f"Only pending invitations can be revoked (status: {invitation.status.value}).",
            code="INVITATION_NOT_PENDING",
        )

    invitation.revoke(revoked_by_id=actor.id, reason=reason)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.invitation_revoked",
        target_type="invitation",
        target_id=invitation.id,
        target_display=invitation.email,
        organization_id=invitation.organization_id,
        request=request,
        notes=reason,
    )

    return invitation


def list_pending_invitations(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    page: PageParams,
) -> tuple[list[OrganizationInvitation], int]:
    """
    List pending invitations for an organization.

    Requires ``PERM_ORG_INVITE_MEMBER`` in the org scope.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_INVITE_MEMBER, organization_id=organization.id,
    )

    stmt = select(OrganizationInvitation).where(
        OrganizationInvitation.organization_id == organization.id,
        OrganizationInvitation.status == InvitationStatus.PENDING,
    )
    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(OrganizationInvitation.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    invitations = list(db.execute(stmt).scalars().all())
    return invitations, int(total)


# ============================================================================
# INTERNAL — invitation lookup shared by accept/decline
# ============================================================================

def _lookup_invitation_by_token(
    db: Session,
    plaintext_token: str,
) -> OrganizationInvitation:
    """
    Look up an invitation by plaintext token. Raises
    ``NotFoundError`` on any failure — the same error for "no such
    prefix" and "hash mismatch" (no timing/response-shape leak).
    """
    stripped = plaintext_token.strip()
    if not stripped:
        raise ValidationError(
            message="Invitation token is required.",
            code="INVITATION_TOKEN_REQUIRED",
        )

    prefix = _build_token_prefix(stripped)
    candidates = db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.token_prefix == prefix,
        )
    ).scalars().all()

    for cand in candidates:
        if verify_password(stripped, cand.token_hash):
            return cand

    raise NotFoundError(
        message="Invitation not found.",
        code="INVITATION_NOT_FOUND",
    )


# ============================================================================
# DIRECT MEMBERSHIP — no invitation
# ============================================================================

def add_member_directly(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    user: User,
    role: OrganizationRole,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Add a user directly to an organization, bypassing the invitation
    flow. Used by:

        - Service/setup scripts (creating the first super admin)
        - Admin bulk-import endpoints (with strong audit trail)
        - Testing fixtures

    Same role-ceiling checks as ``create_invitation``. The target user
    must already exist and have a verified email — we don't silently
    send them a "verify your email" message on the admin's behalf.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_INVITE_MEMBER, organization_id=organization.id,
    )
    actor_role = _get_actor_org_role(db, actor, organization.id)

    if role == OrganizationRole.OWNER and actor_role != OrganizationRole.OWNER:
        raise AuthorizationError(
            message="Only an OWNER can add another OWNER.",
            code="CANNOT_ADD_OWNER",
        )
    if role != OrganizationRole.OWNER:
        _require_actor_outranks(
            actor_role=actor_role, target_role=role, action="add",
        )

    if user.deleted_at is not None:
        raise ValidationError(
            message="Cannot add a deleted user.",
            code="USER_DELETED",
        )
    if not user.is_email_verified:
        raise ValidationError(
            message=(
                "Cannot add a user with an unverified email. The user must "
                "verify their account first."
            ),
            code="USER_EMAIL_NOT_VERIFIED",
        )

    existing = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            message=f"{user.email} is already an active member.",
            code="ALREADY_ORG_MEMBER",
        )

    membership = OrganizationMembership.build_direct(
        user_id=user.id,
        organization_id=organization.id,
        role=role,
        invited_by_id=actor.id,
    )
    db.add(membership)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.added_directly",
        target_type="membership",
        target_id=membership.id,
        target_display=user.email,
        organization_id=organization.id,
        request=request,
        metadata={"role": role.value, "user_id": str(user.id)},
    )

    return membership


def add_workspace_member_directly(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    user: User,
    role: WorkspaceRole,
    request: Any | None = None,
) -> WorkspaceMembership:
    """
    Add a user directly to a workspace.

    Requires ``PERM_WORKSPACE_UPDATE`` in the workspace scope. The
    target user must already be a member of the workspace's parent
    organization (org membership is the outer gate; workspace
    membership is the inner one).
    """
    authorization.check_permission(
        db, actor, PERM_WORKSPACE_UPDATE, workspace_id=workspace.id,
    )

    if workspace.organization_id is not None:
        # Verify the target user is an org member
        org_member = db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == workspace.organization_id,
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.removed_at.is_(None),
            )
        ).scalar_one_or_none()
        if org_member is None:
            raise ValidationError(
                message=(
                    "The user must be an active member of the parent "
                    "organization before joining a workspace within it."
                ),
                code="USER_NOT_ORG_MEMBER",
            )

    existing = db.execute(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            message="User is already a member of this workspace.",
            code="ALREADY_WORKSPACE_MEMBER",
        )

    membership = WorkspaceMembership.build_direct(
        user_id=user.id,
        workspace_id=workspace.id,
        role=role,
        invited_by_id=actor.id,
    )
    db.add(membership)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="workspace.member.added_directly",
        target_type="workspace_membership",
        target_id=membership.id,
        target_display=user.email,
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        request=request,
        metadata={"role": role.value, "user_id": str(user.id)},
    )

    return membership


# ============================================================================
# ROLE CHANGES
# ============================================================================

def change_org_role(
    db: Session,
    *,
    actor: User,
    membership: OrganizationMembership,
    new_role: OrganizationRole,
    reason: str | None = None,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Change an org member's role.

    Requires ``PERM_ORG_MANAGE_ROLES`` — OWNER only.

    Security checks
    ---------------
    - Target membership is active (not removed/suspended)
    - Actor's role outranks both the **current** and **new** role
      (preventing both "demote a superior" and "promote above self")
    - Only OWNER can make someone else OWNER
    - Cannot demote the last OWNER (INVARIANT 6)
    """
    authorization.check_permission(
        db, actor, PERM_ORG_MANAGE_ROLES,
        organization_id=membership.organization_id,
    )
    actor_role = _get_actor_org_role(db, actor, membership.organization_id)

    if not membership.is_active:
        raise InvalidStateTransitionError(
            message="Cannot change the role of an inactive membership.",
            code="MEMBERSHIP_NOT_ACTIVE",
            details={"current_status": _membership_status(membership)},
        )

    if membership.role == new_role:
        return membership  # no-op

    # Only OWNER can promote to OWNER
    if new_role == OrganizationRole.OWNER and actor_role != OrganizationRole.OWNER:
        raise AuthorizationError(
            message="Only an OWNER can promote another member to OWNER.",
            code="CANNOT_PROMOTE_TO_OWNER",
        )

    # Cannot alter a superior
    _require_actor_outranks(
        actor_role=actor_role,
        target_role=membership.role,
        action="change role of",
        allow_equal=True,
    )
    # Cannot promote above own rank
    _require_actor_outranks(
        actor_role=actor_role,
        target_role=new_role,
        action="promote to",
        allow_equal=True,
    )

    # Cannot demote last OWNER (INVARIANT 6)
    if membership.role == OrganizationRole.OWNER and new_role != OrganizationRole.OWNER:
        if _count_active_owners(db, membership.organization_id) <= 1:
            raise InvalidStateTransitionError(
                message=(
                    "Cannot demote the last OWNER. Promote another member "
                    "to OWNER first."
                ),
                code="CANNOT_DEMOTE_LAST_OWNER",
            )

    before = {"role": membership.role.value}
    membership.role = new_role
    db.flush()
    after = {"role": membership.role.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="organization.member.role_changed",
        target_type="membership",
        target_id=membership.id,
        organization_id=membership.organization_id,
        before_state=before,
        after_state=after,
        notes=reason,
        request=request,
    )

    logger.info(
        "Organization member role changed",
        extra={
            "membership_id": str(membership.id),
            "organization_id": str(membership.organization_id),
            "from_role": before["role"],
            "to_role": new_role.value,
            "actor_id": str(actor.id),
        },
    )

    return membership


def change_workspace_role(
    db: Session,
    *,
    actor: User,
    membership: WorkspaceMembership,
    new_role: WorkspaceRole,
    request: Any | None = None,
) -> WorkspaceMembership:
    """
    Change a workspace member's role.

    Requires ``PERM_WORKSPACE_UPDATE`` in the workspace scope.
    """
    authorization.check_permission(
        db, actor, PERM_WORKSPACE_UPDATE, workspace_id=membership.workspace_id,
    )

    if not membership.is_active:
        raise InvalidStateTransitionError(
            message="Cannot change the role of an inactive membership.",
            code="MEMBERSHIP_NOT_ACTIVE",
        )

    if membership.role == new_role:
        return membership

    before = {"role": membership.role.value}
    membership.role = new_role
    db.flush()
    after = {"role": membership.role.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="workspace.member.role_changed",
        target_type="workspace_membership",
        target_id=membership.id,
        workspace_id=membership.workspace_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return membership


# ============================================================================
# SUSPENSION
# ============================================================================

def suspend_org_member(
    db: Session,
    *,
    actor: User,
    membership: OrganizationMembership,
    until: datetime,
    reason: str,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Temporarily suspend an org member.

    Requires ``PERM_ORG_MANAGE_ROLES`` (OWNER only).

    The suspension is **time-bounded** — after ``until``, ``is_suspended``
    returns False automatically, without any background job. This is
    the "pause access during investigation" pattern.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_MANAGE_ROLES,
        organization_id=membership.organization_id,
    )
    actor_role = _get_actor_org_role(db, actor, membership.organization_id)

    if not membership.is_active:
        raise InvalidStateTransitionError(
            message="Cannot suspend an inactive membership.",
            code="MEMBERSHIP_NOT_ACTIVE",
        )

    _require_actor_outranks(
        actor_role=actor_role,
        target_role=membership.role,
        action="suspend",
    )

    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if until <= now:
        raise ValidationError(
            message="Suspension end time must be in the future.",
            code="SUSPENSION_IN_PAST",
        )
    if (until - now).days > _MAX_SUSPENSION_DAYS:
        raise ValidationError(
            message=f"Suspension cannot exceed {_MAX_SUSPENSION_DAYS} days.",
            code="SUSPENSION_TOO_LONG",
        )

    membership.suspended_at = now
    membership.suspended_until = until
    membership.suspension_reason = reason
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.suspended",
        target_type="membership",
        target_id=membership.id,
        organization_id=membership.organization_id,
        request=request,
        notes=reason,
        metadata={"until": until.isoformat()},
    )

    return membership


def unsuspend_org_member(
    db: Session,
    *,
    actor: User,
    membership: OrganizationMembership,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Lift a suspension. Requires ``PERM_ORG_MANAGE_ROLES``.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_MANAGE_ROLES,
        organization_id=membership.organization_id,
    )

    if membership.suspended_at is None:
        return membership  # already not suspended

    membership.suspended_at = None
    membership.suspended_until = None
    membership.suspension_reason = None
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.unsuspended",
        target_type="membership",
        target_id=membership.id,
        organization_id=membership.organization_id,
        request=request,
    )

    return membership


# ============================================================================
# REMOVAL
# ============================================================================

def remove_org_member(
    db: Session,
    *,
    actor: User,
    membership: OrganizationMembership,
    reason: str,
    request: Any | None = None,
) -> OrganizationMembership:
    """
    Soft-remove an org member.

    Requires ``PERM_ORG_REMOVE_MEMBER`` (ADMIN or OWNER).

    Security checks
    ---------------
    - Target is currently active
    - Actor's role outranks target's role (INVARIANT 8)
    - Cannot remove last OWNER (INVARIANT 5)
    - Self-removal is allowed for non-last-owners (a user can leave)

    The row is kept with ``removed_at`` set. Re-inviting the user
    creates a new row — the old one stays for the audit trail.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_REMOVE_MEMBER,
        organization_id=membership.organization_id,
    )
    actor_role = _get_actor_org_role(db, actor, membership.organization_id)

    if not membership.is_active:
        raise InvalidStateTransitionError(
            message="Membership is not active.",
            code="MEMBERSHIP_NOT_ACTIVE",
        )

    # Self-removal (leaving) — allowed for everyone except last OWNER
    is_self = membership.user_id == actor.id
    if not is_self:
        _require_actor_outranks(
            actor_role=actor_role,
            target_role=membership.role,
            action="remove",
        )

    if membership.role == OrganizationRole.OWNER:
        if _count_active_owners(db, membership.organization_id) <= 1:
            raise InvalidStateTransitionError(
                message=(
                    "Cannot remove the last OWNER of an organization. "
                    "Promote another member to OWNER or transfer ownership first."
                ),
                code="CANNOT_REMOVE_LAST_OWNER",
            )

    now = datetime.now(timezone.utc)
    membership.removed_at = now
    membership.removed_by_id = actor.id if not is_self else None
    membership.removal_reason = reason
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="organization.member.removed",
        target_type="membership",
        target_id=membership.id,
        organization_id=membership.organization_id,
        request=request,
        notes=reason,
        metadata={
            "target_user_id": str(membership.user_id),
            "was_self_removal": is_self,
            "role": membership.role.value,
        },
    )

    logger.info(
        "Organization member removed",
        extra={
            "membership_id": str(membership.id),
            "organization_id": str(membership.organization_id),
            "target_user_id": str(membership.user_id),
            "actor_id": str(actor.id),
            "self_removal": is_self,
        },
    )

    return membership


def remove_workspace_member(
    db: Session,
    *,
    actor: User,
    membership: WorkspaceMembership,
    reason: str,
    request: Any | None = None,
) -> WorkspaceMembership:
    """
    Soft-remove a workspace member. Requires ``PERM_WORKSPACE_UPDATE``.
    """
    authorization.check_permission(
        db, actor, PERM_WORKSPACE_UPDATE, workspace_id=membership.workspace_id,
    )

    if not membership.is_active:
        raise InvalidStateTransitionError(
            message="Membership is not active.",
            code="MEMBERSHIP_NOT_ACTIVE",
        )

    now = datetime.now(timezone.utc)
    is_self = membership.user_id == actor.id
    membership.removed_at = now
    membership.removed_by_id = actor.id if not is_self else None
    membership.removal_reason = reason
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="workspace.member.removed",
        target_type="workspace_membership",
        target_id=membership.id,
        workspace_id=membership.workspace_id,
        request=request,
        notes=reason,
    )

    return membership


# ============================================================================
# QUERIES
# ============================================================================

def get_active_org_member(
    db: Session,
    *,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> OrganizationMembership | None:
    """Return the user's active org membership, or None."""
    return db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()


def get_active_workspace_member(
    db: Session,
    *,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID,
) -> WorkspaceMembership | None:
    """Return the user's active workspace membership, or None."""
    return db.execute(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.user_id == user_id,
            WorkspaceMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()


def list_org_members(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    page: PageParams,
    include_removed: bool = False,
) -> tuple[list[OrganizationMembership], int]:
    """
    List org memberships.

    Requires membership in the org (any role). Includes both active
    and removed memberships when ``include_removed=True`` — used by
    admin audit views.
    """
    authorization.require_org_member(db, actor, organization.id)

    stmt = select(OrganizationMembership).where(
        OrganizationMembership.organization_id == organization.id,
    )
    if not include_removed:
        stmt = stmt.where(OrganizationMembership.removed_at.is_(None))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(OrganizationMembership.created_at.asc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


def list_workspace_members(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    page: PageParams,
    include_removed: bool = False,
) -> tuple[list[WorkspaceMembership], int]:
    """List workspace memberships. Requires workspace membership."""
    authorization.require_workspace_member(db, actor, workspace.id)

    stmt = select(WorkspaceMembership).where(
        WorkspaceMembership.workspace_id == workspace.id,
    )
    if not include_removed:
        stmt = stmt.where(WorkspaceMembership.removed_at.is_(None))

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(WorkspaceMembership.created_at.asc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# INTERNAL — membership status string
# ============================================================================

def _membership_status(membership: OrganizationMembership | WorkspaceMembership) -> str:
    """Human-readable status for error messages."""
    if membership.removed_at is not None:
        return "removed"
    if membership.is_suspended:
        return "suspended"
    if membership.joined_at is None:
        return "pending"
    return "active"


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Invitations
    "create_invitation",
    "accept_invitation",
    "decline_invitation",
    "revoke_invitation",
    "list_pending_invitations",
    # Direct membership
    "add_member_directly",
    "add_workspace_member_directly",
    # Role changes
    "change_org_role",
    "change_workspace_role",
    # Suspension
    "suspend_org_member",
    "unsuspend_org_member",
    # Removal
    "remove_org_member",
    "remove_workspace_member",
    # Queries
    "get_active_org_member",
    "get_active_workspace_member",
    "list_org_members",
    "list_workspace_members",
]