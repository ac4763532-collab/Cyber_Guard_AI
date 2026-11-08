"""
CyberGuard AI — Authorization Service
============================================================================

The permission engine. Single source of truth for "can this user do this?".

Every other service calls into this file to answer:
    - Can this user act on this organization?
    - Can this user act on this workspace?
    - Can this user see this case / this evidence / this conversation?
    - Does this user have role X in scope Y?

Design rules
------------
1. **Authorization is a leaf service.**
   This file queries the DB directly (organization_memberships,
   workspace_memberships, case_access_grants, analyst_profiles) and
   does not call any other service. If it called into membership_service
   or case_service, those services would need to call authorization
   for their own permission checks → circular.

2. **Denials always raise.** Use ``check_permission`` (raises on
   failure) or ``has_permission`` (returns bool). Never return None
   to mean "denied" — the caller must see a ``CyberGuardError``
   subclass, or explicitly opt into the boolean variant.

3. **Super admin is an explicit override — not a bypass.**
   ``is_super_admin`` returns True only if the future ``is_super_admin``
   column exists on ``User``. Until then, super-admin actions raise
   ``SUPER_ADMIN_REQUIRED`` from the dependency layer, and this service
   grants no platform-wide permissions. **No one becomes super admin
   by accident.**

4. **Tenant isolation is checked before scope.**
   A user cannot see data belonging to a workspace or organization
   they are not a member of, even with otherwise valid permissions.
   The membership check runs first, so even a compromised permission
   table cannot leak cross-tenant data.

5. **Case access grants are checked after role-based access.**
   A user may have role-based access (assigned analyst), or explicit
   grant-based access (analyst with a scoped grant), or both. Both
   are checked. Role access is coarser; grant access is granular
   (case_read vs evidence_read vs full_case).

6. **Every denial is logged at INFO with structured context.**
   An audit trail of *denied* attempts is often more valuable than
   an audit trail of granted ones. The log includes user_id, permission,
   scope, and result. Failed attempts to escalate privileges are the
   signal security teams look for.

7. **No writes. No commits.**
   Authorization is purely read-only. State changes go through the
   service that owns the resource (case_service, evidence_service, etc.).

8. **Role → permission mapping is a static frozen dict.**
   Not computed, not editable at runtime. When permissions change,
   they change here in code — reviewed by security, deployed with
   the app. This is the security-critical equivalent of "infrastructure
   as code".

Permission matrix
-----------------
The matrix is composed from permission groups::

    _READ           — read-only access to security data
    _WRITE          — create/edit security sources and events
    _ADMIN          — manage users, members, settings in scope
    _OWNER          — full control (delete, transfer, invite)

Org roles::

    OWNER              → _OWNER (all org perms)
    ADMIN              → _ADMIN (all except org:delete, org:manage_roles)
    SECURITY_MANAGER   → _WRITE | _READ (security ops)
    ANALYST            → _READ | case/evidence perms
    EMPLOYEE           → self-service only + read-own
    VIEWER             → _READ only

Workspace roles::

    OWNER              → everything in this workspace
    EDITOR             → create/update within workspace
    VIEWER             → read-only within workspace

Case access grants override role-based scope for the analyst to whom
they are issued, up to the grant's scope::

    CASE_READ           → read case metadata
    EVIDENCE_READ       → + read evidence
    CONVERSATION_READ   → + read conversation
    FULL_CASE           → everything on the case

If a user has no org membership, no workspace membership, and no
case grant on the resource — access is denied, full stop. Admins get
no implicit access to employee evidence.

Usage
-----
    from app.services.authorization import check_permission, has_permission

    # In an endpoint or service:
    check_permission(db, current_user, PERM_CASE_READ, resource=case)

    if not has_permission(db, user, PERM_EVIDENCE_READ, resource=evidence):
        raise AuthorizationError(...)

    # In require_permission (after File 70):
    from app.services.authorization import check_permission
    check_permission(db, current_user, permission)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import (
    ALL_PERMISSIONS,
    PERM_ADMIN_ANALYST_REJECT,
    PERM_ADMIN_ANALYST_VERIFY,
    PERM_ADMIN_AUDIT_READ,
    PERM_ADMIN_EVIDENCE_ACCESS,
    PERM_ADMIN_ORG_SUSPEND,
    PERM_ADMIN_PLATFORM_CONFIG,
    PERM_AI_ANALYST_QUERY,
    PERM_ALERT_ACKNOWLEDGE,
    PERM_ALERT_READ,
    PERM_CASE_ASSIGN,
    PERM_CASE_CLOSE,
    PERM_CASE_READ,
    PERM_CASE_UPDATE,
    PERM_EVENT_INGEST,
    PERM_EVENT_READ,
    PERM_EVIDENCE_DELETE,
    PERM_EVIDENCE_DOWNLOAD,
    PERM_EVIDENCE_READ,
    PERM_EVIDENCE_UPLOAD,
    PERM_FINDING_READ,
    PERM_INCIDENT_ASSIGN,
    PERM_INCIDENT_CLOSE,
    PERM_INCIDENT_CREATE,
    PERM_INCIDENT_READ,
    PERM_INCIDENT_UPDATE,
    PERM_MARKETPLACE_BROWSE,
    PERM_MARKETPLACE_PURCHASE,
    PERM_ORG_CREATE,
    PERM_ORG_DELETE,
    PERM_ORG_INVITE_MEMBER,
    PERM_ORG_MANAGE_ROLES,
    PERM_ORG_READ,
    PERM_ORG_REMOVE_MEMBER,
    PERM_ORG_UPDATE,
    PERM_REPORT_CREATE,
    PERM_REPORT_DOWNLOAD,
    PERM_REPORT_READ,
    PERM_SERVICE_OFFER_CREATE,
    PERM_SERVICE_OFFER_UPDATE,
    PERM_SOURCE_CREATE,
    PERM_SOURCE_DISABLE,
    PERM_SOURCE_ENROLL,
    PERM_SOURCE_READ,
    PERM_SOURCE_REVOKE,
    PERM_SOURCE_UPDATE,
    PERM_USER_DELETE_ANY,
    PERM_USER_READ_ANY,
    PERM_USER_READ_SELF,
    PERM_USER_SUSPEND,
    PERM_USER_UPDATE_ANY,
    PERM_USER_UPDATE_SELF,
    PERM_WORKSPACE_CREATE,
    PERM_WORKSPACE_DELETE,
    PERM_WORKSPACE_READ,
    PERM_WORKSPACE_UPDATE,
)
from app.core.exceptions import (
    AuthorizationError,
    TenantIsolationError,
)
from app.core.logging import get_logger
from app.models.analyst import AnalystProfile
from app.models.case import CaseAccessGrant, SecurityCase
from app.models.enums import (
    AccessGrantScope,
    AnalystVerificationStatus,
    OrganizationRole,
    UserStatus,
    WorkspaceRole,
)
from app.models.evidence import SecurityEvidence
from app.models.membership import (
    OrganizationMembership,
    WorkspaceMembership,
)
from app.models.user import User


logger = get_logger(__name__)


# ============================================================================
# PERMISSION GROUPS
# ============================================================================
# Building blocks for the role matrix. Keep these as frozensets so
# they're immutable at runtime — no accidental mutation via a bug.

#: Read-only access to security data. Given to every role that has
#: any business seeing the workspace at all.
_READ: frozenset[str] = frozenset({
    PERM_ORG_READ,
    PERM_WORKSPACE_READ,
    PERM_SOURCE_READ,
    PERM_EVENT_READ,
    PERM_FINDING_READ,
    PERM_ALERT_READ,
    PERM_INCIDENT_READ,
    PERM_CASE_READ,
    PERM_EVIDENCE_READ,
    PERM_REPORT_READ,
    PERM_MARKETPLACE_BROWSE,
    PERM_AI_ANALYST_QUERY,
})

#: Write access to security operations. Requires read as a baseline.
_WRITE: frozenset[str] = _READ | frozenset({
    PERM_SOURCE_CREATE,
    PERM_SOURCE_UPDATE,
    PERM_SOURCE_DISABLE,
    PERM_SOURCE_ENROLL,
    PERM_SOURCE_REVOKE,
    PERM_INCIDENT_CREATE,
    PERM_INCIDENT_UPDATE,
    PERM_INCIDENT_ASSIGN,
    PERM_INCIDENT_CLOSE,
    PERM_ALERT_ACKNOWLEDGE,
    PERM_CASE_UPDATE,
    PERM_CASE_ASSIGN,
    PERM_CASE_CLOSE,
    PERM_EVIDENCE_UPLOAD,
    PERM_EVIDENCE_DOWNLOAD,
    PERM_EVIDENCE_DELETE,
    PERM_REPORT_CREATE,
    PERM_REPORT_DOWNLOAD,
    PERM_EVENT_INGEST,
    PERM_MARKETPLACE_PURCHASE,
})

#: Administrative access — user/member management in scope. Requires
#: write as a baseline (admins can do everything operators can).
_ADMIN: frozenset[str] = _WRITE | frozenset({
    PERM_ORG_UPDATE,
    PERM_ORG_INVITE_MEMBER,
    PERM_ORG_REMOVE_MEMBER,
    PERM_WORKSPACE_CREATE,
    PERM_WORKSPACE_UPDATE,
    PERM_WORKSPACE_DELETE,
    PERM_USER_READ_ANY,
    PERM_USER_UPDATE_ANY,
    PERM_USER_SUSPEND,
})

#: Owner-level access — destructive/structural actions. Requires
#: admin as a baseline.
_OWNER: frozenset[str] = _ADMIN | frozenset({
    PERM_ORG_DELETE,
    PERM_ORG_MANAGE_ROLES,
    PERM_USER_DELETE_ANY,
})

#: Self-service permissions every authenticated user has on their own
#: profile. Independent of any org/workspace role.
_SELF: frozenset[str] = frozenset({
    PERM_USER_READ_SELF,
    PERM_USER_UPDATE_SELF,
    PERM_WORKSPACE_CREATE,   # anyone can create their own personal workspace
    PERM_SERVICE_OFFER_CREATE,   # any user can become an analyst
    PERM_SERVICE_OFFER_UPDATE,
})


# ============================================================================
# ROLE → PERMISSION MATRIX
# ============================================================================
# These dicts are the actual security policy. Every change here is a
# security review. Frozen so no code path can accidentally grant more.

ORG_ROLE_PERMISSIONS: dict[OrganizationRole, frozenset[str]] = {
    OrganizationRole.OWNER: _OWNER | _SELF,
    OrganizationRole.ADMIN: _ADMIN | _SELF,
    OrganizationRole.SECURITY_MANAGER: _WRITE | _SELF,
    OrganizationRole.ANALYST: _READ | _SELF | frozenset({
        PERM_EVIDENCE_DOWNLOAD,
        PERM_EVIDENCE_UPLOAD,
        PERM_INCIDENT_UPDATE,
        PERM_CASE_UPDATE,
        PERM_REPORT_CREATE,
        PERM_REPORT_DOWNLOAD,
    }),
    OrganizationRole.EMPLOYEE: _READ | _SELF,
    OrganizationRole.VIEWER: _READ,
}

WORKSPACE_ROLE_PERMISSIONS: dict[WorkspaceRole, frozenset[str]] = {
    WorkspaceRole.OWNER: _OWNER | _SELF,
    WorkspaceRole.EDITOR: _WRITE | _SELF,
    WorkspaceRole.VIEWER: _READ,
}


# ============================================================================
# PERMISSION → REQUIRED SCOPE
# ============================================================================
# When the caller checks a permission, this tells us which scope to
# resolve roles for. Two special cases:
#
#   "platform" — requires super admin. No role grants these; only
#                super-admin status does.
#   "self"     — requires only authentication; every active user has
#                these on their own data.

_PERMISSION_SCOPE: dict[str, str] = {}
for _p in _OWNER:
    if _p.startswith("org:"):
        _PERMISSION_SCOPE[_p] = "organization"
_PERMISSION_SCOPE.update({
    # Organization-scoped
    PERM_ORG_READ: "organization",
    PERM_ORG_UPDATE: "organization",
    PERM_ORG_DELETE: "organization",
    PERM_ORG_INVITE_MEMBER: "organization",
    PERM_ORG_REMOVE_MEMBER: "organization",
    PERM_ORG_MANAGE_ROLES: "organization",
    # Workspace-scoped
    PERM_WORKSPACE_READ: "workspace",
    PERM_WORKSPACE_CREATE: "workspace",
    PERM_WORKSPACE_UPDATE: "workspace",
    PERM_WORKSPACE_DELETE: "workspace",
    # Case-scoped (or org, depending on target)
    PERM_CASE_READ: "case",
    PERM_CASE_UPDATE: "case",
    PERM_CASE_ASSIGN: "case",
    PERM_CASE_CLOSE: "case",
    PERM_EVIDENCE_READ: "case",
    PERM_EVIDENCE_DOWNLOAD: "case",
    PERM_EVIDENCE_UPLOAD: "case",
    PERM_EVIDENCE_DELETE: "case",
    # Self-service (requires only authentication)
    PERM_USER_READ_SELF: "self",
    PERM_USER_UPDATE_SELF: "self",
    # Platform (super admin only)
    PERM_ADMIN_ANALYST_VERIFY: "platform",
    PERM_ADMIN_ANALYST_REJECT: "platform",
    PERM_ADMIN_ORG_SUSPEND: "platform",
    PERM_ADMIN_PLATFORM_CONFIG: "platform",
    PERM_ADMIN_AUDIT_READ: "platform",
    PERM_ADMIN_EVIDENCE_ACCESS: "platform",
    # Default for everything else: workspace
})


# ============================================================================
# PUBLIC HELPERS — QUERIES
# ============================================================================

def is_super_admin(user: User) -> bool:
    """
    Return True if the user is a platform super admin.

    Until a dedicated ``is_super_admin`` column exists on ``User``,
    this returns False for every user — super admin operations are
    blocked at the ``get_current_super_admin`` dependency level.

    When the column is added (via migration), this function is the
    single place that changes.
    """
    return bool(getattr(user, "is_super_admin", False))


def get_user_org_role(
    db: Session,
    user: User,
    organization_id: uuid.UUID,
) -> OrganizationRole | None:
    """
    Return the user's active role in the given organization, or None
    if they are not an active member.

    "Active" = joined, not removed, not suspended.
    """
    membership = db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()

    if membership is None or not membership.is_active:
        return None
    return membership.role


def get_user_workspace_role(
    db: Session,
    user: User,
    workspace_id: uuid.UUID,
) -> WorkspaceRole | None:
    """Return the user's active role in the given workspace, or None."""
    membership = db.execute(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.removed_at.is_(None),
        )
    ).scalar_one_or_none()

    if membership is None or not membership.is_active:
        return None
    return membership.role


def get_user_permissions(
    db: Session,
    user: User,
    *,
    organization_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
) -> frozenset[str]:
    """
    Compute the effective permission set for a user within a given scope.

    If both ``organization_id`` and ``workspace_id`` are provided, the
    result is the **union** of org-level and workspace-level permissions
    (a user who is an org admin AND a workspace editor gets the union).

    If neither is provided, returns only ``_SELF`` permissions plus any
    super-admin-wide permissions (currently none until the column exists).
    """
    permissions: set[str] = set(_SELF)

    if is_super_admin(user):
        # Until the super admin column exists, this branch never runs.
        # When it does, it grants platform-level permissions only,
        # not org-level or case-level ones — super admin is explicitly
        # NOT a shortcut to client evidence.
        permissions.update(
            PERM_ADMIN_ANALYST_VERIFY,
            PERM_ADMIN_ANALYST_REJECT,
            PERM_ADMIN_ORG_SUSPEND,
            PERM_ADMIN_PLATFORM_CONFIG,
            PERM_ADMIN_AUDIT_READ,
        )

    if organization_id is not None:
        org_role = get_user_org_role(db, user, organization_id)
        if org_role is not None:
            permissions.update(ORG_ROLE_PERMISSIONS.get(org_role, frozenset()))

    if workspace_id is not None:
        ws_role = get_user_workspace_role(db, user, workspace_id)
        if ws_role is not None:
            permissions.update(
                WORKSPACE_ROLE_PERMISSIONS.get(ws_role, frozenset())
            )

    return frozenset(permissions)


def get_user_organizations(db: Session, user: User) -> list[uuid.UUID]:
    """Return IDs of organizations the user is an active member of."""
    rows = db.execute(
        select(OrganizationMembership.organization_id).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.removed_at.is_(None),
        )
    ).scalars().all()
    return list(rows)


def get_user_workspaces(db: Session, user: User) -> list[uuid.UUID]:
    """Return IDs of workspaces the user is an active member of."""
    rows = db.execute(
        select(WorkspaceMembership.workspace_id).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.removed_at.is_(None),
        )
    ).scalars().all()
    return list(rows)


# ============================================================================
# CASE ACCESS GRANT RESOLUTION
# ============================================================================

def _get_active_case_grant(
    db: Session,
    user: User,
    case_id: uuid.UUID,
) -> CaseAccessGrant | None:
    """
    Return the strongest active access grant the user holds on the
    given case, or None if they hold none.

    "Strongest" = largest scope (FULL_CASE > CONVERSATION_READ >
    EVIDENCE_READ > CASE_READ). When a user has multiple grants
    (rare — usually caused by two concurrent engagements), the
    highest scope wins for the duration of the request.
    """
    grants = db.execute(
        select(CaseAccessGrant).where(
            CaseAccessGrant.case_id == case_id,
            CaseAccessGrant.grantee_user_id == user.id,
            CaseAccessGrant.revoked_at.is_(None),
        )
    ).scalars().all()

    now = datetime.now(timezone.utc)
    scope_rank = {
        AccessGrantScope.CASE_READ: 1,
        AccessGrantScope.EVIDENCE_READ: 2,
        AccessGrantScope.CONVERSATION_READ: 3,
        AccessGrantScope.FULL_CASE: 4,
    }

    best: CaseAccessGrant | None = None
    best_rank = 0
    for grant in grants:
        if grant.expires_at is not None:
            exp = grant.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                continue
        rank = scope_rank.get(grant.scope, 0)
        if rank > best_rank:
            best = grant
            best_rank = rank
    return best


def _grant_permits(grant: CaseAccessGrant | None, permission: str) -> bool:
    """Return True if the grant's scope covers the given case permission."""
    if grant is None:
        return False
    scope = grant.scope

    if permission == PERM_CASE_READ:
        return scope in (
            AccessGrantScope.CASE_READ,
            AccessGrantScope.EVIDENCE_READ,
            AccessGrantScope.CONVERSATION_READ,
            AccessGrantScope.FULL_CASE,
        )
    if permission in (PERM_EVIDENCE_READ, PERM_EVIDENCE_DOWNLOAD):
        return scope in (
            AccessGrantScope.EVIDENCE_READ,
            AccessGrantScope.FULL_CASE,
        )
    # Case update/assign/close and evidence upload/delete are
    # investigation actions — only FULL_CASE grants them.
    # (Assigned analysts get them via role-based access, not grant-based.)
    if permission in (
        PERM_CASE_UPDATE, PERM_CASE_ASSIGN, PERM_CASE_CLOSE,
        PERM_EVIDENCE_UPLOAD, PERM_EVIDENCE_DELETE,
    ):
        return scope == AccessGrantScope.FULL_CASE
    return False


def is_case_participant(
    db: Session,
    user: User,
    case: SecurityCase,
) -> bool:
    """
    Return True if the user is a participant on the case by any means:
    assigned analyst, workspace member with case read, or active grant.
    """
    # Assigned directly (primary analyst)
    if case.assigned_to_id == user.id:
        return True

    # Workspace member with case-read permission
    ws_role = get_user_workspace_role(db, user, case.workspace_id)
    if ws_role is not None:
        if PERM_CASE_READ in WORKSPACE_ROLE_PERMISSIONS.get(ws_role, frozenset()):
            return True

    # Active access grant
    if _get_active_case_grant(db, user, case.id) is not None:
        return True

    return False


# ============================================================================
# CORE PERMISSION CHECK
# ============================================================================

def _permission_denied(
    *,
    user: User,
    permission: str,
    reason: str,
    details: dict[str, Any] | None = None,
) -> AuthorizationError:
    """
    Log the denial at INFO and construct the AuthorizationError.
    Central place to add structured logging — callers just ``raise``.
    """
    logger.info(
        "Permission denied",
        extra={
            "user_id": str(user.id),
            "permission": permission,
            "reason": reason,
            **(details or {}),
        },
    )
    return AuthorizationError(
        message=f"Permission denied: {permission}",
        code="PERMISSION_DENIED",
        details={
            "permission": permission,
            "reason": reason,
            **(details or {}),
        },
    )


def has_permission(
    db: Session,
    user: User,
    permission: str,
    *,
    resource: Any | None = None,
    organization_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    case: SecurityCase | None = None,
) -> bool:
    """
    Non-raising permission check. Use when you want to *branch* on the
    answer (e.g. "show admin tab only if admin"). Use ``check_permission``
    when you want to *enforce* it.

    Parameters
    ----------
    db : Session
    user : User
        The acting user. Must be an ORM instance (not a UUID).
    permission : str
        Permission string from ``app.core.constants.ALL_PERMISSIONS``.
    resource : Any | None
        The concrete entity being acted on. If provided, its type is
        used to infer the scope (a ``SecurityCase`` implies case scope,
        a ``Workspace`` implies workspace scope, etc.).
    organization_id, workspace_id, case : optional overrides
        Explicit scope. When provided, overrides ``resource``-inferred
        scope. Useful for endpoints that create new resources of an
        inferred scope (e.g. "create a case in this workspace" —
        no case exists yet, but the workspace is known).

    Returns
    -------
    bool
        True if the user has the permission; False otherwise.
        Never raises on permission failure — but may raise on
        unexpected internal errors (which should be bugs, not
        authorization outcomes).
    """
    # ── Special-case: self-service always allowed for the user themselves
    if permission in _SELF:
        return True

    # ── Special-case: platform permissions require super admin
    if _PERMISSION_SCOPE.get(permission) == "platform":
        return is_super_admin(user)

    # ── Infer scope from resource if explicit scopes not provided
    if case is None and isinstance(resource, SecurityCase):
        case = resource
    if workspace_id is None and resource is not None:
        workspace_id = getattr(resource, "workspace_id", None)
    if organization_id is None and resource is not None:
        # Some resources don't have org id directly; skip.
        organization_id = getattr(resource, "organization_id", None)

    # ── Case-scoped permissions: check assigned analyst + grant + role
    if case is not None and _PERMISSION_SCOPE.get(permission) == "case":
        # Assigned analyst gets case/evidence read + investigation perms
        if case.assigned_to_id == user.id:
            if permission in (
                PERM_CASE_READ, PERM_CASE_UPDATE,
                PERM_EVIDENCE_READ, PERM_EVIDENCE_DOWNLOAD,
                PERM_EVIDENCE_UPLOAD,
            ):
                return True

        # Active grant
        grant = _get_active_case_grant(db, user, case.id)
        if grant is not None and _grant_permits(grant, permission):
            return True

        # Workspace-member fallback (org/workspace role with case read)
        ws_role = get_user_workspace_role(db, user, case.workspace_id)
        if ws_role is not None:
            perms = WORKSPACE_ROLE_PERMISSIONS.get(ws_role, frozenset())
            if permission in perms:
                return True
        return False

    # ── Org-scoped permissions: check org membership
    if organization_id is not None and _PERMISSION_SCOPE.get(permission) == "organization":
        org_role = get_user_org_role(db, user, organization_id)
        if org_role is None:
            return False
        return permission in ORG_ROLE_PERMISSIONS.get(org_role, frozenset())

    # ── Workspace-scoped permissions: check workspace membership
    if workspace_id is not None:
        ws_role = get_user_workspace_role(db, user, workspace_id)
        if ws_role is None:
            return False
        return permission in WORKSPACE_ROLE_PERMISSIONS.get(ws_role, frozenset())

    # ── No scope resolved — deny
    return False


def check_permission(
    db: Session,
    user: User,
    permission: str,
    *,
    resource: Any | None = None,
    organization_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    case: SecurityCase | None = None,
) -> None:
    """
    Enforce a permission. Raises ``AuthorizationError`` (403) if the
    user does not have it.

    This is the function endpoints should call. When a resource is
    passed, the scope is inferred (a case implies case scope, a
    workspace implies workspace scope, etc.). When explicit scope
    overrides are given, they take priority.

    Calls ``has_permission`` internally and raises on the False path.
    Never returns a value — success is "did not raise".
    """
    if permission not in ALL_PERMISSIONS:
        # Programming error — a typo in the permission string. Raise
        # ValueError (not AuthorizationError) because this is a bug
        # in the caller, not a legitimate denial.
        raise ValueError(
            f"Unknown permission: {permission!r}. "
            f"See app.core.constants.ALL_PERMISSIONS."
        )

    if has_permission(
        db, user, permission,
        resource=resource,
        organization_id=organization_id,
        workspace_id=workspace_id,
        case=case,
    ):
        return

    raise _permission_denied(
        user=user,
        permission=permission,
        reason="no matching role, grant, or super-admin status",
        details={
            "organization_id": str(organization_id) if organization_id else None,
            "workspace_id": str(workspace_id) if workspace_id else None,
            "case_id": str(case.id) if case is not None else None,
            "resource_type": type(resource).__name__ if resource is not None else None,
        },
    )


# ============================================================================
# SCOPE-SPECIFIC HELPERS
# ============================================================================
# Convenience wrappers around check_permission for the three scope
# types. Endpoints and services import these directly — they read
# clearly at the call site:
#
#     require_workspace_member(db, user, workspace_id)
#     require_org_role(db, user, org_id, OrganizationRole.ADMIN)

def require_workspace_member(
    db: Session,
    user: User,
    workspace_id: uuid.UUID,
) -> WorkspaceRole:
    """
    Assert the user is an active member of the workspace (any role).
    Returns the role. Raises ``TenantIsolationError`` on failure —
    the user is trying to touch a workspace they don't belong to,
    which is a *potential security incident*, not just a permission
    miss.
    """
    role = get_user_workspace_role(db, user, workspace_id)
    if role is None:
        logger.warning(
            "Cross-tenant workspace access attempt",
            extra={
                "user_id": str(user.id),
                "workspace_id": str(workspace_id),
            },
        )
        raise TenantIsolationError(
            message="You do not have access to this workspace.",
            code="WORKSPACE_ACCESS_DENIED",
            details={"workspace_id": str(workspace_id)},
        )
    return role


def require_org_member(
    db: Session,
    user: User,
    organization_id: uuid.UUID,
) -> OrganizationRole:
    """
    Assert the user is an active member of the organization (any role).
    Returns the role. Raises ``TenantIsolationError`` on failure.
    """
    role = get_user_org_role(db, user, organization_id)
    if role is None:
        logger.warning(
            "Cross-tenant organization access attempt",
            extra={
                "user_id": str(user.id),
                "organization_id": str(organization_id),
            },
        )
        raise TenantIsolationError(
            message="You do not have access to this organization.",
            code="ORGANIZATION_ACCESS_DENIED",
            details={"organization_id": str(organization_id)},
        )
    return role


def require_org_role(
    db: Session,
    user: User,
    organization_id: uuid.UUID,
    minimum_role: OrganizationRole,
) -> OrganizationRole:
    """
    Assert the user has at least the given role in the org.

    Role hierarchy (higher number = more authority):
        VIEWER < EMPLOYEE < ANALYST < SECURITY_MANAGER < ADMIN < OWNER
    """
    _RANK = {
        OrganizationRole.VIEWER: 1,
        OrganizationRole.EMPLOYEE: 2,
        OrganizationRole.ANALYST: 3,
        OrganizationRole.SECURITY_MANAGER: 4,
        OrganizationRole.ADMIN: 5,
        OrganizationRole.OWNER: 6,
    }
    actual = get_user_org_role(db, user, organization_id)
    if actual is None:
        raise TenantIsolationError(
            message="You do not have access to this organization.",
            code="ORGANIZATION_ACCESS_DENIED",
            details={"organization_id": str(organization_id)},
        )
    if _RANK.get(actual, 0) < _RANK.get(minimum_role, 0):
        raise _permission_denied(
            user=user,
            permission=f"organization:role>={minimum_role.value}",
            reason="role too low",
            details={
                "actual_role": actual.value,
                "required_role": minimum_role.value,
                "organization_id": str(organization_id),
            },
        )
    return actual


def require_workspace_role(
    db: Session,
    user: User,
    workspace_id: uuid.UUID,
    minimum_role: WorkspaceRole,
) -> WorkspaceRole:
    """
    Assert the user has at least the given role in the workspace.

    Role hierarchy:
        VIEWER < EDITOR < OWNER
    """
    _RANK = {
        WorkspaceRole.VIEWER: 1,
        WorkspaceRole.EDITOR: 2,
        WorkspaceRole.OWNER: 3,
    }
    actual = get_user_workspace_role(db, user, workspace_id)
    if actual is None:
        raise TenantIsolationError(
            message="You do not have access to this workspace.",
            code="WORKSPACE_ACCESS_DENIED",
            details={"workspace_id": str(workspace_id)},
        )
    if _RANK.get(actual, 0) < _RANK.get(minimum_role, 0):
        raise _permission_denied(
            user=user,
            permission=f"workspace:role>={minimum_role.value}",
            reason="role too low",
            details={
                "actual_role": actual.value,
                "required_role": minimum_role.value,
                "workspace_id": str(workspace_id),
            },
        )
    return actual


def require_case_access(
    db: Session,
    user: User,
    case: SecurityCase,
    *,
    minimum_scope: AccessGrantScope = AccessGrantScope.CASE_READ,
) -> AccessGrantScope:
    """
    Assert the user can access the given case at the given scope level.

    Scope hierarchy (higher number = more access):
        CASE_READ < EVIDENCE_READ < CONVERSATION_READ < FULL_CASE

    Returns the effective scope granted to the user. Raises
    ``AuthorizationError`` on failure.

    Resolution order:
      1. Assigned analyst → FULL_CASE (they're doing the work)
      2. Workspace/org role → mapped to a scope based on role
      3. Active access grant → its own scope
      4. Deny
    """
    _RANK = {
        AccessGrantScope.CASE_READ: 1,
        AccessGrantScope.EVIDENCE_READ: 2,
        AccessGrantScope.CONVERSATION_READ: 3,
        AccessGrantScope.FULL_CASE: 4,
    }
    required_rank = _RANK.get(minimum_scope, 0)

    # ── 1. Assigned analyst → FULL_CASE
    if case.assigned_to_id == user.id:
        return AccessGrantScope.FULL_CASE

    # ── 2. Workspace/org role → mapped scope
    ws_role = get_user_workspace_role(db, user, case.workspace_id)
    if ws_role is not None:
        if ws_role == WorkspaceRole.OWNER:
            if _RANK[AccessGrantScope.FULL_CASE] >= required_rank:
                return AccessGrantScope.FULL_CASE
        elif ws_role == WorkspaceRole.EDITOR:
            effective = AccessGrantScope.EVIDENCE_READ
            if _RANK[effective] >= required_rank:
                return effective
        elif ws_role == WorkspaceRole.VIEWER:
            effective = AccessGrantScope.CASE_READ
            if _RANK[effective] >= required_rank:
                return effective

    # ── 3. Active access grant
    grant = _get_active_case_grant(db, user, case.id)
    if grant is not None:
        if _RANK.get(grant.scope, 0) >= required_rank:
            return grant.scope

    # ── 4. Deny
    logger.info(
        "Case access denied",
        extra={
            "user_id": str(user.id),
            "case_id": str(case.id),
            "required_scope": minimum_scope.value,
        },
    )
    raise AuthorizationError(
        message="You do not have access to this case.",
        code="CASE_ACCESS_DENIED",
        details={
            "case_id": str(case.id),
            "required_scope": minimum_scope.value,
        },
    )


def require_evidence_access(
    db: Session,
    user: User,
    evidence: SecurityEvidence,
    *,
    case: SecurityCase | None = None,
) -> None:
    """
    Assert the user can view a piece of evidence.

    Checks the *case* access first (must be at least EVIDENCE_READ),
    then the evidence's own ``access_grant_scope_required`` (which
    may be FULL_CASE for sensitive evidence).

    The case is passed in (or fetched if not) to avoid double round
    trips when the caller already has it.
    """
    if case is None:
        case = db.get(SecurityCase, evidence.case_id)
        if case is None:
            raise AuthorizationError(
                message="Evidence references a case that no longer exists.",
                code="EVIDENCE_ORPHANED",
                details={"evidence_id": str(evidence.id)},
            )

    effective_scope = require_case_access(
        db, user, case, minimum_scope=evidence.access_grant_scope_required,
    )
    _ = effective_scope  # used for clarity; the assert is the point

    if not evidence.integrity_verified:
        logger.warning(
            "Access to compromised evidence",
            extra={
                "user_id": str(user.id),
                "evidence_id": str(evidence.id),
                "case_id": str(case.id),
            },
        )
        # Note: we allow access but the warning is logged. The UI is
        # expected to display a "this evidence has failed integrity
        # verification" banner. Refusing outright would be worse —
        # investigators need to see *what* was tampered with.


def require_analyst_profile(
    db: Session,
    user: User,
    *,
    require_verified: bool = True,
) -> AnalystProfile:
    """
    Assert the user has an analyst profile, optionally verified.

    Called by endpoints that need an analyst (case assignment, offering
    creation, etc.). Returns the ``AnalystProfile`` ORM instance.
    """
    profile = db.execute(
        select(AnalystProfile).where(AnalystProfile.user_id == user.id)
    ).scalar_one_or_none()

    if profile is None:
        raise AuthorizationError(
            message="An analyst profile is required for this action.",
            code="ANALYST_PROFILE_NOT_FOUND",
        )

    if require_verified and profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise AuthorizationError(
            message=(
                f"Analyst is not verified (status: "
                f"{profile.verification_status.value})."
            ),
            code="ANALYST_NOT_VERIFIED",
            details={"verification_status": profile.verification_status.value},
        )

    return profile


def require_active_user(user: User) -> None:
    """
    Assert the user account is active (status=ACTIVE, not soft-deleted).

    Most endpoints use ``get_current_active_user`` which already
    enforces this. This helper exists for internal calls where the
    user is loaded differently (e.g. from a background job or agent).
    """
    if user.deleted_at is not None:
        raise AuthorizationError(
            message="User account has been deleted.",
            code="USER_DELETED",
            details={"user_id": str(user.id)},
        )
    if user.status != UserStatus.ACTIVE:
        raise AuthorizationError(
            message=f"User account is not active ({user.status.value}).",
            code="USER_NOT_ACTIVE",
            details={"user_id": str(user.id), "status": user.status.value},
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Permission groups (exposed for tests and admin UI)
    "ORG_ROLE_PERMISSIONS",
    "WORKSPACE_ROLE_PERMISSIONS",
    # Query helpers
    "is_super_admin",
    "get_user_org_role",
    "get_user_workspace_role",
    "get_user_permissions",
    "get_user_organizations",
    "get_user_workspaces",
    # Case participant resolution
    "is_case_participant",
    # Core checks
    "has_permission",
    "check_permission",
    # Scope assertions (raise on failure)
    "require_workspace_member",
    "require_org_member",
    "require_org_role",
    "require_workspace_role",
    "require_case_access",
    "require_evidence_access",
    "require_analyst_profile",
    "require_active_user",
]