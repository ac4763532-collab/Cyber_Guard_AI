"""
CyberGuard AI — Workspace Service
============================================================================

Business logic for workspaces: creation (personal + org), retrieval,
listing, update, and archival.

Workspaces are the **access-control scope** between an organization
(tenant) and every security artifact (source, event, incident, case,
evidence, report). One user can belong to many workspaces — their
personal one, plus any org workspaces they've been invited to.

Workspace types
---------------
    PERSONAL       — auto-created at user registration. One per user,
                     enforced by a DB partial unique index. No org.
    ORGANIZATION   — created by an org admin/owner. Belongs to exactly
                     one org. Requires client-supplied slug (unique
                     within the org).
    SHARED         — reserved for cross-team sharing (future feature).
                     Not currently created by any service method.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Every state-changing method:
       - calls ``authorization.check_permission`` before mutating
       - calls ``audit_service.log_*`` after mutating
5. Personal workspace creation is **idempotent** — called from
   registration code, but safe to call twice.

Personal workspace creation
---------------------------
``create_personal_workspace`` is called exactly once per user —
either during registration, or the first time a user does something
that requires a workspace (defensive re-creation if registration was
interrupted). The DB's partial unique index on
``(owner_id) WHERE workspace_type='personal' AND deleted_at IS NULL``
guarantees only one exists.

If the workspace already exists, this function returns it rather
than raising. That makes it safe to call from a retry path.

Org workspace creation
----------------------
``create_org_workspace`` is the standard "add a team workspace" flow:

    1. Verify actor has PERM_WORKSPACE_CREATE in the org scope
    2. Verify slug uniqueness within the org
    3. Create workspace
    4. Add actor as OWNER (they created it)
    5. Audit

The permission check requires org membership with a role that grants
``PERM_WORKSPACE_CREATE`` (ADMIN or OWNER). Security managers get
``_WRITE`` which does not include ``PERM_WORKSPACE_CREATE`` — they
manage security ops, not team structure.

Slug uniqueness
---------------
Personal workspace slugs are auto-generated (``personal-<uuid-prefix>``)
and globally unique by construction.

Organization workspace slugs are client-supplied and unique *within
the org* — the DB constraint is ``(organization_id, slug)``. Two
different orgs can both have a workspace called "security-ops".

When creating a personal workspace for a user who already has one
(corrupt state), the code logs an error and returns the existing one
rather than creating a duplicate. This is a defensive measure — the
DB constraint should prevent it, but if it somehow slips through,
we fail safely.

Public API
----------
    create_personal_workspace(db, user)                              → Workspace
    create_org_workspace(db, *, actor, organization, payload, ...)   → Workspace
    get_by_id(db, workspace_id)                                      → Workspace
    get_by_slug_in_org(db, org_id, slug)                             → Workspace
    list_user_workspaces(db, *, user, page, filters)                 → (list, int)
    list_org_workspaces(db, *, organization, page, filters)          → (list, int)
    update_workspace(db, *, actor, workspace, payload, request=None) → Workspace
    archive_workspace(db, *, actor, workspace, request=None)         → Workspace

Usage
-----
    from app.services import workspace_service

    # In registration:
    personal_ws = workspace_service.create_personal_workspace(db, user)

    # In an org admin endpoint (POST /organizations/{id}/workspaces):
    ws = workspace_service.create_org_workspace(
        db,
        actor=current_user,
        organization=org,
        payload=body,
    )
    db.commit()
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_ORG_READ,
    PERM_WORKSPACE_CREATE,
    PERM_WORKSPACE_DELETE,
    PERM_WORKSPACE_UPDATE,
)
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    InvalidStateTransitionError,
    ValidationError,
    WorkspaceNotFoundError,
)
from app.core.logging import get_logger
from app.models.enums import (
    OrganizationRole,
    WorkspaceRole,
    WorkspaceType,
)
from app.models.membership import (
    OrganizationMembership,
    WorkspaceMembership,
)
from app.models.organization import Organization
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.schemas.workspace import (
    WorkspaceCreate,
    WorkspaceFilter,
    WorkspaceUpdate,
)
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================
_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_SLUG_MIN = 3
_SLUG_MAX = 64

#: Workspace type → allowed transitions on archive.
#: Personal workspaces cannot be archived via this service — they are
#: tied to the user's lifecycle and are cleaned up when the user is
#: soft-deleted. Org workspaces can be archived by an admin.
_ARCHIVABLE_TYPES = frozenset({WorkspaceType.ORGANIZATION, WorkspaceType.SHARED})


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _get_workspace_by_slug_optional(
    db: Session,
    *,
    organization_id: uuid.UUID,
    slug: str,
) -> Workspace | None:
    """
    Fetch a workspace by (org, slug) without raising. Returns
    non-deleted rows only — soft-deleted workspaces have their slug
    free (reusable) since the row is invisible.
    """
    normalized = slug.strip().lower()
    return db.execute(
        select(Workspace).where(
            Workspace.organization_id == organization_id,
            Workspace.slug == normalized,
            Workspace.deleted_at.is_(None),
        )
    ).scalar_one_or_none()


def _get_personal_workspace_optional(
    db: Session,
    user_id: uuid.UUID,
) -> Workspace | None:
    """
    Return the user's personal workspace if it exists (and is not
    soft-deleted), else None.
    """
    return db.execute(
        select(Workspace).where(
            Workspace.owner_id == user_id,
            Workspace.workspace_type == WorkspaceType.PERSONAL,
            Workspace.deleted_at.is_(None),
        )
    ).scalar_one_or_none()


def _snapshot_state(workspace: Workspace) -> dict[str, Any]:
    """
    Capture mutable fields for audit logging.

    Excludes ``settings`` (potentially large and non-user-facing) and
    immutable fields (id, owner, org, type, timestamps).
    """
    return {
        "name": workspace.name,
        "slug": workspace.slug,
        "description": workspace.description,
        "color": workspace.color,
        "icon": workspace.icon,
    }


def _generate_personal_slug(user_id: uuid.UUID) -> str:
    """Deterministic slug for personal workspaces: ``personal-<hex12>``."""
    return f"personal-{user_id.hex[:12]}"


def _generate_personal_name(user: User) -> str:
    """
    Default name for personal workspaces. Uses the user's display name
    when available; falls back to "Personal".
    """
    display = (user.full_name or "").strip()
    if display:
        return f"{display}'s Workspace"
    return "Personal Workspace"


# ============================================================================
# PERSONAL WORKSPACE — CREATE (idempotent)
# ============================================================================

def create_personal_workspace(
    db: Session,
    user: User,
) -> Workspace:
    """
    Create (or return) the user's personal workspace.

    Idempotent by design — safe to call during registration, and safe
    to call again if a previous attempt was interrupted before
    completion.

    Flow
    ----
    1. Check for existing personal workspace → return it (idempotent).
    2. Create the workspace with a deterministic slug.
    3. Add the user as OWNER.
    4. Audit.
    """
    existing = _get_personal_workspace_optional(db, user.id)
    if existing is not None:
        logger.debug(
            "Personal workspace already exists — returning existing",
            extra={
                "user_id": str(user.id),
                "workspace_id": str(existing.id),
            },
        )
        return existing

    slug = _generate_personal_slug(user.id)
    name = _generate_personal_name(user)

    workspace = Workspace(
        name=name,
        slug=slug,
        description=None,
        workspace_type=WorkspaceType.PERSONAL,
        owner_id=user.id,
        organization_id=None,
    )
    db.add(workspace)
    db.flush()

    # Add user as OWNER of their own personal workspace
    membership = WorkspaceMembership.build_direct(
        user_id=user.id,
        workspace_id=workspace.id,
        role=WorkspaceRole.OWNER,
        invited_by_id=user.id,
    )
    db.add(membership)
    db.flush()

    audit_service.log_action(
        db,
        actor=user,
        action="workspace.created",
        target_type="workspace",
        target_id=workspace.id,
        target_display=workspace.slug,
        workspace_id=workspace.id,
        metadata={
            "workspace_type": WorkspaceType.PERSONAL.value,
            "owner_id": str(user.id),
        },
    )

    logger.info(
        "Personal workspace created",
        extra={
            "workspace_id": str(workspace.id),
            "user_id": str(user.id),
        },
    )

    return workspace


# ============================================================================
# ORGANIZATION WORKSPACE — CREATE
# ============================================================================

def create_org_workspace(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    payload: WorkspaceCreate,
    request: Any | None = None,
) -> Workspace:
    """
    Create a new workspace inside an organization.

    Requires ``PERM_WORKSPACE_CREATE`` in the org scope. Only ADMIN
    and OWNER roles have it — security managers cannot restructure
    teams.

    The actor is automatically added as OWNER of the new workspace
    (they created it). Additional members can be invited separately
    via ``membership_service``.

    Flow
    ----
    1. Verify actor has PERM_WORKSPACE_CREATE in the org
    2. Validate slug is supplied and unique within the org
    3. Create workspace
    4. Add actor as WORKSPACE OWNER
    5. Audit

    Raises
    ------
    AuthorizationError
        If the actor lacks the permission.
    ValidationError
        If ``slug`` was not supplied.
    ConflictError
        If a non-deleted workspace with this slug exists in the org.
    """
    # ── 1. Permission check
    authorization.check_permission(
        db,
        actor,
        PERM_WORKSPACE_CREATE,
        organization_id=organization.id,
    )

    # ── 2. Slug is required for org workspaces
    if not payload.slug:
        raise ValidationError(
            message=(
                "Slug is required for organization workspaces. It must be "
                "unique within the organization."
            ),
            code="WORKSPACE_SLUG_REQUIRED",
        )

    # ── 3. Slug uniqueness within the org
    existing = _get_workspace_by_slug_optional(
        db,
        organization_id=organization.id,
        slug=payload.slug,
    )
    if existing is not None:
        raise ConflictError(
            message=(
                f"A workspace with slug {payload.slug!r} already exists "
                f"in this organization."
            ),
            code="WORKSPACE_SLUG_TAKEN",
            details={
                "slug": payload.slug,
                "organization_id": str(organization.id),
            },
        )

    # ── 4. Create
    workspace = Workspace(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        workspace_type=WorkspaceType.ORGANIZATION,
        owner_id=actor.id,
        organization_id=organization.id,
        color=payload.color,
        icon=payload.icon,
    )
    db.add(workspace)
    db.flush()

    # ── 5. Actor as WORKSPACE OWNER
    membership = WorkspaceMembership.build_direct(
        user_id=actor.id,
        workspace_id=workspace.id,
        role=WorkspaceRole.OWNER,
        invited_by_id=actor.id,
    )
    db.add(membership)
    db.flush()

    # ── 6. Audit
    audit_service.log_action(
        db,
        actor=actor,
        action="workspace.created",
        target_type="workspace",
        target_id=workspace.id,
        target_display=workspace.slug,
        workspace_id=workspace.id,
        organization_id=organization.id,
        request=request,
        metadata={
            "workspace_type": WorkspaceType.ORGANIZATION.value,
            "owner_id": str(actor.id),
        },
    )

    logger.info(
        "Organization workspace created",
        extra={
            "workspace_id": str(workspace.id),
            "organization_id": str(organization.id),
            "slug": workspace.slug,
            "actor_id": str(actor.id),
        },
    )

    return workspace


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, workspace_id: uuid.UUID) -> Workspace:
    """
    Fetch a workspace by ID.

    Does NOT check tenant access — the caller (endpoint or another
    service) must call ``authorization.require_workspace_member`` or
    equivalent. This keeps ``get_by_id`` cheap and reusable from
    contexts where the caller already knows the user is authorized.
    """
    workspace = db.get(Workspace, workspace_id)
    if workspace is None or workspace.deleted_at is not None:
        raise WorkspaceNotFoundError(
            message=f"Workspace {workspace_id} not found.",
            details={"workspace_id": str(workspace_id)},
        )
    return workspace


def get_by_slug_in_org(
    db: Session,
    *,
    organization_id: uuid.UUID,
    slug: str,
) -> Workspace:
    """
    Fetch a workspace by (org, slug).

    Raises ``WorkspaceNotFoundError`` if missing or soft-deleted.
    """
    workspace = _get_workspace_by_slug_optional(
        db,
        organization_id=organization_id,
        slug=slug,
    )
    if workspace is None:
        raise WorkspaceNotFoundError(
            message=(
                f"Workspace with slug {slug!r} not found in organization "
                f"{organization_id}."
            ),
            details={"slug": slug, "organization_id": str(organization_id)},
        )
    return workspace


def list_user_workspaces(
    db: Session,
    *,
    user: User,
    page: PageParams,
    filters: WorkspaceFilter | None = None,
) -> tuple[list[Workspace], int]:
    """
    List workspaces the user is an active member of.

    Includes:
        - Their personal workspace (always — they are OWNER)
        - Any org workspaces they've been added to

    Excludes:
        - Soft-deleted workspaces
        - Workspaces where the user's membership has been removed

    Filters (all optional):
        - ``workspace_type``
        - ``organization_id``
        - ``name_contains`` (case-insensitive substring)
    """
    # Active workspace memberships for the user
    membership_subq = (
        select(WorkspaceMembership.workspace_id)
        .where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.removed_at.is_(None),
        )
    )

    stmt = select(Workspace).where(
        Workspace.deleted_at.is_(None),
        Workspace.id.in_(membership_subq),
    )

    if filters is not None:
        if filters.workspace_type is not None:
            stmt = stmt.where(Workspace.workspace_type == filters.workspace_type)
        if filters.organization_id is not None:
            stmt = stmt.where(Workspace.organization_id == filters.organization_id)
        if filters.name_contains:
            stmt = stmt.where(
                Workspace.name.ilike(f"%{filters.name_contains.lower()}%")
            )

    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    stmt = (
        stmt.order_by(Workspace.created_at.asc(), Workspace.id.asc())
        .offset(page.offset)
        .limit(page.limit)
    )

    workspaces = list(db.execute(stmt).scalars().all())
    return workspaces, int(total)


def list_org_workspaces(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    page: PageParams,
    filters: WorkspaceFilter | None = None,
) -> tuple[list[Workspace], int]:
    """
    List all workspaces in an organization. Requires
    ``PERM_ORG_READ`` in the org scope — visible to every active
    member, but the *contents* (members, sources, cases) may be
    restricted further.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_READ, organization_id=organization.id,
    )

    stmt = select(Workspace).where(
        Workspace.organization_id == organization.id,
        Workspace.deleted_at.is_(None),
    )

    if filters is not None:
        if filters.name_contains:
            stmt = stmt.where(
                Workspace.name.ilike(f"%{filters.name_contains.lower()}%")
            )
        if filters.workspace_type is not None:
            stmt = stmt.where(Workspace.workspace_type == filters.workspace_type)

    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    stmt = (
        stmt.order_by(Workspace.created_at.asc(), Workspace.id.asc())
        .offset(page.offset)
        .limit(page.limit)
    )

    workspaces = list(db.execute(stmt).scalars().all())
    return workspaces, int(total)


# ============================================================================
# UPDATE
# ============================================================================

def update_workspace(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    payload: WorkspaceUpdate,
    request: Any | None = None,
) -> Workspace:
    """
    Update mutable fields of a workspace.

    Requires ``PERM_WORKSPACE_UPDATE``:
        - For personal workspaces: the OWNER (the user themselves)
        - For org workspaces: workspace OWNER or org ADMIN/OWNER

    Cannot change (schema does not allow):
        - ``slug`` — immutable
        - ``workspace_type`` — set at creation
        - ``owner_id`` — dedicated ownership transfer flow
        - ``organization_id`` — set at creation

    ``settings`` is merged, not replaced. To remove a key, pass it with
    a null value.
    """
    authorization.check_permission(
        db, actor, PERM_WORKSPACE_UPDATE, workspace_id=workspace.id,
    )

    before = _snapshot_state(workspace)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return workspace

    # Merge settings rather than replace
    if "settings" in updates and updates["settings"] is not None:
        merged = dict(workspace.settings or {})
        for k, v in updates["settings"].items():
            if v is None:
                merged.pop(k, None)
            else:
                merged[k] = v
        updates["settings"] = merged

    for field, value in updates.items():
        setattr(workspace, field, value)

    db.flush()
    after = _snapshot_state(workspace)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="workspace.updated",
        target_type="workspace",
        target_id=workspace.id,
        target_display=workspace.slug,
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Workspace updated",
        extra={
            "workspace_id": str(workspace.id),
            "fields_changed": list(updates.keys()),
            "actor_id": str(actor.id),
        },
    )

    return workspace


# ============================================================================
# LIFECYCLE — ARCHIVE
# ============================================================================

def archive_workspace(
    db: Session,
    *,
    actor: User,
    workspace: Workspace,
    request: Any | None = None,
) -> Workspace:
    """
    Archive a workspace (soft-delete). Sets ``deleted_at``.

    Requires ``PERM_WORKSPACE_DELETE`` (OWNER only, both for personal
    and org workspaces).

    Personal workspaces cannot be archived — they are tied to the user
    lifecycle and are cleaned up when the user is soft-deleted. This
    prevents a user from accidentally orphaning their own account.

    Idempotent — archiving an already-archived workspace is a no-op.
    """
    authorization.check_permission(
        db, actor, PERM_WORKSPACE_DELETE, workspace_id=workspace.id,
    )

    if workspace.deleted_at is not None:
        return workspace

    if workspace.workspace_type not in _ARCHIVABLE_TYPES:
        raise InvalidStateTransitionError(
            message=(
                f"Workspaces of type {workspace.workspace_type.value!r} "
                "cannot be archived through this endpoint. Personal "
                "workspaces are managed via the user lifecycle."
            ),
            code="WORKSPACE_TYPE_NOT_ARCHIVABLE",
            details={"workspace_type": workspace.workspace_type.value},
        )

    from datetime import datetime, timezone
    before = {"deleted_at": None}
    workspace.deleted_at = datetime.now(timezone.utc)
    db.flush()
    after = {"deleted_at": workspace.deleted_at.isoformat()}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="workspace.archived",
        target_type="workspace",
        target_id=workspace.id,
        target_display=workspace.slug,
        workspace_id=workspace.id,
        organization_id=workspace.organization_id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Workspace archived",
        extra={
            "workspace_id": str(workspace.id),
            "actor_id": str(actor.id),
        },
    )

    return workspace


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Create
    "create_personal_workspace",
    "create_org_workspace",
    # Read
    "get_by_id",
    "get_by_slug_in_org",
    "list_user_workspaces",
    "list_org_workspaces",
    # Update
    "update_workspace",
    # Lifecycle
    "archive_workspace",
]