"""
CyberGuard AI — Organization Service
============================================================================

Business logic for organizations: creation, retrieval, listing, update,
archival, and (admin) suspension.

Organizations are the **tenant boundary**. Every workspace, source,
event, incident, case, and piece of evidence belongs to exactly one
organization. This service is where the top-level tenancy object is
managed.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never create one.
2. Never commit — the endpoint owns the transaction boundary.
3. Raise ``CyberGuardError`` subclasses on failure.
4. Return ORM instances — not Pydantic DTOs.
5. No HTTP awareness.
6. Every state-changing method:
       - calls ``authorization.check_permission`` before mutating
       - calls ``audit_service.log_*`` after mutating
   The two together are the pattern every subsequent service
   (workspace, source, case, ...) follows.

Create flow
-----------
A new organization is a multi-table operation:

    1. ``organizations`` row  (with status=ACTIVE, owner set)
    2. ``organization_memberships`` row  (creator → OWNER)
    3. ``workspaces`` row  (default workspace for the org)
    4. ``workspace_memberships`` row  (creator → OWNER in default ws)
    5. audit entry

All four tables land in the same transaction. If any fails, none
persist — the caller (endpoint) rolls back. This is why
``create_organization`` flushes after each stage: to surface ID
generation and constraint violations immediately, not at final commit.

``create_organization`` is one of the few service functions that
creates rows in *three* other services' domains (workspace, membership).
That's intentional — the "create org with owner and default workspace"
operation is atomic by design. Splitting it into separate service calls
would invite inconsistency (an org with no owner, an org with no
workspaces).

Permission model on create
--------------------------
Any authenticated, active user can create an organization. This is a
**self-service action** — the same category as creating a personal
workspace. No ``PERM_ORG_CREATE`` check is required; the endpoint's
``get_current_active_user`` dependency already ensures the caller is
authenticated and active.

This is intentional. Requiring a permission would mean:
    - either granting ``PERM_ORG_CREATE`` to every user (defeats the
      permission),
    - or creating a bootstrap problem (no one has any permission until
      they're in an org they can't create).

Approval-gating new orgs (requiring super-admin activation before use)
is a valid *policy* but not a *permission*. It is added later by
setting ``status=PENDING_APPROVAL`` and building the approval flow.
The current implementation sets ``status=ACTIVE`` on creation.

Public API
----------
    create_organization(db, *, creator, payload, ...)  → Organization
    get_by_id(db, org_id)                              → Organization
    get_by_slug(db, slug)                              → Organization
    get_by_slug_optional(db, slug)                     → Organization | None
    list_user_organizations(db, *, user, page)         → (list[Organization], int)
    list_all_organizations(db, *, page, filters)       → (list[Organization], int)
    update_organization(db, *, actor, organization, payload, request=None) → Organization
    archive_organization(db, *, actor, organization, request=None) → Organization
    suspend_organization(db, *, actor, organization, reason, request=None) → Organization
    unsuspend_organization(db, *, actor, organization, request=None) → Organization

Usage
-----
    from app.services import organization_service

    # In an endpoint (POST /organizations):
    org = organization_service.create_organization(
        db,
        creator=current_user,
        payload=body,
    )
    db.commit()
    return OrganizationRead.model_validate(org)

    # In an endpoint (GET /organizations/{id}):
    org = organization_service.get_by_id(db, org_id)
    authorization.require_org_member(db, current_user, org.id)
    return OrganizationRead.model_validate(org)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_ADMIN_ORG_SUSPEND,
    PERM_ORG_DELETE,
    PERM_ORG_UPDATE,
)
from app.core.exceptions import (
    ConflictError,
    InvalidStateTransitionError,
    OrganizationNotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.enums import (
    OrganizationRole,
    OrganizationStatus,
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
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationFilter,
    OrganizationUpdate,
)
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================
#: Pattern enforced at ORM level too — validated here first for a
#: clean 422 before hitting the DB.
_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_SLUG_MIN = 3
_SLUG_MAX = 64

#: Default workspace created alongside each new organization.
_DEFAULT_WORKSPACE_NAME = "General"
_DEFAULT_WORKSPACE_SLUG = "general"


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _get_by_slug_optional(db: Session, slug: str) -> Organization | None:
    """
    Fetch an org by slug without raising if missing. Includes
    soft-deleted rows — callers must check ``deleted_at`` themselves.
    """
    normalized = slug.strip().lower()
    return db.execute(
        select(Organization).where(Organization.slug == normalized)
    ).scalar_one_or_none()


def _snapshot_state(org: Organization) -> dict[str, Any]:
    """
    Capture the mutable fields of an organization for the audit log.

    Deliberately excludes:
        - ``settings`` — could be large and isn't user-facing
        - ``id``, timestamps — never change
        - ``owner_id`` — changes via a dedicated flow (not this one)
    """
    return {
        "name": org.name,
        "slug": org.slug,
        "description": org.description,
        "status": org.status.value,
        "contact_email": org.contact_email,
        "website": org.website,
        "industry": org.industry,
        "company_size": org.company_size,
        "country": org.country,
        "timezone": org.timezone,
        "logo_url": org.logo_url,
        "subscription_plan": org.subscription_plan,
    }


def _create_default_workspace(
    db: Session,
    *,
    org: Organization,
    creator: User,
    name: str,
    slug: str,
) -> Workspace:
    """
    Create the default workspace for a new organization, plus the
    creator's OWNER membership in that workspace.

    Not exported — internal only to ``create_organization``. The
    org is not usable without at least one workspace, so this is part
    of the atomic create flow.
    """
    workspace = Workspace(
        name=name,
        slug=slug,
        description=f"Default workspace for {org.name}",
        workspace_type=WorkspaceType.ORGANIZATION,
        owner_id=creator.id,
        organization_id=org.id,
    )
    db.add(workspace)
    db.flush()

    membership = WorkspaceMembership.build_direct(
        user_id=creator.id,
        workspace_id=workspace.id,
        role=WorkspaceRole.OWNER,
        invited_by_id=creator.id,
    )
    db.add(membership)
    db.flush()

    return workspace


# ============================================================================
# CREATE
# ============================================================================

def create_organization(
    db: Session,
    *,
    creator: User,
    payload: OrganizationCreate,
    default_workspace_name: str = _DEFAULT_WORKSPACE_NAME,
    default_workspace_slug: str = _DEFAULT_WORKSPACE_SLUG,
) -> Organization:
    """
    Create a new organization with the creator as owner and a default
    workspace.

    This is a multi-table operation — see module docstring for the full
    flow. All rows land in the caller's transaction (or roll back
    together when the endpoint fails).

    Parameters
    ----------
    db : Session
    creator : User
        The user creating the org. Becomes the OWNER.
    payload : OrganizationCreate
        Validated input.
    default_workspace_name, default_workspace_slug : str
        Names for the automatically-created default workspace. The
        slug is only unique within the org (the model's unique
        constraint is ``(organization_id, slug)``), so "general" is
        free for every org.

    Returns
    -------
    Organization
        The created organization (flushed, id populated, not committed).

    Raises
    ------
    ConflictError
        If an org with this slug already exists (including soft-deleted
        rows — their slugs are reserved until the retention job hard-
        deletes them, preventing "recreate with same slug to hijack
        historical references").
    """
    # ── 1. Slug uniqueness
    existing = _get_by_slug_optional(db, payload.slug)
    if existing is not None:
        raise ConflictError(
            message=(
                f"An organization with slug {payload.slug!r} already exists. "
                "Slugs are unique and may be reserved by a recently deleted "
                "organization until retention cleanup completes."
            ),
            code="ORGANIZATION_SLUG_TAKEN",
            details={"slug": payload.slug},
        )

    # ── 2. Create organization
    org = Organization(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        status=OrganizationStatus.ACTIVE,  # see module docstring
        owner_id=creator.id,
        contact_email=payload.contact_email,
        website=payload.website,
        industry=payload.industry,
        company_size=payload.company_size,
        country=payload.country,
        timezone=payload.timezone,
        logo_url=payload.logo_url,
        subscription_plan="free",
        settings={},
    )
    db.add(org)
    db.flush()  # get org.id for downstream FKs

    # ── 3. Owner membership (direct-add, not an invitation)
    owner_membership = OrganizationMembership.build_direct(
        user_id=creator.id,
        organization_id=org.id,
        role=OrganizationRole.OWNER,
        invited_by_id=creator.id,
    )
    db.add(owner_membership)
    db.flush()

    # ── 4. Default workspace + creator's OWNER membership
    _create_default_workspace(
        db,
        org=org,
        creator=creator,
        name=default_workspace_name,
        slug=default_workspace_slug,
    )

    # ── 5. Audit
    audit_service.log_action(
        db,
        actor=creator,
        action="organization.created",
        target_type="organization",
        target_id=org.id,
        target_display=org.slug,
        organization_id=org.id,
        metadata={
            "owner_id": str(creator.id),
            "subscription_plan": org.subscription_plan,
            "default_workspace_slug": default_workspace_slug,
        },
    )

    logger.info(
        "Organization created",
        extra={
            "organization_id": str(org.id),
            "slug": org.slug,
            "owner_id": str(creator.id),
        },
    )

    return org


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, org_id: uuid.UUID) -> Organization:
    """
    Fetch an organization by ID.

    Raises
    ------
    OrganizationNotFoundError
        If the org does not exist or is soft-deleted.
    """
    org = db.get(Organization, org_id)
    if org is None or org.deleted_at is not None:
        raise OrganizationNotFoundError(
            message=f"Organization {org_id} not found.",
            details={"organization_id": str(org_id)},
        )
    return org


def get_by_slug(db: Session, slug: str) -> Organization:
    """
    Fetch an organization by slug.

    Raises
    ------
    OrganizationNotFoundError
        If no org with this slug exists, or the org is soft-deleted.
    """
    org = _get_by_slug_optional(db, slug)
    if org is None or org.deleted_at is not None:
        raise OrganizationNotFoundError(
            message=f"Organization with slug {slug!r} not found.",
            details={"slug": slug.strip().lower()},
        )
    return org


def get_by_slug_optional(db: Session, slug: str) -> Organization | None:
    """
    Public non-raising variant. Returns ``None`` if missing or
    soft-deleted.
    """
    org = _get_by_slug_optional(db, slug)
    if org is None or org.deleted_at is not None:
        return None
    return org


def list_user_organizations(
    db: Session,
    *,
    user: User,
    page: PageParams,
) -> tuple[list[Organization], int]:
    """
    List organizations the user is an **active member** of. Excludes
    soft-deleted orgs and any org where the user's membership has
    been removed or suspended.

    Returns ``(orgs_on_page, total_count)``.
    """
    # Active memberships for this user
    membership_subq = (
        select(OrganizationMembership.organization_id)
        .where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.removed_at.is_(None),
        )
    )

    stmt = (
        select(Organization)
        .where(
            Organization.deleted_at.is_(None),
            Organization.id.in_(membership_subq),
        )
    )

    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    stmt = (
        stmt.order_by(Organization.created_at.desc(), Organization.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )

    orgs = list(db.execute(stmt).scalars().all())
    return orgs, int(total)


def list_all_organizations(
    db: Session,
    *,
    page: PageParams,
    filters: OrganizationFilter,
) -> tuple[list[Organization], int]:
    """
    List all organizations (admin scope). Uses ``OrganizationFilter``
    for status, name/slug substring, and subscription plan filters.

    The endpoint using this is expected to require an admin permission
    — this service does not enforce it (admin endpoints call
    ``require_permission`` at the route layer).
    """
    stmt = select(Organization).where(Organization.deleted_at.is_(None))

    if filters.status is not None:
        stmt = stmt.where(Organization.status == filters.status)
    if filters.name_contains:
        stmt = stmt.where(
            Organization.name.ilike(f"%{filters.name_contains.lower()}%")
        )
    if filters.slug_contains:
        stmt = stmt.where(
            Organization.slug.ilike(f"%{filters.slug_contains.lower()}%")
        )
    if filters.subscription_plan:
        stmt = stmt.where(
            Organization.subscription_plan == filters.subscription_plan
        )

    total = (
        db.execute(select(func.count()).select_from(stmt.subquery()))
        .scalar_one()
    )

    stmt = (
        stmt.order_by(Organization.created_at.desc(), Organization.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )

    orgs = list(db.execute(stmt).scalars().all())
    return orgs, int(total)


# ============================================================================
# UPDATE
# ============================================================================

def update_organization(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    payload: OrganizationUpdate,
    request: Any | None = None,
) -> Organization:
    """
    Update mutable fields of an organization.

    Requires ``PERM_ORG_UPDATE`` in the organization's scope. Everyone
    with role ADMIN or OWNER has it; SECURITY_MANAGER and below do not.

    Cannot change:
        - ``slug`` — immutable (schema does not allow it)
        - ``owner_id`` — dedicated ownership-transfer flow (future)
        - ``status`` — dedicated archive/suspend/unsuspend methods
        - ``subscription_plan`` — billing endpoint
    """
    authorization.check_permission(
        db, actor, PERM_ORG_UPDATE, organization_id=organization.id,
    )

    before = _snapshot_state(organization)

    # Apply only fields that were explicitly provided. The schema
    # uses `extra="forbid"` so unknown fields are rejected before we
    # even reach here.
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return organization  # no-op, but valid

    for field, value in updates.items():
        setattr(organization, field, value)

    db.flush()
    after = _snapshot_state(organization)

    audit_service.log_state_change(
        db,
        actor=actor,
        action="organization.updated",
        target_type="organization",
        target_id=organization.id,
        target_display=organization.slug,
        organization_id=organization.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Organization updated",
        extra={
            "organization_id": str(organization.id),
            "fields_changed": list(updates.keys()),
            "actor_id": str(actor.id),
        },
    )

    return organization


# ============================================================================
# LIFECYCLE — ARCHIVE
# ============================================================================

def archive_organization(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    request: Any | None = None,
) -> Organization:
    """
    Archive an organization. Sets ``status=ARCHIVED``.

    Archival is the closest thing to "delete" in the platform —
    deletes are soft only, and only after the retention window does
    the background job actually remove rows. Requires
    ``PERM_ORG_DELETE`` (OWNER only).

    Idempotent — archiving an already-archived org is a no-op.
    """
    authorization.check_permission(
        db, actor, PERM_ORG_DELETE, organization_id=organization.id,
    )

    if organization.status == OrganizationStatus.ARCHIVED:
        return organization

    if organization.status == OrganizationStatus.SUSPENDED:
        # Cannot archive a suspended org directly — admin must unsuspend
        # first (or the retention policy must handle suspended orgs).
        # This is a policy decision: suspended orgs may be under active
        # investigation, and the archive operation would race with that.
        raise InvalidStateTransitionError(
            message=(
                "Cannot archive a suspended organization. Contact a "
                "super admin to unsuspend first."
            ),
            code="ORGANIZATION_SUSPENDED_CANNOT_ARCHIVE",
            details={"status": organization.status.value},
        )

    before = {"status": organization.status.value}
    organization.status = OrganizationStatus.ARCHIVED
    db.flush()
    after = {"status": organization.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="organization.archived",
        target_type="organization",
        target_id=organization.id,
        target_display=organization.slug,
        organization_id=organization.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Organization archived",
        extra={
            "organization_id": str(organization.id),
            "actor_id": str(actor.id),
        },
    )

    return organization


# ============================================================================
# LIFECYCLE — SUSPEND / UNSUSPEND (super admin)
# ============================================================================

def suspend_organization(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    reason: str,
    request: Any | None = None,
) -> Organization:
    """
    Suspend an organization. **Super-admin only.**

    Requires ``PERM_ADMIN_ORG_SUSPEND``. This permission currently
    fails closed — no one is a super admin yet. When the super admin
    column is added, this becomes usable without code changes.

    Suspension is a security action: it should be used for policy
    violations, abuse, or compliance holds. A suspended org's users
    can still log in (authentication is platform-wide), but every
    org-scoped operation (create case, upload evidence, etc.) is
    rejected by ``authorization`` because their membership's ``status``
    is tied to the org.

    Raises
    ------
    AuthorizationError
        If the actor is not a super admin (currently: everyone).
    InvalidStateTransitionError
        If the org is already archived or suspended.
    """
    authorization.check_permission(db, actor, PERM_ADMIN_ORG_SUSPEND)

    if organization.status == OrganizationStatus.ARCHIVED:
        raise InvalidStateTransitionError(
            message="Cannot suspend an archived organization.",
            code="ORGANIZATION_ARCHIVED_CANNOT_SUSPEND",
            details={"status": organization.status.value},
        )
    if organization.status == OrganizationStatus.SUSPENDED:
        return organization  # idempotent

    if not reason or not reason.strip():
        raise ValidationError(
            message="Suspension reason is required.",
            code="ORGANIZATION_SUSPEND_REASON_REQUIRED",
        )

    before = {"status": organization.status.value}
    organization.status = OrganizationStatus.SUSPENDED
    db.flush()
    after = {"status": organization.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="organization.suspended",
        target_type="organization",
        target_id=organization.id,
        target_display=organization.slug,
        organization_id=organization.id,
        before_state=before,
        after_state=after,
        notes=reason.strip(),
        request=request,
    )

    logger.warning(
        "Organization suspended",
        extra={
            "organization_id": str(organization.id),
            "actor_id": str(actor.id),
            "reason": reason.strip()[:200],
        },
    )

    return organization


def unsuspend_organization(
    db: Session,
    *,
    actor: User,
    organization: Organization,
    request: Any | None = None,
) -> Organization:
    """
    Lift a suspension. **Super-admin only.** Requires
    ``PERM_ADMIN_ORG_SUSPEND`` — the same permission that gates suspend.
    """
    authorization.check_permission(db, actor, PERM_ADMIN_ORG_SUSPEND)

    if organization.status != OrganizationStatus.SUSPENDED:
        raise InvalidStateTransitionError(
            message=(
                f"Organization is not suspended (status: "
                f"{organization.status.value})."
            ),
            code="ORGANIZATION_NOT_SUSPENDED",
            details={"status": organization.status.value},
        )

    before = {"status": organization.status.value}
    organization.status = OrganizationStatus.ACTIVE
    db.flush()
    after = {"status": organization.status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="organization.unsuspended",
        target_type="organization",
        target_id=organization.id,
        target_display=organization.slug,
        organization_id=organization.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Organization unsuspended",
        extra={
            "organization_id": str(organization.id),
            "actor_id": str(actor.id),
        },
    )

    return organization


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Create
    "create_organization",
    # Read
    "get_by_id",
    "get_by_slug",
    "get_by_slug_optional",
    "list_user_organizations",
    "list_all_organizations",
    # Update
    "update_organization",
    # Lifecycle
    "archive_organization",
    "suspend_organization",
    "unsuspend_organization",
]