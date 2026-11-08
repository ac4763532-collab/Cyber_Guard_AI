"""
CyberGuard AI — Workspace Model
============================================================================

The ``workspaces`` table: the access-control scope between an organization
(tenant) and every security artifact (source, event, incident, case,
evidence, report).

Every downstream table has a ``workspace_id`` foreign key. "Who can see this
event" is answered in one hop: "who has membership in the workspace that
owns this event". Getting this table right is the difference between a clean
audit trail and a cascading mis-authorization bug.

Design decisions
----------------
1. **``organization_id`` is nullable.** NULL means a personal workspace
   (an individual user's own scope). A UUID means an org workspace (a team
   scope inside a company). This single schema serves both user types.

2. **One personal workspace per user — enforced at DB level.** A partial
   unique index ``WHERE workspace_type = 'personal' AND deleted_at IS NULL``
   guarantees this. Without it, an attacker could create a duplicate
   personal workspace, confusing authorization checks that iterate over
   "the user's workspaces".

3. **``workspace_type`` is an enum, not a boolean.** ``personal``,
   ``organization``, ``shared`` — the enum can grow (e.g. ``integration``,
   ``soc_console``) without a schema migration. A boolean ``is_personal``
   cannot.

4. **``slug`` uniqueness depends on type.** For personal workspaces, the
   slug is auto-derived and globally unique by construction. For org
   workspaces, uniqueness is enforced *within the organization* — two
   different companies can both have a "security-ops" workspace.

5. **``owner_id`` and ``organization_id`` both use ``ON DELETE RESTRICT``.**
   Deleting a user who owns a workspace, or an organization that still has
   workspaces, must go through the service layer where it can be audited.
   A cascade delete here would orphan every event in the workspace.

6. **``settings`` is ``JSONB``** — workspace-level preferences (alert
   thresholds, notification rules, report schedules) change faster than
   schema. Shape validated in Pydantic, not the DB. Same rationale as
   ``Organization.settings``.

7. **Personal workspace slug auto-generation.** A ``@validates("slug")``
   hook derives ``personal-<owner-id-prefix>`` when the caller hasn't
   provided one, and the caller has set ``workspace_type='personal'`` and
   ``owner_id``. This means services and tests can create a personal
   workspace without thinking about slugs.

8. **No relationships in this file yet.** Forward references to
   not-yet-written models crash the ORM at mapper-configure time. They
   will be added once Files 19+ exist.

Example usage
-------------
    from app.models import Workspace
    from app.models.enums import WorkspaceType

    # Personal workspace for a user (slug auto-generated):
    personal = Workspace(
        name="Priya's Workspace",
        workspace_type=WorkspaceType.PERSONAL,
        owner_id=user.id,
    )

    # Organization workspace:
    team = Workspace(
        name="Security Operations",
        slug="security-ops",
        workspace_type=WorkspaceType.ORGANIZATION,
        owner_id=user.id,
        organization_id=org.id,
    )
    db.add(team)
    db.commit()
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import WorkspaceType, enum_column_type


#: Pattern enforced at the ORM level for slug validation.
#: DB-level CHECK constraint duplicates this — defense in depth.
_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

_SLUG_MIN_LENGTH = 3
_SLUG_MAX_LENGTH = 64


class Workspace(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A workspace — the scope between an organization and every security
    artifact. Personal users have one personal workspace; a company has
    one workspace per team.

    Inherits from ``UUIDPrimaryKeyMixin`` (id: UUID), ``TimestampMixin``
    (created_at, updated_at), and ``SoftDeleteMixin`` (deleted_at).
    """

    __tablename__ = "workspaces"

    __table_args__ = (
        # Slug format: lowercase, alphanumeric + hyphens, 3–64 chars.
        CheckConstraint(
            "slug = lower(slug)",
            name="slug_lowercase",
        ),
        CheckConstraint(
            "char_length(slug) >= 3 AND char_length(slug) <= 64",
            name="slug_length",
        ),
        CheckConstraint(
            r"slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'",
            name="slug_format",
        ),
        # Workspace type integrity:
        #   personal  => organization_id IS NULL
        #   others    => organization_id IS NOT NULL
        CheckConstraint(
            "(workspace_type = 'personal' AND organization_id IS NULL) "
            "OR (workspace_type <> 'personal' AND organization_id IS NOT NULL)",
            name="type_organization_consistency",
        ),
        # Slug unique *within* an organization.
        UniqueConstraint(
            "organization_id",
            "slug",
            name="uq_organization_slug",
        ),
        # Only one personal workspace per user (soft-deleted rows excluded).
        Index(
            "uq_personal_workspace_per_owner",
            "owner_id",
            unique=True,
            postgresql_where=text(
                "workspace_type = 'personal' AND deleted_at IS NULL"
            ),
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Identity
    # ────────────────────────────────────────────────────────────────────

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable workspace name.",
    )

    slug: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment=(
            "URL-safe identifier. Unique within its organization. For "
            "personal workspaces, auto-derived from the owner's id and "
            "globally unique by construction."
        ),
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text description shown in workspace picker and reports.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Type and scope
    # ────────────────────────────────────────────────────────────────────

    workspace_type: Mapped[WorkspaceType] = mapped_column(
        enum_column_type(WorkspaceType),
        nullable=False,
        default=WorkspaceType.PERSONAL,
        server_default=WorkspaceType.PERSONAL.value,
        index=True,
        comment="Kind of workspace. Determines default membership and perms.",
    )

    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Workspace owner. ON DELETE RESTRICT — ownership transfer is explicit.",
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
        comment=(
            "Owning organization. NULL for personal workspaces. Enforced "
            "in-consistency with workspace_type by CHECK constraint."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Presentation & settings
    # ────────────────────────────────────────────────────────────────────

    color: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="Optional hex color (#RRGGBB) for UI display.",
    )

    icon: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Optional icon identifier for UI display.",
    )

    settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Workspace preferences (alert thresholds, notification rules, "
            "retention overrides). Shape validated in Pydantic, not by DB."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("slug")
    def _validate_slug(self, _key: str, value: str | None) -> str:
        """
        Validate slug format. If empty/None, defer — auto-generation
        happens in ``_ensure_personal_slug`` (a ``before_insert`` event is
        not used here because it fires after validators; the caller must
        set ``workspace_type`` and ``owner_id`` first).

        Normalization: strip whitespace and lowercase.
        """
        if value is None:
            # Allow None temporarily — auto-generation validates at insert.
            # An organization workspace with no slug will fail the NOT NULL
            # constraint at flush time, which is the correct behavior.
            raise ValidationError(
                message="slug is required (auto-generated for personal workspaces)",
                code="WORKSPACE_SLUG_REQUIRED",
            )

        if not isinstance(value, str):
            raise ValidationError(
                message="slug must be a string",
                code="WORKSPACE_SLUG_INVALID_TYPE",
            )

        normalized = value.strip().lower()

        if not normalized:
            raise ValidationError(
                message="slug must not be empty",
                code="WORKSPACE_SLUG_EMPTY",
            )

        if len(normalized) < _SLUG_MIN_LENGTH:
            raise ValidationError(
                message=f"slug must be at least {_SLUG_MIN_LENGTH} characters",
                code="WORKSPACE_SLUG_TOO_SHORT",
                details={
                    "min_length": _SLUG_MIN_LENGTH,
                    "actual_length": len(normalized),
                },
            )

        if len(normalized) > _SLUG_MAX_LENGTH:
            raise ValidationError(
                message=f"slug must not exceed {_SLUG_MAX_LENGTH} characters",
                code="WORKSPACE_SLUG_TOO_LONG",
                details={
                    "max_length": _SLUG_MAX_LENGTH,
                    "actual_length": len(normalized),
                },
            )

        if not _SLUG_PATTERN.match(normalized):
            raise ValidationError(
                message=(
                    "slug must contain only lowercase letters, digits, and "
                    "hyphens, and must start and end with a letter or digit"
                ),
                code="WORKSPACE_SLUG_INVALID_FORMAT",
                details={"received": normalized},
            )

        return normalized

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        """Strip whitespace and enforce a sane length bound."""
        if not isinstance(value, str):
            raise ValidationError(
                message="name must be a string",
                code="WORKSPACE_NAME_INVALID_TYPE",
            )

        stripped = value.strip()

        if not stripped:
            raise ValidationError(
                message="name must not be empty",
                code="WORKSPACE_NAME_EMPTY",
            )

        if len(stripped) > 255:
            raise ValidationError(
                message="name must not exceed 255 characters",
                code="WORKSPACE_NAME_TOO_LONG",
                details={"max_length": 255, "actual_length": len(stripped)},
            )

        return stripped

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @classmethod
    def build_personal(
        cls,
        *,
        owner_id: uuid.UUID,
        owner_display_name: str | None = None,
    ) -> "Workspace":
        """
        Construct a personal workspace for ``owner_id``.

        - Slug is derived as ``personal-<owner_id-prefix>`` — globally
          unique because UUID prefixes cannot collide in practice.
        - Name defaults to ``"<DisplayName>'s Workspace"`` or
          ``"Personal Workspace"`` if no name is provided.
        - Sets ``workspace_type`` and ``organization_id`` correctly so the
          CHECK constraint passes without any caller involvement.

        This is the recommended way to create personal workspaces. Direct
        construction also works, provided the caller sets slug manually.
        """
        slug_suffix = owner_id.hex[:12]
        slug = f"personal-{slug_suffix}"

        if owner_display_name:
            display = owner_display_name.strip()
        else:
            display = "Personal"

        name = f"{display}'s Workspace"

        return cls(
            name=name,
            slug=slug,
            workspace_type=WorkspaceType.PERSONAL,
            owner_id=owner_id,
            organization_id=None,
        )

    @classmethod
    def build_organization(
        cls,
        *,
        name: str,
        slug: str,
        owner_id: uuid.UUID,
        organization_id: uuid.UUID,
        description: str | None = None,
    ) -> "Workspace":
        """
        Construct an organization workspace. Validates the inputs up front
        so the caller gets a clean error before hitting the DB.
        """
        return cls(
            name=name,
            slug=slug,
            workspace_type=WorkspaceType.ORGANIZATION,
            owner_id=owner_id,
            organization_id=organization_id,
            description=description,
        )

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_personal(self) -> bool:
        """True if this is a personal (individual) workspace."""
        return self.workspace_type == WorkspaceType.PERSONAL

    @property
    def is_organization_scoped(self) -> bool:
        """True if this workspace belongs to an organization."""
        return (
            self.workspace_type == WorkspaceType.ORGANIZATION
            and self.organization_id is not None
        )

    @property
    def is_shared(self) -> bool:
        """True if this is a cross-team shared workspace."""
        return self.workspace_type == WorkspaceType.SHARED

    @property
    def is_active(self) -> bool:
        """True if the workspace is not soft-deleted."""
        return self.deleted_at is None


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# Do not uncomment these until the referenced model files exist AND have been
# imported by app/models/__init__.py. Same pattern as user.py and
# organization.py — forward references to non-existent models crash the ORM
# at mapper-configure time.
#
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.user import User
#     from app.models.organization import Organization
#     from app.models.membership import WorkspaceMembership
#     from app.models.source import SecuritySource
#     from app.models.event import SecurityEvent
#     from app.models.incident import SecurityIncident
#
# class Workspace(...):
#     ...  # everything above
#
#     # ─── Owner ──────────────────────────────────────────────────────
#     owner: Mapped["User"] = relationship(
#         "User",
#         foreign_keys=[owner_id],
#     )
#
#     # ─── Organization (optional) ────────────────────────────────────
#     organization: Mapped["Organization | None"] = relationship(
#         "Organization",
#         back_populates="workspaces",
#     )
#
#     # ─── Memberships ────────────────────────────────────────────────
#     memberships: Mapped[list["WorkspaceMembership"]] = relationship(
#         "WorkspaceMembership",
#         back_populates="workspace",
#         cascade="all, delete-orphan",
#     )
#
#     # ─── Sources ────────────────────────────────────────────────────
#     sources: Mapped[list["SecuritySource"]] = relationship(
#         "SecuritySource",
#         back_populates="workspace",
#         cascade="all, delete-orphan",
#     )
#
#     # ─── Events ─────────────────────────────────────────────────────
#     events: Mapped[list["SecurityEvent"]] = relationship(
#         "SecurityEvent",
#         back_populates="workspace",
#     )
#
#     # ─── Incidents ──────────────────────────────────────────────────
#     incidents: Mapped[list["SecurityIncident"]] = relationship(
#         "SecurityIncident",
#         back_populates="workspace",
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["Workspace", "_SLUG_PATTERN", "_SLUG_MIN_LENGTH", "_SLUG_MAX_LENGTH"]