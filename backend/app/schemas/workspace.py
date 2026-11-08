"""
CyberGuard AI — Workspace Schemas
============================================================================

Request/response DTOs for the ``workspaces`` table.

Design rules
------------
1. **``workspace_type`` is set by the service, not by clients.**
   Personal workspaces are auto-created on user registration.
   Organization workspaces are created via an org-scoped endpoint.
   ``WorkspaceCreate`` does not expose ``workspace_type`` — the
   endpoint picks it based on the URL (``/workspaces`` → personal,
   ``/organizations/{id}/workspaces`` → org-scoped).

2. **Slug auto-generated for personal workspaces.**
   Personal workspaces always use ``personal-<owner-id-prefix>``. The
   ``WorkspaceCreate`` schema does not accept ``slug`` for personal
   workspaces — the service computes it. Org workspaces require a
   client-supplied slug.

3. **``owner_id`` and ``organization_id`` not settable by clients.**
   ``owner_id`` = current user. ``organization_id`` = from URL path.

4. **``slug`` immutable after creation.**
   Same reasoning as organizations — changing it would break URLs and
   references.

5. **Computed booleans on Read** — ``is_personal``,
   ``is_organization_scoped``, ``is_shared``, ``is_active``.

6. **Lightweight list view** — enough for a workspace switcher.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Literal

from pydantic import Field, field_validator

from app.models.enums import WorkspaceType
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_SLUG_MIN = 3
_SLUG_MAX = 64
_NAME_MAX = 255
_DESCRIPTION_MAX = 1000
_COLOR_MAX = 16
_ICON_MAX = 64

#: Hex color pattern — ``#RRGGBB`` or ``#RRGGBBAA``.
_COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$")

#: Known keys in the ``settings`` JSONB. Validation is permissive for
#: now — unknown keys pass through. Tighten when the workspace settings
#: schema stabilizes.
_ALLOWED_SETTING_KEYS = frozenset({
    "alert_severity_threshold",
    "notification_email_enabled",
    "default_retention_events_days",
    "brand_color",
    "pinned_incident_ids",
})


# ============================================================================
# CREATE
# ============================================================================

class WorkspaceCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /workspaces`` (personal) or
    ``POST /organizations/{org_id}/workspaces`` (org-scoped).

    ``workspace_type``, ``owner_id``, ``organization_id`` are set by
    the service based on the endpoint, not by the client.

    ``slug`` is required for organization workspaces, forbidden for
    personal ones (auto-generated). The schema accepts either but the
    service enforces per-type rules.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=_NAME_MAX,
        description="Display name.",
        examples=["Security Operations"],
    )

    slug: str | None = Field(
        default=None,
        min_length=_SLUG_MIN,
        max_length=_SLUG_MAX,
        description=(
            "URL-safe identifier. Required for organization workspaces. "
            "Forbidden (must be omitted) for personal workspaces — the "
            "service auto-generates one."
        ),
        examples=["security-ops"],
    )

    description: str | None = Field(
        default=None,
        max_length=_DESCRIPTION_MAX,
    )

    color: str | None = Field(
        default=None,
        max_length=_COLOR_MAX,
        description="Hex color for UI display (#RRGGBB or #RRGGBBAA).",
    )

    icon: str | None = Field(
        default=None,
        max_length=_ICON_MAX,
        description="Icon identifier for UI display.",
    )

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("slug", mode="before")
    @classmethod
    def _validate_slug(cls, v: object) -> object:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("slug must be a string or null")
        normalized = v.strip().lower()
        if not normalized:
            return None
        if not (_SLUG_MIN <= len(normalized) <= _SLUG_MAX):
            raise ValueError(
                f"slug must be {_SLUG_MIN}–{_SLUG_MAX} characters"
            )
        if not _SLUG_PATTERN.match(normalized):
            raise ValueError(
                "slug must contain only lowercase letters, digits, and "
                "hyphens, starting and ending with a letter or digit"
            )
        return normalized

    @field_validator("color")
    @classmethod
    def _validate_color(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            return None
        if not _COLOR_PATTERN.match(stripped):
            raise ValueError(
                "color must be a hex value like '#3B82F6' or '#3B82F6FF'"
            )
        return stripped.lower()


# ============================================================================
# READ
# ============================================================================

class WorkspaceRead(TimestampedModel):
    """
    Full workspace view. Returned by ``GET /workspaces/{id}`` and
    mutation endpoints.
    """

    id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    workspace_type: WorkspaceType

    owner_id: uuid.UUID
    organization_id: uuid.UUID | None = None

    color: str | None = None
    icon: str | None = None

    settings: dict[str, Any] = Field(default_factory=dict)

    # Computed from ORM properties
    is_personal: bool = Field(
        ..., description="True if this is a personal (individual) workspace."
    )
    is_organization_scoped: bool = Field(
        ..., description="True if the workspace belongs to an organization."
    )
    is_shared: bool = Field(
        ..., description="True if this is a cross-team shared workspace."
    )
    is_active: bool = Field(
        ..., description="True if the workspace is not soft-deleted."
    )


class WorkspaceList(ORMModel):
    """
    Lightweight workspace view for a workspace switcher or sidebar.

    Only 6 fields. For full details, fetch ``GET /workspaces/{id}``.
    """

    id: uuid.UUID
    name: str
    slug: str
    workspace_type: WorkspaceType
    organization_id: uuid.UUID | None = None
    color: str | None = None
    icon: str | None = None


# ============================================================================
# UPDATE
# ============================================================================

class WorkspaceUpdate(CyberGuardBaseSchema):
    """
    Fields a workspace owner/admin can change. Every field optional.

    Cannot change:
        - ``slug`` — immutable
        - ``workspace_type`` — set at creation, never changes
        - ``owner_id`` — ownership transfer is a dedicated flow
        - ``organization_id`` — set at creation
    """

    name: str | None = Field(default=None, min_length=1, max_length=_NAME_MAX)
    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)
    color: str | None = Field(default=None, max_length=_COLOR_MAX)
    icon: str | None = Field(default=None, max_length=_ICON_MAX)
    settings: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Merged with existing settings (not replaced). To remove a "
            "key, pass it with a null value."
        ),
    )

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("color")
    @classmethod
    def _validate_color(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            return None
        if not _COLOR_PATTERN.match(stripped):
            raise ValueError(
                "color must be a hex value like '#3B82F6' or '#3B82F6FF'"
            )
        return stripped.lower()


# ============================================================================
# FILTER
# ============================================================================

class WorkspaceFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /workspaces``.
    """

    workspace_type: WorkspaceType | None = Field(
        default=None,
        description="Filter by workspace type.",
    )

    organization_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to workspaces belonging to a specific organization.",
    )

    name_contains: str | None = Field(
        default=None,
        max_length=_NAME_MAX,
        description="Case-insensitive substring match on name.",
    )

    @field_validator("name_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "WorkspaceCreate",
    "WorkspaceRead",
    "WorkspaceList",
    "WorkspaceUpdate",
    "WorkspaceFilter",
]