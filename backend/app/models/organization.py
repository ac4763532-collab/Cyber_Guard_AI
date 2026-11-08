"""
CyberGuard AI — Organization Model
============================================================================

The ``organizations`` table: the tenant boundary for company accounts.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    String,
    Text,
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
from app.models.enums import OrganizationStatus, enum_column_type


_SLUG_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

_COMPANY_SIZE_VALUES = (
    "solo",
    "small",
    "medium",
    "large",
    "enterprise",
    "enterprise_plus",
)


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A company or team organization."""

    __tablename__ = "organizations"

    __table_args__ = (
        CheckConstraint("slug = lower(slug)", name="slug_lowercase"),
        CheckConstraint(
            "char_length(slug) >= 3 AND char_length(slug) <= 64",
            name="slug_length",
        ),
        CheckConstraint(
            r"slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'",
            name="slug_format",
        ),
        CheckConstraint(
            "company_size IS NULL OR company_size IN ("
            "'solo', 'small', 'medium', 'large', 'enterprise', 'enterprise_plus'"
            ")",
            name="company_size_values",
        ),
    )

    # ─── Identity ───────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    slug: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False,
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ─── Status & ownership ─────────────────────────────────────────────
    status: Mapped[OrganizationStatus] = mapped_column(
        enum_column_type(OrganizationStatus),
        nullable=False,
        default=OrganizationStatus.PENDING_APPROVAL,
        server_default=OrganizationStatus.PENDING_APPROVAL.value,
        index=True,
    )

    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # ─── Contact & profile ──────────────────────────────────────────────
    contact_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    website: Mapped[str | None] = mapped_column(String(512), nullable=True)
    industry: Mapped[str | None] = mapped_column(String(128), nullable=True)
    company_size: Mapped[str | None] = mapped_column(String(32), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)

    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="UTC",
    )

    logo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # ─── Subscription & settings ────────────────────────────────────────
    subscription_plan: Mapped[str] = mapped_column(
        String(32), nullable=False, default="free", server_default="free",
    )

    settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("slug")
    def _validate_slug(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="slug must be a string",
                code="ORG_SLUG_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not normalized:
            raise ValidationError(
                message="slug must not be empty",
                code="ORG_SLUG_EMPTY",
            )
        if len(normalized) < 3:
            raise ValidationError(
                message="slug must be at least 3 characters",
                code="ORG_SLUG_TOO_SHORT",
                details={"min_length": 3, "actual_length": len(normalized)},
            )
        if len(normalized) > 64:
            raise ValidationError(
                message="slug must not exceed 64 characters",
                code="ORG_SLUG_TOO_LONG",
                details={"max_length": 64, "actual_length": len(normalized)},
            )
        if not _SLUG_PATTERN.match(normalized):
            raise ValidationError(
                message=(
                    "slug must contain only lowercase letters, digits, and "
                    "hyphens, and must start and end with a letter or digit"
                ),
                code="ORG_SLUG_INVALID_FORMAT",
                details={"received": normalized},
            )
        return normalized

    @validates("name")
    def _validate_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="name must be a string",
                code="ORG_NAME_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="name must not be empty",
                code="ORG_NAME_EMPTY",
            )
        if len(stripped) > 255:
            raise ValidationError(
                message="name must not exceed 255 characters",
                code="ORG_NAME_TOO_LONG",
                details={"max_length": 255, "actual_length": len(stripped)},
            )
        return stripped

    @validates("company_size")
    def _validate_company_size(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in _COMPANY_SIZE_VALUES:
            raise ValidationError(
                message="company_size must be one of: " + ", ".join(_COMPANY_SIZE_VALUES),
                code="ORG_COMPANY_SIZE_INVALID",
                details={"received": value, "allowed": list(_COMPANY_SIZE_VALUES)},
            )
        return value

    @validates("country")
    def _validate_country(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or len(value.strip()) != 2:
            raise ValidationError(
                message="country must be an ISO 3166-1 alpha-2 code (2 letters)",
                code="ORG_COUNTRY_INVALID",
            )
        return value.strip().upper()

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_active(self) -> bool:
        return self.status == OrganizationStatus.ACTIVE and self.deleted_at is None

    @property
    def is_suspended(self) -> bool:
        return self.status == OrganizationStatus.SUSPENDED

    @property
    def is_archived(self) -> bool:
        return self.status == OrganizationStatus.ARCHIVED


__all__ = ["Organization", "_COMPANY_SIZE_VALUES"]