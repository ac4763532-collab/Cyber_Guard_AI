"""
CyberGuard AI — Analyst Profile Model
============================================================================

The ``analyst_profiles`` table: a 1:1 extension of ``users`` that marks a
user as a security analyst.

A user **without** a row here is a normal user (personal or employee).
A user **with** a row here is a security analyst — pending verification,
in review, verified, rejected, suspended, or expired.

This is the record that the marketplace, the analyst workspace, case
assignment, and the super-admin verification workflow all hinge on.

Design decisions
----------------
1. **1:1 with ``users`` via ``UNIQUE`` on ``user_id``.** A user has at most
   one analyst profile. Enforced at the DB level — critical because the
   entire "who is an analyst?" question then has exactly one answer.

2. **No ``SoftDeleteMixin``.** Analysts are not deleted — their
   ``verification_status`` reflects reality (``PENDING``, ``IN_REVIEW``,
   ``VERIFIED``, ``REJECTED``, ``SUSPENDED``, ``EXPIRED``). If an analyst
   stops offering services, they toggle ``available_for_hire = False`` and
   stay ``VERIFIED``. Re-applying after rejection means resetting status
   to ``PENDING`` and updating documents — no row deletion needed.

3. **Money in integer cents.** ``hourly_rate_cents`` is ``INTEGER``, never
   float. Currency is 3-letter ISO 4217 with a ``CHECK`` constraint.
   This blocks a class of rounding bugs in payment calculations.

4. **Specializations, certifications, languages, verification docs are
   JSONB.** The analyst taxonomy and certification schema evolve
   constantly. JSONB with model-level shape validation + Pydantic schema
   validation at the API boundary is the right pattern. A GIN index on
   ``specializations`` enables ``@>`` queries ("find all phishing
   specialists") without a join table.

5. **Denormalized rating aggregates.** ``rating_average`` and
   ``rating_count`` are maintained by the marketplace service on every
   review submission. Source of truth is future ``service_reviews`` table.
   Denormalization is required because ``AVG(rating)`` on every listing
   page would be too slow.

6. **Workload counters.** ``active_case_count``,
   ``max_concurrent_cases``, and ``total_cases_completed`` drive case
   assignment routing. ``active_case_count`` is maintained
   transactionally when cases are assigned and closed.

7. **``verified_by_id`` → ``users.id`` with ``ON DELETE SET NULL``.**
   Attribution preserved in the audit log even after the super-admin's
   account is hard-deleted.

8. **``can_accept_cases`` property is the single assignment gate.**
   Composes ``is_verified``, ``available_for_hire``, and
   ``active_case_count < max_concurrent_cases``. All three must be true.

9. **``working_timezone`` is separate from ``user.timezone``.**
   Analysts may work 9am–5pm IST while personally living in UTC. Reports,
   SLAs, and availability windows use ``working_timezone``.

Usage
-----
    from app.models import AnalystProfile
    from app.models.enums import AnalystVerificationStatus

    # An analyst applies
    profile = AnalystProfile.build_application(
        user_id=user.id,
        display_name="Rahul Verma",
        headline="Phishing & email-forensics specialist",
        specializations=["phishing", "email_forensics"],
        years_of_experience=6,
        hourly_rate_cents=49900,  # ₹499 or $499 depending on currency
        currency="INR",
        languages=["en", "hi"],
        working_timezone="Asia/Kolkata",
    )
    db.add(profile)
    db.commit()

    # Super admin approves
    profile.verification_status = AnalystVerificationStatus.VERIFIED
    profile.verification_completed_at = datetime.now(timezone.utc)
    profile.verified_by_id = admin.id
    profile.available_for_hire = True
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import ValidationError
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import AnalystVerificationStatus, enum_column_type


#: Reasonable bounds enforced at both ORM and DB level.
_MAX_HOURLY_RATE_CENTS = 100_000_000  # 1,000,000 USD — anything above is a typo
_MAX_YEARS_OF_EXPERIENCE = 60
_MAX_SPECIALIZATIONS = 20
_MAX_CERTIFICATIONS = 50
_MAX_LANGUAGES = 20
_MAX_VERIFICATION_DOCUMENTS = 20
_MAX_DISPLAY_NAME_LENGTH = 120
_MAX_HEADLINE_LENGTH = 200
_MAX_BIO_LENGTH = 5000


class AnalystProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A security analyst's profile, extending their ``users`` record.

    Presence of this row indicates "this user is a security analyst". The
    row's ``verification_status`` indicates *where they are* in the
    verification lifecycle.
    """

    __tablename__ = "analyst_profiles"

    __table_args__ = (
        # Money: non-negative, capped, ISO 4217 currency code.
        CheckConstraint(
            "hourly_rate_cents IS NULL OR "
            "hourly_rate_cents >= 0 AND hourly_rate_cents <= 100000000",
            name="hourly_rate_range",
        ),
        CheckConstraint(
            "currency IS NULL OR char_length(currency) = 3",
            name="currency_iso_4217",
        ),
        # Years of experience
        CheckConstraint(
            "years_of_experience IS NULL OR "
            "years_of_experience >= 0 AND years_of_experience <= 60",
            name="years_of_experience_range",
        ),
        # Ratings 0.00 to 5.00
        CheckConstraint(
            "rating_average IS NULL OR "
            "rating_average >= 0 AND rating_average <= 5",
            name="rating_average_range",
        ),
        CheckConstraint(
            "rating_count >= 0",
            name="rating_count_non_negative",
        ),
        # Workload
        CheckConstraint(
            "active_case_count >= 0",
            name="active_case_count_non_negative",
        ),
        CheckConstraint(
            "max_concurrent_cases >= 1",
            name="max_concurrent_cases_positive",
        ),
        CheckConstraint(
            "total_cases_completed >= 0",
            name="total_cases_completed_non_negative",
        ),
        # Verification timestamps must be consistent with status.
        CheckConstraint(
            "verification_status <> 'verified' OR verification_completed_at IS NOT NULL",
            name="verified_requires_completion_timestamp",
        ),
        # GIN index on specializations for @> queries.
        Index(
            "ix_analyst_profiles_specializations_gin",
            "specializations",
            postgresql_using="gin",
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Link to user (1:1)
    # ────────────────────────────────────────────────────────────────────

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
        comment="The user who owns this analyst profile. 1:1 with users.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Verification lifecycle
    # ────────────────────────────────────────────────────────────────────

    verification_status: Mapped[AnalystVerificationStatus] = mapped_column(
        enum_column_type(AnalystVerificationStatus),
        nullable=False,
        default=AnalystVerificationStatus.PENDING,
        server_default=AnalystVerificationStatus.PENDING.value,
        index=True,
        comment="Current state in the analyst verification workflow.",
    )

    verification_submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        comment="When the application was first submitted. Updated on re-apply.",
    )

    verification_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the final decision (approve/reject) was recorded.",
    )

    verified_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Super admin who approved. NULL after that user is hard-deleted.",
    )

    verification_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Internal notes visible to admins only (never to the analyst).",
    )

    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason sent to the analyst when status is REJECTED.",
    )

    verification_documents: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "List of {type, url, uploaded_at} objects. Files live in "
            "static/uploads/verification/. Shape validated by Pydantic."
        ),
    )

    # ────────────────────────────────────────────────────────────────────
    # Public marketplace profile
    # ────────────────────────────────────────────────────────────────────

    display_name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        comment="Public display name for marketplace listings and case cards.",
    )

    headline: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
        comment="One-line tagline shown on marketplace listing cards.",
    )

    bio: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Long-form bio shown on the analyst's public profile page.",
    )

    specializations: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "List of specialization tags (e.g. phishing, malware, "
            "network_forensics). GIN-indexed for @> queries."
        ),
    )

    certifications: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "List of {name, issuer, issued_year, credential_url} objects. "
            "Displayed on public profile."
        ),
    )

    languages: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="BCP 47 language tags the analyst can work in (e.g. ['en', 'hi']).",
    )

    years_of_experience: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Total years of professional security experience.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Pricing & availability
    # ────────────────────────────────────────────────────────────────────

    hourly_rate_cents: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment=(
            "Hourly rate in cents. Nullable — analysts can publish "
            "fixed-price service offerings instead of hourly rates."
        ),
    )

    currency: Mapped[str | None] = mapped_column(
        String(3),
        nullable=True,
        comment="ISO 4217 currency code for hourly_rate_cents (e.g. 'USD', 'INR').",
    )

    available_for_hire: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment=(
            "Whether the analyst accepts new cases. Distinct from "
            "verification status — a verified analyst may pause intake."
        ),
    )

    working_timezone: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="UTC",
        server_default="UTC",
        comment="IANA timezone the analyst works in. Distinct from user.timezone.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Workload counters (maintained transactionally by case service)
    # ────────────────────────────────────────────────────────────────────

    max_concurrent_cases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=10,
        server_default="10",
        comment="Maximum simultaneously active cases before assignment is blocked.",
    )

    active_case_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Cases currently in an active status. Maintained by the case service.",
    )

    total_cases_completed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Lifetime completed cases. Incremented on case closure.",
    )

    # ────────────────────────────────────────────────────────────────────
    # Ratings (maintained by marketplace service on review submission)
    # ────────────────────────────────────────────────────────────────────

    rating_average: Mapped[Decimal | None] = mapped_column(
        Numeric(3, 2),
        nullable=True,
        comment="Average rating (0.00 to 5.00). NULL until first review. Denormalized.",
    )

    rating_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Number of reviews contributing to rating_average.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("display_name")
    def _validate_display_name(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="display_name must be a string",
                code="ANALYST_DISPLAY_NAME_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="display_name must not be empty",
                code="ANALYST_DISPLAY_NAME_EMPTY",
            )
        if len(stripped) > _MAX_DISPLAY_NAME_LENGTH:
            raise ValidationError(
                message=f"display_name must not exceed {_MAX_DISPLAY_NAME_LENGTH} characters",
                code="ANALYST_DISPLAY_NAME_TOO_LONG",
            )
        return stripped

    @validates("headline")
    def _validate_headline(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="headline must be a string or None",
                code="ANALYST_HEADLINE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_HEADLINE_LENGTH:
            raise ValidationError(
                message=f"headline must not exceed {_MAX_HEADLINE_LENGTH} characters",
                code="ANALYST_HEADLINE_TOO_LONG",
            )
        return stripped

    @validates("bio")
    def _validate_bio(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="bio must be a string or None",
                code="ANALYST_BIO_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            return None
        if len(stripped) > _MAX_BIO_LENGTH:
            raise ValidationError(
                message=f"bio must not exceed {_MAX_BIO_LENGTH} characters",
                code="ANALYST_BIO_TOO_LONG",
            )
        return stripped

    @validates("specializations")
    def _validate_specializations(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        """Deduplicate, strip, validate each item is a non-empty string."""
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="specializations must be a list of strings",
                code="ANALYST_SPECIALIZATIONS_INVALID_TYPE",
            )
        if len(value) > _MAX_SPECIALIZATIONS:
            raise ValidationError(
                message=f"specializations must not exceed {_MAX_SPECIALIZATIONS} items",
                code="ANALYST_SPECIALIZATIONS_TOO_MANY",
            )
        seen: set[str] = set()
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each specialization must be a string",
                    code="ANALYST_SPECIALIZATION_INVALID_TYPE",
                )
            stripped = item.strip().lower()
            if not stripped:
                continue
            if stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("certifications")
    def _validate_certifications(
        self, _key: str, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        """Validate that each item is a dict; strip and keep supported keys."""
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="certifications must be a list of objects",
                code="ANALYST_CERTIFICATIONS_INVALID_TYPE",
            )
        if len(value) > _MAX_CERTIFICATIONS:
            raise ValidationError(
                message=f"certifications must not exceed {_MAX_CERTIFICATIONS} items",
                code="ANALYST_CERTIFICATIONS_TOO_MANY",
            )
        cleaned: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise ValidationError(
                    message="each certification must be an object",
                    code="ANALYST_CERTIFICATION_INVALID_TYPE",
                )
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValidationError(
                    message="each certification must have a non-empty 'name'",
                    code="ANALYST_CERTIFICATION_MISSING_NAME",
                )
            cleaned.append(
                {
                    "name": name,
                    "issuer": str(item.get("issuer", "")).strip() or None,
                    "issued_year": item.get("issued_year"),
                    "credential_url": str(item.get("credential_url", "")).strip() or None,
                }
            )
        return cleaned

    @validates("languages")
    def _validate_languages(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="languages must be a list of strings",
                code="ANALYST_LANGUAGES_INVALID_TYPE",
            )
        if len(value) > _MAX_LANGUAGES:
            raise ValidationError(
                message=f"languages must not exceed {_MAX_LANGUAGES} items",
                code="ANALYST_LANGUAGES_TOO_MANY",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each language must be a string",
                    code="ANALYST_LANGUAGE_INVALID_TYPE",
                )
            stripped = item.strip().lower()
            if not stripped or stripped in seen:
                continue
            if not (2 <= len(stripped) <= 8):
                raise ValidationError(
                    message=f"language tag {stripped!r} must be 2–8 characters",
                    code="ANALYST_LANGUAGE_INVALID_FORMAT",
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @validates("verification_documents")
    def _validate_verification_documents(
        self, _key: str, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="verification_documents must be a list of objects",
                code="ANALYST_DOCS_INVALID_TYPE",
            )
        if len(value) > _MAX_VERIFICATION_DOCUMENTS:
            raise ValidationError(
                message=f"verification_documents must not exceed {_MAX_VERIFICATION_DOCUMENTS} items",
                code="ANALYST_DOCS_TOO_MANY",
            )
        cleaned: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise ValidationError(
                    message="each verification document must be an object",
                    code="ANALYST_DOC_INVALID_TYPE",
                )
            doc_type = str(item.get("type", "")).strip()
            url = str(item.get("url", "")).strip()
            if not doc_type or not url:
                raise ValidationError(
                    message="each verification document must have 'type' and 'url'",
                    code="ANALYST_DOC_MISSING_FIELDS",
                )
            cleaned.append(
                {
                    "type": doc_type,
                    "url": url,
                    "uploaded_at": item.get("uploaded_at"),
                }
            )
        return cleaned

    @validates("currency")
    def _validate_currency(self, _key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message="currency must be a string or None",
                code="ANALYST_CURRENCY_INVALID_TYPE",
            )
        normalized = value.strip().upper()
        if len(normalized) != 3:
            raise ValidationError(
                message="currency must be a 3-letter ISO 4217 code",
                code="ANALYST_CURRENCY_INVALID_FORMAT",
            )
        return normalized

    @validates("verification_status")
    def _validate_status(
        self, _key: str, value: AnalystVerificationStatus | str
    ) -> AnalystVerificationStatus:
        if isinstance(value, AnalystVerificationStatus):
            return value
        if isinstance(value, str):
            try:
                return AnalystVerificationStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid verification status {value!r}",
                    code="ANALYST_STATUS_INVALID",
                    details={"allowed": list(AnalystVerificationStatus.values())},
                ) from exc
        raise ValidationError(
            message="verification_status must be an enum or string",
            code="ANALYST_STATUS_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @classmethod
    def build_application(
        cls,
        *,
        user_id: uuid.UUID,
        display_name: str,
        specializations: list[str] | None = None,
        headline: str | None = None,
        bio: str | None = None,
        years_of_experience: int | None = None,
        hourly_rate_cents: int | None = None,
        currency: str | None = None,
        languages: list[str] | None = None,
        working_timezone: str = "UTC",
        certifications: list[dict[str, Any]] | None = None,
        verification_documents: list[dict[str, Any]] | None = None,
    ) -> "AnalystProfile":
        """
        Create a new analyst application in the ``PENDING`` state.

        The applicant must later attach verification documents and be
        reviewed by a super admin before ``verification_status`` becomes
        ``VERIFIED``.
        """
        return cls(
            user_id=user_id,
            display_name=display_name,
            specializations=specializations or [],
            headline=headline,
            bio=bio,
            years_of_experience=years_of_experience,
            hourly_rate_cents=hourly_rate_cents,
            currency=currency,
            languages=languages or [],
            working_timezone=working_timezone,
            certifications=certifications or [],
            verification_documents=verification_documents or [],
            verification_status=AnalystVerificationStatus.PENDING,
            verification_submitted_at=datetime.now(timezone.utc),
            available_for_hire=False,
        )

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_verified(self) -> bool:
        """True if the analyst has completed verification."""
        return self.verification_status == AnalystVerificationStatus.VERIFIED

    @property
    def is_pending_review(self) -> bool:
        """True if the application is awaiting super-admin action."""
        return self.verification_status in (
            AnalystVerificationStatus.PENDING,
            AnalystVerificationStatus.IN_REVIEW,
        )

    @property
    def is_rejected(self) -> bool:
        """True if the application was rejected."""
        return self.verification_status == AnalystVerificationStatus.REJECTED

    @property
    def is_suspended(self) -> bool:
        """True if the analyst has been suspended by a super admin."""
        return self.verification_status == AnalystVerificationStatus.SUSPENDED

    @property
    def is_expired(self) -> bool:
        """True if verification has expired and renewal is needed."""
        return self.verification_status == AnalystVerificationStatus.EXPIRED

    @property
    def has_capacity(self) -> bool:
        """True if the analyst is below their concurrent-case limit."""
        return self.active_case_count < self.max_concurrent_cases

    @property
    def can_accept_cases(self) -> bool:
        """
        The single condition every case-assignment check must consult.

        True iff:
          - the analyst is verified
          - they have toggled ``available_for_hire`` on
          - they have not reached their concurrent-case limit

        All three must be true. If any is false, the analyst must not be
        assigned new cases.
        """
        return self.is_verified and self.available_for_hire and self.has_capacity

    @property
    def hourly_rate_display(self) -> str | None:
        """Human-readable hourly rate (e.g. ``'USD 499.00'``), or None."""
        if self.hourly_rate_cents is None or self.currency is None:
            return None
        whole = self.hourly_rate_cents // 100
        cents = self.hourly_rate_cents % 100
        return f"{self.currency} {whole}.{cents:02d}"


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
#     from app.models.marketplace import AnalystServiceOffering
#
# class AnalystProfile(...):
#     ...
#     user: Mapped["User"] = relationship(
#         "User",
#         back_populates="analyst_profile",
#         foreign_keys=[user_id],
#     )
#     verified_by: Mapped["User | None"] = relationship(
#         "User",
#         foreign_keys=[verified_by_id],
#     )
#     service_offerings: Mapped[list["AnalystServiceOffering"]] = relationship(
#         "AnalystServiceOffering",
#         back_populates="analyst",
#         cascade="all, delete-orphan",
#         foreign_keys="AnalystServiceOffering.analyst_id",
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AnalystProfile",
    "_MAX_HOURLY_RATE_CENTS",
    "_MAX_YEARS_OF_EXPERIENCE",
    "_MAX_SPECIALIZATIONS",
    "_MAX_CERTIFICATIONS",
    "_MAX_LANGUAGES",
    "_MAX_VERIFICATION_DOCUMENTS",
    "_MAX_DISPLAY_NAME_LENGTH",
    "_MAX_HEADLINE_LENGTH",
    "_MAX_BIO_LENGTH",
]