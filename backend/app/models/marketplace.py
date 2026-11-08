"""
CyberGuard AI — Marketplace: Offerings, Purchases, Payments
============================================================================

Three tables that make CyberGuard AI a platform connecting people with
security expertise, not just a monitoring tool:

    analyst_service_offerings  — what analysts sell
    service_purchases          — a customer buying an offering
    payment_transactions       — individual payment records

The marketplace flow
--------------------
    1. Analyst publishes an offering (e.g. "Phishing Investigation — $499")
    2. Customer browses, selects, checks out
    3. A ``ServicePurchase`` is created (status=PAYMENT_PROCESSING)
    4. Payment is processed via provider, ``PaymentTransaction`` succeeds
    5. Purchase flips to PAID
    6. Marketplace service:
         - creates a ``SecurityCase`` for the engagement
         - creates a ``CaseAccessGrant`` scoping the analyst's access
         - links both IDs back on the purchase (case_id, access_grant_id)
         - transitions purchase to IN_PROGRESS
    7. Analyst works the case
    8. Analyst submits deliverables; case is resolved
    9. Purchase flips to COMPLETED; analyst rating is requested

The critical link
-----------------
``service_purchases.case_id`` — the FK that connects a paid engagement to
the security case that fulfills it. Without it, the marketplace is just a
payment system. With it, the marketplace creates auditable investigations
that flow through the platform's full case lifecycle.

Design decisions
----------------
1. **Money in integer cents + ISO 4217 currency.**
   Never floats. Every monetary column follows this rule.

2. **``offering_type`` distinguishes pricing models.**
   ``fixed`` (one price), ``hourly`` (rate × hours), ``subscription``
   (recurring). Additional models can be added by extending the CHECK
   constraint in a migration.

3. **``slots_available`` + ``slots_used`` for capacity-limited offerings.**
   Set ``slots_available = NULL`` for unlimited. The purchase flow
   decrements ``slots_used`` atomically.

4. **``case_id`` FK on purchase — the critical link.**
   See "The critical link" above.

5. **``delivery_status`` orthogonal to payment status.**
   Payment can succeed while delivery hasn't begun. Delivery can complete
   while a refund is pending. ``payment_status='paid' AND
   delivery_status='accepted'`` is the true completion signal.

6. **``access_grant_id`` FK on purchase — the scope bridge.**
   Records which ``CaseAccessGrant`` was created by which purchase.

7. **Multiple ``payment_transactions`` per purchase.**
   Deposits, milestones, refunds each get their own row. The purchase's
   ``amount_paid_cents``/``amount_refunded_cents`` are denormalized sums.

8. **Provider references, not provider secrets.**
   Store ``provider`` and ``provider_reference`` only. NEVER store card
   numbers, CVVs, or API keys. PCI compliance requires this.

9. **Idempotency via ``idempotency_key`` on purchase.**
   Unique per (buyer, key). Prevents duplicate purchases on retry.

10. **``engagement_start_at`` + ``engagement_end_at``.**
    For time-bound engagements. After end, the service revokes the
    ``CaseAccessGrant`` automatically.

11. **``subscription_renewal_at`` + ``subscription_interval``.**
    For subscription offerings. A background job renews at
    ``subscription_renewal_at``.

12. **Refund flow is explicit.**
    A refund is a new ``PaymentTransaction`` (type=refund, parent links
    to original). Matches real payment processors.

13. **``cancellation_reason`` + ``cancellation_policy``.**
    Full refund (before work), partial (work started), none (delivered).
    Policy stored per-purchase for dispute resolution.

14. **Ratings deferred to ``service_reviews`` (future).**
    This file stores aggregate counts on ``AnalystProfile`` (File 20).

15. **``offering_metadata`` and ``purchase_metadata`` JSONB.**
    Flexible per-type fields, provider-specific data.

16. **No ``SoftDeleteMixin`` on transactions.**
    Payments are immutable financial records.

17. **``SoftDeleteMixin`` on offerings only.**
    Retired offerings stay resolvable for historical purchases.

18. **Timezone correctness everywhere.**

Usage
-----
    from app.models import (
        AnalystServiceOffering, ServicePurchase, PaymentTransaction,
    )
    from app.models.enums import (
        ServiceOfferingStatus, PurchaseStatus, PaymentStatus,
    )

    # Analyst publishes an offering
    offering = AnalystServiceOffering.build(
        analyst_id=analyst.id,
        workspace_id=analyst_workspace.id,
        title="Phishing Email Investigation",
        description="Full forensics of a suspicious email; PDF report in 24h.",
        category="phishing",
        offering_type="fixed",
        price_cents=49900,     # $499 USD
        currency="USD",
        turnaround_hours=24,
        slots_available=5,
    )
    db.add(offering)
    db.commit()

    # Customer buys it
    purchase = ServicePurchase.build(
        offering_id=offering.id,
        buyer_user_id=priya.id,
        buyer_workspace_id=priya_ws.id,
        amount_cents=49900,
        currency="USD",
        idempotency_key="checkout-attempt-uuid-abc",
    )
    db.add(purchase)
    db.commit()

    # Provider processes payment
    txn = PaymentTransaction.build_charge(
        purchase_id=purchase.id,
        provider="stripe",
        provider_reference="ch_abc123",
        amount_cents=49900,
        currency="USD",
    )
    db.add(txn)

    # Payment succeeded
    txn.mark_succeeded()
    purchase.mark_paid(amount_cents=49900)

    # Service creates case + access grant, then links them
    case = SecurityCase.build(...)
    grant = CaseAccessGrant.build(...)
    purchase.attach_case(case_id=case.id, access_grant_id=grant.id)

    db.commit()
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.exceptions import (
    InvalidStateTransitionError,
    ValidationError,
)
from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    PaymentStatus,
    PurchaseStatus,
    ServiceOfferingStatus,
    enum_column_type,
)


# ── Constants ──────────────────────────────────────────────────────────────

#: Offering type values.
_OFFERING_TYPE_FIXED = "fixed"
_OFFERING_TYPE_HOURLY = "hourly"
_OFFERING_TYPE_SUBSCRIPTION = "subscription"
_VALID_OFFERING_TYPES = frozenset({
    _OFFERING_TYPE_FIXED,
    _OFFERING_TYPE_HOURLY,
    _OFFERING_TYPE_SUBSCRIPTION,
})

#: Payment transaction type values.
_TXN_TYPE_CHARGE = "charge"
_TXN_TYPE_REFUND = "refund"
_TXN_TYPE_ADJUSTMENT = "adjustment"
_VALID_TXN_TYPES = frozenset({
    _TXN_TYPE_CHARGE,
    _TXN_TYPE_REFUND,
    _TXN_TYPE_ADJUSTMENT,
})

#: Payment provider values.
_VALID_PROVIDERS = frozenset({"stripe", "razorpay", "manual", "internal"})

#: Subscription intervals.
_INTERVAL_MONTHLY = "monthly"
_INTERVAL_YEARLY = "yearly"
_INTERVAL_WEEKLY = "weekly"
_VALID_INTERVALS = frozenset({
    _INTERVAL_MONTHLY, _INTERVAL_YEARLY, _INTERVAL_WEEKLY,
})

#: Delivery status values (purchase).
_DELIVERY_NOT_STARTED = "not_started"
_DELIVERY_IN_PROGRESS = "in_progress"
_DELIVERY_DELIVERED = "delivered"
_DELIVERY_ACCEPTED = "accepted"
_DELIVERY_DISPUTED = "disputed"
_VALID_DELIVERY_STATUSES = frozenset({
    _DELIVERY_NOT_STARTED,
    _DELIVERY_IN_PROGRESS,
    _DELIVERY_DELIVERED,
    _DELIVERY_ACCEPTED,
    _DELIVERY_DISPUTED,
})

#: Cancellation policy values.
_CANCEL_POLICY_FULL_REFUND = "full_refund"
_CANCEL_POLICY_PARTIAL_REFUND = "partial_refund"
_CANCEL_POLICY_NO_REFUND = "no_refund"
_VALID_CANCEL_POLICIES = frozenset({
    _CANCEL_POLICY_FULL_REFUND,
    _CANCEL_POLICY_PARTIAL_REFUND,
    _CANCEL_POLICY_NO_REFUND,
})

# ── Size limits ────────────────────────────────────────────────────────────
_MAX_TITLE_LENGTH = 200
_MAX_DESCRIPTION_LENGTH = 10_000
_MAX_CATEGORY_LENGTH = 64
_MAX_CURRENCY_LENGTH = 3
_MAX_PROVIDER_REFERENCE_LENGTH = 255
_MAX_IDEMPOTENCY_KEY_LENGTH = 128
_MAX_REASON_LENGTH = 1000
_MAX_METADATA_BYTES = 64 * 1024
_MAX_SLOTS = 1_000_000
_MAX_PRICE_CENTS = 100_000_000_00  # $1 billion in cents — sanity cap

_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")


# ============================================================================
# ANALYST SERVICE OFFERING
# ============================================================================

class AnalystServiceOffering(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A service offering published by an analyst.

    Multiple offerings per analyst. Each offering has its own price,
    category, turnaround, and availability. The offering is what a
    customer browses and buys.
    """

    __tablename__ = "analyst_service_offerings"

    __table_args__ = (
        CheckConstraint(
            "offering_type IN ('fixed', 'hourly', 'subscription')",
            name="offering_type_values",
        ),
        CheckConstraint(
            "price_cents >= 0 AND price_cents <= 10000000000",
            name="price_cents_range",
        ),
        CheckConstraint(
            r"currency ~ '^[A-Z]{3}$'",
            name="currency_iso_4217",
        ),
        CheckConstraint(
            "turnaround_hours IS NULL OR turnaround_hours > 0",
            name="turnaround_hours_positive",
        ),
        CheckConstraint(
            "slots_available IS NULL OR "
            "(slots_available >= 0 AND slots_available <= 1000000)",
            name="slots_available_range",
        ),
        CheckConstraint(
            "slots_used >= 0",
            name="slots_used_non_negative",
        ),
        CheckConstraint(
            "slots_available IS NULL OR slots_used <= slots_available",
            name="slots_used_within_available",
        ),
        CheckConstraint(
            "rating_average IS NULL OR "
            "(rating_average >= 0 AND rating_average <= 5)",
            name="rating_average_range",
        ),
        CheckConstraint(
            "rating_count >= 0",
            name="rating_count_non_negative",
        ),
        CheckConstraint(
            "purchase_count >= 0",
            name="purchase_count_non_negative",
        ),
        # Marketplace listing query.
        Index(
            "ix_offerings_active",
            "status",
            "created_at",
        ),
        # Per-analyst offerings.
        Index(
            "ix_offerings_analyst_status",
            "analyst_id",
            "status",
        ),
        # Category browsing.
        Index(
            "ix_offerings_category_status",
            "category",
            "status",
        ),
        # Workspace scope.
        Index(
            "ix_offerings_workspace_status",
            "workspace_id",
            "status",
        ),
    )

    # ─── Ownership ──────────────────────────────────────────────────────
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyst_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Analyst who owns this offering. CASCADE on analyst delete.",
    )

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Workspace the offering is published under.",
    )

    # ─── Presentation ──────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(_MAX_TITLE_LENGTH),
        nullable=False,
        comment="Display title (e.g. 'Phishing Email Investigation').",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Long-form description shown on the offering detail page.",
    )

    category: Mapped[str] = mapped_column(
        String(_MAX_CATEGORY_LENGTH),
        nullable=False,
        index=True,
        comment=(
            "Service category (phishing, malware, network, compliance, "
            "incident_response, forensic_analysis, other)."
        ),
    )

    # ─── Pricing ────────────────────────────────────────────────────────
    offering_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_OFFERING_TYPE_FIXED,
        server_default=_OFFERING_TYPE_FIXED,
        index=True,
        comment="fixed | hourly | subscription.",
    )

    price_cents: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Price in the smallest currency unit (cents, paise, etc.).",
    )

    currency: Mapped[str] = mapped_column(
        String(_MAX_CURRENCY_LENGTH),
        nullable=False,
        comment="ISO 4217 currency code (USD, EUR, INR, ...).",
    )

    # ─── Delivery expectations ─────────────────────────────────────────
    turnaround_hours: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Promised turnaround in hours (e.g. 24 for a 1-day investigation).",
    )

    deliverables: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="List of deliverables (e.g. ['PDF report', 'Raw IOCs', 'Remediation plan']).",
    )

    # ─── Availability ──────────────────────────────────────────────────
    status: Mapped[ServiceOfferingStatus] = mapped_column(
        enum_column_type(ServiceOfferingStatus),
        nullable=False,
        default=ServiceOfferingStatus.DRAFT,
        server_default=ServiceOfferingStatus.DRAFT.value,
        index=True,
        comment="draft, active, paused, archived.",
    )

    slots_available: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Capacity limit. NULL = unlimited.",
    )

    slots_used: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Number of active engagements against this offering.",
    )

    # ─── Subscription fields ───────────────────────────────────────────
    subscription_interval: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="For subscriptions: weekly | monthly | yearly.",
    )

    # ─── Aggregates (maintained by service) ───────────────────────────
    purchase_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Lifetime completed purchases.",
    )

    rating_average: Mapped[float | None] = mapped_column(
        nullable=True,
        comment="Average rating from reviews. NULL until first review.",
    )

    rating_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ─── Metadata ──────────────────────────────────────────────────────
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Free-form structured metadata.",
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("offering_type")
    def _validate_offering_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="offering_type must be a string",
                code="OFFERING_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_OFFERING_TYPES:
            raise ValidationError(
                message=f"offering_type must be one of {sorted(_VALID_OFFERING_TYPES)}",
                code="OFFERING_TYPE_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_OFFERING_TYPES),
                },
            )
        return normalized

    @validates("currency")
    def _validate_currency(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="currency must be a string",
                code="OFFERING_CURRENCY_INVALID_TYPE",
            )
        normalized = value.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValidationError(
                message="currency must be a 3-letter ISO 4217 code",
                code="OFFERING_CURRENCY_INVALID_FORMAT",
                details={"received": value},
            )
        return normalized

    @validates("title")
    def _validate_title(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="title must be a string",
                code="OFFERING_TITLE_INVALID_TYPE",
            )
        stripped = value.strip()
        if not stripped:
            raise ValidationError(
                message="title must not be empty",
                code="OFFERING_TITLE_EMPTY",
            )
        if len(stripped) > _MAX_TITLE_LENGTH:
            raise ValidationError(
                message=f"title must not exceed {_MAX_TITLE_LENGTH} characters",
                code="OFFERING_TITLE_TOO_LONG",
            )
        return stripped

    @validates("price_cents")
    def _validate_price(self, _key: str, value: int) -> int:
        if not isinstance(value, int):
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValidationError(
                    message="price_cents must be an integer",
                    code="OFFERING_PRICE_INVALID_TYPE",
                ) from exc
        if value < 0 or value > _MAX_PRICE_CENTS:
            raise ValidationError(
                message=f"price_cents must be between 0 and {_MAX_PRICE_CENTS}",
                code="OFFERING_PRICE_OUT_OF_RANGE",
                details={"received": value},
            )
        return value

    @validates("status")
    def _validate_status(
        self, _key: str, value: ServiceOfferingStatus | str
    ) -> ServiceOfferingStatus:
        if isinstance(value, ServiceOfferingStatus):
            return value
        if isinstance(value, str):
            try:
                return ServiceOfferingStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid offering status {value!r}",
                    code="OFFERING_STATUS_INVALID",
                    details={"allowed": list(ServiceOfferingStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be a ServiceOfferingStatus or string",
            code="OFFERING_STATUS_INVALID_TYPE",
        )

    @validates("deliverables")
    def _validate_deliverables(
        self, _key: str, value: list[str] | None
    ) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message="deliverables must be a list of strings",
                code="OFFERING_DELIVERABLES_INVALID_TYPE",
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message="each deliverable must be a string",
                    code="OFFERING_DELIVERABLE_INVALID_TYPE",
                )
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 200:
                raise ValidationError(
                    message="each deliverable must not exceed 200 characters",
                    code="OFFERING_DELIVERABLE_TOO_LONG",
                )
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        analyst_id: uuid.UUID,
        workspace_id: uuid.UUID,
        title: str,
        description: str,
        category: str,
        offering_type: str,
        price_cents: int,
        currency: str,
        turnaround_hours: int | None = None,
        deliverables: list[str] | None = None,
        slots_available: int | None = None,
        subscription_interval: str | None = None,
        status: ServiceOfferingStatus = ServiceOfferingStatus.DRAFT,
        metadata: dict[str, Any] | None = None,
    ) -> "AnalystServiceOffering":
        """Construct a new offering. Defaults to DRAFT state."""
        if offering_type == _OFFERING_TYPE_SUBSCRIPTION:
            if subscription_interval is None:
                raise ValidationError(
                    message="subscription offerings require subscription_interval",
                    code="OFFERING_SUBSCRIPTION_INTERVAL_REQUIRED",
                )
            if subscription_interval not in _VALID_INTERVALS:
                raise ValidationError(
                    message=f"subscription_interval must be one of {sorted(_VALID_INTERVALS)}",
                    code="OFFERING_SUBSCRIPTION_INTERVAL_INVALID",
                )
        return cls(
            analyst_id=analyst_id,
            workspace_id=workspace_id,
            title=title,
            description=description,
            category=category.strip().lower(),
            offering_type=offering_type,
            price_cents=price_cents,
            currency=currency,
            turnaround_hours=turnaround_hours,
            deliverables=deliverables or [],
            status=status,
            slots_available=slots_available,
            slots_used=0,
            subscription_interval=subscription_interval,
            metadata_json=metadata or {},
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def publish(self) -> None:
        """Transition from DRAFT to ACTIVE."""
        if self.status != ServiceOfferingStatus.DRAFT:
            raise InvalidStateTransitionError(
                message=f"Cannot publish offering in status {self.status.value!r}",
                code="OFFERING_NOT_DRAFT",
            )
        self.status = ServiceOfferingStatus.ACTIVE

    def pause(self) -> None:
        """Transition from ACTIVE to PAUSED."""
        if self.status != ServiceOfferingStatus.ACTIVE:
            raise InvalidStateTransitionError(
                message=f"Cannot pause offering in status {self.status.value!r}",
                code="OFFERING_NOT_ACTIVE",
            )
        self.status = ServiceOfferingStatus.PAUSED

    def resume(self) -> None:
        """Transition from PAUSED to ACTIVE."""
        if self.status != ServiceOfferingStatus.PAUSED:
            raise InvalidStateTransitionError(
                message=f"Cannot resume offering in status {self.status.value!r}",
                code="OFFERING_NOT_PAUSED",
            )
        self.status = ServiceOfferingStatus.ACTIVE

    def archive(self) -> None:
        """Transition to ARCHIVED (retired). Historical purchases still resolve."""
        self.status = ServiceOfferingStatus.ARCHIVED

    def claim_slot(self) -> None:
        """
        Atomically claim one slot for a new engagement. Raises if the
        offering is sold out or not active.
        """
        if self.status != ServiceOfferingStatus.ACTIVE:
            raise InvalidStateTransitionError(
                message=f"Offering is not active (status={self.status.value})",
                code="OFFERING_NOT_ACTIVE",
            )
        if self.slots_available is not None:
            if self.slots_used >= self.slots_available:
                raise InvalidStateTransitionError(
                    message="Offering has no available slots",
                    code="OFFERING_SOLD_OUT",
                    details={
                        "slots_available": self.slots_available,
                        "slots_used": self.slots_used,
                    },
                )
        self.slots_used += 1

    def release_slot(self) -> None:
        """Release a previously claimed slot (e.g. on cancellation)."""
        if self.slots_used > 0:
            self.slots_used -= 1

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_active(self) -> bool:
        """True if the offering is currently available for purchase."""
        return self.status == ServiceOfferingStatus.ACTIVE

    @property
    def is_draft(self) -> bool:
        return self.status == ServiceOfferingStatus.DRAFT

    @property
    def is_paused(self) -> bool:
        return self.status == ServiceOfferingStatus.PAUSED

    @property
    def is_archived(self) -> bool:
        return self.status == ServiceOfferingStatus.ARCHIVED

    @property
    def is_sold_out(self) -> bool:
        """True if slots_available is exhausted."""
        if self.slots_available is None:
            return False
        return self.slots_used >= self.slots_available

    @property
    def slots_remaining(self) -> int | None:
        """Number of slots left, or None if unlimited."""
        if self.slots_available is None:
            return None
        return max(0, self.slots_available - self.slots_used)

    @property
    def price_display(self) -> str:
        """Human-readable price (e.g. 'USD 499.00')."""
        whole = self.price_cents // 100
        cents = self.price_cents % 100
        return f"{self.currency} {whole}.{cents:02d}"


# ============================================================================
# SERVICE PURCHASE
# ============================================================================

class ServicePurchase(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A customer purchase of an analyst service offering.

    Payment status and delivery status are tracked separately. The
    ``case_id`` link creates the resulting investigation case. The
    ``access_grant_id`` records the scoping grant created for the analyst.
    """

    __tablename__ = "service_purchases"

    __table_args__ = (
        CheckConstraint(
            "amount_cents >= 0 AND amount_cents <= 10000000000",
            name="amount_cents_range",
        ),
        CheckConstraint(
            "amount_paid_cents >= 0",
            name="amount_paid_cents_non_negative",
        ),
        CheckConstraint(
            "amount_refunded_cents >= 0",
            name="amount_refunded_cents_non_negative",
        ),
        CheckConstraint(
            r"currency ~ '^[A-Z]{3}$'",
            name="currency_iso_4217",
        ),
        CheckConstraint(
            "delivery_status IN "
            "('not_started', 'in_progress', 'delivered', 'accepted', 'disputed')",
            name="delivery_status_values",
        ),
        # Payment status must be one of the documented values.
        CheckConstraint(
            "payment_status IN "
            "('pending', 'processing', 'succeeded', 'failed', 'refunded')",
            name="payment_status_values",
        ),
        CheckConstraint(
            "cancellation_policy IN "
            "('full_refund', 'partial_refund', 'no_refund')",
            name="cancellation_policy_values",
        ),
        # Idempotency: unique per (buyer, key).
        UniqueConstraint(
            "buyer_user_id",
            "idempotency_key",
            name="uq_purchase_buyer_idempotency",
        ),
        # Buyer's purchases.
        Index(
            "ix_purchases_buyer_created",
            "buyer_user_id",
            "created_at",
        ),
        # Offering's purchases.
        Index(
            "ix_purchases_offering_status",
            "offering_id",
            "purchase_status",
        ),
        # Workspace scope.
        Index(
            "ix_purchases_workspace_status",
            "buyer_workspace_id",
            "purchase_status",
        ),
        # Lookup by case.
        Index(
            "ix_purchases_case_id",
            "case_id",
        ),
        # Renewal job.
        Index(
            "ix_purchases_subscription_renewal",
            "subscription_renewal_at",
        ),
    )

    # ─── Offering reference ────────────────────────────────────────────
    offering_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyst_service_offerings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "Offering purchased. SET NULL if the offering is hard-deleted — "
            "the purchase record survives with its own snapshot of price."
        ),
    )

    # ─── Buyer ─────────────────────────────────────────────────────────
    buyer_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User who bought the service.",
    )

    buyer_workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Workspace context for the purchase (personal or org).",
    )

    idempotency_key: Mapped[str | None] = mapped_column(
        String(_MAX_IDEMPOTENCY_KEY_LENGTH),
        nullable=True,
        comment=(
            "Client-supplied idempotency key. Unique per buyer. "
            "Prevents duplicate purchases on retry."
        ),
    )

    # ─── Price snapshot ────────────────────────────────────────────────
    amount_cents: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Total amount charged for this purchase (cents).",
    )

    currency: Mapped[str] = mapped_column(
        String(_MAX_CURRENCY_LENGTH),
        nullable=False,
    )

    amount_paid_cents: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Sum of successful payment transactions (denormalized).",
    )

    amount_refunded_cents: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Sum of refund transactions (denormalized).",
    )

    # ─── Status (orthogonal dimensions) ───────────────────────────────
    purchase_status: Mapped[PurchaseStatus] = mapped_column(
        enum_column_type(PurchaseStatus),
        nullable=False,
        default=PurchaseStatus.PENDING,
        server_default=PurchaseStatus.PENDING.value,
        index=True,
        comment="Overall purchase lifecycle.",
    )

    payment_status: Mapped[PaymentStatus] = mapped_column(
        enum_column_type(PaymentStatus),
        nullable=False,
        default=PaymentStatus.PENDING,
        server_default=PaymentStatus.PENDING.value,
        index=True,
        comment="Payment processing status.",
    )

    delivery_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_DELIVERY_NOT_STARTED,
        server_default=_DELIVERY_NOT_STARTED,
        index=True,
        comment="not_started | in_progress | delivered | accepted | disputed.",
    )

    # ─── Engagement window ────────────────────────────────────────────
    engagement_start_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the engagement (case work) can begin.",
    )

    engagement_end_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "When the engagement ends. After this, the marketplace service "
            "revokes the CaseAccessGrant automatically."
        ),
    )

    subscription_renewal_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Next renewal date for subscription purchases.",
    )

    subscription_interval: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        comment="weekly | monthly | yearly (denormalized from offering).",
    )

    # ─── Case linkage (the critical part) ─────────────────────────────
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("security_cases.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "The security case created to fulfill this engagement. "
            "Set when the marketplace service provisions the case. "
            "SET NULL if the case is hard-deleted (rare)."
        ),
    )

    access_grant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("case_access_grants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "The scoped CaseAccessGrant created for the analyst. "
            "Revoking this grant terminates the engagement's scope."
        ),
    )

    # ─── Cancellation ─────────────────────────────────────────────────
    cancellation_policy: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_CANCEL_POLICY_FULL_REFUND,
        server_default=_CANCEL_POLICY_FULL_REFUND,
        comment="full_refund | partial_refund | no_refund.",
    )

    cancellation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    cancelled_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── Completion ───────────────────────────────────────────────────
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    delivery_accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the buyer explicitly accepted the deliverables.",
    )

    # ─── Metadata ─────────────────────────────────────────────────────
    purchase_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("currency")
    def _validate_currency(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="currency must be a string",
                code="PURCHASE_CURRENCY_INVALID_TYPE",
            )
        normalized = value.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValidationError(
                message="currency must be a 3-letter ISO 4217 code",
                code="PURCHASE_CURRENCY_INVALID_FORMAT",
            )
        return normalized

    @validates("purchase_status")
    def _validate_purchase_status(
        self, _key: str, value: PurchaseStatus | str
    ) -> PurchaseStatus:
        if isinstance(value, PurchaseStatus):
            return value
        if isinstance(value, str):
            try:
                return PurchaseStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid purchase_status {value!r}",
                    code="PURCHASE_STATUS_INVALID",
                    details={"allowed": list(PurchaseStatus.values())},
                ) from exc
        raise ValidationError(
            message="purchase_status must be a PurchaseStatus or string",
            code="PURCHASE_STATUS_INVALID_TYPE",
        )

    @validates("payment_status")
    def _validate_payment_status(
        self, _key: str, value: PaymentStatus | str
    ) -> PaymentStatus:
        if isinstance(value, PaymentStatus):
            return value
        if isinstance(value, str):
            try:
                return PaymentStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid payment_status {value!r}",
                    code="PURCHASE_PAYMENT_STATUS_INVALID",
                    details={"allowed": list(PaymentStatus.values())},
                ) from exc
        raise ValidationError(
            message="payment_status must be a PaymentStatus or string",
            code="PURCHASE_PAYMENT_STATUS_INVALID_TYPE",
        )

    @validates("delivery_status")
    def _validate_delivery_status(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="delivery_status must be a string",
                code="PURCHASE_DELIVERY_STATUS_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_DELIVERY_STATUSES:
            raise ValidationError(
                message=(
                    f"delivery_status must be one of "
                    f"{sorted(_VALID_DELIVERY_STATUSES)}"
                ),
                code="PURCHASE_DELIVERY_STATUS_INVALID",
                details={
                    "received": value,
                    "allowed": sorted(_VALID_DELIVERY_STATUSES),
                },
            )
        return normalized

    @validates("cancellation_policy")
    def _validate_cancellation_policy(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="cancellation_policy must be a string",
                code="PURCHASE_CANCEL_POLICY_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_CANCEL_POLICIES:
            raise ValidationError(
                message=(
                    f"cancellation_policy must be one of "
                    f"{sorted(_VALID_CANCEL_POLICIES)}"
                ),
                code="PURCHASE_CANCEL_POLICY_INVALID",
            )
        return normalized

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        offering_id: uuid.UUID,
        buyer_user_id: uuid.UUID,
        amount_cents: int,
        currency: str,
        buyer_workspace_id: uuid.UUID | None = None,
        idempotency_key: str | None = None,
        cancellation_policy: str = _CANCEL_POLICY_FULL_REFUND,
        subscription_interval: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "ServicePurchase":
        """Construct a purchase in PENDING state."""
        return cls(
            offering_id=offering_id,
            buyer_user_id=buyer_user_id,
            buyer_workspace_id=buyer_workspace_id,
            idempotency_key=idempotency_key,
            amount_cents=amount_cents,
            currency=currency,
            amount_paid_cents=0,
            amount_refunded_cents=0,
            purchase_status=PurchaseStatus.PENDING,
            payment_status=PaymentStatus.PENDING,
            delivery_status=_DELIVERY_NOT_STARTED,
            cancellation_policy=cancellation_policy,
            subscription_interval=subscription_interval,
            purchase_metadata=metadata or {},
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def mark_payment_processing(self) -> None:
        """Transition payment_status to PROCESSING."""
        if self.payment_status not in (PaymentStatus.PENDING, PaymentStatus.FAILED):
            raise InvalidStateTransitionError(
                message=f"Cannot start processing from {self.payment_status.value!r}",
                code="PURCHASE_PAYMENT_STATE_INVALID",
            )
        self.payment_status = PaymentStatus.PROCESSING
        self.purchase_status = PurchaseStatus.PAYMENT_PROCESSING

    def mark_paid(self, *, amount_cents: int) -> None:
        """
        Transition to PAID. Called when the payment provider confirms
        success. ``amount_cents`` is the amount confirmed for this
        payment — added to ``amount_paid_cents``.
        """
        if self.payment_status not in (
            PaymentStatus.PENDING,
            PaymentStatus.PROCESSING,
        ):
            raise InvalidStateTransitionError(
                message=f"Cannot mark paid from {self.payment_status.value!r}",
                code="PURCHASE_PAYMENT_STATE_INVALID",
            )
        self.payment_status = PaymentStatus.SUCCEEDED
        self.purchase_status = PurchaseStatus.PAID
        self.amount_paid_cents += amount_cents

    def mark_payment_failed(self) -> None:
        """Transition payment_status to FAILED."""
        self.payment_status = PaymentStatus.FAILED
        self.purchase_status = PurchaseStatus.CANCELLED

    def start_delivery(self) -> None:
        """Transition delivery_status to IN_PROGRESS."""
        if self.payment_status != PaymentStatus.SUCCEEDED:
            raise InvalidStateTransitionError(
                message="Cannot start delivery before payment succeeds",
                code="PURCHASE_NOT_PAID",
            )
        if self.delivery_status != _DELIVERY_NOT_STARTED:
            raise InvalidStateTransitionError(
                message=f"Cannot start delivery from {self.delivery_status!r}",
                code="PURCHASE_DELIVERY_STATE_INVALID",
            )
        self.delivery_status = _DELIVERY_IN_PROGRESS
        self.purchase_status = PurchaseStatus.IN_PROGRESS
        if self.engagement_start_at is None:
            self.engagement_start_at = datetime.now(timezone.utc)

    def mark_delivered(self) -> None:
        """Transition delivery_status to DELIVERED (work submitted)."""
        if self.delivery_status != _DELIVERY_IN_PROGRESS:
            raise InvalidStateTransitionError(
                message=f"Cannot mark delivered from {self.delivery_status!r}",
                code="PURCHASE_DELIVERY_STATE_INVALID",
            )
        self.delivery_status = _DELIVERY_DELIVERED

    def mark_accepted(self) -> None:
        """Transition delivery_status to ACCEPTED. Terminal success."""
        if self.delivery_status != _DELIVERY_DELIVERED:
            raise InvalidStateTransitionError(
                message=f"Cannot accept from {self.delivery_status!r}",
                code="PURCHASE_DELIVERY_STATE_INVALID",
            )
        now = datetime.now(timezone.utc)
        self.delivery_status = _DELIVERY_ACCEPTED
        self.purchase_status = PurchaseStatus.COMPLETED
        self.delivery_accepted_at = now
        self.completed_at = now

    def mark_disputed(self, *, reason: str) -> None:
        """Transition delivery_status to DISPUTED."""
        self.delivery_status = _DELIVERY_DISPUTED
        if not self.cancellation_reason:
            self.cancellation_reason = reason

    def attach_case(
        self,
        *,
        case_id: uuid.UUID,
        access_grant_id: uuid.UUID,
    ) -> None:
        """
        Attach the resulting security case and access grant. Called by the
        marketplace service immediately after provisioning.
        """
        if self.case_id is not None:
            raise InvalidStateTransitionError(
                message="Purchase already has a case attached",
                code="PURCHASE_CASE_ALREADY_ATTACHED",
            )
        self.case_id = case_id
        self.access_grant_id = access_grant_id

    def cancel(
        self,
        *,
        cancelled_by_id: uuid.UUID,
        reason: str,
    ) -> None:
        """Cancel the purchase (may trigger refund per policy)."""
        if self.purchase_status in (
            PurchaseStatus.COMPLETED,
            PurchaseStatus.CANCELLED,
            PurchaseStatus.REFUNDED,
        ):
            raise InvalidStateTransitionError(
                message=f"Cannot cancel in status {self.purchase_status.value!r}",
                code="PURCHASE_TERMINAL_STATE",
            )
        self.purchase_status = PurchaseStatus.CANCELLED
        self.cancelled_at = datetime.now(timezone.utc)
        self.cancelled_by_id = cancelled_by_id
        if len(reason) > _MAX_REASON_LENGTH:
            raise ValidationError(
                message=f"reason must not exceed {_MAX_REASON_LENGTH} characters",
                code="PURCHASE_REASON_TOO_LONG",
            )
        self.cancellation_reason = reason.strip()

    def record_refund(self, *, amount_cents: int) -> None:
        """
        Record a refund of ``amount_cents``. Updates ``amount_refunded_cents``.
        The corresponding PaymentTransaction row must be created separately.
        """
        if amount_cents < 0:
            raise ValidationError(
                message="refund amount must be non-negative",
                code="PURCHASE_REFUND_NEGATIVE",
            )
        if self.amount_refunded_cents + amount_cents > self.amount_paid_cents:
            raise InvalidStateTransitionError(
                message="Refund would exceed amount paid",
                code="PURCHASE_REFUND_EXCEEDS_PAID",
                details={
                    "paid": self.amount_paid_cents,
                    "already_refunded": self.amount_refunded_cents,
                    "requested": amount_cents,
                },
            )
        self.amount_refunded_cents += amount_cents
        if self.amount_refunded_cents >= self.amount_paid_cents > 0:
            self.purchase_status = PurchaseStatus.REFUNDED
            self.payment_status = PaymentStatus.REFUNDED

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_paid(self) -> bool:
        return self.payment_status == PaymentStatus.SUCCEEDED

    @property
    def is_completed(self) -> bool:
        return self.purchase_status == PurchaseStatus.COMPLETED

    @property
    def is_cancelled(self) -> bool:
        return self.purchase_status == PurchaseStatus.CANCELLED

    @property
    def is_refunded(self) -> bool:
        return self.purchase_status == PurchaseStatus.REFUNDED

    @property
    def is_in_progress(self) -> bool:
        return self.purchase_status == PurchaseStatus.IN_PROGRESS

    @property
    def has_case(self) -> bool:
        """True if the resulting case has been provisioned."""
        return self.case_id is not None

    @property
    def net_revenue_cents(self) -> int:
        """Amount actually kept (paid minus refunded), in cents."""
        return self.amount_paid_cents - self.amount_refunded_cents

    @property
    def amount_display(self) -> str:
        """Human-readable amount (e.g. 'USD 499.00')."""
        whole = self.amount_cents // 100
        cents = self.amount_cents % 100
        return f"{self.currency} {whole}.{cents:02d}"

    @property
    def days_until_renewal(self) -> int | None:
        """For subscriptions: days until the next renewal."""
        if self.subscription_renewal_at is None:
            return None
        rn = self.subscription_renewal_at
        if rn.tzinfo is None:
            rn = rn.replace(tzinfo=timezone.utc)
        delta = (rn - datetime.now(timezone.utc)).total_seconds()
        return int(delta / 86400)


# ============================================================================
# PAYMENT TRANSACTION
# ============================================================================

class PaymentTransaction(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single payment transaction (charge, refund, or adjustment).

    Multiple transactions per purchase — a deposit is one transaction, the
    final payment is another. Refunds are separate transactions linked to
    the original charge via ``parent_transaction_id``.

    Never stores card numbers, CVVs, or API keys. Only ``provider`` name
    and ``provider_reference`` (which is safe to log/display). PCI
    compliance requires this.
    """

    __tablename__ = "payment_transactions"

    __table_args__ = (
        CheckConstraint(
            "transaction_type IN ('charge', 'refund', 'adjustment')",
            name="transaction_type_values",
        ),
        CheckConstraint(
            "provider IN ('stripe', 'razorpay', 'manual', 'internal')",
            name="provider_values",
        ),
        CheckConstraint(
            "amount_cents >= 0 AND amount_cents <= 10000000000",
            name="amount_cents_range",
        ),
        CheckConstraint(
            r"currency ~ '^[A-Z]{3}$'",
            name="currency_iso_4217",
        ),
        # Charge requires a provider reference on success.
        CheckConstraint(
            "status <> 'succeeded' OR provider_reference IS NOT NULL OR "
            "provider = 'manual'",
            name="success_requires_reference",
        ),
        # Purchase's transactions.
        Index(
            "ix_transactions_purchase_created",
            "purchase_id",
            "created_at",
        ),
        # Provider reference lookup (for webhook reconciliation).
        Index(
            "ix_transactions_provider_reference",
            "provider",
            "provider_reference",
        ),
        # Status filter (pending → succeeded/failed sweeps).
        Index(
            "ix_transactions_status",
            "status",
        ),
        # Parent lookup (refund → original).
        Index(
            "ix_transactions_parent",
            "parent_transaction_id",
        ),
    )

    # ─── Purchase reference ───────────────────────────────────────────
    purchase_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("service_purchases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning purchase. CASCADE on purchase delete.",
    )

    # ─── Transaction identity ─────────────────────────────────────────
    transaction_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=_TXN_TYPE_CHARGE,
        server_default=_TXN_TYPE_CHARGE,
        index=True,
        comment="charge | refund | adjustment.",
    )

    parent_transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("payment_transactions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="For refunds/adjustments: the original charge transaction.",
    )

    # ─── Amount ────────────────────────────────────────────────────────
    amount_cents: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Amount in the smallest currency unit.",
    )

    currency: Mapped[str] = mapped_column(
        String(_MAX_CURRENCY_LENGTH),
        nullable=False,
    )

    # ─── Provider ──────────────────────────────────────────────────────
    provider: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
        comment="Payment provider: stripe, razorpay, manual, internal.",
    )

    provider_reference: Mapped[str | None] = mapped_column(
        String(_MAX_PROVIDER_REFERENCE_LENGTH),
        nullable=True,
        comment=(
            "Provider's transaction ID (e.g. Stripe's 'ch_...'). "
            "Never store card data here — only opaque references."
        ),
    )

    # ─── Status ────────────────────────────────────────────────────────
    status: Mapped[PaymentStatus] = mapped_column(
        enum_column_type(PaymentStatus),
        nullable=False,
        default=PaymentStatus.PENDING,
        server_default=PaymentStatus.PENDING.value,
        index=True,
        comment="pending, processing, succeeded, failed, refunded.",
    )

    # ─── Timestamps ───────────────────────────────────────────────────
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the provider confirmed success or failure.",
    )

    failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    refunded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ─── Failure detail ───────────────────────────────────────────────
    failure_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="Provider's error code (e.g. 'card_declined').",
    )

    failure_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Provider's human-readable error message.",
    )

    # ─── Metadata ─────────────────────────────────────────────────────
    transaction_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment=(
            "Provider-specific metadata: payment method type (card, upi, "
            "bank_transfer — but NOT the card number), receipt URL, etc."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("transaction_type")
    def _validate_txn_type(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="transaction_type must be a string",
                code="TXN_TYPE_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_TXN_TYPES:
            raise ValidationError(
                message=f"transaction_type must be one of {sorted(_VALID_TXN_TYPES)}",
                code="TXN_TYPE_INVALID",
            )
        return normalized

    @validates("provider")
    def _validate_provider(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="provider must be a string",
                code="TXN_PROVIDER_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if normalized not in _VALID_PROVIDERS:
            raise ValidationError(
                message=f"provider must be one of {sorted(_VALID_PROVIDERS)}",
                code="TXN_PROVIDER_INVALID",
            )
        return normalized

    @validates("currency")
    def _validate_currency(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="currency must be a string",
                code="TXN_CURRENCY_INVALID_TYPE",
            )
        normalized = value.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValidationError(
                message="currency must be a 3-letter ISO 4217 code",
                code="TXN_CURRENCY_INVALID_FORMAT",
            )
        return normalized

    @validates("status")
    def _validate_status(
        self, _key: str, value: PaymentStatus | str
    ) -> PaymentStatus:
        if isinstance(value, PaymentStatus):
            return value
        if isinstance(value, str):
            try:
                return PaymentStatus(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid status {value!r}",
                    code="TXN_STATUS_INVALID",
                    details={"allowed": list(PaymentStatus.values())},
                ) from exc
        raise ValidationError(
            message="status must be a PaymentStatus or string",
            code="TXN_STATUS_INVALID_TYPE",
        )

    # ====================================================================
    # CONSTRUCTION HELPERS
    # ====================================================================

    @classmethod
    def build_charge(
        cls,
        *,
        purchase_id: uuid.UUID,
        provider: str,
        amount_cents: int,
        currency: str,
        provider_reference: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "PaymentTransaction":
        """Construct a charge transaction in PENDING state."""
        return cls(
            purchase_id=purchase_id,
            transaction_type=_TXN_TYPE_CHARGE,
            amount_cents=amount_cents,
            currency=currency,
            provider=provider,
            provider_reference=provider_reference,
            status=PaymentStatus.PENDING,
            transaction_metadata=metadata or {},
        )

    @classmethod
    def build_refund(
        cls,
        *,
        purchase_id: uuid.UUID,
        parent_transaction_id: uuid.UUID,
        provider: str,
        amount_cents: int,
        currency: str,
        provider_reference: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "PaymentTransaction":
        """Construct a refund transaction in PENDING state."""
        return cls(
            purchase_id=purchase_id,
            transaction_type=_TXN_TYPE_REFUND,
            parent_transaction_id=parent_transaction_id,
            amount_cents=amount_cents,
            currency=currency,
            provider=provider,
            provider_reference=provider_reference,
            status=PaymentStatus.PENDING,
            transaction_metadata=metadata or {},
        )

    # ====================================================================
    # LIFECYCLE
    # ====================================================================

    def mark_succeeded(self, *, provider_reference: str | None = None) -> None:
        """Transition status to SUCCEEDED."""
        if self.status not in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
            raise InvalidStateTransitionError(
                message=f"Cannot mark succeeded from {self.status.value!r}",
                code="TXN_STATUS_INVALID_TRANSITION",
            )
        now = datetime.now(timezone.utc)
        self.status = PaymentStatus.SUCCEEDED
        self.processed_at = now
        if provider_reference is not None:
            self.provider_reference = provider_reference
        if self.transaction_type == _TXN_TYPE_REFUND:
            self.refunded_at = now

    def mark_failed(
        self,
        *,
        failure_code: str,
        failure_message: str | None = None,
    ) -> None:
        """Transition status to FAILED."""
        if self.status not in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
            raise InvalidStateTransitionError(
                message=f"Cannot mark failed from {self.status.value!r}",
                code="TXN_STATUS_INVALID_TRANSITION",
            )
        self.status = PaymentStatus.FAILED
        self.failed_at = datetime.now(timezone.utc)
        self.failure_code = failure_code.strip()
        if failure_message:
            self.failure_message = failure_message.strip()

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_succeeded(self) -> bool:
        return self.status == PaymentStatus.SUCCEEDED

    @property
    def is_failed(self) -> bool:
        return self.status == PaymentStatus.FAILED

    @property
    def is_charge(self) -> bool:
        return self.transaction_type == _TXN_TYPE_CHARGE

    @property
    def is_refund(self) -> bool:
        return self.transaction_type == _TXN_TYPE_REFUND

    @property
    def amount_display(self) -> str:
        """Human-readable amount (e.g. 'USD 499.00')."""
        whole = self.amount_cents // 100
        cents = self.amount_cents % 100
        return f"{self.currency} {whole}.{cents:02d}"


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.analyst import AnalystProfile
#     from app.models.workspace import Workspace
#     from app.models.user import User
#     from app.models.case import SecurityCase, CaseAccessGrant
#
# class AnalystServiceOffering(...):
#     ...
#     analyst: Mapped["AnalystProfile"] = relationship("AnalystProfile")
#     workspace: Mapped["Workspace"] = relationship("Workspace")
#     purchases: Mapped[list["ServicePurchase"]] = relationship(
#         "ServicePurchase", back_populates="offering"
#     )
#
# class ServicePurchase(...):
#     ...
#     offering: Mapped["AnalystServiceOffering | None"] = relationship(
#         "AnalystServiceOffering", back_populates="purchases"
#     )
#     buyer: Mapped["User"] = relationship(
#         "User", foreign_keys=[buyer_user_id]
#     )
#     buyer_workspace: Mapped["Workspace | None"] = relationship(
#         "Workspace"
#     )
#     case: Mapped["SecurityCase | None"] = relationship("SecurityCase")
#     access_grant: Mapped["CaseAccessGrant | None"] = relationship(
#         "CaseAccessGrant"
#     )
#     transactions: Mapped[list["PaymentTransaction"]] = relationship(
#         "PaymentTransaction",
#         back_populates="purchase",
#         cascade="all, delete-orphan",
#     )
#
# class PaymentTransaction(...):
#     ...
#     purchase: Mapped["ServicePurchase"] = relationship(
#         "ServicePurchase", back_populates="transactions"
#     )
#     parent_transaction: Mapped["PaymentTransaction | None"] = relationship(
#         "PaymentTransaction",
#         remote_side="PaymentTransaction.id",
#         foreign_keys=[parent_transaction_id],
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AnalystServiceOffering",
    "ServicePurchase",
    "PaymentTransaction",
    "_OFFERING_TYPE_FIXED",
    "_OFFERING_TYPE_HOURLY",
    "_OFFERING_TYPE_SUBSCRIPTION",
    "_VALID_OFFERING_TYPES",
    "_TXN_TYPE_CHARGE",
    "_TXN_TYPE_REFUND",
    "_TXN_TYPE_ADJUSTMENT",
    "_VALID_TXN_TYPES",
    "_VALID_PROVIDERS",
    "_VALID_INTERVALS",
    "_DELIVERY_NOT_STARTED",
    "_DELIVERY_IN_PROGRESS",
    "_DELIVERY_DELIVERED",
    "_DELIVERY_ACCEPTED",
    "_DELIVERY_DISPUTED",
    "_VALID_DELIVERY_STATUSES",
    "_CANCEL_POLICY_FULL_REFUND",
    "_CANCEL_POLICY_PARTIAL_REFUND",
    "_CANCEL_POLICY_NO_REFUND",
    "_VALID_CANCEL_POLICIES",
    "_MAX_TITLE_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_CATEGORY_LENGTH",
    "_MAX_CURRENCY_LENGTH",
    "_MAX_PROVIDER_REFERENCE_LENGTH",
    "_MAX_IDEMPOTENCY_KEY_LENGTH",
    "_MAX_REASON_LENGTH",
    "_MAX_METADATA_BYTES",
    "_MAX_SLOTS",
    "_MAX_PRICE_CENTS",
    "_CURRENCY_PATTERN",
]