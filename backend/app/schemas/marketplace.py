"""
CyberGuard AI — Marketplace Schemas
============================================================================

Request/response DTOs for the marketplace tables:

    - ``analyst_service_offerings``  — what analysts sell
    - ``service_purchases``          — a customer buying an offering
    - ``payment_transactions``       — individual payment records

Design rules
------------
1. **Money is integer cents + ISO 4217 currency, never floats.**
   Every monetary field in every schema follows this rule. The
   ``price_display`` / ``amount_display`` computed fields render
   the human-readable form (e.g. ``"USD 499.00"``) without any
   float rounding.

2. **Currency is validated against ISO 4217.**
   3-letter uppercase code (``USD``, ``INR``, ``EUR``, etc.). Lowercase
   input is normalized. Full ISO validation (that the code exists) is
   deferred to the payment provider — we only enforce shape here.

3. **``price_cents`` is not what the customer pays.**
   The purchase records its own ``amount_cents`` (the price *at
   purchase time*) — an offering can change price after a purchase
   without retroactively altering what the customer paid.

4. **``idempotency_key`` is client-supplied.**
   Optional but recommended. Unique per ``(buyer_user_id, idempotency_key)``
   in the DB. When the client retries a checkout after a network
   blip, the second request returns the existing purchase instead of
   creating a duplicate.

5. **Payment status vs delivery status are orthogonal.**
   Payment can succeed while delivery hasn't started. Delivery can
   complete while a refund is pending. Both are exposed separately.

6. **``case_id`` and ``access_grant_id`` on purchase are the critical links.**
   The whole marketplace flow revolves around: purchase → case created
   → access grant created → analyst works. These FKs are set by
   ``marketplace_service`` after the corresponding rows are created.

7. **Provider references, not provider secrets.**
   ``provider_reference`` (e.g. Stripe's ``ch_...``) is safe to expose.
   The platform never touches card numbers, CVVs, or API keys.

8. **Refunds are new transaction rows.**
   ``PaymentTransactionRefund`` creates a new transaction that
   references the original via ``parent_transaction_id``. Not an
   update to the original — the audit trail requires both events.

9. **Subscriptions carry renewal metadata.**
   ``subscription_interval`` (``weekly`` / ``monthly`` / ``yearly``)
   and ``subscription_renewal_at`` are exposed on the purchase read
   schema. Clients render "next renewal in 27 days" from these.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.models.enums import (
    PaymentStatus,
    PurchaseStatus,
    ServiceOfferingStatus,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_OFFERING_TYPES = frozenset({"fixed", "hourly", "subscription"})
_SUBSCRIPTION_INTERVALS = frozenset({"weekly", "monthly", "yearly"})
_TXN_TYPES = frozenset({"charge", "refund", "adjustment"})
_PROVIDERS = frozenset({"stripe", "razorpay", "manual", "internal"})
_DELIVERY_STATUSES = frozenset({
    "not_started", "in_progress", "delivered", "accepted", "disputed",
})
_CANCEL_POLICIES = frozenset({
    "full_refund", "partial_refund", "no_refund",
})

_TITLE_MAX = 200
_DESCRIPTION_MAX = 10_000
_CATEGORY_MAX = 64
_CURRENCY_LENGTH = 3
_PROVIDER_REFERENCE_MAX = 255
_IDEMPOTENCY_KEY_MAX = 128
_REASON_MAX = 1000
_METADATA_MAX_BYTES = 64 * 1024

#: Sanity cap on price — $1 billion in cents. Anything above is a typo.
_MAX_PRICE_CENTS = 100_000_000_00

_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")


# ============================================================================
# OFFERING — CREATE
# ============================================================================

class OfferingCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /marketplace/offerings``.

    Called by a verified analyst to publish a service they offer.
    The service sets ``analyst_id`` = current user's analyst profile
    and ``workspace_id`` = analyst's default workspace.
    """

    title: str = Field(
        ...,
        min_length=1,
        max_length=_TITLE_MAX,
        description="Display title (e.g. 'Phishing Email Investigation').",
    )

    description: str = Field(
        ...,
        min_length=1,
        max_length=_DESCRIPTION_MAX,
        description="Long-form description shown on the offering detail page.",
    )

    category: str = Field(
        ...,
        min_length=1,
        max_length=_CATEGORY_MAX,
        description=(
            "Service category (phishing, malware, network, compliance, "
            "incident_response, forensic_analysis, other)."
        ),
    )

    offering_type: Literal["fixed", "hourly", "subscription"] = Field(
        ...,
        description=(
            "fixed — one price, one service. "
            "hourly — rate × hours worked. "
            "subscription — recurring charge."
        ),
    )

    price_cents: int = Field(
        ...,
        ge=0,
        le=_MAX_PRICE_CENTS,
        description="Price in the smallest currency unit (cents, paise, etc.).",
    )

    currency: str = Field(
        ...,
        min_length=_CURRENCY_LENGTH,
        max_length=_CURRENCY_LENGTH,
        description="ISO 4217 currency code (USD, EUR, INR, ...).",
    )

    turnaround_hours: int | None = Field(
        default=None,
        ge=1,
        le=720,
        description="Promised turnaround in hours (e.g. 24 for a 1-day investigation).",
    )

    deliverables: list[str] = Field(
        default_factory=list,
        description="List of deliverables (e.g. ['PDF report', 'Raw IOCs']).",
    )

    slots_available: int | None = Field(
        default=None,
        ge=0,
        le=1_000_000,
        description=(
            "Capacity limit. NULL = unlimited. The purchase flow "
            "decrements slots_used atomically."
        ),
    )

    subscription_interval: Literal["weekly", "monthly", "yearly"] | None = Field(
        default=None,
        description="Required for offering_type='subscription'. Ignored otherwise.",
    )

    @field_validator("title")
    @classmethod
    def _clean_title(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @field_validator("category")
    @classmethod
    def _clean_category(cls, v: str) -> str:
        normalized = v.strip().lower()
        if not normalized:
            raise ValueError("category must not be empty")
        return normalized

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, v: str) -> str:
        normalized = v.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValueError("currency must be a 3-letter ISO 4217 code")
        return normalized

    @field_validator("deliverables")
    @classmethod
    def _clean_deliverables(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each deliverable must be a string")
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 200:
                raise ValueError("each deliverable must not exceed 200 characters")
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    @field_validator("subscription_interval")
    @classmethod
    def _validate_subscription_interval(
        cls, v: str | None, info,
    ) -> str | None:
        offering_type = info.data.get("offering_type")
        if offering_type == "subscription" and v is None:
            raise ValueError(
                "subscription_interval is required when offering_type='subscription'"
            )
        if v is not None and v not in _SUBSCRIPTION_INTERVALS:
            raise ValueError(
                f"subscription_interval must be one of "
                f"{sorted(_SUBSCRIPTION_INTERVALS)}"
            )
        return v


# ============================================================================
# OFFERING — READ
# ============================================================================

class OfferingRead(TimestampedModel):
    """
    Full offering view. Returned by ``GET /marketplace/offerings/{id}``.
    """

    id: uuid.UUID
    analyst_id: uuid.UUID
    workspace_id: uuid.UUID

    title: str
    description: str
    category: str

    offering_type: str
    price_cents: int
    currency: str

    turnaround_hours: int | None = None
    deliverables: list[str] = Field(default_factory=list)

    status: ServiceOfferingStatus
    slots_available: int | None = None
    slots_used: int = 0

    subscription_interval: str | None = None

    purchase_count: int = 0
    rating_average: float | None = None
    rating_count: int = 0

    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_active: bool = Field(..., description="True if status is ACTIVE.")
    is_draft: bool = Field(..., description="True if status is DRAFT.")
    is_paused: bool = Field(..., description="True if status is PAUSED.")
    is_archived: bool = Field(..., description="True if status is ARCHIVED.")
    is_sold_out: bool = Field(
        ..., description="True if all available slots are used.",
    )
    slots_remaining: int | None = Field(
        default=None,
        description="Slots left, or None if unlimited.",
    )
    price_display: str = Field(
        ...,
        description="Human-readable price (e.g. 'USD 499.00').",
    )


class OfferingList(ORMModel):
    """
    Lightweight offering view for marketplace browsing.
    """

    id: uuid.UUID
    analyst_id: uuid.UUID
    title: str
    category: str
    offering_type: str
    price_cents: int
    currency: str
    status: ServiceOfferingStatus
    turnaround_hours: int | None = None
    slots_available: int | None = None
    slots_used: int = 0
    rating_average: float | None = None
    rating_count: int = 0
    is_active: bool = False
    price_display: str = ""


# ============================================================================
# OFFERING — UPDATE / STATUS
# ============================================================================

class OfferingUpdate(CyberGuardBaseSchema):
    """
    Fields an analyst can change about their own offering.

    Cannot change:
        - ``analyst_id`` / ``workspace_id`` — ownership, immutable
        - ``slots_used`` / ``purchase_count`` / ``rating_*`` — server-computed
    """

    title: str | None = Field(default=None, min_length=1, max_length=_TITLE_MAX)
    description: str | None = Field(default=None, min_length=1, max_length=_DESCRIPTION_MAX)
    category: str | None = Field(default=None, min_length=1, max_length=_CATEGORY_MAX)
    price_cents: int | None = Field(default=None, ge=0, le=_MAX_PRICE_CENTS)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    turnaround_hours: int | None = Field(default=None, ge=1, le=720)
    deliverables: list[str] | None = None
    slots_available: int | None = Field(default=None, ge=0, le=1_000_000)
    subscription_interval: Literal["weekly", "monthly", "yearly"] | None = None

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValueError("currency must be a 3-letter ISO 4217 code")
        return normalized


class OfferingStatusUpdate(CyberGuardBaseSchema):
    """
    Request body for ``PATCH /marketplace/offerings/{id}/status``.

    Allowed transitions:
        DRAFT → ACTIVE
        ACTIVE → PAUSED
        PAUSED → ACTIVE
        any → ARCHIVED (terminal)
    """

    status: ServiceOfferingStatus = Field(...)


# ============================================================================
# OFFERING — FILTER
# ============================================================================

class OfferingFilter(CyberGuardBaseSchema):
    """
    Query parameters for ``GET /marketplace/offerings``.

    The marketplace listing is filtered to ``status=ACTIVE`` by default
    (only published offerings are browsable). Set ``status=null``
    explicitly to see the analyst's own drafts.
    """

    status: ServiceOfferingStatus | None = Field(
        default=None,
        description="Filter by status. Defaults to ACTIVE for browsing.",
    )
    category: str | None = Field(default=None, max_length=_CATEGORY_MAX)
    offering_type: Literal["fixed", "hourly", "subscription"] | None = None

    analyst_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to offerings from a specific analyst.",
    )

    currency: str | None = Field(default=None, min_length=3, max_length=3)

    max_price_cents: int | None = Field(default=None, ge=0, le=_MAX_PRICE_CENTS)
    min_price_cents: int | None = Field(default=None, ge=0, le=_MAX_PRICE_CENTS)

    search: str | None = Field(
        default=None,
        max_length=200,
        description="Substring search across title and description.",
    )

    has_slots: bool | None = Field(
        default=None,
        description="If True, only offerings with available slots.",
    )

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().upper()
        if not _CURRENCY_PATTERN.match(normalized):
            raise ValueError("currency must be a 3-letter ISO 4217 code")
        return normalized

    @field_validator("search")
    @classmethod
    def _clean_search(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# PURCHASE — CREATE
# ============================================================================

class PurchaseCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /marketplace/purchases``.

    Creates a pending purchase. The service then creates a payment
    transaction (using the client-specified provider) and awaits the
    provider's webhook to confirm success.

    ``idempotency_key`` is client-generated. On retry, the same key
    returns the existing purchase instead of creating a duplicate.
    """

    offering_id: uuid.UUID = Field(...)

    buyer_workspace_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Workspace context for the purchase. If omitted, uses the "
            "buyer's default personal workspace."
        ),
    )

    idempotency_key: str | None = Field(
        default=None,
        min_length=8,
        max_length=_IDEMPOTENCY_KEY_MAX,
        description=(
            "Client-generated key (e.g. a UUID). Prevents duplicate "
            "purchases on retry. Recommended for all checkout flows."
        ),
    )

    cancellation_policy: Literal[
        "full_refund", "partial_refund", "no_refund",
    ] = Field(
        default="full_refund",
        description=(
            "What happens if the buyer cancels before delivery. "
            "full_refund: 100% returned. partial_refund: some kept. "
            "no_refund: non-refundable."
        ),
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional buyer-supplied context (e.g. project ID).",
    )


# ============================================================================
# PURCHASE — READ
# ============================================================================

class PurchaseRead(TimestampedModel):
    """
    Full purchase view. Returned by ``GET /marketplace/purchases/{id}``.
    """

    id: uuid.UUID
    offering_id: uuid.UUID | None = None
    buyer_user_id: uuid.UUID
    buyer_workspace_id: uuid.UUID | None = None

    amount_cents: int
    currency: str
    amount_paid_cents: int = 0
    amount_refunded_cents: int = 0

    purchase_status: PurchaseStatus
    payment_status: PaymentStatus
    delivery_status: str

    engagement_start_at: datetime | None = None
    engagement_end_at: datetime | None = None
    subscription_renewal_at: datetime | None = None
    subscription_interval: str | None = None

    case_id: uuid.UUID | None = None
    access_grant_id: uuid.UUID | None = None

    cancellation_policy: str
    cancellation_reason: str | None = None
    cancelled_at: datetime | None = None
    cancelled_by_id: uuid.UUID | None = None

    completed_at: datetime | None = None
    delivery_accepted_at: datetime | None = None

    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_paid: bool = Field(..., description="True if payment succeeded.")
    is_completed: bool = Field(..., description="True if purchase is COMPLETED.")
    is_cancelled: bool = Field(..., description="True if purchase is CANCELLED.")
    is_refunded: bool = Field(..., description="True if purchase is REFUNDED.")
    is_in_progress: bool = Field(..., description="True if purchase is IN_PROGRESS.")
    has_case: bool = Field(..., description="True if the case has been provisioned.")
    net_revenue_cents: int = Field(
        ..., description="Amount actually kept (paid minus refunded), in cents.",
    )
    amount_display: str = Field(
        ..., description="Human-readable amount (e.g. 'USD 499.00').",
    )
    days_until_renewal: int | None = Field(
        default=None,
        description="For subscriptions: days until the next renewal.",
    )


class PurchaseList(ORMModel):
    """
    Lightweight purchase view for the buyer's purchase history.
    """

    id: uuid.UUID
    offering_id: uuid.UUID | None = None
    buyer_user_id: uuid.UUID
    amount_cents: int
    currency: str
    purchase_status: PurchaseStatus
    payment_status: PaymentStatus
    delivery_status: str
    case_id: uuid.UUID | None = None
    created_at: datetime
    completed_at: datetime | None = None
    amount_display: str = ""


# ============================================================================
# PURCHASE — CANCEL
# ============================================================================

class PurchaseCancelRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /marketplace/purchases/{id}/cancel``.

    Cancels the purchase. What happens to the payment depends on
    ``cancellation_policy`` set at creation. The service creates a
    refund transaction automatically if the policy permits and
    payment was already captured.
    """

    reason: str = Field(
        ...,
        min_length=1,
        max_length=_REASON_MAX,
        description="Why the buyer is cancelling.",
    )


# ============================================================================
# PAYMENT TRANSACTION
# ============================================================================

class PaymentTransactionRead(TimestampedModel):
    """
    Full payment transaction view. Returned by
    ``GET /marketplace/purchases/{id}/transactions``.
    """

    id: uuid.UUID
    purchase_id: uuid.UUID
    transaction_type: str
    parent_transaction_id: uuid.UUID | None = None
    amount_cents: int
    currency: str
    provider: str
    provider_reference: str | None = None
    status: PaymentStatus

    processed_at: datetime | None = None
    failed_at: datetime | None = None
    refunded_at: datetime | None = None

    failure_code: str | None = None
    failure_message: str | None = None

    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_succeeded: bool = Field(..., description="True if status is SUCCEEDED.")
    is_failed: bool = Field(..., description="True if status is FAILED.")
    is_charge: bool = Field(..., description="True if transaction_type is 'charge'.")
    is_refund: bool = Field(..., description="True if transaction_type is 'refund'.")
    amount_display: str = Field(..., description="Human-readable amount.")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "OfferingCreate",
    "OfferingRead",
    "OfferingList",
    "OfferingUpdate",
    "OfferingStatusUpdate",
    "OfferingFilter",
    "PurchaseCreate",
    "PurchaseRead",
    "PurchaseList",
    "PurchaseCancelRequest",
    "PaymentTransactionRead",
]