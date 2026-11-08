"""
CyberGuard AI — Marketplace Service
============================================================================

The analyst marketplace: offering publication, purchase, payment
tracking, engagement lifecycle, and provisioning.

The core flow
-------------
    1. Analyst publishes offering  (AnalystServiceOffering, ACTIVE)
    2. Client browses offerings    (public, no auth needed)
    3. Client checks out           → ServicePurchase (PENDING)
    4. Provider webhook confirms   → PaymentTransaction (SUCCEEDED)
    5. Purchase flips to PAID
    6. Service provisions:
         a. Creates a SecurityCase
         b. Creates a CaseAccessGrant (scoped access for the analyst)
         c. Links both IDs onto the purchase (case_id, access_grant_id)
         d. Flips purchase to IN_PROGRESS
    7. Analyst works the case via case_service
    8. Client accepts deliverables → purchase COMPLETED
    9. (Optional) rating written → offering rating updates

This service owns steps 1–6, 8, and 9. Step 7 is handled by
``case_service``.

Idempotency
-----------
Checkout retries are common (network blips, user double-clicks). Every
purchase accepts an ``idempotency_key`` — unique per ``(buyer_user_id,
key)``. A retry with the same key returns the existing purchase
instead of creating a duplicate.

Clients generate the key (a UUID) before the first attempt and reuse it
for every retry until the request succeeds.

Payment model
-------------
The platform never touches card numbers. The provider (Stripe,
Razorpay, etc.) handles the charge. This service stores:

    - provider (string: "stripe", "razorpay", "manual", "internal")
    - provider_reference (Stripe's ``ch_...``, Razorpay's ``pay_...``)
    - amount_cents, currency (in the purchase)
    - status (SUCCEEDED, FAILED, PENDING)

The provider's webhook calls ``record_payment_result`` with the
provider_reference. This service matches it to the pending
transaction and updates status.

Refunds
-------
Refunds are **new transactions**, not updates to the original. Every
refund is a ``PaymentTransaction`` with ``transaction_type='refund'``
and ``parent_transaction_id`` pointing to the original charge. This
preserves the complete audit trail and matches how real payment
processors report.

Cancellation policy
-------------------
Set at purchase creation:
    - full_refund   — client gets 100% back
    - partial_refund — some fraction (defined by the analyst)
    - no_refund     — non-refundable

Enforced by ``cancel_purchase``: it checks the policy and creates the
refund transaction if applicable. Both the cancel and the refund are
audited.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Auditing: purchases, cancellations, refunds, provisionings are
   audited. Routine updates to ``amount_paid_cents`` on a successful
   charge are not separately audited — the transaction row is the
   audit record.

Public API — offerings
----------------------
    create_offering(db, *, actor, payload)          → AnalystServiceOffering
    update_offering(db, *, actor, offering, payload) → AnalystServiceOffering
    publish_offering(db, *, actor, offering)         → AnalystServiceOffering
    pause_offering(db, *, actor, offering)           → AnalystServiceOffering
    resume_offering(db, *, actor, offering)          → AnalystServiceOffering
    archive_offering(db, *, actor, offering)         → AnalystServiceOffering
    get_offering_by_id(db, offering_id)              → AnalystServiceOffering
    list_offerings(db, *, page, filters)             → (list, int)

Public API — purchases
----------------------
    create_purchase(db, *, actor, payload)           → ServicePurchase
    get_purchase_by_id(db, purchase_id)              → ServicePurchase
    list_purchases(db, *, actor, page, filters)      → (list, int)
    record_payment_result(db, *, purchase_id, transaction_id,
                          succeeded, provider_reference, ...)
                                                     → PaymentTransaction
    provision_case(db, *, purchase, actor=None)      → ServicePurchase
    mark_delivered(db, *, actor, purchase)           → ServicePurchase
    accept_delivery(db, *, actor, purchase)          → ServicePurchase
    cancel_purchase(db, *, actor, purchase, reason)  → ServicePurchase
    issue_refund(db, *, actor, purchase, amount_cents, reason)
                                                     → PaymentTransaction

Public API — listings
---------------------
    get_purchase_transactions(db, *, actor, purchase_id) → list[PaymentTransaction]

Usage
-----
    from app.services import marketplace_service

    # Analyst publishes an offering
    offering = marketplace_service.create_offering(
        db, actor=analyst, payload=OfferingCreate(
            title="Phishing Email Investigation",
            description="Full forensics with PDF report.",
            category="phishing",
            offering_type="fixed",
            price_cents=49900,
            currency="USD",
            turnaround_hours=24,
            deliverables=["PDF report", "IOC list", "Remediation plan"],
        ),
    )
    marketplace_service.publish_offering(db, actor=analyst, offering=offering)
    db.commit()

    # Client purchases
    purchase = marketplace_service.create_purchase(
        db, actor=priya, payload=PurchaseCreate(
            offering_id=offering.id,
            idempotency_key="checkout-uuid-abc",
        ),
    )
    db.commit()

    # Provider webhook confirms charge
    marketplace_service.record_payment_result(
        db,
        purchase_id=purchase.id,
        transaction_id=stripe_txn_id,
        succeeded=True,
        provider_reference="ch_abc123",
    )
    marketplace_service.provision_case(db, purchase=purchase)
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.analyst import AnalystProfile
from app.models.case import CaseAccessGrant, SecurityCase
from app.models.enums import (
    AccessGrantScope,
    AnalystVerificationStatus,
    CasePriority,
    CaseStatus,
    EventSeverity,
    FindingCategory,
    PaymentStatus,
    PurchaseStatus,
    ServiceOfferingStatus,
)
from app.models.marketplace import (
    AnalystServiceOffering,
    PaymentTransaction,
    ServicePurchase,
)
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.common import PageParams
from app.schemas.marketplace import (
    OfferingCreate,
    OfferingFilter,
    OfferingUpdate,
    PurchaseCreate,
)
from app.services import (
    audit_service,
    authorization,
    notification_service,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

_OFFERING_STATUS_TRANSITIONS: dict[ServiceOfferingStatus, frozenset[ServiceOfferingStatus]] = {
    ServiceOfferingStatus.DRAFT: frozenset({ServiceOfferingStatus.ACTIVE, ServiceOfferingStatus.ARCHIVED}),
    ServiceOfferingStatus.ACTIVE: frozenset({
        ServiceOfferingStatus.PAUSED,
        ServiceOfferingStatus.ARCHIVED,
    }),
    ServiceOfferingStatus.PAUSED: frozenset({
        ServiceOfferingStatus.ACTIVE,
        ServiceOfferingStatus.ARCHIVED,
    }),
    ServiceOfferingStatus.ARCHIVED: frozenset(),  # terminal
}

_PURCHASE_TERMINAL_STATUSES = frozenset({
    PurchaseStatus.COMPLETED,
    PurchaseStatus.CANCELLED,
    PurchaseStatus.REFUNDED,
})

#: Cancellation refund percentage by policy.
_CANCEL_REFUND_PCT = {
    "full_refund": 100,
    "partial_refund": 50,
    "no_refund": 0,
}


# ============================================================================
# INTERNAL — offering lookups
# ============================================================================

def _get_analyst_profile(db: Session, user: User) -> AnalystProfile:
    """Fetch the analyst profile for a user, raising if missing."""
    profile = db.execute(
        select(AnalystProfile).where(AnalystProfile.user_id == user.id)
    ).scalar_one_or_none()
    if profile is None:
        raise AuthorizationError(
            message="An analyst profile is required to manage offerings.",
            code="ANALYST_PROFILE_REQUIRED",
        )
    return profile


def _assert_offering_owner(
    db: Session,
    actor: User,
    offering: AnalystServiceOffering,
) -> AnalystProfile:
    """Verify the actor owns the offering; return their profile."""
    profile = _get_analyst_profile(db, actor)
    if profile.id != offering.analyst_id:
        raise AuthorizationError(
            message="You do not own this offering.",
            code="OFFERING_NOT_YOURS",
            details={"offering_id": str(offering.id)},
        )
    return profile


# ============================================================================
# OFFERINGS — CREATE / UPDATE
# ============================================================================

def create_offering(
    db: Session,
    *,
    actor: User,
    payload: OfferingCreate,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """
    Create a new offering in DRAFT status.

    Requires the actor to be a **verified** analyst (their profile must
    have ``verification_status == VERIFIED``). Draft offerings can be
    created by unverified analysts (useful for building them up while
    waiting for approval), but only verified analysts can publish.
    """
    profile = _get_analyst_profile(db, actor)

    # Drafts can be created by anyone with an analyst profile
    # Only publishing requires verified status — checked in
    # ``publish_offering``

    # Ensure the analyst has a personal workspace to publish under
    from app.services import workspace_service
    personal_ws = workspace_service.get_personal_workspace_optional(db, actor.id)
    if personal_ws is None:
        personal_ws = workspace_service.create_personal_workspace(db, actor)

    offering = AnalystServiceOffering.build(
        analyst_id=profile.id,
        workspace_id=personal_ws.id,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        offering_type=payload.offering_type,
        price_cents=payload.price_cents,
        currency=payload.currency,
        turnaround_hours=payload.turnaround_hours,
        deliverables=payload.deliverables,
        slots_available=payload.slots_available,
        subscription_interval=payload.subscription_interval,
        status=ServiceOfferingStatus.DRAFT,
    )
    db.add(offering)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.created",
        target_type="service_offering",
        target_id=offering.id,
        target_display=offering.title[:100],
        workspace_id=personal_ws.id,
        request=request,
        metadata={
            "offering_type": payload.offering_type,
            "price_cents": payload.price_cents,
            "currency": payload.currency,
        },
    )

    logger.info(
        "Offering created",
        extra={
            "offering_id": str(offering.id),
            "analyst_id": str(profile.id),
            "offering_type": payload.offering_type,
        },
    )

    return offering


def update_offering(
    db: Session,
    *,
    actor: User,
    offering: AnalystServiceOffering,
    payload: OfferingUpdate,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """
    Update an offering's mutable fields. Only the owning analyst can
    update. Cannot change ``analyst_id``, ``slots_used``, or ``status``.
    """
    _assert_offering_owner(db, actor, offering)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return offering

    for field, value in updates.items():
        setattr(offering, field, value)

    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.updated",
        target_type="service_offering",
        target_id=offering.id,
        workspace_id=offering.workspace_id,
        request=request,
        metadata={"fields_changed": list(updates.keys())},
    )

    return offering


# ============================================================================
# OFFERINGS — LIFECYCLE
# ============================================================================

def publish_offering(
    db: Session,
    *,
    actor: User,
    offering: AnalystServiceOffering,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """
    Publish an offering. Requires the analyst be VERIFIED.
    """
    profile = _assert_offering_owner(db, actor, offering)

    if profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise AuthorizationError(
            message=(
                "Only verified analysts can publish offerings. "
                f"Current status: {profile.verification_status.value}."
            ),
            code="ANALYST_NOT_VERIFIED",
        )

    if ServiceOfferingStatus.ACTIVE not in _OFFERING_STATUS_TRANSITIONS.get(
        offering.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=f"Cannot publish from status {offering.status.value}.",
            code="OFFERING_INVALID_TRANSITION",
        )

    offering.status = ServiceOfferingStatus.ACTIVE
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.published",
        target_type="service_offering",
        target_id=offering.id,
        workspace_id=offering.workspace_id,
        request=request,
    )

    return offering


def pause_offering(
    db: Session,
    *,
    actor: User,
    offering: AnalystServiceOffering,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """Pause an active offering (temporarily stop accepting new purchases)."""
    _assert_offering_owner(db, actor, offering)

    if ServiceOfferingStatus.PAUSED not in _OFFERING_STATUS_TRANSITIONS.get(
        offering.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=f"Cannot pause from status {offering.status.value}.",
            code="OFFERING_INVALID_TRANSITION",
        )

    offering.status = ServiceOfferingStatus.PAUSED
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.paused",
        target_type="service_offering",
        target_id=offering.id,
        workspace_id=offering.workspace_id,
        request=request,
    )

    return offering


def resume_offering(
    db: Session,
    *,
    actor: User,
    offering: AnalystServiceOffering,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """Resume a paused offering."""
    profile = _assert_offering_owner(db, actor, offering)

    if profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise AuthorizationError(
            message="Only verified analysts can resume offerings.",
            code="ANALYST_NOT_VERIFIED",
        )

    if ServiceOfferingStatus.ACTIVE not in _OFFERING_STATUS_TRANSITIONS.get(
        offering.status, frozenset()
    ):
        raise InvalidStateTransitionError(
            message=f"Cannot resume from status {offering.status.value}.",
            code="OFFERING_INVALID_TRANSITION",
        )

    offering.status = ServiceOfferingStatus.ACTIVE
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.resumed",
        target_type="service_offering",
        target_id=offering.id,
        workspace_id=offering.workspace_id,
        request=request,
    )

    return offering


def archive_offering(
    db: Session,
    *,
    actor: User,
    offering: AnalystServiceOffering,
    request: Any | None = None,
) -> AnalystServiceOffering:
    """
    Archive an offering (terminal). Existing purchases are unaffected
    — their purchase rows reference this offering via FK (SET NULL on
    hard delete), but the row is soft-retained.
    """
    _assert_offering_owner(db, actor, offering)

    if offering.status == ServiceOfferingStatus.ARCHIVED:
        return offering  # idempotent

    offering.status = ServiceOfferingStatus.ARCHIVED
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.offering.archived",
        target_type="service_offering",
        target_id=offering.id,
        workspace_id=offering.workspace_id,
        request=request,
    )

    return offering


# ============================================================================
# OFFERINGS — READ
# ============================================================================

def get_offering_by_id(
    db: Session,
    offering_id: uuid.UUID,
) -> AnalystServiceOffering:
    """Fetch an offering by ID."""
    offering = db.get(AnalystServiceOffering, offering_id)
    if offering is None or offering.deleted_at is not None:
        raise NotFoundError(
            message=f"Offering {offering_id} not found.",
            code="OFFERING_NOT_FOUND",
            details={"offering_id": str(offering_id)},
        )
    return offering


def list_offerings(
    db: Session,
    *,
    page: PageParams,
    filters: OfferingFilter | None = None,
) -> tuple[list[AnalystServiceOffering], int]:
    """
    List offerings. Default filter: only ACTIVE (the public marketplace).
    Analysts browsing their own drafts pass ``filters.status=DRAFT``.
    """
    stmt = select(AnalystServiceOffering).where(
        AnalystServiceOffering.deleted_at.is_(None),
    )

    if filters is not None:
        if filters.status is not None:
            stmt = stmt.where(AnalystServiceOffering.status == filters.status)
        else:
            stmt = stmt.where(AnalystServiceOffering.status == ServiceOfferingStatus.ACTIVE)
        if filters.category:
            stmt = stmt.where(AnalystServiceOffering.category == filters.category)
        if filters.offering_type:
            stmt = stmt.where(AnalystServiceOffering.offering_type == filters.offering_type)
        if filters.analyst_id is not None:
            stmt = stmt.where(AnalystServiceOffering.analyst_id == filters.analyst_id)
        if filters.currency:
            stmt = stmt.where(AnalystServiceOffering.currency == filters.currency.upper())
        if filters.min_price_cents is not None:
            stmt = stmt.where(AnalystServiceOffering.price_cents >= filters.min_price_cents)
        if filters.max_price_cents is not None:
            stmt = stmt.where(AnalystServiceOffering.price_cents <= filters.max_price_cents)
        if filters.search:
            s = f"%{filters.search.lower()}%"
            stmt = stmt.where(
                (AnalystServiceOffering.title.ilike(s))
                | (AnalystServiceOffering.description.ilike(s))
            )
        if filters.has_slots:
            stmt = stmt.where(
                (AnalystServiceOffering.slots_available.is_(None))
                | (AnalystServiceOffering.slots_used < AnalystServiceOffering.slots_available)
            )
    else:
        stmt = stmt.where(AnalystServiceOffering.status == ServiceOfferingStatus.ACTIVE)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            AnalystServiceOffering.rating_average.desc().nullslast(),
            AnalystServiceOffering.purchase_count.desc(),
            AnalystServiceOffering.created_at.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# PURCHASES — CREATE
# ============================================================================

def create_purchase(
    db: Session,
    *,
    actor: User,
    payload: PurchaseCreate,
    request: Any | None = None,
) -> ServicePurchase:
    """
    Create a new purchase in PENDING state.

    Idempotency
    -----------
    If ``payload.idempotency_key`` is set and a purchase with the same
    (buyer, key) exists, that purchase is returned instead of creating
    a new one. Prevents double-charges on retry.

    Flow
    ----
    1. Check idempotency
    2. Load offering (must be ACTIVE)
    3. Verify offering has available slots (atomic ``claim_slot``)
    4. Create purchase in PENDING (no charge yet)
    5. Return the purchase — the caller invokes the payment provider
       next (out of band)
    """
    # ── Idempotency check
    if payload.idempotency_key:
        existing = db.execute(
            select(ServicePurchase).where(
                ServicePurchase.buyer_user_id == actor.id,
                ServicePurchase.idempotency_key == payload.idempotency_key,
            )
        ).scalar_one_or_none()
        if existing is not None:
            logger.info(
                "Idempotent purchase retry",
                extra={
                    "purchase_id": str(existing.id),
                    "idempotency_key": payload.idempotency_key,
                },
            )
            return existing

    # ── Load offering
    offering = get_offering_by_id(db, payload.offering_id)

    if offering.status != ServiceOfferingStatus.ACTIVE:
        raise InvalidStateTransitionError(
            message=(
                f"Offering is not currently purchasable "
                f"(status: {offering.status.value})."
            ),
            code="OFFERING_NOT_PURCHASABLE",
        )

    if offering.is_sold_out:
        raise ConflictError(
            message="This offering has no available slots.",
            code="OFFERING_SOLD_OUT",
            details={
                "slots_available": offering.slots_available,
                "slots_used": offering.slots_used,
            },
        )

    # ── Claim a slot (atomic)
    try:
        offering.claim_slot()
    except Exception as exc:
        raise ConflictError(
            message=f"Could not claim a slot on this offering: {exc}",
            code="OFFERING_SLOT_CLAIM_FAILED",
        )

    # ── Create purchase
    purchase = ServicePurchase.build(
        offering_id=offering.id,
        buyer_user_id=actor.id,
        buyer_workspace_id=payload.buyer_workspace_id,
        amount_cents=offering.price_cents,
        currency=offering.currency,
        idempotency_key=payload.idempotency_key,
        cancellation_policy=payload.cancellation_policy,
        subscription_interval=offering.subscription_interval,
        metadata=payload.metadata,
    )
    db.add(purchase)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.purchase.created",
        target_type="service_purchase",
        target_id=purchase.id,
        target_display=offering.title[:100],
        workspace_id=payload.buyer_workspace_id,
        request=request,
        metadata={
            "offering_id": str(offering.id),
            "amount_cents": purchase.amount_cents,
            "currency": purchase.currency,
            "idempotency_key": payload.idempotency_key,
        },
    )

    logger.info(
        "Purchase created (awaiting payment)",
        extra={
            "purchase_id": str(purchase.id),
            "offering_id": str(offering.id),
            "buyer_user_id": str(actor.id),
            "amount_cents": purchase.amount_cents,
        },
    )

    return purchase


# ============================================================================
# PURCHASES — PAYMENT
# ============================================================================

def record_payment_result(
    db: Session,
    *,
    purchase_id: uuid.UUID,
    succeeded: bool,
    provider_reference: str | None = None,
    failure_code: str | None = None,
    failure_message: str | None = None,
    provider: str = "stripe",
    request: Any | None = None,
) -> PaymentTransaction:
    """
    Record the result of a payment attempt.

    Called by the payment provider's webhook (or by a background
    reconciler polling the provider). Two paths:

        succeeded=True → creates a SUCCEEDED transaction, updates
                         purchase to PAID, calls provision_case
        succeeded=False → creates a FAILED transaction, updates
                         purchase to CANCELLED, releases the offering slot

    Idempotent by ``provider_reference`` — a webhook that fires twice
    for the same charge updates the existing transaction row.

    Returns
    -------
    PaymentTransaction
        The transaction (new or updated).
    """
    purchase = db.get(ServicePurchase, purchase_id)
    if purchase is None:
        raise NotFoundError(
            message=f"Purchase {purchase_id} not found.",
            code="PURCHASE_NOT_FOUND",
        )

    if purchase.purchase_status in _PURCHASE_TERMINAL_STATUSES:
        # Already finalized — check for idempotency
        if provider_reference:
            existing_txn = db.execute(
                select(PaymentTransaction).where(
                    PaymentTransaction.purchase_id == purchase_id,
                    PaymentTransaction.provider_reference == provider_reference,
                )
            ).scalar_one_or_none()
            if existing_txn is not None:
                return existing_txn
        raise InvalidStateTransitionError(
            message=(
                f"Purchase is already {purchase.purchase_status.value}."
            ),
            code="PURCHASE_ALREADY_FINALIZED",
        )

    # ── Deduplicate by provider_reference
    if provider_reference:
        existing_txn = db.execute(
            select(PaymentTransaction).where(
                PaymentTransaction.purchase_id == purchase_id,
                PaymentTransaction.provider_reference == provider_reference,
            )
        ).scalar_one_or_none()
        if existing_txn is not None:
            logger.info(
                "Payment webhook deduplicated",
                extra={
                    "purchase_id": str(purchase_id),
                    "provider_reference": provider_reference,
                },
            )
            return existing_txn

    # ── Create transaction
    txn = PaymentTransaction.build_charge(
        purchase_id=purchase.id,
        provider=provider,
        amount_cents=purchase.amount_cents,
        currency=purchase.currency,
        provider_reference=provider_reference,
    )
    db.add(txn)
    db.flush()

    if succeeded:
        txn.mark_succeeded(provider_reference=provider_reference)
        purchase.mark_paid(amount_cents=purchase.amount_cents)
        db.flush()

        logger.info(
            "Payment succeeded",
            extra={
                "purchase_id": str(purchase.id),
                "txn_id": str(txn.id),
                "amount_cents": purchase.amount_cents,
            },
        )

        # Provision the case
        try:
            provision_case(db, purchase=purchase, request=request)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Payment succeeded but provisioning failed",
                extra={
                    "purchase_id": str(purchase.id),
                    "error": str(exc)[:200],
                },
            )
            # Payment status stays PAID, provisioning can be retried
            # via a separate admin action or background job

        # Increment offering purchase count
        offering = db.get(AnalystServiceOffering, purchase.offering_id) if purchase.offering_id else None
        if offering is not None:
            offering.purchase_count = (offering.purchase_count or 0) + 1
            db.flush()

    else:
        txn.mark_failed(
            failure_code=failure_code or "PAYMENT_FAILED",
            failure_message=failure_message,
        )
        purchase.mark_payment_failed()
        db.flush()

        # Release the slot
        offering = db.get(AnalystServiceOffering, purchase.offering_id) if purchase.offering_id else None
        if offering is not None:
            offering.release_slot()
            db.flush()

        logger.info(
            "Payment failed",
            extra={
                "purchase_id": str(purchase.id),
                "txn_id": str(txn.id),
                "failure_code": failure_code,
            },
        )

    audit_service.log_action(
        db,
        actor=None,
        actor_type="system",
        action="marketplace.payment.succeeded" if succeeded else "marketplace.payment.failed",
        target_type="payment_transaction",
        target_id=txn.id,
        workspace_id=purchase.buyer_workspace_id,
        request=request,
        metadata={
            "purchase_id": str(purchase.id),
            "amount_cents": purchase.amount_cents,
            "provider": provider,
            "provider_reference": provider_reference,
        },
    )

    return txn


# ============================================================================
# PROVISIONING
# ============================================================================

def provision_case(
    db: Session,
    *,
    purchase: ServicePurchase,
    request: Any | None = None,
) -> ServicePurchase:
    """
    Provision the case + access grant for a paid purchase.

    Called automatically by ``record_payment_result`` after a
    successful charge. Can also be called manually by an admin if
    automatic provisioning failed (e.g. transient DB error during the
    webhook).

    Steps
    -----
    1. Load offering + analyst
    2. Create the case (via ``case_service``) with ``is_billable=True``
    3. Create a ``CaseAccessGrant`` for the analyst (scope=FULL_CASE,
       purpose = "Paid engagement — purchase X")
    4. Link both IDs back onto the purchase
    5. Flip purchase to IN_PROGRESS
    6. Notify both analyst and buyer
    """
    if purchase.case_id is not None:
        return purchase  # already provisioned (idempotent)

    if purchase.offering_id is None:
        raise ValidationError(
            message="Purchase has no offering — cannot provision.",
            code="PURCHASE_OFFERING_MISSING",
        )

    offering = db.get(AnalystServiceOffering, purchase.offering_id)
    if offering is None:
        raise ValidationError(
            message="The offering no longer exists — cannot provision.",
            code="OFFERING_DELETED",
        )

    analyst_profile = db.get(AnalystProfile, offering.analyst_id)
    if analyst_profile is None:
        raise ValidationError(
            message="The analyst profile no longer exists.",
            code="ANALYST_PROFILE_DELETED",
        )
    analyst_user = db.get(User, analyst_profile.user_id)
    if analyst_user is None:
        raise ValidationError(
            message="The analyst user account no longer exists.",
            code="ANALYST_USER_DELETED",
        )

    buyer = db.get(User, purchase.buyer_user_id)
    if buyer is None:
        raise ValidationError(
            message="The buyer account no longer exists.",
            code="BUYER_DELETED",
        )

    # ── 1. Create the case (via case_service)
    from app.services import case_service
    from app.schemas.case import CaseCreate

    # Map offering to case fields
    # Offering category → finding category (best-effort)
    try:
        finding_category = FindingCategory(offering.category)
    except ValueError:
        finding_category = FindingCategory.OTHER

    case = case_service.create_case(
        db,
        dto=CaseCreate(
            title=offering.title,
            description=(
                f"Marketplace engagement: {offering.title}\n\n"
                f"{offering.description}\n\n"
                f"Turnaround: {offering.turnaround_hours or 'as agreed'} hours"
            ),
            priority=CasePriority.HIGH,      # paid engagements get priority
            severity=EventSeverity.MEDIUM,
            category=finding_category,
            assigned_to_id=analyst_user.id,
            is_billable=True,
            linked_engagement_id=purchase.id,
        ),
        actor=None,   # system-created
    )

    # ── 2. Create access grant for the analyst
    # The analyst is NOT a workspace member (usually), so they need
    # FULL_CASE to actually work the case. Buyer is the workspace owner,
    # so we pass them as the granting actor.
    grant = CaseAccessGrant.build(
        case_id=case.id,
        grantee_user_id=analyst_user.id,
        granted_by_id=buyer.id,
        scope=AccessGrantScope.FULL_CASE,
        purpose=f"Paid marketplace engagement — purchase {purchase.id}",
        notes=(
            f"Offering: {offering.title}. "
            f"Price: {purchase.currency} {purchase.amount_cents // 100}."
        ),
    )
    db.add(grant)
    db.flush()

    # ── 3. Link back to purchase
    purchase.attach_case(case_id=case.id, access_grant_id=grant.id)
    purchase.engagement_start_at = datetime.now(timezone.utc)
    if offering.turnaround_hours:
        purchase.engagement_end_at = (
            purchase.engagement_start_at
            + timedelta(hours=offering.turnaround_hours)
        )
    purchase.start_delivery()
    db.flush()

    # ── 4. Audit
    audit_service.log_analyst_access_granted(
        db,
        granted_by=buyer,
        grantee_user_id=analyst_user.id,
        case_id=case.id,
        workspace_id=case.workspace_id,
        scope=AccessGrantScope.FULL_CASE.value,
        purpose=f"Paid marketplace engagement — purchase {purchase.id}",
        expires_at=None,
        request=request,
    )

    audit_service.log_action(
        db,
        actor=None,
        actor_type="system",
        action="marketplace.purchase.provisioned",
        target_type="service_purchase",
        target_id=purchase.id,
        workspace_id=case.workspace_id,
        request=request,
        metadata={
            "case_id": str(case.id),
            "access_grant_id": str(grant.id),
            "analyst_user_id": str(analyst_user.id),
        },
    )

    logger.info(
        "Purchase provisioned",
        extra={
            "purchase_id": str(purchase.id),
            "case_id": str(case.id),
            "grant_id": str(grant.id),
            "analyst_user_id": str(analyst_user.id),
        },
    )

    # ── 5. Notify both sides
    try:
        # Analyst gets assignment notification (created by case_service)
        # Buyer gets "engagement started" notification
        notification_service.create(
            db,
            recipient_id=buyer.id,
            notification_type=notification_service.NotificationType.CASE_ASSIGNED,
            title=f"Your engagement has started: {offering.title[:100]}",
            body=(
                f"Case #{case.case_number} has been created and assigned "
                f"to your analyst. Expected turnaround: "
                f"{offering.turnaround_hours or 'as agreed'} hours."
            ),
            priority=notification_service._PRIORITY_MEDIUM,
            icon="check-circle",
            link_to_type="case",
            link_to_id=case.id,
            related_workspace_id=case.workspace_id,
            dedup_key_template=f"engagement_started:{purchase.id}",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to notify buyer about provisioning",
            extra={"purchase_id": str(purchase.id), "error": str(exc)[:200]},
        )

    return purchase


# ============================================================================
# DELIVERY LIFECYCLE
# ============================================================================

def mark_delivered(
    db: Session,
    *,
    actor: User,
    purchase: ServicePurchase,
    request: Any | None = None,
) -> ServicePurchase:
    """
    Analyst marks the work as delivered. Client must still accept.
    """
    if purchase.purchase_status != PurchaseStatus.IN_PROGRESS:
        raise InvalidStateTransitionError(
            message=f"Cannot mark delivered from {purchase.purchase_status.value}.",
            code="PURCHASE_NOT_IN_PROGRESS",
        )

    # Only the assigned analyst can mark delivered
    if purchase.offering_id:
        offering = db.get(AnalystServiceOffering, purchase.offering_id)
        if offering is not None:
            profile = db.get(AnalystProfile, offering.analyst_id)
            if profile is not None and profile.user_id != actor.id:
                # Not the assigned analyst — check if they're a workspace owner
                from app.models.enums import WorkspaceRole
                ws_role = authorization.get_user_workspace_role(
                    db, actor, purchase.buyer_workspace_id,
                ) if purchase.buyer_workspace_id else None
                if ws_role != WorkspaceRole.OWNER:
                    raise AuthorizationError(
                        message="Only the assigned analyst can mark delivery.",
                        code="PURCHASE_DELIVER_NOT_ANALYST",
                    )

    purchase.mark_delivered()
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.purchase.delivered",
        target_type="service_purchase",
        target_id=purchase.id,
        workspace_id=purchase.buyer_workspace_id,
        request=request,
    )

    # Notify buyer
    try:
        notification_service.create(
            db,
            recipient_id=purchase.buyer_user_id,
            notification_type=notification_service.NotificationType.CASE_STATUS_CHANGED,
            title="Deliverables ready for review",
            body=(
                f"Your engagement has deliverables ready. "
                f"Review and accept to complete the purchase."
            ),
            priority=notification_service._PRIORITY_MEDIUM,
            icon="file-check",
            link_to_type="service_purchase",
            link_to_id=purchase.id,
            dedup_key_template=f"delivered:{purchase.id}",
        )
    except Exception:  # noqa: BLE001
        pass

    return purchase


def accept_delivery(
    db: Session,
    *,
    actor: User,
    purchase: ServicePurchase,
    request: Any | None = None,
) -> ServicePurchase:
    """
    Buyer accepts the deliverables. Terminal success state.
    """
    if purchase.buyer_user_id != actor.id:
        raise AuthorizationError(
            message="Only the buyer can accept delivery.",
            code="PURCHASE_ACCEPT_NOT_BUYER",
        )

    if purchase.delivery_status != "delivered":
        raise InvalidStateTransitionError(
            message=(
                f"Cannot accept delivery from {purchase.delivery_status}. "
                f"Deliverables must be marked delivered first."
            ),
            code="PURCHASE_NOT_DELIVERED",
        )

    purchase.mark_accepted()
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.purchase.accepted",
        target_type="service_purchase",
        target_id=purchase.id,
        workspace_id=purchase.buyer_workspace_id,
        request=request,
    )

    logger.info(
        "Purchase accepted",
        extra={"purchase_id": str(purchase.id)},
    )

    return purchase


# ============================================================================
# CANCELLATION & REFUNDS
# ============================================================================

def cancel_purchase(
    db: Session,
    *,
    actor: User,
    purchase: ServicePurchase,
    reason: str,
    request: Any | None = None,
) -> ServicePurchase:
    """
    Cancel a purchase. Refund amount determined by the cancellation
    policy set at creation:

        full_refund    → refund 100% of amount_paid_cents
        partial_refund → refund 50%
        no_refund      → refund 0%

    If a refund is due, a REFUND transaction is created and the
    purchase is marked REFUNDED (or CANCELLED if no refund needed).
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A cancellation reason is required.",
            code="PURCHASE_CANCEL_REASON_REQUIRED",
        )

    if purchase.purchase_status in _PURCHASE_TERMINAL_STATUSES:
        raise InvalidStateTransitionError(
            message=f"Cannot cancel a {purchase.purchase_status.value} purchase.",
            code="PURCHASE_TERMINAL",
        )

    # Only buyer or workspace owner can cancel
    is_buyer = purchase.buyer_user_id == actor.id
    is_owner = False
    if purchase.buyer_workspace_id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, actor, purchase.buyer_workspace_id,
        )
        is_owner = ws_role == WorkspaceRole.OWNER

    if not (is_buyer or is_owner):
        raise AuthorizationError(
            message="Only the buyer can cancel this purchase.",
            code="PURCHASE_CANCEL_DENIED",
        )

    purchase.cancel(cancelled_by_id=actor.id, reason=reason.strip())
    db.flush()

    # Refund calculation
    refund_pct = _CANCEL_REFUND_PCT.get(purchase.cancellation_policy, 0)
    refund_amount = (purchase.amount_paid_cents * refund_pct) // 100

    if refund_amount > 0:
        _issue_refund_transaction(
            db,
            purchase=purchase,
            amount_cents=refund_amount,
            reason=f"Cancellation: {reason.strip()}",
            actor=actor,
        )

    # Release the offering slot
    if purchase.offering_id:
        offering = db.get(AnalystServiceOffering, purchase.offering_id)
        if offering is not None:
            offering.release_slot()
            db.flush()

    # Revoke the access grant (analyst no longer needs access)
    if purchase.access_grant_id:
        grant = db.get(CaseAccessGrant, purchase.access_grant_id)
        if grant is not None and grant.revoked_at is None:
            grant.revoke(
                by_user_id=actor.id,
                reason=f"Purchase cancelled: {reason.strip()}",
            )
            db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.purchase.cancelled",
        target_type="service_purchase",
        target_id=purchase.id,
        workspace_id=purchase.buyer_workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={
            "refund_pct": refund_pct,
            "refund_amount_cents": refund_amount,
        },
    )

    logger.info(
        "Purchase cancelled",
        extra={
            "purchase_id": str(purchase.id),
            "refund_pct": refund_pct,
            "refund_amount_cents": refund_amount,
        },
    )

    return purchase


def issue_refund(
    db: Session,
    *,
    actor: User,
    purchase: ServicePurchase,
    amount_cents: int,
    reason: str,
    request: Any | None = None,
) -> PaymentTransaction:
    """
    Issue a manual refund for a purchase. Distinct from the
    auto-refund in ``cancel_purchase`` — used for adjustments
    (partial dissatisfaction, billing correction, goodwill).
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A refund reason is required.",
            code="REFUND_REASON_REQUIRED",
        )

    if amount_cents <= 0:
        raise ValidationError(
            message="Refund amount must be positive.",
            code="REFUND_AMOUNT_INVALID",
        )

    # Workspace owner only for manual refunds
    if purchase.buyer_workspace_id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, actor, purchase.buyer_workspace_id,
        )
        if ws_role != WorkspaceRole.OWNER:
            raise AuthorizationError(
                message="Only workspace owners can issue manual refunds.",
                code="REFUND_DENIED",
            )
    else:
        raise AuthorizationError(
            message="Only workspace owners can issue manual refunds.",
            code="REFUND_DENIED",
        )

    txn = _issue_refund_transaction(
        db,
        purchase=purchase,
        amount_cents=amount_cents,
        reason=reason.strip(),
        actor=actor,
    )

    audit_service.log_action(
        db,
        actor=actor,
        action="marketplace.refund.issued",
        target_type="payment_transaction",
        target_id=txn.id,
        workspace_id=purchase.buyer_workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={
            "purchase_id": str(purchase.id),
            "amount_cents": amount_cents,
        },
    )

    return txn


def _issue_refund_transaction(
    db: Session,
    *,
    purchase: ServicePurchase,
    amount_cents: int,
    reason: str,
    actor: User | None,
) -> PaymentTransaction:
    """
    Internal: create a refund transaction and update purchase totals.
    """
    # Find the original charge to set parent_transaction_id
    original_charge = db.execute(
        select(PaymentTransaction)
        .where(
            PaymentTransaction.purchase_id == purchase.id,
            PaymentTransaction.transaction_type == "charge",
            PaymentTransaction.status == PaymentStatus.SUCCEEDED,
        )
        .order_by(PaymentTransaction.created_at.asc())
        .limit(1)
    ).scalar_one_or_none()

    txn = PaymentTransaction.build_refund(
        purchase_id=purchase.id,
        parent_transaction_id=original_charge.id if original_charge else None,
        provider="stripe",  # refunds go through the same provider
        amount_cents=amount_cents,
        currency=purchase.currency,
    )
    db.add(txn)
    db.flush()

    txn.mark_succeeded()

    # Update purchase totals
    purchase.record_refund(amount_cents=amount_cents)
    db.flush()

    # If this was a full refund, revoke the case access grant
    if purchase.amount_refunded_cents >= purchase.amount_paid_cents:
        if purchase.access_grant_id:
            grant = db.get(CaseAccessGrant, purchase.access_grant_id)
            if grant is not None and grant.revoked_at is None:
                grant.revoke(
                    by_user_id=actor.id if actor else None,
                    reason=f"Full refund: {reason}",
                )
                db.flush()

    return txn


# ============================================================================
# READ
# ============================================================================

def get_purchase_by_id(
    db: Session,
    purchase_id: uuid.UUID,
) -> ServicePurchase:
    """Fetch a purchase by ID."""
    purchase = db.get(ServicePurchase, purchase_id)
    if purchase is None:
        raise NotFoundError(
            message=f"Purchase {purchase_id} not found.",
            code="PURCHASE_NOT_FOUND",
        )
    return purchase


def list_purchases(
    db: Session,
    *,
    actor: User,
    page: PageParams,
    buyer_only: bool = False,
    offering_id: uuid.UUID | None = None,
) -> tuple[list[ServicePurchase], int]:
    """
    List purchases. If ``buyer_only`` is True, returns only the actor's
    own purchases. If False, returns all purchases visible to the actor
    (buyer's own + purchases on offerings they own as an analyst).
    """
    stmt = select(ServicePurchase)

    if buyer_only:
        stmt = stmt.where(ServicePurchase.buyer_user_id == actor.id)
    else:
        # Buyer's own + analyst's sold (via analyst profile)
        profile = _get_analyst_profile_optional(db, actor)
        if profile is not None:
            # Purchases on offerings this analyst owns
            my_offering_ids = list(db.execute(
                select(AnalystServiceOffering.id).where(
                    AnalystServiceOffering.analyst_id == profile.id,
                )
            ).scalars().all())
            stmt = stmt.where(
                (ServicePurchase.buyer_user_id == actor.id)
                | (ServicePurchase.offering_id.in_(my_offering_ids))
            )
        else:
            stmt = stmt.where(ServicePurchase.buyer_user_id == actor.id)

    if offering_id is not None:
        stmt = stmt.where(ServicePurchase.offering_id == offering_id)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(ServicePurchase.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


def get_purchase_transactions(
    db: Session,
    *,
    actor: User,
    purchase_id: uuid.UUID,
) -> list[PaymentTransaction]:
    """Return the transaction history for a purchase."""
    purchase = get_purchase_by_id(db, purchase_id)

    is_buyer = purchase.buyer_user_id == actor.id
    is_analyst = False
    if purchase.offering_id:
        offering = db.get(AnalystServiceOffering, purchase.offering_id)
        if offering is not None:
            profile = _get_analyst_profile_optional(db, actor)
            is_analyst = profile is not None and profile.id == offering.analyst_id

    if not (is_buyer or is_analyst):
        raise AuthorizationError(
            message="You do not have access to these transactions.",
            code="TRANSACTIONS_ACCESS_DENIED",
        )

    return list(db.execute(
        select(PaymentTransaction)
        .where(PaymentTransaction.purchase_id == purchase_id)
        .order_by(PaymentTransaction.created_at.asc())
    ).scalars().all())


# ============================================================================
# INTERNAL — analyst profile lookup that returns None if missing
# ============================================================================

def _get_analyst_profile_optional(
    db: Session,
    user: User,
) -> AnalystProfile | None:
    return db.execute(
        select(AnalystProfile).where(AnalystProfile.user_id == user.id)
    ).scalar_one_or_none()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Offerings
    "create_offering",
    "update_offering",
    "publish_offering",
    "pause_offering",
    "resume_offering",
    "archive_offering",
    "get_offering_by_id",
    "list_offerings",
    # Purchases
    "create_purchase",
    "get_purchase_by_id",
    "list_purchases",
    "record_payment_result",
    "provision_case",
    "mark_delivered",
    "accept_delivery",
    "cancel_purchase",
    "issue_refund",
    "get_purchase_transactions",
]