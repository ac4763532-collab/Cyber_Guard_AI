"""
CyberGuard AI — Marketplace Endpoints
============================================================================

The analyst marketplace: browse offerings, purchase services, track
engagements.

Thirteen endpoints — the complete "hire an analyst" flow:

Public (no auth required):
    GET    /marketplace/offerings              — browse active offerings
    GET    /marketplace/offerings/{id}         — view offering detail

Analyst (auth, verified analyst required for publish):
    POST   /marketplace/offerings              — create (DRAFT)
    PATCH  /marketplace/offerings/{id}         — update
    POST   /marketplace/offerings/{id}/publish — publish (verified only)
    POST   /marketplace/offerings/{id}/pause   — pause
    POST   /marketplace/offerings/{id}/resume  — resume
    POST   /marketplace/offerings/{id}/archive — archive (terminal)

Customer (auth):
    GET    /marketplace/purchases              — my purchases (buyer or analyst view)
    GET    /marketplace/purchases/{id}         — detail
    POST   /marketplace/purchases              — checkout
    POST   /marketplace/purchases/{id}/cancel  — cancel with refund policy
    GET    /marketplace/purchases/{id}/transactions — payment history

Public browse
-------------
The two GET `/offerings` endpoints are **the only unauthenticated
endpoints in the entire API**. This is deliberate:

    - Analysts need to be discoverable before a customer signs up
    - Browsing must work on the landing page before login
    - The offering data is intentionally public information (price,
      description, analyst rating)

Non-public data is protected:
    - Draft/paused/archived offerings require ownership — filtered out
      of public listing and rejected on public detail
    - Purchase data always requires authentication
    - Analyst contact / full profile requires auth (not in this router)

Idempotency
-----------
`POST /marketplace/purchases` accepts an optional `idempotency_key`.
Clients should generate a UUID before the first checkout attempt and
reuse it for retries. If the key matches an existing purchase from the
same buyer, that purchase is returned instead of creating a duplicate.

The frontend pattern:
    const key = crypto.randomUUID();
    // store key in component state
    // on retry, reuse the same key
    await fetch('/marketplace/purchases', {
        method: 'POST',
        body: JSON.stringify({ offering_id, idempotency_key: key })
    });

This prevents double-charges on flaky networks or user double-clicks.

Purchase provisioning
---------------------
`POST /marketplace/purchases` creates a PENDING purchase but does **not**
charge the customer. The actual payment is handled by the provider
(Stripe/Razorpay) via a webhook that calls
`marketplace_service.record_payment_result`.

On success, the service automatically provisions:
    - A `SecurityCase` with is_billable=True
    - A `CaseAccessGrant` with scope=FULL_CASE for the analyst
    - A notification to the analyst and buyer

This means the analyst gets full case access **automatically** when
payment succeeds. The customer sees a case appear in their dashboard.
No manual step required.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
    OptionalUser,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.enums import ServiceOfferingStatus
from app.models.marketplace import ServicePurchase
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.marketplace import (
    OfferingCreate,
    OfferingFilter,
    OfferingList,
    OfferingRead,
    OfferingStatusUpdate,
    OfferingUpdate,
    PaymentTransactionRead,
    PurchaseCancelRequest,
    PurchaseCreate,
    PurchaseList,
    PurchaseRead,
)
from app.services import (
    authorization,
    marketplace_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/marketplace",
    tags=["marketplace"],
)


# ============================================================================
# PUBLIC BROWSE — offerings list
# ============================================================================

@router.get(
    "/offerings",
    response_model=PaginatedResponse[OfferingList],
    summary="Browse analyst service offerings",
    description=(
        "**Public endpoint** — no authentication required. Returns "
        "ACTIVE offerings only. Draft, paused, and archived offerings "
        "are excluded.\n\n"
        "Filters: category, offering_type, price range, search text, "
        "analyst, currency. Results are ordered by rating desc, then "
        "purchase count desc — the standard marketplace ranking.\n\n"
        "Returns lightweight `OfferingList` rows. Fetch "
        "`GET /marketplace/offerings/{id}` for full details."
    ),
)
def browse_offerings(
    db: DBDep,
    page: PageDep,
    filters: OfferingFilter = Depends(),
    _viewer: OptionalUser = None,  # accepts optional token, but doesn't require it
) -> PaginatedResponse[OfferingList]:
    # Force status filter to ACTIVE for public browsing
    # (a filter.status override from the caller is ignored)
    effective_filters = filters.model_copy(
        update={"status": ServiceOfferingStatus.ACTIVE},
    )

    offerings, total = marketplace_service.list_offerings(
        db, page=page, filters=effective_filters,
    )

    return PaginatedResponse[OfferingList](
        items=[OfferingList.model_validate(o) for o in offerings],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# PUBLIC BROWSE — offering detail
# ============================================================================

@router.get(
    "/offerings/{offering_id}",
    response_model=OfferingRead,
    summary="Get an offering's details",
    description=(
        "**Public endpoint** — no authentication required for ACTIVE "
        "offerings. Non-active offerings (draft/paused/archived) return "
        "404 to non-owners, effectively hiding them from public view.\n\n"
        "The owner (analyst) always sees their own offering regardless of "
        "status."
    ),
    responses={
        200: {"description": "Offering returned."},
        404: {"description": "Offering not found or not publicly visible."},
    },
)
def get_offering(
    offering_id: uuid.UUID,
    db: DBDep,
    viewer: OptionalUser = None,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)

    # Non-active offerings require the viewer to be the owner
    if offering.status != ServiceOfferingStatus.ACTIVE:
        if viewer is None:
            # Anonymous + non-active → 404 (hide existence)
            raise NotFoundError(
                message=f"Offering {offering_id} not found.",
                code="OFFERING_NOT_FOUND",
            )
        # Signed-in: check ownership
        is_owner = marketplace_service._get_analyst_profile_optional(db, viewer)
        if is_owner is None or is_owner.id != offering.analyst_id:
            raise NotFoundError(
                message=f"Offering {offering_id} not found.",
                code="OFFERING_NOT_FOUND",
            )

    return OfferingRead.model_validate(offering)


# ============================================================================
# ANALYST — offering creation
# ============================================================================

@router.post(
    "/offerings",
    response_model=OfferingRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new service offering",
    description=(
        "Creates a DRAFT offering. Requires the caller to have an analyst "
        "profile. Drafts can be edited freely — only verified analysts "
        "can publish them.\n\n"
        "The offering is initially owned by the caller's analyst profile "
        "and published under their personal workspace."
    ),
)
def create_offering(
    body: OfferingCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.create_offering(
        db, actor=current_user, payload=body,
    )
    db.commit()
    return OfferingRead.model_validate(offering)


# ============================================================================
# ANALYST — offering update
# ============================================================================

@router.patch(
    "/offerings/{offering_id}",
    response_model=OfferingRead,
    summary="Update an offering",
    description=(
        "Updates mutable fields (title, description, price, turnaround, "
        "deliverables, slots_available). Only the offering's owner can "
        "update. Cannot change analyst_id, slots_used, or status."
    ),
)
def update_offering(
    offering_id: uuid.UUID,
    body: OfferingUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)
    updated = marketplace_service.update_offering(
        db, actor=current_user, offering=offering, payload=body,
    )
    db.commit()
    return OfferingRead.model_validate(updated)


# ============================================================================
# ANALYST — offering lifecycle
# ============================================================================

@router.post(
    "/offerings/{offering_id}/publish",
    response_model=OfferingRead,
    summary="Publish an offering",
    description=(
        "Transitions DRAFT → ACTIVE. Requires the analyst to be "
        "**verified** — unverified analysts cannot publish. The offering "
        "becomes publicly browsable and purchasable."
    ),
)
def publish_offering(
    offering_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)
    updated = marketplace_service.publish_offering(
        db, actor=current_user, offering=offering,
    )
    db.commit()
    return OfferingRead.model_validate(updated)


@router.post(
    "/offerings/{offering_id}/pause",
    response_model=OfferingRead,
    summary="Pause an offering",
    description=(
        "Transitions ACTIVE → PAUSED. Existing purchases are unaffected. "
        "The offering is removed from public browse — new customers "
        "cannot purchase it."
    ),
)
def pause_offering(
    offering_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)
    updated = marketplace_service.pause_offering(
        db, actor=current_user, offering=offering,
    )
    db.commit()
    return OfferingRead.model_validate(updated)


@router.post(
    "/offerings/{offering_id}/resume",
    response_model=OfferingRead,
    summary="Resume a paused offering",
    description=(
        "Transitions PAUSED → ACTIVE. The analyst must still be verified."
    ),
)
def resume_offering(
    offering_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)
    updated = marketplace_service.resume_offering(
        db, actor=current_user, offering=offering,
    )
    db.commit()
    return OfferingRead.model_validate(updated)


@router.post(
    "/offerings/{offering_id}/archive",
    response_model=OfferingRead,
    summary="Archive an offering",
    description=(
        "Terminal transition to ARCHIVED. The offering disappears from "
        "public view. Existing purchases continue unaffected — the "
        "offering row is retained for purchase history."
    ),
)
def archive_offering(
    offering_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> OfferingRead:
    offering = marketplace_service.get_offering_by_id(db, offering_id)
    updated = marketplace_service.archive_offering(
        db, actor=current_user, offering=offering,
    )
    db.commit()
    return OfferingRead.model_validate(updated)


# ============================================================================
# CUSTOMER — purchase list
# ============================================================================

@router.get(
    "/purchases",
    response_model=PaginatedResponse[PurchaseList],
    summary="List my purchases",
    description=(
        "Returns purchases where the caller is the buyer, or where the "
        "caller is the analyst who owns the offering. Set "
        "`buyer_only=true` to exclude the analyst-side view.\n\n"
        "Requires authentication. Returns lightweight `PurchaseList` "
        "rows — fetch `GET /marketplace/purchases/{id}` for full detail."
    ),
)
def list_purchases(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    buyer_only: bool = Query(
        default=True,
        description=(
            "If true (default), only shows purchases where the caller is "
            "the buyer. If false, also includes purchases where the caller "
            "is the offering's analyst."
        ),
    ),
    offering_id: uuid.UUID | None = Query(default=None),
) -> PaginatedResponse[PurchaseList]:
    purchases, total = marketplace_service.list_purchases(
        db,
        actor=current_user,
        page=page,
        buyer_only=buyer_only,
        offering_id=offering_id,
    )

    return PaginatedResponse[PurchaseList](
        items=[PurchaseList.model_validate(p) for p in purchases],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# CUSTOMER — purchase detail
# ============================================================================

@router.get(
    "/purchases/{purchase_id}",
    response_model=PurchaseRead,
    summary="Get a purchase's details",
    description=(
        "Full purchase view including payment status, delivery status, "
        "and the linked case (if provisioned). Visible to the buyer or "
        "the offering's analyst."
    ),
)
def get_purchase(
    purchase_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> PurchaseRead:
    purchase = marketplace_service.get_purchase_by_id(db, purchase_id)

    # Access: buyer or the offering's analyst
    is_buyer = purchase.buyer_user_id == current_user.id
    is_analyst = False
    if purchase.offering_id:
        from app.models.marketplace import AnalystServiceOffering
        offering = db.get(AnalystServiceOffering, purchase.offering_id)
        if offering is not None:
            profile = marketplace_service._get_analyst_profile_optional(
                db, current_user,
            )
            is_analyst = profile is not None and profile.id == offering.analyst_id

    if not (is_buyer or is_analyst):
        from app.core.exceptions import AuthorizationError
        raise AuthorizationError(
            message="You do not have access to this purchase.",
            code="PURCHASE_ACCESS_DENIED",
        )

    return PurchaseRead.model_validate(purchase)


# ============================================================================
# CUSTOMER — checkout
# ============================================================================

@router.post(
    "/purchases",
    response_model=PurchaseRead,
    status_code=status.HTTP_201_CREATED,
    summary="Checkout — purchase an offering",
    description=(
        "Creates a PENDING purchase for the specified offering. **Does "
        "not charge the customer** — the actual payment is handled by the "
        "payment provider (Stripe/Razorpay) out of band.\n\n"
        "**Idempotency**: pass a client-generated `idempotency_key` "
        "(UUID). On retry with the same key, the existing purchase is "
        "returned instead of creating a duplicate. Strongly recommended "
        "for all checkout flows.\n\n"
        "On successful payment (confirmed by provider webhook), the "
        "purchase is automatically provisioned: a SecurityCase is created, "
        "the analyst gets a FULL_CASE access grant, and both parties are "
        "notified."
    ),
    responses={
        201: {"description": "Purchase created (awaiting payment)."},
        400: {"description": "Offering not purchasable or sold out."},
        404: {"description": "Offering not found."},
        409: {"description": "Offering has no available slots."},
    },
)
def create_purchase(
    body: PurchaseCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> PurchaseRead:
    purchase = marketplace_service.create_purchase(
        db, actor=current_user, payload=body,
    )
    db.commit()

    logger.info(
        "Purchase created via API",
        extra={
            "purchase_id": str(purchase.id),
            "offering_id": str(body.offering_id),
            "amount_cents": purchase.amount_cents,
            "idempotency_key": body.idempotency_key,
            "actor_id": str(current_user.id),
        },
    )

    return PurchaseRead.model_validate(purchase)


# ============================================================================
# CUSTOMER — cancel
# ============================================================================

@router.post(
    "/purchases/{purchase_id}/cancel",
    response_model=PurchaseRead,
    summary="Cancel a purchase",
    description=(
        "Cancels the purchase. Refund amount depends on the "
        "`cancellation_policy` set at creation:\n\n"
        "- `full_refund` — 100% refund\n"
        "- `partial_refund` — 50% refund\n"
        "- `no_refund` — no refund\n\n"
        "A refund transaction is created automatically if applicable. "
        "The linked case access grant (if the case was provisioned) is "
        "revoked on full refund. Requires the buyer or a workspace OWNER."
    ),
)
def cancel_purchase(
    purchase_id: uuid.UUID,
    body: PurchaseCancelRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> PurchaseRead:
    purchase = marketplace_service.get_purchase_by_id(db, purchase_id)
    updated = marketplace_service.cancel_purchase(
        db,
        actor=current_user,
        purchase=purchase,
        reason=body.reason,
    )
    db.commit()
    return PurchaseRead.model_validate(updated)


# ============================================================================
# CUSTOMER — transaction history
# ============================================================================

@router.get(
    "/purchases/{purchase_id}/transactions",
    response_model=list[PaymentTransactionRead],
    summary="List a purchase's payment transactions",
    description=(
        "Returns all payment transactions for the purchase in chronological "
        "order — charges, refunds, and adjustments. Visible to the buyer "
        "or the offering's analyst."
    ),
)
def list_purchase_transactions(
    purchase_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> list[PaymentTransactionRead]:
    transactions = marketplace_service.get_purchase_transactions(
        db, actor=current_user, purchase_id=purchase_id,
    )
    return [PaymentTransactionRead.model_validate(t) for t in transactions]


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]