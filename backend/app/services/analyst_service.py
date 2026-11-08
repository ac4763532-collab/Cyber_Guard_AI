"""
CyberGuard AI — Analyst Service
============================================================================

Business logic for analyst profiles: applications, verification workflow,
self-service profile updates, and marketplace visibility.

Analyst profiles are the bridge between a "user" and a "security
professional who can be assigned cases and publish service offerings".
Their lifecycle determines who can accept marketplace engagements and
who can be assigned to platform-driven incident response.

Verification lifecycle (state machine)
--------------------------------------
    PENDING ──→ IN_REVIEW ──→ VERIFIED ──→ SUSPENDED ──→ VERIFIED
       │           │
       │           └──→ REJECTED  (terminal)
       │
       └──→ (deleted by applicant, or expires after 90 days)

    VERIFIED ──→ EXPIRED  (verification renewal required)

Transitions:
    apply                     PENDING (creates row)
    start_review              PENDING  → IN_REVIEW     (admin)
    approve_application       IN_REVIEW → VERIFIED     (admin)
    reject_application        IN_REVIEW → REJECTED     (admin)
    suspend_analyst           VERIFIED  → SUSPENDED    (admin)
    reactivate_analyst        SUSPENDED → VERIFIED     (admin)
    expire_verification       VERIFIED  → EXPIRED      (background job)

Self-service actions (no verification workflow involvement):
    update_profile            (analyst can change bio, headline, etc.)
    set_available_for_hire    (toggle intake)

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. Every state-changing method audits.
5. All admin actions (approve, reject, suspend, reactivate) require
   the corresponding ``admin:analyst_*`` permission, which currently
   fails closed (no super admin yet).

One profile per user
--------------------
A user has at most one analyst profile. Enforced by the DB unique
constraint on ``analyst_profiles.user_id``. This service raises a
clean ``ConflictError`` before the DB constraint fires.

Re-applying after rejection
---------------------------
A user whose application was REJECTED cannot simply reset to PENDING —
that would erase the rejection history. Instead:

    - If rejected < 30 days ago: reject the re-application (cooldown)
    - If rejected >= 30 days ago: allow reset to PENDING with new
      documents (old rejection reason preserved on the row's
      ``verification_notes`` for admin visibility)

The 30-day cooldown is a rate-limit on re-applications, not a
security control. It prevents spam and gives admins breathing room.

Document handling
-----------------
Verification documents (ID scans, certifications) are uploaded
separately (multipart endpoint) and stored under
``static/uploads/verification/{user_id}/``. The profile's
``verification_documents`` JSONB array holds metadata references:

    [{"type": "id_card", "url": "/static/.../abc.pdf", "uploaded_at": "..."}]

This service **validates that the URL belongs to the applying user**
before accepting it. Otherwise user A could reference user B's ID
scan — a serious privacy issue and a plausible social-engineering
vector.

Marketplace visibility
----------------------
Only VERIFIED analysts with ``available_for_hire=True`` and
``slots_remaining > 0`` appear in ``list_verified_analysts``. The
marketplace endpoints (Phase H) call this service; they don't query
the DB directly.

Public API
----------
    apply_as_analyst(db, *, user, payload, request=None)         → AnalystProfile
    get_by_user_id(db, user_id)                                  → AnalystProfile
    get_by_id(db, profile_id)                                    → AnalystProfile
    get_by_user_id_optional(db, user_id)                         → AnalystProfile | None
    update_profile(db, *, user, profile, payload, request=None)  → AnalystProfile
    set_available_for_hire(db, *, user, profile, available, request=None) → AnalystProfile

    start_review(db, *, actor, profile, request=None)            → AnalystProfile
    approve_application(db, *, actor, profile, notes=None, request=None) → AnalystProfile
    reject_application(db, *, actor, profile, reason, request=None) → AnalystProfile
    suspend_analyst(db, *, actor, profile, reason, request=None) → AnalystProfile
    reactivate_analyst(db, *, actor, profile, request=None)      → AnalystProfile
    expire_verification(db, *, actor, profile, request=None)     → AnalystProfile

    list_pending_applications(db, *, actor, page)                → (list, int)
    list_verified_analysts(db, *, page, specializations=None)    → (list, int)
    list_all_analysts(db, *, actor, page, status=None)           → (list, int)

Usage
-----
    from app.services import analyst_service

    # A user applies
    profile = analyst_service.apply_as_analyst(
        db, user=current_user, payload=body,
    )
    db.commit()

    # Super admin reviews + approves
    analyst_service.start_review(db, actor=admin, profile=profile)
    analyst_service.approve_application(
        db, actor=admin, profile=profile, notes="Credentials verified.",
    )
    db.commit()

    # Analyst toggles availability
    analyst_service.set_available_for_hire(
        db, user=current_user, profile=profile, available=True,
    )
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import (
    PERM_ADMIN_ANALYST_REJECT,
    PERM_ADMIN_ANALYST_VERIFY,
)
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    InvalidStateTransitionError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.analyst import AnalystProfile
from app.models.enums import AnalystVerificationStatus
from app.models.user import User
from app.schemas.analyst import (
    AnalystProfileApply,
    AnalystProfileUpdate,
)
from app.schemas.common import PageParams
from app.services import audit_service, authorization


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Days before a rejected applicant can re-apply.
_REAPPLICATION_COOLDOWN_DAYS = 30

#: URL prefix for verification documents. Matches the upload endpoint
#: path — documents outside this prefix are rejected during
#: ``apply_as_analyst`` and ``update_profile``.
_VERIFICATION_DOC_URL_PREFIX = "/static/uploads/verification/"

#: Specialization tag pattern — lowercase, dashes, alphanumeric.
_SPECIALIZATION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _get_by_user_id_optional(
    db: Session,
    user_id: uuid.UUID,
) -> AnalystProfile | None:
    """Fetch an analyst profile by user ID without raising."""
    return db.execute(
        select(AnalystProfile).where(AnalystProfile.user_id == user_id)
    ).scalar_one_or_none()


def _validate_document_urls(
    documents: list[dict[str, Any]] | None,
    user_id: uuid.UUID,
) -> None:
    """
    Ensure every document URL belongs to the applying user.

    Rejects:
        - URLs not starting with the verification prefix
        - URLs whose user-id segment does not match ``user_id``
        - Relative URLs that escape the upload directory

    The uploaded file is stored at
    ``/static/uploads/verification/{user_id}/{filename}``. A user A
    referencing a document under user B's directory is an attempt to
    access someone else's ID scan — rejected.
    """
    if not documents:
        return

    expected_prefix = f"{_VERIFICATION_DOC_URL_PREFIX}{user_id}/"

    for doc in documents:
        url = doc.get("url", "")
        if not isinstance(url, str):
            raise ValidationError(
                message="Each verification document must have a string 'url'.",
                code="ANALYST_DOC_INVALID_URL",
            )
        if not url.startswith(expected_prefix):
            raise ValidationError(
                message=(
                    "Verification document URLs must reference files in your "
                    f"own upload directory ({expected_prefix}). "
                    f"Received: {url[:60]}"
                ),
                code="ANALYST_DOC_URL_MISMATCH",
                details={"expected_prefix": expected_prefix},
            )


def _validate_specializations(tags: list[str] | None) -> list[str]:
    """
    Validate and deduplicate specialization tags.

    Tags are lowercase alphanumeric + dashes/underscores. An empty
    list is valid (analyst can fill in later), but if tags are
    provided, they must be well-formed.
    """
    if not tags:
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            raise ValidationError(
                message="Specialization tags must be strings.",
                code="ANALYST_SPECIALIZATION_INVALID_TYPE",
            )
        normalized = tag.strip().lower()
        if not normalized:
            continue
        if not _SPECIALIZATION_PATTERN.match(normalized):
            raise ValidationError(
                message=(
                    f"Invalid specialization tag: {normalized!r}. "
                    "Must be lowercase letters, digits, dashes, or "
                    "underscores, starting with a letter or digit."
                ),
                code="ANALYST_SPECIALIZATION_INVALID",
                details={"tag": normalized},
            )
        if normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def _require_admin_verify(db: Session, actor: User) -> None:
    """
    Assert the actor has the permission to verify analysts.

    Currently fails closed — no user has this permission until a
    super-admin column exists. The check runs through the
    authorization engine, so once the column is added and
    ``authorization.is_super_admin`` returns True, this opens without
    any code changes here.
    """
    if not authorization.has_permission(db, actor, PERM_ADMIN_ANALYST_VERIFY):
        raise AuthorizationError(
            message=(
                "Only a platform administrator can perform this action. "
                "The super admin role is not yet configured on this "
                "deployment."
            ),
            code="SUPER_ADMIN_REQUIRED",
        )


def _require_admin_reject(db: Session, actor: User) -> None:
    """Same as ``_require_admin_verify`` but for the reject permission."""
    if not authorization.has_permission(db, actor, PERM_ADMIN_ANALYST_REJECT):
        raise AuthorizationError(
            message=(
                "Only a platform administrator can perform this action. "
                "The super admin role is not yet configured on this "
                "deployment."
            ),
            code="SUPER_ADMIN_REQUIRED",
        )


# ============================================================================
# APPLY
# ============================================================================

def apply_as_analyst(
    db: Session,
    *,
    user: User,
    payload: AnalystProfileApply,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Create a new analyst profile in PENDING status.

    Or, if a previous profile exists in REJECTED status and the
    cooldown has passed, reset it to PENDING with the new application
    data. This preserves the rejection history (``rejection_reason``,
    ``verification_notes``) for admin review.

    Raises
    ------
    ConflictError
        - If a profile already exists in a non-REJECTED state.
        - If the previous rejection is within the 30-day cooldown.
    ValidationError
        - If verification document URLs do not belong to this user.
        - If specialization tags are malformed.
    """
    existing = _get_by_user_id_optional(db, user.id)

    # ── Case 1: no existing profile → create new PENDING
    if existing is None:
        _validate_document_urls(payload.verification_documents, user.id)
        specializations = _validate_specializations(payload.specializations)

        profile = AnalystProfile.build_application(
            user_id=user.id,
            display_name=payload.display_name,
            specializations=specializations,
            headline=payload.headline,
            bio=payload.bio,
            years_of_experience=payload.years_of_experience,
            hourly_rate_cents=payload.hourly_rate_cents,
            currency=payload.currency,
            languages=payload.languages,
            working_timezone=payload.working_timezone,
            certifications=payload.certifications,
            verification_documents=payload.verification_documents,
        )
        db.add(profile)
        db.flush()

        audit_service.log_action(
            db,
            actor=user,
            action="analyst.application.submitted",
            target_type="analyst_profile",
            target_id=profile.id,
            target_display=user.email,
            request=request,
            metadata={
                "specializations": specializations,
                "years_of_experience": payload.years_of_experience,
            },
        )

        logger.info(
            "Analyst application submitted",
            extra={
                "profile_id": str(profile.id),
                "user_id": str(user.id),
            },
        )
        return profile

    # ── Case 2: existing profile in an active state → reject
    if existing.verification_status != AnalystVerificationStatus.REJECTED:
        raise ConflictError(
            message=(
                f"You already have an analyst profile in "
                f"{existing.verification_status.value} status. "
                f"Use the profile update endpoint to modify it."
            ),
            code="ANALYST_PROFILE_EXISTS",
            details={
                "existing_status": existing.verification_status.value,
                "profile_id": str(existing.id),
            },
        )

    # ── Case 3: existing profile is REJECTED → maybe reapply
    rejected_at = existing.verification_completed_at
    if rejected_at is not None:
        if rejected_at.tzinfo is None:
            rejected_at = rejected_at.replace(tzinfo=timezone.utc)
        cooldown_until = rejected_at + timedelta(days=_REAPPLICATION_COOLDOWN_DAYS)
        if datetime.now(timezone.utc) < cooldown_until:
            raise ConflictError(
                message=(
                    f"Your previous application was rejected. You can "
                    f"re-apply after {cooldown_until.isoformat()}."
                ),
                code="ANALYST_REAPPLICATION_COOLDOWN",
                details={
                    "cooldown_until": cooldown_until.isoformat(),
                    "previous_rejection_reason": existing.rejection_reason,
                },
            )

    # ── Re-apply: reset to PENDING with new data, preserve old reason
    _validate_document_urls(payload.verification_documents, user.id)
    specializations = _validate_specializations(payload.specializations)

    # Preserve the rejection history in verification_notes
    previous_note = existing.verification_notes or ""
    reapp_note = (
        f"[Re-applied {datetime.now(timezone.utc).isoformat()}] "
        f"Previous rejection: {existing.rejection_reason or 'no reason given'}"
    )
    existing.verification_notes = (
        f"{previous_note}\n{reapp_note}".strip() if previous_note else reapp_note
    )

    # Reset to PENDING with new data
    existing.display_name = payload.display_name
    existing.specializations = specializations
    existing.headline = payload.headline
    existing.bio = payload.bio
    existing.years_of_experience = payload.years_of_experience
    existing.hourly_rate_cents = payload.hourly_rate_cents
    existing.currency = payload.currency
    existing.languages = payload.languages
    existing.working_timezone = payload.working_timezone
    existing.certifications = payload.certifications
    existing.verification_documents = payload.verification_documents
    existing.verification_status = AnalystVerificationStatus.PENDING
    existing.verification_submitted_at = datetime.now(timezone.utc)
    existing.verification_completed_at = None
    existing.verified_by_id = None
    existing.rejection_reason = None
    existing.available_for_hire = False
    db.flush()

    audit_service.log_action(
        db,
        actor=user,
        action="analyst.application.resubmitted",
        target_type="analyst_profile",
        target_id=existing.id,
        target_display=user.email,
        request=request,
        metadata={
            "previous_rejection_reason": existing.rejection_reason,
            "specializations": specializations,
        },
    )

    logger.info(
        "Analyst application re-submitted",
        extra={
            "profile_id": str(existing.id),
            "user_id": str(user.id),
        },
    )
    return existing


# ============================================================================
# READ
# ============================================================================

def get_by_user_id(db: Session, user_id: uuid.UUID) -> AnalystProfile:
    """
    Fetch an analyst profile by user ID.

    Raises
    ------
    NotFoundError
        If no profile exists for this user.
    """
    from app.core.exceptions import NotFoundError
    profile = _get_by_user_id_optional(db, user_id)
    if profile is None:
        raise NotFoundError(
            message=f"No analyst profile found for user {user_id}.",
            code="ANALYST_PROFILE_NOT_FOUND",
            details={"user_id": str(user_id)},
        )
    return profile


def get_by_id(db: Session, profile_id: uuid.UUID) -> AnalystProfile:
    """Fetch an analyst profile by its own ID."""
    from app.core.exceptions import NotFoundError
    profile = db.get(AnalystProfile, profile_id)
    if profile is None:
        raise NotFoundError(
            message=f"Analyst profile {profile_id} not found.",
            code="ANALYST_PROFILE_NOT_FOUND",
            details={"profile_id": str(profile_id)},
        )
    return profile


def get_by_user_id_optional(
    db: Session,
    user_id: uuid.UUID,
) -> AnalystProfile | None:
    """Public non-raising variant."""
    return _get_by_user_id_optional(db, user_id)


# ============================================================================
# SELF-SERVICE UPDATE
# ============================================================================

def update_profile(
    db: Session,
    *,
    user: User,
    profile: AnalystProfile,
    payload: AnalystProfileUpdate,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Update an analyst's own profile.

    Only fields the analyst is allowed to change about themselves:
        - display_name, headline, bio
        - specializations, certifications, languages
        - years_of_experience, hourly_rate_cents, currency
        - working_timezone
        - verification_documents (before the profile is verified)

    Cannot change (schema does not allow):
        - ``verification_status`` — workflow-managed
        - ``verified_by_id`` / ``verification_completed_at`` —
          admin-only, set by approve/reject
        - ``available_for_hire`` — dedicated endpoint
        - ``active_case_count`` / ``total_cases_completed`` /
          ``rating_*`` / ``purchase_count`` — computed by other services

    Raises ``AuthorizationError`` if the caller is not the profile owner.
    """
    if profile.user_id != user.id:
        raise AuthorizationError(
            message="You can only update your own analyst profile.",
            code="NOT_PROFILE_OWNER",
        )

    if payload.verification_documents is not None:
        _validate_document_urls(payload.verification_documents, user.id)

    if payload.specializations is not None:
        _validate_specializations(payload.specializations)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        return profile

    # If updating documents while VERIFIED, reset to IN_REVIEW —
    # admin must re-approve because the evidence changed.
    resets_to_review = (
        "verification_documents" in updates
        and profile.verification_status == AnalystVerificationStatus.VERIFIED
    )

    for field, value in updates.items():
        setattr(profile, field, value)

    if resets_to_review:
        profile.verification_status = AnalystVerificationStatus.IN_REVIEW
        profile.verification_completed_at = None
        profile.verified_by_id = None
        profile.available_for_hire = False

    db.flush()

    audit_service.log_action(
        db,
        actor=user,
        action="analyst.profile.updated",
        target_type="analyst_profile",
        target_id=profile.id,
        target_display=user.email,
        request=request,
        metadata={
            "fields_changed": list(updates.keys()),
            "resets_to_review": resets_to_review,
        },
    )

    return profile


# ============================================================================
# AVAILABILITY TOGGLE
# ============================================================================

def set_available_for_hire(
    db: Session,
    *,
    user: User,
    profile: AnalystProfile,
    available: bool,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Toggle whether an analyst accepts new cases.

    Only verified analysts can set ``available=True``. Unverified
    analysts must remain unavailable — they have no business accepting
    paid engagements before credentials are checked.
    """
    if profile.user_id != user.id:
        raise AuthorizationError(
            message="You can only change availability on your own profile.",
            code="NOT_PROFILE_OWNER",
        )

    if available and not profile.is_verified:
        raise InvalidStateTransitionError(
            message=(
                "Only verified analysts can accept new cases. "
                f"Current verification status: {profile.verification_status.value}."
            ),
            code="ANALYST_NOT_VERIFIED",
        )

    if profile.available_for_hire == available:
        return profile  # idempotent

    profile.available_for_hire = available
    db.flush()

    audit_service.log_action(
        db,
        actor=user,
        action="analyst.availability.changed",
        target_type="analyst_profile",
        target_id=profile.id,
        target_display=user.email,
        request=request,
        metadata={"available": available},
    )

    return profile


# ============================================================================
# ADMIN: REVIEW WORKFLOW
# ============================================================================

def start_review(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition PENDING → IN_REVIEW.

    Admin action, requires ``admin:analyst_verify``. Currently fails
    closed (no super admins exist).
    """
    _require_admin_verify(db, actor)

    if profile.verification_status != AnalystVerificationStatus.PENDING:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot start review from status "
                f"{profile.verification_status.value}."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    before = {"status": profile.verification_status.value}
    profile.verification_status = AnalystVerificationStatus.IN_REVIEW
    db.flush()
    after = {"status": profile.verification_status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.review.started",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return profile


def approve_application(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    notes: str | None = None,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition IN_REVIEW → VERIFIED.

    Admin action, requires ``admin:analyst_verify``. Sets
    ``verification_completed_at`` and ``verified_by_id``. The
    analyst can then set ``available_for_hire=True`` to accept work.
    """
    _require_admin_verify(db, actor)

    if profile.verification_status != AnalystVerificationStatus.IN_REVIEW:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot approve from status "
                f"{profile.verification_status.value}. "
                f"Application must be IN_REVIEW first."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    before = {"status": profile.verification_status.value}
    profile.verification_status = AnalystVerificationStatus.VERIFIED
    profile.verification_completed_at = datetime.now(timezone.utc)
    profile.verified_by_id = actor.id
    if notes:
        profile.verification_notes = notes.strip()
    db.flush()
    after = {"status": profile.verification_status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.verified",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        notes=notes,
        request=request,
    )

    logger.info(
        "Analyst verified",
        extra={
            "profile_id": str(profile.id),
            "user_id": str(profile.user_id),
            "verified_by": str(actor.id),
        },
    )

    return profile


def reject_application(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    reason: str,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition IN_REVIEW → REJECTED.

    Admin action, requires ``admin:analyst_reject``. Rejection is
    terminal — the applicant must wait for the 30-day cooldown and
    re-apply (see ``apply_as_analyst``).

    The reason is required and is surfaced to the applicant.
    """
    _require_admin_reject(db, actor)

    if profile.verification_status != AnalystVerificationStatus.IN_REVIEW:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot reject from status "
                f"{profile.verification_status.value}. "
                f"Application must be IN_REVIEW first."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    if not reason or not reason.strip():
        raise ValidationError(
            message="A rejection reason is required.",
            code="ANALYST_REJECTION_REASON_REQUIRED",
        )

    before = {"status": profile.verification_status.value}
    profile.verification_status = AnalystVerificationStatus.REJECTED
    profile.verification_completed_at = datetime.now(timezone.utc)
    profile.verified_by_id = actor.id
    profile.rejection_reason = reason.strip()
    profile.available_for_hire = False
    db.flush()
    after = {"status": profile.verification_status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.rejected",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        notes=reason,
        request=request,
    )

    logger.info(
        "Analyst application rejected",
        extra={
            "profile_id": str(profile.id),
            "user_id": str(profile.user_id),
            "reason": reason[:200],
        },
    )

    return profile


# ============================================================================
# ADMIN: SUSPEND / REACTIVATE / EXPIRE
# ============================================================================

def suspend_analyst(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    reason: str,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition VERIFIED → SUSPENDED.

    Admin action, requires ``admin:analyst_verify``. Suspends an
    already-verified analyst — used for policy violations, active
    investigations, or a compliance hold.

    A suspended analyst cannot accept new cases (``available_for_hire``
    is force-set to False). They cannot be assigned to new cases by
    ``case_service`` (which checks verification status).
    """
    _require_admin_verify(db, actor)

    if profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot suspend from status "
                f"{profile.verification_status.value}. "
                f"Only VERIFIED analysts can be suspended."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    if not reason or not reason.strip():
        raise ValidationError(
            message="A suspension reason is required.",
            code="ANALYST_SUSPENSION_REASON_REQUIRED",
        )

    before = {
        "status": profile.verification_status.value,
        "available_for_hire": profile.available_for_hire,
    }
    profile.verification_status = AnalystVerificationStatus.SUSPENDED
    profile.available_for_hire = False
    db.flush()
    after = {
        "status": profile.verification_status.value,
        "available_for_hire": profile.available_for_hire,
    }

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.suspended",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        notes=reason,
        request=request,
    )

    logger.warning(
        "Analyst suspended",
        extra={
            "profile_id": str(profile.id),
            "user_id": str(profile.user_id),
            "reason": reason[:200],
        },
    )

    return profile


def reactivate_analyst(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition SUSPENDED → VERIFIED.

    Admin action, requires ``admin:analyst_verify``. Reinstates a
    suspended analyst. They remain unavailable for new cases until
    they set ``available_for_hire=True`` explicitly — a suspension
    does not leave auto-reactivation of intake.
    """
    _require_admin_verify(db, actor)

    if profile.verification_status != AnalystVerificationStatus.SUSPENDED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot reactivate from status "
                f"{profile.verification_status.value}. "
                f"Only SUSPENDED analysts can be reactivated."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    before = {"status": profile.verification_status.value}
    profile.verification_status = AnalystVerificationStatus.VERIFIED
    db.flush()
    after = {"status": profile.verification_status.value}

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.reactivated",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    logger.info(
        "Analyst reactivated",
        extra={
            "profile_id": str(profile.id),
            "user_id": str(profile.user_id),
        },
    )

    return profile


def expire_verification(
    db: Session,
    *,
    actor: User,
    profile: AnalystProfile,
    request: Any | None = None,
) -> AnalystProfile:
    """
    Transition VERIFIED → EXPIRED.

    Admin or background-job action (the actor is the "system" user in
    the job case). Used when:
        - The analyst's certifications have expired
        - An annual re-verification deadline passed
        - A compliance policy requires periodic re-attestation

    An expired analyst cannot accept new work. They can re-apply via
    ``apply_as_analyst`` after the cooldown (same 30-day window as
    rejected applications).
    """
    _require_admin_verify(db, actor)

    if profile.verification_status != AnalystVerificationStatus.VERIFIED:
        raise InvalidStateTransitionError(
            message=(
                f"Cannot expire from status "
                f"{profile.verification_status.value}. "
                f"Only VERIFIED analysts can be expired."
            ),
            code="ANALYST_INVALID_TRANSITION",
        )

    before = {
        "status": profile.verification_status.value,
        "available_for_hire": profile.available_for_hire,
    }
    profile.verification_status = AnalystVerificationStatus.EXPIRED
    profile.available_for_hire = False
    db.flush()
    after = {
        "status": profile.verification_status.value,
        "available_for_hire": profile.available_for_hire,
    }

    audit_service.log_state_change(
        db,
        actor=actor,
        action="analyst.verification.expired",
        target_type="analyst_profile",
        target_id=profile.id,
        before_state=before,
        after_state=after,
        request=request,
    )

    return profile


# ============================================================================
# ADMIN: LIST
# ============================================================================

def list_pending_applications(
    db: Session,
    *,
    actor: User,
    page: PageParams,
) -> tuple[list[AnalystProfile], int]:
    """
    List analyst applications awaiting review (PENDING or IN_REVIEW).
    Requires ``admin:analyst_verify`` — currently fails closed.
    """
    _require_admin_verify(db, actor)

    stmt = select(AnalystProfile).where(
        AnalystProfile.verification_status.in_([
            AnalystVerificationStatus.PENDING,
            AnalystVerificationStatus.IN_REVIEW,
        ])
    )
    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(AnalystProfile.verification_submitted_at.asc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


def list_all_analysts(
    db: Session,
    *,
    actor: User,
    page: PageParams,
    status: AnalystVerificationStatus | None = None,
) -> tuple[list[AnalystProfile], int]:
    """
    List all analyst profiles, optionally filtered by status.
    Requires ``admin:analyst_verify``.
    """
    _require_admin_verify(db, actor)

    stmt = select(AnalystProfile)
    if status is not None:
        stmt = stmt.where(AnalystProfile.verification_status == status)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(AnalystProfile.created_at.desc(), AnalystProfile.id.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# MARKETPLACE LISTING
# ============================================================================

def list_verified_analysts(
    db: Session,
    *,
    page: PageParams,
    specializations: list[str] | None = None,
) -> tuple[list[AnalystProfile], int]:
    """
    List verified analysts available for hire.

    This is the **marketplace browse** query. Filters:
        - status = VERIFIED (mandatory)
        - available_for_hire = True (mandatory)
        - slots_remaining > 0 (or unlimited — enforced by service filter)
        - optional specializations filter (analyst must have ALL of them)

    Not gated by admin permission — any authenticated user can browse
    the marketplace. The endpoint using this function is expected to
    require authentication, but the service itself does not.
    """
    stmt = select(AnalystProfile).where(
        AnalystProfile.verification_status == AnalystVerificationStatus.VERIFIED,
        AnalystProfile.available_for_hire.is_(True),
    )

    if specializations:
        cleaned = _validate_specializations(specializations)
        # JSONB containment — analyst must have ALL requested tags
        for tag in cleaned:
            stmt = stmt.where(
                AnalystProfile.specializations.contains([tag])
            )

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    # Order by rating desc, then by purchase count desc — the
    # "best and most popular first" heuristic used by every
    # marketplace.
    stmt = (
        stmt.order_by(
            AnalystProfile.rating_average.desc().nullslast(),
            AnalystProfile.purchase_count.desc(),
            AnalystProfile.created_at.asc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Apply
    "apply_as_analyst",
    # Read
    "get_by_user_id",
    "get_by_id",
    "get_by_user_id_optional",
    # Self-service update
    "update_profile",
    "set_available_for_hire",
    # Admin review workflow
    "start_review",
    "approve_application",
    "reject_application",
    # Admin lifecycle
    "suspend_analyst",
    "reactivate_analyst",
    "expire_verification",
    # Admin list
    "list_pending_applications",
    "list_all_analysts",
    # Marketplace
    "list_verified_analysts",
]