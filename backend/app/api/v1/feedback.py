"""
CyberGuard AI - Feedback API Endpoints

Step 12: User feedback mechanism for analysis results.

Security:
- POST /feedback: Requires authentication
- GET /feedback/pending: Admin only
- POST /feedback/{id}/review: Admin only
- GET /feedback/statistics: Admin only
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
import structlog

from app.auth import User, UserRole, get_current_active_user
from app.auth.jwt import require_role
from app.config import settings
from app.core.errors import (
    NotFoundError,
    ValidationError,
    AuthorizationError,
    CyberGuardError,
    ErrorCode,
)
from app.database.models.feedback import (
    EmailFeedback,
    FeedbackType,
    FeedbackStatus,
)
from app.database.repositories.feedback import (
    get_feedback_repository,
    get_analysis_history_repository,
)
from app.schemas.feedback import (
    FeedbackSubmit,
    FeedbackResponse,
    FeedbackDetail,
    FeedbackReview,
    FeedbackStatistics,
    FeedbackListResponse,
    ReviewStatusEnum,
    ModuleAccuracyResponse,
)


router = APIRouter(prefix="/feedback", tags=["Feedback"])
logger = structlog.get_logger(__name__)


def _feedback_to_detail(feedback: EmailFeedback) -> FeedbackDetail:
    """Convert EmailFeedback model to FeedbackDetail response."""
    return FeedbackDetail(
        feedback_id=feedback.id,
        analysis_id=feedback.analysis_id,
        original_classification=feedback.original_classification,
        original_risk_score=feedback.original_risk_score,
        original_findings=feedback.original_findings,
        feedback_type=feedback.feedback_type.value,
        correct_classification=feedback.correct_classification,
        user_comment=feedback.user_comment,
        email_sender=feedback.email_sender,
        email_subject=feedback.email_subject,
        submitted_by=feedback.submitted_by,
        submitted_at=feedback.submitted_at,
        status=feedback.status.value,
        reviewed_by=feedback.reviewed_by,
        reviewed_at=feedback.reviewed_at,
        review_notes=feedback.review_notes,
        included_in_training=feedback.included_in_training,
    )


@router.post(
    "",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Feedback",
    description="""
Submit feedback on an email analysis result.

Requires authentication. The original analysis data is loaded from
the server - clients cannot supply classification/risk/findings.

Feedback types:
- `false_positive`: Email was flagged but is actually safe
- `false_negative`: Email was missed but is actually malicious
- `wrong_category`: Classification was incorrect (specify correct_classification)
    """,
)
async def submit_feedback(
    feedback_request: FeedbackSubmit,
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> FeedbackResponse:
    """Submit feedback on an analysis result."""
    if not settings.db_enabled:
        raise CyberGuardError(
            message="Feedback requires database to be enabled",
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            status_code=503,
        )

    analysis_id = feedback_request.analysis_id
    feedback_type = FeedbackType(feedback_request.feedback_type.value)

    logger.info(
        "Feedback submission",
        analysis_id=analysis_id,
        feedback_type=feedback_type.value,
        user_id=current_user.id,
    )

    # Load original analysis from history - DO NOT trust client
    history_repo = get_analysis_history_repository()
    analysis = await history_repo.get_by_id(analysis_id)

    if not analysis:
        raise NotFoundError(
            message=f"Analysis not found: {analysis_id}",
            detail="The specified analysis_id does not exist in history",
        )

    # Check for duplicate submission
    feedback_repo = get_feedback_repository()
    exists = await feedback_repo.exists_for_analysis(
        analysis_id=analysis_id,
        feedback_type=feedback_type,
        submitted_by=current_user.id,
    )

    if exists:
        raise ValidationError(
            message="Duplicate feedback submission",
            detail="You have already submitted this type of feedback for this analysis",
        )

    # Build findings summary (without sensitive data)
    findings_summary = [
        {
            "rule_id": f.get("rule_id"),
            "name": f.get("name"),
            "severity": f.get("severity"),
        }
        for f in analysis.findings[:10]  # Limit to 10 findings
    ]

    # Create feedback record. analysis_type comes from the looked-up
    # history row (never from client input), same trust model as every
    # other field here - propagates "log" so this feedback is counted
    # toward LogAgent's module accuracy rather than email's.
    feedback = EmailFeedback(
        analysis_id=analysis_id,
        analysis_type=analysis.analysis_type,
        original_classification=analysis.classification,
        original_risk_score=analysis.risk_score,
        original_findings=findings_summary,
        feedback_type=feedback_type,
        correct_classification=feedback_request.correct_classification,
        user_comment=feedback_request.comment,
        email_sender=analysis.email_sender,
        email_subject=analysis.email_subject,
        email_body_hash=analysis.email_body_hash,
        submitted_by=current_user.id,
        status=FeedbackStatus.PENDING,
    )

    created_feedback = await feedback_repo.create(feedback)

    logger.info(
        "Feedback created",
        feedback_id=created_feedback.id,
        analysis_id=analysis_id,
        feedback_type=feedback_type.value,
        user_id=current_user.id,
    )

    return FeedbackResponse(
        feedback_id=created_feedback.id,
        analysis_id=analysis_id,
        feedback_type=feedback_type.value,
        status=FeedbackStatus.PENDING.value,
        submitted_at=created_feedback.submitted_at,
        message="Feedback submitted successfully. Thank you for helping improve our detection.",
    )


@router.get(
    "/pending",
    response_model=FeedbackListResponse,
    summary="Get Pending Feedback (Admin)",
    description="Get all pending feedback awaiting admin review. Admin only.",
    dependencies=[Depends(require_role([UserRole.ADMIN]))],
)
async def get_pending_feedback(
    current_user: Annotated[User, Depends(get_current_active_user)],
    limit: int = 50,
    offset: int = 0,
) -> FeedbackListResponse:
    """Get pending feedback for admin review."""
    if not settings.db_enabled:
        raise CyberGuardError(
            message="Feedback requires database to be enabled",
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            status_code=503,
        )

    feedback_repo = get_feedback_repository()
    pending = await feedback_repo.get_pending(limit=limit, offset=offset)

    logger.info(
        "Pending feedback retrieved",
        count=len(pending),
        admin_id=current_user.id,
    )

    return FeedbackListResponse(
        items=[_feedback_to_detail(f) for f in pending],
        total=len(pending),
        page=offset // limit + 1 if limit > 0 else 1,
        page_size=limit,
    )


@router.post(
    "/{feedback_id}/review",
    response_model=FeedbackDetail,
    summary="Review Feedback (Admin)",
    description="""
Review and approve/reject feedback. Admin only.

Valid status values:
- `approved`: Feedback is verified and will be used for model training
- `rejected`: Feedback is invalid or inaccurate
- `duplicate`: Feedback duplicates an existing submission
    """,
    dependencies=[Depends(require_role([UserRole.ADMIN]))],
)
async def review_feedback(
    feedback_id: str,
    review: FeedbackReview,
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> FeedbackDetail:
    """Review feedback (admin only)."""
    if not settings.db_enabled:
        raise CyberGuardError(
            message="Feedback requires database to be enabled",
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            status_code=503,
        )

    feedback_repo = get_feedback_repository()

    # Check feedback exists
    existing = await feedback_repo.get_by_id(feedback_id)
    if not existing:
        raise NotFoundError(
            message=f"Feedback not found: {feedback_id}",
        )

    # Map ReviewStatusEnum to FeedbackStatus
    status_map = {
        ReviewStatusEnum.APPROVED: FeedbackStatus.APPROVED,
        ReviewStatusEnum.REJECTED: FeedbackStatus.REJECTED,
        ReviewStatusEnum.DUPLICATE: FeedbackStatus.DUPLICATE,
    }
    new_status = status_map[review.status]

    # Update feedback
    updated = await feedback_repo.review(
        feedback_id=feedback_id,
        status=new_status,
        reviewed_by=current_user.id,
        review_notes=review.notes,
    )

    if not updated:
        raise NotFoundError(
            message=f"Feedback not found: {feedback_id}",
        )

    logger.info(
        "Feedback reviewed",
        feedback_id=feedback_id,
        status=new_status.value,
        admin_id=current_user.id,
    )

    return _feedback_to_detail(updated)


@router.get(
    "/statistics",
    response_model=FeedbackStatistics,
    summary="Get Feedback Statistics (Admin)",
    description="Get statistics about feedback submissions. Admin only.",
    dependencies=[Depends(require_role([UserRole.ADMIN]))],
)
async def get_feedback_statistics(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> FeedbackStatistics:
    """Get feedback statistics for admin dashboard."""
    if not settings.db_enabled:
        raise CyberGuardError(
            message="Feedback requires database to be enabled",
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            status_code=503,
        )

    feedback_repo = get_feedback_repository()
    stats = await feedback_repo.get_statistics()

    logger.info(
        "Feedback statistics retrieved",
        admin_id=current_user.id,
    )

    return FeedbackStatistics(**stats)


async def _get_module_accuracy(analysis_type: str) -> ModuleAccuracyResponse:
    """Shared implementation for the per-module accuracy routes below."""
    if not settings.db_enabled:
        return ModuleAccuracyResponse()

    feedback_repo = get_feedback_repository()
    stats = await feedback_repo.get_module_accuracy(analysis_type)

    confirmed = stats["confirmed_count"]
    false_positive = stats["false_positive_count"]
    reviewed = confirmed + false_positive
    accuracy_percent = round(confirmed / reviewed * 100, 1) if reviewed > 0 else None

    return ModuleAccuracyResponse(
        total_analyses=stats["total_analyses"],
        total_feedback_count=stats["total_feedback_count"],
        confirmed_count=confirmed,
        false_positive_count=false_positive,
        accuracy_percent=accuracy_percent,
    )


@router.get(
    "/module-accuracy/log",
    response_model=ModuleAccuracyResponse,
    summary="Get LogAgent Module Accuracy",
    description="""
Real, feedback-derived accuracy signal for LogAgent (the rule-based log
analysis engine).

accuracy_percent is computed as confirmed / (confirmed + false_positive)
and is `null` until at least one of those feedback types has been
submitted for a log analysis - never a fabricated or default percentage.
    """,
)
async def get_log_module_accuracy() -> ModuleAccuracyResponse:
    """Get real, feedback-derived accuracy stats for LogAgent. Read-only aggregate, no PII."""
    return await _get_module_accuracy("log")


@router.get(
    "/module-accuracy/network",
    response_model=ModuleAccuracyResponse,
    summary="Get NetworkAgent Module Accuracy",
    description="""
Real, feedback-derived accuracy signal for NetworkAgent (the rule-based
network scanning/vulnerability engine).

accuracy_percent is computed as confirmed / (confirmed + false_positive)
and is `null` until at least one of those feedback types has been
submitted for a network analysis - never a fabricated or default percentage.
    """,
)
async def get_network_module_accuracy() -> ModuleAccuracyResponse:
    """Get real, feedback-derived accuracy stats for NetworkAgent. Read-only aggregate, no PII."""
    return await _get_module_accuracy("network")


@router.get(
    "/{feedback_id}",
    response_model=FeedbackDetail,
    summary="Get Feedback Detail (Admin)",
    description="Get detailed information about a specific feedback. Admin only.",
    dependencies=[Depends(require_role([UserRole.ADMIN]))],
)
async def get_feedback_detail(
    feedback_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> FeedbackDetail:
    """Get feedback detail by ID."""
    if not settings.db_enabled:
        raise CyberGuardError(
            message="Feedback requires database to be enabled",
            error_code=ErrorCode.SERVICE_UNAVAILABLE,
            status_code=503,
        )

    feedback_repo = get_feedback_repository()
    feedback = await feedback_repo.get_by_id(feedback_id)

    if not feedback:
        raise NotFoundError(
            message=f"Feedback not found: {feedback_id}",
        )

    return _feedback_to_detail(feedback)
