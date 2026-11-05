"""
CyberGuard AI - Feedback Schemas

Step 12: Pydantic schemas for feedback API.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class FeedbackTypeEnum(str, Enum):
    """Feedback type for API validation."""

    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    WRONG_CATEGORY = "wrong_category"
    CONFIRMED = "confirmed"  # Finding reviewed and correct (true positive)


class FeedbackStatusEnum(str, Enum):
    """Feedback status for API validation."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class ReviewStatusEnum(str, Enum):
    """Valid statuses for review action (subset of FeedbackStatus)."""

    APPROVED = "approved"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


# =============================================================================
# Request Schemas
# =============================================================================


class FeedbackSubmit(BaseModel):
    """Schema for submitting feedback on an analysis."""

    analysis_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="ID of the analysis to provide feedback on",
    )
    feedback_type: FeedbackTypeEnum = Field(
        ...,
        description="Type of feedback",
    )
    correct_classification: str | None = Field(
        None,
        max_length=32,
        description="What the classification should have been (for wrong_category)",
    )
    comment: str | None = Field(
        None,
        max_length=1000,
        description="Optional explanation for the feedback",
    )

    @field_validator("comment")
    @classmethod
    def validate_comment_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 1000:
            raise ValueError("Comment must be 1000 characters or less")
        return v

    @field_validator("correct_classification")
    @classmethod
    def validate_correct_classification(cls, v: str | None) -> str | None:
        if v is not None:
            valid_classifications = {
                "benign", "suspicious", "phishing", "malicious", "unknown"
            }
            if v.lower() not in valid_classifications:
                raise ValueError(
                    f"correct_classification must be one of: {', '.join(valid_classifications)}"
                )
            return v.lower()
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
                    "feedback_type": "false_positive",
                    "comment": "This email is from a known internal sender.",
                }
            ]
        }
    }


class FeedbackReview(BaseModel):
    """Schema for admin review of feedback."""

    status: ReviewStatusEnum = Field(
        ...,
        description="Review decision: approved, rejected, or duplicate",
    )
    notes: str | None = Field(
        None,
        max_length=1000,
        description="Optional review notes",
    )

    @field_validator("notes")
    @classmethod
    def validate_notes_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 1000:
            raise ValueError("Notes must be 1000 characters or less")
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "approved",
                    "notes": "Confirmed after security review",
                }
            ]
        }
    }


# =============================================================================
# Response Schemas
# =============================================================================


class FeedbackResponse(BaseModel):
    """Response schema for feedback submission."""

    feedback_id: str
    analysis_id: str
    feedback_type: str
    status: str
    submitted_at: datetime
    message: str = "Feedback submitted successfully"


class FeedbackDetail(BaseModel):
    """Detailed feedback information for admin review."""

    feedback_id: str
    analysis_id: str

    # Original analysis
    original_classification: str
    original_risk_score: int
    original_findings: list[dict[str, Any]]

    # Feedback
    feedback_type: str
    correct_classification: str | None
    user_comment: str | None

    # Email metadata
    email_sender: str | None
    email_subject: str | None

    # Submission
    submitted_by: str | None
    submitted_at: datetime

    # Review status
    status: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None

    # Training
    included_in_training: bool = False


class FeedbackStatistics(BaseModel):
    """Statistics about feedback for admin dashboard."""

    total_feedback: int = 0
    pending_count: int = 0
    approved_count: int = 0
    rejected_count: int = 0
    duplicate_count: int = 0

    # By type
    false_positive_count: int = 0
    false_negative_count: int = 0
    wrong_category_count: int = 0

    # Training
    included_in_training_count: int = 0


class FeedbackListResponse(BaseModel):
    """Response schema for listing feedback."""

    items: list[FeedbackDetail]
    total: int
    page: int = 1
    page_size: int = 20


# =============================================================================
# Analysis Response Extensions
# =============================================================================


class FeedbackLinks(BaseModel):
    """Links for reporting feedback on an analysis."""

    report_false_positive: str
    report_missed_threat: str


class AnalysisHistoryResponse(BaseModel):
    """Response for analysis history lookup."""

    analysis_id: str
    classification: str
    severity: str
    risk_score: int
    confidence: float
    findings_count: int
    email_sender: str | None
    email_subject: str | None
    analyzed_at: datetime
    processing_time_ms: float | None


class ModuleAccuracyResponse(BaseModel):
    """
    Real, feedback-derived accuracy signal for a rule-based analysis
    module (currently: LogAgent). Never fabricated - accuracy_percent is
    None until at least one confirmed/false_positive feedback submission
    exists, rather than defaulting to 0% or inventing a plausible number.
    """

    total_analyses: int = 0
    total_feedback_count: int = 0
    confirmed_count: int = 0
    false_positive_count: int = 0
    accuracy_percent: float | None = Field(
        None,
        description="confirmed / (confirmed + false_positive) * 100. "
        "None when no reviewed feedback exists yet.",
    )
