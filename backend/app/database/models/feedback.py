"""
CyberGuard AI - Feedback and Analysis History Models

Step 12: User feedback mechanism for ML training data collection.

PRIVACY: These models NEVER store:
- Full email body
- Attachment contents
- Authentication tokens
- Passwords
- API keys
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.schemas.analysis import AnalysisType


class FeedbackType(str, Enum):
    """Types of user feedback on analysis results."""

    FALSE_POSITIVE = "false_positive"  # Flagged but is actually safe/benign
    FALSE_NEGATIVE = "false_negative"  # Missed but is actually malicious
    WRONG_CATEGORY = "wrong_category"  # Classification was incorrect
    CONFIRMED = "confirmed"  # Finding was reviewed and is correct (true positive)


class FeedbackStatus(str, Enum):
    """Status of feedback in the review workflow."""

    PENDING = "pending"      # Awaiting admin review
    APPROVED = "approved"    # Verified and approved for training
    REJECTED = "rejected"    # Rejected as invalid/inaccurate
    DUPLICATE = "duplicate"  # Duplicate of existing feedback


class EmailFeedback(BaseModel):
    """
    User feedback on email analysis results.

    Used for:
    - Tracking false positives/negatives
    - ML model retraining
    - Analysis quality improvement

    PRIVACY: email_body_hash is SHA-256 hash, NOT the actual body.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))

    # Link to original analysis
    analysis_id: str = Field(..., max_length=64, description="ID of the original analysis")

    # Which analysis pipeline this feedback is about. Defaults to "email"
    # since this table/model predates log analysis feedback - every
    # pre-existing row and every email submission keeps working unchanged.
    analysis_type: AnalysisType = AnalysisType.EMAIL

    # Original analysis results (server-side populated, NOT from client)
    original_classification: str = Field(..., max_length=32)
    original_risk_score: int = Field(..., ge=0, le=100)
    original_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Feedback details
    feedback_type: FeedbackType
    correct_classification: str | None = Field(
        None,
        max_length=32,
        description="What the classification should have been",
    )
    user_comment: str | None = Field(
        None,
        max_length=1000,
        description="User explanation for the feedback",
    )

    # Email metadata (NO body content)
    email_sender: str | None = Field(None, max_length=255)
    email_subject: str | None = Field(None, max_length=500)
    email_body_hash: str | None = Field(
        None,
        max_length=64,
        description="SHA-256 hash of email body (NOT the body itself)",
    )

    # Submission metadata
    submitted_by: str | None = Field(None, description="User ID who submitted feedback")
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Review workflow
    status: FeedbackStatus = FeedbackStatus.PENDING
    reviewed_by: str | None = Field(None, description="Admin ID who reviewed")
    reviewed_at: datetime | None = None
    review_notes: str | None = Field(None, max_length=1000)

    # Training integration
    included_in_training: bool = False
    training_batch_id: str | None = None


class AnalysisHistory(BaseModel):
    """
    Historical record of email analysis results.

    Used for:
    - Feedback reference lookup
    - Audit trail
    - Analytics

    PRIVACY: email_body_hash is SHA-256 hash, NOT the actual body.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))

    # Which analysis pipeline produced this row. Defaults to "email" since
    # this table predates log analysis - every pre-existing row keeps
    # resolving as email with no data migration needed.
    analysis_type: AnalysisType = AnalysisType.EMAIL

    # Analysis results
    classification: str = Field(..., max_length=32)
    severity: str = Field(..., max_length=20)
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Email metadata (NO body content)
    email_sender: str | None = Field(None, max_length=255)
    email_subject: str | None = Field(None, max_length=500)
    email_body_hash: str | None = Field(
        None,
        max_length=64,
        description="SHA-256 hash of email body (NOT the body itself)",
    )

    # Type-specific metadata that doesn't fit the email columns above
    # (e.g. for log analysis: source, source_host, processed_event_count).
    # Empty dict for email rows - they use the dedicated columns instead.
    context: dict[str, Any] = Field(default_factory=dict)

    # Timing
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time_ms: float | None = None

    # Context
    analyzed_by: str | None = Field(None, description="User ID who requested analysis")
