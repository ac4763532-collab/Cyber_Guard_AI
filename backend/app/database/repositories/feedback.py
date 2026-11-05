"""
CyberGuard AI - Feedback Repository

Step 12: Database operations for feedback and analysis history.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import json

import structlog

from app.database.connection import get_database
from app.database.models.feedback import (
    EmailFeedback,
    AnalysisHistory,
    FeedbackType,
    FeedbackStatus,
)
from app.schemas.analysis import AnalysisType
from app.core.errors import NotFoundError, ValidationError


logger = structlog.get_logger(__name__)


class FeedbackRepository:
    """Repository for feedback database operations."""

    def __init__(self):
        self.db = get_database()

    async def create(self, feedback: EmailFeedback) -> EmailFeedback:
        """Create a new feedback record."""
        query = """
            INSERT INTO email_feedback (
                id, analysis_id, analysis_type,
                original_classification, original_risk_score, original_findings,
                feedback_type, correct_classification, user_comment,
                email_sender, email_subject, email_body_hash,
                submitted_by, submitted_at, status
            )
            VALUES (
                %(id)s, %(analysis_id)s, %(analysis_type)s,
                %(original_classification)s, %(original_risk_score)s, %(original_findings)s,
                %(feedback_type)s, %(correct_classification)s, %(user_comment)s,
                %(email_sender)s, %(email_subject)s, %(email_body_hash)s,
                %(submitted_by)s, %(submitted_at)s, %(status)s
            )
            RETURNING *
        """

        params = {
            "id": feedback.id,
            "analysis_id": feedback.analysis_id,
            "analysis_type": feedback.analysis_type.value,
            "original_classification": feedback.original_classification,
            "original_risk_score": feedback.original_risk_score,
            "original_findings": json.dumps(feedback.original_findings),
            "feedback_type": feedback.feedback_type.value,
            "correct_classification": feedback.correct_classification,
            "user_comment": feedback.user_comment,
            "email_sender": feedback.email_sender,
            "email_subject": feedback.email_subject,
            "email_body_hash": feedback.email_body_hash,
            "submitted_by": feedback.submitted_by,
            "submitted_at": feedback.submitted_at,
            "status": feedback.status.value,
        }

        result = await self.db.execute_one(query, params)
        return self._row_to_feedback(result)

    async def get_by_id(self, feedback_id: str) -> EmailFeedback | None:
        """Get feedback by ID."""
        try:
            # Validate UUID format
            from uuid import UUID
            UUID(feedback_id)
        except ValueError:
            return None

        query = "SELECT * FROM email_feedback WHERE id = %(id)s"
        result = await self.db.execute_one(query, {"id": feedback_id})
        return self._row_to_feedback(result) if result else None

    async def get_pending(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EmailFeedback]:
        """Get all pending feedback for admin review."""
        query = """
            SELECT * FROM email_feedback
            WHERE status = 'pending'
            ORDER BY submitted_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, {"limit": limit, "offset": offset})
        return [self._row_to_feedback(row) for row in results]

    async def get_approved_for_training(
        self,
        limit: int = 100,
        exclude_trained: bool = True,
    ) -> list[EmailFeedback]:
        """Get approved feedback that can be used for training."""
        if exclude_trained:
            query = """
                SELECT * FROM email_feedback
                WHERE status = 'approved' AND included_in_training = false
                ORDER BY submitted_at ASC
                LIMIT %(limit)s
            """
        else:
            query = """
                SELECT * FROM email_feedback
                WHERE status = 'approved'
                ORDER BY submitted_at ASC
                LIMIT %(limit)s
            """

        results = await self.db.execute(query, {"limit": limit})
        return [self._row_to_feedback(row) for row in results]

    async def review(
        self,
        feedback_id: str,
        status: FeedbackStatus,
        reviewed_by: str,
        review_notes: str | None = None,
    ) -> EmailFeedback | None:
        """Update feedback with admin review decision."""
        # Validate status is a valid review status
        valid_review_statuses = {
            FeedbackStatus.APPROVED,
            FeedbackStatus.REJECTED,
            FeedbackStatus.DUPLICATE,
        }
        if status not in valid_review_statuses:
            raise ValidationError(
                message=f"Invalid review status: {status.value}",
                detail="Review status must be approved, rejected, or duplicate",
            )

        query = """
            UPDATE email_feedback
            SET status = %(status)s,
                reviewed_by = %(reviewed_by)s,
                reviewed_at = %(reviewed_at)s,
                review_notes = %(review_notes)s
            WHERE id = %(id)s
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "id": feedback_id,
            "status": status.value,
            "reviewed_by": reviewed_by,
            "reviewed_at": datetime.now(timezone.utc),
            "review_notes": review_notes,
        })

        return self._row_to_feedback(result) if result else None

    async def mark_as_trained(
        self,
        feedback_ids: list[str],
        training_batch_id: str,
    ) -> int:
        """Mark feedback records as included in training."""
        if not feedback_ids:
            return 0

        query = """
            UPDATE email_feedback
            SET included_in_training = true,
                training_batch_id = %(training_batch_id)s
            WHERE id = ANY(%(ids)s) AND status = 'approved'
        """

        await self.db.execute(query, {
            "ids": feedback_ids,
            "training_batch_id": training_batch_id,
        })

        # Return count of updated records
        return len(feedback_ids)

    async def get_statistics(self, analysis_type: str | None = None) -> dict[str, Any]:
        """Get feedback statistics for admin dashboard. Optionally filter by analysis_type."""
        conditions = []
        params: dict[str, Any] = {}
        if analysis_type:
            conditions.append("analysis_type = %(analysis_type)s")
            params["analysis_type"] = analysis_type
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
            SELECT
                COUNT(*) as total_feedback,
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE status = 'approved') as approved_count,
                COUNT(*) FILTER (WHERE status = 'rejected') as rejected_count,
                COUNT(*) FILTER (WHERE status = 'duplicate') as duplicate_count,
                COUNT(*) FILTER (WHERE feedback_type = 'false_positive') as false_positive_count,
                COUNT(*) FILTER (WHERE feedback_type = 'false_negative') as false_negative_count,
                COUNT(*) FILTER (WHERE feedback_type = 'wrong_category') as wrong_category_count,
                COUNT(*) FILTER (WHERE feedback_type = 'confirmed') as confirmed_count,
                COUNT(*) FILTER (WHERE included_in_training = true) as included_in_training_count
            FROM email_feedback
            {where_clause}
        """

        result = await self.db.execute_one(query, params)
        return dict(result) if result else {
            "total_feedback": 0,
            "pending_count": 0,
            "approved_count": 0,
            "rejected_count": 0,
            "duplicate_count": 0,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "wrong_category_count": 0,
            "confirmed_count": 0,
            "included_in_training_count": 0,
        }

    async def get_module_accuracy(self, analysis_type: str) -> dict[str, Any]:
        """
        Real, feedback-derived accuracy signal for a rule-based analysis
        module, keyed by analysis_type ('log', 'network', ...). Two
        independent counts (no FK/JOIN exists between analysis_history and
        email_feedback - linkage is app-layer only) in one round trip.

        Generalized from the LogAgent-only get_log_module_accuracy() so
        NetworkAgent (and any future module) can reuse the same query
        instead of duplicating it per analysis_type.
        """
        query = """
            SELECT
                (SELECT COUNT(*) FROM analysis_history WHERE analysis_type = %(analysis_type)s) as total_analyses,
                COUNT(*) as total_feedback_count,
                COUNT(*) FILTER (WHERE feedback_type = 'confirmed') as confirmed_count,
                COUNT(*) FILTER (WHERE feedback_type = 'false_positive') as false_positive_count
            FROM email_feedback
            WHERE analysis_type = %(analysis_type)s
        """
        result = await self.db.execute_one(query, {"analysis_type": analysis_type})
        return dict(result) if result else {
            "total_analyses": 0,
            "total_feedback_count": 0,
            "confirmed_count": 0,
            "false_positive_count": 0,
        }

    async def exists_for_analysis(
        self,
        analysis_id: str,
        feedback_type: FeedbackType,
        submitted_by: str | None = None,
    ) -> bool:
        """Check if feedback already exists for this analysis/type/user combination."""
        if submitted_by:
            query = """
                SELECT EXISTS(
                    SELECT 1 FROM email_feedback
                    WHERE analysis_id = %(analysis_id)s
                      AND feedback_type = %(feedback_type)s
                      AND submitted_by = %(submitted_by)s
                )
            """
            params = {
                "analysis_id": analysis_id,
                "feedback_type": feedback_type.value,
                "submitted_by": submitted_by,
            }
        else:
            query = """
                SELECT EXISTS(
                    SELECT 1 FROM email_feedback
                    WHERE analysis_id = %(analysis_id)s
                      AND feedback_type = %(feedback_type)s
                )
            """
            params = {
                "analysis_id": analysis_id,
                "feedback_type": feedback_type.value,
            }

        result = await self.db.execute_one(query, params)
        return result["exists"] if result else False

    def _row_to_feedback(self, row: dict[str, Any]) -> EmailFeedback:
        """Convert database row to EmailFeedback model."""
        findings = row.get("original_findings", [])
        if isinstance(findings, str):
            findings = json.loads(findings)

        return EmailFeedback(
            id=str(row["id"]),
            analysis_id=row["analysis_id"],
            analysis_type=AnalysisType(row.get("analysis_type") or "email"),
            original_classification=row["original_classification"],
            original_risk_score=row["original_risk_score"],
            original_findings=findings,
            feedback_type=FeedbackType(row["feedback_type"]),
            correct_classification=row.get("correct_classification"),
            user_comment=row.get("user_comment"),
            email_sender=row.get("email_sender"),
            email_subject=row.get("email_subject"),
            email_body_hash=row.get("email_body_hash"),
            submitted_by=row.get("submitted_by"),
            submitted_at=row["submitted_at"],
            status=FeedbackStatus(row["status"]),
            reviewed_by=row.get("reviewed_by"),
            reviewed_at=row.get("reviewed_at"),
            review_notes=row.get("review_notes"),
            included_in_training=row.get("included_in_training", False),
            training_batch_id=row.get("training_batch_id"),
        )


class AnalysisHistoryRepository:
    """Repository for analysis history database operations."""

    def __init__(self):
        self.db = get_database()

    async def save(self, history: AnalysisHistory) -> AnalysisHistory:
        """Save an analysis history record."""
        query = """
            INSERT INTO analysis_history (
                id, analysis_type, classification, severity, risk_score, confidence, findings,
                email_sender, email_subject, email_body_hash, context,
                analyzed_at, processing_time_ms, analyzed_by
            )
            VALUES (
                %(id)s, %(analysis_type)s, %(classification)s, %(severity)s, %(risk_score)s, %(confidence)s, %(findings)s,
                %(email_sender)s, %(email_subject)s, %(email_body_hash)s, %(context)s,
                %(analyzed_at)s, %(processing_time_ms)s, %(analyzed_by)s
            )
            RETURNING *
        """

        params = {
            "id": history.id,
            "analysis_type": history.analysis_type.value,
            "classification": history.classification,
            "severity": history.severity,
            "risk_score": history.risk_score,
            "confidence": history.confidence,
            "findings": json.dumps(history.findings),
            "email_sender": history.email_sender,
            "email_subject": history.email_subject,
            "email_body_hash": history.email_body_hash,
            "context": json.dumps(history.context),
            "analyzed_at": history.analyzed_at,
            "processing_time_ms": history.processing_time_ms,
            "analyzed_by": history.analyzed_by,
        }

        result = await self.db.execute_one(query, params)
        return self._row_to_history(result)

    async def get_by_id(self, analysis_id: str) -> AnalysisHistory | None:
        """Get analysis history by ID."""
        try:
            from uuid import UUID
            UUID(analysis_id)
        except ValueError:
            return None

        query = "SELECT * FROM analysis_history WHERE id = %(id)s"
        result = await self.db.execute_one(query, {"id": analysis_id})
        return self._row_to_history(result) if result else None

    async def list(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: str | None = None,
        analysis_type: str | None = None,
    ) -> list[AnalysisHistory]:
        """List analysis history with filters."""
        conditions = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if classification:
            conditions.append("classification = %(classification)s")
            params["classification"] = classification

        if analysis_type:
            conditions.append("analysis_type = %(analysis_type)s")
            params["analysis_type"] = analysis_type

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT * FROM analysis_history
            WHERE {where_clause}
            ORDER BY analyzed_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, params)
        return [self._row_to_history(row) for row in results]

    def _row_to_history(self, row: dict[str, Any]) -> AnalysisHistory:
        """Convert database row to AnalysisHistory model."""
        findings = row.get("findings", [])
        if isinstance(findings, str):
            findings = json.loads(findings)

        context = row.get("context", {})
        if isinstance(context, str):
            context = json.loads(context) if context else {}

        return AnalysisHistory(
            id=str(row["id"]),
            analysis_type=AnalysisType(row.get("analysis_type") or "email"),
            classification=row["classification"],
            severity=row["severity"],
            risk_score=row["risk_score"],
            confidence=row["confidence"],
            findings=findings,
            email_sender=row.get("email_sender"),
            email_subject=row.get("email_subject"),
            email_body_hash=row.get("email_body_hash"),
            context=context or {},
            analyzed_at=row["analyzed_at"],
            processing_time_ms=row.get("processing_time_ms"),
            analyzed_by=row.get("analyzed_by"),
        )


# Singletons
_feedback_repo: FeedbackRepository | None = None
_history_repo: AnalysisHistoryRepository | None = None


def get_feedback_repository() -> FeedbackRepository:
    """Get the feedback repository."""
    global _feedback_repo
    if _feedback_repo is None:
        _feedback_repo = FeedbackRepository()
    return _feedback_repo


def get_analysis_history_repository() -> AnalysisHistoryRepository:
    """Get the analysis history repository."""
    global _history_repo
    if _history_repo is None:
        _history_repo = AnalysisHistoryRepository()
    return _history_repo
