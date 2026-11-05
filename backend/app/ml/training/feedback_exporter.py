"""
CyberGuard AI - Feedback Exporter

Step 13: Export approved feedback for training review.

IMPORTANT: Step 12 stores only email_body_hash, NOT the actual email body.
Therefore, exported feedback is metadata-only and cannot by itself be used
as text training samples. The exporter honestly reports this limitation.
"""

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog

from app.config import get_settings
from app.database.repositories.feedback import get_feedback_repository


logger = structlog.get_logger(__name__)


@dataclass
class ExportReport:
    """Report from feedback export operation."""

    batch_id: str
    export_path: str | None
    exported_count: int
    false_positive_count: int
    false_negative_count: int
    wrong_category_count: int
    metadata_only_count: int  # Items without usable training text
    usable_for_training: int  # Items with recoverable training content
    exported_at: datetime
    feedback_ids: list[str] = field(default_factory=list)
    status: str = "success"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "export_path": self.export_path,
            "exported_count": self.exported_count,
            "false_positive_count": self.false_positive_count,
            "false_negative_count": self.false_negative_count,
            "wrong_category_count": self.wrong_category_count,
            "metadata_only_count": self.metadata_only_count,
            "usable_for_training": self.usable_for_training,
            "exported_at": self.exported_at.isoformat(),
            "feedback_ids": self.feedback_ids,
            "status": self.status,
            "error": self.error,
        }


class FeedbackExporter:
    """
    Export approved feedback for training review.

    CRITICAL PRIVACY NOTE:
    Step 12 intentionally does NOT store email body content.
    Only email_body_hash is stored for privacy.

    Therefore:
    - Exported feedback contains metadata (sender, subject, classification, etc.)
    - The actual email text is NOT available for direct training
    - Feedback serves as correction signals, not training text

    For continuous learning to work with actual text:
    1. Original emails would need to be re-fetched (if still available)
    2. Or a separate privacy-consented training corpus would be needed
    3. This exporter honestly reports metadata-only status
    """

    def __init__(self, export_dir: str | Path | None = None):
        settings = get_settings()
        if export_dir:
            self.export_dir = Path(export_dir)
        else:
            # Default to app/ml/training/exports
            self.export_dir = Path(__file__).parent / "exports"

        self.export_dir.mkdir(parents=True, exist_ok=True)

    async def export_approved_feedback(
        self,
        limit: int = 1000,
        mark_as_exported: bool = True,
    ) -> ExportReport:
        """
        Export approved feedback that hasn't been included in training yet.

        Args:
            limit: Maximum number of feedback items to export
            mark_as_exported: Whether to mark feedback as included_in_training

        Returns:
            ExportReport with export statistics
        """
        batch_id = f"batch_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"

        try:
            repo = get_feedback_repository()

            # Get approved feedback not yet used in training
            feedback_items = await repo.get_approved_for_training(
                limit=limit,
                exclude_trained=True,
            )

            if not feedback_items:
                return ExportReport(
                    batch_id=batch_id,
                    export_path=None,
                    exported_count=0,
                    false_positive_count=0,
                    false_negative_count=0,
                    wrong_category_count=0,
                    metadata_only_count=0,
                    usable_for_training=0,
                    exported_at=datetime.now(timezone.utc),
                    feedback_ids=[],
                    status="no_feedback",
                )

            # Count by type
            false_positive_count = 0
            false_negative_count = 0
            wrong_category_count = 0
            metadata_only_count = 0
            usable_for_training = 0

            for item in feedback_items:
                if item.feedback_type.value == "false_positive":
                    false_positive_count += 1
                elif item.feedback_type.value == "false_negative":
                    false_negative_count += 1
                elif item.feedback_type.value == "wrong_category":
                    wrong_category_count += 1

                # Check if this item has usable training content
                # Since Step 12 only stores body_hash, all items are metadata-only
                # unless we have a way to recover the original content
                if self._has_usable_training_content(item):
                    usable_for_training += 1
                else:
                    metadata_only_count += 1

            # Export to CSV
            export_path = self.export_dir / f"{batch_id}.csv"
            feedback_ids = self._write_export_csv(feedback_items, export_path, batch_id)

            # Mark as exported if requested
            if mark_as_exported and feedback_ids:
                await repo.mark_as_trained(feedback_ids, batch_id)

            logger.info(
                "Feedback exported",
                batch_id=batch_id,
                count=len(feedback_ids),
                metadata_only=metadata_only_count,
                usable=usable_for_training,
            )

            return ExportReport(
                batch_id=batch_id,
                export_path=str(export_path),
                exported_count=len(feedback_ids),
                false_positive_count=false_positive_count,
                false_negative_count=false_negative_count,
                wrong_category_count=wrong_category_count,
                metadata_only_count=metadata_only_count,
                usable_for_training=usable_for_training,
                exported_at=datetime.now(timezone.utc),
                feedback_ids=feedback_ids,
                status="success",
            )

        except Exception as e:
            logger.error("Feedback export failed", error=str(e))
            return ExportReport(
                batch_id=batch_id,
                export_path=None,
                exported_count=0,
                false_positive_count=0,
                false_negative_count=0,
                wrong_category_count=0,
                metadata_only_count=0,
                usable_for_training=0,
                exported_at=datetime.now(timezone.utc),
                feedback_ids=[],
                status="error",
                error=str(e),
            )

    def _has_usable_training_content(self, feedback) -> bool:
        """
        Check if feedback item has usable content for text-based training.

        IMPORTANT: Step 12 stores only email_body_hash, not the actual body.
        Therefore, feedback items are metadata-only by design.

        This method returns False because:
        1. We don't have the original email body text
        2. We only have sender, subject, and body hash
        3. Generating fake content from metadata would be misleading

        To make feedback trainable, one would need to:
        - Re-fetch the original email (if still available and permitted)
        - Or link to a separate privacy-consented corpus
        """
        # Step 12 does NOT store email body - only hash
        # Therefore no feedback items have usable training text
        return False

    def _write_export_csv(
        self,
        feedback_items: list,
        export_path: Path,
        batch_id: str,
    ) -> list[str]:
        """Write feedback to CSV file."""
        feedback_ids = []

        fieldnames = [
            "feedback_id",
            "batch_id",
            "analysis_id",
            "feedback_type",
            "original_classification",
            "correct_classification",
            "original_risk_score",
            "email_sender",
            "email_subject",
            "email_body_hash",  # Only hash, NOT body content
            "has_usable_training_content",  # Always False per Step 12
            "user_comment",
            "submitted_by",
            "submitted_at",
            "reviewed_by",
            "reviewed_at",
        ]

        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for item in feedback_items:
                writer.writerow({
                    "feedback_id": item.id,
                    "batch_id": batch_id,
                    "analysis_id": item.analysis_id,
                    "feedback_type": item.feedback_type.value,
                    "original_classification": item.original_classification,
                    "correct_classification": item.correct_classification,
                    "original_risk_score": item.original_risk_score,
                    "email_sender": item.email_sender or "",
                    "email_subject": item.email_subject or "",
                    "email_body_hash": item.email_body_hash or "",
                    "has_usable_training_content": "false",  # Always false per Step 12
                    "user_comment": item.user_comment or "",
                    "submitted_by": item.submitted_by or "",
                    "submitted_at": item.submitted_at.isoformat() if item.submitted_at else "",
                    "reviewed_by": item.reviewed_by or "",
                    "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else "",
                })
                feedback_ids.append(item.id)

        return feedback_ids

    def list_exported_batches(self) -> list[dict[str, Any]]:
        """List all exported feedback batches."""
        batches = []

        for csv_file in self.export_dir.glob("batch_*.csv"):
            stat = csv_file.stat()
            # Count rows (excluding header)
            with open(csv_file, "r", encoding="utf-8") as f:
                row_count = sum(1 for _ in f) - 1

            batches.append({
                "batch_id": csv_file.stem,
                "path": str(csv_file),
                "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "size_bytes": stat.st_size,
                "row_count": max(0, row_count),
            })

        return sorted(batches, key=lambda x: x["created_at"], reverse=True)
