"""
CyberGuard AI - Training Data Combiner

Step 13: Combine original training data with usable feedback.

IMPORTANT LIMITATION:
Step 12 stores only email_body_hash, NOT the actual email body.
Therefore, feedback items are metadata-only and cannot be directly
combined with text training data for the TF-IDF classifier.

This combiner:
1. Loads original training data (if available)
2. Attempts to load feedback batches
3. Honestly reports that feedback is metadata-only
4. Does NOT generate fake email bodies from sender/subject
5. Only includes feedback if a privacy-safe content source exists
"""

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from app.config import get_settings


logger = structlog.get_logger(__name__)


@dataclass
class CombineReport:
    """Report from data combination operation."""

    original_samples: int
    feedback_batches_found: int
    total_feedback_items: int
    usable_feedback_samples: int
    skipped_feedback_samples: int  # Metadata-only, cannot be used for training
    total_samples: int
    label_distribution: dict[str, int]
    output_file: str | None
    combined_at: datetime
    status: str = "success"
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_samples": self.original_samples,
            "feedback_batches_found": self.feedback_batches_found,
            "total_feedback_items": self.total_feedback_items,
            "usable_feedback_samples": self.usable_feedback_samples,
            "skipped_feedback_samples": self.skipped_feedback_samples,
            "total_samples": self.total_samples,
            "label_distribution": self.label_distribution,
            "output_file": self.output_file,
            "combined_at": self.combined_at.isoformat(),
            "status": self.status,
            "error": self.error,
            "warnings": self.warnings,
        }


class DataCombiner:
    """
    Combine original training data with feedback corrections.

    CRITICAL LIMITATION:
    Step 12 intentionally does NOT store email body content for privacy.
    Only email_body_hash is stored.

    Therefore:
    - Feedback items contain: sender, subject, body_hash, classification correction
    - The actual email text is NOT available
    - We CANNOT simply append feedback rows to training data

    This combiner takes an honest approach:
    1. Loads original training data (if the file exists)
    2. Scans feedback batches for items with usable content
    3. Reports how many items are metadata-only (cannot be used)
    4. Only combines items that have actual training text
    5. Never generates fake content from metadata

    For real continuous learning with text classification:
    - Would need to store original emails (privacy concern)
    - Or re-fetch emails when training (if still available)
    - Or use feedback as weight adjustments rather than new samples
    """

    def __init__(
        self,
        original_data_path: str | Path | None = None,
        feedback_dir: str | Path | None = None,
        output_dir: str | Path | None = None,
    ):
        base_dir = Path(__file__).parent

        # Original training data path
        if original_data_path:
            self.original_data_path = Path(original_data_path)
        else:
            # Check common locations
            possible_paths = [
                base_dir / "data" / "train.csv",
                base_dir.parent / "data" / "train.csv",
                base_dir.parent.parent / "ml_data" / "processed" / "splits" / "train.csv",
            ]
            self.original_data_path = None
            for p in possible_paths:
                if p.exists():
                    self.original_data_path = p
                    break

        # Feedback exports directory
        if feedback_dir:
            self.feedback_dir = Path(feedback_dir)
        else:
            self.feedback_dir = base_dir / "exports"

        # Combined output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = base_dir / "combined"

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def combine(self, output_filename: str | None = None) -> CombineReport:
        """
        Combine original training data with usable feedback.

        Returns:
            CombineReport with combination statistics
        """
        warnings = []

        try:
            # Load original training data
            original_samples = []
            original_count = 0

            if self.original_data_path and self.original_data_path.exists():
                original_samples, original_count = self._load_original_data()
                logger.info(
                    "Loaded original training data",
                    path=str(self.original_data_path),
                    count=original_count,
                )
            else:
                warnings.append(
                    f"Original training data not found. "
                    f"Expected at: {self.original_data_path or 'not configured'}"
                )
                logger.warning("Original training data not found")

            # Scan feedback batches
            feedback_batches = list(self.feedback_dir.glob("batch_*.csv"))
            total_feedback_items = 0
            usable_feedback = []
            skipped_count = 0

            for batch_file in feedback_batches:
                batch_usable, batch_skipped = self._process_feedback_batch(batch_file)
                usable_feedback.extend(batch_usable)
                skipped_count += batch_skipped
                total_feedback_items += len(batch_usable) + batch_skipped

            # Report the honest reality
            if total_feedback_items > 0 and len(usable_feedback) == 0:
                warnings.append(
                    f"All {total_feedback_items} feedback items are metadata-only. "
                    "Step 12 stores only email_body_hash, not the actual email text. "
                    "Feedback cannot be directly used for text classifier training."
                )

            # Combine datasets
            combined_samples = original_samples + usable_feedback
            total_samples = len(combined_samples)

            # Calculate label distribution
            label_distribution = self._calculate_label_distribution(combined_samples)

            # Write output if we have samples
            output_path = None
            if combined_samples:
                if output_filename is None:
                    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    output_filename = f"combined_{timestamp}.csv"

                output_path = self.output_dir / output_filename
                self._write_combined_data(combined_samples, output_path)
                logger.info("Combined data written", path=str(output_path), count=total_samples)

            return CombineReport(
                original_samples=original_count,
                feedback_batches_found=len(feedback_batches),
                total_feedback_items=total_feedback_items,
                usable_feedback_samples=len(usable_feedback),
                skipped_feedback_samples=skipped_count,
                total_samples=total_samples,
                label_distribution=label_distribution,
                output_file=str(output_path) if output_path else None,
                combined_at=datetime.now(timezone.utc),
                status="success" if combined_samples else "no_data",
                warnings=warnings,
            )

        except Exception as e:
            logger.error("Data combination failed", error=str(e))
            return CombineReport(
                original_samples=0,
                feedback_batches_found=0,
                total_feedback_items=0,
                usable_feedback_samples=0,
                skipped_feedback_samples=0,
                total_samples=0,
                label_distribution={},
                output_file=None,
                combined_at=datetime.now(timezone.utc),
                status="error",
                error=str(e),
                warnings=warnings,
            )

    def _load_original_data(self) -> tuple[list[dict], int]:
        """Load original training data CSV."""
        samples = []

        with open(self.original_data_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Preserve original schema
                samples.append(dict(row))

        return samples, len(samples)

    def _process_feedback_batch(self, batch_file: Path) -> tuple[list[dict], int]:
        """
        Process a feedback batch, extracting usable training samples.

        IMPORTANT: Step 12 stores only email_body_hash, not the body.
        Therefore, all feedback items are metadata-only and CANNOT
        be converted to training samples for text classification.

        Returns:
            (usable_samples, skipped_count)
        """
        usable = []
        skipped = 0

        with open(batch_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Check if this item has usable training content
                has_content = row.get("has_usable_training_content", "false").lower() == "true"

                if has_content:
                    # Convert feedback to training format
                    # This would need: text content + label
                    # But Step 12 doesn't provide text content
                    training_sample = self._feedback_to_training_sample(row)
                    if training_sample:
                        usable.append(training_sample)
                    else:
                        skipped += 1
                else:
                    # Metadata-only - cannot be used for text training
                    skipped += 1

        return usable, skipped

    def _feedback_to_training_sample(self, feedback_row: dict) -> dict | None:
        """
        Convert feedback row to training sample format.

        IMPORTANT: This requires actual email text content.
        Step 12 only stores email_body_hash, so this will
        return None unless we have a way to recover the text.

        For a real implementation, options would be:
        1. Re-fetch original email (if still available and permitted)
        2. Link to a separate corpus by body_hash
        3. Store email text in a privacy-consented training corpus

        Currently returns None because we don't have the text.
        """
        # We don't have email body text - only hash
        # Cannot create a valid training sample
        return None

    def _calculate_label_distribution(self, samples: list[dict]) -> dict[str, int]:
        """Calculate distribution of labels in the dataset."""
        distribution = {}

        for sample in samples:
            # Try common label column names
            label = sample.get("label") or sample.get("classification") or sample.get("class")
            if label:
                distribution[label] = distribution.get(label, 0) + 1

        return distribution

    def _write_combined_data(self, samples: list[dict], output_path: Path) -> None:
        """Write combined samples to CSV."""
        if not samples:
            return

        # Get all unique fieldnames
        fieldnames = set()
        for sample in samples:
            fieldnames.update(sample.keys())
        fieldnames = sorted(fieldnames)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(samples)

    def get_original_data_info(self) -> dict[str, Any]:
        """Get information about the original training data."""
        if not self.original_data_path:
            return {
                "exists": False,
                "path": None,
                "message": "Original training data path not configured",
            }

        if not self.original_data_path.exists():
            return {
                "exists": False,
                "path": str(self.original_data_path),
                "message": "Training data file not found",
            }

        # Get basic stats
        stat = self.original_data_path.stat()

        with open(self.original_data_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            row_count = sum(1 for _ in reader)

        return {
            "exists": True,
            "path": str(self.original_data_path),
            "columns": header,
            "row_count": row_count,
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }
