"""
CyberGuard AI - Retraining Pipeline

Step 13: Full retraining pipeline with safety checks.

Orchestrates the complete retraining workflow:
1. Export approved feedback
2. Combine with original training data
3. Train new model version
4. Evaluate against current production
5. Deploy with rollback safety
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from app.ml.training.feedback_exporter import FeedbackExporter, ExportReport
from app.ml.training.data_combiner import DataCombiner, CombineReport
from app.ml.training.trainer import ModelTrainer, TrainingReport
from app.ml.training.model_manager import ModelManager, DeploymentResult


logger = structlog.get_logger(__name__)


class PipelineStatus(enum.Enum):
    """Status of pipeline execution."""

    SUCCESS = "success"
    PARTIAL = "partial"  # Some steps completed, but not all
    FAILED = "failed"
    NO_DATA = "no_data"  # No training data available
    SKIPPED = "skipped"  # Pipeline skipped due to conditions


@dataclass
class PipelineResult:
    """Result of retraining pipeline execution."""

    status: PipelineStatus
    started_at: datetime
    completed_at: datetime | None
    steps_completed: list[str]
    steps_failed: list[str]
    export_report: ExportReport | None = None
    combine_report: CombineReport | None = None
    training_report: TrainingReport | None = None
    deployment_result: DeploymentResult | None = None
    comparison: dict | None = None
    message: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "export_report": self.export_report.to_dict() if self.export_report else None,
            "combine_report": self.combine_report.to_dict() if self.combine_report else None,
            "training_report": self.training_report.to_dict() if self.training_report else None,
            "deployment_result": self.deployment_result.to_dict() if self.deployment_result else None,
            "comparison": self.comparison,
            "message": self.message,
            "warnings": self.warnings,
        }


async def run_retraining_pipeline(
    auto_deploy: bool = False,
    min_samples: int = 100,
    min_f1_improvement: float = -0.02,  # Allow slight regression
    export_feedback: bool = True,
    validation_split: float = 0.2,
    version: str | None = None,
) -> PipelineResult:
    """
    Run the complete retraining pipeline.

    Pipeline steps:
    1. Export approved feedback (if enabled and available)
    2. Combine training data (original + feedback)
    3. Train new model version
    4. Compare with current production (if metrics available)
    5. Deploy if auto_deploy=True and safety checks pass

    Args:
        auto_deploy: Automatically deploy if model passes safety checks
        min_samples: Minimum training samples required
        min_f1_improvement: Minimum F1 improvement required for auto-deploy
                           (negative allows small regression)
        export_feedback: Whether to export new feedback
        validation_split: Fraction of data for validation
        version: Optional version string

    Returns:
        PipelineResult with all step results

    IMPORTANT NOTE ON FEEDBACK:
    Step 12 stores only email_body_hash, not actual email body content.
    Therefore, feedback items are metadata-only and cannot be directly
    used as training samples for text classification. The pipeline
    will report this limitation transparently.
    """
    started_at = datetime.now(timezone.utc)
    steps_completed = []
    steps_failed = []
    warnings = []

    export_report = None
    combine_report = None
    training_report = None
    deployment_result = None
    comparison = None

    try:
        # Initialize components
        exporter = FeedbackExporter()
        combiner = DataCombiner()
        trainer = ModelTrainer()
        manager = ModelManager()

        # Step 1: Export approved feedback
        if export_feedback:
            logger.info("Step 1: Exporting approved feedback...")
            export_report = await exporter.export_approved_feedback(
                limit=5000,
                mark_as_exported=True,
            )

            if export_report.status == "error":
                steps_failed.append("export_feedback")
                warnings.append(f"Feedback export failed: {export_report.error}")
            else:
                steps_completed.append("export_feedback")

                # Report the privacy limitation
                if export_report.metadata_only_count > 0 and export_report.usable_for_training == 0:
                    warnings.append(
                        f"Exported {export_report.exported_count} feedback items, but all are "
                        "metadata-only (Step 12 stores only email_body_hash). "
                        "Feedback cannot be directly used for text classifier training."
                    )

        # Step 2: Combine training data
        logger.info("Step 2: Combining training data...")
        combine_report = combiner.combine()

        if combine_report.status == "error":
            steps_failed.append("combine_data")
            return PipelineResult(
                status=PipelineStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                export_report=export_report,
                combine_report=combine_report,
                message=f"Data combination failed: {combine_report.error}",
                warnings=warnings + combine_report.warnings,
            )

        if combine_report.total_samples == 0:
            return PipelineResult(
                status=PipelineStatus.NO_DATA,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                steps_completed=steps_completed,
                steps_failed=["combine_data"],
                export_report=export_report,
                combine_report=combine_report,
                message="No training data available",
                warnings=warnings + combine_report.warnings,
            )

        steps_completed.append("combine_data")
        warnings.extend(combine_report.warnings)

        # Check minimum samples
        if combine_report.total_samples < min_samples:
            warnings.append(
                f"Training samples ({combine_report.total_samples}) below minimum ({min_samples}). "
                "Proceeding with training, but results may be unreliable."
            )

        # Step 3: Train new model
        logger.info("Step 3: Training new model...", samples=combine_report.total_samples)

        if not combine_report.output_file:
            steps_failed.append("train_model")
            return PipelineResult(
                status=PipelineStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                export_report=export_report,
                combine_report=combine_report,
                message="No combined data file available for training",
                warnings=warnings,
            )

        training_report = trainer.train(
            train_data_path=combine_report.output_file,
            version=version,
        )

        if training_report.status == "error":
            steps_failed.append("train_model")
            return PipelineResult(
                status=PipelineStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                steps_completed=steps_completed,
                steps_failed=steps_failed,
                export_report=export_report,
                combine_report=combine_report,
                training_report=training_report,
                message=f"Training failed: {training_report.error}",
                warnings=warnings + training_report.warnings,
            )

        steps_completed.append("train_model")
        warnings.extend(training_report.warnings)

        logger.info(
            "Model trained successfully",
            version=training_report.version,
            samples=training_report.train_samples,
        )

        # Step 4: Compare with current production
        current_version = manager.get_current_version()
        if current_version and training_report.metrics:
            logger.info("Step 4: Comparing with current production...")
            comparison = manager.compare_versions(
                current_version,
                training_report.version,
            )
            steps_completed.append("compare_models")

            if comparison.get("error"):
                warnings.append(f"Comparison failed: {comparison['error']}")
        else:
            warnings.append("Skipping comparison: no current version or no metrics available")

        # Step 5: Deploy (if auto_deploy and safety checks pass)
        if auto_deploy:
            logger.info("Step 5: Evaluating for auto-deployment...")

            # Safety checks
            deploy_approved = True
            deploy_reasons = []

            # Check metrics improvement
            if comparison and training_report.metrics:
                metrics_comparison = comparison.get("metrics_comparison", {})
                f1_comparison = metrics_comparison.get("f1_score", {})

                if f1_comparison:
                    f1_diff = f1_comparison.get("difference", 0)
                    if f1_diff < min_f1_improvement:
                        deploy_approved = False
                        deploy_reasons.append(
                            f"F1 score regression ({f1_diff:.4f}) exceeds threshold ({min_f1_improvement})"
                        )

            # Check minimum samples
            if training_report.train_samples < min_samples:
                deploy_approved = False
                deploy_reasons.append(
                    f"Training samples ({training_report.train_samples}) below minimum ({min_samples})"
                )

            if deploy_approved:
                deployment_result = manager.deploy(training_report.version)
                if deployment_result.success:
                    steps_completed.append("deploy_model")
                    logger.info("Model auto-deployed", version=training_report.version)
                else:
                    steps_failed.append("deploy_model")
                    warnings.append(f"Deployment failed: {deployment_result.message}")
            else:
                warnings.append(f"Auto-deploy declined: {'; '.join(deploy_reasons)}")
                logger.info("Auto-deploy declined", reasons=deploy_reasons)

        # Determine final status
        if steps_failed:
            status = PipelineStatus.PARTIAL
            message = f"Pipeline completed with failures: {', '.join(steps_failed)}"
        else:
            status = PipelineStatus.SUCCESS
            message = f"Pipeline completed successfully. Model version: {training_report.version}"

        return PipelineResult(
            status=status,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            steps_completed=steps_completed,
            steps_failed=steps_failed,
            export_report=export_report,
            combine_report=combine_report,
            training_report=training_report,
            deployment_result=deployment_result,
            comparison=comparison,
            message=message,
            warnings=warnings,
        )

    except Exception as e:
        logger.error("Pipeline failed with exception", error=str(e))
        return PipelineResult(
            status=PipelineStatus.FAILED,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            steps_completed=steps_completed,
            steps_failed=["unknown"],
            export_report=export_report,
            combine_report=combine_report,
            training_report=training_report,
            message=f"Pipeline failed: {e}",
            warnings=warnings,
        )


class RetrainingPipeline:
    """
    Class-based interface for retraining pipeline.

    Provides more control over individual steps.
    """

    def __init__(
        self,
        export_dir: str | Path | None = None,
        models_dir: str | Path | None = None,
    ):
        self.exporter = FeedbackExporter(export_dir=export_dir)
        self.combiner = DataCombiner()
        self.trainer = ModelTrainer()
        self.manager = ModelManager(models_dir=models_dir)

    async def export_feedback(self, limit: int = 1000) -> ExportReport:
        """Export approved feedback."""
        return await self.exporter.export_approved_feedback(limit=limit)

    def combine_data(self, output_filename: str | None = None) -> CombineReport:
        """Combine training data."""
        return self.combiner.combine(output_filename=output_filename)

    def train_model(
        self,
        train_data_path: str | Path,
        validation_data_path: str | Path | None = None,
        version: str | None = None,
    ) -> TrainingReport:
        """Train a new model version."""
        return self.trainer.train(
            train_data_path=train_data_path,
            validation_data_path=validation_data_path,
            version=version,
        )

    def deploy_model(self, version: str, force: bool = False) -> DeploymentResult:
        """Deploy a model version."""
        return self.manager.deploy(version=version, force=force)

    def rollback_model(self) -> DeploymentResult:
        """Rollback to previous version."""
        return self.manager.rollback()

    def compare_models(self, version_a: str, version_b: str) -> dict[str, Any]:
        """Compare two model versions."""
        return self.manager.compare_versions(version_a, version_b)

    async def run_full_pipeline(
        self,
        auto_deploy: bool = False,
        min_samples: int = 100,
    ) -> PipelineResult:
        """Run the full retraining pipeline."""
        return await run_retraining_pipeline(
            auto_deploy=auto_deploy,
            min_samples=min_samples,
        )
