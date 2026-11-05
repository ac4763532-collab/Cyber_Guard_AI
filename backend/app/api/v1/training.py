"""
CyberGuard AI - Admin Training API

Step 13: API endpoints for model training and management.

All endpoints require admin role authentication.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel, Field

import structlog

from app.auth.jwt import require_role
from app.auth.models import User, UserRole


# Admin role dependency
require_admin = require_role([UserRole.ADMIN])
from app.ml.training import (
    FeedbackExporter,
    DataCombiner,
    ModelTrainer,
    ModelManager,
    run_retraining_pipeline,
    PipelineStatus,
)
from app.ml.threshold_tuner import get_threshold_tuner


logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/training", tags=["training"])


# ============================================================================
# Request/Response Models
# ============================================================================


class TrainModelRequest(BaseModel):
    """Request to train a new model version."""

    version: str | None = Field(None, description="Version string (auto-generated if not provided)")
    train_data_path: str | None = Field(None, description="Path to training data (uses combined if not provided)")


class DeployModelRequest(BaseModel):
    """Request to deploy a model version."""

    version: str = Field(..., description="Version to deploy")
    force: bool = Field(False, description="Force deployment even if already deployed")


class RunPipelineRequest(BaseModel):
    """Request to run the full retraining pipeline."""

    auto_deploy: bool = Field(False, description="Auto-deploy if safety checks pass")
    min_samples: int = Field(100, ge=10, description="Minimum training samples required")
    min_f1_improvement: float = Field(-0.02, description="Minimum F1 improvement for auto-deploy")
    export_feedback: bool = Field(True, description="Export new feedback before training")


class CompareModelsRequest(BaseModel):
    """Request to compare two model versions."""

    version_a: str = Field(..., description="First version (typically current)")
    version_b: str = Field(..., description="Second version (typically candidate)")


class ModelVersionResponse(BaseModel):
    """Response with model version information."""

    version: str
    trained_at: str | None
    deployed_at: str | None
    is_current: bool
    train_samples: int
    metrics: dict | None
    status: str


class DeploymentResponse(BaseModel):
    """Response from deployment operation."""

    success: bool
    version: str
    previous_version: str | None
    message: str
    deployed_at: str | None
    rollback_available: bool


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/models")
async def list_models(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    List all available model versions.

    Returns archived versions and current production model info.
    """
    manager = ModelManager()
    versions = manager.list_versions()

    return {
        "current_version": manager.get_current_version(),
        "previous_version": manager.get_previous_version(),
        "versions": [v.to_dict() for v in versions],
        "total_versions": len(versions),
    }


@router.get("/models/{version}")
async def get_model_version(
    version: str,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Get details about a specific model version."""
    manager = ModelManager()
    version_info = manager.get_version(version)

    if not version_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version}' not found",
        )

    return version_info.to_dict()


@router.post("/retrain")
async def trigger_retraining(
    request: RunPipelineRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Trigger model retraining pipeline.

    Runs the full pipeline:
    1. Export approved feedback
    2. Combine with original training data
    3. Train new model version
    4. Compare with current production
    5. Deploy (if auto_deploy=True and safety checks pass)

    NOTE: Step 12 stores only email_body_hash, not actual email body.
    Therefore feedback items are metadata-only and cannot be directly
    used for text classifier training. The pipeline reports this transparently.
    """
    logger.info(
        "Retraining pipeline triggered",
        user=current_user.username,
        auto_deploy=request.auto_deploy,
    )

    # Run pipeline
    result = await run_retraining_pipeline(
        auto_deploy=request.auto_deploy,
        min_samples=request.min_samples,
        min_f1_improvement=request.min_f1_improvement,
        export_feedback=request.export_feedback,
    )

    # Map status to HTTP response
    if result.status == PipelineStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "message": result.message,
                "steps_completed": result.steps_completed,
                "steps_failed": result.steps_failed,
                "warnings": result.warnings,
            },
        )

    return result.to_dict()


@router.post("/deploy")
async def deploy_model(
    request: DeployModelRequest,
    current_user: User = Depends(require_admin),
) -> DeploymentResponse:
    """
    Deploy a specific model version to production.

    Uses atomic deployment with rollback capability.
    """
    logger.info(
        "Model deployment requested",
        user=current_user.username,
        version=request.version,
    )

    manager = ModelManager()
    result = manager.deploy(request.version, force=request.force)

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message,
        )

    return DeploymentResponse(
        success=result.success,
        version=result.version,
        previous_version=result.previous_version,
        message=result.message,
        deployed_at=result.deployed_at.isoformat() if result.deployed_at else None,
        rollback_available=result.rollback_available,
    )


@router.post("/rollback")
async def rollback_model(
    current_user: User = Depends(require_admin),
) -> DeploymentResponse:
    """
    Rollback to the previous model version.

    Only one level of rollback is supported.
    """
    logger.info(
        "Model rollback requested",
        user=current_user.username,
    )

    manager = ModelManager()
    result = manager.rollback()

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message,
        )

    return DeploymentResponse(
        success=result.success,
        version=result.version,
        previous_version=result.previous_version,
        message=result.message,
        deployed_at=result.deployed_at.isoformat() if result.deployed_at else None,
        rollback_available=result.rollback_available,
    )


@router.post("/compare")
async def compare_models(
    request: CompareModelsRequest,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Compare metrics between two model versions.

    Useful for evaluating a candidate model against current production.
    """
    manager = ModelManager()
    comparison = manager.compare_versions(request.version_a, request.version_b)

    if comparison.get("error"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=comparison["error"],
        )

    return comparison


@router.get("/history")
async def get_deployment_history(
    limit: int = 20,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Get deployment history."""
    manager = ModelManager()
    history = manager.get_deployment_history(limit=limit)

    return {
        "history": history,
        "total": len(history),
    }


@router.get("/feedback/export-batches")
async def list_feedback_export_batches(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """List all exported feedback batches."""
    exporter = FeedbackExporter()
    batches = exporter.list_exported_batches()

    return {
        "batches": batches,
        "total": len(batches),
    }


@router.post("/feedback/export")
async def export_feedback(
    limit: int = 1000,
    mark_as_exported: bool = True,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Export approved feedback for training review.

    NOTE: Step 12 stores only email_body_hash, not actual email body.
    Exported feedback is metadata-only and cannot be directly used
    as text training samples. This endpoint reports the limitation.
    """
    logger.info(
        "Feedback export requested",
        user=current_user.username,
        limit=limit,
    )

    exporter = FeedbackExporter()
    report = await exporter.export_approved_feedback(
        limit=limit,
        mark_as_exported=mark_as_exported,
    )

    return report.to_dict()


@router.get("/data/info")
async def get_training_data_info(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Get information about available training data."""
    combiner = DataCombiner()

    return {
        "original_data": combiner.get_original_data_info(),
        "export_dir": str(combiner.feedback_dir),
        "output_dir": str(combiner.output_dir),
    }


@router.post("/data/combine")
async def combine_training_data(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Combine original training data with feedback.

    NOTE: Step 12 feedback is metadata-only (no email body text),
    so feedback items cannot be directly combined with text training data.
    This endpoint reports the limitation transparently.
    """
    logger.info(
        "Data combination requested",
        user=current_user.username,
    )

    combiner = DataCombiner()
    report = combiner.combine()

    return report.to_dict()


# ============================================================================
# Threshold Tuning Endpoints
# ============================================================================


class SetThresholdRequest(BaseModel):
    """Request to manually set a threshold."""

    threshold: float = Field(..., ge=0.3, le=0.8, description="Threshold value")
    domain: str | None = Field(None, description="Domain for domain-specific threshold")
    reason: str = Field("Manual override", description="Reason for the change")


class TuneThresholdRequest(BaseModel):
    """Request to auto-tune thresholds."""

    target_fp_rate: float = Field(0.05, ge=0.0, le=0.5, description="Target false positive rate")
    target_fn_rate: float = Field(0.02, ge=0.0, le=0.5, description="Target false negative rate")
    dry_run: bool = Field(False, description="Calculate without applying")


@router.get("/threshold")
async def get_threshold_config(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Get current threshold configuration.

    Returns the feedback-tuned threshold and adjustment history.
    """
    tuner = get_threshold_tuner()
    config = tuner.get_config()

    return {
        "global_threshold": config.global_threshold,
        "domain_thresholds": config.domain_thresholds,
        "last_updated": config.last_updated.isoformat() if config.last_updated else None,
        "feedback_samples_used": config.feedback_samples_used,
        "false_positive_rate": config.false_positive_rate,
        "false_negative_rate": config.false_negative_rate,
        "adjustment_history": config.adjustment_history,
    }


@router.post("/threshold/tune")
async def tune_threshold(
    request: TuneThresholdRequest,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Auto-tune threshold based on feedback patterns.

    Analyzes false positive and false negative rates from approved feedback
    and adjusts the threshold to minimize errors.

    This is how feedback IMPROVES detection without retraining:
    - High false positives → raise threshold (less aggressive)
    - High false negatives → lower threshold (more aggressive)
    """
    logger.info(
        "Threshold tuning requested",
        user=current_user.username,
        target_fp=request.target_fp_rate,
        target_fn=request.target_fn_rate,
        dry_run=request.dry_run,
    )

    tuner = get_threshold_tuner()
    result = await tuner.tune_thresholds(
        target_fp_rate=request.target_fp_rate,
        target_fn_rate=request.target_fn_rate,
        dry_run=request.dry_run,
    )

    return result


@router.post("/threshold/set")
async def set_threshold(
    request: SetThresholdRequest,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Manually set a classification threshold.

    Use for domain-specific thresholds or manual overrides.
    """
    logger.info(
        "Manual threshold set",
        user=current_user.username,
        threshold=request.threshold,
        domain=request.domain,
    )

    tuner = get_threshold_tuner()
    result = tuner.set_threshold(
        threshold=request.threshold,
        domain=request.domain,
        reason=f"{request.reason} (by {current_user.username})",
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "Failed to set threshold"),
        )

    return result


@router.post("/threshold/reset")
async def reset_threshold(
    domain: str | None = None,
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Reset threshold to default value.

    If domain is provided, removes domain-specific threshold only.
    """
    logger.info(
        "Threshold reset requested",
        user=current_user.username,
        domain=domain,
    )

    tuner = get_threshold_tuner()
    return tuner.reset_threshold(domain=domain)


@router.get("/threshold/analyze")
async def analyze_feedback_errors(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Analyze feedback to show error rates and patterns.

    Returns false positive/negative rates without changing thresholds.
    Use this to understand classifier performance before tuning.
    """
    tuner = get_threshold_tuner()
    stats = await tuner.analyze_feedback()

    return {
        "total_feedback_samples": stats.total_samples,
        "false_positives": stats.false_positives,
        "false_negatives": stats.false_negatives,
        "wrong_category": stats.wrong_category,
        "fp_rate": round(stats.fp_rate, 4),
        "fn_rate": round(stats.fn_rate, 4),
        "by_sender_domain": stats.by_sender_domain,
        "current_threshold": tuner.get_threshold(),
    }


@router.get("/status")
async def get_training_status(
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """
    Get overall training system status.

    Includes current model, available versions, threshold config, and data status.
    """
    manager = ModelManager()
    combiner = DataCombiner()
    exporter = FeedbackExporter()
    tuner = get_threshold_tuner()

    current_version = manager.get_current_version()
    versions = manager.list_versions()
    threshold_config = tuner.get_config()

    return {
        "current_model": {
            "version": current_version,
            "rollback_available": manager.get_previous_version() is not None,
        },
        "threshold": {
            "current": threshold_config.global_threshold,
            "last_tuned": threshold_config.last_updated.isoformat() if threshold_config.last_updated else None,
            "feedback_samples": threshold_config.feedback_samples_used,
            "fp_rate": threshold_config.false_positive_rate,
            "fn_rate": threshold_config.false_negative_rate,
        },
        "available_versions": len(versions),
        "original_data": combiner.get_original_data_info(),
        "feedback_batches": len(exporter.list_exported_batches()),
        "system_ready": current_version is not None,
        "feedback_improves_detection": (
            "Feedback adjusts classification thresholds via /threshold/tune. "
            "High false positive rates raise the threshold (less aggressive), "
            "high false negative rates lower it (more aggressive)."
        ),
    }
