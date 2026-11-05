"""
CyberGuard AI - ML Training Module

Step 13: Continuous Learning Pipeline

Provides:
- Feedback export for training review
- Training data combination
- Model training with TF-IDF + LogisticRegression
- Model version management
- Safe deployment with rollback
"""

from app.ml.training.feedback_exporter import FeedbackExporter, ExportReport
from app.ml.training.data_combiner import DataCombiner, CombineReport
from app.ml.training.trainer import ModelTrainer, TrainingReport
from app.ml.training.model_manager import ModelManager, ModelVersion
from app.ml.training.pipeline import (
    run_retraining_pipeline,
    PipelineResult,
    PipelineStatus,
)

__all__ = [
    "FeedbackExporter",
    "ExportReport",
    "DataCombiner",
    "CombineReport",
    "ModelTrainer",
    "TrainingReport",
    "ModelManager",
    "ModelVersion",
    "run_retraining_pipeline",
    "PipelineResult",
    "PipelineStatus",
]
