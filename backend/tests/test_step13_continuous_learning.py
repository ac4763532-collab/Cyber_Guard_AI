"""
CyberGuard AI - Step 13 Continuous Learning Pipeline Tests

Tests for:
- Feedback Exporter
- Training Data Combiner
- Model Trainer
- Model Manager
- Retraining Pipeline
- Admin Training API
"""

import csv
import json
import pytest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def temp_dirs():
    """Create temporary directories for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        dirs = {
            "export_dir": base / "exports",
            "models_dir": base / "models",
            "archive_dir": base / "models" / "archive",
            "combined_dir": base / "combined",
            "data_dir": base / "data",
        }
        for d in dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        yield dirs


@pytest.fixture
def sample_training_csv(temp_dirs):
    """Create sample training data CSV."""
    train_path = temp_dirs["data_dir"] / "train.csv"

    with open(train_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sender", "subject", "body", "label"])
        writer.writeheader()

        # Benign samples
        for i in range(50):
            writer.writerow({
                "sender": f"colleague{i}@company.com",
                "subject": f"Meeting update {i}",
                "body": f"Hi, the meeting has been rescheduled to next week. Thanks.",
                "label": "benign",
            })

        # Malicious samples
        for i in range(50):
            writer.writerow({
                "sender": f"security{i}@bankofamerica-secure.fake.com",
                "subject": "URGENT: Your account has been compromised",
                "body": "Click here immediately to verify your account: http://malicious-link.com/login",
                "label": "malicious",
            })

    return train_path


@pytest.fixture
def sample_validation_csv(temp_dirs):
    """Create sample validation data CSV."""
    val_path = temp_dirs["data_dir"] / "validation.csv"

    with open(val_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sender", "subject", "body", "label"])
        writer.writeheader()

        # Benign
        for i in range(10):
            writer.writerow({
                "sender": f"hr{i}@company.com",
                "subject": f"Policy update {i}",
                "body": "Please review the updated policy document.",
                "label": "benign",
            })

        # Malicious
        for i in range(10):
            writer.writerow({
                "sender": f"admin{i}@paypal-verify.fake.com",
                "subject": "Action Required: Verify your account",
                "body": "Your account will be suspended unless you verify: http://phishing.com",
                "label": "malicious",
            })

    return val_path


@pytest.fixture
def mock_feedback_items():
    """Create mock feedback items."""
    items = []
    for i in range(5):
        item = MagicMock()
        item.id = f"feedback-{i}"
        item.analysis_id = f"analysis-{i}"
        item.feedback_type = MagicMock(value="false_positive" if i % 2 == 0 else "false_negative")
        item.original_classification = "malicious" if i % 2 == 0 else "benign"
        item.correct_classification = "benign" if i % 2 == 0 else "malicious"
        item.original_risk_score = 0.8
        item.email_sender = f"test{i}@example.com"
        item.email_subject = f"Test subject {i}"
        item.email_body_hash = f"sha256_hash_{i}"  # Only hash, no body!
        item.user_comment = f"Comment {i}"
        item.submitted_by = "analyst"
        item.submitted_at = datetime.now(timezone.utc)
        item.reviewed_by = "admin"
        item.reviewed_at = datetime.now(timezone.utc)
        items.append(item)
    return items


# ============================================================================
# Feedback Exporter Tests
# ============================================================================


class TestFeedbackExporter:
    """Tests for FeedbackExporter."""

    @pytest.mark.asyncio
    async def test_export_no_feedback(self, temp_dirs):
        """Test export when no feedback available."""
        from app.ml.training.feedback_exporter import FeedbackExporter

        with patch("app.ml.training.feedback_exporter.get_feedback_repository") as mock_repo:
            mock_repo.return_value.get_approved_for_training = AsyncMock(return_value=[])

            exporter = FeedbackExporter(export_dir=temp_dirs["export_dir"])
            report = await exporter.export_approved_feedback()

            assert report.status == "no_feedback"
            assert report.exported_count == 0
            assert report.export_path is None

    @pytest.mark.asyncio
    async def test_export_metadata_only_feedback(self, temp_dirs, mock_feedback_items):
        """Test that feedback is correctly reported as metadata-only."""
        from app.ml.training.feedback_exporter import FeedbackExporter

        with patch("app.ml.training.feedback_exporter.get_feedback_repository") as mock_repo:
            mock_repo.return_value.get_approved_for_training = AsyncMock(return_value=mock_feedback_items)
            mock_repo.return_value.mark_as_trained = AsyncMock()

            exporter = FeedbackExporter(export_dir=temp_dirs["export_dir"])
            report = await exporter.export_approved_feedback()

            assert report.status == "success"
            assert report.exported_count == 5

            # Critical: ALL feedback should be metadata-only (Step 12 privacy)
            assert report.metadata_only_count == 5
            assert report.usable_for_training == 0

            # Verify CSV was written
            assert report.export_path is not None
            assert Path(report.export_path).exists()

    @pytest.mark.asyncio
    async def test_export_csv_content(self, temp_dirs, mock_feedback_items):
        """Test exported CSV has correct structure."""
        from app.ml.training.feedback_exporter import FeedbackExporter

        with patch("app.ml.training.feedback_exporter.get_feedback_repository") as mock_repo:
            mock_repo.return_value.get_approved_for_training = AsyncMock(return_value=mock_feedback_items)
            mock_repo.return_value.mark_as_trained = AsyncMock()

            exporter = FeedbackExporter(export_dir=temp_dirs["export_dir"])
            report = await exporter.export_approved_feedback()

            # Read and verify CSV
            with open(report.export_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 5
            assert "email_body_hash" in rows[0]
            assert "has_usable_training_content" in rows[0]

            # All should be marked as not usable for training
            for row in rows:
                assert row["has_usable_training_content"] == "false"

    def test_list_exported_batches(self, temp_dirs):
        """Test listing exported batches."""
        from app.ml.training.feedback_exporter import FeedbackExporter

        # Create some batch files
        (temp_dirs["export_dir"] / "batch_20240101_120000_abc123.csv").write_text("header\ndata")
        (temp_dirs["export_dir"] / "batch_20240102_120000_def456.csv").write_text("header\ndata")

        exporter = FeedbackExporter(export_dir=temp_dirs["export_dir"])
        batches = exporter.list_exported_batches()

        assert len(batches) == 2
        assert all("batch_id" in b for b in batches)


# ============================================================================
# Data Combiner Tests
# ============================================================================


class TestDataCombiner:
    """Tests for DataCombiner."""

    def test_combine_with_original_only(self, temp_dirs, sample_training_csv):
        """Test combining with only original data (no feedback)."""
        from app.ml.training.data_combiner import DataCombiner

        combiner = DataCombiner(
            original_data_path=sample_training_csv,
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        report = combiner.combine()

        assert report.status == "success"
        assert report.original_samples == 100
        assert report.feedback_batches_found == 0
        assert report.total_samples == 100
        assert report.output_file is not None

    def test_combine_reports_metadata_only(self, temp_dirs, sample_training_csv):
        """Test that combiner reports metadata-only feedback correctly."""
        from app.ml.training.data_combiner import DataCombiner

        # Create a feedback batch with metadata-only items
        batch_path = temp_dirs["export_dir"] / "batch_test.csv"
        with open(batch_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "feedback_id", "email_sender", "email_subject",
                "email_body_hash", "has_usable_training_content",
                "correct_classification",
            ])
            writer.writeheader()
            for i in range(3):
                writer.writerow({
                    "feedback_id": f"fb-{i}",
                    "email_sender": f"test{i}@example.com",
                    "email_subject": f"Subject {i}",
                    "email_body_hash": f"hash_{i}",
                    "has_usable_training_content": "false",  # Metadata only!
                    "correct_classification": "benign",
                })

        combiner = DataCombiner(
            original_data_path=sample_training_csv,
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        report = combiner.combine()

        assert report.feedback_batches_found == 1
        assert report.total_feedback_items == 3
        assert report.usable_feedback_samples == 0  # None usable!
        assert report.skipped_feedback_samples == 3
        assert report.total_samples == 100  # Only original data

    def test_combine_no_original_data(self, temp_dirs):
        """Test combining when original data doesn't exist."""
        from app.ml.training.data_combiner import DataCombiner

        combiner = DataCombiner(
            original_data_path=temp_dirs["data_dir"] / "nonexistent.csv",
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        report = combiner.combine()

        assert report.original_samples == 0
        assert len(report.warnings) > 0

    def test_get_original_data_info(self, temp_dirs, sample_training_csv):
        """Test getting info about original training data."""
        from app.ml.training.data_combiner import DataCombiner

        combiner = DataCombiner(
            original_data_path=sample_training_csv,
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        info = combiner.get_original_data_info()

        assert info["exists"] is True
        assert info["row_count"] == 100
        assert "sender" in info["columns"]


# ============================================================================
# Model Trainer Tests
# ============================================================================


class TestModelTrainer:
    """Tests for ModelTrainer."""

    def test_train_basic(self, temp_dirs, sample_training_csv, sample_validation_csv):
        """Test basic model training."""
        from app.ml.training.trainer import ModelTrainer

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])

        report = trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
            version="test_v1",
        )

        assert report.status == "success"
        assert report.version == "test_v1"
        assert report.train_samples == 100
        assert report.validation_samples == 20
        assert report.metrics is not None
        assert report.model_path is not None
        assert Path(report.model_path).exists()

    def test_train_with_metrics(self, temp_dirs, sample_training_csv, sample_validation_csv):
        """Test that training produces valid metrics."""
        from app.ml.training.trainer import ModelTrainer

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])

        report = trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
        )

        assert report.metrics is not None
        assert 0 <= report.metrics.accuracy <= 1
        assert 0 <= report.metrics.precision <= 1
        assert 0 <= report.metrics.recall <= 1
        assert 0 <= report.metrics.f1_score <= 1
        assert 0 <= report.metrics.roc_auc <= 1
        assert report.metrics.confusion_matrix is not None

    def test_train_missing_file(self, temp_dirs):
        """Test training with missing data file."""
        from app.ml.training.trainer import ModelTrainer

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])

        report = trainer.train(
            train_data_path="/nonexistent/path.csv",
        )

        assert report.status == "error"
        assert "not found" in report.error.lower()

    def test_train_empty_data(self, temp_dirs):
        """Test training with empty data file."""
        from app.ml.training.trainer import ModelTrainer

        # Create empty CSV
        empty_csv = temp_dirs["data_dir"] / "empty.csv"
        with open(empty_csv, "w", encoding="utf-8") as f:
            f.write("sender,subject,body,label\n")  # Header only

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        report = trainer.train(train_data_path=empty_csv)

        assert report.status == "error"
        assert "no training samples" in report.error.lower()

    def test_train_generates_metadata(self, temp_dirs, sample_training_csv):
        """Test that training generates metadata file."""
        from app.ml.training.trainer import ModelTrainer

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        report = trainer.train(train_data_path=sample_training_csv, version="test_meta")

        assert report.metadata_path is not None
        assert Path(report.metadata_path).exists()

        with open(report.metadata_path, "r") as f:
            metadata = json.load(f)

        assert metadata["version"] == "test_meta"
        assert metadata["train_samples"] == 100
        assert "preprocessing_version" in metadata

    def test_list_archived_versions(self, temp_dirs, sample_training_csv):
        """Test listing archived model versions."""
        from app.ml.training.trainer import ModelTrainer

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])

        # Train multiple versions
        trainer.train(train_data_path=sample_training_csv, version="v1")
        trainer.train(train_data_path=sample_training_csv, version="v2")

        versions = trainer.list_archived_versions()

        assert len(versions) == 2
        assert any(v["version"] == "v1" for v in versions)
        assert any(v["version"] == "v2" for v in versions)


# ============================================================================
# Model Manager Tests
# ============================================================================


class TestModelManager:
    """Tests for ModelManager."""

    def test_deploy_model(self, temp_dirs, sample_training_csv):
        """Test deploying a trained model."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        # First train a model
        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        train_report = trainer.train(train_data_path=sample_training_csv, version="deploy_test")

        # Deploy it
        manager = ModelManager(models_dir=temp_dirs["models_dir"])
        result = manager.deploy("deploy_test")

        assert result.success is True
        assert result.version == "deploy_test"
        assert manager.get_current_version() == "deploy_test"

    def test_deploy_nonexistent_version(self, temp_dirs):
        """Test deploying a nonexistent version."""
        from app.ml.training.model_manager import ModelManager

        manager = ModelManager(models_dir=temp_dirs["models_dir"])
        result = manager.deploy("nonexistent_v999")

        assert result.success is False
        assert "not found" in result.message.lower()

    def test_rollback(self, temp_dirs, sample_training_csv):
        """Test rolling back to previous version."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        manager = ModelManager(models_dir=temp_dirs["models_dir"])

        # Train and deploy v1
        trainer.train(train_data_path=sample_training_csv, version="v1")
        manager.deploy("v1")

        # Train and deploy v2
        trainer.train(train_data_path=sample_training_csv, version="v2")
        manager.deploy("v2")

        assert manager.get_current_version() == "v2"
        assert manager.get_previous_version() == "v1"

        # Rollback
        result = manager.rollback()

        assert result.success is True
        assert manager.get_current_version() == "v1"

    def test_rollback_no_previous(self, temp_dirs):
        """Test rollback when no previous version exists."""
        from app.ml.training.model_manager import ModelManager

        manager = ModelManager(models_dir=temp_dirs["models_dir"])
        result = manager.rollback()

        assert result.success is False
        assert "no previous version" in result.message.lower()

    def test_compare_versions(self, temp_dirs, sample_training_csv, sample_validation_csv):
        """Test comparing model versions."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        manager = ModelManager(models_dir=temp_dirs["models_dir"])

        # Train two versions
        trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
            version="compare_v1",
        )
        trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
            version="compare_v2",
        )

        comparison = manager.compare_versions("compare_v1", "compare_v2")

        assert "error" not in comparison
        assert comparison["version_a"] == "compare_v1"
        assert comparison["version_b"] == "compare_v2"
        assert "metrics_comparison" in comparison
        assert "recommendation" in comparison

    def test_list_versions(self, temp_dirs, sample_training_csv):
        """Test listing model versions."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        manager = ModelManager(models_dir=temp_dirs["models_dir"])

        trainer.train(train_data_path=sample_training_csv, version="list_v1")
        trainer.train(train_data_path=sample_training_csv, version="list_v2")

        versions = manager.list_versions()

        assert len(versions) == 2

    def test_deployment_history(self, temp_dirs, sample_training_csv):
        """Test deployment history tracking."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        manager = ModelManager(models_dir=temp_dirs["models_dir"])

        trainer.train(train_data_path=sample_training_csv, version="hist_v1")
        manager.deploy("hist_v1")

        trainer.train(train_data_path=sample_training_csv, version="hist_v2")
        manager.deploy("hist_v2")

        history = manager.get_deployment_history()

        assert len(history) >= 2
        assert history[0]["action"] == "deploy"


# ============================================================================
# Pipeline Tests
# ============================================================================


class TestRetrainingPipeline:
    """Tests for the full retraining pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_no_data(self, temp_dirs):
        """Test pipeline with no training data."""
        from app.ml.training.pipeline import run_retraining_pipeline, PipelineStatus

        with patch("app.ml.training.pipeline.FeedbackExporter") as MockExporter:
            mock_exporter = MockExporter.return_value
            mock_exporter.export_approved_feedback = AsyncMock(return_value=MagicMock(
                status="no_feedback",
                exported_count=0,
                metadata_only_count=0,
                usable_for_training=0,
            ))

            with patch("app.ml.training.pipeline.DataCombiner") as MockCombiner:
                mock_combiner = MockCombiner.return_value
                mock_combiner.combine.return_value = MagicMock(
                    status="no_data",
                    total_samples=0,
                    warnings=[],
                    error=None,
                )

                result = await run_retraining_pipeline()

                assert result.status == PipelineStatus.NO_DATA

    @pytest.mark.asyncio
    async def test_pipeline_reports_metadata_only_warning(self, temp_dirs, sample_training_csv):
        """Test that pipeline reports metadata-only feedback limitation."""
        from app.ml.training.pipeline import run_retraining_pipeline

        with patch("app.ml.training.pipeline.FeedbackExporter") as MockExporter:
            mock_exporter = MockExporter.return_value
            mock_exporter.export_approved_feedback = AsyncMock(return_value=MagicMock(
                status="success",
                exported_count=10,
                metadata_only_count=10,  # ALL metadata-only
                usable_for_training=0,   # NONE usable
                error=None,
            ))

            with patch("app.ml.training.pipeline.DataCombiner") as MockCombiner:
                mock_combiner = MockCombiner.return_value
                mock_combiner.combine.return_value = MagicMock(
                    status="success",
                    total_samples=100,
                    output_file=str(sample_training_csv),
                    warnings=[],
                    error=None,
                )

                with patch("app.ml.training.pipeline.ModelTrainer") as MockTrainer:
                    mock_trainer = MockTrainer.return_value
                    mock_trainer.train.return_value = MagicMock(
                        status="success",
                        version="test_v1",
                        train_samples=100,
                        metrics=None,
                        warnings=[],
                        error=None,
                    )

                    with patch("app.ml.training.pipeline.ModelManager"):
                        result = await run_retraining_pipeline(export_feedback=True)

                        # Should have warning about metadata-only feedback
                        assert any("metadata-only" in w for w in result.warnings)


# ============================================================================
# API Tests
# ============================================================================


class TestTrainingAPI:
    """Tests for Admin Training API endpoints."""

    def test_api_module_imports(self):
        """Test that training API module imports correctly."""
        from app.api.v1 import training

        assert hasattr(training, "router")
        assert hasattr(training, "list_models")
        assert hasattr(training, "deploy_model")
        assert hasattr(training, "rollback_model")
        assert hasattr(training, "compare_models")
        assert hasattr(training, "trigger_retraining")

    def test_router_registered(self):
        """Test that training router is registered."""
        from app.api.v1 import training

        # Check that training router has routes
        assert len(training.router.routes) > 0

        # Check expected endpoint paths exist
        route_paths = [r.path for r in training.router.routes if hasattr(r, 'path')]
        assert "/models" in route_paths or any("/models" in p for p in route_paths)

    def test_request_models_defined(self):
        """Test that request/response models are defined."""
        from app.api.v1.training import (
            TrainModelRequest,
            DeployModelRequest,
            RunPipelineRequest,
            CompareModelsRequest,
            ModelVersionResponse,
            DeploymentResponse,
        )

        # Verify models can be instantiated
        deploy_req = DeployModelRequest(version="v1")
        assert deploy_req.version == "v1"

        pipeline_req = RunPipelineRequest()
        assert pipeline_req.auto_deploy is False
        assert pipeline_req.min_samples == 100

        compare_req = CompareModelsRequest(version_a="v1", version_b="v2")
        assert compare_req.version_a == "v1"


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    """Integration tests for the full training workflow."""

    def test_full_training_workflow(self, temp_dirs, sample_training_csv, sample_validation_csv):
        """Test complete training workflow without mocks."""
        from app.ml.training.trainer import ModelTrainer
        from app.ml.training.model_manager import ModelManager

        # Initialize components
        trainer = ModelTrainer(archive_dir=temp_dirs["archive_dir"])
        manager = ModelManager(models_dir=temp_dirs["models_dir"])

        # Train model v1
        report_v1 = trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
            version="integration_v1",
        )
        assert report_v1.status == "success"

        # Deploy v1
        deploy_v1 = manager.deploy("integration_v1")
        assert deploy_v1.success is True
        assert manager.get_current_version() == "integration_v1"

        # Train model v2
        report_v2 = trainer.train(
            train_data_path=sample_training_csv,
            validation_data_path=sample_validation_csv,
            version="integration_v2",
        )
        assert report_v2.status == "success"

        # Compare versions
        comparison = manager.compare_versions("integration_v1", "integration_v2")
        assert "error" not in comparison

        # Deploy v2
        deploy_v2 = manager.deploy("integration_v2")
        assert deploy_v2.success is True
        assert manager.get_current_version() == "integration_v2"
        assert deploy_v2.rollback_available is True

        # Rollback to v1
        rollback = manager.rollback()
        assert rollback.success is True
        assert manager.get_current_version() == "integration_v1"


# ============================================================================
# Privacy Constraint Tests
# ============================================================================


class TestPrivacyConstraints:
    """
    Tests verifying the privacy constraint from Step 12.

    Step 12 intentionally does NOT store email body content.
    Only email_body_hash is stored.
    These tests ensure the training pipeline handles this correctly.
    """

    def test_exporter_reports_all_as_metadata_only(self):
        """Verify exporter marks all feedback as metadata-only."""
        from app.ml.training.feedback_exporter import FeedbackExporter

        exporter = FeedbackExporter()

        # The _has_usable_training_content method should always return False
        mock_item = MagicMock()
        mock_item.email_body_hash = "some_hash"

        result = exporter._has_usable_training_content(mock_item)
        assert result is False, "Feedback should be metadata-only per Step 12 design"

    def test_combiner_skips_metadata_only_feedback(self, temp_dirs, sample_training_csv):
        """Verify combiner doesn't add metadata-only feedback to training."""
        from app.ml.training.data_combiner import DataCombiner

        # Create feedback batch with metadata-only items
        batch_path = temp_dirs["export_dir"] / "batch_privacy.csv"
        with open(batch_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "feedback_id", "email_sender", "email_subject",
                "email_body_hash", "has_usable_training_content",
            ])
            writer.writeheader()
            writer.writerow({
                "feedback_id": "fb-1",
                "email_sender": "test@example.com",
                "email_subject": "Test",
                "email_body_hash": "hash_value",
                "has_usable_training_content": "false",
            })

        combiner = DataCombiner(
            original_data_path=sample_training_csv,
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        report = combiner.combine()

        # All feedback should be skipped
        assert report.usable_feedback_samples == 0
        assert report.skipped_feedback_samples == 1
        # Total should equal original only
        assert report.total_samples == report.original_samples

    def test_feedback_to_training_sample_returns_none(self, temp_dirs):
        """Verify _feedback_to_training_sample returns None (can't recover text)."""
        from app.ml.training.data_combiner import DataCombiner

        combiner = DataCombiner(
            original_data_path=temp_dirs["data_dir"] / "dummy.csv",
            feedback_dir=temp_dirs["export_dir"],
            output_dir=temp_dirs["combined_dir"],
        )

        feedback_row = {
            "feedback_id": "fb-1",
            "email_sender": "test@example.com",
            "email_subject": "Test Subject",
            "email_body_hash": "sha256_hash_value",  # Only hash, no body!
            "correct_classification": "benign",
        }

        result = combiner._feedback_to_training_sample(feedback_row)
        assert result is None, "Cannot create training sample without email body text"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
