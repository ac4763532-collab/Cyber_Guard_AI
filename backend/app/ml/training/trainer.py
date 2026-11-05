"""
CyberGuard AI - Model Trainer

Step 13: Train TF-IDF + LogisticRegression classifier.

Uses the SAME preprocessing pipeline as the production classifier
defined in app/ml/classifier.py to ensure consistency.
"""

import csv
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import structlog

# Import production preprocessing to ensure consistency
from app.ml.classifier import preprocess_email


logger = structlog.get_logger(__name__)


# Training configuration
DEFAULT_TFIDF_PARAMS = {
    "max_features": 10000,
    "ngram_range": (1, 2),
    "min_df": 2,
    "max_df": 0.95,
    "sublinear_tf": True,
}

DEFAULT_CLASSIFIER_PARAMS = {
    "C": 1.0,
    "max_iter": 1000,
    "class_weight": "balanced",
    "random_state": 42,
}


@dataclass
class TrainingMetrics:
    """Metrics from model evaluation."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    confusion_matrix: list[list[int]] | None = None
    classification_report: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "roc_auc": self.roc_auc,
            "confusion_matrix": self.confusion_matrix,
            "classification_report": self.classification_report,
        }


@dataclass
class TrainingReport:
    """Report from model training operation."""

    version: str
    trained_at: datetime
    train_samples: int
    validation_samples: int
    metrics: TrainingMetrics | None
    model_path: str | None
    vectorizer_path: str | None
    metadata_path: str | None
    preprocessing_version: str
    training_data_source: str
    status: str = "success"
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "trained_at": self.trained_at.isoformat(),
            "train_samples": self.train_samples,
            "validation_samples": self.validation_samples,
            "metrics": self.metrics.to_dict() if self.metrics else None,
            "model_path": self.model_path,
            "vectorizer_path": self.vectorizer_path,
            "metadata_path": self.metadata_path,
            "preprocessing_version": self.preprocessing_version,
            "training_data_source": self.training_data_source,
            "status": self.status,
            "error": self.error,
            "warnings": self.warnings,
        }


class ModelTrainer:
    """
    Train TF-IDF + LogisticRegression email classifier.

    Uses the SAME preprocessing as production (app/ml/classifier.py)
    to ensure trained models are compatible with inference.
    """

    def __init__(
        self,
        archive_dir: str | Path | None = None,
        tfidf_params: dict | None = None,
        classifier_params: dict | None = None,
    ):
        base_dir = Path(__file__).parent.parent  # app/ml

        if archive_dir:
            self.archive_dir = Path(archive_dir)
        else:
            self.archive_dir = base_dir / "models" / "archive"

        self.archive_dir.mkdir(parents=True, exist_ok=True)

        self.tfidf_params = tfidf_params or DEFAULT_TFIDF_PARAMS.copy()
        self.classifier_params = classifier_params or DEFAULT_CLASSIFIER_PARAMS.copy()

        # Track preprocessing version for compatibility checks
        self.preprocessing_version = "1.0.0"  # Matches classifier.py

    def train(
        self,
        train_data_path: str | Path,
        validation_data_path: str | Path | None = None,
        version: str | None = None,
    ) -> TrainingReport:
        """
        Train a new model version.

        Args:
            train_data_path: Path to training CSV
            validation_data_path: Path to validation CSV (optional)
            version: Version string (auto-generated if not provided)

        Returns:
            TrainingReport with results and artifact paths
        """
        warnings = []

        # Generate version if not provided
        if version is None:
            version = datetime.now(timezone.utc).strftime("v%Y%m%d_%H%M%S")

        try:
            # Import sklearn here to handle missing dependency gracefully
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.linear_model import LogisticRegression
                from sklearn.metrics import (
                    accuracy_score,
                    precision_score,
                    recall_score,
                    f1_score,
                    roc_auc_score,
                    confusion_matrix,
                    classification_report,
                )
            except ImportError as e:
                return TrainingReport(
                    version=version,
                    trained_at=datetime.now(timezone.utc),
                    train_samples=0,
                    validation_samples=0,
                    metrics=None,
                    model_path=None,
                    vectorizer_path=None,
                    metadata_path=None,
                    preprocessing_version=self.preprocessing_version,
                    training_data_source=str(train_data_path),
                    status="error",
                    error=f"Missing sklearn dependency: {e}",
                )

            # Load training data
            train_data_path = Path(train_data_path)
            if not train_data_path.exists():
                return TrainingReport(
                    version=version,
                    trained_at=datetime.now(timezone.utc),
                    train_samples=0,
                    validation_samples=0,
                    metrics=None,
                    model_path=None,
                    vectorizer_path=None,
                    metadata_path=None,
                    preprocessing_version=self.preprocessing_version,
                    training_data_source=str(train_data_path),
                    status="error",
                    error=f"Training data not found: {train_data_path}",
                )

            X_train, y_train = self._load_data(train_data_path)
            train_samples = len(X_train)

            if train_samples == 0:
                return TrainingReport(
                    version=version,
                    trained_at=datetime.now(timezone.utc),
                    train_samples=0,
                    validation_samples=0,
                    metrics=None,
                    model_path=None,
                    vectorizer_path=None,
                    metadata_path=None,
                    preprocessing_version=self.preprocessing_version,
                    training_data_source=str(train_data_path),
                    status="error",
                    error="No training samples found in data file",
                )

            logger.info("Training data loaded", samples=train_samples)

            # Load validation data if provided
            X_val, y_val = None, None
            validation_samples = 0

            if validation_data_path:
                val_path = Path(validation_data_path)
                if val_path.exists():
                    X_val, y_val = self._load_data(val_path)
                    validation_samples = len(X_val)
                    logger.info("Validation data loaded", samples=validation_samples)
                else:
                    warnings.append(f"Validation file not found: {val_path}")

            # Preprocess using SAME pipeline as production
            logger.info("Preprocessing training data...")
            X_train_processed = [self._preprocess_sample(x) for x in X_train]

            # Train TF-IDF vectorizer
            logger.info("Training TF-IDF vectorizer...", params=self.tfidf_params)
            vectorizer = TfidfVectorizer(**self.tfidf_params)
            X_train_vectors = vectorizer.fit_transform(X_train_processed)

            # Train classifier
            logger.info("Training LogisticRegression classifier...", params=self.classifier_params)
            classifier = LogisticRegression(**self.classifier_params)
            classifier.fit(X_train_vectors, y_train)

            # Evaluate on validation set
            metrics = None
            if X_val is not None and len(X_val) > 0:
                logger.info("Evaluating on validation set...")
                X_val_processed = [self._preprocess_sample(x) for x in X_val]
                X_val_vectors = vectorizer.transform(X_val_processed)

                y_pred = classifier.predict(X_val_vectors)
                y_proba = classifier.predict_proba(X_val_vectors)[:, 1]

                metrics = TrainingMetrics(
                    accuracy=float(accuracy_score(y_val, y_pred)),
                    precision=float(precision_score(y_val, y_pred, average="binary", zero_division=0)),
                    recall=float(recall_score(y_val, y_pred, average="binary", zero_division=0)),
                    f1_score=float(f1_score(y_val, y_pred, average="binary", zero_division=0)),
                    roc_auc=float(roc_auc_score(y_val, y_proba)),
                    confusion_matrix=confusion_matrix(y_val, y_pred).tolist(),
                    classification_report=classification_report(y_val, y_pred, output_dict=True),
                )

                logger.info(
                    "Validation metrics",
                    accuracy=metrics.accuracy,
                    f1=metrics.f1_score,
                    roc_auc=metrics.roc_auc,
                )

            # Save artifacts
            version_dir = self.archive_dir / version
            version_dir.mkdir(parents=True, exist_ok=True)

            classifier_path = version_dir / f"classifier_{version}.joblib"
            vectorizer_path = version_dir / f"vectorizer_{version}.joblib"
            metadata_path = version_dir / f"metadata_{version}.json"

            joblib.dump(classifier, classifier_path)
            joblib.dump(vectorizer, vectorizer_path)

            # Save metadata
            metadata = {
                "version": version,
                "trained_at": datetime.now(timezone.utc).isoformat(),
                "train_samples": train_samples,
                "validation_samples": validation_samples,
                "metrics": metrics.to_dict() if metrics else None,
                "classifier_path": str(classifier_path),
                "vectorizer_path": str(vectorizer_path),
                "preprocessing_version": self.preprocessing_version,
                "training_data_source": str(train_data_path),
                "tfidf_params": self.tfidf_params,
                "classifier_params": {k: v for k, v in self.classifier_params.items() if k != "random_state"},
                "classifier_hash": self._file_hash(classifier_path),
                "vectorizer_hash": self._file_hash(vectorizer_path),
            }

            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            logger.info(
                "Model trained and saved",
                version=version,
                classifier=str(classifier_path),
                vectorizer=str(vectorizer_path),
            )

            return TrainingReport(
                version=version,
                trained_at=datetime.now(timezone.utc),
                train_samples=train_samples,
                validation_samples=validation_samples,
                metrics=metrics,
                model_path=str(classifier_path),
                vectorizer_path=str(vectorizer_path),
                metadata_path=str(metadata_path),
                preprocessing_version=self.preprocessing_version,
                training_data_source=str(train_data_path),
                status="success",
                warnings=warnings,
            )

        except Exception as e:
            logger.error("Model training failed", error=str(e))
            return TrainingReport(
                version=version,
                trained_at=datetime.now(timezone.utc),
                train_samples=0,
                validation_samples=0,
                metrics=None,
                model_path=None,
                vectorizer_path=None,
                metadata_path=None,
                preprocessing_version=self.preprocessing_version,
                training_data_source=str(train_data_path),
                status="error",
                error=str(e),
                warnings=warnings,
            )

    def _load_data(self, data_path: Path) -> tuple[list[dict], list[int]]:
        """
        Load training data from CSV.

        Expected format: columns including text content and label.
        Supports multiple column name conventions.
        """
        X = []
        y = []

        with open(data_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Extract text features
                sample = {
                    "sender": row.get("sender", row.get("from", "")),
                    "subject": row.get("subject", ""),
                    "body": row.get("body", row.get("text", row.get("content", ""))),
                }

                # Extract label (convert to binary: 1=malicious, 0=benign)
                label_str = row.get("label", row.get("class", row.get("classification", ""))).lower()

                if label_str in ("1", "malicious", "phishing", "spam", "true"):
                    label = 1
                elif label_str in ("0", "benign", "safe", "ham", "false"):
                    label = 0
                else:
                    # Skip rows with invalid labels
                    continue

                X.append(sample)
                y.append(label)

        return X, y

    def _preprocess_sample(self, sample: dict) -> str:
        """
        Preprocess a sample using the SAME pipeline as production.

        This ensures trained models are compatible with inference.
        Uses preprocess_email from app/ml/classifier.py.
        """
        return preprocess_email(
            sender=sample.get("sender", ""),
            subject=sample.get("subject", ""),
            body=sample.get("body", ""),
        )

    def _file_hash(self, path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def list_archived_versions(self) -> list[dict[str, Any]]:
        """List all archived model versions."""
        versions = []

        for version_dir in self.archive_dir.iterdir():
            if not version_dir.is_dir():
                continue

            metadata_files = list(version_dir.glob("metadata_*.json"))
            if not metadata_files:
                continue

            metadata_path = metadata_files[0]
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                    versions.append({
                        "version": metadata.get("version", version_dir.name),
                        "trained_at": metadata.get("trained_at"),
                        "train_samples": metadata.get("train_samples"),
                        "metrics": metadata.get("metrics"),
                        "path": str(version_dir),
                    })
            except Exception:
                continue

        return sorted(versions, key=lambda x: x.get("trained_at", ""), reverse=True)
