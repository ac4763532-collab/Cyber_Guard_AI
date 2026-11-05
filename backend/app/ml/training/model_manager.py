"""
CyberGuard AI - Model Manager

Step 13: Model versioning, deployment, and rollback.

Manages model versions with atomic deployment and safe rollback.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import structlog


logger = structlog.get_logger(__name__)


@dataclass
class ModelVersion:
    """Information about a model version."""

    version: str
    trained_at: datetime | None
    deployed_at: datetime | None
    is_current: bool
    train_samples: int
    metrics: dict | None
    classifier_path: str
    vectorizer_path: str
    metadata_path: str | None = None
    preprocessing_version: str | None = None
    status: str = "archived"  # archived, candidate, deployed, rollback

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
            "is_current": self.is_current,
            "train_samples": self.train_samples,
            "metrics": self.metrics,
            "classifier_path": self.classifier_path,
            "vectorizer_path": self.vectorizer_path,
            "metadata_path": self.metadata_path,
            "preprocessing_version": self.preprocessing_version,
            "status": self.status,
        }


@dataclass
class DeploymentResult:
    """Result of a deployment operation."""

    success: bool
    version: str
    previous_version: str | None
    message: str
    deployed_at: datetime | None = None
    rollback_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "version": self.version,
            "previous_version": self.previous_version,
            "message": self.message,
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
            "rollback_available": self.rollback_available,
        }


class ModelManager:
    """
    Manage model versions with safe deployment and rollback.

    Directory structure:
    app/ml/models/
    ├── tfidf_vectorizer.joblib     (current production)
    ├── logistic_classifier.joblib   (current production)
    ├── manifest.json                (deployment history)
    ├── archive/
    │   ├── v20240101_120000/
    │   │   ├── classifier_v20240101_120000.joblib
    │   │   ├── vectorizer_v20240101_120000.joblib
    │   │   └── metadata_v20240101_120000.json
    │   └── ...
    └── rollback/
        ├── classifier_previous.joblib
        └── vectorizer_previous.joblib
    """

    MANIFEST_FILE = "manifest.json"
    CLASSIFIER_FILE = "logistic_classifier.joblib"
    VECTORIZER_FILE = "tfidf_vectorizer.joblib"

    def __init__(self, models_dir: str | Path | None = None):
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = Path(__file__).parent.parent / "models"

        self.archive_dir = self.models_dir / "archive"
        self.rollback_dir = self.models_dir / "rollback"

        # Ensure directories exist
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        self.rollback_dir.mkdir(parents=True, exist_ok=True)

        # Load or create manifest
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        """Load deployment manifest."""
        manifest_path = self.models_dir / self.MANIFEST_FILE
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load manifest", error=str(e))

        # Create default manifest
        return {
            "current_version": None,
            "previous_version": None,
            "deployment_history": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _save_manifest(self) -> None:
        """Save deployment manifest."""
        manifest_path = self.models_dir / self.MANIFEST_FILE
        self._manifest["updated_at"] = datetime.now(timezone.utc).isoformat()

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(self._manifest, f, indent=2)

    def get_current_version(self) -> str | None:
        """Get the currently deployed model version."""
        return self._manifest.get("current_version")

    def get_previous_version(self) -> str | None:
        """Get the previous model version (for rollback)."""
        return self._manifest.get("previous_version")

    def list_versions(self) -> list[ModelVersion]:
        """List all available model versions."""
        versions = []
        current = self.get_current_version()

        for version_dir in self.archive_dir.iterdir():
            if not version_dir.is_dir():
                continue

            version_info = self._load_version_info(version_dir)
            if version_info:
                version_info.is_current = (version_info.version == current)
                versions.append(version_info)

        return sorted(versions, key=lambda v: v.trained_at or datetime.min, reverse=True)

    def get_version(self, version: str) -> ModelVersion | None:
        """Get information about a specific version."""
        version_dir = self.archive_dir / version
        if not version_dir.exists():
            return None

        version_info = self._load_version_info(version_dir)
        if version_info:
            version_info.is_current = (version == self.get_current_version())
        return version_info

    def _load_version_info(self, version_dir: Path) -> ModelVersion | None:
        """Load version information from archive directory."""
        # Find metadata file
        metadata_files = list(version_dir.glob("metadata_*.json"))
        if not metadata_files:
            # Try to construct from files present
            classifier_files = list(version_dir.glob("classifier_*.joblib"))
            vectorizer_files = list(version_dir.glob("vectorizer_*.joblib"))

            if not classifier_files or not vectorizer_files:
                return None

            version = version_dir.name
            return ModelVersion(
                version=version,
                trained_at=None,
                deployed_at=None,
                is_current=False,
                train_samples=0,
                metrics=None,
                classifier_path=str(classifier_files[0]),
                vectorizer_path=str(vectorizer_files[0]),
                status="archived",
            )

        metadata_path = metadata_files[0]
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            return ModelVersion(
                version=metadata.get("version", version_dir.name),
                trained_at=datetime.fromisoformat(metadata["trained_at"]) if metadata.get("trained_at") else None,
                deployed_at=None,
                is_current=False,
                train_samples=metadata.get("train_samples", 0),
                metrics=metadata.get("metrics"),
                classifier_path=metadata.get("classifier_path", ""),
                vectorizer_path=metadata.get("vectorizer_path", ""),
                metadata_path=str(metadata_path),
                preprocessing_version=metadata.get("preprocessing_version"),
                status="archived",
            )
        except Exception as e:
            logger.warning("Failed to load version metadata", version=version_dir.name, error=str(e))
            return None

    def deploy(self, version: str, force: bool = False) -> DeploymentResult:
        """
        Deploy a model version to production.

        Uses atomic deployment:
        1. Backup current production models to rollback/
        2. Copy new version to production location
        3. Update manifest
        4. Verify deployment

        Args:
            version: Version to deploy
            force: Skip safety checks

        Returns:
            DeploymentResult with status
        """
        # Validate version exists
        version_info = self.get_version(version)
        if not version_info:
            return DeploymentResult(
                success=False,
                version=version,
                previous_version=self.get_current_version(),
                message=f"Version '{version}' not found in archive",
            )

        # Check if already deployed
        current = self.get_current_version()
        if current == version and not force:
            return DeploymentResult(
                success=True,
                version=version,
                previous_version=current,
                message=f"Version '{version}' is already deployed",
                deployed_at=datetime.now(timezone.utc),
                rollback_available=self.get_previous_version() is not None,
            )

        try:
            # Step 1: Backup current production models
            classifier_prod = self.models_dir / self.CLASSIFIER_FILE
            vectorizer_prod = self.models_dir / self.VECTORIZER_FILE

            if classifier_prod.exists() and vectorizer_prod.exists():
                # Save to rollback directory
                shutil.copy2(classifier_prod, self.rollback_dir / "classifier_previous.joblib")
                shutil.copy2(vectorizer_prod, self.rollback_dir / "vectorizer_previous.joblib")
                logger.info("Backed up current production models", version=current)

            # Step 2: Copy new version to production
            shutil.copy2(version_info.classifier_path, classifier_prod)
            shutil.copy2(version_info.vectorizer_path, vectorizer_prod)

            # Step 3: Update manifest
            previous_version = self.get_current_version()
            self._manifest["previous_version"] = previous_version
            self._manifest["current_version"] = version
            self._manifest["deployment_history"].append({
                "version": version,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "previous_version": previous_version,
                "action": "deploy",
            })
            self._save_manifest()

            # Step 4: Verify deployment
            if not self._verify_deployment():
                raise RuntimeError("Deployment verification failed")

            logger.info(
                "Model deployed successfully",
                version=version,
                previous=previous_version,
            )

            return DeploymentResult(
                success=True,
                version=version,
                previous_version=previous_version,
                message=f"Successfully deployed version '{version}'",
                deployed_at=datetime.now(timezone.utc),
                rollback_available=previous_version is not None,
            )

        except Exception as e:
            logger.error("Deployment failed", version=version, error=str(e))
            return DeploymentResult(
                success=False,
                version=version,
                previous_version=self.get_current_version(),
                message=f"Deployment failed: {e}",
            )

    def rollback(self) -> DeploymentResult:
        """
        Rollback to the previous model version.

        Restores models from rollback/ directory.
        """
        previous_version = self.get_previous_version()
        current_version = self.get_current_version()

        if not previous_version:
            return DeploymentResult(
                success=False,
                version=current_version or "unknown",
                previous_version=None,
                message="No previous version available for rollback",
            )

        # Check rollback files exist
        rollback_classifier = self.rollback_dir / "classifier_previous.joblib"
        rollback_vectorizer = self.rollback_dir / "vectorizer_previous.joblib"

        if not rollback_classifier.exists() or not rollback_vectorizer.exists():
            return DeploymentResult(
                success=False,
                version=current_version or "unknown",
                previous_version=previous_version,
                message="Rollback files not found",
            )

        try:
            # Restore from rollback
            classifier_prod = self.models_dir / self.CLASSIFIER_FILE
            vectorizer_prod = self.models_dir / self.VECTORIZER_FILE

            shutil.copy2(rollback_classifier, classifier_prod)
            shutil.copy2(rollback_vectorizer, vectorizer_prod)

            # Update manifest
            self._manifest["current_version"] = previous_version
            self._manifest["previous_version"] = None  # Clear rollback (one-level only)
            self._manifest["deployment_history"].append({
                "version": previous_version,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "previous_version": current_version,
                "action": "rollback",
            })
            self._save_manifest()

            logger.info(
                "Model rolled back successfully",
                from_version=current_version,
                to_version=previous_version,
            )

            return DeploymentResult(
                success=True,
                version=previous_version,
                previous_version=current_version,
                message=f"Successfully rolled back to version '{previous_version}'",
                deployed_at=datetime.now(timezone.utc),
                rollback_available=False,
            )

        except Exception as e:
            logger.error("Rollback failed", error=str(e))
            return DeploymentResult(
                success=False,
                version=current_version or "unknown",
                previous_version=previous_version,
                message=f"Rollback failed: {e}",
            )

    def _verify_deployment(self) -> bool:
        """Verify that deployed models can be loaded."""
        try:
            classifier_path = self.models_dir / self.CLASSIFIER_FILE
            vectorizer_path = self.models_dir / self.VECTORIZER_FILE

            if not classifier_path.exists() or not vectorizer_path.exists():
                return False

            # Try loading the models
            classifier = joblib.load(classifier_path)
            vectorizer = joblib.load(vectorizer_path)

            # Basic sanity checks
            if not hasattr(classifier, "predict"):
                return False
            if not hasattr(vectorizer, "transform"):
                return False

            return True

        except Exception as e:
            logger.error("Deployment verification failed", error=str(e))
            return False

    def compare_versions(
        self,
        version_a: str,
        version_b: str,
    ) -> dict[str, Any]:
        """
        Compare metrics between two versions.

        Useful for evaluating a candidate against current production.
        """
        info_a = self.get_version(version_a)
        info_b = self.get_version(version_b)

        if not info_a or not info_b:
            return {
                "error": f"Version not found: {version_a if not info_a else version_b}",
            }

        metrics_a = info_a.metrics or {}
        metrics_b = info_b.metrics or {}

        comparison = {
            "version_a": version_a,
            "version_b": version_b,
            "metrics_comparison": {},
            "recommendation": None,
        }

        # Compare key metrics
        key_metrics = ["accuracy", "precision", "recall", "f1_score", "roc_auc"]
        improvements = 0
        regressions = 0

        for metric in key_metrics:
            val_a = metrics_a.get(metric)
            val_b = metrics_b.get(metric)

            if val_a is not None and val_b is not None:
                diff = val_b - val_a
                pct_change = (diff / val_a * 100) if val_a != 0 else 0

                comparison["metrics_comparison"][metric] = {
                    "version_a": val_a,
                    "version_b": val_b,
                    "difference": diff,
                    "percent_change": pct_change,
                    "improved": diff > 0,
                }

                if diff > 0.001:  # Small threshold for improvement
                    improvements += 1
                elif diff < -0.001:
                    regressions += 1

        # Generate recommendation
        if improvements > regressions:
            comparison["recommendation"] = f"Version {version_b} shows improvement"
        elif regressions > improvements:
            comparison["recommendation"] = f"Version {version_a} performs better"
        else:
            comparison["recommendation"] = "Performance is comparable"

        comparison["summary"] = {
            "improvements": improvements,
            "regressions": regressions,
            "unchanged": len(key_metrics) - improvements - regressions,
        }

        return comparison

    def get_deployment_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get deployment history."""
        history = self._manifest.get("deployment_history", [])
        return history[-limit:][::-1]  # Most recent first
