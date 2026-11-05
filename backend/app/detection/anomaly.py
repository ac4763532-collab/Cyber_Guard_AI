"""
CyberGuard AI - Anomaly Detection

Basic statistical anomaly detection for security events.
Uses simple statistical methods for baseline comparison.

For production, this could be extended with:
- Isolation Forest
- One-Class SVM
- Autoencoders
- Time-series analysis
"""

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
import structlog


logger = structlog.get_logger(__name__)


class AnomalyType(str):
    """Types of anomalies."""
    FREQUENCY = "frequency"
    VALUE = "value"
    SEQUENCE = "sequence"
    TIME = "time"


class Anomaly(BaseModel):
    """Detected anomaly."""

    anomaly_id: str = Field(default_factory=lambda: str(uuid4()))
    anomaly_type: str
    description: str
    severity_score: float = Field(..., ge=0.0, le=1.0)
    field: str
    observed_value: Any
    expected_range: str
    deviation: float
    confidence: float = Field(..., ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StatisticalBaseline:
    """
    Maintains statistical baselines for anomaly detection.
    Uses simple running statistics (mean, std dev).
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._values: list[float] = []
        self._mean: float = 0.0
        self._variance: float = 0.0
        self._count: int = 0

    def add_value(self, value: float) -> None:
        """Add a value to the baseline."""
        self._values.append(value)
        if len(self._values) > self.window_size:
            self._values.pop(0)

        self._count = len(self._values)
        if self._count > 0:
            self._mean = sum(self._values) / self._count
            if self._count > 1:
                self._variance = sum((x - self._mean) ** 2 for x in self._values) / (self._count - 1)
            else:
                self._variance = 0.0

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def std_dev(self) -> float:
        return math.sqrt(self._variance) if self._variance > 0 else 0.0

    @property
    def count(self) -> int:
        return self._count

    def get_z_score(self, value: float) -> float:
        """Calculate z-score for a value."""
        if self.std_dev == 0:
            return 0.0 if value == self.mean else float('inf')
        return (value - self.mean) / self.std_dev

    def is_anomaly(self, value: float, threshold: float = 2.5) -> tuple[bool, float]:
        """
        Check if value is anomalous.

        Args:
            value: Value to check
            threshold: Z-score threshold (default 2.5 = ~99% confidence)

        Returns:
            Tuple of (is_anomaly, z_score)
        """
        if self._count < 10:
            # Not enough data for reliable detection
            return False, 0.0

        z_score = self.get_z_score(value)
        return abs(z_score) > threshold, z_score


class AnomalyDetector:
    """
    Anomaly detector for security events.

    Maintains baselines for various metrics and detects
    deviations from normal patterns.
    """

    def __init__(self):
        # Baselines for different metrics
        self._baselines: dict[str, StatisticalBaseline] = defaultdict(StatisticalBaseline)

        # Time-based patterns (hour of day)
        self._hourly_counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))

        # User behavior baselines
        self._user_baselines: dict[str, dict[str, StatisticalBaseline]] = defaultdict(
            lambda: defaultdict(StatisticalBaseline)
        )

    def detect(self, data: dict[str, Any]) -> list[Anomaly]:
        """
        Detect anomalies in data.

        Args:
            data: Event data to analyze

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Check numeric fields for value anomalies
        anomalies.extend(self._check_value_anomalies(data))

        # Check frequency anomalies
        anomalies.extend(self._check_frequency_anomalies(data))

        # Check time-based anomalies
        anomalies.extend(self._check_time_anomalies(data))

        return anomalies

    def _check_value_anomalies(self, data: dict[str, Any]) -> list[Anomaly]:
        """Check for anomalous numeric values."""
        anomalies = []

        # Fields to check for anomalies
        numeric_fields = [
            "auth_failure_count",
            "request_count",
            "data_transferred_bytes",
            "session_duration_seconds",
            "login_attempts",
        ]

        for field in numeric_fields:
            if field in data:
                value = data[field]
                if isinstance(value, (int, float)):
                    baseline = self._baselines[field]
                    is_anomalous, z_score = baseline.is_anomaly(value)

                    if is_anomalous:
                        severity = min(abs(z_score) / 5.0, 1.0)  # Normalize to 0-1
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.VALUE,
                            description=f"Unusual value for {field}",
                            severity_score=severity,
                            field=field,
                            observed_value=value,
                            expected_range=f"{baseline.mean:.2f} ± {baseline.std_dev * 2:.2f}",
                            deviation=z_score,
                            confidence=min(baseline.count / 100, 1.0),
                        ))

                    # Update baseline
                    baseline.add_value(value)

        return anomalies

    def _check_frequency_anomalies(self, data: dict[str, Any]) -> list[Anomaly]:
        """Check for unusual event frequencies."""
        anomalies = []

        # Check auth failures per source
        source_ip = data.get("source_ip")
        failure_count = data.get("auth_failure_count", 0)

        if source_ip and failure_count:
            key = f"failures_from_{source_ip}"
            baseline = self._baselines[key]

            if baseline.count >= 5:
                is_anomalous, z_score = baseline.is_anomaly(failure_count, threshold=2.0)

                if is_anomalous and failure_count > baseline.mean:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.FREQUENCY,
                        description=f"Unusual number of auth failures from {source_ip}",
                        severity_score=min(z_score / 4.0, 1.0),
                        field="auth_failure_count",
                        observed_value=failure_count,
                        expected_range=f"~{baseline.mean:.1f} failures",
                        deviation=z_score,
                        confidence=min(baseline.count / 50, 1.0),
                    ))

            baseline.add_value(failure_count)

        return anomalies

    def _check_time_anomalies(self, data: dict[str, Any]) -> list[Anomaly]:
        """Check for unusual time-of-day patterns."""
        anomalies = []

        timestamp = data.get("timestamp")
        user = data.get("user")
        event_type = data.get("event_type", "unknown")

        if timestamp and user:
            # Parse timestamp
            if isinstance(timestamp, str):
                try:
                    # Try common formats
                    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            dt = datetime.strptime(timestamp[:19], fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        return anomalies
                except Exception:
                    return anomalies
            elif isinstance(timestamp, datetime):
                dt = timestamp
            else:
                return anomalies

            hour = dt.hour

            # Track hourly patterns per user
            key = f"{user}_{event_type}"
            self._hourly_counts[key][hour] += 1

            # Check if this hour is unusual for this user
            user_hours = self._hourly_counts[key]
            total_events = sum(user_hours.values())

            if total_events > 20:
                expected_ratio = 1.0 / 24  # Uniform distribution
                actual_ratio = user_hours[hour] / total_events

                # Very low activity at this hour historically
                if actual_ratio < expected_ratio * 0.1 and user_hours[hour] == 1:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.TIME,
                        description=f"Unusual login time for user {user}",
                        severity_score=0.6,
                        field="timestamp",
                        observed_value=f"{hour:02d}:00",
                        expected_range="Based on user's typical active hours",
                        deviation=0.0,
                        confidence=min(total_events / 100, 0.8),
                    ))

        return anomalies

    def update_baseline(self, metric: str, value: float) -> None:
        """Manually update a baseline."""
        self._baselines[metric].add_value(value)

    def get_baseline_stats(self, metric: str) -> dict[str, Any]:
        """Get statistics for a baseline."""
        baseline = self._baselines.get(metric)
        if baseline:
            return {
                "metric": metric,
                "mean": baseline.mean,
                "std_dev": baseline.std_dev,
                "count": baseline.count,
            }
        return {"metric": metric, "error": "No baseline found"}

    def get_all_baselines(self) -> list[dict[str, Any]]:
        """Get all baseline statistics."""
        return [
            self.get_baseline_stats(metric)
            for metric in self._baselines
            if self._baselines[metric].count > 0
        ]


# Singleton instance
_detector: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get the global anomaly detector."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
