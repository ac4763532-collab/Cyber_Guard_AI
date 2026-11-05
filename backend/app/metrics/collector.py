"""
CyberGuard AI - Metrics Collector

Thread/async-safe in-memory metrics collection for observability.
Provides counters, histograms, and summary statistics.

Metrics collected:
- emails_analyzed_total
- threats_detected_total
- email_analysis_duration_ms
- external_api_calls_total
- external_api_errors_total
- cache_hits_total
- cache_requests_total
"""

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Any
import statistics


class MetricsCollector:
    """
    Thread/async-safe in-memory metrics collector.

    Supports:
    - Counters: increment()
    - Histograms: observe()
    - Summaries: get_metrics()

    Labels are supported but cardinality is bounded by design.
    Do NOT use user input, IPs, emails, or URLs as labels.
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self._counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._histograms: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._last_reset = datetime.now(timezone.utc)

        # Maximum histogram samples to prevent memory growth
        self._max_histogram_samples = 10000

    async def increment(
        self,
        name: str,
        value: int = 1,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Increment a counter metric.

        Args:
            name: Metric name (e.g., "emails_analyzed_total")
            value: Amount to increment (default 1)
            labels: Optional labels (keep cardinality bounded!)
        """
        label_key = self._labels_to_key(labels)

        async with self._lock:
            self._counters[name][label_key] += value

    async def observe(
        self,
        name: str,
        value: float,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Record a histogram observation.

        Args:
            name: Metric name (e.g., "email_analysis_duration_ms")
            value: Observed value
            labels: Optional labels (keep cardinality bounded!)
        """
        label_key = self._labels_to_key(labels)

        async with self._lock:
            samples = self._histograms[name][label_key]

            # Bound memory by rotating oldest samples
            if len(samples) >= self._max_histogram_samples:
                samples.pop(0)

            samples.append(value)

    async def get_counter(
        self,
        name: str,
        labels: Optional[dict[str, str]] = None,
    ) -> int:
        """Get current counter value."""
        label_key = self._labels_to_key(labels)

        async with self._lock:
            return self._counters[name].get(label_key, 0)

    async def get_histogram_stats(
        self,
        name: str,
        labels: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Get histogram statistics."""
        label_key = self._labels_to_key(labels)

        async with self._lock:
            samples = self._histograms[name].get(label_key, [])

            if not samples:
                return {
                    "count": 0,
                    "min": 0,
                    "max": 0,
                    "avg": 0,
                    "median": 0,
                    "p95": 0,
                    "p99": 0,
                }

            sorted_samples = sorted(samples)
            count = len(sorted_samples)

            return {
                "count": count,
                "min": round(min(sorted_samples), 2),
                "max": round(max(sorted_samples), 2),
                "avg": round(statistics.mean(sorted_samples), 2),
                "median": round(statistics.median(sorted_samples), 2),
                "p95": round(sorted_samples[int(count * 0.95)] if count > 1 else sorted_samples[0], 2),
                "p99": round(sorted_samples[int(count * 0.99)] if count > 1 else sorted_samples[0], 2),
            }

    async def get_metrics(self) -> dict[str, Any]:
        """
        Get all metrics with their current values.

        Returns dict with:
        - counters: all counter values
        - histograms: all histogram stats
        - metadata: collection timestamp, etc.
        """
        async with self._lock:
            counters = {}
            for name, label_values in self._counters.items():
                if len(label_values) == 1 and "" in label_values:
                    # No labels - simple value
                    counters[name] = label_values[""]
                else:
                    # Has labels - nested structure
                    counters[name] = dict(label_values)

            histograms = {}
            for name, label_values in self._histograms.items():
                for label_key, samples in label_values.items():
                    if not samples:
                        continue

                    sorted_samples = sorted(samples)
                    count = len(sorted_samples)

                    stats = {
                        "count": count,
                        "min": round(min(sorted_samples), 2),
                        "max": round(max(sorted_samples), 2),
                        "avg": round(statistics.mean(sorted_samples), 2),
                    }

                    if label_key == "":
                        histograms[name] = stats
                    else:
                        if name not in histograms:
                            histograms[name] = {}
                        histograms[name][label_key] = stats

            return {
                "counters": counters,
                "histograms": histograms,
                "metadata": {
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "last_reset": self._last_reset.isoformat(),
                },
            }

    async def reset(self) -> None:
        """Reset all metrics."""
        async with self._lock:
            self._counters.clear()
            self._histograms.clear()
            self._last_reset = datetime.now(timezone.utc)

    def _labels_to_key(self, labels: Optional[dict[str, str]]) -> str:
        """Convert labels dict to a stable string key."""
        if not labels:
            return ""
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


# Singleton instance
_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the metrics collector singleton."""
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector


# Convenience functions for common metrics
async def increment_emails_analyzed(classification: str = "unknown") -> None:
    """Increment emails analyzed counter."""
    collector = get_metrics_collector()
    await collector.increment("emails_analyzed_total")
    await collector.increment(
        "emails_analyzed_by_classification_total",
        labels={"classification": classification},
    )


async def increment_threats_detected(classification: str = "unknown") -> None:
    """Increment threats detected counter."""
    collector = get_metrics_collector()
    await collector.increment("threats_detected_total")
    await collector.increment(
        "threats_detected_by_classification_total",
        labels={"classification": classification},
    )


async def observe_analysis_duration(duration_ms: float) -> None:
    """Record email analysis duration."""
    collector = get_metrics_collector()
    await collector.observe("email_analysis_duration_ms", duration_ms)


async def increment_external_api_call(service: str) -> None:
    """Increment external API call counter."""
    collector = get_metrics_collector()
    await collector.increment("external_api_calls_total", labels={"service": service})


async def increment_external_api_error(service: str) -> None:
    """Increment external API error counter."""
    collector = get_metrics_collector()
    await collector.increment("external_api_errors_total", labels={"service": service})


async def increment_cache_hit(cache_type: str = "threat_intel") -> None:
    """Increment cache hit counter."""
    collector = get_metrics_collector()
    await collector.increment("cache_hits_total", labels={"type": cache_type})


async def increment_cache_request(cache_type: str = "threat_intel") -> None:
    """Increment cache request counter."""
    collector = get_metrics_collector()
    await collector.increment("cache_requests_total", labels={"type": cache_type})
