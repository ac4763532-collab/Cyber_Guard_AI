"""
CyberGuard AI - Metrics Module

In-memory metrics collection for observability.
"""

from app.metrics.collector import (
    MetricsCollector,
    get_metrics_collector,
    increment_emails_analyzed,
    increment_threats_detected,
    observe_analysis_duration,
    increment_external_api_call,
    increment_external_api_error,
    increment_cache_hit,
    increment_cache_request,
)

__all__ = [
    "MetricsCollector",
    "get_metrics_collector",
    "increment_emails_analyzed",
    "increment_threats_detected",
    "observe_analysis_duration",
    "increment_external_api_call",
    "increment_external_api_error",
    "increment_cache_hit",
    "increment_cache_request",
]
