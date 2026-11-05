"""
CyberGuard AI - Metrics API Endpoints

Provides access to collected application metrics.
"""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.metrics import get_metrics_collector


router = APIRouter(prefix="/metrics", tags=["Metrics"])


class MetricsResponse(BaseModel):
    """Full metrics response."""
    counters: dict = Field(default_factory=dict)
    histograms: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class MetricsSummaryResponse(BaseModel):
    """Summarized metrics for dashboard."""
    emails_analyzed: int = 0
    threats_detected: int = 0
    detection_rate: float = 0.0
    avg_analysis_time_ms: float = 0.0
    cache_hit_rate: float = 0.0
    external_api_error_rate: float = 0.0
    timestamp: datetime


@router.get(
    "",
    response_model=MetricsResponse,
    summary="Get All Metrics",
    description="Returns all collected metrics with counters and histograms.",
)
async def get_metrics() -> MetricsResponse:
    """Get all collected metrics."""
    collector = get_metrics_collector()
    metrics = await collector.get_metrics()

    return MetricsResponse(
        counters=metrics.get("counters", {}),
        histograms=metrics.get("histograms", {}),
        metadata=metrics.get("metadata", {}),
    )


@router.get(
    "/summary",
    response_model=MetricsSummaryResponse,
    summary="Get Metrics Summary",
    description="Returns summarized metrics for dashboard display.",
)
async def get_metrics_summary() -> MetricsSummaryResponse:
    """Get summarized metrics."""
    collector = get_metrics_collector()

    # Get counters
    emails_analyzed = await collector.get_counter("emails_analyzed_total")
    threats_detected = await collector.get_counter("threats_detected_total")

    # Calculate detection rate (avoid division by zero)
    detection_rate = 0.0
    if emails_analyzed > 0:
        detection_rate = round((threats_detected / emails_analyzed) * 100, 2)

    # Get analysis duration stats
    duration_stats = await collector.get_histogram_stats("email_analysis_duration_ms")
    avg_analysis_time = duration_stats.get("avg", 0.0)

    # Calculate cache hit rate
    cache_hits = await collector.get_counter("cache_hits_total")
    cache_requests = await collector.get_counter("cache_requests_total")
    cache_hit_rate = 0.0
    if cache_requests > 0:
        cache_hit_rate = round((cache_hits / cache_requests) * 100, 2)

    # Calculate external API error rate
    api_calls = await collector.get_counter("external_api_calls_total")
    api_errors = await collector.get_counter("external_api_errors_total")
    api_error_rate = 0.0
    if api_calls > 0:
        api_error_rate = round((api_errors / api_calls) * 100, 2)

    return MetricsSummaryResponse(
        emails_analyzed=emails_analyzed,
        threats_detected=threats_detected,
        detection_rate=detection_rate,
        avg_analysis_time_ms=avg_analysis_time,
        cache_hit_rate=cache_hit_rate,
        external_api_error_rate=api_error_rate,
        timestamp=datetime.now(timezone.utc),
    )
