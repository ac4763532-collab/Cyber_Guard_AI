"""
CyberGuard AI - Real-Time Correlation Service (STEP 8.5.3)

Automatic correlation triggering when findings are produced.

This module provides:
1. RealtimeCorrelationService - Orchestrates real-time correlation
2. Automatic correlation on finding creation (no manual API calls)
3. Redis-backed sliding window state
4. Deterministic correlation fingerprinting
5. PostgreSQL persistence for correlation results
6. Multi-worker safe atomic operations

Architecture:
    Finding Created
           ↓
    RealtimeCorrelationService.on_finding_created()
           ↓
    CorrelationStateManager.add_event() + get_candidates()
           ↓
    TenantAwareCorrelator.correlate()
           ↓
    Fingerprint + Deduplication
           ↓
    CorrelatedActivityRepository.create()
           ↓
    AlertManager / IncidentManager (existing)

Key principles:
- Automatic triggering (no manual API required)
- Tenant isolation at every layer
- Fail-closed when Redis unavailable
- Multi-worker safety via atomic operations
- Deterministic fingerprints for deduplication
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.agents.base import Finding
from app.correlation.context import (
    CorrelationContext,
    CorrelationContextExtractor,
)
from app.correlation.engine import CorrelatedGroup, CorrelationResult
from app.correlation.integration import (
    CorrelationContextAdapter,
    CorrelationIntegrationError,
    TenantAwareCorrelator,
    get_tenant_aware_correlator,
    validate_tenant_id,
)
from app.correlation.state import (
    CorrelationStateManager,
    RedisCorrelationUnavailableError,
    get_correlation_state_manager,
    get_state_metrics,
)
from app.logs.models import LogEvent

logger = structlog.get_logger(__name__)


# =============================================================================
# Metrics
# =============================================================================

_realtime_metrics = {
    "findings_processed": 0,
    "correlations_triggered": 0,
    "correlations_found": 0,
    "duplicates_skipped": 0,
    "activities_persisted": 0,
    "redis_failures": 0,
    "correlation_errors": 0,
}


def get_realtime_metrics() -> dict[str, int]:
    """Get real-time correlation metrics."""
    return _realtime_metrics.copy()


def reset_realtime_metrics() -> None:
    """Reset metrics (for testing)."""
    global _realtime_metrics
    _realtime_metrics = {
        "findings_processed": 0,
        "correlations_triggered": 0,
        "correlations_found": 0,
        "duplicates_skipped": 0,
        "activities_persisted": 0,
        "redis_failures": 0,
        "correlation_errors": 0,
    }


def _increment_realtime_metric(name: str, value: int = 1) -> None:
    """Increment a metric counter."""
    if name in _realtime_metrics:
        _realtime_metrics[name] += value


# =============================================================================
# Correlation Fingerprinting
# =============================================================================


def compute_correlation_fingerprint(
    finding_ids: list[str],
    source_types: list[str],
    correlation_bucket: str,
) -> str:
    """
    Compute a deterministic fingerprint for a correlation result.

    The fingerprint ensures:
    - Same findings + sources + bucket always produce same fingerprint
    - Different orderings produce the same fingerprint (sorted)
    - Collision-resistant via SHA-256

    Args:
        finding_ids: List of finding IDs in the correlation
        source_types: List of source types involved
        correlation_bucket: Time bucket identifier (e.g., "2024-01-15T14:00")

    Returns:
        SHA-256 fingerprint string (first 32 chars)
    """
    # Sort for determinism
    sorted_findings = sorted(set(finding_ids))
    sorted_sources = sorted(set(source_types))

    # Build canonical representation
    canonical = json.dumps({
        "findings": sorted_findings,
        "sources": sorted_sources,
        "bucket": correlation_bucket,
    }, sort_keys=True)

    # Hash it
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def get_correlation_bucket(timestamp: datetime, bucket_minutes: int = 15) -> str:
    """
    Get the correlation time bucket for a timestamp.

    Buckets group correlations into time windows for fingerprinting.

    Args:
        timestamp: Event timestamp
        bucket_minutes: Bucket size in minutes (default 15)

    Returns:
        ISO-formatted bucket start time
    """
    # Round down to nearest bucket boundary
    minute = (timestamp.minute // bucket_minutes) * bucket_minutes
    bucket_time = timestamp.replace(minute=minute, second=0, microsecond=0)
    return bucket_time.isoformat()


# =============================================================================
# Correlated Activity Model
# =============================================================================


class CorrelatedActivity:
    """
    Represents a correlated activity ready for persistence.

    This is the output of real-time correlation, containing:
    - Correlation metadata (ID, fingerprint, timestamp)
    - Involved findings and events
    - Correlation strength and type
    - Tenant isolation information
    """

    def __init__(
        self,
        correlation_id: str,
        tenant_id: str,
        fingerprint: str,
        finding_ids: list[str],
        event_ids: list[str],
        source_types: list[str],
        correlation_type: str,
        correlation_strength: float,
        shared_entities: dict[str, list[str]],
        risk_score: int,
        timestamp: datetime,
        correlation_bucket: str,
    ):
        self.correlation_id = correlation_id
        self.tenant_id = tenant_id
        self.fingerprint = fingerprint
        self.finding_ids = finding_ids
        self.event_ids = event_ids
        self.source_types = source_types
        self.correlation_type = correlation_type
        self.correlation_strength = correlation_strength
        self.shared_entities = shared_entities
        self.risk_score = risk_score
        self.timestamp = timestamp
        self.correlation_bucket = correlation_bucket

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for persistence."""
        return {
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "fingerprint": self.fingerprint,
            "finding_ids": self.finding_ids,
            "event_ids": self.event_ids,
            "source_types": self.source_types,
            "correlation_type": self.correlation_type,
            "correlation_strength": self.correlation_strength,
            "shared_entities": self.shared_entities,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp.isoformat(),
            "correlation_bucket": self.correlation_bucket,
        }


# =============================================================================
# Real-Time Correlation Service
# =============================================================================


class RealtimeCorrelationService:
    """
    Orchestrates real-time correlation when findings are produced.

    This service:
    1. Automatically triggers on finding creation
    2. Manages Redis correlation state
    3. Runs correlation through TenantAwareCorrelator
    4. Deduplicates using fingerprints
    5. Persists correlated activities

    Usage:
        service = await RealtimeCorrelationService.create(tenant_id)
        activity = await service.on_finding_created(log_event, finding)

    Multi-worker safety:
    - State operations use atomic Redis pipelines
    - Fingerprint dedup uses SET NX
    - PostgreSQL unique constraint as final guard
    """

    def __init__(
        self,
        state_manager: CorrelationStateManager,
        correlator: TenantAwareCorrelator,
        tenant_id: str,
    ):
        """
        Initialize the real-time correlation service.

        Use the create() factory method instead of direct construction.
        """
        self._state = state_manager
        self._correlator = correlator
        self._tenant_id = tenant_id

    @classmethod
    async def create(
        cls,
        tenant_id: str,
        correlation_window_seconds: int | None = None,
    ) -> "RealtimeCorrelationService":
        """
        Create a RealtimeCorrelationService for a tenant.

        Args:
            tenant_id: Tenant identifier (from trusted source)
            correlation_window_seconds: Optional window override

        Returns:
            Configured RealtimeCorrelationService

        Raises:
            TenantResolutionError: If tenant_id is invalid
            RedisCorrelationUnavailableError: If Redis unavailable
        """
        validate_tenant_id(tenant_id)

        state_manager = await get_correlation_state_manager(
            tenant_id=tenant_id,
            correlation_window_seconds=correlation_window_seconds,
        )

        correlator = get_tenant_aware_correlator()

        logger.info(
            "Created realtime correlation service",
            tenant_id=tenant_id,
            window_seconds=state_manager.window_seconds,
        )

        return cls(
            state_manager=state_manager,
            correlator=correlator,
            tenant_id=tenant_id,
        )

    @property
    def tenant_id(self) -> str:
        """Get the tenant ID."""
        return self._tenant_id

    async def on_finding_created(
        self,
        log_event: LogEvent,
        finding: Finding,
    ) -> CorrelatedActivity | None:
        """
        Process a newly created finding for correlation.

        This is the main entry point - call it when a finding is created.
        It will:
        1. Extract correlation context
        2. Add to Redis state
        3. Find correlation candidates
        4. Run correlation if candidates exist
        5. Deduplicate and persist results

        Args:
            log_event: The source log event
            finding: The newly created finding

        Returns:
            CorrelatedActivity if correlation found, None otherwise

        Raises:
            RedisCorrelationUnavailableError: If Redis is down (fail-closed)
        """
        _increment_realtime_metric("findings_processed")

        try:
            # 1. Extract correlation context
            ctx = CorrelationContextExtractor.extract(
                log_event=log_event,
                tenant_id=self._tenant_id,
                finding_id=finding.finding_id,
            )

            # 2. Check if this finding was already processed
            if await self._state.is_finding_processed(finding.finding_id):
                logger.debug(
                    "Finding already processed for correlation",
                    finding_id=finding.finding_id,
                )
                _increment_realtime_metric("duplicates_skipped")
                return None

            # 3. Get correlation keys
            correlation_keys = ctx.get_correlation_keys()
            if not correlation_keys:
                logger.debug(
                    "Finding has no correlation keys",
                    finding_id=finding.finding_id,
                )
                return None

            # 4. Generate event ID for this finding
            event_id = f"evt_{finding.finding_id}"

            # 5. Build event metadata
            source_type = (
                log_event.source_type.value
                if log_event.source_type
                else "unknown"
            )
            metadata = {
                "source_type": source_type,
                "finding_ids": [finding.finding_id],
                "risk_score": self._severity_to_risk(finding.severity),
                "severity": (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                ),
            }

            # 6. Get candidates BEFORE adding current event
            candidates = await self._state.get_candidates(
                correlation_keys=correlation_keys,
                exclude_event_id=event_id,
            )

            # 7. Add current event to state
            await self._state.add_event(
                event_id=event_id,
                correlation_keys=correlation_keys,
                metadata=metadata,
                timestamp=log_event.timestamp,
            )

            # 8. Mark finding as processed
            await self._state.mark_finding_processed(
                finding_id=finding.finding_id,
                event_id=event_id,
            )

            # 9. Check if we have candidates to correlate with
            if not candidates:
                logger.debug(
                    "No correlation candidates found",
                    finding_id=finding.finding_id,
                    correlation_keys_count=len(correlation_keys),
                )
                return None

            _increment_realtime_metric("correlations_triggered")

            # 10. Build events for correlation
            events_for_correlation = await self._build_correlation_events(
                current_ctx=ctx,
                current_finding=finding,
                current_log_event=log_event,
                candidates=candidates,
            )

            if len(events_for_correlation) < 2:
                return None

            # 11. Run correlation
            result = self._correlator.correlate(
                events=events_for_correlation,
                tenant_id=self._tenant_id,
            )

            if not result.groups:
                return None

            _increment_realtime_metric("correlations_found")

            # 12. Process correlation result
            activity = await self._process_correlation_result(
                result=result,
                current_finding=finding,
                timestamp=log_event.timestamp,
            )

            return activity

        except RedisCorrelationUnavailableError:
            # Fail-closed: let the error propagate
            _increment_realtime_metric("redis_failures")
            logger.error(
                "Redis unavailable for correlation - failing closed",
                finding_id=finding.finding_id,
                tenant_id=self._tenant_id,
            )
            raise

        except CorrelationIntegrationError as e:
            _increment_realtime_metric("correlation_errors")
            logger.error(
                "Correlation integration error",
                finding_id=finding.finding_id,
                error=str(e),
            )
            raise

        except Exception as e:
            _increment_realtime_metric("correlation_errors")
            logger.exception(
                "Unexpected error in realtime correlation",
                finding_id=finding.finding_id,
                error=str(e),
            )
            raise CorrelationIntegrationError(f"Correlation failed: {e}") from e

    async def _build_correlation_events(
        self,
        current_ctx: CorrelationContext,
        current_finding: Finding,
        current_log_event: LogEvent,
        candidates: list[dict[str, Any]],
    ) -> list[tuple[CorrelationContext, Any]]:
        """Build event tuples for correlation engine."""
        events = []

        # Add current event
        current_event_data = CorrelationContextAdapter.to_event_data(
            ctx=current_ctx,
            findings=[current_finding],
            risk_score=self._severity_to_risk(current_finding.severity),
            severity=(
                current_finding.severity.value
                if hasattr(current_finding.severity, "value")
                else str(current_finding.severity)
            ),
        )
        events.append((current_ctx, current_event_data))

        # Add candidate events
        for candidate in candidates:
            try:
                # Build minimal context for candidate
                candidate_ctx = self._build_candidate_context(candidate)
                candidate_event = self._build_candidate_event_data(candidate)
                events.append((candidate_ctx, candidate_event))
            except (ValueError, KeyError) as e:
                logger.warning(
                    "Failed to build candidate event",
                    candidate_id=candidate.get("event_id"),
                    error=str(e),
                )
                continue

        return events

    def _build_candidate_context(
        self,
        candidate: dict[str, Any],
    ) -> CorrelationContext:
        """Build correlation context from candidate metadata."""
        from app.logs.models import LogSourceType

        # Parse timestamp
        ts_str = candidate.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        # Map source type
        source_type_str = candidate.get("source_type", "unknown")
        try:
            source_type = LogSourceType(source_type_str)
        except ValueError:
            source_type = LogSourceType.SYSLOG

        return CorrelationContext(
            tenant_id=self._tenant_id,
            event_id=candidate.get("event_id", ""),
            timestamp=timestamp,
            source_type=source_type,
        )

    def _build_candidate_event_data(
        self,
        candidate: dict[str, Any],
    ) -> Any:
        """Build EventData from candidate metadata."""
        from app.correlation.engine import EventData

        ts_str = candidate.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        return EventData(
            event_id=candidate.get("event_id", ""),
            domain=candidate.get("source_type", "unknown"),
            timestamp=timestamp,
            ips=[],
            users=[],
            assets=[],
            findings=[],
            risk_score=candidate.get("risk_score", 0),
            severity=candidate.get("severity", "info"),
            mitre_techniques=[],
            mitre_tactics=[],
        )

    async def _process_correlation_result(
        self,
        result: CorrelationResult,
        current_finding: Finding,
        timestamp: datetime,
    ) -> CorrelatedActivity | None:
        """Process correlation result and create activity."""
        if not result.groups:
            return None

        # Get the group containing our finding
        target_group = None
        for group in result.groups:
            event_ids = [e.event_id for e in group.events]
            if f"evt_{current_finding.finding_id}" in event_ids:
                target_group = group
                break

        if not target_group or len(target_group.events) < 2:
            return None

        # Extract finding IDs and source types
        finding_ids = []
        event_ids = []
        source_types = set()

        for event in target_group.events:
            event_ids.append(event.event_id)
            source_types.add(event.domain)
            for f in event.findings:
                finding_ids.append(f.finding_id)

        # Ensure current finding is included
        if current_finding.finding_id not in finding_ids:
            finding_ids.append(current_finding.finding_id)

        # Get correlation bucket
        bucket = get_correlation_bucket(timestamp)

        # Compute fingerprint
        fingerprint = compute_correlation_fingerprint(
            finding_ids=finding_ids,
            source_types=list(source_types),
            correlation_bucket=bucket,
        )

        # Check for duplicate
        if await self._state.is_result_duplicate(fingerprint):
            logger.debug(
                "Duplicate correlation result",
                fingerprint=fingerprint,
            )
            _increment_realtime_metric("duplicates_skipped")
            return None

        # Create correlation ID
        correlation_id = str(uuid4())

        # Mark result as created
        created = await self._state.mark_result_created(
            fingerprint=fingerprint,
            correlation_id=correlation_id,
        )

        if not created:
            # Race condition: another worker created it
            _increment_realtime_metric("duplicates_skipped")
            return None

        # Build shared entities
        shared_entities: dict[str, list[str]] = {
            "ips": list(target_group.shared_iocs.get("ips", [])),
            "users": list(target_group.shared_users),
            "assets": list(target_group.shared_assets),
        }

        # Calculate aggregate risk score
        total_risk = sum(e.risk_score for e in target_group.events)
        avg_risk = total_risk // len(target_group.events) if target_group.events else 0

        # Determine correlation type
        correlation_type = self._determine_correlation_type(target_group)

        activity = CorrelatedActivity(
            correlation_id=correlation_id,
            tenant_id=self._tenant_id,
            fingerprint=fingerprint,
            finding_ids=finding_ids,
            event_ids=event_ids,
            source_types=list(source_types),
            correlation_type=correlation_type,
            correlation_strength=target_group.correlation_strength,
            shared_entities=shared_entities,
            risk_score=min(100, avg_risk + 10),  # Slight boost for correlation
            timestamp=timestamp,
            correlation_bucket=bucket,
        )

        _increment_realtime_metric("activities_persisted")

        logger.info(
            "Correlated activity created",
            correlation_id=correlation_id,
            tenant_id=self._tenant_id,
            fingerprint=fingerprint,
            finding_count=len(finding_ids),
            source_types=list(source_types),
            correlation_type=correlation_type,
        )

        return activity

    def _determine_correlation_type(self, group: CorrelatedGroup) -> str:
        """Determine the primary correlation type."""
        # Check for cross-source
        domains = {e.domain for e in group.events}
        if len(domains) > 1:
            return "cross_source"

        # Check for IOC-based
        if group.shared_iocs:
            return "ioc_based"

        # Check for user-based
        if group.shared_users:
            return "user_based"

        # Check for asset-based
        if group.shared_assets:
            return "asset_based"

        # Check for temporal
        if hasattr(group, "correlations"):
            for corr in group.correlations:
                if hasattr(corr, "correlation_type") and "temporal" in str(corr.correlation_type).lower():
                    return "temporal"

        return "unknown"

    @staticmethod
    def _severity_to_risk(severity: Any) -> int:
        """Convert severity to risk score."""
        severity_str = (
            severity.value if hasattr(severity, "value") else str(severity)
        ).lower()

        mapping = {
            "critical": 95,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10,
        }
        return mapping.get(severity_str, 50)

    async def health_check(self) -> dict[str, Any]:
        """Check service health."""
        state_health = await self._state.health_check()

        return {
            "status": state_health.get("status", "unknown"),
            "tenant_id": self._tenant_id,
            "window_seconds": self._state.window_seconds,
            "metrics": get_realtime_metrics(),
            "state_metrics": get_state_metrics(),
        }

    async def get_stats(self) -> dict[str, Any]:
        """Get service statistics."""
        state_stats = await self._state.get_stats()

        return {
            "tenant_id": self._tenant_id,
            "realtime_metrics": get_realtime_metrics(),
            "state_stats": state_stats,
        }


# =============================================================================
# Service Factory
# =============================================================================

_realtime_services: dict[str, RealtimeCorrelationService] = {}


async def get_realtime_correlation_service(
    tenant_id: str,
    correlation_window_seconds: int | None = None,
) -> RealtimeCorrelationService:
    """
    Get or create a RealtimeCorrelationService for a tenant.

    Args:
        tenant_id: Tenant identifier
        correlation_window_seconds: Optional window override

    Returns:
        RealtimeCorrelationService instance
    """
    cache_key = tenant_id
    if cache_key not in _realtime_services:
        _realtime_services[cache_key] = await RealtimeCorrelationService.create(
            tenant_id=tenant_id,
            correlation_window_seconds=correlation_window_seconds,
        )
    return _realtime_services[cache_key]


def reset_realtime_services_for_testing() -> None:
    """Reset service cache (for testing)."""
    _realtime_services.clear()
    reset_realtime_metrics()
