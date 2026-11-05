"""
CyberGuard AI - Correlation Engine Integration (STEP 8.5.2)

Integrates CorrelationContext with the existing CorrelationEngine.

This module provides:
1. CorrelationContextAdapter - Converts CorrelationContext to EventData
2. TenantAwareCorrelator - Wraps CorrelationEngine with tenant isolation
3. Integration with existing detection/finding flow
4. Metrics and error handling

Architecture:
    Finding (from Detection)
           ↓
    CorrelationContextExtractor.extract(log_event, tenant_id, finding_id)
           ↓
    CorrelationContext
           ↓
    CorrelationContextAdapter.to_event_data(ctx)
           ↓
    EventData
           ↓
    TenantAwareCorrelator.correlate(events, tenant_id)
           ↓
    CorrelationEngine (existing)
           ↓
    CorrelationResult

Key principles:
- Reuse existing CorrelationEngine (no new engine)
- Tenant isolation is mandatory
- Tenant ID from trusted server-side source only
- Stable event identity
- Errors are observable and safely handled
"""

from datetime import datetime, timedelta, timezone

import structlog

from app.agents.base import Finding
from app.correlation.context import (
    CorrelationContext,
    CorrelationContextExtractor,
)
from app.correlation.engine import (
    CorrelationEngine,
    CorrelationResult,
    EventData,
    get_correlation_engine,
)
from app.logs.models import LogEvent

logger = structlog.get_logger(__name__)


# =============================================================================
# Metrics
# =============================================================================


_correlation_metrics = {
    "events_received": 0,
    "events_processed": 0,
    "events_skipped_no_tenant": 0,
    "events_skipped_no_entities": 0,
    "correlation_errors": 0,
    "correlation_groups_created": 0,
    "cross_source_correlations": 0,
}


def get_correlation_metrics() -> dict[str, int]:
    """Get correlation integration metrics."""
    return _correlation_metrics.copy()


def reset_correlation_metrics() -> None:
    """Reset metrics (for testing)."""
    global _correlation_metrics
    _correlation_metrics = {
        "events_received": 0,
        "events_processed": 0,
        "events_skipped_no_tenant": 0,
        "events_skipped_no_entities": 0,
        "correlation_errors": 0,
        "correlation_groups_created": 0,
        "cross_source_correlations": 0,
    }


def _increment_metric(name: str, value: int = 1) -> None:
    """Increment a metric counter."""
    if name in _correlation_metrics:
        _correlation_metrics[name] += value


# =============================================================================
# Errors
# =============================================================================


class CorrelationIntegrationError(Exception):
    """Base exception for correlation integration errors."""


class TenantResolutionError(CorrelationIntegrationError):
    """Raised when tenant identity cannot be resolved from trusted source."""

    def __init__(self, reason: str, source_id: str | None = None):
        self.reason = reason
        self.source_id = source_id
        super().__init__(f"Tenant resolution failed: {reason} (source_id={source_id})")


class InvalidCorrelationDataError(CorrelationIntegrationError):
    """Raised when correlation data is malformed."""

    def __init__(self, reason: str, event_id: str | None = None):
        self.reason = reason
        self.event_id = event_id
        super().__init__(f"Invalid correlation data: {reason} (event_id={event_id})")


# =============================================================================
# Context Adapter
# =============================================================================


class CorrelationContextAdapter:
    """
    Adapts CorrelationContext to CorrelationEngine's EventData.

    This is the canonical adapter - do not duplicate normalization logic.
    Uses CorrelationContext.to_event_data_dict() for the base conversion,
    then constructs a proper EventData instance.
    """

    @classmethod
    def to_event_data(
        cls,
        ctx: CorrelationContext,
        findings: list[Finding] | None = None,
        mitre_techniques: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        risk_score: int = 0,
        severity: str = "info",
    ) -> EventData:
        """
        Convert CorrelationContext to EventData for the existing CorrelationEngine.

        Args:
            ctx: CorrelationContext with normalized entities
            findings: Optional list of findings associated with this event
            mitre_techniques: MITRE ATT&CK technique IDs
            mitre_tactics: MITRE ATT&CK tactic IDs
            risk_score: Risk score (0-100)
            severity: Severity level string

        Returns:
            EventData suitable for CorrelationEngine.correlate()

        Raises:
            InvalidCorrelationDataError: If context cannot be converted
        """
        # Get base dict from context
        base_dict = ctx.to_event_data_dict()

        # Validate required fields
        event_id = base_dict.get("event_id")
        if not event_id:
            raise InvalidCorrelationDataError(
                reason="Missing event_id",
                event_id=None,
            )

        # Build EventData
        try:
            event_data = EventData(
                event_id=event_id,
                domain=base_dict.get("domain", "unknown"),
                timestamp=base_dict.get("timestamp", datetime.now(timezone.utc)),
                ips=base_dict.get("ips", []),
                users=base_dict.get("users", []),
                assets=base_dict.get("assets", []),
                findings=findings or [],
                risk_score=risk_score,
                severity=severity,
                mitre_techniques=mitre_techniques or [],
                mitre_tactics=mitre_tactics or [],
            )
            return event_data

        except (ValueError, TypeError, KeyError) as e:
            raise InvalidCorrelationDataError(
                reason=str(e),
                event_id=event_id,
            ) from e

    @classmethod
    def from_log_event(
        cls,
        log_event: LogEvent,
        tenant_id: str,
        finding: Finding | None = None,
    ) -> tuple[CorrelationContext, EventData]:
        """
        Create both CorrelationContext and EventData from a LogEvent.

        This is the primary integration method for the detection pipeline.

        Args:
            log_event: The source log event
            tenant_id: Trusted tenant identifier (from LogSource.organization_id)
            finding: Optional finding associated with this event

        Returns:
            Tuple of (CorrelationContext, EventData)

        Raises:
            TenantResolutionError: If tenant_id is not provided
            InvalidCorrelationDataError: If conversion fails
        """
        if not tenant_id:
            raise TenantResolutionError(
                reason="tenant_id is required",
                source_id=log_event.source_id,
            )

        # Extract correlation context
        finding_id = finding.finding_id if finding else None
        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id=tenant_id,
            finding_id=finding_id,
        )

        # Convert to EventData
        findings_list = [finding] if finding else []
        mitre_techniques = finding.mitre_techniques if finding else []
        risk_score = 0
        severity = "info"

        if finding:
            # Map severity to risk score
            severity_risk_map = {
                "critical": 95,
                "high": 75,
                "medium": 50,
                "low": 25,
                "info": 10,
            }
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            risk_score = severity_risk_map.get(severity.lower(), 50)

        event_data = cls.to_event_data(
            ctx=ctx,
            findings=findings_list,
            mitre_techniques=mitre_techniques,
            risk_score=risk_score,
            severity=severity,
        )

        return ctx, event_data


# =============================================================================
# Tenant-Aware Correlator
# =============================================================================


class TenantAwareCorrelator:
    """
    Wrapper around CorrelationEngine that enforces tenant isolation.

    The existing CorrelationEngine does not have tenant awareness.
    This wrapper ensures events from different tenants are never correlated.

    Usage:
        correlator = TenantAwareCorrelator()
        result = correlator.correlate(events, tenant_id="org-123")
    """

    def __init__(self, engine: CorrelationEngine | None = None):
        """
        Initialize with an optional CorrelationEngine instance.

        Args:
            engine: CorrelationEngine to use, or None for singleton
        """
        self._engine = engine

    @property
    def engine(self) -> CorrelationEngine:
        """Get the underlying CorrelationEngine."""
        if self._engine is None:
            self._engine = get_correlation_engine()
        return self._engine

    def correlate(
        self,
        events: list[tuple[CorrelationContext, EventData]],
        tenant_id: str,
        time_window: timedelta | None = None,
    ) -> CorrelationResult:
        """
        Correlate events within a single tenant.

        This method enforces tenant isolation by:
        1. Filtering events to only those matching tenant_id
        2. Rejecting any event without a tenant context
        3. Logging cross-tenant correlation attempts

        Args:
            events: List of (CorrelationContext, EventData) tuples
            tenant_id: Tenant to correlate within
            time_window: Optional time window override

        Returns:
            CorrelationResult from the existing engine

        Raises:
            TenantResolutionError: If tenant_id is empty
        """
        if not tenant_id:
            raise TenantResolutionError(
                reason="tenant_id is required for correlation",
            )

        _increment_metric("events_received", len(events))

        # Filter events to this tenant only
        tenant_events: list[EventData] = []
        skipped_no_tenant = 0
        skipped_wrong_tenant = 0

        for ctx, event_data in events:
            if not ctx.tenant_id:
                skipped_no_tenant += 1
                logger.warning(
                    "Skipping event without tenant context",
                    event_id=event_data.event_id,
                )
                continue

            if ctx.tenant_id != tenant_id:
                skipped_wrong_tenant += 1
                logger.warning(
                    "Cross-tenant correlation blocked",
                    event_id=event_data.event_id,
                    event_tenant=ctx.tenant_id,
                    correlation_tenant=tenant_id,
                )
                continue

            tenant_events.append(event_data)

        _increment_metric("events_skipped_no_tenant", skipped_no_tenant)
        if skipped_wrong_tenant > 0:
            logger.error(
                "Cross-tenant correlation attempts detected and blocked",
                count=skipped_wrong_tenant,
                target_tenant=tenant_id,
            )

        if not tenant_events:
            logger.info(
                "No events for correlation after tenant filtering",
                tenant_id=tenant_id,
                original_count=len(events),
            )
            return CorrelationResult(
                event_count=0,
                groups=[],
                total_correlations=0,
            )

        # Run correlation through existing engine
        try:
            result = self.engine.correlate(
                events=tenant_events,
                time_window=time_window,
            )

            _increment_metric("events_processed", len(tenant_events))
            _increment_metric("correlation_groups_created", len(result.groups))
            _increment_metric("cross_source_correlations", result.cross_domain_groups)

            logger.info(
                "Correlation complete",
                tenant_id=tenant_id,
                events=len(tenant_events),
                groups=len(result.groups),
                cross_domain=result.cross_domain_groups,
            )

            return result

        except Exception as e:
            _increment_metric("correlation_errors")
            logger.exception(
                "Correlation engine error",
                tenant_id=tenant_id,
                error=str(e),
            )
            raise CorrelationIntegrationError(f"Correlation failed: {e}") from e

    def correlate_single_event(
        self,
        log_event: LogEvent,
        tenant_id: str,
        finding: Finding | None = None,
        existing_events: list[tuple[CorrelationContext, EventData]] | None = None,
    ) -> tuple[CorrelationContext, CorrelationResult]:
        """
        Correlate a single event with existing events.

        Convenience method for the detection pipeline.

        Args:
            log_event: New log event to correlate
            tenant_id: Trusted tenant identifier
            finding: Optional finding for this event
            existing_events: Existing events to correlate against

        Returns:
            Tuple of (CorrelationContext, CorrelationResult)
        """
        # Create context and event data
        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id=tenant_id,
            finding=finding,
        )

        if not ctx.can_correlate():
            _increment_metric("events_skipped_no_entities")
            logger.debug(
                "Event cannot correlate (no entities)",
                event_id=log_event.id,
                tenant_id=tenant_id,
            )
            return ctx, CorrelationResult(event_count=0)

        # Combine with existing events
        all_events = list(existing_events or [])
        all_events.append((ctx, event_data))

        # Run correlation
        result = self.correlate(
            events=all_events,
            tenant_id=tenant_id,
        )

        return ctx, result


# =============================================================================
# Tenant Resolution
# =============================================================================


async def resolve_tenant_from_source(source_id: str | None) -> str | None:
    """
    Resolve tenant ID from a LogSource's organization_id.

    This is the TRUSTED method for tenant resolution.
    The tenant ID comes from the persisted LogSource record,
    not from untrusted request data.

    Args:
        source_id: LogSource identifier

    Returns:
        organization_id from the LogSource, or None if not found
    """
    if not source_id:
        return None

    try:
        from app.logs.repository import LogSourceRepository

        repo = LogSourceRepository()
        source = await repo.get(source_id)

        if source:
            return source.organization_id

        logger.warning(
            "LogSource not found for tenant resolution",
            source_id=source_id,
        )
        return None

    except ImportError:
        # Repository not available
        logger.warning(
            "LogSourceRepository not available for tenant resolution",
            source_id=source_id,
        )
        return None
    except (AttributeError, ValueError, RuntimeError) as e:
        logger.error(
            "Error resolving tenant from source",
            source_id=source_id,
            error=str(e),
        )
        return None


def validate_tenant_id(
    tenant_id: str | None,
    source_id: str | None = None,
    raise_on_failure: bool = True,
) -> str:
    """
    Validate that a tenant ID is present and non-empty.

    Args:
        tenant_id: Tenant ID to validate
        source_id: Source ID for error context
        raise_on_failure: If True, raise on invalid tenant

    Returns:
        The validated tenant_id

    Raises:
        TenantResolutionError: If tenant_id is invalid and raise_on_failure=True
    """
    if not tenant_id or not str(tenant_id).strip():
        if raise_on_failure:
            raise TenantResolutionError(
                reason="Tenant ID is required but was empty",
                source_id=source_id,
            )
        return ""

    return str(tenant_id).strip()


# =============================================================================
# Detection Pipeline Integration
# =============================================================================


async def correlate_finding(
    log_event: LogEvent,
    finding: Finding,
    tenant_id: str | None = None,
) -> tuple[CorrelationContext, CorrelationResult | None]:
    """
    Integrate a finding into the correlation engine.

    This is the main integration point for the detection pipeline.
    Called after a detection rule produces a finding.

    Args:
        log_event: The source log event
        finding: The finding produced by detection
        tenant_id: Tenant ID (if known), otherwise resolved from source

    Returns:
        Tuple of (CorrelationContext, CorrelationResult or None)

    Raises:
        TenantResolutionError: If tenant cannot be resolved
    """
    # Resolve tenant from trusted source if not provided
    effective_tenant = tenant_id
    if not effective_tenant:
        effective_tenant = await resolve_tenant_from_source(log_event.source_id)

    if not effective_tenant:
        logger.warning(
            "Cannot correlate finding without tenant identity",
            event_id=log_event.id,
            finding_id=finding.finding_id,
            source_id=log_event.source_id,
        )
        raise TenantResolutionError(
            reason="Could not resolve tenant from source",
            source_id=log_event.source_id,
        )

    # Extract correlation context
    ctx = CorrelationContextExtractor.extract(
        log_event=log_event,
        tenant_id=effective_tenant,
        finding_id=finding.finding_id,
    )

    # Check if correlation is possible
    if not ctx.can_correlate():
        logger.debug(
            "Finding cannot correlate (no entities)",
            finding_id=finding.finding_id,
            tenant_id=effective_tenant,
        )
        return ctx, None

    # Log correlation context for observability
    logger.info(
        "Correlation context created",
        tenant_id=effective_tenant,
        event_id=log_event.id,
        finding_id=finding.finding_id,
        source_type=log_event.source_type.value if log_event.source_type else None,
        correlation_keys=ctx.get_correlation_keys(),
    )

    # For single-event correlation, we create the context and return it
    # The actual correlation with other events happens at a higher level
    # (e.g., when batching events or in the consumer)
    return ctx, None


def create_correlation_context_from_finding(
    log_event: LogEvent,
    finding: Finding,
    tenant_id: str,
) -> CorrelationContext:
    """
    Create a CorrelationContext from a log event and finding.

    Synchronous version for use in tests and non-async contexts.

    Args:
        log_event: Source log event
        finding: Detection finding
        tenant_id: Trusted tenant identifier

    Returns:
        CorrelationContext with normalized entities
    """
    validate_tenant_id(tenant_id, log_event.source_id)

    return CorrelationContextExtractor.extract(
        log_event=log_event,
        tenant_id=tenant_id,
        finding_id=finding.finding_id,
    )


# =============================================================================
# Singleton Correlator
# =============================================================================


_tenant_aware_correlator: TenantAwareCorrelator | None = None


def get_tenant_aware_correlator() -> TenantAwareCorrelator:
    """Get the singleton TenantAwareCorrelator."""
    global _tenant_aware_correlator
    if _tenant_aware_correlator is None:
        _tenant_aware_correlator = TenantAwareCorrelator()
    return _tenant_aware_correlator


def reset_tenant_aware_correlator() -> None:
    """Reset the singleton (for testing)."""
    global _tenant_aware_correlator
    _tenant_aware_correlator = None
