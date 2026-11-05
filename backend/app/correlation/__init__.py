"""
CyberGuard AI - Correlation Package

Cross-domain threat correlation engine.
"""

from app.correlation.alert_integration import (
    CorrelationAlertIntegration,
    compute_alert_fingerprint,
    get_correlation_alert_integration,
    get_integration_metrics,
    process_correlation_to_alert,
    reset_integration_metrics,
    reset_integrations_for_testing,
)
from app.correlation.finding_lifecycle import (
    get_lifecycle_metrics,
    on_finding_created,
    on_findings_created_batch,
    reset_lifecycle_metrics,
)
from app.correlation.context import (
    CorrelationContext,
    CorrelationContextExtractor,
    CorrelationEntityType,
    build_correlation_key,
    is_localhost_ip,
    normalize_hostname,
    normalize_ip_address,
    normalize_process_id,
    normalize_request_id,
    normalize_session_id,
    normalize_username,
    parse_correlation_key,
)
from app.correlation.engine import (
    CorrelatedGroup,
    Correlation,
    CorrelationEngine,
    CorrelationResult,
    CorrelationStrength,
    CorrelationType,
    EventData,
    get_correlation_engine,
)
from app.correlation.integration import (
    CorrelationContextAdapter,
    CorrelationIntegrationError,
    InvalidCorrelationDataError,
    TenantAwareCorrelator,
    TenantResolutionError,
    correlate_finding,
    create_correlation_context_from_finding,
    get_correlation_metrics,
    get_tenant_aware_correlator,
    reset_correlation_metrics,
    resolve_tenant_from_source,
    validate_tenant_id,
)
from app.correlation.realtime import (
    CorrelatedActivity,
    RealtimeCorrelationService,
    compute_correlation_fingerprint,
    get_correlation_bucket,
    get_realtime_correlation_service,
    get_realtime_metrics,
    reset_realtime_metrics,
    reset_realtime_services_for_testing,
)
from app.correlation.state import (
    CorrelationStateError,
    CorrelationStateManager,
    RedisCorrelationUnavailableError,
    close_correlation_state,
    get_correlation_state_manager,
    get_state_metrics,
    reset_correlation_state_for_testing,
    reset_state_metrics,
)

__all__ = [
    # Engine
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelatedGroup",
    "CorrelationType",
    "CorrelationStrength",
    "Correlation",
    "EventData",
    "get_correlation_engine",
    # Context (STEP 8.5.1)
    "CorrelationContext",
    "CorrelationContextExtractor",
    "CorrelationEntityType",
    "normalize_ip_address",
    "normalize_username",
    "normalize_hostname",
    "normalize_session_id",
    "normalize_request_id",
    "normalize_process_id",
    "is_localhost_ip",
    "build_correlation_key",
    "parse_correlation_key",
    # Integration (STEP 8.5.2)
    "CorrelationContextAdapter",
    "TenantAwareCorrelator",
    "CorrelationIntegrationError",
    "TenantResolutionError",
    "InvalidCorrelationDataError",
    "correlate_finding",
    "create_correlation_context_from_finding",
    "resolve_tenant_from_source",
    "validate_tenant_id",
    "get_tenant_aware_correlator",
    "get_correlation_metrics",
    "reset_correlation_metrics",
    # State (STEP 8.5.3)
    "CorrelationStateManager",
    "CorrelationStateError",
    "RedisCorrelationUnavailableError",
    "get_correlation_state_manager",
    "close_correlation_state",
    "get_state_metrics",
    "reset_state_metrics",
    "reset_correlation_state_for_testing",
    # Realtime (STEP 8.5.3)
    "RealtimeCorrelationService",
    "CorrelatedActivity",
    "compute_correlation_fingerprint",
    "get_correlation_bucket",
    "get_realtime_correlation_service",
    "get_realtime_metrics",
    "reset_realtime_metrics",
    "reset_realtime_services_for_testing",
    # Alert/Incident Integration (STEP 8.5.4)
    "CorrelationAlertIntegration",
    "compute_alert_fingerprint",
    "get_correlation_alert_integration",
    "get_integration_metrics",
    "reset_integration_metrics",
    "reset_integrations_for_testing",
    "process_correlation_to_alert",
    # Finding Lifecycle (STEP 8.5.4.1)
    "on_finding_created",
    "on_findings_created_batch",
    "get_lifecycle_metrics",
    "reset_lifecycle_metrics",
]
