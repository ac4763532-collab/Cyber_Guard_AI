"""
CyberGuard AI - Windows Event Detection Processor

STEP 8.2/8.2.1/8.2.2: Redis-backed Windows Event Log detection processing.

This processor:
- Uses Redis-backed detection state (sorted sets for windowed tracking)
- Provides event and finding idempotency
- Supports multi-worker concurrent processing
- Survives worker restarts
- Fails safely when Redis is unavailable

Flow:
    WindowsCollector → LogEvent → SecurityEvent → Redpanda
                                                     ↓
    DetectionEngine ← WindowsDetectionProcessor ← Dispatcher
         ↓
    RuleMatch → Finding → AlertManager → PostgreSQL

STEP 8.2.2 Integration:
- This processor is now ACTIVATED in the runtime pipeline
- Redis-backed rules are the default (not in-memory)
- Finding fingerprints are deterministic and persisted
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.agents.base import Finding, Severity
from app.config import get_settings
from app.detection.rules.base import RuleMatch, RuleSeverity
from app.detection.state.redis_state import (
    DetectionStateManager,
    RedisUnavailableError,
)
from app.logs.models import LogEvent, LogSourceType


logger = structlog.get_logger(__name__)


# =============================================================================
# Severity Mapping
# =============================================================================

RULE_SEVERITY_TO_FINDING: dict[RuleSeverity, Severity] = {
    RuleSeverity.CRITICAL: Severity.CRITICAL,
    RuleSeverity.HIGH: Severity.HIGH,
    RuleSeverity.MEDIUM: Severity.MEDIUM,
    RuleSeverity.LOW: Severity.LOW,
    RuleSeverity.INFO: Severity.INFO,
}


# =============================================================================
# Windows Detection Processor - Redis-Backed
# =============================================================================


class WindowsDetectionProcessor:
    """
    Processes Windows Event Log events through Redis-backed detection rules.

    STEP 8.2.2: This is now the PRODUCTION processor that:
    - Uses Redis for shared detection state
    - Provides multi-worker safety
    - Survives restarts
    - Fails safely when Redis is unavailable

    Uses:
    - RedisWindowsFailedAuthBurstRule (WIN-001)
    - RedisWindowsAuthSequenceRule (WIN-002)
    - WindowsPrivilegedActivityRule (WIN-003, stateless)

    Does NOT:
    - Fall back silently to in-memory state
    - Create duplicate findings on event replay
    - Allow cross-tenant data access
    """

    def __init__(
        self,
        state_manager: DetectionStateManager,
        tenant_id: str = "default",
    ):
        """
        Initialize the processor with Redis state manager.

        Args:
            state_manager: Redis-backed state manager
            tenant_id: Tenant identifier for isolation
        """
        self._state_manager = state_manager
        self._tenant_id = tenant_id
        self._rules: dict[str, Any] = {}
        self._initialized = False

        settings = get_settings()
        self._detection_enabled = settings.windows_detection_enabled
        self._failed_auth_threshold = settings.windows_failed_auth_threshold
        self._failed_auth_window = settings.windows_failed_auth_window
        self._sequence_threshold = settings.windows_auth_sequence_threshold
        self._privileged_enabled = settings.windows_privileged_detection_enabled

        logger.info(
            "WindowsDetectionProcessor created",
            tenant_id=tenant_id,
            detection_enabled=self._detection_enabled,
        )

    async def initialize(self) -> None:
        """
        Initialize Redis-backed detection rules.

        Must be called before processing events.
        """
        if self._initialized:
            return

        if not self._detection_enabled:
            logger.info("Windows detection disabled by configuration")
            self._initialized = True
            return

        try:
            # Import here to avoid circular imports
            from app.detection.rules.windows_redis import create_redis_windows_rules
            from app.detection.rules.windows import WindowsPrivilegedActivityRule

            self._rules = await create_redis_windows_rules(
                state_manager=self._state_manager,
                failed_auth_threshold=self._failed_auth_threshold,
                failed_auth_window=self._failed_auth_window,
                sequence_threshold=self._sequence_threshold,
                enable_privileged_rule=self._privileged_enabled,
            )

            self._initialized = True

            logger.info(
                "WindowsDetectionProcessor initialized with Redis rules",
                rules=list(self._rules.keys()),
                tenant_id=self._tenant_id,
            )

        except RedisUnavailableError as e:
            logger.error(
                "Failed to initialize WindowsDetectionProcessor - Redis unavailable",
                error=str(e),
            )
            raise

    async def process_log_event(self, log_event: LogEvent) -> list[Finding]:
        """
        Process a LogEvent through Windows detection rules.

        Args:
            log_event: The LogEvent to analyze

        Returns:
            List of findings generated (may be empty)

        Raises:
            RedisUnavailableError: If Redis is not available
            RuntimeError: If processor not initialized
        """
        if not self._initialized:
            raise RuntimeError("WindowsDetectionProcessor not initialized. Call initialize() first.")

        # Only process Windows events
        if log_event.source_type != LogSourceType.WINDOWS_EVENT:
            return []

        if not self._detection_enabled:
            return []

        # Convert LogEvent to detection data format
        detection_data = self._prepare_detection_data(log_event)

        # Run through Redis-backed rules
        findings = []
        for rule_id, rule in self._rules.items():
            if not rule.enabled:
                continue

            try:
                # Use async evaluation for Redis-backed rules
                if hasattr(rule, "evaluate_async"):
                    match = await rule.evaluate_async(detection_data)
                else:
                    # Stateless rule (WIN-003)
                    match = rule.evaluate(detection_data)

                if match:
                    finding = self._rule_match_to_finding(match, log_event)
                    findings.append(finding)
                    logger.info(
                        "Windows detection finding",
                        rule_id=rule_id,
                        log_event_id=log_event.id,
                        source_event_id=log_event.source_event_id,
                        fingerprint=match.matched_data.get("fingerprint"),
                    )

            except RedisUnavailableError:
                # Re-raise Redis errors - don't silently continue
                logger.error(
                    "Redis unavailable during rule evaluation",
                    rule_id=rule_id,
                )
                raise

            except Exception as e:
                logger.error(
                    "Windows rule evaluation error",
                    rule_id=rule_id,
                    error=str(e),
                )
                # Continue with other rules for non-Redis errors

        return findings

    async def process_extracted_fields(
        self,
        extracted_fields: dict[str, Any],
        source_event_id: str | None = None,
        hostname: str | None = None,
        timestamp: datetime | None = None,
    ) -> list[Finding]:
        """
        Process extracted Windows event fields directly.

        Useful when processing events from the collector
        before they are wrapped in LogEvent.

        Args:
            extracted_fields: Fields extracted from Windows event
            source_event_id: Stable event identifier for idempotency
            hostname: Host the event came from
            timestamp: Event timestamp

        Returns:
            List of findings

        Raises:
            RedisUnavailableError: If Redis is not available
        """
        if not self._initialized:
            raise RuntimeError("WindowsDetectionProcessor not initialized")

        if not self._detection_enabled:
            return []

        # Add metadata to fields
        detection_data = {
            **extracted_fields,
            "source_event_id": source_event_id,
            "hostname": hostname or extracted_fields.get("computer_name"),
            "timestamp": timestamp or datetime.now(timezone.utc),
        }

        # Run through rules
        findings = []
        for rule_id, rule in self._rules.items():
            if not rule.enabled:
                continue

            try:
                if hasattr(rule, "evaluate_async"):
                    match = await rule.evaluate_async(detection_data)
                else:
                    match = rule.evaluate(detection_data)

                if match:
                    finding = self._rule_match_to_finding_standalone(
                        match,
                        source_event_id,
                        hostname,
                        timestamp,
                    )
                    findings.append(finding)

            except RedisUnavailableError:
                raise
            except Exception as e:
                logger.error(
                    "Windows rule evaluation error",
                    rule_id=rule_id,
                    error=str(e),
                )

        return findings

    def _prepare_detection_data(self, log_event: LogEvent) -> dict[str, Any]:
        """Convert LogEvent to detection rule input format."""
        data = {
            "event_id": log_event.id,
            "source_event_id": log_event.source_event_id,
            "source_id": log_event.source_id,
            "hostname": log_event.hostname,
            "timestamp": log_event.timestamp,
            "message": log_event.message,
            "level": log_event.level.value,
            "category": log_event.category,
            # Include all extracted fields
            **log_event.extracted_fields,
        }
        return data

    def _rule_match_to_finding(
        self,
        match: RuleMatch,
        log_event: LogEvent,
    ) -> Finding:
        """Convert RuleMatch to Finding model with fingerprint."""
        severity = RULE_SEVERITY_TO_FINDING.get(match.severity, Severity.MEDIUM)

        # Get fingerprint from matched_data (set by Redis rules)
        fingerprint = match.matched_data.get("fingerprint")

        # Build evidence dict
        evidence_dict = {
            "rule_id": match.rule_id,
            "rule_name": match.rule_name,
            "source_event_id": log_event.source_event_id,
            "log_event_id": log_event.id,
            "hostname": log_event.hostname,
            "source_id": log_event.source_id,
            "timestamp": log_event.timestamp.isoformat() if log_event.timestamp else None,
            "fingerprint": fingerprint,
            "tenant_id": self._tenant_id,
            **match.matched_data,
        }

        # Use fingerprint as finding_id for deterministic deduplication
        finding_id = fingerprint if fingerprint else str(uuid4())

        return Finding(
            finding_id=finding_id,
            rule_id=match.rule_id,
            name=match.rule_name,
            description=match.description,
            severity=severity,
            confidence=match.confidence,
            evidence=match.evidence,  # List of evidence strings
            mitre_techniques=match.mitre_techniques,
            recommendations=self._generate_recommendations(match),
            metadata=evidence_dict,
        )

    def _rule_match_to_finding_standalone(
        self,
        match: RuleMatch,
        source_event_id: str | None,
        hostname: str | None,
        timestamp: datetime | None,
    ) -> Finding:
        """Convert RuleMatch to Finding without LogEvent context."""
        severity = RULE_SEVERITY_TO_FINDING.get(match.severity, Severity.MEDIUM)

        fingerprint = match.matched_data.get("fingerprint")

        evidence_dict = {
            "rule_id": match.rule_id,
            "rule_name": match.rule_name,
            "source_event_id": source_event_id,
            "hostname": hostname,
            "timestamp": timestamp.isoformat() if timestamp else None,
            "fingerprint": fingerprint,
            "tenant_id": self._tenant_id,
            **match.matched_data,
        }

        finding_id = fingerprint if fingerprint else str(uuid4())

        return Finding(
            finding_id=finding_id,
            rule_id=match.rule_id,
            name=match.rule_name,
            description=match.description,
            severity=severity,
            confidence=match.confidence,
            evidence=match.evidence,
            mitre_techniques=match.mitre_techniques,
            recommendations=self._generate_recommendations(match),
            metadata=evidence_dict,
        )

    def _generate_recommendations(self, match: RuleMatch) -> list[str]:
        """Generate analyst recommendations based on rule match."""
        recommendations = []

        if match.rule_id == "WIN-001":
            recommendations = [
                "Review authentication logs for the affected user",
                "Check if the source IP is expected for this user",
                "Consider temporary account lockout if attack is ongoing",
                "Verify account has not been compromised",
            ]
        elif match.rule_id == "WIN-002":
            recommendations = [
                "Immediately investigate the successful login",
                "Verify the login was authorized",
                "Check for post-compromise activity",
                "Consider forcing password reset",
                "Review session activity following the login",
            ]
        elif match.rule_id == "WIN-003":
            recommendations = [
                "Verify this privileged activity was authorized",
                "Review what actions the privileged session performed",
                "Check if privileges align with the user's role",
            ]
        else:
            recommendations = [
                "Review the security event for context",
                "Verify activity is expected and authorized",
            ]

        return recommendations

    async def get_statistics(self) -> dict[str, Any]:
        """Get processor statistics."""
        stats = {
            "tenant_id": self._tenant_id,
            "initialized": self._initialized,
            "detection_enabled": self._detection_enabled,
            "rules": list(self._rules.keys()),
        }

        if self._initialized and self._state_manager:
            try:
                health = await self._state_manager.health_check()
                stats["redis_health"] = health
            except Exception as e:
                stats["redis_health"] = {"status": "error", "error": str(e)}

        return stats

    @property
    def is_redis_backed(self) -> bool:
        """Confirm this processor uses Redis-backed state."""
        return True

    @property
    def tenant_id(self) -> str:
        """Get the tenant ID."""
        return self._tenant_id


# =============================================================================
# Factory Functions
# =============================================================================

_processors: dict[str, WindowsDetectionProcessor] = {}


async def get_windows_detection_processor(
    tenant_id: str = "default",
) -> WindowsDetectionProcessor:
    """
    Get or create a Windows detection processor for a tenant.

    Args:
        tenant_id: Tenant identifier for isolation

    Returns:
        Initialized WindowsDetectionProcessor

    Raises:
        RedisUnavailableError: If Redis cannot be connected
    """
    global _processors

    if tenant_id in _processors:
        return _processors[tenant_id]

    # Import here to avoid circular imports
    from app.detection.state import get_detection_state_manager

    # Get or create state manager for this tenant
    state_manager = await get_detection_state_manager(tenant_id)

    # Create and initialize processor
    processor = WindowsDetectionProcessor(
        state_manager=state_manager,
        tenant_id=tenant_id,
    )
    await processor.initialize()

    _processors[tenant_id] = processor

    return processor


async def reset_windows_detection_processor(tenant_id: str | None = None) -> None:
    """
    Reset processor(s) for testing.

    Args:
        tenant_id: Specific tenant to reset, or None for all
    """
    global _processors

    if tenant_id:
        _processors.pop(tenant_id, None)
    else:
        _processors.clear()
