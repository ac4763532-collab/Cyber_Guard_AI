"""
CyberGuard AI - Windows Detection Integration

STEP 8.2.2: Activates Redis-backed Windows detection in the runtime pipeline.
STEP 8.5.3: Automatic real-time correlation on finding creation.

This module integrates WindowsDetectionProcessor into the event flow:
- Routes Windows events to Redis-backed detection rules
- Converts findings to alerts via existing AlertManager
- Handles finding/alert idempotency with PostgreSQL
- Triggers real-time correlation automatically on findings

Integration Point:
    Redpanda (security-events, source_type=windows_event)
           ↓
    handle_windows_log_event()
           ↓
    WindowsDetectionProcessor (Redis-backed)
           ↓
    Finding (deterministic fingerprint)
           ↓
    create_finding_with_dedup() → PostgreSQL
           ↓
    trigger_realtime_correlation() → Redis + CorrelationEngine  [STEP 8.5.3]
           ↓
    create_alert_with_dedup() → PostgreSQL
"""

from datetime import datetime, timezone
import json
from typing import Any
from uuid import uuid4

import structlog

from app.agents.base import Finding, Severity
from app.config import get_settings
from app.database.models.base import SeverityLevel
from app.detection.state.redis_state import RedisUnavailableError
from app.event_bus.events import SecurityEvent
from app.logs.event_bus_integration import (
    UnsupportedSourceTypeError,
    security_event_to_log_event,
)
from app.logs.models import LogEvent, LogSourceType

logger = structlog.get_logger(__name__)


# =============================================================================
# Severity Mapping
# =============================================================================

FINDING_SEVERITY_TO_DB: dict[Severity, SeverityLevel] = {
    Severity.CRITICAL: SeverityLevel.CRITICAL,
    Severity.HIGH: SeverityLevel.HIGH,
    Severity.MEDIUM: SeverityLevel.MEDIUM,
    Severity.LOW: SeverityLevel.LOW,
    Severity.INFO: SeverityLevel.INFO,
}


# =============================================================================
# Windows Event Detection Handler
# =============================================================================


async def handle_windows_log_event(
    event: SecurityEvent,
    tenant_id: str = "default",
) -> dict[str, Any] | None:
    """
    Handle a Windows log event through the Redis-backed detection pipeline.

    This is the ACTIVATED production path for Windows event detection.

    Flow:
    1. Extract LogEvent from SecurityEvent
    2. Validate it's a Windows event
    3. Process through WindowsDetectionProcessor (Redis-backed)
    4. Create findings with deduplication
    5. Create alerts with deduplication
    6. Return results

    Args:
        event: SecurityEvent from Redpanda
        tenant_id: Tenant identifier for isolation

    Returns:
        Detection results dict, or None if not a Windows event

    Raises:
        RedisUnavailableError: If Redis is unavailable (fail-safe)
    """
    if event.event_type != "log":
        return None

    # Extract source_type from payload
    payload = event.payload or {}
    source_type = payload.get("source_type")

    if source_type != LogSourceType.WINDOWS_EVENT.value:
        # Not a Windows event - let normal LogAgent handle it
        return None

    logger.info(
        "Processing Windows event through detection pipeline",
        event_id=event.event_id,
        source_type=source_type,
    )

    try:
        # Extract LogEvent
        log_event = security_event_to_log_event(event)
        if not log_event:
            logger.warning(
                "Failed to extract LogEvent from Windows SecurityEvent",
                event_id=event.event_id,
            )
            return None

        # Get Windows detection processor
        from app.detection.windows_processor import get_windows_detection_processor

        processor = await get_windows_detection_processor(tenant_id)

        # Process through Redis-backed detection
        findings = await processor.process_log_event(log_event)

        logger.info(
            "Windows event processed",
            event_id=event.event_id,
            log_event_id=log_event.id,
            findings_count=len(findings),
        )

        # Persist findings and create alerts
        persisted_findings = []
        created_alerts = []

        for finding in findings:
            # Create finding with deduplication
            finding_result = await create_finding_with_dedup(
                finding=finding,
                log_event=log_event,
                tenant_id=tenant_id,
            )

            if finding_result:
                persisted_findings.append(finding_result)

                # STEP 8.5.3: Trigger real-time correlation automatically
                correlation_result = await trigger_realtime_correlation(
                    finding=finding,
                    log_event=log_event,
                    tenant_id=tenant_id,
                )
                if correlation_result:
                    logger.info(
                        "Correlation triggered for finding",
                        finding_id=finding.finding_id,
                        correlation_id=correlation_result.get("correlation_id"),
                    )

                # Create alert for significant findings
                if finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                    alert_result = await create_alert_with_dedup(
                        finding=finding,
                        log_event=log_event,
                        tenant_id=tenant_id,
                    )
                    if alert_result:
                        created_alerts.append(alert_result)

        return {
            "event_id": event.event_id,
            "log_event_id": log_event.id,
            "source_type": source_type,
            "findings_count": len(findings),
            "persisted_findings": len(persisted_findings),
            "alerts_created": len(created_alerts),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "name": f.name,
                }
                for f in findings
            ],
        }

    except UnsupportedSourceTypeError as e:
        logger.error(
            "Unsupported source type in Windows event",
            event_id=event.event_id,
            source_type=e.source_type,
        )
        return None

    except RedisUnavailableError as e:
        # Fail safely - don't silently continue without detection state
        logger.error(
            "Redis unavailable for Windows detection - failing safely",
            event_id=event.event_id,
            error=str(e),
        )
        raise

    except Exception as e:
        logger.exception(
            "Error processing Windows event",
            event_id=event.event_id,
            error=str(e),
        )
        return None


# =============================================================================
# Finding Persistence with Deduplication
# =============================================================================


async def create_finding_with_dedup(
    finding: Finding,
    log_event: LogEvent,
    tenant_id: str,
) -> dict[str, Any] | None:
    """
    Create a finding in PostgreSQL with deduplication.

    Uses the finding's fingerprint (finding_id) to prevent duplicates.
    If a finding with the same fingerprint exists, returns None (duplicate).

    Args:
        finding: Finding to persist
        log_event: Source log event
        tenant_id: Tenant identifier

    Returns:
        Created finding dict, or None if duplicate
    """
    try:
        from app.database.connection import get_database

        db = get_database()

        # Get fingerprint from finding metadata or finding_id
        fingerprint = finding.metadata.get("fingerprint") or finding.finding_id

        # Try to insert - use ON CONFLICT to handle race conditions
        # This is the authoritative deduplication layer
        query = """
            INSERT INTO findings (
                id, event_id, detection_id, finding_type, rule_id,
                severity, confidence, title, description, evidence,
                mitre_tactics, mitre_techniques, created_at
            )
            SELECT
                %(id)s, NULL, %(detection_id)s, %(finding_type)s, %(rule_id)s,
                %(severity)s, %(confidence)s, %(title)s, %(description)s, %(evidence)s,
                %(mitre_tactics)s, %(mitre_techniques)s, %(created_at)s
            WHERE NOT EXISTS (
                SELECT 1 FROM findings WHERE id = %(id)s
            )
            RETURNING id
        """

        result = await db.execute_one(query, {
            "id": fingerprint,  # Use fingerprint as ID for deduplication
            "detection_id": str(uuid4()),
            "finding_type": "rule",
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "title": finding.name,
            "description": finding.description,
            "evidence": json.dumps(finding.metadata),  # Serialize dict to JSON string
            "mitre_tactics": [],
            "mitre_techniques": finding.mitre_techniques,
            "created_at": datetime.now(timezone.utc),
        })

        if result:
            logger.info(
                "Finding persisted",
                finding_id=fingerprint,
                rule_id=finding.rule_id,
            )
            return {"finding_id": fingerprint, "created": True}
        else:
            logger.debug(
                "Duplicate finding skipped",
                finding_id=fingerprint,
                rule_id=finding.rule_id,
            )
            return None

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        # Check if it's a duplicate key error
        error_str = str(e).lower()
        if "duplicate" in error_str or "unique" in error_str:
            logger.debug(
                "Finding already exists (race condition handled)",
                finding_id=finding.finding_id,
            )
            return None

        logger.error(
            "Failed to persist finding",
            finding_id=finding.finding_id,
            error=str(e),
        )
        return None


# =============================================================================
# Alert Creation with Deduplication
# =============================================================================


async def create_alert_with_dedup(
    finding: Finding,
    log_event: LogEvent,
    tenant_id: str,
) -> dict[str, Any] | None:
    """
    Create an alert in PostgreSQL with deduplication.

    STEP 8.5.4.2: Uses separate UUID id and fingerprint columns.
    Deduplication via UNIQUE(tenant_id, fingerprint) constraint.

    Args:
        finding: Finding that triggered the alert
        log_event: Source log event
        tenant_id: Tenant identifier

    Returns:
        Created alert dict, or None if duplicate
    """
    try:
        import hashlib

        # Get fingerprint from finding metadata
        finding_fingerprint = finding.metadata.get("fingerprint") or finding.finding_id

        # Compute alert fingerprint using SHA-256 (deterministic)
        # Format: alert:{tenant_id}:{finding_fingerprint}
        canonical = f"alert:{tenant_id}:{finding_fingerprint}"
        alert_fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:32]

        # Convert severity
        severity = FINDING_SEVERITY_TO_DB.get(finding.severity, SeverityLevel.MEDIUM)

        # Calculate risk score based on severity
        risk_scores = {
            Severity.CRITICAL: 95,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }
        risk_score = risk_scores.get(finding.severity, 50)

        # Build alert title and description
        username = finding.metadata.get("username", "unknown")
        source_ip = finding.metadata.get("source_ip", "unknown")

        title = f"{finding.name}: {username}"
        if source_ip and source_ip != "unknown":
            title += f" from {source_ip}"

        description = finding.description
        if finding.recommendations:
            description += "\n\nRecommendations:\n" + "\n".join(f"- {r}" for r in finding.recommendations)

        from app.database.connection import get_database

        db = get_database()

        # STEP 8.5.4.2: Use separate UUID id and fingerprint columns
        # ON CONFLICT provides atomic deduplication via unique constraint
        query = """
            INSERT INTO alerts (
                id, fingerprint, tenant_id,
                title, description, severity, risk_score,
                finding_ids, source_ips, mitre_techniques,
                created_at, updated_at
            )
            VALUES (
                gen_random_uuid(), %(fingerprint)s, %(tenant_id)s,
                %(title)s, %(description)s, %(severity)s, %(risk_score)s,
                %(finding_ids)s, %(source_ips)s, %(mitre_techniques)s,
                %(created_at)s, %(updated_at)s
            )
            ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                updated_at = EXCLUDED.updated_at
            RETURNING id, (xmax = 0) AS inserted
        """

        now = datetime.now(timezone.utc)

        # Parse source_ip for INET array
        source_ips = []
        if source_ip and source_ip != "unknown":
            source_ips = [source_ip]

        result = await db.execute_one(query, {
            "fingerprint": alert_fingerprint,
            "tenant_id": tenant_id,
            "title": title,
            "description": description,
            "severity": severity.value,
            "risk_score": risk_score,
            "finding_ids": [finding_fingerprint],
            "source_ips": source_ips,
            "mitre_techniques": finding.mitre_techniques,
            "created_at": now,
            "updated_at": now,
        })

        if result:
            alert_id = str(result["id"])
            was_inserted = result.get("inserted", True)

            if was_inserted:
                logger.info(
                    "Alert created",
                    alert_id=alert_id,
                    fingerprint=alert_fingerprint,
                    tenant_id=tenant_id,
                    rule_id=finding.rule_id,
                    severity=severity.value,
                )
                return {"alert_id": alert_id, "created": True}
            else:
                logger.debug(
                    "Duplicate alert updated timestamp",
                    alert_id=alert_id,
                    fingerprint=alert_fingerprint,
                )
                return {"alert_id": alert_id, "created": False}
        else:
            logger.warning(
                "Alert insert returned no result",
                fingerprint=alert_fingerprint,
            )
            return None

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        # Check if it's a duplicate key error
        error_str = str(e).lower()
        if "duplicate" in error_str or "unique" in error_str:
            logger.debug(
                "Alert already exists (race condition handled)",
                finding_id=finding.finding_id,
            )
            return None

        logger.error(
            "Failed to create alert",
            finding_id=finding.finding_id,
            error=str(e),
        )
        return None


# =============================================================================
# Enhanced Dispatcher Integration
# =============================================================================


async def process_security_event_with_windows_detection(
    event: SecurityEvent,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """
    Enhanced event handler that routes Windows events to specialized detection.

    This function should be called from the event consumer to process events.
    It routes Windows events to the Redis-backed WindowsDetectionProcessor,
    while other events go through the standard LogAgent path.

    Args:
        event: SecurityEvent from Redpanda
        tenant_id: Tenant identifier

    Returns:
        Processing results dict
    """
    # Check if this is a Windows event
    payload = event.payload or {}
    source_type = payload.get("source_type")

    if event.event_type == "log" and source_type == LogSourceType.WINDOWS_EVENT.value:
        # Route to Windows detection pipeline
        result = await handle_windows_log_event(event, tenant_id)
        if result:
            return {
                "handler": "windows_detection",
                "tenant_id": tenant_id,
                **result,
            }

    # Fall through to standard processing
    return {
        "handler": "standard",
        "event_id": event.event_id,
        "event_type": event.event_type,
        "source_type": source_type,
    }


# =============================================================================
# Metrics and Observability
# =============================================================================

_detection_metrics = {
    "events_processed": 0,
    "findings_created": 0,
    "alerts_created": 0,
    "duplicates_skipped": 0,
    "redis_errors": 0,
    "processing_errors": 0,
}


def get_windows_detection_metrics() -> dict[str, int]:
    """Get detection metrics for observability."""
    return _detection_metrics.copy()


def reset_windows_detection_metrics() -> None:
    """Reset metrics (for testing)."""
    global _detection_metrics
    _detection_metrics = {
        "events_processed": 0,
        "findings_created": 0,
        "alerts_created": 0,
        "duplicates_skipped": 0,
        "redis_errors": 0,
        "processing_errors": 0,
    }


# =============================================================================
# Real-Time Correlation Trigger (STEP 8.5.3 / 8.5.4.1)
# =============================================================================


async def trigger_realtime_correlation(
    finding: Finding,
    log_event: LogEvent,
    tenant_id: str,
) -> dict[str, Any] | None:
    """
    Automatically trigger real-time correlation when a finding is created.

    STEP 8.5.4.1: Uses the COMMON finding lifecycle hook for all downstream
    processing (correlation → alert → incident).

    This is the AUTOMATIC correlation hook - no manual API call required.
    Called from handle_windows_log_event() after finding persistence.

    Behavior:
    - If correlation is disabled: returns None silently
    - If Redis unavailable: logs error and returns None (does not block finding)
    - If correlation found: returns correlation metadata
    - If no correlation: returns None

    Args:
        finding: The newly created finding
        log_event: Source log event
        tenant_id: Tenant identifier (from trusted source)

    Returns:
        Correlation result dict, or None
    """
    settings = get_settings()

    # Check if correlation is enabled
    if not getattr(settings, 'correlation_enabled', True):
        return None

    try:
        # STEP 8.5.4.1: Use common finding lifecycle hook
        from app.correlation.finding_lifecycle import on_finding_created

        result = await on_finding_created(
            log_event=log_event,
            finding=finding,
            tenant_id=tenant_id,
        )

        if result.get("correlation_id"):
            logger.info(
                "Finding processed through lifecycle hook",
                finding_id=finding.finding_id,
                correlation_id=result.get("correlation_id"),
                alert_id=result.get("alert_id"),
                incident_id=result.get("incident_id"),
                source_type=result.get("source_type"),
            )

            return {
                "correlation_id": result["correlation_id"],
                "alert_id": result.get("alert_id"),
                "incident_id": result.get("incident_id"),
                "source_type": result.get("source_type"),
                "errors": result.get("errors", []),
            }

        return None

    except ImportError as e:
        # Correlation module not available - this is fine
        logger.debug(
            "Finding lifecycle module not available",
            error=str(e),
        )
        return None

    except (OSError, ValueError, RuntimeError) as e:
        # Lifecycle errors - log but don't block
        logger.error(
            "Finding lifecycle error - skipping",
            finding_id=finding.finding_id,
            error=str(e),
        )
        return None


async def _persist_correlated_activity(activity: Any) -> None:
    """
    Persist a correlated activity to PostgreSQL.

    Uses the existing database connection and repository.

    Args:
        activity: CorrelatedActivity to persist
    """
    try:
        from app.database.connection import get_database
        from app.database.repositories.correlated_activities import (
            CorrelatedActivityRepository,
        )

        db = get_database()
        repo = CorrelatedActivityRepository(db)

        await repo.create(activity)

        logger.debug(
            "Correlated activity persisted",
            correlation_id=activity.correlation_id,
        )

    except ImportError:
        # Repository not available
        logger.debug("CorrelatedActivityRepository not available")

    except (OSError, ValueError, RuntimeError) as e:
        # Log but don't fail
        logger.warning(
            "Failed to persist correlated activity",
            correlation_id=activity.correlation_id,
            error=str(e),
        )
