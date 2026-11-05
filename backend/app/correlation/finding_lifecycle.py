"""
CyberGuard AI - Common Finding Lifecycle Hook (STEP 8.5.4.1)

Provides a SINGLE authoritative downstream trigger for all finding sources.

Architecture:
    Any Source (Windows, Linux, Web)
           ↓
    Detection (Agent or WindowsProcessor)
           ↓
    Finding Created
           ↓
    on_finding_created()  ← THIS MODULE (COMMON HOOK)
           ↓
    Correlation (if enabled)
           ↓
    CorrelatedActivity
           ↓
    Alert

Key Principles:
- ONE authoritative hook for all sources
- Source-agnostic - works with any finding
- Fail-safe - finding persists even if downstream fails
- Tenant isolation at every layer
- Atomic operations for concurrent safety

Usage:
    from app.correlation.finding_lifecycle import on_finding_created

    # After creating a finding from ANY source
    result = await on_finding_created(
        log_event=log_event,
        finding=finding,
        tenant_id=tenant_id,
    )

This replaces direct calls to trigger_realtime_correlation() in individual
detection modules, providing a unified entry point.
"""

from typing import Any

import structlog

from app.agents.base import Finding, Severity

logger = structlog.get_logger(__name__)


# =============================================================================
# Individual Alert Policy
# =============================================================================

# Minimum finding severity that always produces its own alert, independent
# of whether cross-agent correlation finds a relationship. This is what
# makes "one agent finds something suspicious -> an alert exists" true even
# when nothing else correlates with it - previously _trigger_alerting() was
# only ever reached when RealtimeCorrelationService returned a
# CorrelatedActivity, so a lone high-severity finding with no correlation
# partner never produced an alert at all.
INDIVIDUAL_ALERT_MIN_SEVERITY = Severity.MEDIUM

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _meets_individual_alert_threshold(severity: Severity) -> bool:
    """Whether a finding's severity is high enough to always get its own
    alert, regardless of correlation outcome."""
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK[INDIVIDUAL_ALERT_MIN_SEVERITY]


# =============================================================================
# Metrics
# =============================================================================

_lifecycle_metrics = {
    "findings_received": 0,
    "findings_from_windows": 0,
    "findings_from_linux": 0,
    "findings_from_android": 0,
    "findings_from_other": 0,
    "correlation_triggered": 0,
    "correlation_skipped": 0,
    "correlation_failed": 0,
    "individual_alerts_created": 0,
    "individual_alerts_deduplicated": 0,
    "alerts_created": 0,
    "downstream_errors": 0,
}


def get_lifecycle_metrics() -> dict[str, int]:
    """Get lifecycle metrics."""
    return _lifecycle_metrics.copy()


def reset_lifecycle_metrics() -> None:
    """Reset metrics (for testing)."""
    global _lifecycle_metrics
    _lifecycle_metrics = {
        "findings_received": 0,
        "findings_from_windows": 0,
        "findings_from_linux": 0,
        "findings_from_android": 0,
        "findings_from_other": 0,
        "correlation_triggered": 0,
        "correlation_skipped": 0,
        "correlation_failed": 0,
        "individual_alerts_created": 0,
        "individual_alerts_deduplicated": 0,
        "alerts_created": 0,
        "downstream_errors": 0,
    }


def _increment_metric(name: str, value: int = 1) -> None:
    """Increment a metric counter."""
    if name in _lifecycle_metrics:
        _lifecycle_metrics[name] += value


# =============================================================================
# Source Type Detection
# =============================================================================


def _detect_source_type(log_event: Any) -> str:
    """
    Detect the source type from a log event.

    Returns one of: windows, linux, android, other
    """
    if not log_event:
        return "other"

    source_type = getattr(log_event, "source_type", None)
    if source_type:
        source_str = source_type.value if hasattr(source_type, "value") else str(source_type)
        source_lower = source_str.lower()

        if "windows" in source_lower:
            return "windows"
        if "linux" in source_lower or "ssh" in source_lower or "syslog" in source_lower:
            return "linux"
        if "android" in source_lower or "adb" in source_lower:
            return "android"
        # Email/network findings arrive via _create_log_event_from_security_event()
        # (app/event_bus/dispatcher_integration.py), whose adapter's
        # source_type is now (after _normalize_source_type's EMAIL/NETWORK
        # cases) an enum whose .value is literally "email"/"network" -
        # recognize those explicitly so _alert_category_for_source maps
        # them to email_security/network_security instead of falling
        # through to "other" -> log_security.
        if "email" in source_lower:
            return "email"
        if "network" in source_lower:
            return "network"

    return "other"


# =============================================================================
# Common Finding Lifecycle Hook
# =============================================================================


async def on_finding_created(
    log_event: Any,
    finding: Finding,
    tenant_id: str,
    *,
    skip_correlation: bool = False,
    skip_alerting: bool = False,
) -> dict[str, Any]:
    """
    Process a newly created finding through the common downstream pipeline.

    This is the SINGLE authoritative hook for all finding sources.
    Call this after a finding is created from ANY detection path.

    The function is fail-safe:
    - Finding is already persisted before this is called
    - Correlation failure does not lose the finding
    - Alert failure does not lose the CorrelatedActivity

    Args:
        log_event: The source log event (LogEvent or similar)
        finding: The newly created Finding
        tenant_id: Tenant identifier (from trusted source)
        skip_correlation: If True, skip correlation (for testing)
        skip_alerting: If True, skip alert creation (for testing)

    Returns:
        Result dict with:
        - finding_id: The finding ID
        - correlation_id: If correlation found
        - alert_id: If alert created
        - source_type: Detected source type
        - errors: List of non-fatal errors
    """
    _increment_metric("findings_received")

    # Track source type
    source_type = _detect_source_type(log_event)
    _increment_metric(f"findings_from_{source_type}")

    result: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "tenant_id": tenant_id,
        "source_type": source_type,
        "correlation_id": None,
        "individual_alert_id": None,
        "alert_id": None,
        "errors": [],
    }

    # Validate tenant
    if not tenant_id or not tenant_id.strip():
        logger.error(
            "Finding lifecycle: missing tenant_id",
            finding_id=finding.finding_id,
        )
        result["errors"].append("Missing tenant_id")
        return result

    # Step 1: Individual alert - fires on this finding alone whenever its
    # severity meets the policy threshold, regardless of whether anything
    # correlates with it. This must not wait on or depend on correlation:
    # a single-agent detection is required to alert on its own (see
    # INDIVIDUAL_ALERT_MIN_SEVERITY above).
    if not skip_alerting and _meets_individual_alert_threshold(finding.severity):
        individual_result = await _trigger_individual_alert(
            log_event=log_event,
            finding=finding,
            tenant_id=tenant_id,
            source_type=source_type,
        )
        result["individual_alert_id"] = individual_result.get("alert_id")
        if individual_result.get("error"):
            result["errors"].append(f"Individual alert: {individual_result['error']}")

    # Step 2: Correlation (if enabled)
    if not skip_correlation:
        correlation_result = await _trigger_correlation(
            log_event=log_event,
            finding=finding,
            tenant_id=tenant_id,
        )

        if correlation_result.get("error"):
            result["errors"].append(f"Correlation: {correlation_result['error']}")
        else:
            result["correlation_id"] = correlation_result.get("correlation_id")
            activity = correlation_result.get("activity")

            # Step 3: Correlated alert/incident (if correlation found and
            # alerting enabled). This is a SEPARATE alert from the
            # individual one above - it is never a substitute for it, and
            # the individual alert (if any) is never removed or replaced
            # when a correlated alert is also created for the same finding.
            if activity and not skip_alerting:
                alert_result = await _trigger_alerting(
                    activity=activity,
                    tenant_id=tenant_id,
                )

                result["alert_id"] = alert_result.get("alert_id")

                if alert_result.get("errors"):
                    result["errors"].extend(alert_result["errors"])

    logger.info(
        "Finding lifecycle complete",
        finding_id=finding.finding_id,
        tenant_id=tenant_id,
        source_type=source_type,
        correlation_id=result["correlation_id"],
        alert_id=result["alert_id"],
        error_count=len(result["errors"]),
    )

    return result


async def _trigger_correlation(
    log_event: Any,
    finding: Finding,
    tenant_id: str,
) -> dict[str, Any]:
    """
    Trigger correlation for a finding.

    Fail-safe: errors are caught and returned, not raised.
    """
    try:
        from app.correlation.realtime import (
            get_realtime_correlation_service,
        )
        from app.correlation.state import RedisCorrelationUnavailableError

        service = await get_realtime_correlation_service(tenant_id)
        activity = await service.on_finding_created(
            log_event=log_event,
            finding=finding,
        )

        if activity:
            _increment_metric("correlation_triggered")

            # Persist CorrelatedActivity BEFORE downstream operations
            try:
                await _persist_correlated_activity(activity)
            except (OSError, ValueError, RuntimeError) as persist_err:
                # Log but continue - activity object is still valid
                logger.warning(
                    "Failed to persist correlated activity",
                    correlation_id=activity.correlation_id,
                    error=str(persist_err),
                )

            return {
                "correlation_id": activity.correlation_id,
                "activity": activity,
            }
        else:
            _increment_metric("correlation_skipped")
            return {"correlation_id": None, "activity": None}

    except RedisCorrelationUnavailableError as e:
        _increment_metric("correlation_failed")
        logger.error(
            "Redis unavailable for correlation",
            finding_id=finding.finding_id,
            error=str(e),
        )
        return {"error": f"Redis unavailable: {e}"}

    except ImportError as e:
        _increment_metric("correlation_skipped")
        logger.debug(
            "Correlation module not available",
            error=str(e),
        )
        return {"error": None}  # Not an error, just not available

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        _increment_metric("correlation_failed")
        logger.error(
            "Correlation error",
            finding_id=finding.finding_id,
            error=str(e),
        )
        return {"error": str(e)}


def compute_individual_alert_fingerprint(finding_id: str, tenant_id: str) -> str:
    """
    Compute the dedup fingerprint for a single-finding (non-correlated)
    alert. Deliberately uses a different prefix than
    app.correlation.alert_integration.compute_alert_fingerprint() (which is
    keyed on a *correlation* fingerprint) so an individual alert and a
    correlated alert can never collide on the alerts.UNIQUE(tenant_id,
    fingerprint) constraint even if they end up covering the same finding.
    """
    import hashlib

    canonical = f"individual_alert:{tenant_id}:{finding_id}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


async def _trigger_individual_alert(
    log_event: Any,
    finding: Finding,
    tenant_id: str,
    source_type: str,
) -> dict[str, Any]:
    """
    Create (or find, if already created) the standalone alert for a single
    finding - independent of correlation. Fail-safe: errors are caught and
    returned, not raised, so a failure here never loses the finding or
    blocks the correlation step that runs after this one.
    """
    try:
        from app.database.connection import get_database
        from app.database.models import AlertStatus

        db = get_database()
        fingerprint = compute_individual_alert_fingerprint(finding.finding_id, tenant_id)

        existing = await db.execute_one(
            "SELECT id FROM alerts WHERE tenant_id = %(tenant_id)s AND fingerprint = %(fingerprint)s",
            {"tenant_id": tenant_id, "fingerprint": fingerprint},
        )
        if existing:
            _increment_metric("individual_alerts_deduplicated")
            return {"alert_id": str(existing["id"])}

        category = _alert_category_for_source(source_type)
        title = f"{category.replace('_', ' ').title()}: {finding.name}"
        description = finding.description or finding.name
        source_ip = [finding.source_ip] if getattr(finding, "source_ip", None) else []
        affected_assets = [finding.host] if getattr(finding, "host", None) else []

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        result = await db.execute_one(
            """
            INSERT INTO alerts (
                id, fingerprint, tenant_id, category,
                title, description, severity, risk_score,
                finding_ids, source_ips, affected_assets,
                mitre_techniques, status, created_at, updated_at
            )
            VALUES (
                gen_random_uuid(), %(fingerprint)s, %(tenant_id)s, %(category)s,
                %(title)s, %(description)s, %(severity)s, %(risk_score)s,
                %(finding_ids)s, %(source_ips)s, %(affected_assets)s,
                %(mitre_techniques)s, %(status)s, %(created_at)s, %(updated_at)s
            )
            ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                updated_at = EXCLUDED.updated_at
            RETURNING id
            """,
            {
                "fingerprint": fingerprint,
                "tenant_id": tenant_id,
                "category": category,
                "title": title,
                "description": description,
                "severity": finding.severity.value,
                "risk_score": int(finding.confidence * 100),
                "finding_ids": [finding.finding_id],
                "source_ips": source_ip,
                "affected_assets": affected_assets,
                "mitre_techniques": finding.mitre_techniques,
                "status": AlertStatus.NEW.value,
                "created_at": now,
                "updated_at": now,
            },
        )

        if not result:
            return {"alert_id": None, "error": "Alert insert returned no result"}

        alert_id = str(result["id"])
        _increment_metric("individual_alerts_created")
        logger.info(
            "Individual alert created",
            alert_id=alert_id,
            finding_id=finding.finding_id,
            tenant_id=tenant_id,
            category=category,
            severity=finding.severity.value,
        )

        await _notify_individual_alert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            severity=finding.severity,
            title=title,
            summary=description,
        )

        return {"alert_id": alert_id}

    except ImportError as e:
        logger.debug("Individual alert module not available", error=str(e))
        return {"alert_id": None, "error": None}

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        error_str = str(e).lower()
        if "duplicate" in error_str or "unique" in error_str:
            # Race: another worker inserted the same fingerprint first.
            try:
                from app.database.connection import get_database
                db = get_database()
                fingerprint = compute_individual_alert_fingerprint(finding.finding_id, tenant_id)
                existing = await db.execute_one(
                    "SELECT id FROM alerts WHERE tenant_id = %(tenant_id)s AND fingerprint = %(fingerprint)s",
                    {"tenant_id": tenant_id, "fingerprint": fingerprint},
                )
                if existing:
                    return {"alert_id": str(existing["id"])}
            except (OSError, ValueError, RuntimeError, KeyError):
                pass

        _increment_metric("downstream_errors")
        logger.error(
            "Failed to create individual alert",
            finding_id=finding.finding_id,
            tenant_id=tenant_id,
            error=str(e),
        )
        return {"alert_id": None, "error": str(e)}


def _alert_category_for_source(source_type: str) -> str:
    """Map a detected source type to the alert category taxonomy the
    frontend filters on: email_security / log_security / network_security.
    `source_type` here is whatever _detect_source_type()/the caller already
    resolved (windows/linux/android -> log; email/network pass through)."""
    if source_type in ("windows", "linux", "android", "log"):
        return "log_security"
    if source_type == "email":
        return "email_security"
    if source_type == "network":
        return "network_security"
    return "log_security"


async def _notify_individual_alert(
    alert_id: str,
    tenant_id: str,
    severity: Severity,
    title: str,
    summary: str,
) -> None:
    """
    Deliver a notification for a newly created individual alert, reusing
    the same recipient-resolution and NotificationService call that
    app.correlation.alert_integration.CorrelationAlertIntegration already
    uses for correlated alerts - same channel, same fail-safe contract
    (a delivery failure here never undoes the alert that was already
    persisted).
    """
    try:
        from app.auth.users import get_user_manager
        from app.database.models import SeverityLevel
        from app.services.notifications.service import get_notification_service

        manager = get_user_manager()
        all_users = await manager.list_users_async()
        recipients = [u for u in all_users if u.is_active and u.organization_id == tenant_id]

        if not recipients:
            logger.debug(
                "No notification recipients resolved for individual alert",
                tenant_id=tenant_id,
                alert_id=alert_id,
            )
            return

        service = get_notification_service()
        severity_level = SeverityLevel(severity.value)

        for user in recipients:
            await service.notify(
                source_id=alert_id,
                source_type="alert",
                tenant_id=tenant_id,
                recipient_user_id=user.id,
                recipient_email=user.email,
                severity=severity_level,
                title=title,
                summary=summary,
            )

    except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError, AttributeError) as e:
        logger.error(
            "Notification delivery failed for individual alert (alert persisted regardless)",
            alert_id=alert_id,
            tenant_id=tenant_id,
            error=str(e),
        )

    # Real-time popup delivery to any connected clients for this tenant.
    # Deliberately its own try/except, independent of the notification-inbox
    # block above: a WebSocket fan-out failure must never be mistaken for
    # (or mask) a notification-delivery failure, and neither can undo the
    # alert row that is already persisted at this point.
    try:
        from app.websocket.events import broadcast_alert_to_tenant

        await broadcast_alert_to_tenant(
            tenant_id=tenant_id,
            alert_id=alert_id,
            title=title,
            severity=severity.value,
            additional_data={"summary": summary},
        )
    except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError, AttributeError) as e:
        logger.error(
            "Real-time broadcast failed for individual alert (alert persisted regardless)",
            alert_id=alert_id,
            tenant_id=tenant_id,
            error=str(e),
        )


async def _persist_correlated_activity(activity: Any) -> None:
    """
    Persist a correlated activity to PostgreSQL.

    This ensures CorrelatedActivity is durable BEFORE alert/incident creation.
    """
    try:
        from app.database.connection import get_database

        db = get_database()

        query = """
            INSERT INTO correlated_activities (
                correlation_id, fingerprint, tenant_id,
                finding_ids, event_ids, source_types,
                correlation_type, correlation_strength, shared_entities,
                risk_score, timestamp, correlation_bucket
            )
            VALUES (
                %(correlation_id)s, %(fingerprint)s, %(tenant_id)s,
                %(finding_ids)s, %(event_ids)s, %(source_types)s,
                %(correlation_type)s, %(correlation_strength)s, %(shared_entities)s,
                %(risk_score)s, %(timestamp)s, %(correlation_bucket)s
            )
            ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                finding_ids = ARRAY(SELECT DISTINCT unnest(
                    correlated_activities.finding_ids || EXCLUDED.finding_ids
                )),
                event_ids = ARRAY(SELECT DISTINCT unnest(
                    correlated_activities.event_ids || EXCLUDED.event_ids
                )),
                correlation_strength = GREATEST(
                    correlated_activities.correlation_strength,
                    EXCLUDED.correlation_strength
                ),
                risk_score = GREATEST(
                    correlated_activities.risk_score,
                    EXCLUDED.risk_score
                )
        """

        import json
        await db.execute_one(query, {
            "correlation_id": activity.correlation_id,
            "fingerprint": activity.fingerprint,
            "tenant_id": activity.tenant_id,
            "finding_ids": activity.finding_ids,
            "event_ids": activity.event_ids,
            "source_types": activity.source_types,
            "correlation_type": activity.correlation_type,
            "correlation_strength": activity.correlation_strength,
            "shared_entities": json.dumps(activity.shared_entities),
            "risk_score": activity.risk_score,
            "timestamp": activity.timestamp,
            "correlation_bucket": activity.correlation_bucket,
        })

        logger.debug(
            "Correlated activity persisted",
            correlation_id=activity.correlation_id,
        )

    except ImportError:
        logger.debug("Database module not available")
        raise


async def _trigger_alerting(
    activity: Any,
    tenant_id: str,
) -> dict[str, Any]:
    """
    Trigger alert creation from a CorrelatedActivity.

    Fail-safe: errors are caught and returned, not raised.
    """
    try:
        from app.correlation.alert_integration import (
            process_correlation_to_alert,
        )

        result = await process_correlation_to_alert(
            activity=activity,
            tenant_id=tenant_id,
        )

        if result.get("alert_id"):
            _increment_metric("alerts_created")

        return result

    except ImportError as e:
        logger.debug(
            "Alert integration module not available",
            error=str(e),
        )
        return {"errors": []}

    except (OSError, ValueError, RuntimeError) as e:
        _increment_metric("downstream_errors")
        logger.error(
            "Alert creation error",
            correlation_id=activity.correlation_id,
            error=str(e),
        )
        return {"errors": [str(e)]}


# =============================================================================
# Batch Processing
# =============================================================================


async def on_findings_created_batch(
    findings_with_context: list[tuple[Any, Finding, str]],
    *,
    skip_correlation: bool = False,
    skip_alerting: bool = False,
) -> list[dict[str, Any]]:
    """
    Process a batch of findings through the common downstream pipeline.

    Args:
        findings_with_context: List of (log_event, finding, tenant_id) tuples
        skip_correlation: If True, skip correlation
        skip_alerting: If True, skip alerting

    Returns:
        List of results, one per finding
    """
    results = []
    for log_event, finding, tenant_id in findings_with_context:
        result = await on_finding_created(
            log_event=log_event,
            finding=finding,
            tenant_id=tenant_id,
            skip_correlation=skip_correlation,
            skip_alerting=skip_alerting,
        )
        results.append(result)
    return results
