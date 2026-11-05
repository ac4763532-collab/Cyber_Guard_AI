"""
CyberGuard AI - Correlated Activity → Alert Integration (STEP 8.5.4)

Integrates CorrelatedActivity with existing AlertManager.

This module provides:
1. Alert creation from CorrelatedActivity (reuses existing AlertRepository)
2. Alert deduplication using correlation fingerprint
3. Alert enrichment when new evidence is found (correlation evolution)
4. Correlation evolution handling (A+B → A+B+C updates)
5. Fail-safe: findings persist even if alert creation fails

Architecture:
    CorrelatedActivity (from STEP 8.5.3)
           ↓
    CorrelationAlertIntegration.create_alert_from_correlation()
           ↓
    AlertRepository.create()  [EXISTING]

Key principles:
- REUSE existing AlertManager (do NOT create a new one)
- Alert references correlation_id
- Alert deduplication using fingerprint
- Correlation evolution updates existing records
- Fail-safe: findings never lost even if integration fails
- Tenant isolation enforced at every layer
"""

from datetime import datetime, timezone
from typing import Any

import structlog

from app.config import get_settings
from app.database.models import (
    AlertStatus,
    SeverityLevel,
)

logger = structlog.get_logger(__name__)


# =============================================================================
# Metrics
# =============================================================================

_integration_metrics = {
    "alerts_created": 0,
    "alerts_deduplicated": 0,
    "alerts_enriched": 0,
    "correlation_evolutions": 0,
    "integration_errors": 0,
    "db_errors": 0,
}


def get_integration_metrics() -> dict[str, int]:
    """Get integration metrics."""
    return _integration_metrics.copy()


def reset_integration_metrics() -> None:
    """Reset metrics (for testing)."""
    global _integration_metrics
    _integration_metrics = {
        "alerts_created": 0,
        "alerts_deduplicated": 0,
        "alerts_enriched": 0,
        "correlation_evolutions": 0,
        "integration_errors": 0,
        "db_errors": 0,
    }


def _increment_metric(name: str, value: int = 1) -> None:
    """Increment a metric counter."""
    if name in _integration_metrics:
        _integration_metrics[name] += value


# =============================================================================
# Severity Mapping
# =============================================================================


def _correlation_risk_to_severity(risk_score: int) -> SeverityLevel:
    """Map correlation risk score to severity level."""
    if risk_score >= 90:
        return SeverityLevel.CRITICAL
    if risk_score >= 70:
        return SeverityLevel.HIGH
    if risk_score >= 50:
        return SeverityLevel.MEDIUM
    if risk_score >= 25:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def _severity_to_priority(severity: SeverityLevel) -> int:
    """Map severity to a numeric priority (1 = highest)."""
    mapping = {
        SeverityLevel.CRITICAL: 1,
        SeverityLevel.HIGH: 2,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 4,
        SeverityLevel.INFO: 5,
    }
    return mapping.get(severity, 3)


# =============================================================================
# Alert Fingerprint
# =============================================================================


def compute_alert_fingerprint(correlation_fingerprint: str, tenant_id: str) -> str:
    """
    Compute alert fingerprint from correlation fingerprint.

    The alert fingerprint is derived from the correlation fingerprint,
    ensuring the same correlation produces the same alert (deduplication).

    Args:
        correlation_fingerprint: Fingerprint from CorrelatedActivity
        tenant_id: Tenant identifier

    Returns:
        Alert fingerprint string
    """
    import hashlib

    # Include tenant in hash to prevent cross-tenant collisions
    canonical = f"alert:{tenant_id}:{correlation_fingerprint}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


# =============================================================================
# Correlation Alert Integration
# =============================================================================


class CorrelationAlertIntegration:
    """
    Integrates CorrelatedActivity with the existing AlertManager.

    This class:
    1. Creates alerts from correlated activities
    2. Handles deduplication via fingerprints
    3. Handles correlation evolution (A+B → A+B+C)
    4. Provides fail-safe operation

    Usage:
        integration = await CorrelationAlertIntegration.create(tenant_id)
        result = await integration.process_correlated_activity(activity)
    """

    def __init__(
        self,
        tenant_id: str,
        db_enabled: bool = True,
    ):
        """
        Initialize the integration.

        Use the create() factory method for proper async initialization.

        Args:
            tenant_id: Tenant identifier (from trusted source)
            db_enabled: Whether database persistence is enabled
        """
        self._tenant_id = tenant_id
        self._db_enabled = db_enabled

    @classmethod
    async def create(cls, tenant_id: str) -> "CorrelationAlertIntegration":
        """
        Create a CorrelationAlertIntegration instance.

        Args:
            tenant_id: Tenant identifier (from trusted source)

        Returns:
            Configured CorrelationAlertIntegration

        Raises:
            ValueError: If tenant_id is invalid
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required")

        settings = get_settings()
        db_enabled = settings.db_enabled

        logger.info(
            "Created correlation alert integration",
            tenant_id=tenant_id,
            db_enabled=db_enabled,
        )

        return cls(
            tenant_id=tenant_id,
            db_enabled=db_enabled,
        )

    @property
    def tenant_id(self) -> str:
        """Get the tenant ID."""
        return self._tenant_id

    async def process_correlated_activity(
        self,
        activity: Any,  # CorrelatedActivity from realtime.py
    ) -> dict[str, Any]:
        """
        Process a CorrelatedActivity through alert creation.

        This is the main entry point. It:
        1. Creates an alert from the correlation (with deduplication)
        2. Handles correlation evolution

        The operation is fail-safe: if alert creation fails, the error
        is logged but the CorrelatedActivity is not lost.

        Args:
            activity: CorrelatedActivity from RealtimeCorrelationService

        Returns:
            Result dict with alert_id and status

        Note:
            This method catches all exceptions to ensure fail-safe operation.
            Errors are logged and returned in the result dict.
        """
        result: dict[str, Any] = {
            "correlation_id": activity.correlation_id,
            "tenant_id": self._tenant_id,
            "alert_id": None,
            "alert_status": "not_created",
            "errors": [],
        }

        try:
            # Create alert from correlation
            alert_result = await self._create_alert_from_correlation(activity)
            result["alert_id"] = alert_result.get("alert_id")
            result["alert_status"] = alert_result.get("status", "error")

            if alert_result.get("error"):
                result["errors"].append(f"Alert: {alert_result['error']}")

            logger.info(
                "Processed correlated activity",
                correlation_id=activity.correlation_id,
                alert_id=result["alert_id"],
                alert_status=result["alert_status"],
            )

            return result

        except (OSError, ValueError, RuntimeError, KeyError) as e:
            _increment_metric("integration_errors")
            logger.exception(
                "Failed to process correlated activity",
                correlation_id=activity.correlation_id,
                error=str(e),
            )
            result["errors"].append(str(e))
            return result

    async def _create_alert_from_correlation(
        self,
        activity: Any,
    ) -> dict[str, Any]:
        """
        Create an alert from a CorrelatedActivity.

        Uses the existing AlertRepository for persistence.
        Deduplicates using the correlation fingerprint.

        Args:
            activity: CorrelatedActivity

        Returns:
            Result dict with alert_id and status
        """
        if not self._db_enabled:
            return {"alert_id": None, "status": "db_disabled"}

        try:
            # Compute alert fingerprint for deduplication
            alert_fingerprint = compute_alert_fingerprint(
                correlation_fingerprint=activity.fingerprint,
                tenant_id=self._tenant_id,
            )

            # Check if alert already exists (deduplication)
            existing_alert = await self._get_alert_by_fingerprint(alert_fingerprint)

            if existing_alert:
                # Alert exists - check if we need to enrich it
                enriched = await self._enrich_existing_alert(
                    alert_id=existing_alert["id"],
                    activity=activity,
                )

                if enriched:
                    _increment_metric("alerts_enriched")
                    return {
                        "alert_id": existing_alert["id"],
                        "status": "enriched",
                    }
                else:
                    _increment_metric("alerts_deduplicated")
                    return {
                        "alert_id": existing_alert["id"],
                        "status": "deduplicated",
                    }

            # Create new alert
            alert_id = await self._create_alert(
                activity=activity,
                alert_fingerprint=alert_fingerprint,
            )

            if alert_id:
                _increment_metric("alerts_created")
                return {"alert_id": alert_id, "status": "created"}
            else:
                return {"alert_id": None, "status": "creation_failed"}

        except (OSError, ValueError, RuntimeError, KeyError) as e:
            _increment_metric("db_errors")
            logger.error(
                "Failed to create alert from correlation",
                correlation_id=activity.correlation_id,
                error=str(e),
            )
            return {"alert_id": None, "status": "error", "error": str(e)}

    async def _get_alert_by_fingerprint(
        self,
        fingerprint: str,
    ) -> dict[str, Any] | None:
        """
        Get an alert by tenant_id and fingerprint.

        Uses the UNIQUE(tenant_id, fingerprint) constraint for deduplication.
        Tenant isolation is enforced - only alerts for this tenant are returned.

        Args:
            fingerprint: Alert fingerprint

        Returns:
            Alert dict if found, None otherwise
        """
        try:
            from app.database.connection import get_database

            db = get_database()

            # Query by tenant_id AND fingerprint (uses unique index)
            query = """
                SELECT id, correlation_id, finding_ids, status, fingerprint
                FROM alerts
                WHERE tenant_id = %(tenant_id)s AND fingerprint = %(fingerprint)s
            """

            result = await db.execute_one(query, {
                "tenant_id": self._tenant_id,
                "fingerprint": fingerprint,
            })

            if result:
                return {
                    "id": str(result["id"]),
                    "correlation_id": result.get("correlation_id"),
                    "finding_ids": result.get("finding_ids", []),
                    "status": result.get("status"),
                    "fingerprint": result.get("fingerprint"),
                }
            return None

        except (OSError, ValueError, RuntimeError, KeyError) as e:
            logger.warning(
                "Failed to get alert by fingerprint",
                fingerprint=fingerprint,
                tenant_id=self._tenant_id,
                error=str(e),
            )
            return None

    async def _create_alert(
        self,
        activity: Any,
        alert_fingerprint: str,
    ) -> str | None:
        """
        Create a new alert in the database.

        Uses separate UUID id and fingerprint columns.
        The UNIQUE(tenant_id, fingerprint) constraint handles deduplication.

        Args:
            activity: CorrelatedActivity
            alert_fingerprint: Computed alert fingerprint

        Returns:
            Alert ID (UUID) if created, None otherwise
        """
        try:
            from app.database.connection import get_database

            db = get_database()

            # Build alert title and description
            source_types_str = ", ".join(activity.source_types)
            finding_count = len(activity.finding_ids)
            title = f"Correlated Activity: {finding_count} findings across {source_types_str}"

            description = self._build_alert_description(activity)
            severity = _correlation_risk_to_severity(activity.risk_score)

            # Shared entities for context
            shared_ips = activity.shared_entities.get("ips", [])
            affected_assets = activity.shared_entities.get("assets", [])

            now = datetime.now(timezone.utc)

            # Insert with separate id (UUID) and fingerprint columns
            # ON CONFLICT handles race conditions atomically
            query = """
                INSERT INTO alerts (
                    id, fingerprint, tenant_id,
                    title, description, severity, risk_score,
                    correlation_id, finding_ids, source_ips, affected_assets,
                    status, created_at, updated_at
                )
                VALUES (
                    gen_random_uuid(), %(fingerprint)s, %(tenant_id)s,
                    %(title)s, %(description)s, %(severity)s, %(risk_score)s,
                    %(correlation_id)s, %(finding_ids)s, %(source_ips)s, %(affected_assets)s,
                    %(status)s, %(created_at)s, %(updated_at)s
                )
                ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                    updated_at = EXCLUDED.updated_at
                RETURNING id
            """

            result = await db.execute_one(query, {
                "fingerprint": alert_fingerprint,
                "tenant_id": self._tenant_id,
                "title": title,
                "description": description,
                "severity": severity.value,
                "risk_score": activity.risk_score,
                "correlation_id": activity.correlation_id,
                "finding_ids": activity.finding_ids,
                "source_ips": shared_ips if shared_ips else [],
                "affected_assets": affected_assets if affected_assets else [],
                "status": AlertStatus.NEW.value,
                "created_at": now,
                "updated_at": now,
            })

            if result:
                alert_id = str(result["id"])
                logger.info(
                    "Alert created from correlation",
                    alert_id=alert_id,
                    fingerprint=alert_fingerprint,
                    correlation_id=activity.correlation_id,
                    tenant_id=self._tenant_id,
                    severity=severity.value,
                )

                # Notify immediately - a new alert is a new detection even
                # if it later gets grouped into an incident (Phase 10:
                # single-source detections alert promptly on their own).
                await self._notify_recipients(
                    source_id=alert_id,
                    source_type="alert",
                    severity=severity,
                    title=title,
                    summary=description,
                )

                return alert_id
            else:
                logger.warning(
                    "Alert insert returned no result",
                    fingerprint=alert_fingerprint,
                    tenant_id=self._tenant_id,
                )
                return None

        except (OSError, ValueError, RuntimeError, KeyError) as e:
            error_str = str(e).lower()
            if "duplicate" in error_str or "unique" in error_str:
                # Race condition - another worker created it, fetch the existing one
                logger.debug(
                    "Alert already exists (unique constraint), fetching existing",
                    fingerprint=alert_fingerprint,
                    tenant_id=self._tenant_id,
                )
                existing = await self._get_alert_by_fingerprint(alert_fingerprint)
                if existing:
                    return existing["id"]
                return None

            logger.error(
                "Failed to create alert",
                correlation_id=activity.correlation_id,
                tenant_id=self._tenant_id,
                error=str(e),
            )
            return None

    async def _enrich_existing_alert(
        self,
        alert_id: str,
        activity: Any,
    ) -> bool:
        """
        Enrich an existing alert with new evidence from correlation evolution.

        When correlation evolves (A+B → A+B+C), this adds new findings
        to the existing alert.

        Uses PostgreSQL atomic operations for concurrent update safety.
        Tenant isolation enforced via tenant_id check.

        Args:
            alert_id: Existing alert ID
            activity: CorrelatedActivity with potentially new evidence

        Returns:
            True if alert was enriched, False if no changes
        """
        try:
            from app.database.connection import get_database

            db = get_database()

            # Atomic update: only update if we have new findings to add
            # Uses array operations to merge finding_ids without duplicates
            update_query = """
                WITH current_alert AS (
                    SELECT id, finding_ids
                    FROM alerts
                    WHERE id = %(id)s AND tenant_id = %(tenant_id)s
                    FOR UPDATE
                ),
                new_findings AS (
                    SELECT unnest(%(activity_findings)s::uuid[]) AS finding_id
                    EXCEPT
                    SELECT unnest(finding_ids) FROM current_alert
                )
                UPDATE alerts
                SET finding_ids = (
                    SELECT array_agg(DISTINCT f) FROM (
                        SELECT unnest(finding_ids) AS f FROM current_alert
                        UNION
                        SELECT finding_id FROM new_findings
                    ) combined
                ),
                updated_at = %(updated_at)s,
                notes = notes || %(note)s::jsonb
                WHERE id = %(id)s
                AND tenant_id = %(tenant_id)s
                AND EXISTS (SELECT 1 FROM new_findings)
                RETURNING id, (SELECT count(*) FROM new_findings) as added_count
            """

            note = [{
                "text": f"Correlation evolved: merging findings from {activity.correlation_id}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "correlation_evolution",
            }]

            import json
            result = await db.execute_one(update_query, {
                "id": alert_id,
                "tenant_id": self._tenant_id,
                "activity_findings": activity.finding_ids,
                "updated_at": datetime.now(timezone.utc),
                "note": json.dumps(note),
            })

            if result:
                _increment_metric("correlation_evolutions")
                logger.info(
                    "Alert enriched with correlation evolution",
                    alert_id=alert_id,
                    tenant_id=self._tenant_id,
                    added_findings=result.get("added_count", 0),
                )
                return True

            return False

        except (OSError, ValueError, RuntimeError, KeyError) as e:
            logger.warning(
                "Failed to enrich alert",
                alert_id=alert_id,
                tenant_id=self._tenant_id,
                error=str(e),
            )
            return False

    def _build_alert_description(self, activity: Any) -> str:
        """Build a descriptive alert description from the activity."""
        lines = [
            "Cross-source correlated activity detected.",
            "",
            f"**Correlation ID:** {activity.correlation_id}",
            f"**Correlation Type:** {activity.correlation_type}",
            f"**Correlation Strength:** {activity.correlation_strength:.2f}",
            f"**Risk Score:** {activity.risk_score}",
            "",
            f"**Source Types:** {', '.join(activity.source_types)}",
            f"**Findings:** {len(activity.finding_ids)}",
            "",
        ]

        # Add shared entities
        shared = activity.shared_entities
        if shared.get("ips"):
            lines.append(f"**Shared IPs:** {', '.join(shared['ips'][:5])}")
        if shared.get("users"):
            lines.append(f"**Shared Users:** {', '.join(shared['users'][:5])}")
        if shared.get("assets"):
            lines.append(f"**Affected Assets:** {', '.join(shared['assets'][:5])}")

        return "\n".join(lines)

    async def _resolve_recipients(self) -> list[Any]:
        """
        Resolve which users should be notified for this tenant.

        There is no dedicated "notification recipients" table - this
        resolves to every active user scoped to this tenant via
        organization_id (admins, who have organization_id=None, are
        intentionally excluded from this per-tenant fan-out; they are
        not "the affected user" for a specific tenant's incident).

        Returns an empty list (never raises) if the user store is
        unavailable or no users match - callers must treat that as
        "nothing to notify" rather than an error.
        """
        try:
            from app.auth.users import get_user_manager

            manager = get_user_manager()
            all_users = await manager.list_users_async()
            return [
                u for u in all_users
                if u.is_active and u.organization_id == self._tenant_id
            ]
        except (OSError, ValueError, RuntimeError, TypeError, KeyError, ImportError, AttributeError) as e:
            # Deliberately broad: resolving recipients is a best-effort
            # side effect of alert creation, which has already
            # succeeded by the time this runs. Any failure here (DB
            # driver error, unexpected mock/test double, missing
            # module) must degrade to "no recipients resolved" rather
            # than propagate and look like the alert itself
            # failed to persist.
            logger.warning(
                "Failed to resolve notification recipients",
                tenant_id=self._tenant_id,
                error=str(e),
            )
            return []

    async def _notify_recipients(
        self,
        *,
        source_id: str,
        source_type: str,
        severity: SeverityLevel,
        title: str,
        summary: str,
    ) -> None:
        """
        Deliver a notification to every resolved recipient for this
        tenant. Fail-safe: a notification delivery problem must never
        prevent the alert itself from having been persisted -
        this is called after that write already succeeded, and any
        error here is logged, not raised.
        """
        try:
            from app.services.notifications import get_notification_service

            recipients = await self._resolve_recipients()
            if not recipients:
                logger.debug(
                    "No notification recipients resolved for tenant",
                    tenant_id=self._tenant_id,
                    source_id=source_id,
                )
                return

            service = get_notification_service()
            for user in recipients:
                await service.notify(
                    source_id=source_id,
                    source_type=source_type,
                    tenant_id=self._tenant_id,
                    recipient_user_id=user.id,
                    recipient_email=user.email,
                    severity=severity,
                    title=title,
                    summary=summary,
                )
        except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError, AttributeError) as e:
            logger.error(
                "Notification delivery failed (alert persisted regardless)",
                source_id=source_id,
                source_type=source_type,
                tenant_id=self._tenant_id,
                error=str(e),
            )

        # Real-time popup delivery, separate try/except from the
        # notification-inbox block above for the same reason as
        # app.correlation.finding_lifecycle._notify_individual_alert: a
        # WebSocket fan-out failure must stay distinguishable from (and
        # can't mask or be masked by) an inbox-notification failure, and
        # neither can undo the alert/incident row already persisted.
        try:
            from app.websocket.events import broadcast_alert_to_tenant

            if source_type == "alert":
                await broadcast_alert_to_tenant(
                    tenant_id=self._tenant_id,
                    alert_id=source_id,
                    title=title,
                    severity=severity.value,
                    additional_data={"summary": summary},
                )
        except (OSError, ValueError, RuntimeError, ImportError, TypeError, KeyError, AttributeError) as e:
            logger.error(
                "Real-time broadcast failed (alert persisted regardless)",
                source_id=source_id,
                source_type=source_type,
                tenant_id=self._tenant_id,
                error=str(e),
            )


# =============================================================================
# Factory Functions
# =============================================================================

_integrations: dict[str, CorrelationAlertIntegration] = {}


async def get_correlation_alert_integration(
    tenant_id: str,
) -> CorrelationAlertIntegration:
    """
    Get or create a CorrelationAlertIntegration for a tenant.

    Args:
        tenant_id: Tenant identifier

    Returns:
        CorrelationAlertIntegration instance
    """
    if tenant_id not in _integrations:
        _integrations[tenant_id] = await CorrelationAlertIntegration.create(tenant_id)
    return _integrations[tenant_id]


def reset_integrations_for_testing() -> None:
    """Reset integration cache (for testing)."""
    _integrations.clear()
    reset_integration_metrics()


# =============================================================================
# High-Level API
# =============================================================================


async def process_correlation_to_alert(
    activity: Any,
    tenant_id: str,
) -> dict[str, Any]:
    """
    Process a CorrelatedActivity through to Alert creation.

    This is the main entry point for STEP 8.5.4 integration.
    Call this after a CorrelatedActivity is created.

    The function is fail-safe: if alert creation fails,
    the error is logged but does not propagate.

    Args:
        activity: CorrelatedActivity from RealtimeCorrelationService
        tenant_id: Tenant identifier

    Returns:
        Result dict with alert_id and status
    """
    try:
        integration = await get_correlation_alert_integration(tenant_id)
        return await integration.process_correlated_activity(activity)

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        logger.exception(
            "Failed to process correlation to alert",
            correlation_id=getattr(activity, "correlation_id", "unknown"),
            tenant_id=tenant_id,
            error=str(e),
        )
        _increment_metric("integration_errors")
        return {
            "correlation_id": getattr(activity, "correlation_id", "unknown"),
            "tenant_id": tenant_id,
            "alert_id": None,
            "alert_status": "error",
            "errors": [str(e)],
        }
