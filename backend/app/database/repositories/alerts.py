"""
CyberGuard AI - Alert Repository

Database operations for Alert entities.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.database.connection import get_database
from app.database.models import (
    Alert,
    AlertCreate,
    AlertStatus,
    AlertUpdate,
)

logger = structlog.get_logger(__name__)


class AlertRepository:
    """Repository for Alert database operations."""

    def __init__(self):
        self.db = get_database()

    async def create(self, alert: AlertCreate) -> Alert:
        """Create a new alert."""
        alert_id = str(uuid4())
        now = datetime.now(timezone.utc)

        query = """
            INSERT INTO alerts (
                id, title, description, severity, risk_score,
                event_id, finding_ids, created_at, updated_at
            )
            VALUES (
                %(id)s, %(title)s, %(description)s, %(severity)s, %(risk_score)s,
                %(event_id)s, %(finding_ids)s, %(created_at)s, %(updated_at)s
            )
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "id": alert_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "risk_score": alert.risk_score,
            "event_id": alert.event_id,
            "finding_ids": alert.finding_ids,
            "created_at": now,
            "updated_at": now,
        })

        return self._row_to_alert(result)

    async def get(
        self,
        alert_id: str,
        tenant_ids: list[str] | None = None,
    ) -> Alert | None:
        """Get an alert by ID, optionally scoped to tenant_ids."""
        if tenant_ids is not None:
            if not tenant_ids:
                return None
            query = "SELECT * FROM alerts WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s)"
            params = {"id": alert_id, "tenant_ids": tenant_ids}
        else:
            query = "SELECT * FROM alerts WHERE id = %(id)s"
            params = {"id": alert_id}
        result = await self.db.execute_one(query, params)
        return self._row_to_alert(result) if result else None

    async def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        tenant_ids: list[str] | None = None,
    ) -> list[Alert]:
        """List alerts with filters."""
        conditions = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if status:
            conditions.append("status = %(status)s")
            params["status"] = status

        if severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = severity

        if assigned_to:
            conditions.append("assigned_to = %(assigned_to)s")
            params["assigned_to"] = assigned_to

        if category:
            conditions.append("category = %(category)s")
            params["category"] = category

        if start_time:
            conditions.append("created_at >= %(start_time)s")
            params["start_time"] = start_time

        if end_time:
            conditions.append("created_at <= %(end_time)s")
            params["end_time"] = end_time

        if tenant_ids is not None:
            if not tenant_ids:
                return []
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT * FROM alerts
            WHERE {where_clause}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, params)
        return [self._row_to_alert(row) for row in results]

    async def list_by_event_ids(self, event_ids: list[str]) -> list[Alert]:
        """
        Fetch alerts linked (via the soft event_id FK) to any of the
        given events.id values.

        Used by the detection-report endpoint to surface "links to
        relevant alerts" for a source + time range (plan requirement #3) -
        reuses the existing alerts.event_id column, no new linkage
        invented. Returns [] for an empty event_ids list rather than
        matching every row.
        """
        if not event_ids:
            return []

        query = "SELECT * FROM alerts WHERE event_id = ANY(%(event_ids)s)"
        results = await self.db.execute(query, {"event_ids": event_ids})
        return [self._row_to_alert(row) for row in results]

    async def update(self, alert_id: str, update: AlertUpdate) -> Alert | None:
        """Update an alert."""
        updates = []
        params: dict[str, Any] = {"id": alert_id}

        if update.status is not None:
            updates.append("status = %(status)s")
            params["status"] = update.status.value

            if update.status == AlertStatus.ACKNOWLEDGED:
                updates.append("acknowledged_at = %(acknowledged_at)s")
                params["acknowledged_at"] = datetime.now(timezone.utc)
            elif update.status == AlertStatus.RESOLVED:
                updates.append("resolved_at = %(resolved_at)s")
                params["resolved_at"] = datetime.now(timezone.utc)

        if update.assigned_to is not None:
            updates.append("assigned_to = %(assigned_to)s")
            params["assigned_to"] = update.assigned_to

        if update.notes is not None:
            updates.append("""
                notes = notes || %(note)s::jsonb
            """)
            params["note"] = [{
                "text": update.notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]

        if not updates:
            return await self.get(alert_id)

        query = f"""
            UPDATE alerts
            SET {", ".join(updates)}
            WHERE id = %(id)s
            RETURNING *
        """

        result = await self.db.execute_one(query, params)
        return self._row_to_alert(result) if result else None

    async def count_by_status(self) -> dict[str, int]:
        """Count alerts by status."""
        query = """
            SELECT status, COUNT(*) as count
            FROM alerts
            GROUP BY status
        """
        results = await self.db.execute(query, {})
        return {row["status"]: row["count"] for row in results}

    async def count_by_severity(self) -> dict[str, int]:
        """Count alerts by severity."""
        query = """
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE status NOT IN ('resolved', 'false_positive')
            GROUP BY severity
        """
        results = await self.db.execute(query, {})
        return {row["severity"]: row["count"] for row in results}

    async def get_recent(self, hours: int = 24, limit: int = 10) -> list[Alert]:
        """Get recent alerts."""
        query = """
            SELECT * FROM alerts
            WHERE created_at > NOW() - INTERVAL '%(hours)s hours'
            ORDER BY created_at DESC
            LIMIT %(limit)s
        """
        results = await self.db.execute(query, {"hours": hours, "limit": limit})
        return [self._row_to_alert(row) for row in results]

    async def list_recent_for_tenants(
        self,
        tenant_ids: list[str] | None,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[Alert]:
        """
        List recent alerts scoped to the given tenants, for a connecting
        WebSocket client to recover alerts it may have missed while
        disconnected (requirement: "use persisted alert retrieval to
        recover missed alerts without repeatedly replaying old sirens" -
        the frontend, not this method, is responsible for the "don't
        replay the siren for an already-seen alert" dedup; this just
        returns the real persisted rows).

        Args:
            tenant_ids: Admin callers (resolve_tenant_scope() returned
                None) pass None to see every tenant, exactly like
                get_authorized_tenant_ids's tenant_ids=None semantics
                elsewhere in this codebase. Any other caller must pass
                their own organization_id as a single-element list - never
                None - so a non-admin can never see another tenant's
                alerts through this method.
            since: Only alerts created at or after this timestamp (used
                for "catch me up since my last_seen timestamp" on
                reconnect). None returns the most recent `limit` alerts
                regardless of age.
            limit: Max rows to return.

        Returns:
            Alerts ordered oldest-first (so a client replays them in the
            order they actually happened), newest `limit` capped.
        """
        conditions = []
        params: dict[str, Any] = {"limit": limit}

        if tenant_ids is not None:
            if not tenant_ids:
                return []
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids

        if since is not None:
            conditions.append("created_at >= %(since)s")
            params["since"] = since

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Inner query grabs the newest `limit` rows, outer re-orders them
        # oldest-first for chronological replay on the client.
        query = f"""
            SELECT * FROM (
                SELECT * FROM alerts
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT %(limit)s
            ) recent
            ORDER BY created_at ASC
        """

        results = await self.db.execute(query, params)
        return [self._row_to_alert(row) for row in results]

    def _row_to_alert(self, row: dict[str, Any]) -> Alert:
        """Convert database row to Alert model."""
        return Alert(
            id=str(row["id"]),
            fingerprint=row.get("fingerprint"),
            tenant_id=row.get("tenant_id"),
            event_id=str(row["event_id"]) if row.get("event_id") else None,
            finding_ids=[str(f) for f in row.get("finding_ids", [])],
            correlation_id=str(row["correlation_id"]) if row.get("correlation_id") else None,
            category=row.get("category"),
            title=row["title"],
            description=row.get("description", ""),
            severity=row["severity"],
            risk_score=row.get("risk_score", 0),
            status=row.get("status", "new"),
            assigned_to=row.get("assigned_to"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            acknowledged_at=row.get("acknowledged_at"),
            resolved_at=row.get("resolved_at"),
            source_ips=[str(ip) for ip in row.get("source_ips", [])],
            destination_ips=[str(ip) for ip in row.get("destination_ips", [])],
            affected_assets=row.get("affected_assets", []),
            mitre_tactics=row.get("mitre_tactics", []),
            mitre_techniques=row.get("mitre_techniques", []),
            notes=row.get("notes", []),
            actions_taken=row.get("actions_taken", []),
        )


# Singleton
_alert_repo: AlertRepository | None = None


def get_alert_repository() -> AlertRepository:
    """Get the alert repository."""
    global _alert_repo
    if _alert_repo is None:
        _alert_repo = AlertRepository()
    return _alert_repo
