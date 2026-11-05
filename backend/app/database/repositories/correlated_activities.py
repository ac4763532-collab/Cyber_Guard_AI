"""
CyberGuard AI - Correlated Activities Repository (STEP 8.5.3)

PostgreSQL persistence for correlated activities.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog

from app.correlation.realtime import CorrelatedActivity

logger = structlog.get_logger(__name__)


class CorrelatedActivityRepository:
    """
    Repository for persisting correlated activities to PostgreSQL.

    This repository:
    - Persists correlation results
    - Enforces tenant isolation
    - Uses unique constraint for deduplication
    - Provides query methods for correlation history
    """

    def __init__(self, db):
        """
        Initialize repository with database connection.

        Args:
            db: Database connection (AsyncPG pool or similar)
        """
        self._db = db

    async def create(self, activity: CorrelatedActivity) -> dict[str, Any] | None:
        """
        Persist a correlated activity.

        Uses ON CONFLICT DO NOTHING to handle duplicates gracefully.

        Args:
            activity: CorrelatedActivity to persist

        Returns:
            Created record as dict, or None if duplicate
        """
        sql = """
            INSERT INTO correlated_activities (
                correlation_id,
                fingerprint,
                tenant_id,
                finding_ids,
                event_ids,
                source_types,
                correlation_type,
                correlation_strength,
                shared_entities,
                risk_score,
                timestamp,
                correlation_bucket
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
            )
            ON CONFLICT (tenant_id, fingerprint) DO NOTHING
            RETURNING *
        """

        try:
            async with self._db.connection() as conn:
                row = await conn.fetchrow(
                    sql,
                    UUID(activity.correlation_id),
                    activity.fingerprint,
                    activity.tenant_id,
                    [UUID(fid) for fid in activity.finding_ids] if activity.finding_ids else [],
                    activity.event_ids,
                    activity.source_types,
                    activity.correlation_type,
                    activity.correlation_strength,
                    activity.shared_entities,
                    activity.risk_score,
                    activity.timestamp,
                    activity.correlation_bucket,
                )

                if row:
                    logger.info(
                        "Correlated activity persisted",
                        correlation_id=activity.correlation_id,
                        tenant_id=activity.tenant_id,
                        fingerprint=activity.fingerprint,
                    )
                    return dict(row)

                logger.debug(
                    "Duplicate correlated activity skipped",
                    fingerprint=activity.fingerprint,
                    tenant_id=activity.tenant_id,
                )
                return None

        except Exception as e:
            logger.error(
                "Failed to persist correlated activity",
                correlation_id=activity.correlation_id,
                error=str(e),
            )
            raise

    async def get_by_correlation_id(
        self,
        correlation_id: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """
        Get a correlated activity by its ID.

        Args:
            correlation_id: Correlation ID
            tenant_id: Tenant ID for isolation

        Returns:
            Activity as dict or None
        """
        sql = """
            SELECT * FROM correlated_activities
            WHERE correlation_id = $1 AND tenant_id = $2
        """

        async with self._db.connection() as conn:
            row = await conn.fetchrow(sql, UUID(correlation_id), tenant_id)
            return dict(row) if row else None

    async def get_by_fingerprint(
        self,
        fingerprint: str,
        tenant_id: str,
    ) -> dict[str, Any] | None:
        """
        Get a correlated activity by its fingerprint.

        Args:
            fingerprint: Correlation fingerprint
            tenant_id: Tenant ID for isolation

        Returns:
            Activity as dict or None
        """
        sql = """
            SELECT * FROM correlated_activities
            WHERE fingerprint = $1 AND tenant_id = $2
        """

        async with self._db.connection() as conn:
            row = await conn.fetchrow(sql, fingerprint, tenant_id)
            return dict(row) if row else None

    async def list_by_tenant(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        List correlated activities for a tenant.

        Args:
            tenant_id: Tenant ID
            limit: Max records to return
            offset: Skip this many records
            since: Only return activities after this time

        Returns:
            List of activities as dicts
        """
        if since:
            sql = """
                SELECT * FROM correlated_activities
                WHERE tenant_id = $1 AND timestamp >= $2
                ORDER BY timestamp DESC
                LIMIT $3 OFFSET $4
            """
            params = [tenant_id, since, limit, offset]
        else:
            sql = """
                SELECT * FROM correlated_activities
                WHERE tenant_id = $1
                ORDER BY timestamp DESC
                LIMIT $2 OFFSET $3
            """
            params = [tenant_id, limit, offset]

        async with self._db.connection() as conn:
            rows = await conn.fetch(sql, *params)
            return [dict(row) for row in rows]

    async def list_by_finding(
        self,
        finding_id: str,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """
        List correlated activities containing a specific finding.

        Args:
            finding_id: Finding ID to search for
            tenant_id: Tenant ID for isolation

        Returns:
            List of activities as dicts
        """
        sql = """
            SELECT * FROM correlated_activities
            WHERE tenant_id = $1 AND $2 = ANY(finding_ids)
            ORDER BY timestamp DESC
        """

        async with self._db.connection() as conn:
            rows = await conn.fetch(sql, tenant_id, UUID(finding_id))
            return [dict(row) for row in rows]

    async def count_by_tenant(
        self,
        tenant_id: str,
        since: datetime | None = None,
    ) -> int:
        """
        Count correlated activities for a tenant.

        Args:
            tenant_id: Tenant ID
            since: Only count activities after this time

        Returns:
            Count of activities
        """
        if since:
            sql = """
                SELECT COUNT(*) FROM correlated_activities
                WHERE tenant_id = $1 AND timestamp >= $2
            """
            params = [tenant_id, since]
        else:
            sql = """
                SELECT COUNT(*) FROM correlated_activities
                WHERE tenant_id = $1
            """
            params = [tenant_id]

        async with self._db.connection() as conn:
            return await conn.fetchval(sql, *params)

    async def get_correlation_stats(
        self,
        tenant_id: str,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Get correlation statistics for a tenant.

        Args:
            tenant_id: Tenant ID
            since: Only include activities after this time

        Returns:
            Statistics dict
        """
        since_clause = "AND timestamp >= $2" if since else ""
        since_params = [tenant_id, since] if since else [tenant_id]

        sql = f"""
            SELECT
                COUNT(*) as total_correlations,
                COUNT(DISTINCT correlation_type) as correlation_types,
                AVG(correlation_strength) as avg_strength,
                AVG(risk_score) as avg_risk_score,
                COUNT(DISTINCT UNNEST(source_types)) as unique_sources,
                SUM(array_length(finding_ids, 1)) as total_findings
            FROM correlated_activities
            WHERE tenant_id = $1 {since_clause}
        """

        async with self._db.connection() as conn:
            row = await conn.fetchrow(sql, *since_params)

            return {
                "total_correlations": row["total_correlations"] or 0,
                "correlation_types": row["correlation_types"] or 0,
                "avg_strength": float(row["avg_strength"] or 0),
                "avg_risk_score": float(row["avg_risk_score"] or 0),
                "unique_sources": row["unique_sources"] or 0,
                "total_findings": row["total_findings"] or 0,
            }

    async def delete_old_activities(
        self,
        tenant_id: str,
        older_than: datetime,
    ) -> int:
        """
        Delete old correlated activities.

        Args:
            tenant_id: Tenant ID
            older_than: Delete activities older than this

        Returns:
            Number of deleted records
        """
        sql = """
            DELETE FROM correlated_activities
            WHERE tenant_id = $1 AND timestamp < $2
        """

        async with self._db.connection() as conn:
            result = await conn.execute(sql, tenant_id, older_than)
            # Extract count from "DELETE N"
            count = int(result.split()[-1]) if result else 0

            logger.info(
                "Deleted old correlated activities",
                tenant_id=tenant_id,
                older_than=older_than.isoformat(),
                deleted=count,
            )

            return count
