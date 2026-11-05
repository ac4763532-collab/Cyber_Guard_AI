"""
CyberGuard AI - Finding Repository (Phase 1: Log Collection -> Automatic
Detection)

Database operations for Finding entities, tenant-scoped.

Dedup strategy: a finding is a duplicate when the same rule matched the
same event again (same event_id + rule_id). This happens legitimately on
Kafka redelivery after a consumer restart (see the manual-commit fix in
app/event_bus/consumer.py) - the same SecurityEvent gets re-processed by
LogAgent, which re-emits the same Finding (same rule_id) for the same
event. find_duplicate()/create() make that redelivery idempotent instead
of producing duplicate finding rows.

Findings without a rule_id (anomaly/IOC-type findings, per
app.agents.base.Finding.rule_id being optional) are not covered by the
unique index's dedup guarantee - find_duplicate() returns None for them
and create() always inserts, since there is no stable natural key to
dedupe on without a rule_id.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog
from psycopg.types.json import Json

from app.database.connection import get_database
from app.database.models import Finding, FindingCreate, FindingQuery, FindingStatus, SeverityLevel


logger = structlog.get_logger(__name__)


class FindingRepository:
    """Repository for Finding database operations, tenant-scoped."""

    def __init__(self):
        self.db = get_database()

    async def find_duplicate(
        self,
        event_id: str,
        rule_id: str | None,
    ) -> Finding | None:
        """
        Look up an existing finding for (event_id, rule_id), if any.

        Returns None (never a false match) when rule_id is None, since
        rule-less findings have no stable dedup key - see module
        docstring.
        """
        if not rule_id:
            return None

        query = (
            "SELECT * FROM findings WHERE event_id = %(event_id)s "
            "AND rule_id = %(rule_id)s"
        )
        result = await self.db.execute_one(
            query, {"event_id": event_id, "rule_id": rule_id}
        )
        return self._row_to_finding(result) if result else None

    async def create(self, finding: FindingCreate) -> Finding:
        """
        Create a new finding, or return the existing one if this exact
        (event_id, rule_id) pair was already recorded (idempotent on
        Kafka redelivery - see module docstring).

        A finding is only ever inserted here from a real rule match
        (detection_id is required and is not generated/fabricated by
        this method) - callers are responsible for only calling this
        when LogAgent (or another detector) actually produced a Finding.
        """
        existing = await self.find_duplicate(finding.event_id, finding.rule_id)
        if existing:
            logger.info(
                "Duplicate finding suppressed (idempotent redelivery)",
                event_id=finding.event_id,
                rule_id=finding.rule_id,
                finding_id=existing.id,
            )
            return existing

        finding_id = str(uuid4())
        now = datetime.now(timezone.utc)

        query = """
            INSERT INTO findings (
                id, event_id, detection_id, finding_type, rule_id,
                severity, confidence, title, description, evidence,
                mitre_tactics, mitre_techniques, status, tenant_id,
                created_at
            )
            VALUES (
                %(id)s, %(event_id)s, %(detection_id)s, %(finding_type)s, %(rule_id)s,
                %(severity)s, %(confidence)s, %(title)s, %(description)s, %(evidence)s,
                %(mitre_tactics)s, %(mitre_techniques)s, %(status)s, %(tenant_id)s,
                %(created_at)s
            )
            -- Race guard: two concurrent redeliveries could both pass the
            -- find_duplicate() check above before either commits. The
            -- partial unique index on (event_id, rule_id) WHERE rule_id
            -- IS NOT NULL (see app/database/schema.py) makes the second
            -- INSERT a no-op here instead of a duplicate row or an
            -- unhandled constraint-violation exception.
            ON CONFLICT (event_id, rule_id) WHERE rule_id IS NOT NULL
            DO NOTHING
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "id": finding_id,
            "event_id": finding.event_id,
            "detection_id": finding.detection_id,
            "finding_type": finding.finding_type,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "title": finding.title,
            "description": finding.description,
            "evidence": Json(finding.evidence),
            "mitre_tactics": finding.mitre_tactics,
            "mitre_techniques": finding.mitre_techniques,
            "status": FindingStatus.NEW.value,
            "tenant_id": finding.tenant_id,
            "created_at": now,
        })

        if result:
            return self._row_to_finding(result)

        # Lost the race to a concurrent insert - fetch what the winner
        # created instead of returning nothing.
        winner = await self.find_duplicate(finding.event_id, finding.rule_id)
        if winner is None:
            raise RuntimeError(
                f"FindingRepository.create: INSERT conflicted but no row "
                f"found for event_id={finding.event_id!r} rule_id={finding.rule_id!r}"
            )
        return winner

    async def get(
        self,
        finding_id: str,
        tenant_ids: list[str] | None = None,
    ) -> Finding | None:
        """
        Get a finding by ID, optionally scoped to tenant_ids.

        Same no-existence-leakage convention as EventRepository.get()/
        LogEventRepository.get(): a finding that exists but belongs to
        another tenant returns None here, indistinguishable from "does
        not exist" to the caller.
        """
        if tenant_ids is not None:
            query = (
                "SELECT * FROM findings WHERE id = %(id)s "
                "AND tenant_id = ANY(%(tenant_ids)s)"
            )
            result = await self.db.execute_one(
                query, {"id": finding_id, "tenant_ids": tenant_ids}
            )
        else:
            query = "SELECT * FROM findings WHERE id = %(id)s"
            result = await self.db.execute_one(query, {"id": finding_id})
        return self._row_to_finding(result) if result else None

    async def list(self, query_params: FindingQuery) -> list[Finding]:
        """List findings with filters, tenant-scoped per query_params."""
        conditions = []
        params: dict[str, Any] = {
            "limit": query_params.limit,
            "offset": query_params.offset,
        }

        if query_params.event_id:
            conditions.append("event_id = %(event_id)s")
            params["event_id"] = query_params.event_id

        if query_params.event_ids is not None:
            conditions.append("event_id = ANY(%(event_ids)s)")
            params["event_ids"] = query_params.event_ids

        if query_params.severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = query_params.severity.value

        if query_params.rule_id:
            conditions.append("rule_id = %(rule_id)s")
            params["rule_id"] = query_params.rule_id

        if query_params.status:
            conditions.append("status = %(status)s")
            params["status"] = query_params.status.value

        if query_params.start_time:
            conditions.append("created_at >= %(start_time)s")
            params["start_time"] = query_params.start_time

        if query_params.end_time:
            conditions.append("created_at <= %(end_time)s")
            params["end_time"] = query_params.end_time

        # Tenant isolation - server-resolved only, same convention as
        # LogEventQuery/EventRepository above.
        if query_params.tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = query_params.tenant_ids
        elif query_params.tenant_id:
            conditions.append("tenant_id = %(tenant_id)s")
            params["tenant_id"] = query_params.tenant_id

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT * FROM findings
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, params)
        return [self._row_to_finding(row) for row in results]

    async def count(self, query_params: FindingQuery) -> int:
        """Count findings matching the same filters as list()."""
        conditions = []
        params: dict[str, Any] = {}

        if query_params.event_id:
            conditions.append("event_id = %(event_id)s")
            params["event_id"] = query_params.event_id

        if query_params.event_ids is not None:
            conditions.append("event_id = ANY(%(event_ids)s)")
            params["event_ids"] = query_params.event_ids

        if query_params.severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = query_params.severity.value

        if query_params.rule_id:
            conditions.append("rule_id = %(rule_id)s")
            params["rule_id"] = query_params.rule_id

        if query_params.status:
            conditions.append("status = %(status)s")
            params["status"] = query_params.status.value

        if query_params.start_time:
            conditions.append("created_at >= %(start_time)s")
            params["start_time"] = query_params.start_time

        if query_params.end_time:
            conditions.append("created_at <= %(end_time)s")
            params["end_time"] = query_params.end_time

        if query_params.tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = query_params.tenant_ids
        elif query_params.tenant_id:
            conditions.append("tenant_id = %(tenant_id)s")
            params["tenant_id"] = query_params.tenant_id

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT COUNT(*) as count FROM findings WHERE {where_clause}"

        result = await self.db.execute_one(query, params)
        return result["count"] if result else 0

    async def update_status(
        self,
        finding_id: str,
        status: FindingStatus,
        tenant_ids: list[str] | None = None,
    ) -> Finding | None:
        """
        Update a finding's status, optionally scoped to tenant_ids.

        Returns None (no row updated) if the finding doesn't exist or
        belongs to another tenant - same no-leakage convention as get().
        """
        if tenant_ids is not None:
            query = (
                "UPDATE findings SET status = %(status)s "
                "WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s) "
                "RETURNING *"
            )
            params: dict[str, Any] = {
                "id": finding_id,
                "status": status.value,
                "tenant_ids": tenant_ids,
            }
        else:
            query = (
                "UPDATE findings SET status = %(status)s "
                "WHERE id = %(id)s RETURNING *"
            )
            params = {"id": finding_id, "status": status.value}

        result = await self.db.execute_one(query, params)
        return self._row_to_finding(result) if result else None

    def _row_to_finding(self, row: dict[str, Any]) -> Finding:
        """Convert database row to Finding model."""
        return Finding(
            id=str(row["id"]),
            event_id=str(row["event_id"]),
            detection_id=str(row["detection_id"]),
            finding_type=row["finding_type"],
            rule_id=row.get("rule_id"),
            severity=row["severity"],
            confidence=row.get("confidence", 0.0),
            title=row["title"],
            description=row.get("description") or "",
            evidence=row.get("evidence") or {},
            mitre_tactics=list(row.get("mitre_tactics") or []),
            mitre_techniques=list(row.get("mitre_techniques") or []),
            status=row.get("status", FindingStatus.NEW.value),
            tenant_id=row.get("tenant_id"),
            created_at=row["created_at"],
        )


# Singleton
_finding_repo: FindingRepository | None = None


def get_finding_repository() -> FindingRepository:
    """Get the finding repository."""
    global _finding_repo
    if _finding_repo is None:
        _finding_repo = FindingRepository()
    return _finding_repo
