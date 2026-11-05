"""
CyberGuard AI - Event Repository

Database operations for Event entities.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog
from psycopg.types.json import Json

from app.database.connection import get_database
from app.database.models import Event, EventCreate, EventStatus, EventType, SeverityLevel


logger = structlog.get_logger(__name__)


class EventRepository:
    """Repository for Event database operations."""

    def __init__(self):
        self.db = get_database()

    async def create(self, event: EventCreate) -> Event:
        """Create a new event."""
        event_id = str(uuid4())
        now = datetime.now(timezone.utc)

        query = """
            INSERT INTO events (
                id, event_type, source, raw_data, tenant_id,
                source_event_id, created_at, updated_at
            )
            VALUES (
                %(id)s, %(event_type)s, %(source)s, %(raw_data)s, %(tenant_id)s,
                %(source_event_id)s, %(created_at)s, %(updated_at)s
            )
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "id": event_id,
            "event_type": event.event_type.value,
            "source": event.source,
            "raw_data": Json(event.raw_data),
            "tenant_id": event.tenant_id,
            "source_event_id": event.source_event_id,
            "created_at": now,
            "updated_at": now,
        })

        return self._row_to_event(result)

    async def get_or_create_from_log_event(
        self,
        *,
        source: str,
        log_event_id: str,
        tenant_id: str | None,
        raw_data: dict[str, Any],
        event_type: EventType = EventType.LOG,
    ) -> Event:
        """
        Idempotently get-or-create a minimal `events` row for a
        log-sourced SecurityEvent, keyed by (source, log_event_id).

        Why this exists: findings.event_id has a hard foreign key to
        events.id, but log-sourced SecurityEvents only ever carry a
        log_events.id (see app/logs/event_bus_integration.py's
        log_event_to_security_event()) - no events row is created on
        that path otherwise. Rather than relaxing the FK, this creates
        one thin events row per log event on first sight, so
        FindingRepository.create() always has a real events.id to
        reference.

        Idempotency: uses the partial unique index on
        events(source, source_event_id) (see app/database/schema.py)
        via ON CONFLICT DO NOTHING, then falls back to a SELECT if the
        INSERT found an existing row. This makes it safe to call on
        every redelivery of the same Kafka message (e.g. after a
        consumer restart - see the manual-commit fix in
        app/event_bus/consumer.py) without creating duplicate events
        rows or inflating findings_count/statistics.
        """
        insert_query = """
            INSERT INTO events (
                id, event_type, source, raw_data, tenant_id,
                source_event_id, created_at, updated_at
            )
            VALUES (
                %(id)s, %(event_type)s, %(source)s, %(raw_data)s, %(tenant_id)s,
                %(source_event_id)s, %(created_at)s, %(updated_at)s
            )
            ON CONFLICT (source, source_event_id) WHERE source_event_id IS NOT NULL
            DO NOTHING
            RETURNING *
        """
        now = datetime.now(timezone.utc)
        result = await self.db.execute_one(insert_query, {
            "id": str(uuid4()),
            "event_type": event_type.value,
            "source": source,
            "raw_data": Json(raw_data),
            "tenant_id": tenant_id,
            "source_event_id": log_event_id,
            "created_at": now,
            "updated_at": now,
        })

        if result:
            return self._row_to_event(result)

        # Conflict: a row for this (source, log_event_id) already exists
        # (either from a prior attempt, or a race from a concurrent
        # consumer instance). Fetch it instead of treating this as new.
        existing_query = (
            "SELECT * FROM events WHERE source = %(source)s "
            "AND source_event_id = %(source_event_id)s"
        )
        existing = await self.db.execute_one(
            existing_query, {"source": source, "source_event_id": log_event_id}
        )
        if existing is None:
            # Should not happen (ON CONFLICT implies a row exists), but
            # don't silently fabricate - surface the real failure.
            raise RuntimeError(
                f"get_or_create_from_log_event: INSERT conflicted but no "
                f"row found for source={source!r} log_event_id={log_event_id!r}"
            )
        return self._row_to_event(existing)

    async def get(
        self,
        event_id: str,
        tenant_ids: list[str] | None = None,
    ) -> Event | None:
        """
        Get an event by ID.

        When tenant_ids is provided, the row must belong to one of
        those tenants or this returns None - the same as "not found" -
        so a caller probing another tenant's event ID cannot distinguish
        "doesn't exist" from "exists but isn't yours" (no existence
        leakage). Pass None only for trusted internal/admin callers that
        have already decided to see all tenants.
        """
        if tenant_ids is not None:
            query = (
                "SELECT * FROM events WHERE id = %(id)s "
                "AND tenant_id = ANY(%(tenant_ids)s)"
            )
            result = await self.db.execute_one(
                query, {"id": event_id, "tenant_ids": tenant_ids}
            )
        else:
            query = "SELECT * FROM events WHERE id = %(id)s"
            result = await self.db.execute_one(query, {"id": event_id})
        return self._row_to_event(result) if result else None

    async def list(
        self,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        tenant_ids: list[str] | None = None,
    ) -> list[Event]:
        """List events with filters, optionally scoped to tenant_ids."""
        conditions = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if event_type:
            conditions.append("event_type = %(event_type)s")
            params["event_type"] = event_type

        if status:
            conditions.append("status = %(status)s")
            params["status"] = status

        if severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = severity

        if search:
            # Matches the event's source label or its raw_data payload
            # (cast to text) - there is no dedicated free-text column on
            # this thin events table (unlike log_events.message), so this
            # is the honest equivalent: it searches whatever was actually
            # captured for the event, not a fabricated summary field.
            conditions.append("(source ILIKE %(search)s OR raw_data::text ILIKE %(search)s)")
            params["search"] = f"%{search}%"

        if start_time:
            conditions.append("created_at >= %(start_time)s")
            params["start_time"] = start_time

        if end_time:
            conditions.append("created_at <= %(end_time)s")
            params["end_time"] = end_time

        if tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # id DESC tiebreaker for a deterministic sort (see the identical
        # fix and rationale in LogEventRepository.list,
        # app/logs/repository.py) - created_at alone is not guaranteed
        # unique, so pagination without a tiebreaker can skip or
        # re-return rows across pages when timestamps collide.
        query = f"""
            SELECT * FROM events
            WHERE {where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """

        results = await self.db.execute(query, params)
        return [self._row_to_event(row) for row in results]

    async def list_by_source_event_ids(
        self,
        source_event_ids: list[str],
        tenant_ids: list[str] | None = None,
    ) -> list[Event]:
        """
        Fetch `events` rows whose source_event_id is one of the given
        log_events.id values.

        Used by the detection-report endpoint (GET /logs/sources/{id}/report)
        to join from a time-scoped set of `log_events` rows (which carry a
        real source_id FK to log_sources) to the `events` rows that record
        each one's actual processing outcome - see
        app/event_bus/dispatcher_integration.py's _resolve_event_id_for_finding(),
        which is what stores a log_events.id into events.source_event_id in
        the first place. events.source itself is free text and not a
        reliable per-source-instance key, so this id-list join is the
        correct link, not events.source.

        Returns [] (not an error) for an empty source_event_ids list - a
        source with no log_events in the requested window has nothing to
        join against, which is a legitimate "no activity yet" case, not a
        query failure.
        """
        if not source_event_ids:
            return []

        conditions = ["source_event_id = ANY(%(source_event_ids)s)"]
        params: dict[str, Any] = {"source_event_ids": source_event_ids}

        if tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids

        where_clause = " AND ".join(conditions)
        query = f"SELECT * FROM events WHERE {where_clause} ORDER BY created_at DESC"

        results = await self.db.execute(query, params)
        return [self._row_to_event(row) for row in results]

    async def list_by_ids(
        self,
        event_ids: list[str],
        tenant_ids: list[str] | None = None,
    ) -> list[Event]:
        """Fetch a bounded set of parent events within an optional tenant scope."""
        if not event_ids:
            return []
        conditions = ["id = ANY(%(event_ids)s)"]
        params: dict[str, Any] = {"event_ids": list(dict.fromkeys(event_ids))}
        if tenant_ids is not None:
            if not tenant_ids:
                return []
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids
        rows = await self.db.execute(
            f"SELECT * FROM events WHERE {' AND '.join(conditions)}",
            params,
        )
        return [self._row_to_event(row) for row in rows]

    async def update_status(
        self,
        event_id: str,
        status: EventStatus,
        risk_score: int | None = None,
        severity: SeverityLevel | None = None,
        findings_count: int | None = None,
    ) -> Event | None:
        """Update event processing status."""
        updates = ["status = %(status)s"]
        params: dict[str, Any] = {"id": event_id, "status": status.value}

        if status == EventStatus.COMPLETED:
            updates.append("processed_at = %(processed_at)s")
            params["processed_at"] = datetime.now(timezone.utc)

        if risk_score is not None:
            updates.append("risk_score = %(risk_score)s")
            params["risk_score"] = risk_score

        if severity is not None:
            updates.append("severity = %(severity)s")
            params["severity"] = severity.value

        if findings_count is not None:
            updates.append("findings_count = %(findings_count)s")
            params["findings_count"] = findings_count

        query = f"""
            UPDATE events
            SET {", ".join(updates)}
            WHERE id = %(id)s
            RETURNING *
        """

        result = await self.db.execute_one(query, params)
        return self._row_to_event(result) if result else None

    async def count(
        self,
        event_type: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        tenant_ids: list[str] | None = None,
    ) -> int:
        """Count events with filters, optionally scoped to tenant_ids."""
        conditions = []
        params: dict[str, Any] = {}

        if event_type:
            conditions.append("event_type = %(event_type)s")
            params["event_type"] = event_type

        if status:
            conditions.append("status = %(status)s")
            params["status"] = status

        if severity:
            conditions.append("severity = %(severity)s")
            params["severity"] = severity

        if search:
            conditions.append("(source ILIKE %(search)s OR raw_data::text ILIKE %(search)s)")
            params["search"] = f"%{search}%"

        if start_time:
            conditions.append("created_at >= %(start_time)s")
            params["start_time"] = start_time

        if end_time:
            conditions.append("created_at <= %(end_time)s")
            params["end_time"] = end_time

        if tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT COUNT(*) as count FROM events WHERE {where_clause}"

        result = await self.db.execute_one(query, params)
        return result["count"] if result else 0

    async def get_statistics(self, tenant_ids: list[str] | None = None) -> dict[str, Any]:
        """Get event statistics, optionally scoped to tenant_ids."""
        tenant_clause = ""
        params: dict[str, Any] = {}
        if tenant_ids is not None:
            tenant_clause = "AND tenant_id = ANY(%(tenant_ids)s)"
            params["tenant_ids"] = tenant_ids

        query = f"""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'processing') as processing,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                AVG(risk_score) as avg_risk_score
            FROM events
            WHERE created_at > NOW() - INTERVAL '24 hours'
            {tenant_clause}
        """

        result = await self.db.execute_one(query, params)
        stats = dict(result) if result else {}

        # Per-type breakdown, same 24-hour window as the aggregate query
        # above. Returned separately since COUNT(*) FILTER can't produce a
        # dynamic set of columns for an open-ended set of event types.
        type_query = f"""
            SELECT event_type, COUNT(*) as count
            FROM events
            WHERE created_at > NOW() - INTERVAL '24 hours'
            {tenant_clause}
            GROUP BY event_type
        """
        type_rows = await self.db.execute(type_query, params)
        stats["by_type"] = {row["event_type"]: row["count"] for row in type_rows}

        return stats

    def _row_to_event(self, row: dict[str, Any]) -> Event:
        """Convert database row to Event model."""
        return Event(
            id=str(row["id"]),
            event_type=row["event_type"],
            source=row["source"],
            raw_data=row["raw_data"],
            status=row["status"],
            processed_at=row.get("processed_at"),
            risk_score=row.get("risk_score", 0),
            severity=row.get("severity", "info"),
            findings_count=row.get("findings_count", 0),
            correlation_id=str(row["correlation_id"]) if row.get("correlation_id") else None,
            related_events=[str(e) for e in row.get("related_events", [])],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tenant_id=row.get("tenant_id"),
            source_event_id=row.get("source_event_id"),
        )


# Singleton
_event_repo: EventRepository | None = None


def get_event_repository() -> EventRepository:
    """Get the event repository."""
    global _event_repo
    if _event_repo is None:
        _event_repo = EventRepository()
    return _event_repo
