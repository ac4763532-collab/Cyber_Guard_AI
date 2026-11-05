"""Tenant-scoped persistence for incident lifecycle records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from psycopg.types.json import Json

from app.database.connection import get_database
from app.database.models.incidents import Incident, IncidentCreate


class IncidentRepository:
    def __init__(self):
        self.db = get_database()

    async def create_or_update_from_finding(self, incident: IncidentCreate) -> Incident:
        now = datetime.now(timezone.utc)
        incident_id = str(uuid4())
        initial_history = [{
            "action": "created",
            "actor_id": incident.created_by,
            "timestamp": now.isoformat(),
            "reason": "Qualified finding met incident-creation policy.",
        }]
        query = """
            INSERT INTO incidents (
                id, tenant_id, fingerprint, title, description, severity, status,
                finding_ids, event_ids, recommendations, history, created_by,
                created_at, updated_at
            ) VALUES (
                %(id)s, %(tenant_id)s, %(fingerprint)s, %(title)s, %(description)s,
                %(severity)s, 'open', %(finding_ids)s::uuid[], %(event_ids)s::uuid[],
                %(recommendations)s, %(history)s, %(created_by)s, %(now)s, %(now)s
            )
            ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
                finding_ids = ARRAY(
                    SELECT DISTINCT value FROM unnest(incidents.finding_ids || EXCLUDED.finding_ids) AS value
                ),
                event_ids = ARRAY(
                    SELECT DISTINCT value FROM unnest(incidents.event_ids || EXCLUDED.event_ids) AS value
                ),
                recommendations = EXCLUDED.recommendations,
                updated_at = EXCLUDED.updated_at,
                history = CASE
                    WHEN NOT incidents.finding_ids @> EXCLUDED.finding_ids THEN
                        incidents.history || jsonb_build_array(jsonb_build_object(
                            'action', 'evidence_added',
                            'actor_id', EXCLUDED.created_by,
                            'timestamp', EXCLUDED.updated_at,
                            'finding_id', EXCLUDED.finding_ids[1],
                            'reason', 'Additional qualifying finding linked.'
                        ))
                    ELSE incidents.history
                END
            WHERE NOT incidents.finding_ids @> EXCLUDED.finding_ids
            RETURNING *
        """
        row = await self.db.execute_one(query, {
            "id": incident_id,
            "tenant_id": incident.tenant_id,
            "fingerprint": incident.fingerprint,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "finding_ids": [incident.finding_id],
            "event_ids": [incident.event_id],
            "recommendations": Json(incident.recommendations),
            "history": Json(initial_history),
            "created_by": incident.created_by,
            "now": now,
        })
        if row is None:
            row = await self.db.execute_one(
                "SELECT * FROM incidents WHERE tenant_id = %(tenant_id)s AND fingerprint = %(fingerprint)s",
                {"tenant_id": incident.tenant_id, "fingerprint": incident.fingerprint},
            )
        if row is None:
            raise RuntimeError("Incident upsert returned no row")
        return self._row_to_incident(row)

    async def list(
        self,
        tenant_ids: list[str] | None,
        limit: int = 100,
        status: str | None = None,
    ) -> list[Incident]:
        if tenant_ids is not None and not tenant_ids:
            return []
        conditions = []
        params: dict[str, Any] = {"limit": limit}
        if tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids
        if status:
            conditions.append("status = %(status)s")
            params["status"] = status
        where_clause = " AND ".join(conditions) if conditions else "TRUE"
        rows = await self.db.execute(
            f"SELECT * FROM incidents WHERE {where_clause} ORDER BY updated_at DESC LIMIT %(limit)s",
            params,
        )
        return [self._row_to_incident(row) for row in rows]

    async def get(self, incident_id: str, tenant_ids: list[str] | None) -> Incident | None:
        if tenant_ids is not None:
            if not tenant_ids:
                return None
            row = await self.db.execute_one(
                "SELECT * FROM incidents WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s)",
                {"id": incident_id, "tenant_ids": tenant_ids},
            )
        else:
            row = await self.db.execute_one(
                "SELECT * FROM incidents WHERE id = %(id)s", {"id": incident_id}
            )
        return self._row_to_incident(row) if row else None

    async def transition(
        self,
        incident_id: str,
        tenant_ids: list[str] | None,
        status: str,
        actor_id: str,
        reason: str,
    ) -> Incident | None:
        incident = await self.get(incident_id, tenant_ids)
        if incident is None:
            return None
        transitions = {
            "open": {"investigating"},
            "investigating": {"containment_in_progress", "resolved"},
            "containment_in_progress": {"investigating", "resolved"},
            "resolved": {"investigating", "closed"},
            "closed": set(),
        }
        if status not in transitions.get(incident.status, set()):
            raise ValueError(f"Transition from {incident.status} to {status} is not allowed")

        now = datetime.now(timezone.utc)
        history = incident.history + [{
            "action": "status_changed",
            "from_status": incident.status,
            "to_status": status,
            "actor_id": actor_id,
            "timestamp": now.isoformat(),
            "reason": reason,
        }]
        if tenant_ids is None:
            query = """
                UPDATE incidents SET status = %(status)s, history = %(history)s,
                    updated_at = %(updated_at)s
                WHERE id = %(id)s AND status = %(previous_status)s RETURNING *
            """
            params = {
                "status": status,
                "history": Json(history),
                "updated_at": now,
                "id": incident_id,
                "previous_status": incident.status,
            }
        else:
            query = """
                UPDATE incidents SET status = %(status)s, history = %(history)s,
                    updated_at = %(updated_at)s
                WHERE id = %(id)s AND status = %(previous_status)s
                    AND tenant_id = ANY(%(tenant_ids)s) RETURNING *
            """
            params = {
                "status": status,
                "history": Json(history),
                "updated_at": now,
                "id": incident_id,
                "tenant_ids": tenant_ids,
                "previous_status": incident.status,
            }
        row = await self.db.execute_one(query, params)
        if row is None:
            raise ValueError("Incident changed concurrently; refresh and retry the transition")
        return self._row_to_incident(row) if row else None

    @staticmethod
    def _row_to_incident(row: dict[str, Any]) -> Incident:
        return Incident(
            id=str(row["id"]),
            tenant_id=row["tenant_id"],
            fingerprint=row["fingerprint"],
            title=row["title"],
            description=row.get("description") or "",
            severity=row["severity"],
            status=row["status"],
            finding_ids=[str(item) for item in row.get("finding_ids", [])],
            alert_ids=[str(item) for item in row.get("alert_ids", [])],
            event_ids=[str(item) for item in row.get("event_ids", [])],
            correlation_ids=[str(item) for item in row.get("correlation_ids", [])],
            recommendations=row.get("recommendations") or [],
            actions_taken=row.get("actions_taken") or [],
            history=row.get("history") or [],
            created_by=row.get("created_by"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


_incident_repository: IncidentRepository | None = None


def get_incident_repository() -> IncidentRepository:
    global _incident_repository
    if _incident_repository is None:
        _incident_repository = IncidentRepository()
    return _incident_repository
