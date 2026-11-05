"""Tenant-scoped persistence for generated security reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from psycopg.types.json import Json

from app.database.connection import get_database
from app.database.models.incidents import Report, ReportCreate, ReportStatus, ReportFormat


class ReportRepository:
    def __init__(self):
        self.db = get_database()

    async def create(self, report: ReportCreate) -> Report:
        now = datetime.now(timezone.utc)
        report_id = str(uuid4())
        query = """
            INSERT INTO reports (
                id, tenant_id, report_type, title, description, generated_by,
                period_start, period_end, filters, data, narrative,
                file_format, status, created_at, updated_at
            ) VALUES (
                %(id)s, %(tenant_id)s, %(report_type)s, %(title)s, %(description)s,
                %(generated_by)s, %(period_start)s, %(period_end)s, %(filters)s,
                %(data)s, %(narrative)s, %(file_format)s, %(status)s, %(now)s, %(now)s
            )
            ON CONFLICT (tenant_id, report_type, period_start, period_end, generated_by) DO UPDATE SET
                data = EXCLUDED.data,
                narrative = EXCLUDED.narrative,
                file_format = EXCLUDED.file_format,
                status = EXCLUDED.status,
                updated_at = EXCLUDED.updated_at
            RETURNING *
        """
        row = await self.db.execute_one(query, {
            "id": report_id,
            "tenant_id": report.tenant_id,
            "report_type": report.report_type,
            "title": report.title,
            "description": report.description,
            "generated_by": report.generated_by,
            "period_start": report.period_start,
            "period_end": report.period_end,
            "filters": Json(report.filters),
            "data": Json(report.data),
            "narrative": report.narrative,
            "file_format": report.file_format.value,
            "status": ReportStatus.COMPLETED.value,
            "now": now,
        })
        if row is None:
            row = await self.db.execute_one(
                """SELECT * FROM reports WHERE tenant_id = %(tenant_id)s
                   AND report_type = %(report_type)s AND period_start = %(period_start)s
                   AND period_end = %(period_end)s AND generated_by = %(generated_by)s""",
                {"tenant_id": report.tenant_id, "report_type": report.report_type,
                 "period_start": report.period_start, "period_end": report.period_end,
                 "generated_by": report.generated_by},
            )
        if row is None:
            raise RuntimeError("Report upsert returned no row")
        return self._row_to_report(row)

    async def list(
        self,
        tenant_ids: list[str] | None,
        limit: int = 100,
        report_type: str | None = None,
        status: ReportStatus | None = None,
    ) -> list[Report]:
        if tenant_ids is not None and not tenant_ids:
            return []
        conditions = []
        params: dict[str, Any] = {"limit": limit}
        if tenant_ids is not None:
            conditions.append("tenant_id = ANY(%(tenant_ids)s)")
            params["tenant_ids"] = tenant_ids
        if report_type:
            conditions.append("report_type = %(report_type)s")
            params["report_type"] = report_type
        if status:
            conditions.append("status = %(status)s")
            params["status"] = status.value
        where_clause = " AND ".join(conditions) if conditions else "TRUE"
        rows = await self.db.execute(
            f"SELECT * FROM reports WHERE {where_clause} ORDER BY created_at DESC LIMIT %(limit)s",
            params,
        )
        return [self._row_to_report(row) for row in rows]

    async def get(
        self,
        report_id: str,
        tenant_ids: list[str] | None,
    ) -> Report | None:
        if tenant_ids is not None:
            if not tenant_ids:
                return None
            row = await self.db.execute_one(
                "SELECT * FROM reports WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s)",
                {"id": report_id, "tenant_ids": tenant_ids},
            )
        else:
            row = await self.db.execute_one(
                "SELECT * FROM reports WHERE id = %(id)s", {"id": report_id}
            )
        return self._row_to_report(row) if row else None

    async def update_file_info(
        self,
        report_id: str,
        tenant_ids: list[str] | None,
        file_path: str,
        file_format: ReportFormat,
        file_size_bytes: int,
    ) -> Report | None:
        now = datetime.now(timezone.utc)
        if tenant_ids is None:
            query = """
                UPDATE reports SET file_path = %(file_path)s, file_format = %(file_format)s,
                    file_size_bytes = %(file_size_bytes)s, updated_at = %(now)s
                WHERE id = %(id)s RETURNING *
            """
            params = {
                "id": report_id, "file_path": file_path,
                "file_format": file_format.value, "file_size_bytes": file_size_bytes,
                "now": now,
            }
        else:
            query = """
                UPDATE reports SET file_path = %(file_path)s, file_format = %(file_format)s,
                    file_size_bytes = %(file_size_bytes)s, updated_at = %(now)s
                WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s) RETURNING *
            """
            params = {
                "id": report_id, "file_path": file_path,
                "file_format": file_format.value, "file_size_bytes": file_size_bytes,
                "tenant_ids": tenant_ids, "now": now,
            }
        row = await self.db.execute_one(query, params)
        return self._row_to_report(row) if row else None

    async def update_status(
        self,
        report_id: str,
        tenant_ids: list[str] | None,
        status: ReportStatus,
        error_message: str | None = None,
    ) -> Report | None:
        now = datetime.now(timezone.utc)
        if tenant_ids is None:
            query = """
                UPDATE reports SET status = %(status)s, error_message = %(error_message)s,
                    updated_at = %(now)s
                WHERE id = %(id)s RETURNING *
            """
            params = {
                "id": report_id, "status": status.value,
                "error_message": error_message, "now": now,
            }
        else:
            query = """
                UPDATE reports SET status = %(status)s, error_message = %(error_message)s,
                    updated_at = %(now)s
                WHERE id = %(id)s AND tenant_id = ANY(%(tenant_ids)s) RETURNING *
            """
            params = {
                "id": report_id, "status": status.value,
                "error_message": error_message, "tenant_ids": tenant_ids, "now": now,
            }
        row = await self.db.execute_one(query, params)
        return self._row_to_report(row) if row else None

    @staticmethod
    def _row_to_report(row: dict[str, Any]) -> Report:
        return Report(
            id=str(row["id"]),
            tenant_id=row["tenant_id"],
            report_type=row["report_type"],
            title=row["title"],
            description=row.get("description"),
            generated_by=row["generated_by"],
            period_start=row.get("period_start"),
            period_end=row.get("period_end"),
            filters=row.get("filters") or {},
            data=row.get("data") or {},
            narrative=row.get("narrative"),
            file_path=row.get("file_path"),
            file_format=ReportFormat(row.get("file_format", "json")),
            file_size_bytes=row.get("file_size_bytes"),
            status=ReportStatus(row.get("status", "completed")),
            error_message=row.get("error_message"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


_report_repository: ReportRepository | None = None


def get_report_repository() -> ReportRepository:
    global _report_repository
    if _report_repository is None:
        _report_repository = ReportRepository()
    return _report_repository