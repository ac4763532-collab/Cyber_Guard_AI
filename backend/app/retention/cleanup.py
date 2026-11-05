"""
CyberGuard AI - Evidence-Aware Retention Cleanup

Deletes raw log telemetry (log_events) once it is both past the
configured retention cutoff AND provably not needed as evidence. This
is the only place in the codebase that deletes log_events rows for
retention purposes - it replaces the three dead/no-op attempts that
previously existed (LogEventRepository.delete_old, Celery's
cleanup_old_events task, correlated_activities.delete_old_activities),
none of which were ever actually wired to a real schedule.

Scope: this module ONLY ever deletes from `log_events` (raw collector
telemetry). It never deletes from `events`, `findings`, `alerts`,
`correlated_activities`, or `notifications` - those are
evidence/detection-result tables, not raw telemetry, and are explicitly
out of scope for this cleanup.

Evidence-safety rule (the core invariant this module exists to enforce):
A log_events row is eligible for deletion only when ALL of:
  1. row.timestamp < now - retention_days (age cutoff)
  2. row.legal_hold = false (explicit preservation flag, never auto-set,
     only ever set by an operator/compliance action - see
     log_events.legal_hold in app/database/schema.py)
  3. No Finding references this row, even indirectly.

Why (3) is checked the way it is: findings.event_id has a hard foreign
key to events.id, but log_events rows are never directly referenced by
findings - the link is log_events.id -> (as a string) ->
events.source_event_id -> findings.event_id (see
EventRepository.get_or_create_from_log_event in
app/database/repositories/events.py, and
_resolve_event_id_for_finding in app/event_bus/dispatcher_integration.py,
which is the ONLY code path that ever creates that bridging `events`
row). That bridging row is only ever created when a finding is about to
be persisted for that log event - so "no `events` row exists for this
log_events.id" already implies "no finding exists for it", but this
module checks the full chain through to `findings` explicitly (rather
than stopping at "no events row") so it stays correct even if some
future code path ever creates an `events` row for another reason.

Transitive protection: alerts/correlated_activities are never created
without a Finding existing first in this codebase (every write path for
those tables is reached from app/correlation/finding_lifecycle.py's
on_finding_created(), which only runs after a Finding is persisted -
confirmed by inspection, there is no admin/manual "create alert without
a finding" endpoint). So "no Finding references this log_events row"
transitively means no alert or correlation references it either - this
module does not need to separately query those tables.

If this invariant ever changes (e.g. a future manual-alert-creation
endpoint is added that does not go through a Finding), this module's
safety guarantee breaks silently unless that change also updates the
exists-check below. This is called out here deliberately so it is not
missed.

Observability: every run logs, per tenant, the retention cutoff used,
how many rows were deleted, and how many delete attempts failed -
never the row contents (message/raw_content/extracted_fields are
never included in any log line this module emits).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog

from app.config import get_settings
from app.database.connection import get_database

logger = structlog.get_logger(__name__)


# The exists-check described above, as a single reusable SQL fragment.
# %(id_text)s is log_events.id cast to text so it can be compared against
# events.source_event_id (VARCHAR) without a cast on every row of
# log_events itself - the correlated subquery below casts per-candidate
# instead, which is fine at retention-cleanup batch sizes (hundreds of
# rows per batch, not millions).
_REFERENCED_BY_FINDING_SQL = """
    EXISTS (
        SELECT 1
        FROM events e
        JOIN findings f ON f.event_id = e.id
        WHERE e.source_event_id = log_events.id::text
    )
"""


class RetentionCleanupResult:
    """Outcome of one cleanup run, safe to log/serialize (no row content)."""

    def __init__(self) -> None:
        self.cutoff: datetime | None = None
        self.tenants_scanned = 0
        self.deleted_total = 0
        self.retained_referenced_total = 0
        self.failed_tenants: list[str] = []
        self.per_tenant_deleted: dict[str, int] = {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "cutoff": self.cutoff.isoformat() if self.cutoff else None,
            "tenants_scanned": self.tenants_scanned,
            "deleted_total": self.deleted_total,
            "failed_tenants": self.failed_tenants,
            "per_tenant_deleted": self.per_tenant_deleted,
        }


async def _list_distinct_tenant_ids() -> list[str | None]:
    """
    Distinct tenant_id values currently present in log_events, including
    NULL (pre-tenant-column rows). Each is cleaned up as its own scoped
    batch loop so cleanup is always tenant-bounded, never a single
    cross-tenant DELETE.
    """
    db = get_database()
    rows = await db.execute("SELECT DISTINCT tenant_id FROM log_events", {})
    return [row["tenant_id"] for row in rows]


async def _delete_one_batch(
    *,
    tenant_id: str | None,
    cutoff: datetime,
    batch_size: int,
) -> int:
    """
    Delete up to `batch_size` eligible log_events rows for one tenant
    (or the NULL/"no tenant" bucket when tenant_id is None).

    Eligible = older than cutoff AND legal_hold is not true AND not
    referenced by any Finding (see module docstring). Selects the
    candidate ids first (bounded by LIMIT) then deletes exactly those
    ids, rather than a single DELETE ... LIMIT (not supported directly
    by Postgres) or an unbounded DELETE ... WHERE (which could lock/
    scan an unbounded number of rows on a large table).

    Returns the number of rows actually deleted (0 means nothing left
    eligible for this tenant on this call - the caller's loop stops).
    """
    db = get_database()
    tenant_clause = "tenant_id = %(tenant_id)s" if tenant_id is not None else "tenant_id IS NULL"

    select_candidates = f"""
        SELECT id
        FROM log_events
        WHERE {tenant_clause}
          AND timestamp < %(cutoff)s
          AND legal_hold = false
          AND NOT {_REFERENCED_BY_FINDING_SQL}
        ORDER BY timestamp ASC
        LIMIT %(batch_size)s
    """
    params: dict[str, Any] = {"cutoff": cutoff, "batch_size": batch_size}
    if tenant_id is not None:
        params["tenant_id"] = tenant_id

    candidates = await db.execute(select_candidates, params)
    if not candidates:
        return 0

    candidate_ids = [row["id"] for row in candidates]

    delete_query = "DELETE FROM log_events WHERE id = ANY(%(ids)s)"
    await db.execute(delete_query, {"ids": candidate_ids})

    return len(candidate_ids)


async def _count_retained_referenced(
    *,
    tenant_id: str | None,
    cutoff: datetime,
) -> int:
    """
    Count rows that are past the age cutoff but retained anyway because
    a Finding references them. Purely observational (reported in the
    run summary so operators can see evidence is being protected, not
    silently never-cleaned) - never used to decide what to delete.
    """
    db = get_database()
    tenant_clause = "tenant_id = %(tenant_id)s" if tenant_id is not None else "tenant_id IS NULL"

    query = f"""
        SELECT COUNT(*) as count
        FROM log_events
        WHERE {tenant_clause}
          AND timestamp < %(cutoff)s
          AND legal_hold = false
          AND {_REFERENCED_BY_FINDING_SQL}
    """
    params: dict[str, Any] = {"cutoff": cutoff}
    if tenant_id is not None:
        params["tenant_id"] = tenant_id

    result = await db.execute_one(query, params)
    return result["count"] if result else 0


async def run_retention_cleanup() -> RetentionCleanupResult:
    """
    Run one evidence-aware retention cleanup pass across all tenants.

    Safe to call repeatedly / on any schedule: each call independently
    re-evaluates eligibility against the current clock, so a prior
    partial run (e.g. interrupted by a restart) is simply picked back
    up - there is no persisted "cleanup job" state to corrupt or resume
    incorrectly. Bounded per tenant per run via
    log_event_retention_max_batches_per_tenant_per_run so one run can
    never run unboundedly long even if a tenant has a very large
    eligible backlog; the next scheduled run continues where this one
    left off.
    """
    settings = get_settings()
    result = RetentionCleanupResult()

    if not settings.log_event_retention_enabled:
        logger.info("Retention cleanup skipped - log_event_retention_enabled is false")
        return result

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.log_event_retention_days)
    result.cutoff = cutoff
    batch_size = settings.log_event_retention_batch_size
    max_batches = settings.log_event_retention_max_batches_per_tenant_per_run

    try:
        tenant_ids = await _list_distinct_tenant_ids()
    except Exception as e:
        logger.error("Retention cleanup: failed to list tenants - aborting run", error=str(e))
        return result

    for tenant_id in tenant_ids:
        result.tenants_scanned += 1
        tenant_label = tenant_id or "(none)"
        deleted_for_tenant = 0

        try:
            for _ in range(max_batches):
                deleted = await _delete_one_batch(
                    tenant_id=tenant_id,
                    cutoff=cutoff,
                    batch_size=batch_size,
                )
                deleted_for_tenant += deleted
                if deleted < batch_size:
                    # Fewer than a full batch came back eligible - this
                    # tenant has no more eligible rows right now, stop
                    # early rather than running max_batches empty queries.
                    break

            retained_referenced = await _count_retained_referenced(
                tenant_id=tenant_id, cutoff=cutoff
            )
            result.retained_referenced_total += retained_referenced

            if deleted_for_tenant or retained_referenced:
                logger.info(
                    "Retention cleanup processed tenant",
                    tenant_id=tenant_label,
                    cutoff=cutoff.isoformat(),
                    deleted=deleted_for_tenant,
                    retained_referenced_by_finding=retained_referenced,
                )

        except Exception as e:
            result.failed_tenants.append(tenant_label)
            logger.error(
                "Retention cleanup failed for tenant - other tenants unaffected",
                tenant_id=tenant_label,
                error=str(e),
            )
            continue

        result.deleted_total += deleted_for_tenant
        if deleted_for_tenant:
            result.per_tenant_deleted[tenant_label] = deleted_for_tenant

    logger.info(
        "Retention cleanup run complete",
        cutoff=cutoff.isoformat(),
        tenants_scanned=result.tenants_scanned,
        deleted_total=result.deleted_total,
        retained_referenced_total=result.retained_referenced_total,
        failed_tenants=result.failed_tenants,
    )
    return result
