"""
CyberGuard AI - Audit Logging Service (Phase 1: Log Collection ->
Automatic Detection)

Real, minimal audit trail for security-sensitive actions, backed by the
existing (previously unused) `audit_log` table in
app/database/schema.py.

Call sites added in this phase: finding creation, log source
create/enable/disable/remove, finding status changes, and
security-sensitive processing failures. Not a retrofit of unrelated
routes - only the call sites this phase's spec names.

Security: never pass raw log message/raw_content or credentials into
old_value/new_value. Callers should pass IDs, status enums, and rule
metadata only - this module does not itself inspect values for secrets,
so the responsibility is on each call site (same trust boundary as the
rest of this codebase's redaction conventions, e.g.
app/logs/redaction.py for log content).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.database.connection import get_database


logger = structlog.get_logger(__name__)


async def record_audit_event(
    action: str,
    entity_type: str,
    entity_id: str | None,
    user_id: str | None,
    ip_address: str | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> None:
    """
    Record an audit log entry.

    This is fail-safe by design: a failure to write an audit record
    must never block or fail the action it is auditing (e.g. a finding
    was already correctly persisted - losing its audit trail entry due
    to a transient DB hiccup is a logged problem, not a reason to roll
    back or error out the caller). Exceptions are caught and logged,
    never re-raised.

    Args:
        action: Short action identifier, e.g. "finding_created",
            "log_source_created", "log_source_enabled",
            "log_source_disabled", "log_source_removed",
            "finding_status_changed", "log_processing_failed".
        entity_type: What kind of entity this concerns, e.g. "finding",
            "log_source".
        entity_id: The entity's ID, if applicable (None for events with
            no single entity, e.g. a startup-time failure).
        user_id: The acting user's ID, or None for system/automated
            actions (e.g. the consumer persisting a finding has no
            human user attached).
        ip_address: Caller's IP address, if known (e.g. from the HTTP
            request for interactive actions; None for background jobs).
        old_value: Prior state, IDs/enums/metadata only - never raw log
            content or credentials.
        new_value: New state, same redaction requirement as old_value.
    """
    try:
        db = get_database()
        if not db.is_initialized:
            # Database not available (e.g. db_enabled=False in this
            # environment, or not yet initialized at startup) - skip
            # rather than raise, consistent with this being a
            # best-effort trail, not a transactional requirement.
            logger.debug(
                "Audit log skipped - database not initialized",
                action=action,
                entity_type=entity_type,
            )
            return

        query = """
            INSERT INTO audit_log (
                id, action, entity_type, entity_id, user_id,
                ip_address, old_value, new_value, created_at
            )
            VALUES (
                %(id)s, %(action)s, %(entity_type)s, %(entity_id)s, %(user_id)s,
                %(ip_address)s, %(old_value)s, %(new_value)s, %(created_at)s
            )
        """
        from psycopg.types.json import Json

        await db.execute(query, {
            "id": str(uuid4()),
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": user_id,
            "ip_address": ip_address,
            "old_value": Json(old_value) if old_value is not None else None,
            "new_value": Json(new_value) if new_value is not None else None,
            "created_at": datetime.now(timezone.utc),
        })

    except Exception as e:
        # Never let audit logging break the action it's auditing.
        logger.error(
            "Failed to record audit event",
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(e),
        )
