#!/usr/bin/env python3
"""
Backfill event_type for existing `events` rows mis-categorized as "log".

Why this exists: EventRepository.get_or_create_from_log_event() used to
default event_type to EventType.LOG and nothing overrode it (see
app/event_bus/dispatcher_integration.py's _resolve_event_id_for_finding(),
now fixed to pass the real category). Every events row created before
that fix - including genuine local_network_monitor connection telemetry -
is stuck with event_type='log' no matter its real source.

This script corrects exactly one case, using only a reliable structural
signal already visible on the Events page itself:

    source LIKE 'log_collector:local_network_monitor%'  AND  event_type = 'log'
        -> event_type = 'network'

That `source` prefix is set verbatim by log_event_to_security_event()
(app/logs/event_bus_integration.py: `source=f"log_collector:{log_event.source_type.value}"`)
for every event from the local network monitor collector - it is not a
heuristic over free text or an IP-address guess, it is the same literal
string already observed on the Events page for these rows.

Deliberately NOT done:
- No row is reclassified based on IP/port presence in raw_data.
- No row already tagged 'email' or 'network' is touched.
- Rows whose source doesn't match a known, reliable pattern are left
  exactly as-is and counted separately - never guessed at.
- No row is deleted, and no event is fabricated.

Usage (dry-run by default; requires --apply to actually write):
    python -m scripts.backfill_event_categories
    python -m scripts.backfill_event_categories --apply
"""

from __future__ import annotations

import argparse
import asyncio
import sys

# Fix Windows event loop for psycopg async - same fix used by
# scripts/live_e2e_verification.py for the same reason.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, ".")

# The one reliable, structural signal this script acts on - matches the
# literal source string set by log_event_to_security_event() for every
# local network monitor event. Kept as a named constant so the WHERE
# clause below is never duplicated/out of sync with the report query.
NETWORK_SOURCE_PATTERN = "log_collector:local_network_monitor%"


async def _bootstrap_db():
    """Initialize the DB pool for standalone script use."""
    from app.database.connection import get_database

    db = get_database()
    await db.initialize()
    return db


async def _report(db) -> dict:
    """Dry-run report: counts only, no row contents, per the project's
    existing observability convention (see app/retention/cleanup.py)."""
    to_reclassify = await db.execute_one(
        """
        SELECT COUNT(*) AS count
        FROM events
        WHERE event_type = 'log'
          AND source LIKE %(pattern)s
        """,
        {"pattern": NETWORK_SOURCE_PATTERN},
    )
    already_network = await db.execute_one(
        "SELECT COUNT(*) AS count FROM events WHERE event_type = 'network'"
    )
    already_email = await db.execute_one(
        "SELECT COUNT(*) AS count FROM events WHERE event_type = 'email'"
    )
    remaining_log = await db.execute_one(
        """
        SELECT COUNT(*) AS count
        FROM events
        WHERE event_type = 'log'
          AND source NOT LIKE %(pattern)s
        """,
        {"pattern": NETWORK_SOURCE_PATTERN},
    )
    by_tenant = await db.execute(
        """
        SELECT tenant_id, COUNT(*) AS count
        FROM events
        WHERE event_type = 'log'
          AND source LIKE %(pattern)s
        GROUP BY tenant_id
        ORDER BY count DESC
        """,
        {"pattern": NETWORK_SOURCE_PATTERN},
    )
    return {
        "to_reclassify_as_network": to_reclassify["count"] if to_reclassify else 0,
        "already_network": already_network["count"] if already_network else 0,
        "already_email": already_email["count"] if already_email else 0,
        "left_as_log_untouched": remaining_log["count"] if remaining_log else 0,
        "to_reclassify_by_tenant": [
            {"tenant_id": row["tenant_id"], "count": row["count"]} for row in by_tenant
        ],
    }


async def _apply(db) -> int:
    """Perform the actual reclassification. Returns rows updated."""
    rows = await db.execute(
        """
        UPDATE events
        SET event_type = 'network', updated_at = NOW()
        WHERE event_type = 'log'
          AND source LIKE %(pattern)s
        RETURNING id
        """,
        {"pattern": NETWORK_SOURCE_PATTERN},
    )
    return len(rows)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually run the UPDATE. Without this flag, only reports counts.",
    )
    args = parser.parse_args()

    db = await _bootstrap_db()

    print("=" * 70)
    print("Event category backfill - local_network_monitor -> network")
    print("=" * 70)
    print(f"Pattern: source LIKE '{NETWORK_SOURCE_PATTERN}' AND event_type = 'log'")
    print()

    before = await _report(db)
    print("Before:")
    print(f"  To reclassify as 'network': {before['to_reclassify_as_network']}")
    print(f"  Already 'network':          {before['already_network']}")
    print(f"  Already 'email':            {before['already_email']}")
    print(f"  Left as 'log' (untouched):  {before['left_as_log_untouched']}")
    if before["to_reclassify_by_tenant"]:
        print("  By tenant:")
        for row in before["to_reclassify_by_tenant"]:
            print(f"    tenant_id={row['tenant_id']!r}: {row['count']}")
    print()

    if not args.apply:
        print("Dry run only - no changes made. Re-run with --apply to update rows.")
        return

    if before["to_reclassify_as_network"] == 0:
        print("Nothing to reclassify - no changes made.")
        return

    updated = await _apply(db)
    print(f"Applied: {updated} row(s) reclassified from 'log' to 'network'.")
    print()

    after = await _report(db)
    print("After:")
    print(f"  Still matching pattern as 'log' (should be 0): {after['to_reclassify_as_network']}")
    print(f"  Now 'network':                                 {after['already_network']}")
    print(f"  Left as 'log' (untouched, different sources):  {after['left_as_log_untouched']}")


if __name__ == "__main__":
    asyncio.run(main())
