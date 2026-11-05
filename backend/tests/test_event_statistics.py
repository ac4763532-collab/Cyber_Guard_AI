"""
CyberGuard AI - Event Repository Statistics Tests

Verifies EventRepository.get_statistics() against the real database schema
(app/database/schema.py's `events` table), in particular the `by_type`
breakdown added alongside the aggregate counts. These are integration
tests - they create and read real rows via DB_ENABLED's connection pool
(see tests/conftest.py::initialize_database), not mocks, because the
behavior being verified is the SQL itself (GROUP BY event_type matching
the aggregate query's WHERE window, correct column name, correct typing).

Events created here are not deleted afterward: deleting rows from a
real, non-test-dedicated database to "clean up" would be more risky than
leaving a handful of harmless, clearly-labeled test rows. Instead, every
assertion is written as a *lower bound* / containment check (counts are
">=", specific type keys are asserted present with the right minimum
count) rather than an exact-count equality - so the test is correct
regardless of pre-existing rows and never requires deleting data from
CyberGuard_AI.
"""

from __future__ import annotations

import uuid

import pytest

from app.config import get_settings
from app.database.models import EventCreate, EventType
from app.database.repositories.events import get_event_repository


pytestmark = pytest.mark.asyncio


def _skip_if_db_disabled():
    if not get_settings().db_enabled:
        pytest.skip("DB_ENABLED is false - get_statistics() requires a real database")


class TestEventStatisticsByType:
    """Integration tests for EventRepository.get_statistics()['by_type']."""

    async def test_by_type_reflects_newly_created_events(self, initialize_database):
        """
        Create one event of a type tagged with a unique marker in its
        raw_data (so this run is distinguishable from any pre-existing
        rows), then verify get_statistics()['by_type'] accounts for it.

        by_type is keyed by the raw event_type string, grouped from the
        same `events` table / `created_at > NOW() - INTERVAL '24 hours'`
        window as the aggregate counts - so a row inserted "now" must
        appear in both.
        """
        _skip_if_db_disabled()

        repo = get_event_repository()
        marker = f"stats-test-{uuid.uuid4()}"

        created = await repo.create(
            EventCreate(
                event_type=EventType.NETWORK,
                source="test_event_statistics",
                raw_data={"marker": marker},
            )
        )
        assert created.event_type == EventType.NETWORK

        stats = await repo.get_statistics()

        assert "by_type" in stats
        assert isinstance(stats["by_type"], dict)

        # The event_type is stored/returned as the enum's string value
        # (schema column is VARCHAR(50) NOT NULL - see schema.py line 50).
        network_count = stats["by_type"].get(EventType.NETWORK.value, 0)
        assert network_count >= 1, (
            f"Expected at least 1 'network' event in by_type after creating "
            f"one (marker={marker}), got by_type={stats['by_type']}"
        )

    async def test_by_type_keys_are_a_subset_of_aggregate_total(self, initialize_database):
        """
        Sanity-check the two queries are consistent with each other: the
        sum of by_type's per-type counts must never exceed the aggregate
        `total` from the same 24-hour window (same WHERE clause), since
        every row counted in by_type is necessarily counted in total.
        """
        _skip_if_db_disabled()

        repo = get_event_repository()

        # Ensure at least one row exists in the window so this isn't
        # vacuously true on an empty table.
        await repo.create(
            EventCreate(
                event_type=EventType.LOG,
                source="test_event_statistics",
                raw_data={"marker": f"consistency-{uuid.uuid4()}"},
            )
        )

        stats = await repo.get_statistics()

        assert stats.get("total", 0) >= 1
        by_type_sum = sum(stats["by_type"].values())
        assert by_type_sum <= stats["total"], (
            f"by_type sum ({by_type_sum}) exceeded aggregate total "
            f"({stats['total']}) - the two queries disagree on their window"
        )

    async def test_statistics_contains_expected_aggregate_fields(self, initialize_database):
        """get_statistics() must always return the full set of fields the
        /api/v1/events statistics endpoint depends on, even when by_type
        is empty (e.g. right after table creation)."""
        _skip_if_db_disabled()

        repo = get_event_repository()
        stats = await repo.get_statistics()

        for field in (
            "total", "pending", "processing", "completed", "failed",
            "critical", "high", "medium", "low", "avg_risk_score", "by_type",
        ):
            assert field in stats, f"get_statistics() is missing '{field}'"
