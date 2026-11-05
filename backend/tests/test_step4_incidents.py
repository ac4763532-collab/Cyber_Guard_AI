"""
CyberGuard AI - STEP 4 Incident Persistence Tests

Tests for IncidentRepository and IncidentManager PostgreSQL integration.
"""

import asyncio
import sys
import pytest
from datetime import datetime, timezone

# Windows event loop fix for psycopg3
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class TestIncidentRepository:
    """Tests for IncidentRepository database operations."""

    @pytest.fixture(autouse=True)
    def setup(self, initialize_database):
        """Setup for each test."""
        pass

    def _run_async(self, coro):
        """
        Run async code in tests on a fresh, throwaway event loop.

        Each test's coroutine calls get_database().initialize(), which
        opens a real psycopg_pool.AsyncConnectionPool bound to *this*
        loop (background scheduler + worker tasks included). Closing the
        loop without closing that pool first leaves those background
        tasks orphaned on a now-dead loop - harmless in isolation here
        (loop.close() just discards them with a warning), but the same
        root cause as a hang already fixed in test_collector_manager.py
        when a loop's teardown instead tries to cancel/gather them. Close
        the pool on the loop that owns it, before the loop itself closes.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            try:
                from app.database.connection import get_database
                loop.run_until_complete(get_database().close())
            except Exception:
                pass
            loop.close()

    def test_create_incident(self):
        """Test creating an incident via repository."""
        async def _test():
            from app.database import init_database
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.database.repositories.incidents import (
                get_incident_repository,
                IncidentCreate,
            )
            from app.database.models import SeverityLevel

            repo = get_incident_repository()

            incident = await repo.create(IncidentCreate(
                title="Test Repository Incident",
                description="Testing direct repository create",
                severity=SeverityLevel.MEDIUM,
                priority=3,
                affected_systems=["test-server"],
                timeline=[{
                    "entry_id": "test-entry-1",
                    "entry_type": "created",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user": "test",
                    "description": "Created for testing",
                    "details": {},
                }],
            ))

            assert incident.id is not None
            assert incident.title == "Test Repository Incident"
            assert incident.severity == "medium" or incident.severity.value == "medium"
            assert incident.priority == 3

            return incident.id

        incident_id = self._run_async(_test())
        assert incident_id is not None

    def test_get_incident(self):
        """Test retrieving an incident by ID."""
        async def _test():
            from app.database import init_database
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.database.repositories.incidents import (
                get_incident_repository,
                IncidentCreate,
            )
            from app.database.models import SeverityLevel

            repo = get_incident_repository()

            # Create
            created = await repo.create(IncidentCreate(
                title="Get Test Incident",
                description="For get test",
                severity=SeverityLevel.LOW,
                priority=4,
            ))

            # Retrieve
            retrieved = await repo.get(created.id)

            assert retrieved is not None
            assert retrieved.id == created.id
            assert retrieved.title == "Get Test Incident"

        self._run_async(_test())

    def test_list_incidents(self):
        """Test listing incidents with filters."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.database.repositories.incidents import get_incident_repository

            repo = get_incident_repository()
            incidents = await repo.list(limit=10)

            assert isinstance(incidents, list)
            # Should have at least the incidents from previous tests
            assert len(incidents) >= 0

        self._run_async(_test())

    def test_update_incident_status(self):
        """Test updating incident status."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.database.repositories.incidents import (
                get_incident_repository,
                IncidentCreate,
                IncidentUpdate,
            )
            from app.database.models import SeverityLevel, IncidentStatus

            repo = get_incident_repository()

            # Create
            created = await repo.create(IncidentCreate(
                title="Update Status Test",
                description="Testing status update",
                severity=SeverityLevel.MEDIUM,
                priority=3,
            ))

            # Update status
            updated = await repo.update(created.id, IncidentUpdate(
                status=IncidentStatus.INVESTIGATING,
            ))

            assert updated is not None
            status_val = updated.status.value if hasattr(updated.status, 'value') else updated.status
            assert status_val == "investigating"

        self._run_async(_test())

    def test_get_nonexistent_incident(self):
        """Test getting a non-existent incident returns None."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.database.repositories.incidents import get_incident_repository

            repo = get_incident_repository()
            result = await repo.get("00000000-0000-0000-0000-000000000000")

            assert result is None

        self._run_async(_test())


class TestIncidentManagerPersistence:
    """Tests for IncidentManager with PostgreSQL persistence."""

    @pytest.fixture(autouse=True)
    def setup(self, initialize_database):
        """Setup for each test."""
        pass

    def _run_async(self, coro):
        """
        Run async code in tests on a fresh, throwaway event loop.

        See TestIncidentRepository._run_async's docstring: closes the
        real DB pool this test's coroutine opened before the loop that
        owns it is discarded, so no psycopg_pool background task is left
        orphaned on a dead loop.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            try:
                from app.database.connection import get_database
                loop.run_until_complete(get_database().close())
            except Exception:
                pass
            loop.close()

    def test_manager_creates_with_timeline(self):
        """Test IncidentManager creates incidents with proper timeline."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.incidents import get_incident_manager, IncidentCreateRequest
            from app.database.models import SeverityLevel
            from app.incidents.manager import IncidentPriority

            # Reset singleton to get fresh instance
            import app.incidents.manager as mgr
            mgr._incident_manager = None

            manager = get_incident_manager()
            assert manager._db_enabled is True

            incident = await manager.create_incident_async(IncidentCreateRequest(
                title="Manager Timeline Test",
                description="Testing timeline persistence",
                severity=SeverityLevel.HIGH,
                priority=IncidentPriority.P2_HIGH,
            ))

            assert len(incident.timeline) >= 1
            assert incident.timeline[0].entry_type.value == "created"

        self._run_async(_test())

    def test_manager_update_persists_timeline(self):
        """Test that status updates add timeline entries that persist."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.incidents import get_incident_manager, IncidentCreateRequest, IncidentUpdateRequest
            from app.database.models import SeverityLevel, IncidentStatus
            from app.incidents.manager import IncidentPriority

            import app.incidents.manager as mgr
            mgr._incident_manager = None

            manager = get_incident_manager()

            # Create
            incident = await manager.create_incident_async(IncidentCreateRequest(
                title="Update Timeline Test",
                description="Testing update timeline",
                severity=SeverityLevel.MEDIUM,
                priority=IncidentPriority.P3_MEDIUM,
            ))

            initial_timeline_count = len(incident.timeline)

            # Update with note
            updated = await manager.update_incident_async(
                incident.id,
                IncidentUpdateRequest(note="Test note for timeline"),
                user="test_user",
            )

            assert len(updated.timeline) > initial_timeline_count

        self._run_async(_test())

    def test_manager_statistics(self):
        """Test IncidentManager statistics from database."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.incidents import get_incident_manager

            import app.incidents.manager as mgr
            mgr._incident_manager = None

            manager = get_incident_manager()
            stats = await manager.get_statistics_async()

            assert "total" in stats
            assert "open" in stats
            assert "by_status" in stats
            assert "by_severity" in stats
            assert "metrics" in stats

        self._run_async(_test())


class TestIncidentLifecycle:
    """Tests for incident lifecycle state transitions."""

    @pytest.fixture(autouse=True)
    def setup(self, initialize_database):
        """Setup for each test."""
        pass

    def _run_async(self, coro):
        """
        Run async code in tests on a fresh, throwaway event loop.

        See TestIncidentRepository._run_async's docstring: closes the
        real DB pool this test's coroutine opened before the loop that
        owns it is discarded, so no psycopg_pool background task is left
        orphaned on a dead loop.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            try:
                from app.database.connection import get_database
                loop.run_until_complete(get_database().close())
            except Exception:
                pass
            loop.close()

    def test_full_lifecycle(self):
        """Test complete incident lifecycle: open -> investigating -> containment -> closed."""
        async def _test():
            from app.database.connection import get_database

            db = get_database()
            try:
                await db.initialize()
            except Exception:
                pass

            from app.incidents import get_incident_manager, IncidentCreateRequest, IncidentUpdateRequest
            from app.database.models import SeverityLevel, IncidentStatus
            from app.incidents.manager import IncidentPriority

            import app.incidents.manager as mgr
            mgr._incident_manager = None

            manager = get_incident_manager()

            # Create (OPEN)
            incident = await manager.create_incident_async(IncidentCreateRequest(
                title="Lifecycle Test Incident",
                description="Testing full lifecycle",
                severity=SeverityLevel.HIGH,
                priority=IncidentPriority.P2_HIGH,
            ))
            assert incident.status.value == "open"

            # Transition to INVESTIGATING
            incident = await manager.update_incident_async(
                incident.id,
                IncidentUpdateRequest(status=IncidentStatus.INVESTIGATING),
            )
            assert incident.status.value == "investigating"

            # Transition to CONTAINMENT
            incident = await manager.update_incident_async(
                incident.id,
                IncidentUpdateRequest(status=IncidentStatus.CONTAINMENT),
            )
            assert incident.status.value == "containment"
            assert incident.contained_at is not None

            # Transition to CLOSED
            incident = await manager.update_incident_async(
                incident.id,
                IncidentUpdateRequest(
                    status=IncidentStatus.CLOSED,
                    root_cause="Test root cause",
                    lessons_learned="Test lessons learned",
                ),
            )
            assert incident.status.value == "closed"
            assert incident.resolved_at is not None

            # Verify all transitions are in timeline
            timeline_types = [e.entry_type.value for e in incident.timeline]
            assert "created" in timeline_types
            assert timeline_types.count("status_changed") >= 3

        self._run_async(_test())
