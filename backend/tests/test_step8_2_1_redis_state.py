"""
CyberGuard AI - STEP 8.2.1 Tests

Tests for production state, idempotency, and alert deduplication.

Test Categories:
1. Redis State Manager - windowed event tracking
2. Atomic threshold checks
3. Event idempotency
4. Finding fingerprint/deduplication
5. Tenant isolation
6. Redis failure handling
7. Redis-backed rules (WIN-001, WIN-002)
8. Multi-worker simulation
"""

import asyncio
import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import redis.asyncio as redis


# =============================================================================
# Test Fixtures
# =============================================================================


class MockRedis:
    """Mock Redis client for testing without real Redis."""

    def __init__(self):
        self._data: dict[str, str] = {}
        self._sorted_sets: dict[str, dict[str, float]] = {}
        self._ttls: dict[str, int] = {}
        self._connected = True

    async def ping(self):
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        return True

    async def get(self, key: str) -> str | None:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        return self._data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False) -> bool | None:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        if nx and key in self._data:
            return None
        self._data[key] = value
        if ex:
            self._ttls[key] = ex
        return True

    async def exists(self, key: str) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        return 1 if key in self._data or key in self._sorted_sets else 0

    async def delete(self, key: str) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        deleted = 0
        if key in self._data:
            del self._data[key]
            deleted += 1
        if key in self._sorted_sets:
            del self._sorted_sets[key]
            deleted += 1
        return deleted

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            self._sorted_sets[key] = {}
        added = 0
        for member, score in mapping.items():
            if member not in self._sorted_sets[key]:
                added += 1
            self._sorted_sets[key][member] = score
        return added

    async def zremrangebyscore(self, key: str, min_score: str | float, max_score: str | float) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            return 0
        min_val = float('-inf') if min_score == "-inf" else float(min_score)
        max_val = float('inf') if max_score == "+inf" else float(max_score)
        to_remove = [m for m, s in self._sorted_sets[key].items() if min_val <= s <= max_val]
        for m in to_remove:
            del self._sorted_sets[key][m]
        return len(to_remove)

    async def zcard(self, key: str) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        return len(self._sorted_sets.get(key, {}))

    async def zcount(self, key: str, min_score: float, max_score: str | float) -> int:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            return 0
        max_val = float('inf') if max_score == "+inf" else float(max_score)
        return sum(1 for s in self._sorted_sets[key].values() if min_score <= s <= max_val)

    async def zrangebyscore(self, key: str, min_score: float, max_score: str | float) -> list[str]:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            return []
        max_val = float('inf') if max_score == "+inf" else float(max_score)
        items = [(m, s) for m, s in self._sorted_sets[key].items() if min_score <= s <= max_val]
        items.sort(key=lambda x: x[1])
        return [m for m, _ in items]

    async def expire(self, key: str, seconds: int) -> bool:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        self._ttls[key] = seconds
        return True

    async def scan(self, cursor: int, match: str = "*", count: int = 100) -> tuple[int, list[str]]:
        if not self._connected:
            raise redis.ConnectionError("Redis unavailable")
        # Simple mock - return all matching keys
        import fnmatch
        all_keys = list(self._data.keys()) + list(self._sorted_sets.keys())
        matched = [k for k in all_keys if fnmatch.fnmatch(k, match)]
        return 0, matched

    async def info(self, section: str = None) -> dict:
        return {"used_memory_human": "1M"}

    def pipeline(self, transaction: bool = True):
        return MockPipeline(self)

    def simulate_disconnect(self):
        self._connected = False

    def simulate_reconnect(self):
        self._connected = True


class MockPipeline:
    """Mock Redis pipeline."""

    def __init__(self, redis_mock: MockRedis):
        self._redis = redis_mock
        self._commands: list[tuple[str, tuple]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def zadd(self, key: str, mapping: dict[str, float]):
        self._commands.append(("zadd", (key, mapping)))
        return self

    def zremrangebyscore(self, key: str, min_score, max_score):
        self._commands.append(("zremrangebyscore", (key, min_score, max_score)))
        return self

    def zcard(self, key: str):
        self._commands.append(("zcard", (key,)))
        return self

    def zcount(self, key: str, min_score, max_score):
        self._commands.append(("zcount", (key, min_score, max_score)))
        return self

    def zrangebyscore(self, key: str, min_score, max_score):
        self._commands.append(("zrangebyscore", (key, min_score, max_score)))
        return self

    def expire(self, key: str, seconds: int):
        self._commands.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list:
        results = []
        for cmd, args in self._commands:
            method = getattr(self._redis, cmd)
            result = await method(*args)
            results.append(result)
        self._commands.clear()
        return results


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    return MockRedis()


@pytest.fixture
def state_manager(mock_redis):
    """Create DetectionStateManager with mock Redis."""
    from app.detection.state.redis_state import DetectionStateManager
    return DetectionStateManager(mock_redis, tenant_id="test-tenant")


@pytest.fixture
def state_manager_other_tenant(mock_redis):
    """Create DetectionStateManager for a different tenant."""
    from app.detection.state.redis_state import DetectionStateManager
    return DetectionStateManager(mock_redis, tenant_id="other-tenant")


# =============================================================================
# 1. Redis State Manager - Basic Operations
# =============================================================================


class TestDetectionStateManager:
    """Tests for DetectionStateManager basic operations."""

    @pytest.mark.asyncio
    async def test_add_event_creates_sorted_set_entry(self, state_manager, mock_redis):
        """Events are stored in sorted sets with timestamp as score."""
        timestamp = datetime.now(timezone.utc)

        count = await state_manager.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            event_data={"hostname": "DC01", "status": "0xC000006D"},
            timestamp=timestamp,
            window_seconds=300,
        )

        assert count == 1
        # Check sorted set exists
        key_pattern = "detection:test-tenant:WIN-001:"
        assert any(k.startswith(key_pattern) for k in mock_redis._sorted_sets.keys())

    @pytest.mark.asyncio
    async def test_add_event_increments_count(self, state_manager):
        """Multiple events increase the count."""
        base_time = datetime.now(timezone.utc)

        # Add 5 events
        for i in range(5):
            count = await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"hostname": f"DC0{i}", "index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        assert count == 5

    @pytest.mark.asyncio
    async def test_add_event_removes_old_entries(self, state_manager):
        """Events outside the window are removed."""
        base_time = datetime.now(timezone.utc)

        # Add event from 10 minutes ago
        await state_manager.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            event_data={"hostname": "DC01", "age": "old"},
            timestamp=base_time - timedelta(seconds=600),
            window_seconds=300,
        )

        # Add current event - should remove the old one
        count = await state_manager.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            event_data={"hostname": "DC01", "age": "new"},
            timestamp=base_time,
            window_seconds=300,
        )

        assert count == 1  # Only the new event remains

    @pytest.mark.asyncio
    async def test_get_events_in_window(self, state_manager):
        """Can retrieve events within the time window."""
        base_time = datetime.now(timezone.utc)

        # Add events
        for i in range(3):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"hostname": f"DC0{i}", "index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        events = await state_manager.get_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )

        assert len(events) == 3
        hostnames = [e["hostname"] for e in events]
        assert "DC00" in hostnames
        assert "DC01" in hostnames
        assert "DC02" in hostnames

    @pytest.mark.asyncio
    async def test_count_events_in_window(self, state_manager):
        """Can count events without retrieving them."""
        base_time = datetime.now(timezone.utc)

        for i in range(7):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        count = await state_manager.count_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )

        assert count == 7

    @pytest.mark.asyncio
    async def test_clear_events(self, state_manager):
        """Can clear all events for a correlation key."""
        base_time = datetime.now(timezone.utc)

        # Add events
        for i in range(5):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        # Clear
        cleared = await state_manager.clear_events(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
        )

        assert cleared == 5

        # Verify empty
        count = await state_manager.count_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )
        assert count == 0


# =============================================================================
# 2. Atomic Threshold Checks
# =============================================================================


class TestAtomicThresholdCheck:
    """Tests for atomic threshold checking."""

    @pytest.mark.asyncio
    async def test_threshold_not_reached(self, state_manager):
        """Returns False when below threshold."""
        base_time = datetime.now(timezone.utc)

        # Add 3 events (threshold is 5)
        for i in range(3):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        reached, events = await state_manager.check_threshold_and_get_events(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            threshold=5,
            window_seconds=300,
        )

        assert reached is False
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_threshold_reached(self, state_manager):
        """Returns True when threshold is reached."""
        base_time = datetime.now(timezone.utc)

        # Add 5 events (threshold is 5)
        for i in range(5):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        reached, events = await state_manager.check_threshold_and_get_events(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            threshold=5,
            window_seconds=300,
        )

        assert reached is True
        assert len(events) == 5

    @pytest.mark.asyncio
    async def test_threshold_exceeded(self, state_manager):
        """Returns True when exceeding threshold."""
        base_time = datetime.now(timezone.utc)

        # Add 10 events
        for i in range(10):
            await state_manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"index": i},
                timestamp=base_time + timedelta(seconds=i),
                window_seconds=300,
            )

        reached, events = await state_manager.check_threshold_and_get_events(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            threshold=5,
            window_seconds=300,
        )

        assert reached is True
        assert len(events) == 10


# =============================================================================
# 3. Event Idempotency
# =============================================================================


class TestEventIdempotency:
    """Tests for event processing idempotency."""

    @pytest.mark.asyncio
    async def test_mark_event_processed_new(self, state_manager):
        """New events are marked as processed."""
        result = await state_manager.mark_event_processed(
            rule_id="WIN-001",
            source_event_id="win-sec-12345",
            ttl_seconds=3600,
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_mark_event_processed_duplicate(self, state_manager):
        """Duplicate events return False."""
        # First mark
        await state_manager.mark_event_processed(
            rule_id="WIN-001",
            source_event_id="win-sec-12345",
            ttl_seconds=3600,
        )

        # Second mark - should return False
        result = await state_manager.mark_event_processed(
            rule_id="WIN-001",
            source_event_id="win-sec-12345",
            ttl_seconds=3600,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_check_and_mark_atomic(self, state_manager):
        """check_and_mark_processed is atomic."""
        # First call - should process
        should_process = await state_manager.check_and_mark_processed(
            rule_id="WIN-001",
            source_event_id="win-sec-99999",
            ttl_seconds=3600,
        )
        assert should_process is True

        # Second call - should skip
        should_process = await state_manager.check_and_mark_processed(
            rule_id="WIN-001",
            source_event_id="win-sec-99999",
            ttl_seconds=3600,
        )
        assert should_process is False

    @pytest.mark.asyncio
    async def test_is_event_processed(self, state_manager):
        """Can check if event was processed without marking."""
        # Initially not processed
        assert await state_manager.is_event_processed("WIN-001", "win-sec-55555") is False

        # Mark it
        await state_manager.mark_event_processed("WIN-001", "win-sec-55555")

        # Now it's processed
        assert await state_manager.is_event_processed("WIN-001", "win-sec-55555") is True

    @pytest.mark.asyncio
    async def test_idempotency_per_rule(self, state_manager):
        """Idempotency is per-rule."""
        # Mark for WIN-001
        await state_manager.mark_event_processed("WIN-001", "win-sec-shared-id")

        # Same event ID for WIN-002 should be new
        result = await state_manager.mark_event_processed("WIN-002", "win-sec-shared-id")
        assert result is True


# =============================================================================
# 4. Finding Fingerprint/Deduplication
# =============================================================================


class TestFindingDeduplication:
    """Tests for finding fingerprint and deduplication."""

    def test_compute_finding_fingerprint_deterministic(self, state_manager):
        """Same inputs produce same fingerprint."""
        window_start = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
        window_end = datetime(2026, 9, 17, 10, 5, 0, tzinfo=timezone.utc)

        fp1 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=window_start,
            window_end=window_end,
        )

        fp2 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=window_start,
            window_end=window_end,
        )

        assert fp1 == fp2
        assert len(fp1) == 32  # SHA256 truncated to 32 chars

    def test_compute_finding_fingerprint_differs_by_rule(self, state_manager):
        """Different rules produce different fingerprints."""
        window_start = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
        window_end = datetime(2026, 9, 17, 10, 5, 0, tzinfo=timezone.utc)

        fp1 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=window_start,
            window_end=window_end,
        )

        fp2 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-002",
            correlation_key="admin@10.0.0.1",
            window_start=window_start,
            window_end=window_end,
        )

        assert fp1 != fp2

    def test_compute_finding_fingerprint_buckets_timestamps(self, state_manager):
        """Timestamps are bucketed to nearest minute."""
        # Same minute, different seconds
        fp1 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=datetime(2026, 9, 17, 10, 0, 15, tzinfo=timezone.utc),
            window_end=datetime(2026, 9, 17, 10, 5, 45, tzinfo=timezone.utc),
        )

        fp2 = state_manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=datetime(2026, 9, 17, 10, 0, 30, tzinfo=timezone.utc),
            window_end=datetime(2026, 9, 17, 10, 5, 10, tzinfo=timezone.utc),
        )

        # Same minute bucket = same fingerprint
        assert fp1 == fp2

    @pytest.mark.asyncio
    async def test_mark_finding_created_new(self, state_manager):
        """New findings are marked."""
        result = await state_manager.mark_finding_created(
            fingerprint="abc123def456",
            finding_id="finding-001",
            ttl_seconds=3600,
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_mark_finding_created_duplicate(self, state_manager):
        """Duplicate findings return False."""
        await state_manager.mark_finding_created(
            fingerprint="abc123def456",
            finding_id="finding-001",
        )

        result = await state_manager.mark_finding_created(
            fingerprint="abc123def456",
            finding_id="finding-002",  # Different ID, same fingerprint
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_is_finding_duplicate(self, state_manager):
        """Can check for duplicate findings."""
        assert await state_manager.is_finding_duplicate("new-fingerprint") is False

        await state_manager.mark_finding_created("new-fingerprint", "finding-x")

        assert await state_manager.is_finding_duplicate("new-fingerprint") is True


# =============================================================================
# 5. Tenant Isolation
# =============================================================================


class TestTenantIsolation:
    """Tests for tenant isolation in detection state."""

    @pytest.mark.asyncio
    async def test_events_isolated_by_tenant(self, state_manager, state_manager_other_tenant):
        """Events from different tenants don't mix."""
        base_time = datetime.now(timezone.utc)

        # Tenant 1 adds events
        await state_manager.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            event_data={"tenant": "test-tenant"},
            timestamp=base_time,
            window_seconds=300,
        )

        # Tenant 2 adds events
        await state_manager_other_tenant.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",  # Same correlation key
            event_data={"tenant": "other-tenant"},
            timestamp=base_time,
            window_seconds=300,
        )

        # Each tenant sees only their own events
        events1 = await state_manager.get_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )
        events2 = await state_manager_other_tenant.get_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )

        assert len(events1) == 1
        assert events1[0]["tenant"] == "test-tenant"

        assert len(events2) == 1
        assert events2[0]["tenant"] == "other-tenant"

    @pytest.mark.asyncio
    async def test_idempotency_isolated_by_tenant(self, state_manager, state_manager_other_tenant):
        """Event idempotency is per-tenant."""
        # Mark event for tenant 1
        await state_manager.mark_event_processed("WIN-001", "shared-event-id")

        # Same event ID for tenant 2 should be new
        result = await state_manager_other_tenant.mark_event_processed("WIN-001", "shared-event-id")
        assert result is True

    @pytest.mark.asyncio
    async def test_findings_isolated_by_tenant(self, state_manager, state_manager_other_tenant):
        """Finding deduplication is per-tenant."""
        await state_manager.mark_finding_created("shared-fingerprint", "finding-t1")

        # Same fingerprint for tenant 2 should be new
        result = await state_manager_other_tenant.mark_finding_created("shared-fingerprint", "finding-t2")
        assert result is True


# =============================================================================
# 6. Redis Failure Handling
# =============================================================================


class TestRedisFailureHandling:
    """Tests for Redis failure scenarios."""

    @pytest.mark.asyncio
    async def test_redis_unavailable_raises_error(self, mock_redis):
        """Operations fail loudly when Redis is unavailable."""
        from app.detection.state.redis_state import DetectionStateManager, RedisUnavailableError

        mock_redis.simulate_disconnect()
        manager = DetectionStateManager(mock_redis, tenant_id="test")

        with pytest.raises(RedisUnavailableError) as exc_info:
            await manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"test": True},
                window_seconds=300,
            )

        assert "Redis unavailable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_redis_recovery(self, mock_redis):
        """Operations work after Redis recovers."""
        from app.detection.state.redis_state import DetectionStateManager, RedisUnavailableError

        manager = DetectionStateManager(mock_redis, tenant_id="test")

        # Disconnect
        mock_redis.simulate_disconnect()

        with pytest.raises(RedisUnavailableError):
            await manager.add_event(
                rule_id="WIN-001",
                correlation_key="admin@10.0.0.1",
                event_data={"test": True},
                window_seconds=300,
            )

        # Reconnect
        mock_redis.simulate_reconnect()

        # Should work now
        count = await manager.add_event(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            event_data={"test": True},
            window_seconds=300,
        )

        assert count == 1

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, state_manager):
        """Health check reports healthy state."""
        health = await state_manager.health_check()

        assert health["status"] == "healthy"
        assert health["tenant_id"] == "test-tenant"

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, mock_redis):
        """Health check reports unhealthy when Redis is down."""
        from app.detection.state.redis_state import DetectionStateManager

        mock_redis.simulate_disconnect()
        manager = DetectionStateManager(mock_redis, tenant_id="test")

        health = await manager.health_check()

        assert health["status"] == "unhealthy"
        assert "error" in health


# =============================================================================
# 7. Redis-Backed Rules (WIN-001, WIN-002)
# =============================================================================


class TestRedisWindowsFailedAuthBurstRule:
    """Tests for Redis-backed WIN-001 rule."""

    @pytest.fixture
    def rule(self, state_manager):
        from app.detection.rules.windows_redis import RedisWindowsFailedAuthBurstRule
        return RedisWindowsFailedAuthBurstRule(
            state_manager=state_manager,
            threshold=5,
            window_seconds=300,
            enabled=True,
        )

    @pytest.mark.asyncio
    async def test_ignores_non_4625_events(self, rule):
        """Only processes 4625 events."""
        result = await rule.evaluate_async({
            "event_code": "4624",  # Success event
            "target_user": "admin",
            "source_ip": "10.0.0.1",
            "source_event_id": "win-001",
        })

        assert result is None

    @pytest.mark.asyncio
    async def test_no_match_below_threshold(self, rule):
        """No match when below threshold."""
        base_time = datetime.now(timezone.utc)

        # Add 3 failures (threshold is 5)
        for i in range(3):
            result = await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "10.0.0.1",
                "hostname": "DC01",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-4625-{i}",
            })

        assert result is None

    @pytest.mark.asyncio
    async def test_matches_at_threshold(self, rule):
        """Matches when threshold is reached."""
        base_time = datetime.now(timezone.utc)

        # Add 5 failures
        result = None
        for i in range(5):
            result = await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "10.0.0.1",
                "hostname": "DC01",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-thresh-{i}",
            })

        assert result is not None
        assert result.rule_id == "WIN-001"
        assert result.matched_data["failure_count"] == 5
        assert result.matched_data["username"] == "admin"
        assert "fingerprint" in result.matched_data

    @pytest.mark.asyncio
    async def test_idempotency_skips_duplicates(self, rule):
        """Duplicate events are skipped."""
        event = {
            "event_code": "4625",
            "target_user": "admin",
            "source_ip": "10.0.0.1",
            "hostname": "DC01",
            "timestamp": datetime.now(timezone.utc),
            "source_event_id": "win-dup-001",  # Same ID
        }

        # First call
        await rule.evaluate_async(event)

        # Process many duplicates (would exceed threshold if counted)
        for _ in range(10):
            await rule.evaluate_async(event)

        # Should not trigger (only 1 unique event)
        # Check by adding a new event and verifying count
        count = await rule._state.count_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )

        assert count == 1

    @pytest.mark.asyncio
    async def test_finding_deduplication(self, rule):
        """Duplicate findings are not created."""
        base_time = datetime.now(timezone.utc)

        # Trigger first finding
        for i in range(5):
            result = await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "10.0.0.1",
                "hostname": "DC01",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-first-{i}",
            })

        first_match = result
        assert first_match is not None

        # Add more events (same user/ip within same minute bucket)
        for i in range(5, 10):
            result = await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "10.0.0.1",
                "hostname": "DC01",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-second-{i}",
            })

        # Should not create another finding (same fingerprint bucket)
        assert result is None


class TestRedisWindowsAuthSequenceRule:
    """Tests for Redis-backed WIN-002 rule."""

    @pytest.fixture
    def rule(self, state_manager):
        from app.detection.rules.windows_redis import RedisWindowsAuthSequenceRule
        return RedisWindowsAuthSequenceRule(
            state_manager=state_manager,
            failure_threshold=3,
            window_seconds=300,
            enabled=True,
        )

    @pytest.mark.asyncio
    async def test_tracks_failures(self, rule):
        """Tracks 4625 failures."""
        base_time = datetime.now(timezone.utc)

        # Add failures
        for i in range(2):
            result = await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "user1",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-seq-fail-{i}",
            })

        # No match on failures alone
        assert result is None

    @pytest.mark.asyncio
    async def test_matches_on_success_after_failures(self, rule):
        """Matches when success follows enough failures."""
        base_time = datetime.now(timezone.utc)

        # Add 3 failures
        for i in range(3):
            await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "user1",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-seq2-fail-{i}",
            })

        # Success
        result = await rule.evaluate_async({
            "event_code": "4624",
            "target_user": "user1",
            "source_ip": "192.168.1.100",
            "hostname": "WS01",
            "timestamp": base_time + timedelta(seconds=10),
            "source_event_id": "win-seq2-success",
            "logon_type": 10,
        })

        assert result is not None
        assert result.rule_id == "WIN-002"
        assert result.matched_data["failure_count"] == 3
        assert "fingerprint" in result.matched_data

    @pytest.mark.asyncio
    async def test_clears_failures_after_success(self, rule):
        """Failures are cleared after any success."""
        base_time = datetime.now(timezone.utc)

        # Add 2 failures (below threshold)
        for i in range(2):
            await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "user2",
                "source_ip": "192.168.1.200",
                "timestamp": base_time + timedelta(seconds=i),
                "source_event_id": f"win-seq3-fail-{i}",
            })

        # Success (doesn't trigger - below threshold)
        result = await rule.evaluate_async({
            "event_code": "4624",
            "target_user": "user2",
            "source_ip": "192.168.1.200",
            "timestamp": base_time + timedelta(seconds=5),
            "source_event_id": "win-seq3-success-1",
        })
        assert result is None

        # Add 3 more failures
        for i in range(3):
            await rule.evaluate_async({
                "event_code": "4625",
                "target_user": "user2",
                "source_ip": "192.168.1.200",
                "timestamp": base_time + timedelta(seconds=10 + i),
                "source_event_id": f"win-seq3-fail2-{i}",
            })

        # Second success - should trigger (3 failures)
        result = await rule.evaluate_async({
            "event_code": "4624",
            "target_user": "user2",
            "source_ip": "192.168.1.200",
            "timestamp": base_time + timedelta(seconds=20),
            "source_event_id": "win-seq3-success-2",
        })

        assert result is not None
        assert result.matched_data["failure_count"] == 3


# =============================================================================
# 8. Multi-Worker Simulation
# =============================================================================


class TestMultiWorkerResilience:
    """Tests simulating multi-worker processing."""

    @pytest.mark.asyncio
    async def test_concurrent_event_processing(self, mock_redis):
        """Multiple workers can process events concurrently."""
        from app.detection.state.redis_state import DetectionStateManager

        # Simulate 3 workers with same Redis
        worker1 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")
        worker2 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")
        worker3 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")

        base_time = datetime.now(timezone.utc)

        # Each worker adds events concurrently
        async def worker_add_events(manager: DetectionStateManager, worker_id: int):
            for i in range(2):
                await manager.add_event(
                    rule_id="WIN-001",
                    correlation_key="shared-user@10.0.0.1",
                    event_data={"worker": worker_id, "index": i},
                    timestamp=base_time + timedelta(seconds=worker_id * 10 + i),
                    window_seconds=300,
                )

        # Run concurrently
        await asyncio.gather(
            worker_add_events(worker1, 1),
            worker_add_events(worker2, 2),
            worker_add_events(worker3, 3),
        )

        # All events should be visible to any worker
        count = await worker1.count_events_in_window(
            rule_id="WIN-001",
            correlation_key="shared-user@10.0.0.1",
            window_seconds=300,
        )

        assert count == 6  # 3 workers × 2 events each

    @pytest.mark.asyncio
    async def test_idempotency_across_workers(self, mock_redis):
        """Event idempotency works across workers."""
        from app.detection.state.redis_state import DetectionStateManager

        worker1 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")
        worker2 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")

        # Worker 1 marks event
        result1 = await worker1.check_and_mark_processed("WIN-001", "shared-event")

        # Worker 2 tries to process same event
        result2 = await worker2.check_and_mark_processed("WIN-001", "shared-event")

        assert result1 is True  # Worker 1 processes
        assert result2 is False  # Worker 2 skips

    @pytest.mark.asyncio
    async def test_finding_dedup_across_workers(self, mock_redis):
        """Finding deduplication works across workers."""
        from app.detection.state.redis_state import DetectionStateManager

        worker1 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")
        worker2 = DetectionStateManager(mock_redis, tenant_id="shared-tenant")

        fingerprint = "shared-finding-fingerprint"

        # Worker 1 creates finding
        result1 = await worker1.mark_finding_created(fingerprint, "finding-w1")

        # Worker 2 tries to create same finding
        result2 = await worker2.mark_finding_created(fingerprint, "finding-w2")

        assert result1 is True  # Worker 1 creates
        assert result2 is False  # Worker 2 is duplicate


# =============================================================================
# 9. Integration with create_redis_windows_rules
# =============================================================================


class TestCreateRedisWindowsRules:
    """Tests for the factory function."""

    @pytest.mark.asyncio
    async def test_creates_all_rules(self, state_manager):
        """Factory creates WIN-001, WIN-002, WIN-003."""
        from app.detection.rules.windows_redis import create_redis_windows_rules

        rules = await create_redis_windows_rules(state_manager)

        assert "WIN-001" in rules
        assert "WIN-002" in rules
        assert "WIN-003" in rules
        assert len(rules) == 3

    @pytest.mark.asyncio
    async def test_respects_thresholds(self, state_manager):
        """Factory applies custom thresholds."""
        from app.detection.rules.windows_redis import create_redis_windows_rules

        rules = await create_redis_windows_rules(
            state_manager,
            failed_auth_threshold=10,
            sequence_threshold=5,
        )

        assert rules["WIN-001"].threshold == 10
        assert rules["WIN-002"].failure_threshold == 5

    @pytest.mark.asyncio
    async def test_can_disable_privileged_rule(self, state_manager):
        """Can disable WIN-003."""
        from app.detection.rules.windows_redis import create_redis_windows_rules

        rules = await create_redis_windows_rules(
            state_manager,
            enable_privileged_rule=False,
        )

        assert "WIN-001" in rules
        assert "WIN-002" in rules
        assert "WIN-003" not in rules
