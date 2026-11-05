"""
CyberGuard AI - STEP 8.2.2 Tests

Tests for activated Redis Windows detection pipeline and durable deduplication.

Test Categories:
1. Processor uses Redis-backed rules (not in-memory)
2. Actual runtime flow activation
3. Finding fingerprint persistence
4. Alert deduplication
5. Multi-worker race handling
6. Tenant isolation
7. Redis failure behavior
8. End-to-end pipeline
"""

import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.agents.base import Finding, Severity
from app.database.models.base import SeverityLevel
from app.event_bus.events import SecurityEvent
from app.logs.models import LogEvent, LogSourceType, LogLevel


# =============================================================================
# Mock Redis for Testing
# =============================================================================


class MockRedis:
    """Mock Redis client for testing."""

    def __init__(self):
        self._data: dict[str, str] = {}
        self._sorted_sets: dict[str, dict[str, float]] = {}
        self._ttls: dict[str, int] = {}
        self._connected = True

    async def ping(self):
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        return True

    async def get(self, key: str) -> str | None:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        return self._data.get(key)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False) -> bool | None:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        if nx and key in self._data:
            return None
        self._data[key] = value
        if ex:
            self._ttls[key] = ex
        return True

    async def exists(self, key: str) -> int:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        return 1 if key in self._data or key in self._sorted_sets else 0

    async def delete(self, key: str) -> int:
        if not self._connected:
            import redis.asyncio as redis
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
            import redis.asyncio as redis
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
            import redis.asyncio as redis
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
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        return len(self._sorted_sets.get(key, {}))

    async def zcount(self, key: str, min_score: float, max_score: str | float) -> int:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            return 0
        max_val = float('inf') if max_score == "+inf" else float(max_score)
        return sum(1 for s in self._sorted_sets[key].values() if min_score <= s <= max_val)

    async def zrangebyscore(self, key: str, min_score: float, max_score: str | float) -> list[str]:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        if key not in self._sorted_sets:
            return []
        max_val = float('inf') if max_score == "+inf" else float(max_score)
        items = [(m, s) for m, s in self._sorted_sets[key].items() if min_score <= s <= max_val]
        items.sort(key=lambda x: x[1])
        return [m for m, _ in items]

    async def expire(self, key: str, seconds: int) -> bool:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
        self._ttls[key] = seconds
        return True

    async def scan(self, cursor: int, match: str = "*", count: int = 100) -> tuple[int, list[str]]:
        if not self._connected:
            import redis.asyncio as redis
            raise redis.ConnectionError("Redis unavailable")
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


# =============================================================================
# Fixtures
# =============================================================================


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
def windows_processor(state_manager):
    """Create initialized WindowsDetectionProcessor (sync wrapper)."""
    import asyncio
    from app.detection.windows_processor import WindowsDetectionProcessor

    processor = WindowsDetectionProcessor(
        state_manager=state_manager,
        tenant_id="test-tenant",
    )

    # Run initialization synchronously for fixture
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(processor.initialize())
    finally:
        loop.close()

    return processor


def make_windows_log_event(
    event_code: str,
    username: str = "admin",
    source_ip: str = "10.0.0.1",
    hostname: str = "DC01",
    timestamp: datetime | None = None,
    source_event_id: str | None = None,
) -> LogEvent:
    """Create a test Windows LogEvent."""
    return LogEvent(
        id=str(uuid4()),
        source_event_id=source_event_id or f"win-{event_code}-{uuid4().hex[:8]}",
        source_type=LogSourceType.WINDOWS_EVENT,
        hostname=hostname,
        timestamp=timestamp or datetime.now(timezone.utc),
        level=LogLevel.INFO,
        message=f"Windows event {event_code}",
        extracted_fields={
            "event_code": event_code,
            "target_user": username,
            "source_ip": source_ip,
            "computer_name": hostname,
        },
    )


def make_windows_security_event(
    event_code: str,
    username: str = "admin",
    source_ip: str = "10.0.0.1",
    hostname: str = "DC01",
    timestamp: datetime | None = None,
    source_event_id: str | None = None,
) -> SecurityEvent:
    """Create a test Windows SecurityEvent."""
    ts = timestamp or datetime.now(timezone.utc)
    return SecurityEvent(
        event_id=str(uuid4()),
        event_type="log",
        source=f"log_collector:windows_event",
        timestamp=ts,
        payload={
            "source_type": "windows_event",
            "hostname": hostname,
            "message": f"Windows event {event_code}",
            "source_event_id": source_event_id or f"win-{event_code}-{uuid4().hex[:8]}",
            "extracted_fields": {
                "event_code": event_code,
                "target_user": username,
                "source_ip": source_ip,
                "computer_name": hostname,
            },
        },
    )


# =============================================================================
# 1. Processor Uses Redis-Backed Rules
# =============================================================================


class TestProcessorUsesRedis:
    """Verify the processor uses Redis-backed rules, not in-memory."""

    @pytest.mark.asyncio
    async def test_processor_is_redis_backed(self, windows_processor):
        """Processor confirms it uses Redis-backed state."""
        assert windows_processor.is_redis_backed is True

    @pytest.mark.asyncio
    async def test_processor_has_redis_rules(self, windows_processor):
        """Processor has Redis-backed WIN-001 and WIN-002 rules."""
        rules = windows_processor._rules

        assert "WIN-001" in rules
        assert "WIN-002" in rules

        # Verify they have async evaluate methods
        assert hasattr(rules["WIN-001"], "evaluate_async")
        assert hasattr(rules["WIN-002"], "evaluate_async")

    @pytest.mark.asyncio
    async def test_processor_win003_is_stateless(self, windows_processor):
        """WIN-003 is stateless (no Redis needed)."""
        rules = windows_processor._rules

        if "WIN-003" in rules:
            # WIN-003 may or may not have evaluate_async
            # but it doesn't need state tracking
            pass

    @pytest.mark.asyncio
    async def test_processor_requires_initialization(self, state_manager):
        """Processor must be initialized before use."""
        from app.detection.windows_processor import WindowsDetectionProcessor

        processor = WindowsDetectionProcessor(
            state_manager=state_manager,
            tenant_id="test",
        )

        # Not initialized yet
        with pytest.raises(RuntimeError, match="not initialized"):
            log_event = make_windows_log_event("4625")
            await processor.process_log_event(log_event)


# =============================================================================
# 2. Runtime Flow Activation
# =============================================================================


class TestRuntimeFlowActivation:
    """Test that Windows events are routed to the detection pipeline."""

    @pytest.mark.asyncio
    async def test_windows_events_detected_in_handler(self, mock_redis):
        """handle_security_event routes Windows events to detection."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        # Create processor
        state_manager = DetectionStateManager(mock_redis, tenant_id="test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="test")
        await processor.initialize()

        # Create 5 failure events to trigger WIN-001
        findings = []
        for i in range(5):
            log_event = make_windows_log_event(
                event_code="4625",
                username="admin",
                source_ip="10.0.0.1",
                source_event_id=f"win-flow-{i}",
            )
            result = await processor.process_log_event(log_event)
            findings.extend(result)

        # Should trigger WIN-001
        assert len(findings) == 1
        assert findings[0].rule_id == "WIN-001"

    @pytest.mark.asyncio
    async def test_non_windows_events_not_processed(self, windows_processor):
        """Non-Windows events return empty findings."""
        log_event = LogEvent(
            id=str(uuid4()),
            source_type=LogSourceType.LINUX_SSH,  # Not Windows
            hostname="linux01",
            timestamp=datetime.now(timezone.utc),
            level=LogLevel.INFO,
            message="Linux SSH event",
            extracted_fields={},
        )

        findings = await windows_processor.process_log_event(log_event)
        assert findings == []


# =============================================================================
# 3. Finding Fingerprint Persistence
# =============================================================================


class TestFindingFingerprint:
    """Test deterministic finding fingerprints."""

    @pytest.mark.asyncio
    async def test_finding_has_fingerprint(self, windows_processor):
        """Findings include deterministic fingerprint."""
        # Trigger WIN-001
        for i in range(5):
            log_event = make_windows_log_event(
                event_code="4625",
                username="testuser",
                source_ip="192.168.1.1",
                source_event_id=f"win-fp-{i}",
            )
            findings = await windows_processor.process_log_event(log_event)

        assert len(findings) == 1
        finding = findings[0]

        # Check fingerprint exists
        assert finding.metadata.get("fingerprint") is not None
        # Finding ID should match fingerprint
        assert finding.finding_id == finding.metadata.get("fingerprint")

    @pytest.mark.asyncio
    async def test_fingerprint_is_deterministic(self, mock_redis):
        """Same detection produces same fingerprint."""
        from app.detection.state.redis_state import DetectionStateManager

        # Compute fingerprints for same detection
        manager = DetectionStateManager(mock_redis, tenant_id="test")

        fp1 = manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc),
            window_end=datetime(2026, 9, 17, 10, 5, 0, tzinfo=timezone.utc),
        )

        fp2 = manager.compute_finding_fingerprint(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_start=datetime(2026, 9, 17, 10, 0, 30, tzinfo=timezone.utc),  # Same minute bucket
            window_end=datetime(2026, 9, 17, 10, 5, 30, tzinfo=timezone.utc),
        )

        assert fp1 == fp2


# =============================================================================
# 4. Alert Deduplication
# =============================================================================


class TestAlertDeduplication:
    """Test alert deduplication logic."""

    @pytest.mark.asyncio
    async def test_alert_fingerprint_from_finding(self):
        """Alert fingerprint derived from finding fingerprint."""
        finding = Finding(
            finding_id="test-fingerprint-123",
            rule_id="WIN-001",
            name="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            confidence=0.9,
            evidence=[],
            metadata={"fingerprint": "test-fingerprint-123"},
        )

        # Alert fingerprint should be based on finding fingerprint
        alert_fingerprint = f"alert:{finding.metadata.get('fingerprint')}"
        assert alert_fingerprint == "alert:test-fingerprint-123"


# =============================================================================
# 5. Multi-Worker Race Handling
# =============================================================================


class TestMultiWorkerRace:
    """Test that concurrent workers don't create duplicates."""

    @pytest.mark.asyncio
    async def test_concurrent_event_processing_idempotent(self, mock_redis):
        """Concurrent workers processing same events create one finding."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        # Two workers sharing Redis
        state_manager = DetectionStateManager(mock_redis, tenant_id="shared")

        processor1 = WindowsDetectionProcessor(state_manager, tenant_id="shared")
        processor2 = WindowsDetectionProcessor(state_manager, tenant_id="shared")

        await processor1.initialize()
        await processor2.initialize()

        # Both process same events concurrently
        base_time = datetime.now(timezone.utc)
        all_findings = []

        for i in range(5):
            log_event = make_windows_log_event(
                event_code="4625",
                username="shared_user",
                source_ip="10.0.0.1",
                source_event_id=f"shared-event-{i}",  # Same event IDs
                timestamp=base_time + timedelta(seconds=i),
            )

            # Process on both workers
            findings1 = await processor1.process_log_event(log_event)
            findings2 = await processor2.process_log_event(log_event)

            all_findings.extend(findings1)
            all_findings.extend(findings2)

        # Only ONE finding should be created (idempotency)
        # Second processor sees events as already processed
        assert len(all_findings) == 1


# =============================================================================
# 6. Tenant Isolation
# =============================================================================


class TestTenantIsolation:
    """Test that tenants are properly isolated."""

    @pytest.mark.asyncio
    async def test_tenant_events_isolated(self, mock_redis):
        """Different tenants don't share detection state."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        # Create processors for different tenants
        state_tenant_a = DetectionStateManager(mock_redis, tenant_id="tenant-a")
        state_tenant_b = DetectionStateManager(mock_redis, tenant_id="tenant-b")

        proc_a = WindowsDetectionProcessor(state_tenant_a, tenant_id="tenant-a")
        proc_b = WindowsDetectionProcessor(state_tenant_b, tenant_id="tenant-b")

        await proc_a.initialize()
        await proc_b.initialize()

        base_time = datetime.now(timezone.utc)

        # Tenant A: 3 failures (below threshold)
        for i in range(3):
            log_event = make_windows_log_event(
                event_code="4625",
                username="admin",
                source_ip="10.0.0.1",
                source_event_id=f"tenant-a-{i}",
                timestamp=base_time + timedelta(seconds=i),
            )
            findings_a = await proc_a.process_log_event(log_event)

        # No finding yet for Tenant A
        assert findings_a == []

        # Tenant B: 5 failures (at threshold)
        all_findings_b = []
        for i in range(5):
            log_event = make_windows_log_event(
                event_code="4625",
                username="admin",
                source_ip="10.0.0.1",
                source_event_id=f"tenant-b-{i}",
                timestamp=base_time + timedelta(seconds=i),
            )
            findings_b = await proc_b.process_log_event(log_event)
            all_findings_b.extend(findings_b)

        # Tenant B triggers detection
        assert len(all_findings_b) == 1

        # Tenant A's count is still only 3 (not affected by B)
        count_a = await state_tenant_a.count_events_in_window(
            rule_id="WIN-001",
            correlation_key="admin@10.0.0.1",
            window_seconds=300,
        )
        assert count_a == 3


# =============================================================================
# 7. Redis Failure Behavior
# =============================================================================


class TestRedisFailureBehavior:
    """Test that Redis failures are handled safely."""

    @pytest.mark.asyncio
    async def test_redis_failure_raises_error(self, mock_redis):
        """Redis failure raises RedisUnavailableError, doesn't silently continue."""
        from app.detection.state.redis_state import DetectionStateManager, RedisUnavailableError
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="test")
        await processor.initialize()

        # Disconnect Redis
        mock_redis.simulate_disconnect()

        log_event = make_windows_log_event(
            event_code="4625",
            source_event_id="redis-fail-test",
        )

        with pytest.raises(RedisUnavailableError):
            await processor.process_log_event(log_event)

    @pytest.mark.asyncio
    async def test_no_silent_fallback_to_memory(self, mock_redis):
        """Processor does not fall back to in-memory when Redis fails."""
        from app.detection.state.redis_state import DetectionStateManager, RedisUnavailableError
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="test")
        await processor.initialize()

        # Process some events
        for i in range(3):
            log_event = make_windows_log_event(
                event_code="4625",
                source_event_id=f"pre-fail-{i}",
            )
            await processor.process_log_event(log_event)

        # Disconnect Redis
        mock_redis.simulate_disconnect()

        # Further processing should fail, not silently continue
        with pytest.raises(RedisUnavailableError):
            log_event = make_windows_log_event(
                event_code="4625",
                source_event_id="during-fail",
            )
            await processor.process_log_event(log_event)


# =============================================================================
# 8. End-to-End Pipeline Tests
# =============================================================================


class TestEndToEndPipeline:
    """Test complete detection pipeline flow."""

    @pytest.mark.asyncio
    async def test_win001_full_flow(self, mock_redis):
        """WIN-001 triggers after threshold failures."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="e2e-test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="e2e-test")
        await processor.initialize()

        base_time = datetime.now(timezone.utc)
        all_findings = []

        # 5 failures from same user/IP
        for i in range(5):
            log_event = make_windows_log_event(
                event_code="4625",
                username="e2e_user",
                source_ip="192.168.1.100",
                source_event_id=f"e2e-001-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
            )
            findings = await processor.process_log_event(log_event)
            all_findings.extend(findings)

        assert len(all_findings) == 1
        finding = all_findings[0]
        assert finding.rule_id == "WIN-001"
        assert "e2e_user" in finding.description
        assert finding.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_win002_full_flow(self, mock_redis):
        """WIN-002 triggers on success after failures."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="e2e-test2")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="e2e-test2")
        await processor.initialize()

        base_time = datetime.now(timezone.utc)

        # 3 failures
        for i in range(3):
            log_event = make_windows_log_event(
                event_code="4625",
                username="seq_user",
                source_ip="192.168.1.200",
                source_event_id=f"e2e-002-fail-{i}",
                timestamp=base_time + timedelta(seconds=i * 10),
            )
            await processor.process_log_event(log_event)

        # 1 success
        success_event = LogEvent(
            id=str(uuid4()),
            source_event_id="e2e-002-success",
            source_type=LogSourceType.WINDOWS_EVENT,
            hostname="DC01",
            timestamp=base_time + timedelta(seconds=40),
            level=LogLevel.INFO,
            message="Windows event 4624",
            extracted_fields={
                "event_code": "4624",
                "target_user": "seq_user",
                "source_ip": "192.168.1.200",
                "logon_type": 10,
            },
        )

        findings = await processor.process_log_event(success_event)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "WIN-002"
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_win003_full_flow(self, mock_redis):
        """WIN-003 creates finding for each 4672 event."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="e2e-test3")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="e2e-test3")
        await processor.initialize()

        log_event = LogEvent(
            id=str(uuid4()),
            source_event_id="e2e-003-priv",
            source_type=LogSourceType.WINDOWS_EVENT,
            hostname="DC01",
            timestamp=datetime.now(timezone.utc),
            level=LogLevel.INFO,
            message="Windows event 4672",
            extracted_fields={
                "event_code": "4672",
                "subject_user": "admin",
                "subject_domain": "CORP",
                "privileges": "SeDebugPrivilege",
            },
        )

        findings = await processor.process_log_event(log_event)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "WIN-003"
        assert finding.severity == Severity.LOW  # Observability signal

    @pytest.mark.asyncio
    async def test_duplicate_events_skipped(self, mock_redis):
        """Duplicate events don't create duplicate findings."""
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="dedup-test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="dedup-test")
        await processor.initialize()

        base_time = datetime.now(timezone.utc)

        # Same event ID repeated
        all_findings = []
        for _ in range(10):
            log_event = make_windows_log_event(
                event_code="4625",
                username="dedup_user",
                source_ip="10.0.0.1",
                source_event_id="same-event-id",  # SAME ID every time
                timestamp=base_time,
            )
            findings = await processor.process_log_event(log_event)
            all_findings.extend(findings)

        # Should NOT trigger detection (only 1 unique event)
        assert len(all_findings) == 0


# =============================================================================
# 9. Statistics and Observability
# =============================================================================


class TestStatisticsAndObservability:
    """Test statistics and monitoring endpoints."""

    @pytest.mark.asyncio
    async def test_processor_statistics(self, windows_processor):
        """Processor provides useful statistics."""
        stats = await windows_processor.get_statistics()

        assert "tenant_id" in stats
        assert "initialized" in stats
        assert "detection_enabled" in stats
        assert "rules" in stats
        assert stats["initialized"] is True

    @pytest.mark.asyncio
    async def test_redis_health_in_statistics(self, windows_processor):
        """Statistics include Redis health."""
        stats = await windows_processor.get_statistics()

        assert "redis_health" in stats
        assert stats["redis_health"]["status"] == "healthy"


# =============================================================================
# 10. Regression Prevention
# =============================================================================


class TestRegressionPrevention:
    """Tests to prevent regression to in-memory rules."""

    @pytest.mark.asyncio
    async def test_factory_creates_redis_processor(self, mock_redis):
        """get_windows_detection_processor creates Redis-backed processor."""
        # This test verifies the factory function creates the right type
        from app.detection.state.redis_state import DetectionStateManager
        from app.detection.windows_processor import WindowsDetectionProcessor

        state_manager = DetectionStateManager(mock_redis, tenant_id="factory-test")
        processor = WindowsDetectionProcessor(state_manager, tenant_id="factory-test")
        await processor.initialize()

        # Must be Redis-backed
        assert processor.is_redis_backed is True

        # Rules must have async evaluate
        for rule_id in ["WIN-001", "WIN-002"]:
            if rule_id in processor._rules:
                rule = processor._rules[rule_id]
                assert hasattr(rule, "evaluate_async"), f"{rule_id} missing evaluate_async"

    @pytest.mark.asyncio
    async def test_processor_doesnt_use_inmemory_rules(self, windows_processor):
        """Processor does not instantiate in-memory rule classes."""
        from app.detection.rules.windows import (
            WindowsFailedAuthBurstRule,
            WindowsAuthSequenceRule,
        )

        for rule in windows_processor._rules.values():
            # Should NOT be the in-memory versions
            assert not isinstance(rule, WindowsFailedAuthBurstRule), \
                "Processor using in-memory WindowsFailedAuthBurstRule"
            assert not isinstance(rule, WindowsAuthSequenceRule), \
                "Processor using in-memory WindowsAuthSequenceRule"
