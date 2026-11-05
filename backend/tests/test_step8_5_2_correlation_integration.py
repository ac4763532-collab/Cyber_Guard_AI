"""
STEP 8.5.2 Tests - Existing CorrelationEngine Integration

Tests proving that normalized cross-source entities can actually reach
and be processed by the existing CorrelationEngine.

Test Categories:
1. Windows Integration (1-3)
2. Linux Integration (4-6)
3. Web Integration (7-9)
4. Cross-Source Correlation (10-13)
5. Tenant Isolation (14-18)
6. Event Identity (19-21)
7. Error Handling (22-25)
8. Adapter Tests
9. Metrics Tests
"""

from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from app.correlation.context import (
    CorrelationContext,
    CorrelationContextExtractor,
)
from app.correlation.engine import (
    CorrelationEngine,
    CorrelationResult,
    EventData,
    get_correlation_engine,
)
from app.correlation.integration import (
    CorrelationContextAdapter,
    TenantAwareCorrelator,
    CorrelationIntegrationError,
    TenantResolutionError,
    InvalidCorrelationDataError,
    validate_tenant_id,
    create_correlation_context_from_finding,
    get_correlation_metrics,
    reset_correlation_metrics,
    get_tenant_aware_correlator,
    reset_tenant_aware_correlator,
)
from app.logs.models import LogEvent, LogSourceType, LogLevel
from app.agents.base import Finding, Severity


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def reset_metrics():
    """Reset metrics before and after each test."""
    reset_correlation_metrics()
    reset_tenant_aware_correlator()
    yield
    reset_correlation_metrics()
    reset_tenant_aware_correlator()


@pytest.fixture
def correlation_engine():
    """Get the singleton correlation engine."""
    return get_correlation_engine()


@pytest.fixture
def tenant_correlator():
    """Get a fresh TenantAwareCorrelator."""
    return TenantAwareCorrelator()


def make_windows_log_event(
    event_id: int = 4624,
    username: str = "jsmith",
    source_ip: str = "192.168.1.100",
    hostname: str = "workstation01",
    logon_id: str = "0x12345",
    source_id: str | None = None,
) -> LogEvent:
    """Create a Windows log event for testing."""
    return LogEvent(
        id=str(uuid4()),
        source_event_id=f"win-{event_id}-{uuid4().hex[:8]}",
        source_id=source_id or str(uuid4()),
        source_type=LogSourceType.WINDOWS_EVENT,
        hostname=hostname,
        program="Security",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.INFO,
        message=f"Windows Event {event_id}",
        extracted_fields={
            "event_id": event_id,
            "event_data": {
                "TargetUserName": username,
                "IpAddress": source_ip,
                "WorkstationName": hostname,
                "TargetLogonId": logon_id,
            },
        },
    )


def make_linux_log_event(
    username: str = "jsmith",
    source_ip: str = "192.168.1.100",
    hostname: str = "server01",
    session_id: str = "ssh-12345",
    source_id: str | None = None,
) -> LogEvent:
    """Create a Linux SSH log event for testing."""
    return LogEvent(
        id=str(uuid4()),
        source_event_id=f"linux-{uuid4().hex[:8]}",
        source_id=source_id or str(uuid4()),
        source_type=LogSourceType.LINUX_SSH,
        hostname=hostname,
        program="sshd",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.INFO,
        message=f"Accepted password for {username} from {source_ip}",
        extracted_fields={
            "username": username,
            "source_ip": source_ip,
            "session": session_id,
        },
    )


def make_android_log_event(
    device_serial: str = "emulator-5554",
    tag: str = "ActivityManager",
    pid: int = 1234,
    tid: int = 1234,
    source_id: str | None = None,
) -> LogEvent:
    """Create an Android ADB/logcat log event for testing.

    Unlike Windows/Linux/the old Web factory, there is deliberately no
    username/source_ip here - _extract_android() never fabricates a user
    or IP that logcat didn't actually report. device_serial (-> hostname
    -> EventData.assets) and tag/pid (-> process_name/process_id) are the
    real correlatable entities for this source type.
    """
    return LogEvent(
        id=str(uuid4()),
        source_event_id=f"android-{uuid4().hex[:8]}",
        source_id=source_id or str(uuid4()),
        source_type=LogSourceType.ANDROID_ADB,
        hostname=device_serial,
        program=tag,
        pid=pid,
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.INFO,
        message="su invoked",
        extracted_fields={
            "device_serial": device_serial,
            "tag": tag,
            "pid": pid,
            "tid": tid,
        },
    )


def make_finding(
    rule_id: str = "WIN-001",
    name: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
    mitre_techniques: list[str] | None = None,
) -> Finding:
    """Create a Finding for testing."""
    return Finding(
        finding_id=str(uuid4()),
        rule_id=rule_id,
        name=name,
        description="Test finding description",
        severity=severity,
        confidence=0.85,
        mitre_techniques=mitre_techniques or ["T1078"],
        metadata={
            "fingerprint": f"fp-{uuid4().hex[:8]}",
        },
    )


# =============================================================================
# 1-3. Windows Integration Tests
# =============================================================================


class TestWindowsIntegration:
    """Windows event → CorrelationContext → EventData → CorrelationEngine."""

    def test_windows_event_to_correlation_context(self):
        """Test 1: Windows event extracts to CorrelationContext."""
        log_event = make_windows_log_event(
            event_id=4624,
            username="admin",
            source_ip="10.0.0.50",
            hostname="dc01",
        )

        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id="org-windows-test",
        )

        assert ctx.tenant_id == "org-windows-test"
        assert ctx.username == "admin"
        assert ctx.source_ip == "10.0.0.50"
        assert ctx.hostname == "dc01"
        assert ctx.source_type == LogSourceType.WINDOWS_EVENT
        assert ctx.can_correlate()

    def test_windows_context_to_event_data(self):
        """Test 2: CorrelationContext converts to EventData."""
        log_event = make_windows_log_event(username="admin", source_ip="10.0.0.50")
        finding = make_finding(rule_id="WIN-001")

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        assert isinstance(event_data, EventData)
        assert event_data.event_id
        assert event_data.domain == "windows_event"
        assert "10.0.0.50" in event_data.ips
        assert "admin" in event_data.users
        assert len(event_data.findings) == 1

    def test_windows_event_data_to_correlation_engine(self, correlation_engine):
        """Test 3: EventData processes through existing CorrelationEngine."""
        log_event = make_windows_log_event()
        finding = make_finding()

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        # Run through engine
        result = correlation_engine.correlate(events=[event_data])

        assert isinstance(result, CorrelationResult)
        assert result.event_count == 1
        # Single event won't form groups
        assert result.total_correlations == 0


# =============================================================================
# 4-6. Linux Integration Tests
# =============================================================================


class TestLinuxIntegration:
    """Linux event → CorrelationContext → EventData → CorrelationEngine."""

    def test_linux_event_to_correlation_context(self):
        """Test 4: Linux SSH event extracts to CorrelationContext."""
        log_event = make_linux_log_event(
            username="admin",
            source_ip="192.168.10.5",
            hostname="appserver",
        )

        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id="org-linux-test",
        )

        assert ctx.tenant_id == "org-linux-test"
        assert ctx.username == "admin"
        assert ctx.source_ip == "192.168.10.5"
        assert ctx.hostname == "appserver"
        assert ctx.source_type == LogSourceType.LINUX_SSH
        assert ctx.can_correlate()

    def test_linux_context_to_event_data(self):
        """Test 5: Linux CorrelationContext converts to EventData."""
        log_event = make_linux_log_event(username="dbadmin", source_ip="10.1.1.1")
        finding = make_finding(rule_id="SSH-001")

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        assert isinstance(event_data, EventData)
        assert event_data.domain == "linux_ssh"
        assert "10.1.1.1" in event_data.ips
        assert "dbadmin" in event_data.users

    def test_linux_event_data_to_correlation_engine(self, correlation_engine):
        """Test 6: Linux EventData processes through CorrelationEngine."""
        log_event = make_linux_log_event()
        finding = make_finding(rule_id="SSH-001")

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        result = correlation_engine.correlate(events=[event_data])

        assert isinstance(result, CorrelationResult)
        assert result.event_count == 1


# =============================================================================
# 7-9. Web Integration Tests
# =============================================================================


class TestAndroidIntegration:
    """Android event → CorrelationContext → EventData → CorrelationEngine."""

    def test_android_event_to_correlation_context(self):
        """Test 7: Android event extracts to CorrelationContext."""
        log_event = make_android_log_event(
            device_serial="ZY223JL4GF",
            tag="PackageManager",
            pid=4321,
        )

        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id="org-android-test",
        )

        assert ctx.tenant_id == "org-android-test"
        # normalize_hostname() lowercases, matching every other source type
        assert ctx.hostname == "zy223jl4gf"
        assert ctx.process_name == "PackageManager"
        assert ctx.process_id == 4321
        assert ctx.source_type == LogSourceType.ANDROID_ADB
        # No username/user_id/source_ip - _extract_android never fabricates
        # entities logcat didn't actually report.
        assert ctx.username is None
        assert ctx.user_id is None
        assert ctx.source_ip is None
        assert ctx.can_correlate()  # hostname alone is enough to correlate

    def test_android_context_to_event_data(self):
        """Test 8: Android CorrelationContext converts to EventData."""
        log_event = make_android_log_event(
            device_serial="emulator-5554",
            tag="su",
        )
        finding = make_finding(rule_id="AND-001")

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        assert isinstance(event_data, EventData)
        assert event_data.domain == "android_adb"
        assert "emulator-5554" in event_data.assets
        # No ips/users populated for Android - matches _extract_android's
        # deliberate "missing entities remain None" behavior.
        assert event_data.ips == []
        assert event_data.users == []

    def test_android_event_data_to_correlation_engine(self, correlation_engine):
        """Test 9: Android EventData processes through CorrelationEngine."""
        log_event = make_android_log_event()
        finding = make_finding(rule_id="AND-001")

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        result = correlation_engine.correlate(events=[event_data])

        assert isinstance(result, CorrelationResult)
        assert result.event_count == 1


# =============================================================================
# 10-13. Cross-Source Correlation Tests
# =============================================================================


class TestCrossSourceCorrelation:
    """Cross-source correlation with shared IP/user."""

    def test_windows_linux_same_ip_correlates(self, correlation_engine):
        """Test 10: Windows + Linux with same IP correlate."""
        shared_ip = "192.168.1.100"
        tenant_id = "org-cross-test"

        # Create Windows event
        win_event = make_windows_log_event(
            username="win-user",
            source_ip=shared_ip,
        )
        win_ctx, win_data = CorrelationContextAdapter.from_log_event(
            log_event=win_event,
            tenant_id=tenant_id,
            finding=make_finding(rule_id="WIN-001"),
        )

        # Create Linux event with same IP
        linux_event = make_linux_log_event(
            username="linux-user",
            source_ip=shared_ip,
        )
        linux_ctx, linux_data = CorrelationContextAdapter.from_log_event(
            log_event=linux_event,
            tenant_id=tenant_id,
            finding=make_finding(rule_id="SSH-001"),
        )

        # Both should have the same IP
        assert shared_ip in win_data.ips
        assert shared_ip in linux_data.ips

        # Correlate
        result = correlation_engine.correlate(events=[win_data, linux_data])

        # Should find IOC correlation
        assert result.event_count == 2
        assert result.total_correlations > 0
        assert len(result.groups) >= 1

        # Check cross-domain
        if result.groups:
            group = result.groups[0]
            assert "windows_event" in group.domains
            assert "linux_ssh" in group.domains

    def test_windows_android_same_asset_correlates(self, correlation_engine):
        """Test 11: Windows + Android with the same asset (hostname /
        device_serial) correlate. Android has no username to share with
        Windows, so - unlike the old Web variant of this test - the shared
        entity here is the asset, not a user."""
        shared_asset = "kiosk-07"
        tenant_id = "org-cross-test"

        win_event = make_windows_log_event(
            username="jsmith", source_ip="10.0.0.1", hostname=shared_asset
        )
        win_ctx, win_data = CorrelationContextAdapter.from_log_event(
            log_event=win_event,
            tenant_id=tenant_id,
            finding=make_finding(),
        )

        # Android event with the same asset (e.g. the kiosk's attached device)
        android_event = make_android_log_event(device_serial=shared_asset)
        android_ctx, android_data = CorrelationContextAdapter.from_log_event(
            log_event=android_event,
            tenant_id=tenant_id,
            finding=make_finding(rule_id="AND-001"),
        )

        assert shared_asset in win_data.assets
        assert shared_asset in android_data.assets

        result = correlation_engine.correlate(events=[win_data, android_data])

        # Should find asset correlation
        assert result.total_correlations > 0

    def test_linux_android_same_asset_correlates(self, correlation_engine):
        """Test 12: Linux + Android with the same asset correlate."""
        shared_asset = "lab-device-3"
        tenant_id = "org-cross-test"

        linux_event = make_linux_log_event(
            username="admin",
            source_ip="172.16.5.10",
            hostname=shared_asset,
        )
        linux_ctx, linux_data = CorrelationContextAdapter.from_log_event(
            log_event=linux_event,
            tenant_id=tenant_id,
            finding=make_finding(rule_id="SSH-001"),
        )

        android_event = make_android_log_event(device_serial=shared_asset)
        android_ctx, android_data = CorrelationContextAdapter.from_log_event(
            log_event=android_event,
            tenant_id=tenant_id,
            finding=make_finding(rule_id="AND-001"),
        )

        result = correlation_engine.correlate(events=[linux_data, android_data])

        assert result.event_count == 2
        assert result.total_correlations > 0

    def test_all_three_sources_correlate(self, correlation_engine):
        """Test 13: Windows + Linux + Android with the same asset all
        correlate."""
        shared_asset = "rig-01"
        tenant_id = "org-cross-test"

        # Windows
        win_event = make_windows_log_event(hostname=shared_asset)
        _, win_data = CorrelationContextAdapter.from_log_event(
            win_event, tenant_id, make_finding(rule_id="WIN-001")
        )

        # Linux
        linux_event = make_linux_log_event(hostname=shared_asset)
        _, linux_data = CorrelationContextAdapter.from_log_event(
            linux_event, tenant_id, make_finding(rule_id="SSH-001")
        )

        # Android
        android_event = make_android_log_event(device_serial=shared_asset)
        _, android_data = CorrelationContextAdapter.from_log_event(
            android_event, tenant_id, make_finding(rule_id="AND-001")
        )

        result = correlation_engine.correlate(events=[win_data, linux_data, android_data])

        assert result.event_count == 3
        assert result.total_correlations > 0
        assert len(result.groups) >= 1

        # All three domains should be in the group
        if result.groups:
            group = result.groups[0]
            assert len(group.domains) == 3


# =============================================================================
# 14-18. Tenant Isolation Tests
# =============================================================================


class TestTenantIsolation:
    """Tenant isolation enforcement."""

    def test_same_tenant_may_correlate(self, tenant_correlator, reset_metrics):
        """Test 14: Tenant A + Tenant A may correlate."""
        tenant_id = "org-A"
        shared_ip = "192.168.1.1"

        event1 = make_windows_log_event(source_ip=shared_ip)
        ctx1, data1 = CorrelationContextAdapter.from_log_event(
            event1, tenant_id, make_finding()
        )

        event2 = make_linux_log_event(source_ip=shared_ip)
        ctx2, data2 = CorrelationContextAdapter.from_log_event(
            event2, tenant_id, make_finding(rule_id="SSH-001")
        )

        result = tenant_correlator.correlate(
            events=[(ctx1, data1), (ctx2, data2)],
            tenant_id=tenant_id,
        )

        # Both events should be processed
        assert result.event_count == 2
        assert result.total_correlations > 0

    def test_different_tenants_must_not_correlate(self, tenant_correlator, reset_metrics):
        """Test 15: Tenant A + Tenant B MUST NOT correlate."""
        shared_ip = "192.168.1.1"

        # Event from Tenant A
        event_a = make_windows_log_event(source_ip=shared_ip)
        ctx_a, data_a = CorrelationContextAdapter.from_log_event(
            event_a, "tenant-A", make_finding()
        )

        # Event from Tenant B
        event_b = make_linux_log_event(source_ip=shared_ip)
        ctx_b, data_b = CorrelationContextAdapter.from_log_event(
            event_b, "tenant-B", make_finding(rule_id="SSH-001")
        )

        # Correlate within Tenant A only
        result = tenant_correlator.correlate(
            events=[(ctx_a, data_a), (ctx_b, data_b)],
            tenant_id="tenant-A",
        )

        # Only Tenant A event should be processed
        assert result.event_count == 1

    def test_same_username_different_tenants_no_correlation(self, tenant_correlator, reset_metrics):
        """Test 16: Same username across tenants MUST NOT correlate."""
        shared_user = "admin"

        event_a = make_windows_log_event(username=shared_user, source_ip="10.0.0.1")
        ctx_a, data_a = CorrelationContextAdapter.from_log_event(
            event_a, "tenant-A", make_finding()
        )

        event_b = make_linux_log_event(username=shared_user, source_ip="10.0.0.2")
        ctx_b, data_b = CorrelationContextAdapter.from_log_event(
            event_b, "tenant-B", make_finding(rule_id="SSH-001")
        )

        # Correlate as Tenant A
        result = tenant_correlator.correlate(
            events=[(ctx_a, data_a), (ctx_b, data_b)],
            tenant_id="tenant-A",
        )

        # Only 1 event (Tenant A)
        assert result.event_count == 1
        # No correlations (only 1 event)
        assert result.total_correlations == 0

    def test_same_asset_different_tenants_no_correlation(self, tenant_correlator, reset_metrics):
        """Test 17: Same asset (hostname/device_serial) across tenants
        MUST NOT correlate. Uses Windows + Android specifically because
        Android has no username/source_ip of its own - asset is the only
        entity it can share with another source, so this is the test that
        actually proves tenant isolation holds for Android's correlation
        path, not just a duplicate of the IP-based test above."""
        shared_asset = "shared-kiosk"

        event_a = make_windows_log_event(hostname=shared_asset)
        ctx_a, data_a = CorrelationContextAdapter.from_log_event(
            event_a, "tenant-A", make_finding()
        )

        event_b = make_android_log_event(device_serial=shared_asset)
        ctx_b, data_b = CorrelationContextAdapter.from_log_event(
            event_b, "tenant-B", make_finding(rule_id="AND-001")
        )

        result = tenant_correlator.correlate(
            events=[(ctx_a, data_a), (ctx_b, data_b)],
            tenant_id="tenant-A",
        )

        assert result.event_count == 1

    def test_same_session_id_different_tenants_no_correlation(self, tenant_correlator, reset_metrics):
        """Test 18: Same session ID across tenants MUST NOT correlate."""
        shared_session = "ssh-12345"

        event_a = make_linux_log_event(session_id=shared_session, source_ip="10.0.0.1")
        ctx_a, data_a = CorrelationContextAdapter.from_log_event(
            event_a, "tenant-A", make_finding(rule_id="SSH-001")
        )

        event_b = make_linux_log_event(session_id=shared_session, source_ip="10.0.0.2")
        ctx_b, data_b = CorrelationContextAdapter.from_log_event(
            event_b, "tenant-B", make_finding(rule_id="SSH-002")
        )

        result = tenant_correlator.correlate(
            events=[(ctx_a, data_a), (ctx_b, data_b)],
            tenant_id="tenant-A",
        )

        assert result.event_count == 1


# =============================================================================
# 19-21. Event Identity Tests
# =============================================================================


class TestEventIdentity:
    """Stable event identity tests."""

    def test_same_event_processed_twice_stable_identity(self):
        """Test 19: Same event processed twice has stable identity."""
        log_event = make_windows_log_event()
        tenant_id = "org-test"

        # Process same event twice
        ctx1, data1 = CorrelationContextAdapter.from_log_event(
            log_event, tenant_id, make_finding()
        )

        ctx2, data2 = CorrelationContextAdapter.from_log_event(
            log_event, tenant_id, make_finding()
        )

        # Event ID should be the same (from log_event.id or source_event_id)
        assert data1.event_id == data2.event_id

        # Context fingerprint should be the same
        assert ctx1.get_entity_fingerprint() == ctx2.get_entity_fingerprint()

    def test_missing_optional_fields_handled(self):
        """Test 20: Missing optional fields don't break conversion."""
        # Event with minimal fields
        log_event = LogEvent(
            id=str(uuid4()),
            source_type=LogSourceType.WINDOWS_EVENT,
            timestamp=datetime.now(timezone.utc),
            message="Minimal event",
            extracted_fields={},
        )

        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id="org-test",
        )

        # Should not raise
        data_dict = ctx.to_event_data_dict()

        assert data_dict["event_id"]
        assert data_dict["ips"] == []
        assert data_dict["users"] == []

    def test_malformed_entities_safely_handled(self):
        """Test 21: Malformed entities don't break correlation."""
        log_event = LogEvent(
            id=str(uuid4()),
            source_type=LogSourceType.WINDOWS_EVENT,
            timestamp=datetime.now(timezone.utc),
            message="Event with bad data",
            extracted_fields={
                "event_data": {
                    "TargetUserName": "",  # Empty
                    "IpAddress": "not-an-ip",  # Invalid
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(
            log_event=log_event,
            tenant_id="org-test",
        )

        # Invalid values should be None
        assert ctx.username is None
        assert ctx.source_ip is None

        # Should still be able to convert
        data_dict = ctx.to_event_data_dict()
        assert data_dict["event_id"]


# =============================================================================
# 22-25. Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Error handling and validation tests."""

    def test_correlation_engine_exception_observable(self, reset_metrics):
        """Test 22: CorrelationEngine exception is observable."""
        # Create a correlator with a mock engine that raises
        class BrokenEngine(CorrelationEngine):
            def correlate(self, events, time_window=None):
                raise RuntimeError("Engine failure")

        correlator = TenantAwareCorrelator(engine=BrokenEngine())

        event = make_windows_log_event()
        ctx, data = CorrelationContextAdapter.from_log_event(
            event, "org-test", make_finding()
        )

        with pytest.raises(CorrelationIntegrationError) as exc_info:
            correlator.correlate(events=[(ctx, data)], tenant_id="org-test")

        assert "Engine failure" in str(exc_info.value)

        # Check metric was incremented
        metrics = get_correlation_metrics()
        assert metrics["correlation_errors"] == 1

    def test_invalid_event_data_rejected(self):
        """Test 23: Invalid EventData conversion raises error."""
        # Create context with no event_id
        ctx = CorrelationContext(
            tenant_id="org-test",
            source_type=LogSourceType.WINDOWS_EVENT,
            timestamp=datetime.now(timezone.utc),
            # No event_id, no source_event_id
        )

        with pytest.raises(InvalidCorrelationDataError) as exc_info:
            CorrelationContextAdapter.to_event_data(ctx)

        assert "Missing event_id" in str(exc_info.value)

    def test_missing_tenant_identity_rejected(self, tenant_correlator):
        """Test 24: Missing tenant identity is rejected."""
        with pytest.raises(TenantResolutionError) as exc_info:
            tenant_correlator.correlate(events=[], tenant_id="")

        assert "required" in str(exc_info.value).lower()

    def test_validate_tenant_id_rejects_empty(self):
        """Test 25: validate_tenant_id rejects empty values."""
        with pytest.raises(TenantResolutionError):
            validate_tenant_id(None)

        with pytest.raises(TenantResolutionError):
            validate_tenant_id("")

        with pytest.raises(TenantResolutionError):
            validate_tenant_id("   ")

        # Valid tenant should pass
        result = validate_tenant_id("org-123")
        assert result == "org-123"


# =============================================================================
# Adapter Tests
# =============================================================================


class TestCorrelationContextAdapter:
    """CorrelationContextAdapter unit tests."""

    def test_to_event_data_maps_ips(self):
        """Adapter maps source_ip and destination_ip to ips list."""
        ctx = CorrelationContext(
            tenant_id="org-test",
            source_type=LogSourceType.WINDOWS_EVENT,
            event_id="evt-123",
            timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
        )

        event_data = CorrelationContextAdapter.to_event_data(ctx)

        assert "10.0.0.1" in event_data.ips
        assert "10.0.0.2" in event_data.ips

    def test_to_event_data_maps_users(self):
        """Adapter maps username and user_id to users list."""
        ctx = CorrelationContext(
            tenant_id="org-test",
            source_type=LogSourceType.LINUX_SSH,
            event_id="evt-123",
            timestamp=datetime.now(timezone.utc),
            username="alice",
            user_id="user-456",
        )

        event_data = CorrelationContextAdapter.to_event_data(ctx)

        assert "alice" in event_data.users
        assert "user-456" in event_data.users

    def test_to_event_data_maps_hostname_to_assets(self):
        """Adapter maps hostname to assets list."""
        ctx = CorrelationContext(
            tenant_id="org-test",
            source_type=LogSourceType.LINUX_SSH,
            event_id="evt-123",
            timestamp=datetime.now(timezone.utc),
            hostname="server01",
        )

        event_data = CorrelationContextAdapter.to_event_data(ctx)

        assert "server01" in event_data.assets

    def test_to_event_data_maps_domain(self):
        """Adapter maps source_type to domain."""
        for source_type, expected_domain in [
            (LogSourceType.WINDOWS_EVENT, "windows_event"),
            (LogSourceType.LINUX_SSH, "linux_ssh"),
            (LogSourceType.ANDROID_ADB, "android_adb"),
        ]:
            ctx = CorrelationContext(
                tenant_id="org-test",
                source_type=source_type,
                event_id="evt-123",
                timestamp=datetime.now(timezone.utc),
            )

            event_data = CorrelationContextAdapter.to_event_data(ctx)
            assert event_data.domain == expected_domain

    def test_from_log_event_requires_tenant(self):
        """from_log_event rejects missing tenant_id."""
        log_event = make_windows_log_event()

        with pytest.raises(TenantResolutionError):
            CorrelationContextAdapter.from_log_event(
                log_event=log_event,
                tenant_id="",
                finding=None,
            )

    def test_from_log_event_with_finding_sets_severity(self):
        """from_log_event extracts severity from finding."""
        log_event = make_windows_log_event()
        finding = make_finding(severity=Severity.HIGH)

        ctx, event_data = CorrelationContextAdapter.from_log_event(
            log_event=log_event,
            tenant_id="org-test",
            finding=finding,
        )

        assert event_data.severity == "high"
        assert event_data.risk_score == 75  # HIGH = 75


# =============================================================================
# Metrics Tests
# =============================================================================


class TestCorrelationMetrics:
    """Correlation metrics tests."""

    def test_metrics_track_events_received(self, tenant_correlator, reset_metrics):
        """Metrics track events received."""
        event = make_windows_log_event()
        ctx, data = CorrelationContextAdapter.from_log_event(
            event, "org-test", make_finding()
        )

        tenant_correlator.correlate(events=[(ctx, data)], tenant_id="org-test")

        metrics = get_correlation_metrics()
        assert metrics["events_received"] == 1

    def test_metrics_track_events_processed(self, tenant_correlator, reset_metrics):
        """Metrics track events processed."""
        event = make_windows_log_event()
        ctx, data = CorrelationContextAdapter.from_log_event(
            event, "org-test", make_finding()
        )

        tenant_correlator.correlate(events=[(ctx, data)], tenant_id="org-test")

        metrics = get_correlation_metrics()
        assert metrics["events_processed"] == 1

    def test_metrics_track_skipped_no_tenant(self, tenant_correlator, reset_metrics):
        """Metrics track events skipped due to no tenant."""
        # Create context without tenant
        ctx = CorrelationContext(
            tenant_id=None,  # No tenant
            source_type=LogSourceType.WINDOWS_EVENT,
            event_id="evt-123",
            timestamp=datetime.now(timezone.utc),
        )
        data = EventData(
            event_id="evt-123",
            domain="windows_event",
            timestamp=datetime.now(timezone.utc),
        )

        tenant_correlator.correlate(events=[(ctx, data)], tenant_id="org-test")

        metrics = get_correlation_metrics()
        assert metrics["events_skipped_no_tenant"] == 1

    def test_metrics_reset(self, reset_metrics):
        """Metrics can be reset."""
        # Get fresh metrics
        metrics = get_correlation_metrics()

        assert metrics["events_received"] == 0
        assert metrics["events_processed"] == 0
        assert metrics["correlation_errors"] == 0


# =============================================================================
# Singleton Tests
# =============================================================================


class TestSingletons:
    """Singleton behavior tests."""

    def test_get_tenant_aware_correlator_returns_singleton(self, reset_metrics):
        """get_tenant_aware_correlator returns same instance."""
        correlator1 = get_tenant_aware_correlator()
        correlator2 = get_tenant_aware_correlator()

        assert correlator1 is correlator2

    def test_correlator_uses_singleton_engine(self, reset_metrics):
        """TenantAwareCorrelator uses singleton CorrelationEngine."""
        correlator = get_tenant_aware_correlator()
        engine = get_correlation_engine()

        assert correlator.engine is engine


# =============================================================================
# create_correlation_context_from_finding Tests
# =============================================================================


class TestCreateCorrelationContextFromFinding:
    """Tests for create_correlation_context_from_finding function."""

    def test_creates_context_with_finding_id(self):
        """Creates context with finding_id populated."""
        log_event = make_windows_log_event()
        finding = make_finding()

        ctx = create_correlation_context_from_finding(
            log_event=log_event,
            finding=finding,
            tenant_id="org-test",
        )

        assert ctx.finding_id == finding.finding_id
        assert ctx.tenant_id == "org-test"

    def test_raises_on_empty_tenant(self):
        """Raises TenantResolutionError on empty tenant."""
        log_event = make_windows_log_event()
        finding = make_finding()

        with pytest.raises(TenantResolutionError):
            create_correlation_context_from_finding(
                log_event=log_event,
                finding=finding,
                tenant_id="",
            )


# =============================================================================
# Email Analysis Unchanged Test
# =============================================================================


class TestEmailAnalysisUnchanged:
    """Verify email analysis is not affected."""

    def test_email_agent_import_works(self):
        """Email agent can still be imported."""
        try:
            from app.agents.email_agent_v2 import EmailAgent
            agent = EmailAgent()
            assert agent is not None
        except ImportError:
            pytest.skip("EmailAgent not available")

    def test_correlation_engine_works_independently(self):
        """CorrelationEngine works without integration module."""
        engine = get_correlation_engine()

        # Create events directly (old way)
        events = [
            EventData(
                event_id="email-1",
                domain="email",
                timestamp=datetime.now(timezone.utc),
                ips=["10.0.0.1"],
                users=["sender@example.com"],
            ),
            EventData(
                event_id="email-2",
                domain="email",
                timestamp=datetime.now(timezone.utc),
                ips=["10.0.0.1"],
                users=["attacker@malicious.com"],
            ),
        ]

        result = engine.correlate(events=events)

        assert result.event_count == 2
        assert result.total_correlations > 0
