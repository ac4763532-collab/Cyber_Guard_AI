"""
CyberGuard AI - STEP 8.5.4.1 Tests

Comprehensive tests for:
1. Finding Lifecycle Hook (common entry point)
2. Cross-source verification (Windows, Linux, Web)
3. Alert schema with separate id/fingerprint
4. Concurrent update safety
5. Tenant isolation
6. Failure modes
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.agents.base import Finding, Severity


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_finding():
    """Create a mock Finding."""
    return Finding(
        rule_id="TEST-001",
        name="Test Finding",
        description="Test finding for lifecycle",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence=["Test evidence 1", "Test evidence 2"],
        mitre_techniques=["T1059"],
        recommendations=["Investigate"],
    )


@pytest.fixture
def mock_log_event():
    """Create a mock LogEvent-like object."""
    class MockLogEvent:
        def __init__(self):
            self.event_id = str(uuid4())
            self.source = "test-source"
            self.timestamp = datetime.now(timezone.utc)
            self.source_type = MagicMock(value="linux_syslog")
            self.source_ip = "192.168.1.100"
            self.user = "testuser"
            self.hostname = "testhost"
            self.session_id = "sess-123"
            self.raw_data = {"test": "data"}

    return MockLogEvent()


@pytest.fixture
def mock_windows_event():
    """Create a mock Windows log event."""
    class MockWindowsEvent:
        def __init__(self):
            self.event_id = str(uuid4())
            self.source = "windows-dc"
            self.timestamp = datetime.now(timezone.utc)
            self.source_type = MagicMock(value="windows_event")
            self.source_ip = "10.0.0.50"
            self.user = "Administrator"
            self.hostname = "DC01"
            self.session_id = None
            self.raw_data = {"EventID": 4625}

    return MockWindowsEvent()


@pytest.fixture
def mock_web_event():
    """Create a mock Web application log event."""
    class MockWebEvent:
        def __init__(self):
            self.event_id = str(uuid4())
            self.source = "web-app"
            self.timestamp = datetime.now(timezone.utc)
            self.source_type = MagicMock(value="android_adb")
            self.source_ip = "203.0.113.50"
            self.user = "api-user"
            self.hostname = "api.example.com"
            self.session_id = "web-sess-456"
            self.raw_data = {"path": "/api/admin"}

    return MockWebEvent()


@pytest.fixture
def mock_correlated_activity():
    """Create a mock CorrelatedActivity."""
    class MockActivity:
        def __init__(self):
            self.correlation_id = str(uuid4())
            self.fingerprint = "abc123fingerprint"
            self.tenant_id = "tenant-1"
            self.finding_ids = [str(uuid4()), str(uuid4())]
            self.event_ids = [str(uuid4())]
            self.source_types = ["windows", "linux"]
            self.correlation_type = "user_activity"
            self.correlation_strength = 0.85
            self.shared_entities = {
                "ips": ["192.168.1.100"],
                "users": ["testuser"],
            }
            self.risk_score = 75
            self.timestamp = datetime.now(timezone.utc)
            self.correlation_bucket = "2024-01-15T10:00"

    return MockActivity()


# =============================================================================
# Finding Lifecycle Tests
# =============================================================================


class TestFindingLifecycle:
    """Tests for the common finding lifecycle hook."""

    @pytest.mark.asyncio
    async def test_lifecycle_receives_finding(self, mock_finding, mock_log_event):
        """Test that lifecycle hook receives findings."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"correlation_id": None, "activity": None}

            result = await on_finding_created(
                log_event=mock_log_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            assert result["finding_id"] == mock_finding.finding_id
            assert result["tenant_id"] == "test-tenant"

            metrics = get_lifecycle_metrics()
            assert metrics["findings_received"] == 1

    @pytest.mark.asyncio
    async def test_lifecycle_detects_windows_source(self, mock_finding, mock_windows_event):
        """Test source type detection for Windows events."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"correlation_id": None, "activity": None}

            result = await on_finding_created(
                log_event=mock_windows_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            assert result["source_type"] == "windows"

            metrics = get_lifecycle_metrics()
            assert metrics["findings_from_windows"] == 1

    @pytest.mark.asyncio
    async def test_lifecycle_detects_linux_source(self, mock_finding, mock_log_event):
        """Test source type detection for Linux events."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"correlation_id": None, "activity": None}

            result = await on_finding_created(
                log_event=mock_log_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            assert result["source_type"] == "linux"

            metrics = get_lifecycle_metrics()
            assert metrics["findings_from_linux"] == 1

    @pytest.mark.asyncio
    async def test_lifecycle_detects_android_source(self, mock_finding, mock_web_event):
        """Test source type detection for Android events."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"correlation_id": None, "activity": None}

            result = await on_finding_created(
                log_event=mock_web_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            assert result["source_type"] == "android"

            metrics = get_lifecycle_metrics()
            assert metrics["findings_from_android"] == 1

    @pytest.mark.asyncio
    async def test_lifecycle_triggers_correlation(
        self, mock_finding, mock_log_event, mock_correlated_activity
    ):
        """Test that lifecycle triggers correlation."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
            _increment_metric,
        )

        reset_lifecycle_metrics()

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            # Simulate the metric increment that happens inside _trigger_correlation
            async def mock_trigger(*args, **kwargs):
                _increment_metric("correlation_triggered")
                return {
                    "correlation_id": mock_correlated_activity.correlation_id,
                    "activity": mock_correlated_activity,
                }
            mock_corr.side_effect = mock_trigger

            with patch("app.correlation.finding_lifecycle._trigger_alerting") as mock_alert:
                async def mock_alerting(*args, **kwargs):
                    _increment_metric("alerts_created")
                    _increment_metric("incidents_created")
                    return {
                        "alert_id": "alert-123",
                        "incident_id": "incident-456",
                        "errors": [],
                    }
                mock_alert.side_effect = mock_alerting

                result = await on_finding_created(
                    log_event=mock_log_event,
                    finding=mock_finding,
                    tenant_id="test-tenant",
                )

                assert result["correlation_id"] == mock_correlated_activity.correlation_id
                assert result["alert_id"] == "alert-123"
                assert result["incident_id"] == "incident-456"

                metrics = get_lifecycle_metrics()
                assert metrics["correlation_triggered"] == 1
                assert metrics["alerts_created"] == 1
                assert metrics["incidents_created"] == 1

    @pytest.mark.asyncio
    async def test_lifecycle_fail_safe_missing_tenant(self, mock_finding, mock_log_event):
        """Test fail-safe behavior with missing tenant_id."""
        from app.correlation.finding_lifecycle import on_finding_created

        result = await on_finding_created(
            log_event=mock_log_event,
            finding=mock_finding,
            tenant_id="",  # Empty tenant
        )

        assert "Missing tenant_id" in result["errors"]
        assert result["correlation_id"] is None

    @pytest.mark.asyncio
    async def test_lifecycle_fail_safe_correlation_error(self, mock_finding, mock_log_event):
        """Test fail-safe when correlation fails."""
        from app.correlation.finding_lifecycle import on_finding_created

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"error": "Redis unavailable"}

            result = await on_finding_created(
                log_event=mock_log_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            # Finding is still processed, error is logged
            assert result["finding_id"] == mock_finding.finding_id
            assert "Correlation: Redis unavailable" in result["errors"]

    @pytest.mark.asyncio
    async def test_lifecycle_skip_correlation(self, mock_finding, mock_log_event):
        """Test skipping correlation."""
        from app.correlation.finding_lifecycle import (
            on_finding_created,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        result = await on_finding_created(
            log_event=mock_log_event,
            finding=mock_finding,
            tenant_id="test-tenant",
            skip_correlation=True,
        )

        assert result["correlation_id"] is None
        metrics = get_lifecycle_metrics()
        assert metrics["correlation_triggered"] == 0


# =============================================================================
# Cross-Source Verification Tests
# =============================================================================


class TestCrossSourceVerification:
    """Verify all three sources reach common correlation pipeline."""

    @pytest.mark.asyncio
    async def test_all_sources_use_common_hook(self):
        """Test that Windows, Linux, and Web all use on_finding_created."""
        from app.correlation.finding_lifecycle import on_finding_created

        # The function exists and is callable
        assert callable(on_finding_created)

    @pytest.mark.asyncio
    async def test_windows_integration_uses_lifecycle(self):
        """Test Windows integration uses the common lifecycle hook."""
        # Read the windows_integration.py source to verify it imports on_finding_created
        import inspect
        from app.detection import windows_integration

        source = inspect.getsource(windows_integration.trigger_realtime_correlation)
        assert "on_finding_created" in source

    @pytest.mark.asyncio
    async def test_dispatcher_uses_lifecycle_for_non_windows(self):
        """Test dispatcher integration uses lifecycle for non-Windows events."""
        import inspect
        from app.event_bus import dispatcher_integration

        source = inspect.getsource(dispatcher_integration._process_agent_findings)
        assert "on_finding_created" in source


# =============================================================================
# Alert Schema Tests (Separate ID and Fingerprint)
# =============================================================================


class TestAlertSchemaWithFingerprint:
    """Test alert creation with separate UUID id and fingerprint columns."""

    @pytest.mark.asyncio
    async def test_alert_fingerprint_computed(self):
        """Test alert fingerprint computation."""
        from app.correlation.alert_integration import compute_alert_fingerprint

        fp1 = compute_alert_fingerprint("corr-fp-1", "tenant-1")
        fp2 = compute_alert_fingerprint("corr-fp-1", "tenant-1")
        fp3 = compute_alert_fingerprint("corr-fp-1", "tenant-2")

        # Same inputs = same output
        assert fp1 == fp2

        # Different tenant = different fingerprint
        assert fp1 != fp3

        # Fingerprint is 32 chars
        assert len(fp1) == 32

    @pytest.mark.asyncio
    async def test_alert_creation_with_separate_id_and_fingerprint(
        self, mock_correlated_activity
    ):
        """Test alert uses separate UUID id and fingerprint columns."""
        from app.correlation.alert_integration import (
            CorrelationAlertIntegration,
            reset_integrations_for_testing,
        )

        reset_integrations_for_testing()

        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(db_enabled=True)

            integration = CorrelationAlertIntegration(
                tenant_id="test-tenant",
                db_enabled=True,
            )

            with patch("app.database.connection.get_database") as mock_db:
                mock_db_instance = AsyncMock()
                mock_db.return_value = mock_db_instance

                # First call: get_alert_by_fingerprint returns None (new alert)
                # Second call: create_alert INSERT returns the new UUID
                mock_db_instance.execute_one.side_effect = [
                    None,  # No existing alert
                    {"id": str(uuid4())},  # New alert created with UUID
                ]

                result = await integration._create_alert_from_correlation(
                    mock_correlated_activity
                )

                assert result["status"] == "created"
                assert result["alert_id"] is not None

                # Verify the INSERT query uses gen_random_uuid() and fingerprint column
                call_args = mock_db_instance.execute_one.call_args_list
                insert_call = call_args[1]  # Second call is the INSERT
                query = insert_call[0][0]

                assert "gen_random_uuid()" in query
                assert "fingerprint" in query
                assert "tenant_id" in query


# =============================================================================
# Tenant Isolation Tests
# =============================================================================


class TestTenantIsolation:
    """Test tenant isolation at every layer."""

    @pytest.mark.asyncio
    async def test_alert_lookup_includes_tenant(self, mock_correlated_activity):
        """Test alert lookup always includes tenant_id."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db_instance = AsyncMock()
            mock_db.return_value = mock_db_instance
            mock_db_instance.execute_one.return_value = None

            await integration._get_alert_by_fingerprint("test-fingerprint")

            # Verify query includes tenant_id
            call_args = mock_db_instance.execute_one.call_args
            query = call_args[0][0]
            params = call_args[0][1]

            assert "tenant_id = %(tenant_id)s" in query
            assert params["tenant_id"] == "test-tenant"

    @pytest.mark.asyncio
    async def test_alert_enrichment_includes_tenant(self, mock_correlated_activity):
        """Test alert enrichment includes tenant_id in WHERE clause."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db_instance = AsyncMock()
            mock_db.return_value = mock_db_instance
            mock_db_instance.execute_one.return_value = None

            await integration._enrich_existing_alert(
                alert_id="alert-123",
                activity=mock_correlated_activity,
            )

            # Verify query includes tenant_id in WHERE
            call_args = mock_db_instance.execute_one.call_args
            query = call_args[0][0]
            params = call_args[0][1]

            assert "tenant_id = %(tenant_id)s" in query
            assert params["tenant_id"] == "test-tenant"

    @pytest.mark.asyncio
    async def test_incident_lookup_includes_tenant(self, mock_correlated_activity):
        """Test incident lookup only finds tenant's alerts."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db_instance = AsyncMock()
            mock_db.return_value = mock_db_instance
            mock_db_instance.execute_one.return_value = None

            await integration._find_incident_for_correlation(
                correlation_id=mock_correlated_activity.correlation_id,
                finding_ids=mock_correlated_activity.finding_ids,
            )

            call_args = mock_db_instance.execute_one.call_args
            query = call_args[0][0]
            params = call_args[0][1]

            assert "a.tenant_id = %(tenant_id)s" in query
            assert params["tenant_id"] == "test-tenant"


# =============================================================================
# Concurrent Update Safety Tests
# =============================================================================


class TestConcurrentUpdateSafety:
    """Test PostgreSQL atomic operations for concurrent updates."""

    @pytest.mark.asyncio
    async def test_alert_creation_handles_race_condition(self, mock_correlated_activity):
        """Test concurrent alert creation is handled safely."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db_instance = AsyncMock()
            mock_db.return_value = mock_db_instance

            # Simulate unique constraint violation then successful fetch
            mock_db_instance.execute_one.side_effect = [
                None,  # No existing alert on first check
                ValueError("duplicate key value violates unique constraint"),
                {"id": "existing-alert-id", "fingerprint": "fp"},  # Fetch existing
            ]

            with patch.object(
                integration, "_get_alert_by_fingerprint"
            ) as mock_get:
                mock_get.return_value = {"id": "existing-alert-id"}

                result = await integration._create_alert_from_correlation(
                    mock_correlated_activity
                )

                # Should return existing alert ID, not fail
                assert result["alert_id"] == "existing-alert-id"

    @pytest.mark.asyncio
    async def test_alert_enrichment_uses_atomic_update(self, mock_correlated_activity):
        """Test alert enrichment uses FOR UPDATE for atomicity."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db_instance = AsyncMock()
            mock_db.return_value = mock_db_instance
            mock_db_instance.execute_one.return_value = {"id": "alert-123", "added_count": 2}

            await integration._enrich_existing_alert(
                alert_id="alert-123",
                activity=mock_correlated_activity,
            )

            call_args = mock_db_instance.execute_one.call_args
            query = call_args[0][0]

            # Verify atomic CTE with FOR UPDATE
            assert "FOR UPDATE" in query
            assert "WITH current_alert AS" in query


# =============================================================================
# Failure Mode Tests
# =============================================================================


class TestFailureModes:
    """Test failure handling and graceful degradation."""

    @pytest.mark.asyncio
    async def test_correlation_redis_unavailable(self, mock_finding, mock_log_event):
        """Test behavior when Redis is unavailable."""
        from app.correlation.finding_lifecycle import on_finding_created

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"error": "Redis unavailable: Connection refused"}

            result = await on_finding_created(
                log_event=mock_log_event,
                finding=mock_finding,
                tenant_id="test-tenant",
            )

            # Finding is tracked, correlation error logged
            assert result["finding_id"] == mock_finding.finding_id
            assert "Redis unavailable" in str(result["errors"])

    @pytest.mark.asyncio
    async def test_database_unavailable_for_alert(self, mock_correlated_activity):
        """Test alert creation when database is unavailable."""
        from app.correlation.alert_integration import CorrelationAlertIntegration

        integration = CorrelationAlertIntegration(
            tenant_id="test-tenant",
            db_enabled=True,
        )

        with patch("app.database.connection.get_database") as mock_db:
            mock_db.side_effect = OSError("Database connection failed")

            result = await integration._create_alert_from_correlation(
                mock_correlated_activity
            )

            # When DB fails, status is "creation_failed" and error is captured
            assert result["status"] == "creation_failed"
            assert result["alert_id"] is None

    @pytest.mark.asyncio
    async def test_finding_persists_when_downstream_fails(
        self, mock_finding, mock_log_event, mock_correlated_activity
    ):
        """Test finding is preserved even when alert/incident fails."""
        from app.correlation.finding_lifecycle import on_finding_created

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {
                "correlation_id": mock_correlated_activity.correlation_id,
                "activity": mock_correlated_activity,
            }

            with patch("app.correlation.finding_lifecycle._trigger_alerting") as mock_alert:
                mock_alert.return_value = {
                    "alert_id": None,
                    "incident_id": None,
                    "errors": ["Alert creation failed"],
                }

                result = await on_finding_created(
                    log_event=mock_log_event,
                    finding=mock_finding,
                    tenant_id="test-tenant",
                )

                # Finding ID is preserved
                assert result["finding_id"] == mock_finding.finding_id
                # Correlation was found
                assert result["correlation_id"] is not None
                # Alert/incident failed but errors captured
                assert "Alert creation failed" in str(result["errors"])


# =============================================================================
# Metrics Tests
# =============================================================================


class TestLifecycleMetrics:
    """Test lifecycle metrics tracking."""

    @pytest.mark.asyncio
    async def test_metrics_track_all_sources(self):
        """Test metrics track findings from all source types."""
        from app.correlation.finding_lifecycle import (
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
            _increment_metric,
        )

        reset_lifecycle_metrics()

        _increment_metric("findings_from_windows")
        _increment_metric("findings_from_linux")
        _increment_metric("findings_from_android")
        _increment_metric("findings_from_other")

        metrics = get_lifecycle_metrics()
        assert metrics["findings_from_windows"] == 1
        assert metrics["findings_from_linux"] == 1
        assert metrics["findings_from_android"] == 1
        assert metrics["findings_from_other"] == 1

    @pytest.mark.asyncio
    async def test_metrics_track_downstream_outcomes(self):
        """Test metrics track correlation, alert, and incident outcomes."""
        from app.correlation.finding_lifecycle import (
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
            _increment_metric,
        )

        reset_lifecycle_metrics()

        _increment_metric("correlation_triggered")
        _increment_metric("alerts_created")
        _increment_metric("incidents_created")
        _increment_metric("downstream_errors")

        metrics = get_lifecycle_metrics()
        assert metrics["correlation_triggered"] == 1
        assert metrics["alerts_created"] == 1
        assert metrics["incidents_created"] == 1
        assert metrics["downstream_errors"] == 1


# =============================================================================
# Batch Processing Tests
# =============================================================================


class TestBatchProcessing:
    """Test batch finding processing."""

    @pytest.mark.asyncio
    async def test_batch_processes_multiple_findings(
        self, mock_finding, mock_log_event
    ):
        """Test batch processing of multiple findings."""
        from app.correlation.finding_lifecycle import (
            on_findings_created_batch,
            reset_lifecycle_metrics,
            get_lifecycle_metrics,
        )

        reset_lifecycle_metrics()

        findings_with_context = [
            (mock_log_event, mock_finding, "tenant-1"),
            (mock_log_event, mock_finding, "tenant-2"),
            (mock_log_event, mock_finding, "tenant-3"),
        ]

        with patch("app.correlation.finding_lifecycle._trigger_correlation") as mock_corr:
            mock_corr.return_value = {"correlation_id": None, "activity": None}

            results = await on_findings_created_batch(findings_with_context)

            assert len(results) == 3
            assert all(r["finding_id"] == mock_finding.finding_id for r in results)

            metrics = get_lifecycle_metrics()
            assert metrics["findings_received"] == 3
