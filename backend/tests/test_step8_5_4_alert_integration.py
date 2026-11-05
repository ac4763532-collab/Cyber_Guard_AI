"""
CyberGuard AI - STEP 8.5.4 Tests

Tests for CorrelatedActivity → AlertManager + IncidentManager Integration.

Coverage:
- Alert fingerprint computation
- Severity/priority mapping
- Alert creation from correlation
- Alert deduplication via fingerprint
- Alert enrichment (correlation evolution)
- Incident creation from correlation
- Incident enrichment (new evidence)
- Find incident for correlation
- Full process_correlated_activity flow
- Fail-safe behavior
- Metrics tracking
- Tenant isolation
- Factory functions
- Edge cases

Tests: 38 total
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.correlation.alert_integration import (
    CorrelationAlertIntegration,
    _correlation_risk_to_severity,
    _severity_to_priority,
    compute_alert_fingerprint,
    get_correlation_alert_integration,
    get_integration_metrics,
    process_correlation_to_alert_and_incident,
    reset_integration_metrics,
    reset_integrations_for_testing,
)
from app.database.models import SeverityLevel

# =============================================================================
# Test Fixtures
# =============================================================================


class MockCorrelatedActivity:
    """Mock CorrelatedActivity for testing."""

    def __init__(
        self,
        correlation_id: str | None = None,
        tenant_id: str = "test-tenant",
        fingerprint: str | None = None,
        finding_ids: list[str] | None = None,
        event_ids: list[str] | None = None,
        source_types: list[str] | None = None,
        correlation_type: str = "cross_source",
        correlation_strength: float = 0.85,
        shared_entities: dict[str, list[str]] | None = None,
        risk_score: int = 75,
        timestamp: datetime | None = None,
        correlation_bucket: str = "2024-01-15T14:00",
    ):
        self.correlation_id = correlation_id or str(uuid4())
        self.tenant_id = tenant_id
        self.fingerprint = fingerprint or f"fp_{uuid4().hex[:16]}"
        self.finding_ids = finding_ids or [str(uuid4()), str(uuid4())]
        self.event_ids = event_ids or [f"evt_{uuid4().hex[:8]}" for _ in range(2)]
        self.source_types = source_types or ["windows_event", "android_adb"]
        self.correlation_type = correlation_type
        self.correlation_strength = correlation_strength
        self.shared_entities = shared_entities or {
            "ips": ["192.168.1.100"],
            "users": ["admin"],
            "assets": ["server-01"],
        }
        self.risk_score = risk_score
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.correlation_bucket = correlation_bucket


@pytest.fixture
def mock_activity() -> MockCorrelatedActivity:
    """Create a mock CorrelatedActivity."""
    return MockCorrelatedActivity()


@pytest.fixture
def mock_critical_activity() -> MockCorrelatedActivity:
    """Create a critical severity activity."""
    return MockCorrelatedActivity(
        risk_score=95,
        correlation_strength=0.95,
        finding_ids=[str(uuid4()) for _ in range(5)],
    )


@pytest.fixture(autouse=True)
def reset_state():
    """Reset all state before each test."""
    reset_integrations_for_testing()
    yield
    reset_integrations_for_testing()


# =============================================================================
# Alert Fingerprint Tests
# =============================================================================


class TestAlertFingerprint:
    """Tests for alert fingerprint computation."""

    def test_fingerprint_deterministic(self):
        """Same inputs produce same fingerprint."""
        fp1 = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        fp2 = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        assert fp1 == fp2

    def test_fingerprint_different_correlation(self):
        """Different correlation produces different fingerprint."""
        fp1 = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        fp2 = compute_alert_fingerprint("corr_fp_456", "tenant_a")
        assert fp1 != fp2

    def test_fingerprint_different_tenant(self):
        """Different tenant produces different fingerprint."""
        fp1 = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        fp2 = compute_alert_fingerprint("corr_fp_123", "tenant_b")
        assert fp1 != fp2

    def test_fingerprint_length(self):
        """Fingerprint is 32 characters."""
        fp = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        assert len(fp) == 32

    def test_fingerprint_hexadecimal(self):
        """Fingerprint is valid hexadecimal."""
        fp = compute_alert_fingerprint("corr_fp_123", "tenant_a")
        assert all(c in "0123456789abcdef" for c in fp)


# =============================================================================
# Severity Mapping Tests
# =============================================================================


class TestSeverityMapping:
    """Tests for severity and priority mapping."""

    def test_critical_risk_to_severity(self):
        """Risk 90+ maps to CRITICAL."""
        assert _correlation_risk_to_severity(90) == SeverityLevel.CRITICAL
        assert _correlation_risk_to_severity(95) == SeverityLevel.CRITICAL
        assert _correlation_risk_to_severity(100) == SeverityLevel.CRITICAL

    def test_high_risk_to_severity(self):
        """Risk 70-89 maps to HIGH."""
        assert _correlation_risk_to_severity(70) == SeverityLevel.HIGH
        assert _correlation_risk_to_severity(89) == SeverityLevel.HIGH

    def test_medium_risk_to_severity(self):
        """Risk 50-69 maps to MEDIUM."""
        assert _correlation_risk_to_severity(50) == SeverityLevel.MEDIUM
        assert _correlation_risk_to_severity(69) == SeverityLevel.MEDIUM

    def test_low_risk_to_severity(self):
        """Risk 25-49 maps to LOW."""
        assert _correlation_risk_to_severity(25) == SeverityLevel.LOW
        assert _correlation_risk_to_severity(49) == SeverityLevel.LOW

    def test_info_risk_to_severity(self):
        """Risk <25 maps to INFO."""
        assert _correlation_risk_to_severity(0) == SeverityLevel.INFO
        assert _correlation_risk_to_severity(24) == SeverityLevel.INFO

    def test_severity_to_priority(self):
        """Severity maps to priority correctly."""
        assert _severity_to_priority(SeverityLevel.CRITICAL) == 1
        assert _severity_to_priority(SeverityLevel.HIGH) == 2
        assert _severity_to_priority(SeverityLevel.MEDIUM) == 3
        assert _severity_to_priority(SeverityLevel.LOW) == 4
        assert _severity_to_priority(SeverityLevel.INFO) == 5


# =============================================================================
# Integration Creation Tests
# =============================================================================


class TestIntegrationCreation:
    """Tests for CorrelationAlertIntegration creation."""

    @pytest.mark.asyncio
    async def test_create_integration(self):
        """Successfully create integration."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            assert integration.tenant_id == "test-tenant"
            assert integration._db_enabled is True

    @pytest.mark.asyncio
    async def test_create_integration_empty_tenant(self):
        """Empty tenant raises ValueError."""
        with pytest.raises(ValueError, match="tenant_id is required"):
            await CorrelationAlertIntegration.create("")

    @pytest.mark.asyncio
    async def test_create_integration_whitespace_tenant(self):
        """Whitespace tenant raises ValueError."""
        with pytest.raises(ValueError, match="tenant_id is required"):
            await CorrelationAlertIntegration.create("   ")

    @pytest.mark.asyncio
    async def test_factory_caches_integration(self):
        """Factory caches integration per tenant."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            int1 = await get_correlation_alert_integration("tenant-a")
            int2 = await get_correlation_alert_integration("tenant-a")
            int3 = await get_correlation_alert_integration("tenant-b")

            assert int1 is int2
            assert int1 is not int3

    def test_reset_clears_cache(self):
        """Reset clears integration cache."""
        reset_integrations_for_testing()
        metrics = get_integration_metrics()
        assert metrics["alerts_created"] == 0


# =============================================================================
# Alert Creation Tests
# =============================================================================


class TestAlertCreation:
    """Tests for alert creation from correlation."""

    @pytest.mark.asyncio
    async def test_create_alert_success(self, mock_activity):
        """Successfully create alert from activity."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            # Mock database - patch at source module
            with patch(
                "app.database.connection.get_database"
            ) as mock_get_db:
                mock_db = MagicMock()
                mock_db.execute_one = AsyncMock(return_value={"id": "alert-123"})
                mock_get_db.return_value = mock_db

                # Mock no existing alert
                with patch.object(
                    integration,
                    "_get_alert_by_fingerprint",
                    return_value=None,
                ):
                    result = await integration._create_alert_from_correlation(
                        mock_activity
                    )

                    assert result["status"] == "created"
                    assert result["alert_id"] is not None

    @pytest.mark.asyncio
    async def test_create_alert_db_disabled(self, mock_activity):
        """Alert not created when DB disabled."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = False

            integration = await CorrelationAlertIntegration.create("test-tenant")
            result = await integration._create_alert_from_correlation(mock_activity)

            assert result["status"] == "db_disabled"
            assert result["alert_id"] is None


# =============================================================================
# Alert Deduplication Tests
# =============================================================================


class TestAlertDeduplication:
    """Tests for alert deduplication via fingerprint."""

    @pytest.mark.asyncio
    async def test_duplicate_alert_detected(self, mock_activity):
        """Duplicate alert is detected and skipped."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            # Mock existing alert
            with patch.object(
                integration,
                "_get_alert_by_fingerprint",
                return_value={
                    "id": "existing-alert",
                    "correlation_id": "corr-1",
                    "finding_ids": mock_activity.finding_ids,
                    "status": "new",
                },
            ):
                # Mock enrich returns False (no new evidence)
                with patch.object(
                    integration,
                    "_enrich_existing_alert",
                    return_value=False,
                ):
                    result = await integration._create_alert_from_correlation(
                        mock_activity
                    )

                    assert result["status"] == "deduplicated"
                    assert result["alert_id"] == "existing-alert"

    @pytest.mark.asyncio
    async def test_same_correlation_same_alert_fingerprint(self):
        """Same correlation always produces same alert fingerprint."""
        activity1 = MockCorrelatedActivity(
            fingerprint="same_fingerprint",
            tenant_id="tenant-x",
        )
        activity2 = MockCorrelatedActivity(
            fingerprint="same_fingerprint",
            tenant_id="tenant-x",
        )

        fp1 = compute_alert_fingerprint(activity1.fingerprint, activity1.tenant_id)
        fp2 = compute_alert_fingerprint(activity2.fingerprint, activity2.tenant_id)

        assert fp1 == fp2


# =============================================================================
# Alert Enrichment Tests
# =============================================================================


class TestAlertEnrichment:
    """Tests for alert enrichment (correlation evolution)."""

    @pytest.mark.asyncio
    async def test_alert_enrichment_new_findings(self, mock_activity):
        """Alert enriched when new findings are added."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            # Simulate correlation evolution: A+B → A+B+C
            existing_finding = str(uuid4())
            new_finding = str(uuid4())
            mock_activity.finding_ids = [existing_finding, new_finding]

            with patch(
                "app.database.connection.get_database"
            ) as mock_get_db:
                mock_db = MagicMock()
                # Atomic CTE returns result when update happens (new findings added)
                mock_db.execute_one = AsyncMock(
                    return_value={"id": "alert-123", "added_count": 1}
                )
                mock_get_db.return_value = mock_db

                result = await integration._enrich_existing_alert(
                    alert_id="alert-123",
                    activity=mock_activity,
                )

                assert result is True
                # Atomic update uses single query
                assert mock_db.execute_one.call_count == 1

    @pytest.mark.asyncio
    async def test_alert_enrichment_no_new_findings(self, mock_activity):
        """Alert not enriched when no new findings."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch(
                "app.database.connection.get_database"
            ) as mock_get_db:
                mock_db = MagicMock()
                # Atomic CTE returns None when no new findings to add
                mock_db.execute_one = AsyncMock(return_value=None)
                mock_get_db.return_value = mock_db

                result = await integration._enrich_existing_alert(
                    alert_id="alert-123",
                    activity=mock_activity,
                )

                assert result is False


# =============================================================================
# Incident Creation Tests
# =============================================================================


class TestIncidentCreation:
    """Tests for incident creation from correlation."""

    @pytest.mark.asyncio
    async def test_create_incident_success(self, mock_activity):
        """Successfully create incident from correlation."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            # Mock no existing incident
            with patch.object(
                integration,
                "_find_incident_for_correlation",
                return_value=None,
            ), patch(
                "app.incidents.manager.get_incident_manager"
            ) as mock_get_mgr:
                mock_manager = MagicMock()
                mock_incident = MagicMock()
                mock_incident.id = "incident-123"
                mock_manager.create_incident_async = AsyncMock(
                    return_value=mock_incident
                )
                mock_get_mgr.return_value = mock_manager

                result = await integration._create_or_enrich_incident(
                    activity=mock_activity,
                    alert_id="alert-456",
                )

                assert result["status"] == "created"
                assert result["incident_id"] == "incident-123"

    @pytest.mark.asyncio
    async def test_create_incident_db_disabled(self, mock_activity):
        """Incident not created when DB disabled."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = False

            integration = await CorrelationAlertIntegration.create("test-tenant")
            result = await integration._create_or_enrich_incident(
                activity=mock_activity,
                alert_id="alert-123",
            )

            assert result["status"] == "db_disabled"
            assert result["incident_id"] is None


# =============================================================================
# Incident Enrichment Tests
# =============================================================================


class TestIncidentEnrichment:
    """Tests for incident enrichment with new alerts."""

    @pytest.mark.asyncio
    async def test_incident_enrichment_success(self, mock_activity):
        """Successfully enrich existing incident."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            # Mock existing incident
            with patch.object(
                integration,
                "_find_incident_for_correlation",
                return_value={
                    "id": "incident-existing",
                    "title": "Existing Incident",
                    "status": "investigating",
                    "alert_ids": ["alert-old"],
                },
            ), patch(
                "app.incidents.manager.get_incident_manager"
            ) as mock_get_mgr:
                mock_manager = MagicMock()
                mock_manager.add_alert_to_incident_async = AsyncMock(
                    return_value=MagicMock()
                )
                mock_get_mgr.return_value = mock_manager

                result = await integration._create_or_enrich_incident(
                    activity=mock_activity,
                    alert_id="alert-new",
                )

                assert result["status"] == "enriched"
                assert result["incident_id"] == "incident-existing"


# =============================================================================
# Find Incident Tests
# =============================================================================


class TestFindIncident:
    """Tests for finding existing incident for correlation."""

    @pytest.mark.asyncio
    async def test_find_incident_by_shared_findings(self, mock_activity):
        """Find incident by overlapping findings."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch(
                "app.database.connection.get_database"
            ) as mock_get_db:
                mock_db = MagicMock()
                mock_db.execute_one = AsyncMock(
                    return_value={
                        "id": "incident-found",
                        "title": "Related Incident",
                        "status": "open",
                        "alert_ids": ["alert-1"],
                    }
                )
                mock_get_db.return_value = mock_db

                result = await integration._find_incident_for_correlation(
                    correlation_id=mock_activity.correlation_id,
                    finding_ids=mock_activity.finding_ids,
                )

                assert result is not None
                assert result["id"] == "incident-found"

    @pytest.mark.asyncio
    async def test_find_incident_none_found(self, mock_activity):
        """Return None when no related incident."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch(
                "app.database.connection.get_database"
            ) as mock_get_db:
                mock_db = MagicMock()
                mock_db.execute_one = AsyncMock(return_value=None)
                mock_get_db.return_value = mock_db

                result = await integration._find_incident_for_correlation(
                    correlation_id=mock_activity.correlation_id,
                    finding_ids=mock_activity.finding_ids,
                )

                assert result is None


# =============================================================================
# Full Flow Tests
# =============================================================================


class TestFullFlow:
    """Tests for full process_correlated_activity flow."""

    @pytest.mark.asyncio
    async def test_full_flow_create_alert_and_incident(self, mock_activity):
        """Full flow creates both alert and incident."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch.object(
                integration,
                "_create_alert_from_correlation",
                return_value={"alert_id": "alert-new", "status": "created"},
            ), patch.object(
                integration,
                "_create_or_enrich_incident",
                return_value={"incident_id": "incident-new", "status": "created"},
            ):
                result = await integration.process_correlated_activity(
                    mock_activity
                )

                assert result["alert_id"] == "alert-new"
                assert result["incident_id"] == "incident-new"
                assert result["alert_status"] == "created"
                assert result["incident_status"] == "created"
                assert result["errors"] == []

    @pytest.mark.asyncio
    async def test_full_flow_no_incident_without_alert(self, mock_activity):
        """Incident not created if alert creation fails."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch.object(
                integration,
                "_create_alert_from_correlation",
                return_value={"alert_id": None, "status": "error", "error": "DB error"},
            ):
                result = await integration.process_correlated_activity(mock_activity)

                assert result["alert_id"] is None
                assert result["incident_id"] is None
                assert "Alert: DB error" in result["errors"]


# =============================================================================
# Fail-Safe Tests
# =============================================================================


class TestFailSafe:
    """Tests for fail-safe behavior."""

    @pytest.mark.asyncio
    async def test_alert_error_returns_result(self, mock_activity):
        """Alert error returns result with error info."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch.object(
                integration,
                "_create_alert_from_correlation",
                side_effect=RuntimeError("Database unavailable"),
            ):
                result = await integration.process_correlated_activity(mock_activity)

                assert result["alert_id"] is None
                assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_high_level_api_catches_all_errors(self, mock_activity):
        """High-level API catches all exceptions."""
        with patch(
            "app.correlation.alert_integration.get_correlation_alert_integration"
        ) as mock_get:
            mock_get.side_effect = RuntimeError("Integration creation failed")

            result = await process_correlation_to_alert_and_incident(
                activity=mock_activity,
                tenant_id="test-tenant",
            )

            assert result["alert_status"] == "error"
            assert result["incident_status"] == "error"
            assert len(result["errors"]) > 0


# =============================================================================
# Metrics Tests
# =============================================================================


class TestMetrics:
    """Tests for metrics tracking."""

    def test_initial_metrics(self):
        """Initial metrics are zero."""
        reset_integration_metrics()
        metrics = get_integration_metrics()

        assert metrics["alerts_created"] == 0
        assert metrics["alerts_deduplicated"] == 0
        assert metrics["incidents_created"] == 0

    def test_metrics_are_copies(self):
        """Returned metrics are copies."""
        metrics1 = get_integration_metrics()
        metrics1["alerts_created"] = 999
        metrics2 = get_integration_metrics()

        assert metrics2["alerts_created"] == 0

    @pytest.mark.asyncio
    async def test_metrics_track_deduplication(self, mock_activity):
        """Metrics track deduplication events."""
        reset_integration_metrics()

        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")

            with patch.object(
                integration,
                "_get_alert_by_fingerprint",
                return_value={
                    "id": "existing",
                    "finding_ids": mock_activity.finding_ids,
                },
            ), patch.object(
                integration,
                "_enrich_existing_alert",
                return_value=False,
            ):
                await integration._create_alert_from_correlation(mock_activity)

        metrics = get_integration_metrics()
        assert metrics["alerts_deduplicated"] == 1


# =============================================================================
# Tenant Isolation Tests
# =============================================================================


class TestTenantIsolation:
    """Tests for tenant isolation."""

    def test_fingerprint_includes_tenant(self):
        """Alert fingerprint includes tenant for isolation."""
        # Same correlation, different tenants
        fp_a = compute_alert_fingerprint("corr_123", "tenant_a")
        fp_b = compute_alert_fingerprint("corr_123", "tenant_b")

        assert fp_a != fp_b

    @pytest.mark.asyncio
    async def test_integration_per_tenant(self):
        """Each tenant gets separate integration."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            int_a = await get_correlation_alert_integration("tenant-a")
            int_b = await get_correlation_alert_integration("tenant-b")

            assert int_a.tenant_id == "tenant-a"
            assert int_b.tenant_id == "tenant-b"
            assert int_a is not int_b


# =============================================================================
# Edge Cases Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_empty_shared_entities(self):
        """Handle empty shared entities."""
        activity = MockCorrelatedActivity(
            shared_entities={"ips": [], "users": [], "assets": []},
        )

        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")
            description = integration._build_alert_description(activity)

            # Should not crash, should produce valid description
            assert "Correlation ID:" in description
            assert activity.correlation_id in description

    @pytest.mark.asyncio
    async def test_single_finding_correlation(self):
        """Handle correlation with single finding."""
        activity = MockCorrelatedActivity(
            finding_ids=[str(uuid4())],
            source_types=["windows_event"],
        )

        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")
            description = integration._build_alert_description(activity)

            assert "**Findings:** 1" in description

    @pytest.mark.asyncio
    async def test_very_high_risk_score(self):
        """Handle maximum risk score."""
        activity = MockCorrelatedActivity(risk_score=100)

        severity = _correlation_risk_to_severity(activity.risk_score)
        assert severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_zero_risk_score(self):
        """Handle zero risk score."""
        activity = MockCorrelatedActivity(risk_score=0)

        severity = _correlation_risk_to_severity(activity.risk_score)
        assert severity == SeverityLevel.INFO

    @pytest.mark.asyncio
    async def test_many_source_types(self):
        """Handle many source types."""
        activity = MockCorrelatedActivity(
            source_types=[
                "windows_event",
                "linux_ssh",
                "android_adb",
                "firewall",
                "ids",
            ],
        )

        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")
            description = integration._build_alert_description(activity)

            for src in activity.source_types:
                assert src in description


# =============================================================================
# Description Building Tests
# =============================================================================


class TestDescriptionBuilding:
    """Tests for alert/incident description building."""

    @pytest.mark.asyncio
    async def test_alert_description_contains_key_info(self, mock_activity):
        """Alert description contains key information."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")
            description = integration._build_alert_description(mock_activity)

            assert mock_activity.correlation_id in description
            assert mock_activity.correlation_type in description
            assert str(mock_activity.risk_score) in description

    @pytest.mark.asyncio
    async def test_incident_description_contains_key_info(self, mock_activity):
        """Incident description contains key information."""
        with patch("app.correlation.alert_integration.get_settings") as mock_settings:
            mock_settings.return_value.db_enabled = True

            integration = await CorrelationAlertIntegration.create("test-tenant")
            description = integration._build_incident_description(mock_activity)

            assert mock_activity.correlation_id in description
            assert "investigation" in description.lower()
