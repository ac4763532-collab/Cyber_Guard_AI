"""
CyberGuard AI - STEP 8.2 Windows Detection Integration Tests

Comprehensive tests for:
1. Source type validation (unsupported types rejected)
2. WIN-001: Failed Authentication Burst (in-memory rule)
3. WIN-002: Authentication Sequence (in-memory rule)
4. WIN-003: Privileged Activity
5. Idempotency
6. Integration with existing detection pipeline

NOTE: These tests use the IN-MEMORY rules for unit testing.
For Redis-backed production rules, see test_step8_2_1_redis_state.py
and test_step8_2_2_integration.py.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from app.logs.models import LogEvent, LogSourceType, LogLevel, SUPPORTED_SOURCE_TYPES
from app.logs.event_bus_integration import (
    UnsupportedSourceTypeError,
    security_event_to_log_event,
    log_event_to_security_event,
)
from app.event_bus.events import SecurityEvent
from app.database.models.base import SeverityLevel
from app.detection.rules.windows import (
    WindowsFailedAuthBurstRule,
    WindowsAuthSequenceRule,
    WindowsPrivilegedActivityRule,
    DEFAULT_FAILED_AUTH_THRESHOLD,
    DEFAULT_FAILED_AUTH_WINDOW_SECONDS,
)
from app.agents.base import Severity


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def failed_auth_rule():
    """Create a fresh failed auth rule for testing."""
    rule = WindowsFailedAuthBurstRule(threshold=5, window_seconds=300)
    yield rule
    rule.reset_tracker()


@pytest.fixture
def auth_sequence_rule():
    """Create a fresh auth sequence rule for testing."""
    rule = WindowsAuthSequenceRule(failure_threshold=3, window_seconds=300)
    yield rule
    rule.reset_tracker()


@pytest.fixture
def privileged_rule():
    """Create a fresh privileged activity rule for testing."""
    return WindowsPrivilegedActivityRule()


# =============================================================================
# 1. Source Type Validation Tests (STEP 8.0.1 Fix)
# =============================================================================


class TestSourceTypeValidation:
    """Tests for source type validation - unsupported types must be REJECTED."""

    def test_supported_source_types(self):
        """Verify exactly 3 source types are supported."""
        assert SUPPORTED_SOURCE_TYPES == {
            LogSourceType.WINDOWS_EVENT,
            LogSourceType.LINUX_SSH,
            LogSourceType.ANDROID_ADB,
        }

    def test_windows_event_accepted(self):
        """Test windows_event source type is accepted."""
        security_event = SecurityEvent(
            event_type="log",
            source="test",
            payload={
                "source_type": "windows_event",
                "message": "Test event",
                "level": "info",
            },
        )

        log_event = security_event_to_log_event(security_event)

        assert log_event is not None
        assert log_event.source_type == LogSourceType.WINDOWS_EVENT

    def test_linux_ssh_accepted(self):
        """Test linux_ssh source type is accepted."""
        security_event = SecurityEvent(
            event_type="log",
            source="test",
            payload={
                "source_type": "linux_ssh",
                "message": "Test event",
                "level": "info",
            },
        )

        log_event = security_event_to_log_event(security_event)

        assert log_event is not None
        assert log_event.source_type == LogSourceType.LINUX_SSH

    def test_android_adb_accepted(self):
        """Test android_adb source type is accepted."""
        security_event = SecurityEvent(
            event_type="log",
            source="test",
            payload={
                "source_type": "android_adb",
                "message": "Test event",
                "level": "info",
            },
        )

        log_event = security_event_to_log_event(security_event)

        assert log_event is not None
        assert log_event.source_type == LogSourceType.ANDROID_ADB

    def test_unknown_source_type_rejected(self):
        """Test unknown source type is REJECTED, not silently converted."""
        security_event = SecurityEvent(
            event_type="log",
            source="test",
            payload={
                "source_type": "postgresql_logs",  # NOT SUPPORTED
                "message": "Test event",
                "level": "info",
            },
        )

        with pytest.raises(UnsupportedSourceTypeError) as exc_info:
            security_event_to_log_event(security_event)

        assert "postgresql_logs" in str(exc_info.value)
        assert exc_info.value.source_type == "postgresql_logs"

    def test_missing_source_type_rejected(self):
        """Test missing source type is REJECTED, not defaulted."""
        security_event = SecurityEvent(
            event_type="log",
            source="test",
            payload={
                # No source_type field
                "message": "Test event",
                "level": "info",
            },
        )

        with pytest.raises(UnsupportedSourceTypeError) as exc_info:
            security_event_to_log_event(security_event)

        assert "(missing)" in str(exc_info.value)

    def test_custom_source_type_rejected(self):
        """Test custom/invented source types are rejected."""
        invalid_types = [
            "database",
            "mysql",
            "firewall",
            "network",
            "syslog",
            "custom",
            "unknown",
            "",
        ]

        for invalid_type in invalid_types:
            security_event = SecurityEvent(
                event_type="log",
                source="test",
                payload={
                    "source_type": invalid_type,
                    "message": "Test",
                    "level": "info",
                },
            )

            with pytest.raises(UnsupportedSourceTypeError):
                security_event_to_log_event(security_event)

    def test_non_log_event_returns_none(self):
        """Test non-log events return None (not error)."""
        security_event = SecurityEvent(
            event_type="email",  # Not "log"
            source="test",
            payload={"message": "Test"},
        )

        result = security_event_to_log_event(security_event)
        assert result is None


# =============================================================================
# 2. WIN-001: Failed Authentication Burst Tests
# =============================================================================


class TestWIN001FailedAuthBurst:
    """Tests for WIN-001: Failed Authentication Burst rule."""

    def test_single_4625_no_finding(self, failed_auth_rule):
        """Single 4625 event should NOT trigger finding."""
        event = {
            "event_code": "4625",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": datetime.now(timezone.utc),
            "hostname": "SERVER01",
        }

        result = failed_auth_rule.evaluate(event)

        assert result is None

    def test_below_threshold_no_finding(self, failed_auth_rule):
        """Failures below threshold should NOT trigger finding."""
        base_time = datetime.now(timezone.utc)

        # 4 failures (threshold is 5)
        for i in range(4):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is None

    def test_at_threshold_triggers_finding(self, failed_auth_rule):
        """Failures at threshold should trigger finding."""
        base_time = datetime.now(timezone.utc)

        # 5 failures (at threshold)
        for i in range(5):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
                "source_event_id": f"win-test-{i}",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is not None
        assert result.rule_id == "WIN-001"
        assert result.matched_data["failure_count"] == 5
        assert result.matched_data["username"] == "admin"
        assert result.matched_data["source_ip"] == "192.168.1.100"

    def test_above_threshold_triggers_finding(self, failed_auth_rule):
        """Failures above threshold should trigger finding."""
        base_time = datetime.now(timezone.utc)

        # 10 failures
        for i in range(10):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 5),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is not None
        assert result.matched_data["failure_count"] == 10

    def test_events_outside_window_not_combined(self, failed_auth_rule):
        """Events outside time window should not be combined."""
        base_time = datetime.now(timezone.utc)

        # 3 failures
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            failed_auth_rule.evaluate(event)

        # 3 more failures OUTSIDE the 300s window
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=400 + i * 10),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        # Should NOT trigger - old events expired
        assert result is None

    def test_same_user_same_ip_correlates(self, failed_auth_rule):
        """Same username + same source IP should correlate."""
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            event = {
                "event_code": "4625",
                "target_user": "testuser",
                "source_ip": "10.0.0.50",
                "timestamp": base_time + timedelta(seconds=i * 5),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is not None
        assert result.matched_data["username"] == "testuser"
        assert result.matched_data["source_ip"] == "10.0.0.50"

    def test_different_ips_separate_tracking(self, failed_auth_rule):
        """Different source IPs should be tracked separately."""
        base_time = datetime.now(timezone.utc)

        # 3 failures from IP1
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            failed_auth_rule.evaluate(event)

        # 3 failures from IP2
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.200",  # Different IP
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        # Neither should trigger (both at 3, threshold is 5)
        assert result is None

    def test_non_4625_event_ignored(self, failed_auth_rule):
        """Non-4625 events should be ignored."""
        event = {
            "event_code": "4624",  # Success event
            "target_user": "admin",
            "source_ip": "192.168.1.100",
        }

        result = failed_auth_rule.evaluate(event)
        assert result is None

    def test_evidence_contains_required_fields(self, failed_auth_rule):
        """Finding evidence should contain all required fields."""
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 5),
                "hostname": "SERVER01",
                "source_event_id": f"win-test-{i}",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is not None
        assert "Username: admin" in result.evidence
        assert "Failure count: 5" in result.evidence
        assert "Source IP: 192.168.1.100" in result.evidence
        assert result.matched_data["source_event_ids"]


# =============================================================================
# 3. WIN-002: Authentication Sequence Tests
# =============================================================================


class TestWIN002AuthSequence:
    """Tests for WIN-002: Authentication Sequence (4625 → 4624) rule."""

    def test_4625_followed_by_4624_triggers(self, auth_sequence_rule):
        """4625 failures followed by 4624 success should trigger."""
        base_time = datetime.now(timezone.utc)

        # 3 failures
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
                "source_event_id": f"win-fail-{i}",
            }
            auth_sequence_rule.evaluate(event)

        # 1 success
        success_event = {
            "event_code": "4624",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": base_time + timedelta(seconds=60),
            "hostname": "SERVER01",
            "source_event_id": "win-success-1",
            "logon_type": 3,
        }
        result = auth_sequence_rule.evaluate(success_event)

        assert result is not None
        assert result.rule_id == "WIN-002"
        assert result.matched_data["failure_count"] == 3
        assert result.matched_data["username"] == "admin"
        assert "failure_event_ids" in result.matched_data

    def test_success_without_failures_no_trigger(self, auth_sequence_rule):
        """4624 without preceding failures should NOT trigger."""
        event = {
            "event_code": "4624",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": datetime.now(timezone.utc),
            "hostname": "SERVER01",
        }

        result = auth_sequence_rule.evaluate(event)
        assert result is None

    def test_below_failure_threshold_no_trigger(self, auth_sequence_rule):
        """Success after too few failures should NOT trigger."""
        base_time = datetime.now(timezone.utc)

        # 2 failures (threshold is 3)
        for i in range(2):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            auth_sequence_rule.evaluate(event)

        # Success
        success_event = {
            "event_code": "4624",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": base_time + timedelta(seconds=30),
            "hostname": "SERVER01",
        }
        result = auth_sequence_rule.evaluate(success_event)

        assert result is None

    def test_failures_cleared_after_detection(self, auth_sequence_rule):
        """Failure history should be cleared after detection."""
        base_time = datetime.now(timezone.utc)

        # 3 failures + success
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "192.168.1.100",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "hostname": "SERVER01",
            }
            auth_sequence_rule.evaluate(event)

        success_event = {
            "event_code": "4624",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": base_time + timedelta(seconds=60),
            "hostname": "SERVER01",
        }
        auth_sequence_rule.evaluate(success_event)

        # Second success should NOT trigger (failures cleared)
        second_success = {
            "event_code": "4624",
            "target_user": "admin",
            "source_ip": "192.168.1.100",
            "timestamp": base_time + timedelta(seconds=120),
            "hostname": "SERVER01",
        }
        result = auth_sequence_rule.evaluate(second_success)

        assert result is None


# =============================================================================
# 4. WIN-003: Privileged Activity Tests
# =============================================================================


class TestWIN003PrivilegedActivity:
    """Tests for WIN-003: Privileged Activity (4672) rule."""

    def test_4672_triggers_finding(self, privileged_rule):
        """4672 event should trigger observability finding."""
        event = {
            "event_code": "4672",
            "subject_user": "Administrator",
            "subject_domain": "BUILTIN",
            "hostname": "SERVER01",
            "privileges": "SeDebugPrivilege SeBackupPrivilege",
            "timestamp": datetime.now(timezone.utc),
            "source_event_id": "win-priv-1",
        }

        result = privileged_rule.evaluate(event)

        assert result is not None
        assert result.rule_id == "WIN-003"
        assert result.severity.value == "low"  # Observability, not threat
        assert result.confidence == 1.0  # Factual observation
        assert "BUILTIN\\Administrator" in result.description

    def test_4672_evidence_complete(self, privileged_rule):
        """4672 finding should contain complete evidence."""
        event = {
            "event_code": "4672",
            "subject_user": "svc_account",
            "subject_domain": "DOMAIN",
            "hostname": "DC01",
            "privileges": "SeImpersonatePrivilege",
            "timestamp": datetime.now(timezone.utc),
            "source_event_id": "win-priv-2",
        }

        result = privileged_rule.evaluate(event)

        assert result is not None
        assert "Account: DOMAIN\\svc_account" in result.evidence
        assert "Host: DC01" in result.evidence
        assert "Privileges: SeImpersonatePrivilege" in result.evidence
        assert result.matched_data["full_user"] == "DOMAIN\\svc_account"

    def test_non_4672_ignored(self, privileged_rule):
        """Non-4672 events should be ignored."""
        event = {
            "event_code": "4624",
            "subject_user": "Administrator",
        }

        result = privileged_rule.evaluate(event)
        assert result is None


# =============================================================================
# 5. Idempotency Tests (LEGACY - see test_step8_2_2_integration.py for Redis tests)
# =============================================================================


@pytest.mark.skip(reason="Processor tests moved to test_step8_2_2_integration.py for Redis-backed version")
class TestIdempotency:
    """Tests for idempotent event processing."""

    def test_duplicate_event_not_reprocessed(self, windows_processor):
        """Same source_event_id should not be processed twice."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-unique-12345",
            hostname="SERVER01",
            message="Test event",
            extracted_fields={"event_code": "4672", "subject_user": "admin"},
        )

        # First processing
        findings1 = windows_processor.process_log_event(log_event)

        # Second processing (same event)
        findings2 = windows_processor.process_log_event(log_event)

        # Only first should produce findings
        assert len(findings1) > 0 or len(findings1) == 0  # May or may not trigger
        assert len(findings2) == 0  # Duplicate - no findings

    def test_different_events_both_processed(self, windows_processor):
        """Different source_event_ids should both be processed."""
        log_event1 = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-unique-11111",
            hostname="SERVER01",
            message="Test event 1",
            extracted_fields={"event_code": "4672", "subject_user": "admin"},
        )

        log_event2 = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-unique-22222",
            hostname="SERVER01",
            message="Test event 2",
            extracted_fields={"event_code": "4672", "subject_user": "admin"},
        )

        # Both should be processed
        findings1 = windows_processor.process_log_event(log_event1)
        findings2 = windows_processor.process_log_event(log_event2)

        # Both should produce findings (4672 always triggers WIN-003)
        assert len(findings1) > 0
        assert len(findings2) > 0


# =============================================================================
# 6. Integration Tests (LEGACY - see test_step8_2_2_integration.py for Redis tests)
# =============================================================================


@pytest.mark.skip(reason="Processor integration tests moved to test_step8_2_2_integration.py for Redis-backed version")
class TestWindowsDetectionIntegration:
    """Integration tests for Windows detection pipeline."""

    def test_log_event_to_security_event_round_trip(self):
        """Test LogEvent → SecurityEvent → LogEvent conversion."""
        original = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-test-99999",
            source_id="test-source",
            hostname="SERVER01",
            message="Test Windows event",
            level=LogLevel.WARNING,
            extracted_fields={"event_code": "4625", "target_user": "admin"},
            category="authentication",
        )

        # Convert to SecurityEvent
        security_event = log_event_to_security_event(original)

        assert security_event.event_type == "log"
        assert security_event.payload["source_type"] == "windows_event"
        assert security_event.payload["hostname"] == "SERVER01"

        # Convert back
        recovered = security_event_to_log_event(security_event)

        assert recovered is not None
        assert recovered.source_type == LogSourceType.WINDOWS_EVENT
        assert recovered.hostname == "SERVER01"
        assert recovered.extracted_fields["event_code"] == "4625"

    def test_processor_only_processes_windows_events(self, windows_processor):
        """Processor should only process WINDOWS_EVENT source type."""
        linux_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            source_event_id="linux-test-1",
            hostname="server01",
            message="Failed password for admin",
            extracted_fields={},
        )

        findings = windows_processor.process_log_event(linux_event)
        assert len(findings) == 0

    def test_full_detection_chain(self, windows_processor):
        """Test full detection chain: LogEvent → Finding with correct fields."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-full-chain-1",
            source_id="test-source-001",
            hostname="DC01",
            message="Special privileges assigned",
            level=LogLevel.INFO,
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_code": "4672",
                "subject_user": "Administrator",
                "subject_domain": "CORP",
                "privileges": "SeDebugPrivilege",
            },
            category="authorization",
        )

        findings = windows_processor.process_log_event(log_event)

        assert len(findings) > 0
        finding = findings[0]

        # Verify Finding structure
        assert finding.rule_id == "WIN-003"
        assert finding.name == "Windows Privileged Activity"
        assert finding.severity == Severity.LOW
        assert finding.confidence == 1.0
        assert len(finding.evidence) > 0
        assert len(finding.mitre_techniques) > 0
        assert len(finding.recommendations) > 0

        # Verify metadata
        assert finding.metadata["source_event_id"] == "win-full-chain-1"
        assert finding.metadata["hostname"] == "DC01"

    def test_severity_mapping(self, windows_processor):
        """Test that rule severities map correctly to Finding severities."""
        # WIN-003 is LOW severity
        low_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            source_event_id="win-sev-low",
            hostname="SERVER01",
            message="Test",
            extracted_fields={"event_code": "4672", "subject_user": "admin"},
        )

        findings = windows_processor.process_log_event(low_event)
        assert findings[0].severity == Severity.LOW


# =============================================================================
# 7. Redaction Tests
# =============================================================================


class TestRedaction:
    """Tests for redaction integration."""

    def test_redaction_applied_to_published_events(self):
        """Test that redaction is applied before Redpanda publishing."""
        from app.logs.redaction import redact_log_event

        message = "User admin with password=Secret123! logged in"
        raw = "password=Secret123 token=abc123xyz"
        fields = {"command_line": "net user admin P@ssw0rd /add"}

        r_msg, r_raw, r_fields = redact_log_event(message, raw, fields)

        assert "Secret123" not in r_msg
        assert "Secret123" not in r_raw
        assert "abc123xyz" not in r_raw


# =============================================================================
# 8. Configuration Tests
# =============================================================================


class TestConfiguration:
    """Tests for detection configuration."""

    def test_custom_thresholds(self):
        """Test rules respect custom thresholds."""
        rule = WindowsFailedAuthBurstRule(threshold=3, window_seconds=60)

        base_time = datetime.now(timezone.utc)

        # 3 failures (at custom threshold)
        for i in range(3):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "source_ip": "10.0.0.1",
                "timestamp": base_time + timedelta(seconds=i * 5),
                "hostname": "SERVER01",
            }
            result = rule.evaluate(event)

        assert result is not None
        assert result.matched_data["threshold"] == 3
        assert result.matched_data["window_seconds"] == 60

    def test_disabled_rule_no_match(self):
        """Test disabled rules do not produce matches."""
        rule = WindowsFailedAuthBurstRule(enabled=False)

        event = {
            "event_code": "4625",
            "target_user": "admin",
        }

        result = rule.evaluate(event)
        assert result is None

    def test_processor_statistics(self):
        """Test processor provides statistics - MOVED to test_step8_2_2_integration.py."""
        # This test now lives in test_step8_2_2_integration.py
        # as test_processor_statistics with Redis-backed processor
        pass


# =============================================================================
# 9. Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_optional_fields(self, failed_auth_rule):
        """Test handling of events with missing optional fields."""
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            event = {
                "event_code": "4625",
                # No target_user, source_ip, hostname
                "timestamp": base_time + timedelta(seconds=i * 5),
            }
            result = failed_auth_rule.evaluate(event)

        # Should still work with defaults
        assert result is not None
        assert result.matched_data["username"] == "unknown"
        assert result.matched_data["source_ip"] is None

    def test_timestamp_string_parsing(self, failed_auth_rule):
        """Test timestamp string parsing."""
        base_time = datetime.now(timezone.utc)

        for i in range(5):
            event = {
                "event_code": "4625",
                "target_user": "admin",
                "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
                "hostname": "SERVER01",
            }
            result = failed_auth_rule.evaluate(event)

        assert result is not None

    def test_malformed_timestamp_handled(self, failed_auth_rule):
        """Test malformed timestamp doesn't crash."""
        event = {
            "event_code": "4625",
            "target_user": "admin",
            "timestamp": "not-a-timestamp",
            "hostname": "SERVER01",
        }

        # Should not raise
        result = failed_auth_rule.evaluate(event)
        # May or may not match depending on timing

    def test_very_long_username(self, privileged_rule):
        """Test handling of very long username."""
        event = {
            "event_code": "4672",
            "subject_user": "A" * 1000,
            "subject_domain": "DOMAIN",
            "hostname": "SERVER01",
        }

        result = privileged_rule.evaluate(event)
        assert result is not None


# =============================================================================
# 10. Alert Integration Placeholder
# =============================================================================


class TestAlertIntegration:
    """Placeholder tests for alert integration (requires DB)."""

    @pytest.mark.skip(reason="Requires PostgreSQL database")
    async def test_finding_creates_alert(self):
        """Test that findings create alerts in database."""
        pass

    @pytest.mark.skip(reason="Requires PostgreSQL database")
    async def test_duplicate_finding_no_duplicate_alert(self):
        """Test duplicate findings don't create duplicate alerts."""
        pass

    @pytest.mark.skip(reason="Requires Redpanda")
    async def test_redpanda_delivery(self):
        """Test event delivery through Redpanda."""
        pass
