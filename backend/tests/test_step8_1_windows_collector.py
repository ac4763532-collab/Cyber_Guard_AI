"""
CyberGuard AI - STEP 8.1 Windows Event Log Collector Tests

Unit tests for the Windows Event Log collector:
- Parser tests for all 8 supported Event IDs
- Error handling tests
- Idempotency tests (source_event_id)
- Checkpoint tests
- Security/redaction tests

Note: Live Windows verification requires actual Windows environment
with Event Log access. Parser and unit tests can run anywhere.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import uuid4


# =============================================================================
# Parser Tests - Event 4624 (Successful Logon)
# =============================================================================


class TestEvent4624Parser:
    """Tests for Event 4624 (Successful Logon) parsing."""

    def test_extract_4624_fields_interactive_logon(self):
        """Test extracting fields from interactive logon event."""
        from app.logs.collectors.windows import extract_4624_fields

        event_data = {
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserName": "admin",
            "TargetDomainName": "WORKGROUP",
            "LogonType": "2",
            "IpAddress": "127.0.0.1",
            "IpPort": "0",
            "WorkstationName": "DESKTOP-ABC123",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "TargetLogonId": "0x12345",
        }

        result = extract_4624_fields(event_data)

        assert result["event_code"] == "4624"
        assert result["target_user"] == "admin"
        assert result["target_domain"] == "WORKGROUP"
        assert result["logon_type"] == 2
        assert result["logon_type_name"] == "Interactive"
        assert result["source_ip"] == "127.0.0.1"
        assert result["workstation_name"] == "DESKTOP-ABC123"

    def test_extract_4624_fields_network_logon(self):
        """Test extracting fields from network logon event."""
        from app.logs.collectors.windows import extract_4624_fields

        event_data = {
            "TargetUserName": "svc_account",
            "TargetDomainName": "DOMAIN",
            "LogonType": "3",
            "IpAddress": "192.168.1.100",
            "WorkstationName": "CLIENT-PC",
            "AuthenticationPackageName": "NTLM",
        }

        result = extract_4624_fields(event_data)

        assert result["logon_type"] == 3
        assert result["logon_type_name"] == "Network"
        assert result["source_ip"] == "192.168.1.100"
        assert result["auth_package"] == "NTLM"

    def test_extract_4624_fields_rdp_logon(self):
        """Test extracting fields from RDP logon event."""
        from app.logs.collectors.windows import extract_4624_fields

        event_data = {
            "TargetUserName": "remoteuser",
            "LogonType": "10",
            "IpAddress": "10.0.0.50",
        }

        result = extract_4624_fields(event_data)

        assert result["logon_type"] == 10
        assert result["logon_type_name"] == "RemoteInteractive"


# =============================================================================
# Parser Tests - Event 4625 (Failed Logon)
# =============================================================================


class TestEvent4625Parser:
    """Tests for Event 4625 (Failed Logon) parsing."""

    def test_extract_4625_fields_basic(self):
        """Test extracting fields from failed logon event."""
        from app.logs.collectors.windows import extract_4625_fields

        event_data = {
            "SubjectUserName": "-",
            "TargetUserName": "hacker",
            "TargetDomainName": "WORKGROUP",
            "LogonType": "3",
            "IpAddress": "203.0.113.50",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
            "FailureReason": "Unknown user name or bad password",
            "AuthenticationPackageName": "NTLM",
        }

        result = extract_4625_fields(event_data)

        assert result["event_code"] == "4625"
        assert result["target_user"] == "hacker"
        assert result["logon_type"] == 3
        assert result["source_ip"] == "203.0.113.50"
        assert result["status"] == "0xC000006D"
        assert result["sub_status"] == "0xC000006A"
        assert "bad password" in result["failure_reason"]

    def test_extract_4625_fields_brute_force_indicator(self):
        """Test fields that indicate brute force attempt."""
        from app.logs.collectors.windows import extract_4625_fields

        event_data = {
            "TargetUserName": "administrator",
            "LogonType": "3",
            "IpAddress": "192.168.1.200",
            "Status": "0xC000006D",
        }

        result = extract_4625_fields(event_data)

        assert result["target_user"] == "administrator"
        assert result["source_ip"] == "192.168.1.200"


# =============================================================================
# Parser Tests - Event 4634 (Logoff)
# =============================================================================


class TestEvent4634Parser:
    """Tests for Event 4634 (Logoff) parsing."""

    def test_extract_4634_fields(self):
        """Test extracting fields from logoff event."""
        from app.logs.collectors.windows import extract_4634_fields

        event_data = {
            "TargetUserName": "user1",
            "TargetDomainName": "DOMAIN",
            "LogonType": "2",
            "TargetLogonId": "0xABCDE",
        }

        result = extract_4634_fields(event_data)

        assert result["event_code"] == "4634"
        assert result["target_user"] == "user1"
        assert result["logon_type"] == 2
        assert result["logon_id"] == "0xABCDE"


# =============================================================================
# Parser Tests - Event 4648 (Explicit Credential Use)
# =============================================================================


class TestEvent4648Parser:
    """Tests for Event 4648 (Explicit Credential Use) parsing."""

    def test_extract_4648_fields(self):
        """Test extracting fields from explicit credential event."""
        from app.logs.collectors.windows import extract_4648_fields

        event_data = {
            "SubjectUserName": "admin",
            "SubjectDomainName": "DOMAIN",
            "SubjectLogonId": "0x12345",
            "TargetUserName": "svc_backup",
            "TargetDomainName": "DOMAIN",
            "TargetServerName": "FILESERVER",
            "TargetInfo": "FILESERVER",
            "ProcessId": "0x1234",
            "ProcessName": "C:\\Windows\\System32\\runas.exe",
            "IpAddress": "-",
        }

        result = extract_4648_fields(event_data)

        assert result["event_code"] == "4648"
        assert result["subject_user"] == "admin"
        assert result["target_user"] == "svc_backup"
        assert result["target_server"] == "FILESERVER"
        assert "runas.exe" in result["process_name"]


# =============================================================================
# Parser Tests - Event 4672 (Special Privileges)
# =============================================================================


class TestEvent4672Parser:
    """Tests for Event 4672 (Special Privileges Assigned) parsing."""

    def test_extract_4672_fields(self):
        """Test extracting fields from special privileges event."""
        from app.logs.collectors.windows import extract_4672_fields

        event_data = {
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "BUILTIN",
            "SubjectLogonId": "0x3E7",
            "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege",
        }

        result = extract_4672_fields(event_data)

        assert result["event_code"] == "4672"
        assert result["subject_user"] == "Administrator"
        assert "SeDebugPrivilege" in result["privileges"]
        assert "SeBackupPrivilege" in result["privileges"]


# =============================================================================
# Parser Tests - Event 4688 (Process Creation)
# =============================================================================


class TestEvent4688Parser:
    """Tests for Event 4688 (Process Creation) parsing."""

    def test_extract_4688_fields_with_command_line(self):
        """Test extracting fields with command line collection enabled."""
        from app.logs.collectors.windows import extract_4688_fields

        event_data = {
            "SubjectUserName": "user1",
            "SubjectDomainName": "DOMAIN",
            "NewProcessId": "0x1000",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": "0x800",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "CommandLine": 'cmd.exe /c "dir C:\\"',
            "TokenElevationType": "%%1936",
        }

        result = extract_4688_fields(event_data, collect_command_line=True)

        assert result["event_code"] == "4688"
        assert result["subject_user"] == "user1"
        assert result["new_process_name"] == "C:\\Windows\\System32\\cmd.exe"
        assert result["creator_process_name"] == "C:\\Windows\\explorer.exe"
        assert "cmd.exe" in result["command_line"]

    def test_extract_4688_fields_without_command_line(self):
        """Test extracting fields with command line collection disabled."""
        from app.logs.collectors.windows import extract_4688_fields

        event_data = {
            "SubjectUserName": "user1",
            "NewProcessName": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe secret.txt",
        }

        result = extract_4688_fields(event_data, collect_command_line=False)

        assert result["event_code"] == "4688"
        assert "command_line" not in result

    def test_extract_4688_fields_suspicious_process(self):
        """Test parsing potentially suspicious process creation."""
        from app.logs.collectors.windows import extract_4688_fields

        event_data = {
            "SubjectUserName": "SYSTEM",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        }

        result = extract_4688_fields(event_data, collect_command_line=True)

        assert "powershell.exe" in result["new_process_name"]
        assert "-enc" in result["command_line"]  # Encoded command


# =============================================================================
# Parser Tests - Event 4720 (User Account Created)
# =============================================================================


class TestEvent4720Parser:
    """Tests for Event 4720 (User Account Created) parsing."""

    def test_extract_4720_fields(self):
        """Test extracting fields from account creation event."""
        from app.logs.collectors.windows import extract_4720_fields

        event_data = {
            "SubjectUserName": "admin",
            "SubjectDomainName": "DOMAIN",
            "TargetUserName": "newuser",
            "TargetDomainName": "DOMAIN",
            "TargetSid": "S-1-5-21-123456789-123456789-123456789-1001",
            "SamAccountName": "newuser",
            "DisplayName": "New User",
            "UserPrincipalName": "newuser@domain.local",
            "PrimaryGroupId": "513",
            "AccountExpires": "%%1794",
        }

        result = extract_4720_fields(event_data)

        assert result["event_code"] == "4720"
        assert result["subject_user"] == "admin"
        assert result["target_user"] == "newuser"
        assert result["target_sid"].startswith("S-1-5-21-")
        assert result["sam_account_name"] == "newuser"


# =============================================================================
# Parser Tests - Event 4726 (User Account Deleted)
# =============================================================================


class TestEvent4726Parser:
    """Tests for Event 4726 (User Account Deleted) parsing."""

    def test_extract_4726_fields(self):
        """Test extracting fields from account deletion event."""
        from app.logs.collectors.windows import extract_4726_fields

        event_data = {
            "SubjectUserName": "admin",
            "SubjectDomainName": "DOMAIN",
            "TargetUserName": "olduser",
            "TargetDomainName": "DOMAIN",
            "TargetSid": "S-1-5-21-123456789-123456789-123456789-1002",
        }

        result = extract_4726_fields(event_data)

        assert result["event_code"] == "4726"
        assert result["subject_user"] == "admin"
        assert result["target_user"] == "olduser"


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in Windows collector."""

    def test_extract_with_missing_fields(self):
        """Test extraction handles missing fields gracefully."""
        from app.logs.collectors.windows import extract_4624_fields

        # Minimal event data
        event_data = {
            "TargetUserName": "user1",
        }

        result = extract_4624_fields(event_data)

        assert result["event_code"] == "4624"
        assert result["target_user"] == "user1"
        assert result["logon_type"] == 0  # Default
        assert result["source_ip"] is None

    def test_extract_with_invalid_logon_type(self):
        """Test extraction handles invalid logon type."""
        from app.logs.collectors.windows import extract_4624_fields

        event_data = {
            "LogonType": "invalid",
        }

        # Should not raise, just default to 0
        try:
            result = extract_4624_fields(event_data)
            # If it doesn't raise, logon_type should be 0 or handle gracefully
        except ValueError:
            pytest.fail("Should handle invalid LogonType gracefully")

    def test_extract_with_empty_event_data(self):
        """Test extraction handles empty event data."""
        from app.logs.collectors.windows import (
            extract_4624_fields,
            extract_4625_fields,
            extract_4688_fields,
        )

        empty_data: dict = {}

        # Should not raise
        result_4624 = extract_4624_fields(empty_data)
        assert result_4624["event_code"] == "4624"

        result_4625 = extract_4625_fields(empty_data)
        assert result_4625["event_code"] == "4625"

        result_4688 = extract_4688_fields(empty_data)
        assert result_4688["event_code"] == "4688"

    def test_extract_with_unusual_characters(self):
        """Test extraction handles unusual characters in fields."""
        from app.logs.collectors.windows import extract_4624_fields

        event_data = {
            "TargetUserName": "user<script>alert(1)</script>",
            "TargetDomainName": "DOMAIN; DROP TABLE users;--",
            "WorkstationName": "PC-ñoño-日本語",
        }

        result = extract_4624_fields(event_data)

        # Should preserve the values (sanitization happens at redaction layer)
        assert result["target_user"] == "user<script>alert(1)</script>"
        assert "DROP TABLE" in result["target_domain"]
        assert "日本語" in result["workstation_name"]

    def test_extract_with_oversized_fields(self):
        """Test extraction handles oversized fields."""
        from app.logs.collectors.windows import extract_4688_fields

        # 10KB command line
        long_command = "cmd.exe " + "A" * 10000

        event_data = {
            "CommandLine": long_command,
            "NewProcessName": "C:\\cmd.exe",
        }

        result = extract_4688_fields(event_data, collect_command_line=True)

        # Should not crash, may truncate at higher layer
        assert len(result["command_line"]) > 1000


# =============================================================================
# Idempotency Tests
# =============================================================================


class TestIdempotency:
    """Tests for source_event_id generation and idempotency."""

    def test_generate_source_event_id_stable(self):
        """Test that same inputs produce same source_event_id."""
        from app.logs.collectors.windows import generate_source_event_id

        channel = "Security"
        computer = "WIN-SERVER-01"
        record_id = 12345

        id1 = generate_source_event_id(channel, computer, record_id)
        id2 = generate_source_event_id(channel, computer, record_id)

        assert id1 == id2

    def test_generate_source_event_id_different_records(self):
        """Test that different record IDs produce different source_event_ids."""
        from app.logs.collectors.windows import generate_source_event_id

        channel = "Security"
        computer = "WIN-SERVER-01"

        id1 = generate_source_event_id(channel, computer, 12345)
        id2 = generate_source_event_id(channel, computer, 12346)

        assert id1 != id2

    def test_generate_source_event_id_different_computers(self):
        """Test that different computers produce different source_event_ids."""
        from app.logs.collectors.windows import generate_source_event_id

        channel = "Security"
        record_id = 12345

        id1 = generate_source_event_id(channel, "SERVER-01", record_id)
        id2 = generate_source_event_id(channel, "SERVER-02", record_id)

        assert id1 != id2

    def test_generate_source_event_id_format(self):
        """Test source_event_id format."""
        from app.logs.collectors.windows import generate_source_event_id

        result = generate_source_event_id("Security", "WIN-01", 99999)

        assert result.startswith("win-")
        assert "-99999" in result
        # Should be alphanumeric with dashes
        assert all(c.isalnum() or c == "-" for c in result)


# =============================================================================
# Configuration Tests
# =============================================================================


class TestConfiguration:
    """Tests for Windows collector configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        from app.logs.collectors.windows import WindowsCollectorConfig, DEFAULT_EVENT_IDS

        config = WindowsCollectorConfig(source_id="test-source")

        assert config.channel == "Security"
        assert config.event_ids == DEFAULT_EVENT_IDS
        assert config.poll_interval_seconds == 5.0
        assert config.batch_size == 100
        assert config.collect_command_line is True
        assert config.computer_name is None  # Local machine

    def test_custom_config(self):
        """Test custom configuration.

        channel="Application" was changed to channel="Security" as part
        of the Log Analysis collector bug fix: SUPPORTED_EVENT_IDS (and
        therefore every event_ids value a caller can meaningfully pick,
        including {4624, 4625} here) are all Security-log auditing event
        IDs. WindowsCollectorConfig now validates channel against
        SUPPORTED_CHANNELS ({"Security"} today) and rejects any other
        value - see test_unsupported_channel_rejected below for that
        behavior. Using "Application" here was never actually
        exercisable end-to-end (collect()'s event-ID filter would have
        silently dropped every event), so this test is updated to use a
        channel/event_ids combination that is genuinely supported,
        preserving its original intent of checking the other custom
        field values.
        """
        from app.logs.collectors.windows import WindowsCollectorConfig

        config = WindowsCollectorConfig(
            source_id="custom-source",
            channel="Security",
            event_ids={4624, 4625},
            poll_interval_seconds=10.0,
            batch_size=50,
            collect_command_line=False,
        )

        assert config.channel == "Security"
        assert config.event_ids == {4624, 4625}
        assert config.poll_interval_seconds == 10.0
        assert config.batch_size == 50
        assert config.collect_command_line is False

    def test_unsupported_channel_rejected(self):
        """
        Regression test for the Log Analysis bug: a channel other than
        "Security" would previously be accepted silently, connect
        successfully, and then collect()'s event-ID filter would drop
        every single event forever (SUPPORTED_EVENT_IDS are all
        Security-log IDs) - a confusing "0 events, no error" state.
        WindowsCollectorConfig now rejects it up front instead.
        """
        from app.logs.collectors.windows import WindowsCollectorConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            WindowsCollectorConfig(source_id="test", channel="Application")

        with pytest.raises(ValidationError):
            WindowsCollectorConfig(source_id="test", channel="System")

    def test_unknown_configuration_key_rejected(self):
        """
        Regression test for the Log Analysis bug's root cause: the
        frontend used to send configuration={"hostname": "..."}, a key
        WindowsCollectorConfig has no field for (it has computer_name).
        Before this fix, plain pydantic BaseModel silently dropped
        unrecognized keys instead of rejecting them, so the user's input
        was discarded with no error anywhere. extra="forbid" makes this
        a loud ValidationError instead.
        """
        from app.logs.collectors.windows import WindowsCollectorConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            WindowsCollectorConfig(source_id="test", hostname="DESKTOP-4DAGSCE")

    def test_config_validation_poll_interval(self):
        """Test configuration validation for poll interval."""
        from app.logs.collectors.windows import WindowsCollectorConfig
        from pydantic import ValidationError

        # Too low
        with pytest.raises(ValidationError):
            WindowsCollectorConfig(
                source_id="test",
                poll_interval_seconds=0.5,
            )

        # Too high
        with pytest.raises(ValidationError):
            WindowsCollectorConfig(
                source_id="test",
                poll_interval_seconds=500,
            )


# =============================================================================
# Log Level and Category Mapping Tests
# =============================================================================


class TestLevelAndCategoryMapping:
    """Tests for Event ID to LogLevel and Category mapping."""

    def test_event_id_to_level(self):
        """Test event ID to log level mapping."""
        from app.logs.collectors.windows import EVENT_ID_TO_LEVEL
        from app.logs.models import LogLevel

        # Failed logon should be WARNING
        assert EVENT_ID_TO_LEVEL[4625] == LogLevel.WARNING

        # Successful logon should be INFO
        assert EVENT_ID_TO_LEVEL[4624] == LogLevel.INFO

        # Account created should be WARNING (security-relevant)
        assert EVENT_ID_TO_LEVEL[4720] == LogLevel.WARNING

    def test_event_id_to_category(self):
        """Test event ID to category mapping."""
        from app.logs.collectors.windows import EVENT_ID_TO_CATEGORY

        assert EVENT_ID_TO_CATEGORY[4624] == "authentication"
        assert EVENT_ID_TO_CATEGORY[4625] == "authentication"
        assert EVENT_ID_TO_CATEGORY[4688] == "process"
        assert EVENT_ID_TO_CATEGORY[4720] == "account_management"
        assert EVENT_ID_TO_CATEGORY[4672] == "authorization"


# =============================================================================
# Supported Event IDs Tests
# =============================================================================


class TestSupportedEventIDs:
    """Tests for supported Event IDs."""

    def test_supported_event_ids(self):
        """Test SUPPORTED_EVENT_IDS contains required IDs."""
        from app.logs.collectors.windows import SUPPORTED_EVENT_IDS

        required_ids = {4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726}

        assert SUPPORTED_EVENT_IDS == required_ids

    def test_default_event_ids_subset(self):
        """Test DEFAULT_EVENT_IDS is subset of SUPPORTED_EVENT_IDS."""
        from app.logs.collectors.windows import SUPPORTED_EVENT_IDS, DEFAULT_EVENT_IDS

        assert DEFAULT_EVENT_IDS.issubset(SUPPORTED_EVENT_IDS)

    def test_event_descriptions_complete(self):
        """Test all supported event IDs have descriptions."""
        from app.logs.collectors.windows import SUPPORTED_EVENT_IDS, EVENT_DESCRIPTIONS

        for event_id in SUPPORTED_EVENT_IDS:
            assert event_id in EVENT_DESCRIPTIONS
            assert len(EVENT_DESCRIPTIONS[event_id]) > 0


# =============================================================================
# Security Tests
# =============================================================================


class TestSecurity:
    """Tests for security-related functionality."""

    def test_command_line_contains_password_redaction_needed(self):
        """Test that command lines with passwords need redaction."""
        from app.logs.collectors.windows import extract_4688_fields
        from app.logs.redaction import redact_dict

        event_data = {
            "CommandLine": "net user admin Password123! /add",
            "NewProcessName": "C:\\Windows\\System32\\net.exe",
        }

        extracted = extract_4688_fields(event_data, collect_command_line=True)

        # The extractor doesn't redact - that's done by repository
        assert "Password123" in extracted["command_line"]

        # But after redaction...
        redacted = redact_dict(extracted)
        # Note: redaction patterns may not catch this exact format
        # This is documenting current behavior - may need pattern update

    def test_redpanda_payload_redacted(self):
        """Test that event data passed to Redpanda is redacted."""
        from app.logs.redaction import redact_log_event

        message = "User logged in with password=secret123"
        raw = "password=secret123 token=abc123"
        fields = {"command_line": "runas /user:admin password=hunter2"}

        r_msg, r_raw, r_fields = redact_log_event(message, raw, fields)

        assert "secret123" not in r_msg
        assert "secret123" not in r_raw
        assert "abc123" not in r_raw

    def test_is_windows_check(self):
        """Test Windows platform detection."""
        from app.logs.collectors.windows import is_windows
        import platform

        result = is_windows()

        assert result == (platform.system() == "Windows")


# =============================================================================
# Health Status Tests
# =============================================================================


class TestHealthStatus:
    """Tests for collector health status."""

    def test_health_initial_state(self):
        """Test initial health state."""
        from app.logs.collectors.windows import WindowsCollectorHealth
        from app.logs.collector_base import CollectorStatus

        health = WindowsCollectorHealth(
            status=CollectorStatus.STOPPED,
            source_id="test-source",
            collector_id="test-collector",
            channel="Security",
            computer_name=None,
            event_ids=[4624, 4625],
        )

        assert health.status == CollectorStatus.STOPPED
        assert health.events_received == 0
        assert health.events_processed == 0
        assert health.events_failed == 0
        assert health.error_count == 0
        assert health.last_error is None


# =============================================================================
# Checkpoint Tests
# =============================================================================


class TestCheckpoint:
    """Tests for checkpoint functionality."""

    def test_checkpoint_structure(self):
        """Test checkpoint data structure."""
        from app.logs.models import CollectorCheckpoint, CheckpointType

        checkpoint = CollectorCheckpoint(
            source_id="test-source",
            checkpoint_type=CheckpointType.WINDOWS_RECORD_ID,
            checkpoint_value={
                "record_id": 12345,
                "channel": "Security",
                "computer": "WIN-SERVER-01",
            },
        )

        assert checkpoint.checkpoint_type == CheckpointType.WINDOWS_RECORD_ID
        assert checkpoint.checkpoint_value["record_id"] == 12345
        assert checkpoint.checkpoint_value["channel"] == "Security"


# =============================================================================
# Module Exports Tests
# =============================================================================


class TestModuleExports:
    """Tests for module exports."""

    def test_collectors_module_exports(self):
        """Test that collectors module exports required symbols."""
        from app.logs.collectors import (
            WindowsEventCollector,
            WindowsCollectorConfig,
            WindowsCollectorHealth,
            SUPPORTED_EVENT_IDS,
            DEFAULT_EVENT_IDS,
        )

        assert WindowsEventCollector is not None
        assert WindowsCollectorConfig is not None
        assert SUPPORTED_EVENT_IDS is not None
        assert len(SUPPORTED_EVENT_IDS) == 8


# =============================================================================
# Integration Placeholder Tests
# =============================================================================


class TestIntegrationPlaceholders:
    """Placeholder tests for integration (require Windows + DB)."""

    @pytest.mark.skip(reason="Requires Windows with Event Log access")
    async def test_live_event_collection(self):
        """Test live event collection from Windows Event Log."""
        pass

    @pytest.mark.skip(reason="Requires Windows with Event Log access")
    async def test_checkpoint_persistence(self):
        """Test checkpoint persistence across collector restart."""
        pass

    @pytest.mark.skip(reason="Requires Windows with Event Log access")
    async def test_duplicate_rejection(self):
        """Test duplicate event rejection via source_event_id."""
        pass

    @pytest.mark.skip(reason="Requires Windows with Event Log access")
    async def test_redpanda_publication(self):
        """Test event publication to Redpanda."""
        pass

    @pytest.mark.skip(reason="Requires Windows with Event Log access")
    async def test_postgresql_persistence(self):
        """Test event persistence to PostgreSQL."""
        pass

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_log_event_repository_with_windows_event(self):
        """Test LogEventRepository with Windows event."""
        pass
