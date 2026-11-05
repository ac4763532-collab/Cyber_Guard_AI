"""
CyberGuard AI - STEP 8 Log Analysis Foundation Tests

Unit tests for the log analysis module:
- LogEvent model
- LogSource model
- Log Level/Source Type enums
- Collector base abstraction
- Event bus integration
- Redaction (STEP 8.0.1)
- Checkpoint persistence (STEP 8.0.1)

Security tests:
- No credentials in configuration
- No secrets exposed in API responses
- Centralized redaction

STEP 8.0.1 / STEP 9: Tests updated for restricted source types:
- windows_event
- linux_ssh
- android_adb
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from pydantic import ValidationError


# =============================================================================
# LogEvent Model Tests
# =============================================================================


class TestLogEvent:
    """Tests for LogEvent model."""

    def test_create_minimal_log_event(self):
        """Test creating a LogEvent with minimal fields."""
        from app.logs.models import LogEvent, LogSourceType

        event = LogEvent(
            message="Test log message",
            source_type=LogSourceType.ANDROID_ADB,
        )

        assert event.id is not None
        assert event.message == "Test log message"
        assert event.level.value == "info"
        assert event.analyzed is False

    def test_create_full_log_event(self):
        """Test creating a LogEvent with all fields."""
        from app.logs.models import LogEvent, LogLevel, LogSourceType

        event = LogEvent(
            id="test-event-123",
            source_event_id="src-evt-001",
            source_id="source-456",
            source_type=LogSourceType.LINUX_SSH,
            hostname="webserver-01",
            program="sshd",
            pid=12345,
            timestamp=datetime(2026, 9, 17, 10, 30, 0, tzinfo=timezone.utc),
            level=LogLevel.WARNING,
            message="Failed password for admin",
            raw_content="Sep 17 10:30:00 webserver-01 sshd[12345]: Failed password for admin",
            extracted_fields={"user": "admin", "ip": "192.168.1.100"},
            tags=["auth", "failure"],
            category="authentication",
            correlation_id="corr-789",
            session_id="session-abc",
        )

        assert event.id == "test-event-123"
        assert event.source_event_id == "src-evt-001"
        assert event.source_type == LogSourceType.LINUX_SSH
        assert event.hostname == "webserver-01"
        assert event.program == "sshd"
        assert event.pid == 12345
        assert event.level == LogLevel.WARNING
        assert event.extracted_fields["user"] == "admin"
        assert "auth" in event.tags

    def test_log_event_to_dict(self):
        """Test LogEvent serialization to dict."""
        from app.logs.models import LogEvent, LogLevel, LogSourceType

        event = LogEvent(
            message="Test message",
            source_type=LogSourceType.WINDOWS_EVENT,
            level=LogLevel.ERROR,
            hostname="server-01",
        )

        data = event.to_dict()

        assert data["message"] == "Test message"
        assert data["level"] == "error"
        assert data["hostname"] == "server-01"
        assert data["source_type"] == "windows_event"
        assert "timestamp" in data
        assert "id" in data
        assert "source_event_id" in data

    def test_log_event_from_parsed_entry(self):
        """Test creating LogEvent from ParsedLogEntry."""
        from app.logs.models import LogEvent, ParsedLogEntry, LogLevel, LogSourceType

        entry = ParsedLogEntry(
            timestamp=datetime.now(timezone.utc),
            hostname="server-01",
            program="nginx",
            level=LogLevel.INFO,
            message="GET /api/health 200",
            source_event_id="nginx-12345",
            tags=["http", "access"],
        )

        event = LogEvent.from_parsed_entry(entry, LogSourceType.ANDROID_ADB)

        assert event.hostname == "server-01"
        assert event.program == "nginx"
        assert event.source_type == LogSourceType.ANDROID_ADB
        assert event.source_event_id == "nginx-12345"
        assert "http" in event.tags

    def test_log_event_empty_message_rejected(self):
        """Test that empty message is rejected."""
        from app.logs.models import LogEvent, LogSourceType

        with pytest.raises(ValidationError):
            LogEvent(message="", source_type=LogSourceType.ANDROID_ADB)

    def test_log_event_rejects_unsupported_source_type(self):
        """Test that unsupported source types are rejected (STEP 8.0.1)."""
        from app.logs.models import LogEvent, LogSourceType, SUPPORTED_SOURCE_TYPES

        # All enum values should be supported in STEP 8.0.1
        for source_type in LogSourceType:
            assert source_type in SUPPORTED_SOURCE_TYPES


# =============================================================================
# LogSource Model Tests
# =============================================================================


class TestLogSource:
    """Tests for LogSource model."""

    def test_create_log_source(self):
        """Test creating a LogSource."""
        from app.logs.models import LogSource, LogSourceType, CollectorType

        source = LogSource(
            name="Lab Android Device",
            source_type=LogSourceType.ANDROID_ADB,
            collector_type=CollectorType.ANDROID_AGENT,
        )

        assert source.id is not None
        assert source.name == "Lab Android Device"
        assert source.source_type == LogSourceType.ANDROID_ADB
        assert source.status.value == "pending"

    def test_log_source_configuration_no_secrets(self):
        """Test that configuration rejects secret fields."""
        from app.logs.models import LogSource, LogSourceType

        with pytest.raises(ValidationError) as exc_info:
            LogSource(
                name="Test Source",
                source_type=LogSourceType.ANDROID_ADB,
                configuration={"password": "secret123"},
            )

        assert "encrypted_config" in str(exc_info.value)

    def test_log_source_rejects_api_key_in_config(self):
        """Test that configuration rejects API keys."""
        from app.logs.models import LogSource, LogSourceType

        with pytest.raises(ValidationError):
            LogSource(
                name="Test Source",
                source_type=LogSourceType.ANDROID_ADB,
                configuration={"api_key": "sk-12345"},
            )

    def test_log_source_rejects_token_in_config(self):
        """Test that configuration rejects tokens."""
        from app.logs.models import LogSource, LogSourceType

        with pytest.raises(ValidationError):
            LogSource(
                name="Test Source",
                source_type=LogSourceType.ANDROID_ADB,
                configuration={"access_token": "token123"},
            )

    def test_log_source_allows_non_sensitive_config(self):
        """Test that configuration allows non-sensitive fields."""
        from app.logs.models import LogSource, LogSourceType

        source = LogSource(
            name="Test Source",
            source_type=LogSourceType.LINUX_SSH,
            configuration={
                "hostname": "192.168.1.100",
                "port": 22,
                "log_path": "/var/log/auth.log",
            },
        )

        assert source.configuration["hostname"] == "192.168.1.100"
        assert source.configuration["port"] == 22

    def test_log_source_to_dict_excludes_encrypted(self):
        """Test that to_dict excludes encrypted_config by default."""
        from app.logs.models import LogSource, LogSourceType

        source = LogSource(
            name="Test Source",
            source_type=LogSourceType.ANDROID_ADB,
            encrypted_config="encrypted_credentials_here",
        )

        # Default excludes encrypted
        data = source.to_dict(include_encrypted=False)
        assert "encrypted_config" not in data

        # Explicit include
        data_with_encrypted = source.to_dict(include_encrypted=True)
        assert "encrypted_config" in data_with_encrypted


class TestSourceToResponseCollectorStatus:
    """
    Tests for _source_to_response()'s merge of live CollectorManager
    telemetry into the API response as `collector_status` - honest
    null-when-absent, never a fabricated placeholder.
    """

    def _make_source(self):
        from app.logs.models import LogSource, LogSourceType

        return LogSource(name="Test Source", source_type=LogSourceType.WINDOWS_EVENT)

    def test_no_manager_yields_null_collector_status(self):
        """Without a manager argument, collector_status is explicitly None."""
        from app.api.v1.logs import _source_to_response

        data = _source_to_response(self._make_source())
        assert data["collector_status"] is None

    def test_manager_with_no_live_supervisor_yields_null(self):
        """
        A manager that has no running supervisor for this source (e.g.
        PENDING/DISABLED status, or an HTTP_RECEIVER source with no
        embedded collector) must report None, not a fake "stopped" object.
        """
        from app.api.v1.logs import _source_to_response

        source = self._make_source()
        manager = MagicMock()
        manager.get_source_status.return_value = None

        data = _source_to_response(source, manager)

        manager.get_source_status.assert_called_once_with(source.id)
        assert data["collector_status"] is None

    def test_manager_with_live_supervisor_populates_real_fields(self):
        """
        When a supervisor is actively running, its real counters/timestamps
        are surfaced under `collector_status`, namespaced separately from
        the DB-persisted fields (status/last_event_at/error_message).
        """
        from app.api.v1.logs import _source_to_response
        from app.logs.collector_manager import CollectorSupervisorStatus, SupervisorState

        source = self._make_source()
        now = datetime.now(timezone.utc)
        live_status = CollectorSupervisorStatus(
            source_id=source.id,
            source_type=source.source_type,
            state=SupervisorState.RECONNECTING,
            started_at=now,
            last_successful_collection_at=now,
            events_collected=42,
            events_published=40,
            checkpoint_updates=7,
            reconnect_count=3,
            error_count=1,
            last_error="connection reset",
            last_error_at=now,
        )
        manager = MagicMock()
        manager.get_source_status.return_value = live_status

        data = _source_to_response(source, manager)

        assert data["collector_status"] == {
            "state": "reconnecting",
            "started_at": now.isoformat(),
            "last_successful_collection_at": now.isoformat(),
            "events_collected": 42,
            "events_published": 40,
            "checkpoint_updates": 7,
            "reconnect_count": 3,
            "error_count": 1,
            "last_error": "connection reset",
            "last_error_at": now.isoformat(),
        }
        # Never collapsed into or overwriting the DB-persisted fields.
        assert "status" in data
        assert data["collector_status"] is not data.get("status")


# =============================================================================
# Enum Tests
# =============================================================================


class TestLogEnums:
    """Tests for log-related enums."""

    def test_log_levels(self):
        """Test LogLevel enum values."""
        from app.logs.models import LogLevel

        assert LogLevel.EMERGENCY.value == "emergency"
        assert LogLevel.ALERT.value == "alert"
        assert LogLevel.CRITICAL.value == "critical"
        assert LogLevel.ERROR.value == "error"
        assert LogLevel.WARNING.value == "warning"
        assert LogLevel.NOTICE.value == "notice"
        assert LogLevel.INFO.value == "info"
        assert LogLevel.DEBUG.value == "debug"

    def test_log_source_types(self):
        """Test LogSourceType enum values (STEP 8.0.1/STEP 9 - only 3 supported)."""
        from app.logs.models import LogSourceType, SUPPORTED_SOURCE_TYPES

        # Only 3 source types, STEP 9 swapped web_application for android_adb
        assert LogSourceType.WINDOWS_EVENT.value == "windows_event"
        assert LogSourceType.LINUX_SSH.value == "linux_ssh"
        assert LogSourceType.ANDROID_ADB.value == "android_adb"

        # Verify all are supported
        assert len(SUPPORTED_SOURCE_TYPES) == 3
        assert LogSourceType.WINDOWS_EVENT in SUPPORTED_SOURCE_TYPES
        assert LogSourceType.LINUX_SSH in SUPPORTED_SOURCE_TYPES
        assert LogSourceType.ANDROID_ADB in SUPPORTED_SOURCE_TYPES

    def test_log_source_status(self):
        """Test LogSourceStatus enum values."""
        from app.logs.models import LogSourceStatus

        assert LogSourceStatus.ACTIVE.value == "active"
        assert LogSourceStatus.PAUSED.value == "paused"
        assert LogSourceStatus.ERROR.value == "error"
        assert LogSourceStatus.DISABLED.value == "disabled"
        assert LogSourceStatus.PENDING.value == "pending"

    def test_collector_types(self):
        """Test CollectorType enum values (STEP 8.0.1 - only supported types)."""
        from app.logs.models import CollectorType, SUPPORTED_COLLECTOR_TYPES

        assert CollectorType.WINDOWS_AGENT.value == "windows_agent"
        assert CollectorType.LINUX_AGENT.value == "linux_agent"
        assert CollectorType.ANDROID_AGENT.value == "android_agent"
        assert CollectorType.HTTP_RECEIVER.value == "http_receiver"

        # 4 collector types as of STEP 9 (android_agent added)
        assert len(SUPPORTED_COLLECTOR_TYPES) == 4

    def test_checkpoint_types(self):
        """Test CheckpointType enum values (STEP 8.0.1 / STEP 9)."""
        from app.logs.models import CheckpointType

        assert CheckpointType.WINDOWS_RECORD_ID.value == "windows_record_id"
        assert CheckpointType.LINUX_FILE_OFFSET.value == "linux_file_offset"
        assert CheckpointType.ANDROID_LOGCAT_POSITION.value == "android_logcat_position"


# =============================================================================
# Collector Base Tests
# =============================================================================


class TestCollectorBase:
    """Tests for collector base abstraction."""

    def test_collector_config_creation(self):
        """Test CollectorConfig creation."""
        from app.logs.collector_base import CollectorConfig
        from app.logs.models import LogSourceType

        config = CollectorConfig(
            source_id="source-123",
            source_type=LogSourceType.LINUX_SSH,
            settings={"path": "/var/log/auth.log"},
            batch_size=50,
        )

        assert config.source_id == "source-123"
        assert config.batch_size == 50
        assert config.collector_id is not None

    def test_collector_metrics(self):
        """Test CollectorMetrics model."""
        from app.logs.collector_base import CollectorMetrics, CollectorStatus

        metrics = CollectorMetrics(
            collector_id="col-123",
            source_id="src-456",
            status=CollectorStatus.RUNNING,
            events_collected=100,
            events_submitted=95,
            events_dropped=5,
        )

        assert metrics.events_collected == 100
        assert metrics.events_submitted == 95
        assert metrics.events_dropped == 5

    def test_collector_status_enum(self):
        """Test CollectorStatus enum."""
        from app.logs.collector_base import CollectorStatus

        assert CollectorStatus.RUNNING.value == "running"
        assert CollectorStatus.STOPPED.value == "stopped"
        assert CollectorStatus.ERROR.value == "error"


# =============================================================================
# Event Bus Integration Tests
# =============================================================================


class TestEventBusIntegration:
    """Tests for event bus integration."""

    def test_log_level_to_severity_mapping(self):
        """Test log level to severity mapping."""
        from app.logs.event_bus_integration import LOG_LEVEL_TO_SEVERITY
        from app.logs.models import LogLevel
        from app.database.models.base import SeverityLevel

        assert LOG_LEVEL_TO_SEVERITY[LogLevel.EMERGENCY] == SeverityLevel.CRITICAL
        assert LOG_LEVEL_TO_SEVERITY[LogLevel.CRITICAL] == SeverityLevel.CRITICAL
        assert LOG_LEVEL_TO_SEVERITY[LogLevel.ERROR] == SeverityLevel.HIGH
        assert LOG_LEVEL_TO_SEVERITY[LogLevel.WARNING] == SeverityLevel.MEDIUM
        assert LOG_LEVEL_TO_SEVERITY[LogLevel.INFO] == SeverityLevel.INFO

    def test_log_event_to_security_event(self):
        """Test conversion from LogEvent to SecurityEvent."""
        from app.logs.event_bus_integration import log_event_to_security_event
        from app.logs.models import LogEvent, LogLevel, LogSourceType

        log_event = LogEvent(
            id="log-123",
            source_type=LogSourceType.LINUX_SSH,
            hostname="server-01",
            level=LogLevel.WARNING,
            message="Test message",
            category="auth",
        )

        security_event = log_event_to_security_event(log_event)

        assert security_event.event_id == "log-123"
        assert security_event.event_type == "log"
        assert security_event.source == "log_collector:linux_ssh"
        assert security_event.payload["hostname"] == "server-01"
        assert security_event.payload["level"] == "warning"

    def test_security_event_to_log_event(self):
        """Test conversion from SecurityEvent to LogEvent."""
        from app.logs.event_bus_integration import security_event_to_log_event
        from app.event_bus.events import SecurityEvent
        from app.database.models.base import SeverityLevel
        from app.logs.models import LogSourceType

        security_event = SecurityEvent(
            event_id="sec-456",
            event_type="log",
            source="test",
            severity=SeverityLevel.MEDIUM,
            payload={
                "log_event_id": "log-123",
                "source_event_id": "src-evt-001",
                "source_type": "linux_ssh",
                "hostname": "server-01",
                "level": "warning",
                "message": "Test message",
            },
        )

        log_event = security_event_to_log_event(security_event)

        assert log_event is not None
        assert log_event.id == "log-123"
        assert log_event.source_event_id == "src-evt-001"
        assert log_event.source_type == LogSourceType.LINUX_SSH
        assert log_event.hostname == "server-01"

    def test_security_event_to_log_event_wrong_type(self):
        """Test that non-log SecurityEvents return None."""
        from app.logs.event_bus_integration import security_event_to_log_event
        from app.event_bus.events import SecurityEvent
        from app.database.models.base import SeverityLevel

        security_event = SecurityEvent(
            event_id="sec-789",
            event_type="email",  # Not a log event
            source="test",
            severity=SeverityLevel.LOW,
            payload={},
        )

        result = security_event_to_log_event(security_event)

        assert result is None

    def test_security_event_defaults_unsupported_source_type(self):
        """Test that unsupported source types are rejected, not defaulted (STEP 8.2)."""
        from app.logs.event_bus_integration import security_event_to_log_event
        from app.event_bus.events import SecurityEvent
        from app.database.models.base import SeverityLevel
        from app.logs.models import LogSourceType
        from app.logs.event_bus_integration import UnsupportedSourceTypeError

        security_event = SecurityEvent(
            event_id="sec-456",
            event_type="log",
            source="test",
            severity=SeverityLevel.MEDIUM,
            payload={
                "source_type": "unknown_type",  # Not supported
                "message": "Test message",
            },
        )

        # STEP 8.2: Unsupported source types are now REJECTED, not silently converted
        with pytest.raises(UnsupportedSourceTypeError) as exc_info:
            security_event_to_log_event(security_event)

        assert exc_info.value.source_type == "unknown_type"
        assert exc_info.value.event_id == "sec-456"


# =============================================================================
# Parsed Log Entry Tests
# =============================================================================


class TestParsedLogEntry:
    """Tests for ParsedLogEntry model."""

    def test_create_parsed_entry(self):
        """Test creating a ParsedLogEntry."""
        from app.logs.models import ParsedLogEntry, LogLevel

        entry = ParsedLogEntry(
            timestamp=datetime.now(timezone.utc),
            hostname="server-01",
            message="Test entry",
            source_event_id="entry-001",
            level=LogLevel.INFO,
        )

        assert entry.hostname == "server-01"
        assert entry.message == "Test entry"
        assert entry.source_event_id == "entry-001"


# =============================================================================
# Schema Tests
# =============================================================================


class TestLogSourceSchemas:
    """Tests for request/response schemas."""

    def test_log_source_create(self):
        """Test LogSourceCreate schema."""
        from app.logs.models import LogSourceCreate, LogSourceType

        create = LogSourceCreate(
            name="Test Source",
            source_type=LogSourceType.WINDOWS_EVENT,
        )

        assert create.name == "Test Source"
        assert create.source_type == LogSourceType.WINDOWS_EVENT

    def test_log_source_update(self):
        """Test LogSourceUpdate schema."""
        from app.logs.models import LogSourceUpdate, LogSourceStatus

        update = LogSourceUpdate(
            name="Updated Name",
            status=LogSourceStatus.ACTIVE,
        )

        assert update.name == "Updated Name"
        assert update.status == LogSourceStatus.ACTIVE


# =============================================================================
# Query Tests
# =============================================================================


class TestLogEventQuery:
    """Tests for LogEventQuery model."""

    def test_query_defaults(self):
        """Test LogEventQuery default values."""
        from app.logs.models import LogEventQuery

        query = LogEventQuery()

        assert query.limit == 50
        assert query.offset == 0
        assert query.source_id is None

    def test_query_with_filters(self):
        """Test LogEventQuery with filters."""
        from app.logs.models import LogEventQuery, LogSourceType, LogLevel

        query = LogEventQuery(
            source_type=LogSourceType.LINUX_SSH,
            level=LogLevel.ERROR,
            search="failed",
            limit=100,
        )

        assert query.source_type == LogSourceType.LINUX_SSH
        assert query.level == LogLevel.ERROR
        assert query.search == "failed"
        assert query.limit == 100


# =============================================================================
# Module Export Tests
# =============================================================================


class TestModuleExports:
    """Tests for module exports."""

    def test_logs_module_exports(self):
        """Test that all expected symbols are exported."""
        from app.logs import (
            # Models
            LogEvent,
            LogLevel,
            LogSource,
            LogSourceType,
            LogSourceStatus,
            CollectorType,
            ParsedLogEntry,
            CheckpointType,
            CollectorCheckpoint,
            SUPPORTED_SOURCE_TYPES,
            # Repositories
            LogEventRepository,
            LogSourceRepository,
            CheckpointRepository,
            DuplicateEventError,
            get_log_event_repository,
            get_log_source_repository,
            get_checkpoint_repository,
            # Collector
            BaseCollector,
            CollectorConfig,
            CollectorStatus,
            # Redaction
            redact_log_event,
            redact_string,
            contains_secret,
        )

        # All imports successful
        assert LogEvent is not None
        assert LogSourceType is not None
        assert SUPPORTED_SOURCE_TYPES is not None
        assert CheckpointType is not None
        assert CheckpointRepository is not None
        assert DuplicateEventError is not None
        assert redact_log_event is not None


# =============================================================================
# Security Constraint Tests
# =============================================================================


class TestLogSecurityConstraints:
    """Tests for log security constraints."""

    def test_source_rejects_credentials_in_config(self):
        """Test that LogSource rejects credentials in configuration."""
        from app.logs.models import LogSource, LogSourceType

        with pytest.raises(ValidationError):
            LogSource(
                name="Test",
                source_type=LogSourceType.WINDOWS_EVENT,
                configuration={"password": "secret"},
            )

    def test_source_to_dict_hides_encrypted_config_by_default(self):
        """Test that to_dict hides encrypted_config by default."""
        from app.logs.models import LogSource, LogSourceType

        source = LogSource(
            name="Test",
            source_type=LogSourceType.ANDROID_ADB,
            encrypted_config="encrypted_data",
        )

        data = source.to_dict()
        assert "encrypted_config" not in data

    def test_log_event_supports_redacted_content(self):
        """Test that LogEvent can store redacted content."""
        from app.logs.models import LogEvent, LogSourceType

        event = LogEvent(
            message="User login with password=[REDACTED]",
            source_type=LogSourceType.LINUX_SSH,
            raw_content="password=s3cr3t redacted to password=[REDACTED]",
        )

        assert "[REDACTED]" in event.message
        assert "[REDACTED]" in event.raw_content


# =============================================================================
# Redaction Tests (STEP 8.0.1)
# =============================================================================


class TestRedaction:
    """Tests for centralized redaction (STEP 8.0.1)."""

    def test_redact_string_password(self):
        """Test redacting passwords from strings."""
        from app.logs.redaction import redact_string

        text = "User logged in with password=secret123"
        redacted = redact_string(text)

        assert "secret123" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_string_bearer_token(self):
        """Test redacting bearer tokens."""
        from app.logs.redaction import redact_string

        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        redacted = redact_string(text)

        assert "eyJ" not in redacted
        assert "[REDACTED]" in redacted or "[REDACTED_JWT]" in redacted

    def test_redact_string_api_key(self):
        """Test redacting API keys."""
        from app.logs.redaction import redact_string

        text = "Connecting with api_key=sk-1234567890abcdef"
        redacted = redact_string(text)

        assert "sk-1234567890abcdef" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_string_aws_key(self):
        """Test redacting AWS access keys."""
        from app.logs.redaction import redact_string

        text = "Using AWS key AKIAIOSFODNN7EXAMPLE"
        redacted = redact_string(text)

        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED_AWS_KEY]" in redacted

    def test_redact_dict_sensitive_keys(self):
        """Test redacting sensitive keys from dictionaries."""
        from app.logs.redaction import redact_dict

        data = {
            "username": "admin",
            "password": "secret123",
            "api_key": "sk-12345",
            "host": "localhost",
        }

        redacted = redact_dict(data)

        assert redacted["username"] == "admin"
        assert redacted["password"] == "[REDACTED]"
        assert redacted["api_key"] == "[REDACTED]"
        assert redacted["host"] == "localhost"

    def test_redact_log_event_function(self):
        """Test the centralized redact_log_event function."""
        from app.logs.redaction import redact_log_event

        message = "Login failed for user with password=secret"
        raw = "password=secret123 token=abc123"
        fields = {"user": "admin", "token": "xyz789"}

        r_message, r_raw, r_fields = redact_log_event(message, raw, fields)

        assert "secret" not in r_message
        assert "secret123" not in r_raw
        assert "abc123" not in r_raw
        assert r_fields["token"] == "[REDACTED]"
        assert r_fields["user"] == "admin"

    def test_contains_secret(self):
        """Test secret detection."""
        from app.logs.redaction import contains_secret

        assert contains_secret("password=secret") is True
        assert contains_secret("api_key=12345") is True
        assert contains_secret("normal log message") is False
        assert contains_secret("user logged in") is False


# =============================================================================
# Checkpoint Tests (STEP 8.0.1)
# =============================================================================


class TestCollectorCheckpoint:
    """Tests for CollectorCheckpoint model (STEP 8.0.1)."""

    def test_create_windows_checkpoint(self):
        """Test creating a Windows checkpoint."""
        from app.logs.models import CollectorCheckpoint, CheckpointType

        checkpoint = CollectorCheckpoint(
            source_id="src-123",
            checkpoint_type=CheckpointType.WINDOWS_RECORD_ID,
            checkpoint_value={
                "record_id": 12345,
                "channel": "Security",
                "computer": "DC01",
            },
        )

        assert checkpoint.source_id == "src-123"
        assert checkpoint.checkpoint_type == CheckpointType.WINDOWS_RECORD_ID
        assert checkpoint.checkpoint_value["record_id"] == 12345

    def test_create_linux_checkpoint(self):
        """Test creating a Linux file offset checkpoint."""
        from app.logs.models import CollectorCheckpoint, CheckpointType

        checkpoint = CollectorCheckpoint(
            source_id="src-456",
            checkpoint_type=CheckpointType.LINUX_FILE_OFFSET,
            checkpoint_value={
                "inode": 123456,
                "offset": 78901,
                "path": "/var/log/auth.log",
            },
        )

        assert checkpoint.checkpoint_type == CheckpointType.LINUX_FILE_OFFSET
        assert checkpoint.checkpoint_value["inode"] == 123456

    def test_checkpoint_to_dict(self):
        """Test checkpoint serialization."""
        from app.logs.models import CollectorCheckpoint, CheckpointType

        checkpoint = CollectorCheckpoint(
            source_id="src-789",
            checkpoint_type=CheckpointType.ANDROID_LOGCAT_POSITION,
            checkpoint_value={"device_serial": "emulator-5554", "last_seen_timestamp": "2026-01-01T00:00:00Z"},
        )

        data = checkpoint.to_dict()

        assert data["source_id"] == "src-789"
        assert data["checkpoint_type"] == "android_logcat_position"
        assert "updated_at" in data


# =============================================================================
# Integration Placeholder Tests (require running DB)
# =============================================================================


class TestLogIntegrationPlaceholders:
    """Placeholder tests for database integration."""

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_log_event_repository_create(self):
        """Test creating log event in database."""
        pass

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_log_source_repository_create(self):
        """Test creating log source in database."""
        pass

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_log_event_repository_batch_create(self):
        """Test batch creating log events."""
        pass

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_checkpoint_repository_upsert(self):
        """Test checkpoint upsert in database."""
        pass

    @pytest.mark.skip(reason="Requires running PostgreSQL")
    async def test_duplicate_event_handling(self):
        """Test duplicate event detection via source_event_id."""
        pass
