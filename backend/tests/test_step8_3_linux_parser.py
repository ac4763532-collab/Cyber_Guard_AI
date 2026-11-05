"""
CyberGuard AI - Linux SSH Log Parser Tests (STEP 8.3)

Tests for the Linux authentication log parser.

Tests cover:
- SSH successful authentication
- SSH failed authentication
- Invalid user attempts
- sudo commands
- su commands
- System/PAM messages
- Timestamp parsing (syslog + ISO formats)
- Malformed line handling
- IPv4 and IPv6 addresses
- Edge cases
"""

import pytest
from datetime import datetime, timezone

from app.logs.parsers.linux_ssh import (
    LinuxSSHLogParser,
    SSHEventType,
    parse_linux_log_line,
    parse_syslog_timestamp,
    EVENT_TYPE_TO_LEVEL,
    EVENT_TYPE_TO_CATEGORY,
)
from app.logs.models import LogLevel


# =============================================================================
# Timestamp Parsing Tests
# =============================================================================


class TestTimestampParsing:
    """Tests for syslog timestamp parsing."""

    def test_traditional_syslog_timestamp(self):
        """Test traditional syslog format: Sep 17 14:23:45."""
        line = "Sep 17 14:23:45 hostname sshd[1234]: test message"
        timestamp, remaining = parse_syslog_timestamp(line, year=2024)

        assert timestamp is not None
        assert timestamp.month == 9
        assert timestamp.day == 17
        assert timestamp.hour == 14
        assert timestamp.minute == 23
        assert timestamp.second == 45
        assert "hostname" in remaining

    def test_iso_timestamp(self):
        """Test ISO format timestamp."""
        line = "2024-09-17T14:23:45+00:00 hostname sshd[1234]: test"
        timestamp, remaining = parse_syslog_timestamp(line)

        assert timestamp is not None
        assert timestamp.year == 2024
        assert timestamp.month == 9
        assert timestamp.day == 17
        assert "hostname" in remaining

    def test_rsyslog_high_precision(self):
        """Test rsyslog high-precision format."""
        line = "2024-09-17T14:23:45.123456+00:00 hostname sshd[1234]: test"
        timestamp, remaining = parse_syslog_timestamp(line)

        assert timestamp is not None
        assert timestamp.year == 2024
        assert timestamp.microsecond == 123456

    def test_single_digit_day(self):
        """Test single digit day (Sep  5 vs Sep 05)."""
        line = "Sep  5 14:23:45 hostname sshd[1234]: test"
        timestamp, remaining = parse_syslog_timestamp(line, year=2024)

        assert timestamp is not None
        assert timestamp.day == 5

    def test_no_timestamp(self):
        """Test line without recognized timestamp."""
        line = "random text without timestamp"
        timestamp, remaining = parse_syslog_timestamp(line)

        assert timestamp is None
        assert remaining == line


# =============================================================================
# SSH Authentication Tests
# =============================================================================


class TestSSHAuthentication:
    """Tests for SSH authentication event parsing."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_ssh_accepted_password(self):
        """Test successful SSH password authentication."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted password for admin from 192.168.1.100 port 52345 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.program == "sshd"
        assert entry.pid == 12345
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_SUCCESS.value
        assert entry.extracted_fields["username"] == "admin"
        assert entry.extracted_fields["source_ip"] == "192.168.1.100"
        assert entry.extracted_fields["source_port"] == 52345
        assert entry.extracted_fields["auth_method"] == "password"
        assert entry.extracted_fields["auth_result"] == "success"
        assert entry.level == LogLevel.INFO
        assert "authentication" in entry.tags

    def test_ssh_accepted_publickey(self):
        """Test successful SSH public key authentication."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted publickey for deploy from 10.0.0.50 port 54321 ssh2: ED25519 SHA256:abc123xyz"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_KEY_AUTH.value
        assert entry.extracted_fields["username"] == "deploy"
        assert entry.extracted_fields["auth_method"] == "publickey"
        assert entry.extracted_fields["key_type"] == "ED25519"
        assert entry.extracted_fields["key_fingerprint"] == "SHA256:abc123xyz"

    def test_ssh_failed_password(self):
        """Test failed SSH password authentication."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Failed password for admin from 192.168.1.100 port 52345 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_FAILED.value
        assert entry.extracted_fields["username"] == "admin"
        assert entry.extracted_fields["source_ip"] == "192.168.1.100"
        assert entry.extracted_fields["auth_result"] == "failed"
        assert entry.level == LogLevel.WARNING

    def test_ssh_failed_invalid_user(self):
        """Test failed SSH with invalid user."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Failed password for invalid user hacker from 10.0.0.1 port 12345 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_INVALID_USER.value
        assert entry.extracted_fields["username"] == "hacker"
        assert entry.extracted_fields["invalid_user"] is True

    def test_ssh_invalid_user_standalone(self):
        """Test Invalid user message (before auth attempt)."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Invalid user attacker from 203.0.113.50 port 54321"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_INVALID_USER.value
        assert entry.extracted_fields["username"] == "attacker"
        assert entry.extracted_fields["source_ip"] == "203.0.113.50"

    def test_ssh_disconnect(self):
        """Test SSH disconnect message."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Disconnected from authenticating user admin 192.168.1.100 port 52345"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_DISCONNECT.value
        assert entry.extracted_fields["username"] == "admin"
        assert entry.extracted_fields["source_ip"] == "192.168.1.100"

    def test_ssh_connection(self):
        """Test SSH new connection message."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Connection from 192.168.1.100 port 52345"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_CONNECTION.value
        assert entry.extracted_fields["source_ip"] == "192.168.1.100"
        assert entry.extracted_fields["source_port"] == 52345

    def test_ssh_ipv6_address(self):
        """Test SSH with IPv6 address."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted password for admin from 2001:db8::1 port 52345 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["source_ip"] == "2001:db8::1"

    def test_ssh_ipv6_localhost(self):
        """Test SSH with IPv6 localhost."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted password for admin from ::1 port 52345 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["source_ip"] == "::1"


# =============================================================================
# Sudo Tests
# =============================================================================


class TestSudoEvents:
    """Tests for sudo event parsing."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_sudo_success(self):
        """Test successful sudo command."""
        line = "Sep 17 14:23:45 server1 sudo[12345]:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.program == "sudo"
        assert entry.extracted_fields["event_type"] == SSHEventType.SUDO_SUCCESS.value
        assert entry.extracted_fields["username"] == "admin"
        assert entry.extracted_fields["target_user"] == "root"
        assert entry.extracted_fields["command"] == "/usr/bin/apt update"
        assert entry.extracted_fields["tty"] == "pts/0"
        assert entry.level == LogLevel.NOTICE

    def test_sudo_with_env(self):
        """Test sudo with environment preservation."""
        line = "Sep 17 14:23:45 server1 sudo[12345]:   admin : TTY=pts/0 ; PWD=/home ; USER=root ; ENV=DISPLAY=:0 ; COMMAND=/usr/bin/vim"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SUDO_SUCCESS.value

    def test_sudo_auth_failure(self):
        """Test sudo authentication failure."""
        line = "Sep 17 14:23:45 server1 sudo[12345]:   admin : 3 incorrect password attempts"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SUDO_FAILED.value
        assert entry.extracted_fields["failed_attempts"] == 3
        assert entry.level == LogLevel.WARNING


# =============================================================================
# su Tests
# =============================================================================


class TestSuEvents:
    """Tests for su event parsing."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_su_success(self):
        """Test successful su."""
        line = "Sep 17 14:23:45 server1 su[12345]: Successful su for root by admin"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SU_SUCCESS.value
        assert entry.extracted_fields["username"] == "admin"
        assert entry.extracted_fields["target_user"] == "root"
        assert entry.level == LogLevel.NOTICE

    def test_su_failed(self):
        """Test failed su."""
        line = "Sep 17 14:23:45 server1 su[12345]: FAILED su for root by hacker"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SU_FAILED.value
        assert entry.extracted_fields["username"] == "hacker"
        assert entry.extracted_fields["target_user"] == "root"
        assert entry.level == LogLevel.WARNING

    def test_su_session_opened(self):
        """Test su session opened via PAM."""
        line = "Sep 17 14:23:45 server1 su[12345]: pam_unix(su:session): session opened for user root by admin(uid=1000)"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SESSION_OPENED.value
        assert entry.extracted_fields["target_user"] == "root"


# =============================================================================
# PAM Session Tests
# =============================================================================


class TestPAMEvents:
    """Tests for PAM session event parsing."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_pam_session_opened(self):
        """Test PAM session opened."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: pam_unix(sshd:session): session opened for user admin by (uid=0)"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SESSION_OPENED.value
        assert entry.extracted_fields["username"] == "admin"
        # Service is captured as just "sshd" (without :session suffix)
        assert "sshd" in entry.extracted_fields.get("service", "")

    def test_pam_session_closed(self):
        """Test PAM session closed."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: pam_unix(sshd:session): session closed for user admin"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SESSION_CLOSED.value
        assert entry.extracted_fields["username"] == "admin"


# =============================================================================
# systemd Tests
# =============================================================================


class TestSystemdEvents:
    """Tests for systemd event parsing."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_service_started(self):
        """Test service started message."""
        line = "Sep 17 14:23:45 server1 systemd[1]: Started OpenSSH server daemon."
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SERVICE_START.value
        assert entry.extracted_fields["service_name"] == "OpenSSH server daemon"

    def test_service_stopped(self):
        """Test service stopped message."""
        line = "Sep 17 14:23:45 server1 systemd[1]: Stopped OpenSSH server daemon."
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SERVICE_STOP.value


# =============================================================================
# Edge Cases and Malformed Input
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and malformed input."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_empty_line(self):
        """Test empty line returns None."""
        entry = self.parser.parse_line("")
        assert entry is None

        entry = self.parser.parse_line("   ")
        assert entry is None

    def test_whitespace_only(self):
        """Test whitespace-only line."""
        entry = self.parser.parse_line("\t\n  \t")
        assert entry is None

    def test_malformed_line(self):
        """Test malformed line still produces entry."""
        line = "completely malformed log line without structure"
        entry = self.parser.parse_line(line)

        # Should still return an entry (as unparsed)
        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.UNKNOWN.value
        assert "unparsed" in entry.tags

    def test_username_with_special_chars(self):
        """Test username with allowed special characters."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted password for user_name.test from 192.168.1.1 port 22 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.extracted_fields["username"] == "user_name.test"

    def test_long_line(self):
        """Test very long log line."""
        long_command = "/usr/bin/python3 " + "a" * 5000
        line = f"Sep 17 14:23:45 server1 sudo[12345]:   admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND={long_command}"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert len(entry.extracted_fields["command"]) > 5000

    def test_hostname_with_domain(self):
        """Test hostname with domain."""
        line = "Sep 17 14:23:45 server1.example.com sshd[12345]: Accepted password for admin from 192.168.1.1 port 22 ssh2"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.hostname == "server1.example.com"

    def test_no_pid(self):
        """Test program without PID."""
        line = "Sep 17 14:23:45 server1 kernel: some kernel message"
        entry = self.parser.parse_line(line)

        assert entry is not None
        assert entry.program == "kernel"
        assert entry.pid is None


# =============================================================================
# Source Event ID Tests
# =============================================================================


class TestSourceEventID:
    """Tests for source event ID generation."""

    def setup_method(self):
        """Set up parser for each test."""
        self.parser = LinuxSSHLogParser()

    def test_source_event_id_passed_through(self):
        """Test source_event_id is passed through to entry."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: test message"
        entry = self.parser.parse_line(
            line,
            source_id="src-123",
            source_event_id="evt-456",
        )

        assert entry is not None
        assert entry.source_id == "src-123"
        assert entry.source_event_id == "evt-456"


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunction:
    """Tests for the parse_linux_log_line convenience function."""

    def test_basic_parsing(self):
        """Test basic parsing via convenience function."""
        line = "Sep 17 14:23:45 server1 sshd[12345]: Accepted password for admin from 192.168.1.1 port 22 ssh2"
        entry = parse_linux_log_line(line)

        assert entry is not None
        assert entry.extracted_fields["event_type"] == SSHEventType.SSH_SUCCESS.value

    def test_with_default_hostname(self):
        """Test parsing with default hostname."""
        line = "some malformed line"
        entry = parse_linux_log_line(line, hostname="fallback-host")

        assert entry is not None
        assert entry.hostname == "fallback-host"


# =============================================================================
# Category and Level Mapping Tests
# =============================================================================


class TestCategoryAndLevelMappings:
    """Tests for event type to category/level mappings."""

    def test_all_event_types_have_level(self):
        """Verify all event types have a level mapping."""
        for event_type in SSHEventType:
            assert event_type in EVENT_TYPE_TO_LEVEL, f"Missing level for {event_type}"

    def test_all_event_types_have_category(self):
        """Verify all event types have a category mapping."""
        for event_type in SSHEventType:
            assert event_type in EVENT_TYPE_TO_CATEGORY, f"Missing category for {event_type}"

    def test_auth_events_are_authentication_category(self):
        """Verify auth events are in authentication category."""
        auth_events = [
            SSHEventType.SSH_SUCCESS,
            SSHEventType.SSH_FAILED,
            SSHEventType.SSH_INVALID_USER,
        ]
        for event_type in auth_events:
            assert EVENT_TYPE_TO_CATEGORY[event_type] == "authentication"

    def test_privilege_events_have_appropriate_level(self):
        """Verify privilege events have notice level."""
        assert EVENT_TYPE_TO_LEVEL[SSHEventType.SUDO_SUCCESS] == LogLevel.NOTICE
        assert EVENT_TYPE_TO_LEVEL[SSHEventType.SU_SUCCESS] == LogLevel.NOTICE

    def test_failed_events_have_warning_level(self):
        """Verify failed events have warning level."""
        failed_events = [
            SSHEventType.SSH_FAILED,
            SSHEventType.SSH_INVALID_USER,
            SSHEventType.SUDO_FAILED,
            SSHEventType.SU_FAILED,
        ]
        for event_type in failed_events:
            assert EVENT_TYPE_TO_LEVEL[event_type] == LogLevel.WARNING
