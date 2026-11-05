"""
STEP 8.5.1 - Correlation Context & Cross-Source Entity Normalization Tests

Comprehensive tests for:
A-F: Windows Event normalization (4624, 4625, 4648, 4672, 4688, account events)
G-J: Linux SSH normalization (success, failure, sudo, session)
K-N: Web Application normalization (auth, request, session, trace/request ID)
O-R: Edge cases (missing entities, invalid IP, empty username, IPv4/IPv6)
T-X: Tenant isolation (separate tenants, same username/IP/request across tenants)
Y-Z: Redaction safety, deterministic keys
"""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.correlation.context import (
    LOCALHOST_IPS,
    SYSTEM_ACCOUNTS,
    CorrelationContext,
    CorrelationContextExtractor,
    CorrelationEntityType,
    build_correlation_key,
    is_localhost_ip,
    normalize_hostname,
    normalize_ip_address,
    normalize_process_id,
    normalize_request_id,
    normalize_session_id,
    normalize_username,
    parse_correlation_key,
)
from app.logs.models import LogEvent, LogLevel, LogSourceType


# =============================================================================
# A: Windows 4624 (Successful Logon) Normalization
# =============================================================================


class TestWindows4624Normalization:
    """Tests for Windows Event ID 4624 (successful logon) normalization."""

    def test_4624_extracts_username(self):
        """Test 4624 extracts TargetUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="An account was successfully logged on.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {
                    "TargetUserName": "jsmith",
                    "TargetDomainName": "CORP",
                    "IpAddress": "192.168.1.100",
                    "LogonType": "10",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "jsmith"
        assert ctx.source_ip == "192.168.1.100"

    def test_4624_extracts_domain_username(self):
        """Test 4624 preserves DOMAIN\\user format."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Logon",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {
                    "TargetUserName": "CORP\\jsmith",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "CORP\\jsmith"

    def test_4624_extracts_logon_id(self):
        """Test 4624 extracts TargetLogonId as session_id."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Logon",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {
                    "TargetUserName": "admin",
                    "TargetLogonId": "0x12345678",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.session_id == "0x12345678"

    def test_4624_extracts_workstation(self):
        """Test 4624 extracts WorkstationName as hostname."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Logon",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "computer_name": "DC01",
                "event_data": {
                    "TargetUserName": "admin",
                    "WorkstationName": "WORKSTATION01",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.hostname == "workstation01"


# =============================================================================
# B: Windows 4625 (Failed Logon) Normalization
# =============================================================================


class TestWindows4625Normalization:
    """Tests for Windows Event ID 4625 (failed logon) normalization."""

    def test_4625_extracts_failed_username(self):
        """Test 4625 extracts TargetUserName from failed attempt."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="An account failed to log on.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4625,
                "event_data": {
                    "TargetUserName": "attacker",
                    "IpAddress": "10.0.0.50",
                    "FailureReason": "%%2313",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "attacker"
        assert ctx.source_ip == "10.0.0.50"

    def test_4625_extracts_source_ip(self):
        """Test 4625 extracts attacker IP."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Failed logon",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4625,
                "event_data": {
                    "TargetUserName": "admin",
                    "IpAddress": "203.0.113.50",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.source_ip == "203.0.113.50"


# =============================================================================
# C: Windows 4648 (Explicit Credentials) Normalization
# =============================================================================


class TestWindows4648Normalization:
    """Tests for Windows Event ID 4648 (explicit credentials) normalization."""

    def test_4648_extracts_subject_user(self):
        """Test 4648 extracts SubjectUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="A logon was attempted using explicit credentials.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4648,
                "event_data": {
                    "SubjectUserName": "svc_account",
                    "TargetUserName": "admin",
                    "TargetServerName": "DC02",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        # SubjectUserName is first in priority list for 4648
        # But TargetUserName comes first in our mapping
        assert ctx.username in ["admin", "svc_account"]

    def test_4648_extracts_target_server(self):
        """Test 4648 can correlate target server."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Explicit credentials",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4648,
                "computer_name": "WORKSTATION01",
                "event_data": {
                    "SubjectUserName": "jsmith",
                    "TargetServerName": "FILESERVER",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.hostname == "workstation01"


# =============================================================================
# D: Windows 4672 (Special Privileges) Normalization
# =============================================================================


class TestWindows4672Normalization:
    """Tests for Windows Event ID 4672 (special privileges) normalization."""

    def test_4672_extracts_privileged_user(self):
        """Test 4672 extracts SubjectUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Special privileges assigned to new logon.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4672,
                "computer_name": "DC01",
                "event_data": {
                    "SubjectUserName": "Administrator",
                    "SubjectLogonId": "0xABCDEF",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "Administrator"
        assert ctx.hostname == "dc01"

    def test_4672_extracts_logon_id(self):
        """Test 4672 extracts SubjectLogonId."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Privileges",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4672,
                "event_data": {
                    "SubjectUserName": "admin",
                    "SubjectLogonId": "0x12345",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.session_id == "0x12345"


# =============================================================================
# E: Windows 4688 (Process Creation) Normalization
# =============================================================================


class TestWindows4688Normalization:
    """Tests for Windows Event ID 4688 (process creation) normalization."""

    def test_4688_extracts_process_name(self):
        """Test 4688 extracts NewProcessName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="A new process has been created.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4688,
                "event_data": {
                    "SubjectUserName": "jsmith",
                    "NewProcessId": "0x1234",
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "ParentProcessId": "0x5678",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.process_name == "cmd.exe"
        assert ctx.process_id == 0x1234
        assert ctx.parent_process_id == 0x5678

    def test_4688_extracts_pid_hex(self):
        """Test 4688 handles hex PIDs."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Process created",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4688,
                "event_data": {
                    "NewProcessId": "0xABC",
                    "NewProcessName": "powershell.exe",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.process_id == 0xABC  # 2748 in decimal

    def test_4688_extracts_subject_user(self):
        """Test 4688 extracts SubjectUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Process created",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4688,
                "event_data": {
                    "SubjectUserName": "admin",
                    "NewProcessName": "whoami.exe",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "admin"


# =============================================================================
# F: Windows Account Events (4720/4726) Normalization
# =============================================================================


class TestWindowsAccountEvents:
    """Tests for Windows account management events."""

    def test_4720_extracts_new_account(self):
        """Test 4720 (account created) extracts TargetUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="A user account was created.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4720,
                "computer_name": "DC01",
                "event_data": {
                    "TargetUserName": "newuser",
                    "SubjectUserName": "Administrator",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "newuser"
        assert ctx.hostname == "dc01"

    def test_4726_extracts_deleted_account(self):
        """Test 4726 (account deleted) extracts TargetUserName."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="A user account was deleted.",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4726,
                "event_data": {
                    "TargetUserName": "olduser",
                    "SubjectUserName": "admin",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username == "olduser"


# =============================================================================
# G: Linux SSH Success Normalization
# =============================================================================


class TestLinuxSSHSuccess:
    """Tests for Linux SSH successful authentication normalization."""

    def test_ssh_success_extracts_username(self):
        """Test SSH success extracts username."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sshd",
            message="Accepted publickey for jsmith from 192.168.1.50 port 52345",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "ssh_success",
                "username": "jsmith",
                "source_ip": "192.168.1.50",
                "method": "publickey",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.username == "jsmith"
        assert ctx.source_ip == "192.168.1.50"
        assert ctx.hostname == "server01"

    def test_ssh_success_extracts_session(self):
        """Test SSH success extracts session info."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="webhost",
            program="sshd",
            pid=12345,
            message="SSH session opened",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "ssh_success",
                "username": "admin",
                "source_ip": "10.0.0.5",
                "session": "session-abc123",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.session_id == "session-abc123"
        assert ctx.process_id == 12345


# =============================================================================
# H: Linux SSH Failure Normalization
# =============================================================================


class TestLinuxSSHFailure:
    """Tests for Linux SSH failed authentication normalization."""

    def test_ssh_failure_extracts_attacker_ip(self):
        """Test SSH failure extracts attacker IP."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="bastion",
            program="sshd",
            message="Failed password for admin from 203.0.113.100",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "ssh_failed",
                "username": "admin",
                "source_ip": "203.0.113.100",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.source_ip == "203.0.113.100"
        assert ctx.username == "admin"

    def test_ssh_invalid_user_extracts_ip(self):
        """Test SSH invalid user extracts attacker IP."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sshd",
            message="Invalid user hacker from 198.51.100.50",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "ssh_invalid_user",
                "username": "hacker",
                "source_ip": "198.51.100.50",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.source_ip == "198.51.100.50"
        assert ctx.username == "hacker"


# =============================================================================
# I: Linux Sudo Normalization
# =============================================================================


class TestLinuxSudo:
    """Tests for Linux sudo event normalization."""

    def test_sudo_extracts_user_and_target(self):
        """Test sudo extracts both user and target user."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sudo",
            message="jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "sudo_success",
                "username": "jsmith",
                "target_user": "root",
                "command": "/bin/cat /etc/shadow",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.username == "jsmith"
        assert ctx.user_id == "root"

    def test_sudo_failed_extracts_username(self):
        """Test sudo failure extracts username."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sudo",
            message="jsmith : 3 incorrect password attempts",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "sudo_failed",
                "username": "jsmith",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.username == "jsmith"


# =============================================================================
# J: Linux Session Events Normalization
# =============================================================================


class TestLinuxSession:
    """Tests for Linux session event normalization."""

    def test_pam_session_opened(self):
        """Test PAM session opened extracts username."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sshd",
            pid=54321,
            message="pam_unix(sshd:session): session opened for user jsmith",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "session_opened",
                "username": "jsmith",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.username == "jsmith"
        assert ctx.process_id == 54321

    def test_session_closed_extracts_username(self):
        """Test session closed extracts username."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server01",
            program="sshd",
            message="session closed for user admin",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "session_closed",
                "username": "admin",
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-linux")

        assert ctx.username == "admin"


# =============================================================================
# K: Android Device Identity Normalization
# =============================================================================


class TestAndroidDeviceIdentity:
    """Tests for Android ADB/logcat device-identity normalization.

    Unlike the removed Web Application extractor, _extract_android never
    fabricates a user_id/username/source_ip - logcat lines don't actually
    carry those. The only stable identity logcat gives us is the device
    serial, which is mapped to hostname (matching how the collector
    mirrors device_serial onto LogEvent.hostname).
    """

    def test_android_extracts_device_serial_as_hostname(self):
        """Test Android event extracts device_serial as hostname."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            hostname="emulator-5554",
            program="ActivityManager",
            pid=1234,
            message="Start proc activity",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "device_serial": "emulator-5554",
                "tag": "ActivityManager",
                "pid": 1234,
                "tid": 1234,
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-android")

        assert ctx.hostname == "emulator-5554"
        # No user_id/username/source_ip - never fabricated for Android
        assert ctx.user_id is None
        assert ctx.username is None
        assert ctx.source_ip is None

    def test_android_falls_back_to_log_event_hostname(self):
        """Test Android extraction falls back to LogEvent.hostname when
        extracted_fields has no device_serial (the collector always sets
        both, but the extractor shouldn't depend on extracted_fields
        alone)."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            hostname="ZY223JL4GF",
            message="Device log line",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={},
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-android")

        # normalize_hostname() lowercases - device serials are case-sensitive
        # on the wire, but hostname normalization is consistent with every
        # other source type here.
        assert ctx.hostname == "zy223jl4gf"


# =============================================================================
# L: Android Process (tag/pid) Normalization
# =============================================================================


class TestAndroidProcess:
    """Tests for Android logcat tag/pid/tid normalization."""

    def test_android_extracts_tag_as_process_name(self):
        """Test Android extraction maps logcat tag to process_name."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            hostname="emulator-5554",
            program="PackageManager",
            message="Package installed",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "device_serial": "emulator-5554",
                "tag": "PackageManager",
                "pid": 4321,
                "tid": 4321,
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-android")

        assert ctx.process_name == "PackageManager"
        assert ctx.process_id == 4321
        assert ctx.raw_entities.get("tid") == 4321

    def test_android_no_tag_leaves_process_name_none(self):
        """Test missing tag/program leaves process_name None, not
        fabricated."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            hostname="emulator-5554",
            message="Untagged line",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={"device_serial": "emulator-5554"},
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-android")

        assert ctx.process_name is None
        assert ctx.process_id is None


# =============================================================================
# M: Android Missing-Entity Guarantees
# =============================================================================


class TestAndroidMissingEntities:
    """Tests proving Android extraction never fabricates web/session-style
    entities that logcat has no concept of."""

    def test_android_has_no_session_request_or_trace_id(self):
        """Test Android events never populate session_id/request_id/
        trace_id - those are web-specific concepts with no logcat analog."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            hostname="emulator-5554",
            program="su",
            message="su invoked by shell",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "device_serial": "emulator-5554",
                "tag": "su",
                "pid": 999,
                "tid": 999,
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-android")

        assert ctx.session_id is None
        assert ctx.request_id is None
        assert ctx.trace_id is None


# =============================================================================
# O: Missing Optional Entities
# =============================================================================


class TestMissingEntities:
    """Tests for handling missing optional entities."""

    def test_missing_ip_returns_none(self):
        """Test missing IP returns None, not fabricated."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Event without IP",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {
                    "TargetUserName": "admin",
                    # No IpAddress
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.source_ip is None

    def test_missing_username_returns_none(self):
        """Test missing username returns None."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            hostname="server",
            message="System event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_type": "service_start",
                # No username
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.username is None

    def test_empty_extracted_fields(self):
        """Test empty extracted_fields doesn't crash."""
        log_event = LogEvent(
            source_type=LogSourceType.ANDROID_ADB,
            message="Minimal event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={},
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        assert ctx.source_ip is None
        assert ctx.username is None
        assert ctx.user_id is None


# =============================================================================
# P: Invalid IP Handling
# =============================================================================


class TestInvalidIP:
    """Tests for invalid IP address handling."""

    def test_invalid_ip_returns_none(self):
        """Test invalid IP format returns None."""
        assert normalize_ip_address("not-an-ip") is None
        assert normalize_ip_address("999.999.999.999") is None
        assert normalize_ip_address("abc.def.ghi.jkl") is None

    def test_placeholder_ip_returns_none(self):
        """Test placeholder values return None."""
        assert normalize_ip_address("-") is None
        assert normalize_ip_address("n/a") is None
        assert normalize_ip_address("unknown") is None
        assert normalize_ip_address("") is None

    def test_zero_ip_returns_none(self):
        """Test 0.0.0.0 returns None."""
        assert normalize_ip_address("0.0.0.0") is None


# =============================================================================
# Q: Empty Username Handling
# =============================================================================


class TestEmptyUsername:
    """Tests for empty/system username handling."""

    def test_empty_username_returns_none(self):
        """Test empty username returns None."""
        assert normalize_username("") is None
        assert normalize_username("   ") is None
        assert normalize_username(None) is None

    def test_system_accounts_return_none(self):
        """Test system accounts return None."""
        assert normalize_username("SYSTEM") is None
        assert normalize_username("Local Service") is None
        assert normalize_username("NT AUTHORITY\\SYSTEM") is None
        assert normalize_username("root") is None  # Linux system account
        assert normalize_username("nobody") is None

    def test_placeholder_username_returns_none(self):
        """Test placeholder usernames return None."""
        assert normalize_username("-") is None
        assert normalize_username("n/a") is None
        assert normalize_username("unknown") is None


# =============================================================================
# R: IPv4 Normalization
# =============================================================================


class TestIPv4Normalization:
    """Tests for IPv4 address normalization."""

    def test_ipv4_normalized(self):
        """Test IPv4 addresses are normalized."""
        assert normalize_ip_address("192.168.1.1") == "192.168.1.1"
        assert normalize_ip_address("  10.0.0.1  ") == "10.0.0.1"

    def test_ipv4_localhost(self):
        """Test localhost IP is recognized."""
        ip = normalize_ip_address("127.0.0.1")
        assert ip == "127.0.0.1"
        assert is_localhost_ip(ip)


# =============================================================================
# S: IPv6 Normalization
# =============================================================================


class TestIPv6Normalization:
    """Tests for IPv6 address normalization."""

    def test_ipv6_normalized(self):
        """Test IPv6 addresses are normalized."""
        # Full form should be compressed
        ip = normalize_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert ip == "2001:db8::1"

    def test_ipv6_localhost(self):
        """Test IPv6 localhost is recognized."""
        ip = normalize_ip_address("::1")
        assert ip == "::1"
        assert is_localhost_ip(ip)

    def test_ipv6_compressed(self):
        """Test already compressed IPv6."""
        ip = normalize_ip_address("fe80::1")
        assert ip == "fe80::1"


# =============================================================================
# T: Tenant A Isolation
# =============================================================================


class TestTenantAIsolation:
    """Tests for Tenant A isolation."""

    def test_tenant_a_has_tenant_id(self):
        """Test Tenant A context has tenant_id."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Tenant A event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {"TargetUserName": "admin"},
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="tenant-A")

        assert ctx.tenant_id == "tenant-A"
        assert ctx.has_tenant()

    def test_tenant_a_correlation_keys(self):
        """Test Tenant A correlation keys include tenant."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_data": {
                    "TargetUserName": "admin",
                    "IpAddress": "10.0.0.5",
                },
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="tenant-A")
        keys = ctx.get_correlation_keys()

        assert all("tenant:tenant-A:" in k for k in keys)


# =============================================================================
# U: Tenant B Isolation
# =============================================================================


class TestTenantBIsolation:
    """Tests for Tenant B isolation."""

    def test_tenant_b_has_different_tenant_id(self):
        """Test Tenant B context has different tenant_id."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Tenant B event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_id": 4624,
                "event_data": {"TargetUserName": "admin"},
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="tenant-B")

        assert ctx.tenant_id == "tenant-B"

    def test_tenant_b_keys_different_from_a(self):
        """Test Tenant B keys don't match Tenant A keys."""
        log_event = LogEvent(
            source_type=LogSourceType.WINDOWS_EVENT,
            message="Event",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "event_data": {
                    "TargetUserName": "admin",
                    "IpAddress": "10.0.0.5",
                },
            },
        )

        ctx_a = CorrelationContextExtractor.extract(log_event, tenant_id="tenant-A")
        ctx_b = CorrelationContextExtractor.extract(log_event, tenant_id="tenant-B")

        keys_a = set(ctx_a.get_correlation_keys())
        keys_b = set(ctx_b.get_correlation_keys())

        # Keys should be completely disjoint
        assert keys_a.isdisjoint(keys_b)


# =============================================================================
# V: Same Username Across Tenants
# =============================================================================


class TestSameUsernameAcrossTenants:
    """Tests for same username in different tenants."""

    def test_same_username_different_keys(self):
        """Test same username produces different keys for different tenants."""
        ctx_a = CorrelationContext(
            tenant_id="org-A",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )
        ctx_b = CorrelationContext(
            tenant_id="org-B",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )

        keys_a = ctx_a.get_correlation_keys()
        keys_b = ctx_b.get_correlation_keys()

        # Both have user:admin but with different tenant prefixes
        assert "tenant:org-A:user:admin" in keys_a
        assert "tenant:org-B:user:admin" in keys_b
        assert "tenant:org-A:user:admin" not in keys_b
        assert "tenant:org-B:user:admin" not in keys_a


# =============================================================================
# W: Same IP Across Tenants
# =============================================================================


class TestSameIPAcrossTenants:
    """Tests for same IP in different tenants."""

    def test_same_ip_different_keys(self):
        """Test same IP produces different keys for different tenants."""
        ctx_a = CorrelationContext(
            tenant_id="org-A",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
        )
        ctx_b = CorrelationContext(
            tenant_id="org-B",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
        )

        keys_a = ctx_a.get_correlation_keys()
        keys_b = ctx_b.get_correlation_keys()

        assert "tenant:org-A:ip:192.168.1.100" in keys_a
        assert "tenant:org-B:ip:192.168.1.100" in keys_b
        assert set(keys_a).isdisjoint(set(keys_b))


# =============================================================================
# X: Same Request ID Across Tenants
# =============================================================================


class TestSameRequestIdAcrossTenants:
    """Tests for same request ID in different tenants."""

    def test_same_request_id_different_keys(self):
        """Test same request ID produces different keys for different tenants."""
        ctx_a = CorrelationContext(
            tenant_id="org-A",
            request_id="req-123",
            timestamp=datetime.now(timezone.utc),
        )
        ctx_b = CorrelationContext(
            tenant_id="org-B",
            request_id="req-123",
            timestamp=datetime.now(timezone.utc),
        )

        keys_a = ctx_a.get_correlation_keys()
        keys_b = ctx_b.get_correlation_keys()

        assert "tenant:org-A:request:req-123" in keys_a
        assert "tenant:org-B:request:req-123" in keys_b
        assert set(keys_a).isdisjoint(set(keys_b))


# =============================================================================
# Y: Redaction Safety
# =============================================================================


class TestRedactionSafety:
    """Tests for ensuring secrets don't enter correlation data."""

    def test_no_password_in_context(self):
        """Test passwords don't appear in correlation context."""
        log_event = LogEvent(
            source_type=LogSourceType.LINUX_SSH,
            message="Login with password=secret123",
            timestamp=datetime.now(timezone.utc),
            extracted_fields={
                "username": "admin",
                "password": "secret123",  # Should not be extracted
            },
        )

        ctx = CorrelationContextExtractor.extract(log_event, tenant_id="org-123")

        # Context should not have password field
        assert not hasattr(ctx, "password")
        # Password should not be in raw_entities
        assert "password" not in ctx.raw_entities

    def test_no_token_in_correlation_keys(self):
        """Test tokens don't appear in correlation keys."""
        ctx = CorrelationContext(
            tenant_id="org-123",
            username="admin",
            source_ip="10.0.0.1",
            timestamp=datetime.now(timezone.utc),
        )

        keys = ctx.get_correlation_keys()
        key_str = "|".join(keys)

        # No sensitive keywords should appear
        assert "password" not in key_str.lower()
        assert "token" not in key_str.lower()
        assert "secret" not in key_str.lower()
        assert "key" not in key_str.lower()  # API key


# =============================================================================
# Z: Deterministic Key Generation
# =============================================================================


class TestDeterministicKeys:
    """Tests for deterministic correlation key generation."""

    def test_same_input_same_keys(self):
        """Test same input produces same keys."""
        ctx1 = CorrelationContext(
            tenant_id="org-123",
            source_ip="192.168.1.1",
            username="jsmith",
            hostname="server01",
            timestamp=datetime.now(timezone.utc),
        )
        ctx2 = CorrelationContext(
            tenant_id="org-123",
            source_ip="192.168.1.1",
            username="jsmith",
            hostname="server01",
            timestamp=datetime.now(timezone.utc),
        )

        assert ctx1.get_correlation_keys() == ctx2.get_correlation_keys()

    def test_same_input_same_fingerprint(self):
        """Test same input produces same fingerprint."""
        ctx1 = CorrelationContext(
            tenant_id="org-123",
            source_ip="10.0.0.5",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )
        ctx2 = CorrelationContext(
            tenant_id="org-123",
            source_ip="10.0.0.5",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )

        assert ctx1.get_entity_fingerprint() == ctx2.get_entity_fingerprint()

    def test_build_correlation_key_deterministic(self):
        """Test build_correlation_key is deterministic."""
        key1 = build_correlation_key("tenant-1", CorrelationEntityType.IP_ADDRESS, "10.0.0.1")
        key2 = build_correlation_key("tenant-1", CorrelationEntityType.IP_ADDRESS, "10.0.0.1")

        assert key1 == key2
        assert key1 == "tenant:tenant-1:ip:10.0.0.1"

    def test_parse_correlation_key(self):
        """Test correlation key parsing."""
        key = "tenant:org-123:user:jsmith"
        result = parse_correlation_key(key)

        assert result == ("org-123", "user", "jsmith")

    def test_parse_invalid_key(self):
        """Test invalid key parsing returns None."""
        assert parse_correlation_key("invalid") is None
        assert parse_correlation_key("not:enough:parts") is None
        assert parse_correlation_key("wrong:prefix:type:value") is None


# =============================================================================
# Additional: CorrelationContext Methods
# =============================================================================


class TestCorrelationContextMethods:
    """Tests for CorrelationContext helper methods."""

    def test_can_correlate_with_entities(self):
        """Test can_correlate returns True with entities."""
        ctx = CorrelationContext(
            tenant_id="org-123",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )

        assert ctx.can_correlate() is True

    def test_can_correlate_without_tenant(self):
        """Test can_correlate returns False without tenant."""
        ctx = CorrelationContext(
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )

        assert ctx.can_correlate() is False

    def test_can_correlate_without_entities(self):
        """Test can_correlate returns False without entities."""
        ctx = CorrelationContext(
            tenant_id="org-123",
            timestamp=datetime.now(timezone.utc),
        )

        assert ctx.can_correlate() is False

    def test_localhost_ip_excluded_from_keys(self):
        """Test localhost IPs are excluded from correlation keys."""
        ctx = CorrelationContext(
            tenant_id="org-123",
            source_ip="127.0.0.1",
            username="admin",
            timestamp=datetime.now(timezone.utc),
        )

        keys = ctx.get_correlation_keys()

        # Localhost should NOT be in keys (not useful for cross-source correlation)
        assert "tenant:org-123:ip:127.0.0.1" not in keys
        # But username should be
        assert "tenant:org-123:user:admin" in keys

    def test_to_event_data_dict(self):
        """Test conversion to EventData format."""
        ctx = CorrelationContext(
            tenant_id="org-123",
            source_type=LogSourceType.WINDOWS_EVENT,
            event_id="evt-123",
            source_ip="10.0.0.5",
            username="admin",
            hostname="server01",
            timestamp=datetime.now(timezone.utc),
        )

        data = ctx.to_event_data_dict()

        assert data["event_id"] == "evt-123"
        assert data["domain"] == "windows_event"
        assert "10.0.0.5" in data["ips"]
        assert "admin" in data["users"]
        assert "server01" in data["assets"]

    def test_timezone_aware_timestamp(self):
        """Test timestamp is always timezone-aware."""
        # Naive datetime should be converted
        naive_dt = datetime(2026, 9, 18, 12, 0, 0)
        ctx = CorrelationContext(
            tenant_id="org-123",
            timestamp=naive_dt,
        )

        assert ctx.timestamp.tzinfo is not None
        assert ctx.timestamp.tzinfo == timezone.utc


# =============================================================================
# Email Analysis Unchanged Test
# =============================================================================


class TestEmailAnalysisUnchanged:
    """Verify email analysis is not affected by correlation context changes."""

    def test_email_agent_import_works(self):
        """Test EmailAgent can still be imported."""
        from app.agents.email_agent import EmailAgent
        assert EmailAgent is not None

    def test_correlation_engine_still_works(self):
        """Test CorrelationEngine is not broken."""
        from app.correlation import CorrelationEngine, EventData

        engine = CorrelationEngine()
        event = EventData(
            event_id="test-1",
            domain="email",
            timestamp=datetime.now(timezone.utc),
            ips=["1.2.3.4"],
            users=["test@example.com"],
        )

        # Should not crash
        result = engine.correlate([event])
        assert result is not None
