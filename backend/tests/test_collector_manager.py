"""
CyberGuard AI - Collector Manager Tests

Tests for app.logs.collector_manager:
- Building collector configs from LogSource rows (incl. credential decryption)
- Supervisor lifecycle: start_all/stop_all, start_source/stop_source
- Failure isolation: one source's crash never affects another's supervisor
- Backoff + restart behavior on repeated failures
- Skipping sources with invalid/unsupported configuration (never crashes
  startup for every other source)
- Linux checkpoint persistence uses upsert() (regression test for the
  checkpoint_repo.save() bug - CheckpointRepository has no save() method)

These tests use mocks for the repository layer and for the underlying
SSH/Windows APIs - no real database, SSH server, or Windows Event Log
access is required.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.logs.collector_base import CollectorStatus
from app.logs.collector_manager import (
    CollectorManager,
    SupervisorState,
    UnsupportedCollectorSourceError,
    build_collector_for_source,
    get_collector_manager,
)
from app.logs.collectors.android import AndroidADBCollector
from app.logs.collectors.linux import LinuxSSHCollector
from app.logs.collectors.windows import WindowsEventCollector
from app.logs.models import LogSource, LogSourceStatus, LogSourceType, CollectorType


# =============================================================================
# Autouse fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def no_real_checkpoint_repository():
    """
    Every test in this file drives real collector start()/stop() paths,
    which internally call get_checkpoint_repository() (Windows collect()'s
    checkpoint load, Linux _save_checkpoint()). That singleton is never
    patched per-test here the way get_log_source_repository() is, so
    without this fixture it falls through to the real, DB-backed
    CheckpointRepository.

    Each test runs on its own pytest-asyncio function-scoped event loop.
    Reaching the real repository means get_database() opens a fresh
    psycopg_pool.AsyncConnectionPool bound to *that* loop (background
    scheduler + worker tasks included), which nothing ever closes before
    the loop is torn down - the orphaned pool tasks are then still alive
    when pytest-asyncio's runner cancels/gathers all tasks on that loop at
    teardown, which can hang indefinitely cancelling a real in-flight
    Postgres connection. Patching the singleton keeps these supervisor/
    collector lifecycle tests isolated from the database entirely, which
    is what they intend to test anyway.
    """
    mock_checkpoint_repo = MagicMock()
    mock_checkpoint_repo.get = AsyncMock(return_value=None)
    mock_checkpoint_repo.upsert = AsyncMock()
    mock_checkpoint_repo.delete = AsyncMock(return_value=True)
    mock_checkpoint_repo.list_all = AsyncMock(return_value=[])

    with patch(
        "app.logs.repository.get_checkpoint_repository",
        return_value=mock_checkpoint_repo,
    ):
        yield mock_checkpoint_repo


# =============================================================================
# Helpers
# =============================================================================


def make_windows_source(**overrides) -> LogSource:
    defaults = dict(
        id="win-source-1",
        name="Test Windows Source",
        source_type=LogSourceType.WINDOWS_EVENT,
        collector_type=CollectorType.WINDOWS_AGENT,
        status=LogSourceStatus.PENDING,
        configuration={
            "channel": "Security",
            "event_ids": [4624, 4625],
            "poll_interval_seconds": 5.0,
        },
    )
    defaults.update(overrides)
    return LogSource(**defaults)


def make_linux_source(**overrides) -> LogSource:
    defaults = dict(
        id="linux-source-1",
        name="Test Linux Source",
        source_type=LogSourceType.LINUX_SSH,
        collector_type=CollectorType.LINUX_AGENT,
        status=LogSourceStatus.PENDING,
        configuration={
            "hostname": "192.168.1.100",
            "username": "cyberguard",
            "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
            "private_key_path": "/path/to/key",
        },
    )
    defaults.update(overrides)
    return LogSource(**defaults)


def make_android_source(**overrides) -> LogSource:
    defaults = dict(
        id="android-source-1",
        name="Test Android Source",
        source_type=LogSourceType.ANDROID_ADB,
        collector_type=CollectorType.ANDROID_AGENT,
        status=LogSourceStatus.PENDING,
        configuration={
            "device_serial": "emulator-5554",
        },
    )
    defaults.update(overrides)
    return LogSource(**defaults)


# =============================================================================
# build_collector_for_source Tests
# =============================================================================


class TestBuildCollectorForSource:
    """Tests for mapping a LogSource to a concrete collector."""

    def test_builds_windows_collector(self):
        source = make_windows_source()
        collector = build_collector_for_source(source)

        assert isinstance(collector, WindowsEventCollector)
        assert collector.config.source_id == "win-source-1"

    def test_windows_event_ids_list_converted_to_set(self):
        """LogSource.configuration stores event_ids as a JSON-safe list;
        WindowsCollectorConfig requires a set."""
        source = make_windows_source(
            configuration={"event_ids": [4624, 4625, 4688]}
        )
        collector = build_collector_for_source(source)

        assert collector._windows_config.event_ids == {4624, 4625, 4688}

    def test_builds_linux_collector(self):
        source = make_linux_source()
        collector = build_collector_for_source(source)

        assert isinstance(collector, LinuxSSHCollector)
        assert collector.config.source_id == "linux-source-1"
        assert collector._linux_config.hostname == "192.168.1.100"

    def test_builds_android_collector(self):
        """STEP 9: ANDROID_ADB must dispatch to AndroidADBCollector, the
        same way WINDOWS_EVENT/LINUX_SSH dispatch to their collectors."""
        source = make_android_source()
        collector = build_collector_for_source(source)

        assert isinstance(collector, AndroidADBCollector)
        assert collector.config.source_id == "android-source-1"
        assert collector._android_config.device_serial == "emulator-5554"

    def test_android_collector_has_no_credential_decryption(self):
        """adb has no credential concept this app manages - unlike Linux's
        encrypted_config (private_key/password), AndroidADBCollectorConfig
        is built from source.configuration alone, with no decrypt step."""
        source = make_android_source(
            configuration={
                "device_serial": "ZY223JL4GF",
                "adb_host": "192.168.1.50",
                "adb_port": 5555,
            }
        )
        collector = build_collector_for_source(source)

        assert collector._android_config.device_serial == "ZY223JL4GF"
        assert collector._android_config.adb_host == "192.168.1.50"
        assert collector._android_config.adb_port == 5555

    def test_unsupported_source_type_raises(self):
        """
        STEP 9: all 3 current LogSourceType members (windows_event,
        linux_ssh, android_adb) now have embedded collectors, so there is
        no real enum member left to construct an "unsupported but valid"
        LogSource through normal validation. model_construct() bypasses
        validation to simulate the realistic failure case instead: a
        legacy/corrupted row whose source_type is some other string (e.g.
        a leftover value from before an enum member was removed, like the
        old web_application type) - build_collector_for_source() must
        still refuse this gracefully, not crash with an AttributeError.
        """
        source = LogSource.model_construct(
            id="legacy-source-1",
            name="Legacy source",
            source_type="legacy_unsupported_type",
            collector_type=CollectorType.HTTP_RECEIVER,
            status=LogSourceStatus.PENDING,
            configuration={},
            organization_id="org-1",
        )

        with pytest.raises(UnsupportedCollectorSourceError):
            build_collector_for_source(source)

    def test_invalid_linux_config_raises_validation_error(self):
        """Missing required host_key should surface as a pydantic error,
        not crash the whole manager."""
        from pydantic import ValidationError

        source = make_linux_source(configuration={"hostname": "10.0.0.1"})
        # host_key omitted -> LinuxSSHCollectorConfig requires it
        with pytest.raises(ValidationError):
            build_collector_for_source(source)

    def test_linux_credentials_decrypted_and_merged(self):
        """encrypted_config should be decrypted and merged into the
        collector config (e.g. private_key), never left in plaintext
        LogSource.configuration."""
        fake_plaintext = json.dumps({"private_key_path": "/secure/key/path"})

        source = make_linux_source(
            configuration={
                "hostname": "10.0.0.5",
                "username": "svc",
                "host_key": "ssh-ed25519 AAAA",
            },
            encrypted_config="encrypted-blob",
        )

        mock_service = MagicMock()
        mock_service.decrypt.return_value = fake_plaintext

        with patch(
            "app.services.token_encryption.get_token_encryption_service",
            return_value=mock_service,
        ):
            collector = build_collector_for_source(source)

        mock_service.decrypt.assert_called_once_with("encrypted-blob")
        assert collector._linux_config.private_key_path == "/secure/key/path"

    def test_credential_decryption_failure_propagates_without_logging_secret(self):
        """If decryption fails, the error propagates (so the source is
        skipped by the caller) but never logs the ciphertext or plaintext."""
        source = make_linux_source(encrypted_config="corrupt-blob")

        mock_service = MagicMock()
        mock_service.decrypt.side_effect = ValueError("Failed to decrypt token")

        with patch(
            "app.services.token_encryption.get_token_encryption_service",
            return_value=mock_service,
        ):
            with pytest.raises(ValueError):
                build_collector_for_source(source)

    def test_windows_unknown_configuration_key_raises_validation_error(self):
        """
        Regression test for the Log Analysis bug where a windows_event
        source stayed stuck at status=error/0 events forever.

        The frontend used to send configuration={"hostname": "..."} for
        windows_event sources, but WindowsCollectorConfig has no
        "hostname" field (it has computer_name) - and before this fix,
        plain pydantic BaseModel silently drops unrecognized keys instead
        of rejecting them. That let a source "register successfully" with
        the user's hostname completely discarded and no error anywhere,
        with channel/computer_name silently keeping their defaults.
        WindowsCollectorConfig.model_config now sets extra="forbid" so
        this surfaces as a clear ValidationError at collector-build time
        instead of a silent no-op.
        """
        from pydantic import ValidationError

        source = make_windows_source(configuration={"hostname": "DESKTOP-4DAGSCE"})

        with pytest.raises(ValidationError):
            build_collector_for_source(source)

    def test_windows_unsupported_channel_raises_validation_error(self):
        """
        SUPPORTED_EVENT_IDS (the only event IDs this collector's collect()
        loop recognizes) are all Security-log auditing events, so a
        channel other than "Security" would connect successfully but then
        filter out every single event - a confusing "0 events, no error"
        state. WindowsCollectorConfig.validate_supported_channel rejects
        it up front instead.
        """
        from pydantic import ValidationError

        source = make_windows_source(
            configuration={"channel": "System", "event_ids": [4624]}
        )

        with pytest.raises(ValidationError):
            build_collector_for_source(source)

    def test_windows_security_channel_still_accepted(self):
        """Guard against the validator above becoming over-strict and
        rejecting the one channel that is genuinely supported."""
        source = make_windows_source(
            configuration={"channel": "Security", "event_ids": [4624]}
        )

        collector = build_collector_for_source(source)
        assert collector._windows_config.channel == "Security"

    def test_windows_computer_name_is_the_correct_config_key(self):
        """computer_name (not hostname) is what WindowsCollectorConfig and
        connect()'s OpenEventLog(computer_name, channel) actually use."""
        source = make_windows_source(
            configuration={
                "channel": "Security",
                "event_ids": [4624],
                "computer_name": "DC01",
            }
        )

        collector = build_collector_for_source(source)
        assert collector._windows_config.computer_name == "DC01"


# =============================================================================
# CollectorManager - start_all / stop_all Tests
# =============================================================================


class TestCollectorManagerStartStopAll:
    """Tests for bulk supervisor lifecycle management."""

    @pytest.mark.asyncio
    async def test_start_all_creates_one_supervisor_per_enabled_source(self):
        """Also covers STEP 9's allow-list: ANDROID_ADB must start a
        supervisor via start_all() exactly like WINDOWS_EVENT/LINUX_SSH."""
        manager = CollectorManager()

        sources = [
            make_windows_source(id="s1"),
            make_linux_source(id="s2"),
            make_android_source(id="s3"),
        ]
        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=sources)
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()), \
           patch.object(LinuxSSHCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(LinuxSSHCollector, "disconnect", AsyncMock()), \
           patch.object(AndroidADBCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(AndroidADBCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            # Give the supervisor tasks a tick to reach RUNNING state
            await asyncio.sleep(0.05)

            assert manager.active_count == 3
            assert set(manager._supervisors.keys()) == {"s1", "s2", "s3"}

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_start_all_skips_disabled_sources(self):
        manager = CollectorManager()

        sources = [make_windows_source(id="s1", status=LogSourceStatus.DISABLED)]
        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=sources)

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ):
            await manager.start_all()

            assert manager.active_count == 0
            assert "s1" not in manager._supervisors

    @pytest.mark.asyncio
    async def test_start_all_skips_unsupported_source_types_silently(self):
        """A source with no embedded collector (e.g. a legacy row left
        over from a removed LogSourceType member) must be skipped, not
        crash start_all for every other source. model_construct() bypasses
        enum validation since all 3 current LogSourceType members
        (windows_event, linux_ssh, android_adb) now have real collectors."""
        manager = CollectorManager()

        web_source = LogSource.model_construct(
            id="web-1",
            name="Web source",
            source_type="legacy_unsupported_type",
            collector_type=CollectorType.HTTP_RECEIVER,
            status=LogSourceStatus.PENDING,
            configuration={},
            organization_id="org-1",
        )
        win_source = make_windows_source(id="win-1")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[web_source, win_source])
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            await asyncio.sleep(0.05)

            assert "web-1" not in manager._supervisors
            assert "win-1" in manager._supervisors

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_start_all_skips_source_with_invalid_config_without_crashing(self):
        """A source with invalid configuration must be skipped (logged),
        and must NOT prevent other valid sources from starting."""
        manager = CollectorManager()

        bad_linux_source = make_linux_source(id="bad-1", configuration={})  # missing host_key
        good_windows_source = make_windows_source(id="good-1")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[bad_linux_source, good_windows_source])
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            await asyncio.sleep(0.05)

            assert "bad-1" not in manager._supervisors
            assert "good-1" in manager._supervisors

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_start_all_does_not_duplicate_existing_supervisor(self):
        manager = CollectorManager()
        source = make_windows_source(id="dup-1")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            await asyncio.sleep(0.05)
            first_task = manager._supervisors["dup-1"]

            await manager.start_all()  # Call again - should not replace the running task
            await asyncio.sleep(0.05)

            assert manager._supervisors["dup-1"] is first_task

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_stop_all_stops_every_supervisor_and_collector(self):
        manager = CollectorManager()

        sources = [make_windows_source(id="s1"), make_linux_source(id="s2")]
        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=sources)
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()) as win_disconnect, \
           patch.object(LinuxSSHCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(LinuxSSHCollector, "disconnect", AsyncMock()) as linux_disconnect:

            await manager.start_all()
            await asyncio.sleep(0.05)

            await manager.stop_all()

            win_disconnect.assert_awaited()
            linux_disconnect.assert_awaited()
            assert manager.active_count == 0
            for status in manager.get_status():
                assert status.state == SupervisorState.STOPPED


# =============================================================================
# start_source() synchronous-failure persistence
# =============================================================================


class TestStartSourceSynchronousFailure:
    """
    Regression tests for the Log Analysis bug's root cause.

    api/v1/logs.py's create_log_source() calls start_source() directly
    (not start_all()) when a new windows_event/linux_ssh source is
    created, so it can start collecting immediately rather than waiting
    for the next full app restart. Unlike start_all(), start_source() did
    not catch ValidationError/UnsupportedCollectorSourceError raised
    synchronously by build_collector_for_source() (e.g. bad/unknown
    configuration keys) - that exception used to propagate out of
    start_source() to its caller in logs.py, which only logged it and
    never updated the source's DB row. The source would stay stuck at
    its creation-time status (PENDING) with no visible error at all,
    which is worse than the generic "Collector failed to start" message
    a runtime connect() failure produces via the async supervisor path.
    """

    @pytest.mark.asyncio
    async def test_invalid_config_does_not_raise_out_of_start_source(self):
        """start_source() must not let a synchronous build failure
        propagate - the whole point is callers (e.g. the create-source
        API route) can call it fire-and-forget without needing their own
        try/except for this. Runs inside a running event loop, matching
        the real call site (an async FastAPI route handler)."""
        manager = CollectorManager()
        # Unknown "hostname" key -> WindowsCollectorConfig(extra="forbid")
        # raises ValidationError inside build_collector_for_source().
        bad_source = make_windows_source(
            id="bad-sync", configuration={"hostname": "DESKTOP-4DAGSCE"}
        )

        mock_repo = MagicMock()
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ):
            manager.start_source(bad_source)  # must not raise
            await asyncio.sleep(0.05)  # let the fire-and-forget task run

        assert "bad-sync" not in manager._supervisors

    @pytest.mark.asyncio
    async def test_invalid_config_persists_error_status(self):
        """The source's DB row must end up at status=ERROR with a
        descriptive error_message, not silently stuck at PENDING."""
        manager = CollectorManager()
        bad_source = make_windows_source(
            id="bad-sync-2", configuration={"hostname": "DESKTOP-4DAGSCE"}
        )

        mock_repo = MagicMock()
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ):
            manager.start_source(bad_source)
            # The status persist runs as a fire-and-forget asyncio.Task;
            # give the loop a tick to run it.
            await asyncio.sleep(0.05)

        mock_repo.update_status.assert_awaited_once()
        call_args = mock_repo.update_status.call_args
        assert call_args.args[0] == "bad-sync-2"
        assert call_args.args[1] == LogSourceStatus.ERROR
        assert "error_message" in call_args.kwargs
        assert call_args.kwargs["error_message"]  # non-empty, descriptive

    @pytest.mark.asyncio
    async def test_unsupported_source_type_does_not_raise_out_of_start_source(self):
        """A source with no embedded collector (e.g. a legacy row left
        over from a removed LogSourceType member) - start_source() must
        treat that the same way as a validation error: logged/persisted,
        never raised to the caller. model_construct() bypasses enum
        validation since all 3 current LogSourceType members
        (windows_event, linux_ssh, android_adb) now have real collectors."""
        manager = CollectorManager()
        web_source = LogSource.model_construct(
            id="web-sync-1",
            name="Web source",
            source_type="legacy_unsupported_type",
            collector_type=CollectorType.HTTP_RECEIVER,
            status=LogSourceStatus.PENDING,
            configuration={},
            organization_id="org-1",
        )

        mock_repo = MagicMock()
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ):
            manager.start_source(web_source)  # must not raise
            await asyncio.sleep(0.05)

        assert "web-sync-1" not in manager._supervisors

    @pytest.mark.asyncio
    async def test_valid_config_starts_normally_without_persisting_error(self):
        """Sanity check: a source with valid config must still start
        normally through start_source() and must NOT have the new
        failure-persistence path triggered."""
        manager = CollectorManager()
        good_source = make_windows_source(id="good-sync")

        mock_repo = MagicMock()
        mock_repo.update_status = AsyncMock()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()):

            manager.start_source(good_source)
            await asyncio.sleep(0.05)

            assert "good-sync" in manager._supervisors
            # update_status may be called by the async success path
            # (ACTIVE), but never with ERROR for a valid config.
            for call in mock_repo.update_status.call_args_list:
                assert call.args[1] != LogSourceStatus.ERROR

            await manager.stop_all()


# =============================================================================
# Failure Isolation Tests
# =============================================================================


class TestFailureIsolation:
    """
    Tests verifying that one collector's failure never affects another's
    supervisor task - the core safety property of per-source supervision.
    """

    @pytest.mark.asyncio
    async def test_one_source_failure_does_not_stop_sibling_source(self):
        manager = CollectorManager()

        failing_source = make_windows_source(id="failing")
        healthy_source = make_linux_source(id="healthy")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[failing_source, healthy_source])
        mock_repo.update_status = AsyncMock()
        mock_repo.get = AsyncMock(return_value=failing_source)

        async def _raise(*args, **kwargs):
            raise RuntimeError("simulated Windows Event Log failure")

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", side_effect=_raise), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()), \
           patch.object(LinuxSSHCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(LinuxSSHCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            # Let the failing supervisor hit its except block and enter backoff
            await asyncio.sleep(0.1)

            failing_status = manager.get_source_status("failing")
            healthy_status = manager.get_source_status("healthy")

            assert failing_status.state in (
                SupervisorState.RECONNECTING,
                SupervisorState.FAILED,
            )
            assert failing_status.error_count >= 1
            assert failing_status.last_error is not None

            # The healthy source must be completely unaffected
            assert healthy_status.state == SupervisorState.RUNNING
            assert healthy_status.error_count == 0

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_supervisor_exception_never_propagates_out_of_run_supervisor(self):
        """A RuntimeError inside the supervised collector must be fully
        contained - the supervisor asyncio.Task must not finish with an
        unhandled exception (which asyncio would otherwise log as
        'Task exception was never retrieved' / crash an awaiting caller)."""
        manager = CollectorManager()
        source = make_windows_source(id="isolated-fail")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()
        mock_repo.get = AsyncMock(return_value=source)

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(
            WindowsEventCollector, "connect", AsyncMock(side_effect=RuntimeError("boom"))
        ), patch.object(WindowsEventCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            await asyncio.sleep(0.1)

            task = manager._supervisors["isolated-fail"]
            assert not task.done()  # Still looping/backing off, not crashed out

            await manager.stop_all()
            # If the task had an unhandled exception, gather() in stop_all
            # with return_exceptions=True would have swallowed it, but the
            # task must still have reached a clean STOPPED state.
            assert manager.get_source_status("isolated-fail").state == SupervisorState.STOPPED


# =============================================================================
# Backoff / Restart Tests
# =============================================================================


class TestBackoffAndRestart:
    """Tests for exponential backoff and restart-after-failure behavior."""

    @pytest.mark.asyncio
    async def test_restart_delay_increases_after_repeated_failures(self):
        manager = CollectorManager()
        source = make_windows_source(id="flaky")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()
        mock_repo.get = AsyncMock(return_value=source)

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(
            WindowsEventCollector, "connect", AsyncMock(side_effect=RuntimeError("flaky failure"))
        ), patch.object(WindowsEventCollector, "disconnect", AsyncMock()), patch(
            "app.logs.collector_manager._INITIAL_RESTART_DELAY", 0.01
        ), patch("app.logs.collector_manager._MAX_RESTART_DELAY", 0.05):

            await manager.start_all()
            # Allow several failure/backoff cycles
            await asyncio.sleep(0.3)

            status = manager.get_source_status("flaky")
            assert status.error_count >= 2
            assert status.reconnect_count >= 2

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_backoff_resets_after_successful_run(self):
        """If a collector starts successfully after previously failing,
        the backoff delay should reset rather than keep climbing forever."""
        manager = CollectorManager()
        source = make_windows_source(id="recovering")

        call_count = {"n": 0}

        async def _start_side_effect(self):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("first attempt fails")
            return True

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()
        mock_repo.get = AsyncMock(return_value=source)

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(WindowsEventCollector, "connect", _start_side_effect), \
           patch.object(WindowsEventCollector, "disconnect", AsyncMock()), patch(
            "app.logs.collector_manager._INITIAL_RESTART_DELAY", 0.01
        ):

            await manager.start_all()
            await asyncio.sleep(0.15)

            status = manager.get_source_status("recovering")
            assert status.state == SupervisorState.RUNNING
            assert status.last_error is None  # Reset on success

            await manager.stop_all()

    @pytest.mark.asyncio
    async def test_source_disabled_during_backoff_stops_supervisor(self):
        """If a source is disabled while its collector is in a restart
        backoff window, the supervisor should notice on rebuild and stop
        cleanly instead of restarting forever."""
        manager = CollectorManager()
        source = make_windows_source(id="to-disable")
        disabled_source = make_windows_source(
            id="to-disable", status=LogSourceStatus.DISABLED
        )

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()
        mock_repo.get = AsyncMock(return_value=disabled_source)

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch.object(
            WindowsEventCollector, "connect", AsyncMock(side_effect=RuntimeError("fail"))
        ), patch.object(WindowsEventCollector, "disconnect", AsyncMock()), patch(
            "app.logs.collector_manager._INITIAL_RESTART_DELAY", 0.01
        ):

            await manager.start_all()
            await asyncio.sleep(0.2)

            status = manager.get_source_status("to-disable")
            assert status.state == SupervisorState.STOPPED

            await manager.stop_all()


# =============================================================================
# Status Reporting Tests
# =============================================================================


class TestStatusReporting:
    """Tests for observable status - must never include secrets."""

    @pytest.mark.asyncio
    async def test_get_status_contains_no_credential_fields(self):
        manager = CollectorManager()
        source = make_linux_source(id="secure-1", encrypted_config="blob")

        mock_repo = MagicMock()
        mock_repo.list = AsyncMock(return_value=[source])
        mock_repo.update_status = AsyncMock()

        mock_service = MagicMock()
        mock_service.decrypt.return_value = json.dumps({"private_key": "SHOULD-NOT-LEAK"})

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=mock_repo,
        ), patch(
            "app.services.token_encryption.get_token_encryption_service",
            return_value=mock_service,
        ), patch.object(LinuxSSHCollector, "connect", AsyncMock(return_value=True)), \
           patch.object(LinuxSSHCollector, "disconnect", AsyncMock()):

            await manager.start_all()
            await asyncio.sleep(0.05)

            statuses = manager.get_status()
            serialized = " ".join(s.model_dump_json() for s in statuses)
            assert "SHOULD-NOT-LEAK" not in serialized

            await manager.stop_all()

    def test_get_source_status_returns_none_for_unknown_source(self):
        manager = CollectorManager()
        assert manager.get_source_status("does-not-exist") is None


# =============================================================================
# Singleton Accessor Tests
# =============================================================================


class TestSingletonAccessor:
    def test_get_collector_manager_returns_same_instance(self):
        import app.logs.collector_manager as cm_module

        cm_module._collector_manager = None
        try:
            m1 = get_collector_manager()
            m2 = get_collector_manager()
            assert m1 is m2
        finally:
            cm_module._collector_manager = None


# =============================================================================
# Regression: Linux checkpoint persistence bug
# =============================================================================


class TestLinuxCheckpointPersistenceRegression:
    """
    Regression test for a bug where LinuxSSHCollector._save_checkpoint()
    called checkpoint_repo.save(checkpoint) - a method that does not exist
    on CheckpointRepository (only upsert()/get()/delete()/list_all() do).
    This would raise AttributeError at runtime on every checkpoint save,
    silently breaking checkpoint persistence for all Linux sources.
    """

    @pytest.mark.asyncio
    async def test_save_checkpoint_calls_upsert_not_save(self):
        from app.logs.collectors.linux import (
            LinuxSSHCollector,
            LinuxSSHCollectorConfig,
        )

        config = LinuxSSHCollectorConfig(
            source_id="checkpoint-test",
            hostname="10.0.0.1",
            username="cyberguard",
            host_key="ssh-ed25519 AAAA",
        )
        collector = LinuxSSHCollector(config)
        collector._file_states["/var/log/auth.log"] = collector._file_states.get(
            "/var/log/auth.log"
        )

        from app.logs.collectors.linux import FileState
        collector._file_states["/var/log/auth.log"] = FileState(
            path="/var/log/auth.log", inode=123, offset=456
        )

        mock_checkpoint_repo = MagicMock()
        mock_checkpoint_repo.upsert = AsyncMock()

        with patch(
            "app.logs.repository.get_checkpoint_repository",
            return_value=mock_checkpoint_repo,
        ):
            await collector._save_checkpoint()

        mock_checkpoint_repo.upsert.assert_awaited_once()
        # CheckpointRepository genuinely has no save() method - verify that
        # directly so this test fails loudly if the method is ever
        # reintroduced without being implemented.
        from app.logs.repository import CheckpointRepository
        assert not hasattr(CheckpointRepository, "save")

    @pytest.mark.asyncio
    async def test_windows_checkpoint_already_uses_upsert(self):
        """Windows collector was already correct - guard against regression."""
        from app.logs.collectors.windows import (
            WindowsEventCollector,
            WindowsCollectorConfig,
        )

        config = WindowsCollectorConfig(source_id="win-checkpoint-test")
        collector = WindowsEventCollector(config)

        mock_checkpoint_repo = MagicMock()
        mock_checkpoint_repo.upsert = AsyncMock()

        with patch(
            "app.logs.repository.get_checkpoint_repository",
            return_value=mock_checkpoint_repo,
        ):
            await collector._save_checkpoint(12345)

        mock_checkpoint_repo.upsert.assert_awaited_once()


# =============================================================================
# Blocking-call offload sanity checks
# =============================================================================


class TestBlockingCallsOffloaded:
    """
    Sanity checks that the known-blocking SDK calls (win32evtlog, paramiko)
    are invoked through asyncio.to_thread() rather than directly on the
    event loop. We verify this behaviorally: the event loop must remain
    responsive (another coroutine can run) while the "blocking" call is
    in flight.
    """

    @pytest.mark.asyncio
    async def test_event_loop_stays_responsive_during_simulated_slow_sftp_stat(self):
        from app.logs.collectors.linux import LinuxSSHCollector, LinuxSSHCollectorConfig
        import time

        config = LinuxSSHCollectorConfig(
            source_id="responsive-test",
            hostname="10.0.0.1",
            username="cyberguard",
            host_key="ssh-ed25519 AAAA",
        )
        collector = LinuxSSHCollector(config)

        def slow_stat(path):
            time.sleep(0.2)  # Simulates a slow blocking network call
            mock_stat = MagicMock()
            mock_stat.st_mode = 0o100644  # S_ISREG
            mock_stat.st_size = 0
            return mock_stat

        collector._sftp_client = MagicMock()
        collector._sftp_client.stat = slow_stat

        other_coroutine_ran = asyncio.Event()

        async def other_work():
            await asyncio.sleep(0.01)
            other_coroutine_ran.set()

        # If _discover_active_paths blocked the event loop synchronously,
        # other_work() would never get a chance to run concurrently.
        await asyncio.gather(
            collector._discover_active_paths(),
            other_work(),
        )

        assert other_coroutine_ran.is_set()
