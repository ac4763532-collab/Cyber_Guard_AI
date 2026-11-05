"""
CyberGuard AI - Linux SSH Collector Real Integration Test (Step 3, Part 4)

Proves the REAL runtime path:

    configured Linux LogSource
            |
    CollectorManager (real)
            |
    LinuxSSHCollector.start()/.connect()/.collect()/._tail_file()/.stop() (real)
            |
    LinuxSSHLogParser.parse_line() (real)
            |
    LogEvent.from_parsed_entry() (real)
            |
    publish_log_event() -> log_event_to_security_event() -> EventProducer.publish() (real)
            |
    EventProducer._producer.send_and_wait() <- ONLY THIS is faked

What is mocked and why (external SSH/SFTP boundary + DB + network socket
only - never the collector or parser logic itself, per the Step 3 task
constraints: "Do NOT mock the entire collector. Mock only the external
SSH/SFTP boundary where necessary."):

- paramiko (via sys.modules): paramiko makes a real TCP connection in
  SSHClient.connect() - there is no authorized SSH server to connect to in
  this test environment, so the connection itself is the external boundary
  being faked. A FakeSSHClient/FakeSFTPFile simulate exactly the methods
  LinuxSSHCollector.connect()/_discover_active_paths()/_read_new_lines_sync()
  call: SSHClient(), set_missing_host_key_policy(), connect(), open_sftp(),
  sftp.stat(), sftp.open(), file.seek()/.readline()/.tell(). The private key
  loading classes (Ed25519Key etc.) are also faked since there's no real key
  file/content needed for this test (private_key_path points at a key the
  fake loader accepts unconditionally).
- get_checkpoint_repository() / get_log_event_repository() /
  get_log_source_repository(): no real Postgres is available in this
  environment. Same in-memory fakes as the Windows integration test.
- EventProducer._producer.send_and_wait: the actual aiokafka network call.

NOT mocked: CollectorManager, LinuxSSHCollector.start()/.stop()/.connect()/
.collect()/._tail_file()/._read_new_lines_sync(), LinuxSSHLogParser.parse_line(),
LogEvent.from_parsed_entry(), publish_log_event(), log_event_to_security_event(),
EventProducer.publish().
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import types
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.logs.collector_manager import CollectorManager
from app.logs.models import (
    CollectorCheckpoint,
    CollectorType,
    LogEvent,
    LogSource,
    LogSourceStatus,
    LogSourceType,
)
from app.event_bus.events import SecurityEvent


# =============================================================================
# Fakes for the DB boundary (shared pattern with the Windows integration test)
# =============================================================================


class FakeCheckpointRepo:
    def __init__(self):
        self._store: dict[str, CollectorCheckpoint] = {}

    async def get(self, source_id: str) -> CollectorCheckpoint | None:
        return self._store.get(source_id)

    async def upsert(self, checkpoint: CollectorCheckpoint) -> CollectorCheckpoint:
        self._store[checkpoint.source_id] = checkpoint
        return checkpoint

    async def delete(self, source_id: str) -> bool:
        return self._store.pop(source_id, None) is not None

    async def list_all(self) -> list[CollectorCheckpoint]:
        return list(self._store.values())


class FakeLogEventRepo:
    def __init__(self):
        self.created: list[LogEvent] = []

    async def create(self, event: LogEvent, skip_duplicates: bool = False) -> LogEvent | None:
        self.created.append(event)
        return event


class FakeLogSourceRepo:
    def __init__(self, sources: list[LogSource]):
        self._sources = {s.id: s for s in sources}

    async def list(self, limit: int = 50, **kwargs) -> list[LogSource]:
        return list(self._sources.values())

    async def get(self, source_id: str) -> LogSource | None:
        return self._sources.get(source_id)

    async def update_status(self, source_id, status, error_message=None):
        src = self._sources.get(source_id)
        if src:
            src.status = status
        return src

    async def update_event_stats(self, source_id: str, event_count_increment: int = 1):
        return None


# =============================================================================
# Fake paramiko module (the actual SSH/SFTP network boundary)
# =============================================================================


class FakeSFTPAttr:
    def __init__(self, size: int, inode: int, mode: int = 0o100644):
        self.st_size = size
        self.st_ino = inode
        self.st_mode = mode


class FakeSFTPFile:
    """Fakes the file object returned by sftp.open() - supports the exact
    subset LinuxSSHCollector._read_new_lines_sync() uses: a context
    manager with seek()/readline()/tell()."""

    def __init__(self, content: bytes):
        self._buf = io.BytesIO(content)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def seek(self, offset: int) -> None:
        self._buf.seek(offset)

    def readline(self):
        raw = self._buf.readline()
        return raw.decode("utf-8") if raw else ""

    def tell(self) -> int:
        return self._buf.tell()


class FakeChannel:
    def settimeout(self, timeout):
        pass


class FakeSFTPClient:
    """Fakes paramiko.SFTPClient - only stat()/open()/get_channel(),
    exactly what the real collector calls."""

    def __init__(self, file_contents: dict[str, bytes], inode_by_path: dict[str, int]):
        self._file_contents = file_contents
        self._inode_by_path = inode_by_path

    def get_channel(self):
        return FakeChannel()

    def stat(self, path: str) -> FakeSFTPAttr:
        if path not in self._file_contents:
            raise FileNotFoundError(path)
        content = self._file_contents[path]
        return FakeSFTPAttr(size=len(content), inode=self._inode_by_path.get(path, 1))

    def open(self, path: str, mode: str = "r") -> FakeSFTPFile:
        return FakeSFTPFile(self._file_contents[path])

    def close(self):
        pass


class FakeTransport:
    def is_active(self) -> bool:
        return True


class FakeSSHClient:
    """Fakes paramiko.SSHClient - only the methods LinuxSSHCollector.connect()/
    disconnect()/_is_connected() call."""

    _shared_sftp: FakeSFTPClient | None = None  # set by the test before connect()

    def __init__(self):
        self._policy = None
        self.connected_with: dict | None = None

    def set_missing_host_key_policy(self, policy):
        self._policy = policy

    def connect(self, hostname, port, username, pkey, password, timeout,
                look_for_keys, allow_agent):
        # Exercise the real StrictHostKeyPolicy by simulating paramiko
        # offering a host key during connect, the same way a real SSH
        # handshake would trigger missing_host_key().
        fake_key = MagicMock()
        fake_key.get_name.return_value = self._policy.key_type
        fake_key.get_base64.return_value = self._policy.key_data
        self._policy.missing_host_key(self, hostname, fake_key)

        self.connected_with = dict(
            hostname=hostname, port=port, username=username,
        )

    def open_sftp(self) -> FakeSFTPClient:
        return FakeSSHClient._shared_sftp

    def get_transport(self):
        return FakeTransport()

    def close(self):
        pass


class FakeKey:
    """Fakes paramiko.Ed25519Key/RSAKey/etc. - accepts any key content/file
    unconditionally (no real private key material needed for this test)."""

    @classmethod
    def from_private_key(cls, key_file, password=None):
        return cls()

    @classmethod
    def from_private_key_file(cls, path, password=None):
        return cls()


class FakeSSHException(Exception):
    pass


class FakeAuthenticationException(FakeSSHException):
    pass


def install_fake_paramiko(sftp_client: FakeSFTPClient) -> None:
    """Installs a fake `paramiko` module into sys.modules so the real
    collector's local `import paramiko` picks it up. This is the external
    SSH/SFTP boundary explicitly permitted to be mocked by the task."""
    FakeSSHClient._shared_sftp = sftp_client

    fake_module = types.ModuleType("paramiko")
    fake_module.SSHClient = FakeSSHClient
    fake_module.SFTPClient = FakeSFTPClient
    fake_module.Ed25519Key = FakeKey
    fake_module.ECDSAKey = FakeKey
    fake_module.RSAKey = FakeKey
    fake_module.DSSKey = FakeKey
    fake_module.SSHException = FakeSSHException
    fake_module.AuthenticationException = FakeAuthenticationException
    sys.modules["paramiko"] = fake_module


def uninstall_fake_paramiko() -> None:
    sys.modules.pop("paramiko", None)


def make_linux_source(**overrides) -> LogSource:
    # _load_private_key() does a real os.path.exists() check before handing
    # off to the (faked) paramiko key loader, so the configured path must
    # point at an actual file on disk - its content is irrelevant since
    # FakeKey.from_private_key_file() accepts anything unconditionally.
    key_path = _ensure_fake_private_key_file()

    defaults = dict(
        id="linux-integration-1",
        name="Integration Linux Source",
        source_type=LogSourceType.LINUX_SSH,
        collector_type=CollectorType.LINUX_AGENT,
        status=LogSourceStatus.PENDING,
        configuration={
            "hostname": "10.0.0.5",
            "port": 22,
            "username": "cyberguard",
            "private_key_path": key_path,
            "host_key": "ssh-ed25519 AAAAFAKEHOSTKEYDATA",
            "log_paths": ["/var/log/auth.log"],
            "poll_interval_seconds": 1.0,
            "checkpoint_interval_seconds": 5.0,
        },
    )
    defaults.update(overrides)
    return LogSource(**defaults)


_FAKE_KEY_PATH: str | None = None


def _ensure_fake_private_key_file() -> str:
    """Creates (once) a real temp file to stand in for a private key path.
    Its content is never parsed for real - FakeKey.from_private_key_file()
    is the only thing that reads it, and it accepts any content."""
    global _FAKE_KEY_PATH
    if _FAKE_KEY_PATH is None:
        import tempfile

        fd, path = tempfile.mkstemp(prefix="fake_test_key_", suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write("-----BEGIN FAKE TEST KEY-----\nnot a real key\n-----END FAKE TEST KEY-----\n")
        _FAKE_KEY_PATH = path
    return _FAKE_KEY_PATH


# =============================================================================
# Fake producer boundary (shared pattern with the Windows integration test)
# =============================================================================


class FakeSendResult:
    def __init__(self):
        self.partition = 0
        self.offset = 1


class FakeAIOKafkaProducer:
    def __init__(self):
        self.sent: list[dict] = []

    async def send_and_wait(self, topic: str, value: dict, key=None):
        json.dumps(value)
        self.sent.append({"topic": topic, "value": value, "key": key})
        return FakeSendResult()

    async def start(self):
        pass

    async def stop(self):
        pass


@pytest.fixture
def fake_producer_wiring():
    from app.event_bus.producer import EventProducer

    producer = EventProducer()
    fake_kafka = FakeAIOKafkaProducer()
    producer._producer = fake_kafka
    producer._started = True

    with patch("app.event_bus.producer._producer", producer):
        yield producer, fake_kafka


# =============================================================================
# Realistic auth.log content (several failed SSH, one successful, one sudo)
# =============================================================================

AUTH_LOG_CONTENT = (
    "Oct  9 03:14:01 prod-web01 sshd[1021]: Failed password for invalid user "
    "admin from 203.0.113.77 port 51233 ssh2\n"
    "Oct  9 03:14:05 prod-web01 sshd[1022]: Failed password for root "
    "from 203.0.113.77 port 51240 ssh2\n"
    "Oct  9 03:14:09 prod-web01 sshd[1023]: Failed password for root "
    "from 203.0.113.77 port 51251 ssh2\n"
    "Oct  9 03:15:40 prod-web01 sshd[1030]: Accepted publickey for deploy "
    "from 198.51.100.22 port 60412 ssh2: ED25519 SHA256:abcd1234\n"
    "Oct  9 03:16:02 prod-web01 sudo[1035]: deploy : TTY=pts/0 ; PWD=/home/deploy ; "
    "USER=root ; COMMAND=/usr/bin/systemctl restart nginx\n"
).encode("utf-8")


# =============================================================================
# The integration test
# =============================================================================


class TestLinuxRealIntegrationPipeline:
    """REAL CollectorManager + REAL LinuxSSHCollector lifecycle, with only
    the paramiko SSH/SFTP boundary, the Postgres boundary, and the aiokafka
    network boundary faked."""

    def setup_method(self):
        pass

    def teardown_method(self):
        uninstall_fake_paramiko()

    @pytest.mark.asyncio
    async def test_configured_linux_source_processes_realistic_auth_log(
        self, fake_producer_wiring
    ):
        producer, fake_kafka = fake_producer_wiring

        source = make_linux_source()
        source_repo = FakeLogSourceRepo([source])
        checkpoint_repo = FakeCheckpointRepo()
        log_event_repo = FakeLogEventRepo()

        sftp = FakeSFTPClient(
            file_contents={"/var/log/auth.log": AUTH_LOG_CONTENT},
            inode_by_path={"/var/log/auth.log": 9001},
        )
        install_fake_paramiko(sftp)

        manager = CollectorManager()

        try:
            with patch(
                "app.logs.collector_manager.get_log_source_repository",
                return_value=source_repo,
            ), patch(
                "app.logs.repository.get_checkpoint_repository",
                return_value=checkpoint_repo,
            ), patch(
                "app.logs.repository.get_log_event_repository",
                return_value=log_event_repo,
            ), patch(
                "app.logs.repository.get_log_source_repository",
                return_value=source_repo,
            ), patch(
                "app.logs.event_bus_integration.get_event_bus_config",
                return_value=MagicMock(event_bus_enabled=True),
            ):
                # REAL CollectorManager.start_all() -> REAL LinuxSSHCollector
                # -> REAL .start()/.connect()/.collect()/._tail_file().
                await manager.start_all()

                for _ in range(30):
                    await asyncio.sleep(0.05)
                    if len(fake_kafka.sent) >= 5:
                        break

                await manager.stop_all()
        finally:
            uninstall_fake_paramiko()

        # --- Assert the collector really connected and processed the file ---
        #
        # VERIFIED ARCHITECTURAL FACT (confirmed by reading
        # LinuxSSHCollector._run_collection_loop() directly - it has no
        # get_log_event_repository()/log_event_repo.create() call anywhere,
        # unlike WindowsEventCollector._run_collection()): the Linux
        # collector's real code path publishes each LogEvent to the event
        # bus but does NOT independently persist it to the log_events table
        # itself. So log_event_repo.created will correctly stay empty here -
        # that is not a test bug, it is what the real collector does. The
        # publish boundary (fake_kafka.sent) is the only sink this
        # collector's real code actually writes to, so assertions below
        # verify against the published wire payloads instead.
        assert log_event_repo.created == [], (
            "Sanity check on the just-verified fact above: the real Linux "
            "collection loop does not call log_event_repo.create()."
        )
        assert len(fake_kafka.sent) == 5, (
            f"Expected 5 real parsed+published LogEvents (3 failed SSH, "
            f"1 success, 1 sudo) via the real LinuxSSHLogParser -> "
            f"LogEvent.from_parsed_entry() -> publish_log_event() chain, "
            f"got {len(fake_kafka.sent)}"
        )

        def _payload(sent: dict) -> dict:
            p = sent["value"]["payload"]
            assert sent["topic"] == "security-events"
            assert p["source_id"] == "linux-integration-1"
            assert p["source_type"] == "linux_ssh"
            # Round-trips through the real pydantic envelope model.
            SecurityEvent(**sent["value"])
            return p

        payloads = [_payload(s) for s in fake_kafka.sent]
        extracted = [p.get("extracted_fields", {}) for p in payloads]

        failed_events = [f for f in extracted if f.get("event_type") == "ssh_failed"]
        success_events = [
            f for f in extracted
            if f.get("event_type") in ("ssh_success", "ssh_key_auth")
        ]
        sudo_events = [f for f in extracted if f.get("event_type") == "sudo_success"]
        invalid_user_events = [
            f for f in extracted if f.get("event_type") == "ssh_invalid_user"
        ]

        assert len(failed_events) == 2, (
            "Expected 2 'Failed password' (non-invalid-user) SSH events "
            "parsed by the real LinuxSSHLogParser"
        )
        for fields in failed_events:
            assert fields.get("source_ip") == "203.0.113.77"
            assert fields.get("username") == "root"

        for p in payloads:
            assert p.get("hostname") == "prod-web01"

        assert len(invalid_user_events) == 1
        assert invalid_user_events[0].get("username") == "admin"
        assert invalid_user_events[0].get("source_ip") == "203.0.113.77"

        assert len(success_events) == 1
        assert success_events[0].get("username") == "deploy"
        assert success_events[0].get("source_ip") == "198.51.100.22"

        assert len(sudo_events) == 1
        assert sudo_events[0].get("username") == "deploy"
        assert sudo_events[0].get("target_user") == "root"
        assert "systemctl restart nginx" in sudo_events[0].get("command", "")

        # --- Assert checkpoint was advanced to end-of-file for this source ---
        saved_checkpoint = await checkpoint_repo.get("linux-integration-1")
        assert saved_checkpoint is not None
        file_states = saved_checkpoint.checkpoint_value["file_states"]
        assert "/var/log/auth.log" in file_states
        assert file_states["/var/log/auth.log"]["offset"] == len(AUTH_LOG_CONTENT)
        assert file_states["/var/log/auth.log"]["inode"] == 9001

    @pytest.mark.asyncio
    async def test_checkpoint_restart_resumes_without_reprocessing(
        self, fake_producer_wiring
    ):
        """Part 8 (checkpoint restart), exercised against the real
        LinuxSSHCollector + real CheckpointRepository behavior (not just
        asserting upsert() was called): start, process the initial file
        content, stop (saving a real checkpoint), append new lines, start
        again, and verify only the NEW lines are reprocessed."""
        producer, fake_kafka = fake_producer_wiring

        source = make_linux_source(id="linux-restart-1")
        source_repo = FakeLogSourceRepo([source])
        checkpoint_repo = FakeCheckpointRepo()  # same instance across both runs
        log_event_repo = FakeLogEventRepo()     # same instance across both runs

        initial_content = (
            "Oct  9 04:00:01 prod-web02 sshd[2001]: Failed password for root "
            "from 198.51.100.9 port 40001 ssh2\n"
        ).encode("utf-8")

        sftp_run1 = FakeSFTPClient(
            file_contents={"/var/log/auth.log": initial_content},
            inode_by_path={"/var/log/auth.log": 7001},
        )
        install_fake_paramiko(sftp_run1)

        patches = [
            patch("app.logs.collector_manager.get_log_source_repository", return_value=source_repo),
            patch("app.logs.repository.get_checkpoint_repository", return_value=checkpoint_repo),
            patch("app.logs.repository.get_log_event_repository", return_value=log_event_repo),
            patch("app.logs.repository.get_log_source_repository", return_value=source_repo),
            patch("app.logs.event_bus_integration.get_event_bus_config",
                  return_value=MagicMock(event_bus_enabled=True)),
        ]

        try:
            for p in patches:
                p.start()

            manager1 = CollectorManager()
            await manager1.start_all()
            for _ in range(30):
                await asyncio.sleep(0.05)
                if len(fake_kafka.sent) >= 1:
                    break
            await manager1.stop_all()
        finally:
            for p in patches:
                p.stop()
            uninstall_fake_paramiko()

        # NOTE: LinuxSSHCollector._run_collection_loop() publishes but does
        # not call log_event_repo.create() (confirmed architectural fact,
        # see the sibling test above) - so fake_kafka.sent is the real
        # signal here, not log_event_repo.created.
        assert len(fake_kafka.sent) == 1, "First run should publish exactly 1 event"

        # Real checkpoint must have been persisted with the end-of-file offset.
        checkpoint_after_run1 = await checkpoint_repo.get("linux-restart-1")
        assert checkpoint_after_run1 is not None
        offset_after_run1 = checkpoint_after_run1.checkpoint_value["file_states"][
            "/var/log/auth.log"
        ]["offset"]
        assert offset_after_run1 == len(initial_content)

        # --- Second run: same source, file now has old + new lines, same
        # inode (no rotation). The real collector must resume from the
        # saved offset and only process the appended line. ---
        appended_content = (
            "Oct  9 04:05:30 prod-web02 sshd[2050]: Accepted publickey for deploy "
            "from 198.51.100.22 port 55001 ssh2: ED25519 SHA256:zzzz9999\n"
        ).encode("utf-8")
        full_content_run2 = initial_content + appended_content

        sftp_run2 = FakeSFTPClient(
            file_contents={"/var/log/auth.log": full_content_run2},
            inode_by_path={"/var/log/auth.log": 7001},  # same inode - no rotation
        )
        install_fake_paramiko(sftp_run2)

        # Fresh source_repo/manager instance to simulate an actual process
        # restart, but SAME checkpoint_repo/log_event_repo instances, since
        # those represent the real persisted state surviving a restart.
        source_repo2 = FakeLogSourceRepo([make_linux_source(id="linux-restart-1")])

        patches2 = [
            patch("app.logs.collector_manager.get_log_source_repository", return_value=source_repo2),
            patch("app.logs.repository.get_checkpoint_repository", return_value=checkpoint_repo),
            patch("app.logs.repository.get_log_event_repository", return_value=log_event_repo),
            patch("app.logs.repository.get_log_source_repository", return_value=source_repo2),
            patch("app.logs.event_bus_integration.get_event_bus_config",
                  return_value=MagicMock(event_bus_enabled=True)),
        ]

        try:
            for p in patches2:
                p.start()

            manager2 = CollectorManager()
            await manager2.start_all()
            for _ in range(30):
                await asyncio.sleep(0.05)
                if len(fake_kafka.sent) >= 2:
                    break
            await manager2.stop_all()
        finally:
            for p in patches2:
                p.stop()
            uninstall_fake_paramiko()

        # Exactly ONE new event should have been added (the appended line) -
        # the already-processed first line must NOT be reprocessed.
        assert len(fake_kafka.sent) == 2, (
            f"Expected exactly 2 total published events across both runs (1 "
            f"from run 1 + 1 NEW from run 2) - got {len(fake_kafka.sent)}. "
            f"A count > 2 means the real checkpoint offset was not honored "
            f"and the old line was reprocessed."
        )
        new_payload = fake_kafka.sent[1]["value"]["payload"]
        new_fields = new_payload.get("extracted_fields", {})
        assert new_fields.get("username") == "deploy"
        assert new_fields.get("event_type") in ("ssh_success", "ssh_key_auth")

        # Checkpoint must have advanced again to the new end-of-file.
        checkpoint_after_run2 = await checkpoint_repo.get("linux-restart-1")
        offset_after_run2 = checkpoint_after_run2.checkpoint_value["file_states"][
            "/var/log/auth.log"
        ]["offset"]
        assert offset_after_run2 == len(full_content_run2)
        assert offset_after_run2 > offset_after_run1
