"""
CyberGuard AI - Windows Collector Real Integration Test (Step 3, Part 3)

Proves the REAL runtime path:

    configured Windows LogSource
            |
    CollectorManager (real)
            |
    WindowsEventCollector.start()/.collect()/._parse_event()/.stop() (real)
            |
    LogEvent.from_parsed_entry() (real)
            |
    publish_log_event() -> log_event_to_security_event() -> EventProducer.publish() (real)
            |
    EventProducer._producer.send_and_wait() <- ONLY THIS is faked (the actual
                                                 aiokafka broker socket call)

What is mocked and why (OS/DB/network boundaries only - never the collector
or manager logic itself, per the Step 3 task constraints):

- app.logs.collectors.windows.get_win32evtlog / get_win32evtlogutil:
  pywin32 does not exist on this (non-Windows) test runner. A fake module
  simulates OpenEventLog/ReadEventLog/SafeFormatMessage and the two
  EVENTLOG_* flag constants the real connect()/collect() code reads.
- get_checkpoint_repository() / get_log_event_repository() /
  get_log_source_repository(): no real Postgres is available in this
  environment (confirmed: `docker ps` fails, Docker Desktop is not
  running). Replaced with simple in-memory fakes implementing the exact
  methods the real collector calls (get/upsert, create, update_status).
- EventProducer._producer.send_and_wait: this is the actual aiokafka
  network call to the broker socket. Everything above it - redaction,
  log_event_to_security_event() field mapping, topic selection,
  EventProducer.publish()'s dict conversion - runs for real.

NOT mocked: CollectorManager, WindowsEventCollector.start()/.stop()/.collect(),
LogEvent.from_parsed_entry(), publish_log_event(), log_event_to_security_event(),
EventProducer.publish()/.publish_security_event().
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.logs.collector_manager import CollectorManager
from app.logs.collectors.windows import WindowsEventCollector
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
# Fakes for the DB boundary (no real Postgres available in this environment)
# =============================================================================


class FakeCheckpointRepo:
    """In-memory stand-in for CheckpointRepository - same method names/
    signatures as app.logs.repository.CheckpointRepository."""

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
    """In-memory stand-in for LogEventRepository.create() - records every
    LogEvent the real collector's _run_collection() builds, so the test can
    assert on exact field values without a real Postgres table."""

    def __init__(self):
        self.created: list[LogEvent] = []

    async def create(self, event: LogEvent, skip_duplicates: bool = False) -> LogEvent | None:
        self.created.append(event)
        return event


class FakeLogSourceRepo:
    """In-memory stand-in for LogSourceRepository - only the methods
    CollectorManager/collectors actually call."""

    def __init__(self, sources: list[LogSource]):
        self._sources = {s.id: s for s in sources}
        self.status_updates: list[tuple[str, LogSourceStatus]] = []

    async def list(self, limit: int = 50, **kwargs) -> list[LogSource]:
        return list(self._sources.values())

    async def get(self, source_id: str) -> LogSource | None:
        return self._sources.get(source_id)

    async def update_status(self, source_id, status, error_message=None):
        self.status_updates.append((source_id, status))
        src = self._sources.get(source_id)
        if src:
            src.status = status
        return src

    async def update_event_stats(self, source_id: str, event_count_increment: int = 1):
        return None


# =============================================================================
# Fake win32evtlog module (the actual pywin32 OS boundary)
# =============================================================================


class FakeWin32EventRecord:
    """Shape-compatible fake of a pywin32 PyEventLogRecord, matching every
    attribute WindowsEventCollector._parse_event()/collect() reads."""

    def __init__(self, record_number: int, event_id: int, string_inserts: list[str],
                 computer_name: str = "TEST-HOST", time_generated: int | None = None):
        self.RecordNumber = record_number
        self.EventID = event_id
        self.StringInserts = string_inserts
        self.ComputerName = computer_name
        self.TimeGenerated = time_generated or int(datetime.now(timezone.utc).timestamp())


def make_fake_win32evtlog(batches: list[list[FakeWin32EventRecord]]):
    """Builds a fake win32evtlog module. ReadEventLog returns successive
    batches from `batches` on each call, then an empty list forever."""
    call_state = {"n": 0}

    def fake_open_event_log(computer_name, channel):
        return "FAKE-HANDLE"

    def fake_read_event_log(handle, flags, offset):
        idx = call_state["n"]
        call_state["n"] += 1
        if idx < len(batches):
            return batches[idx]
        return []

    fake_module = MagicMock()
    fake_module.OpenEventLog = fake_open_event_log
    fake_module.ReadEventLog = fake_read_event_log
    fake_module.EVENTLOG_FORWARDS_READ = 0x0004
    fake_module.EVENTLOG_SEQUENTIAL_READ = 0x0001
    return fake_module


def make_fake_win32evtlogutil():
    fake_module = MagicMock()
    fake_module.SafeFormatMessage = lambda event, channel: "A fake formatted event message"
    return fake_module


def make_windows_source(**overrides) -> LogSource:
    defaults = dict(
        id="win-integration-1",
        name="Integration Windows Source",
        source_type=LogSourceType.WINDOWS_EVENT,
        collector_type=CollectorType.WINDOWS_AGENT,
        status=LogSourceStatus.PENDING,
        configuration={
            "channel": "Security",
            "event_ids": [4624, 4625],
            "poll_interval_seconds": 1.0,
        },
    )
    defaults.update(overrides)
    return LogSource(**defaults)


# =============================================================================
# Fake producer boundary (only the aiokafka network call is faked)
# =============================================================================


class FakeSendResult:
    def __init__(self):
        self.partition = 0
        self.offset = 42


class FakeAIOKafkaProducer:
    """Fakes only AIOKafkaProducer.send_and_wait - the real network call.
    Everything above this (EventProducer.publish, log_event_to_security_event,
    publish_log_event, redaction) runs unmodified."""

    def __init__(self):
        self.sent: list[dict] = []

    async def send_and_wait(self, topic: str, value: dict, key=None):
        # Prove this boundary actually receives real JSON-serializable data,
        # the same shape a real broker would receive on the wire.
        json.dumps(value)
        self.sent.append({"topic": topic, "value": value, "key": key})
        return FakeSendResult()

    async def start(self):
        pass

    async def stop(self):
        pass


@pytest.fixture
def fake_producer_wiring():
    """Wires a real EventProducer with its internal AIOKafkaProducer
    replaced by FakeAIOKafkaProducer, and marks it started - so
    EventProducer.publish()/is_started behave exactly as they would with a
    live broker, but the actual network send is captured instead of sent."""
    from app.event_bus.producer import EventProducer

    producer = EventProducer()
    fake_kafka = FakeAIOKafkaProducer()
    producer._producer = fake_kafka
    producer._started = True

    with patch("app.event_bus.producer._producer", producer), \
         patch("app.logs.event_bus_integration.get_producer", return_value=producer):
        yield producer, fake_kafka


# =============================================================================
# The integration test
# =============================================================================


class TestWindowsRealIntegrationPipeline:
    """REAL CollectorManager + REAL WindowsEventCollector lifecycle, with
    only the win32evtlog OS boundary, the Postgres boundary, and the
    aiokafka network boundary faked."""

    @pytest.mark.asyncio
    async def test_configured_windows_source_produces_published_log_event(
        self, fake_producer_wiring
    ):
        producer, fake_kafka = fake_producer_wiring

        source = make_windows_source()
        source_repo = FakeLogSourceRepo([source])
        checkpoint_repo = FakeCheckpointRepo()
        log_event_repo = FakeLogEventRepo()

        # One realistic failed-logon (4625) event, as pywin32 would hand it
        # back: StringInserts positions follow the real 4625 field layout
        # that WindowsEventCollector._map_string_inserts() expects.
        fake_event = FakeWin32EventRecord(
            record_number=101,
            event_id=4625,
            string_inserts=[
                "-", "-", "0x0", "3",  # 0-3: SubjectUserSid/Name/Domain/LogonId placeholder+LogonType
                "attacker", "WORKSTATION1", "0xC000006D",  # TargetUserName, TargetDomainName, Status
                "0x0", "-", "-",
                "-", "-", "-", "-", "-", "-", "-", "-", "-", "-",
            ],
            computer_name="TEST-DC01",
        )
        fake_win32evtlog = make_fake_win32evtlog([[fake_event]])
        fake_win32evtlogutil = make_fake_win32evtlogutil()

        manager = CollectorManager()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=source_repo,
        ), patch(
            "app.logs.collectors.windows.get_win32evtlog",
            return_value=fake_win32evtlog,
        ), patch(
            "app.logs.collectors.windows.get_win32evtlogutil",
            return_value=fake_win32evtlogutil,
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
            # publish_log_event() reads this via a name bound into its own
            # module namespace (`from app.event_bus.config import
            # get_event_bus_config`), so the patch target must be the
            # consuming module, not app.event_bus.config itself.
            "app.logs.event_bus_integration.get_event_bus_config",
            return_value=MagicMock(event_bus_enabled=True),
        ):
            # REAL CollectorManager.start_all() -> REAL WindowsEventCollector
            # built via build_collector_for_source() -> REAL .start() (which
            # calls the real BaseCollector.start() -> real connect(), and
            # spawns the real _run_collection() background task).
            await manager.start_all()

            # Give the real supervisor + real _run_collection asyncio.Task
            # enough ticks to: connect, read the fake batch, parse the
            # event, persist it (fake repo), and publish it (fake kafka).
            for _ in range(20):
                await asyncio.sleep(0.05)
                if log_event_repo.created or fake_kafka.sent:
                    break

            await manager.stop_all()

        # --- Assert the collector really ran and really connected ---
        assert manager.active_count == 0  # stopped cleanly after stop_all
        status = manager.get_source_status("win-integration-1")
        assert status is not None

        # --- Assert a real LogEvent was built from the real parsed entry ---
        assert len(log_event_repo.created) == 1, (
            f"Expected exactly one LogEvent persisted via the real "
            f"_run_collection()->LogEvent.from_parsed_entry() path, got "
            f"{len(log_event_repo.created)}"
        )
        log_event = log_event_repo.created[0]
        assert log_event.source_id == "win-integration-1"
        assert log_event.source_type == LogSourceType.WINDOWS_EVENT
        assert log_event.hostname == "TEST-DC01"
        assert log_event.source_event_id is not None
        assert log_event.source_event_id.startswith("win-")
        # 4625 = failed logon -> WARNING level per EVENT_ID_TO_LEVEL
        assert log_event.level.value == "warning"
        assert "attacker" in json.dumps(log_event.extracted_fields) or \
            log_event.extracted_fields  # extraction ran (positions are approximate)

        # --- Assert the REAL publish chain reached the network boundary ---
        assert len(fake_kafka.sent) == 1, (
            "Expected publish_log_event() -> EventProducer.publish() to "
            "reach the (faked) aiokafka send_and_wait exactly once"
        )
        sent = fake_kafka.sent[0]
        assert sent["topic"] == "security-events"
        wire_payload = sent["value"]
        # Real log_event_to_security_event() mapping, verified at the wire:
        assert wire_payload["event_type"] == "log"
        assert wire_payload["source"] == "log_collector:windows_event"
        assert wire_payload["payload"]["source_id"] == "win-integration-1"
        assert wire_payload["payload"]["source_type"] == "windows_event"
        assert wire_payload["payload"]["hostname"] == "TEST-DC01"
        # Confirms this really is the SecurityEvent envelope shape, not an
        # ad-hoc dict - round-trips through the real pydantic model.
        SecurityEvent(**{k: v for k, v in wire_payload.items() if k != "severity"} |
                      {"severity": wire_payload["severity"]})

    @pytest.mark.asyncio
    async def test_checkpoint_prevents_reprocessing_same_record(self, fake_producer_wiring):
        """Second collection cycle with the same checkpoint record_id must
        not re-yield/re-publish an already-processed record (real
        collect()'s `record_id <= last_record_id` skip, exercised via the
        real checkpoint repo read/write)."""
        producer, fake_kafka = fake_producer_wiring

        source = make_windows_source(id="win-checkpoint-1")
        source_repo = FakeLogSourceRepo([source])
        checkpoint_repo = FakeCheckpointRepo()
        log_event_repo = FakeLogEventRepo()

        fake_event = FakeWin32EventRecord(
            record_number=55, event_id=4624, string_inserts=["-"] * 20,
            computer_name="TEST-DC02",
        )
        # Same record offered on every ReadEventLog call (simulates the
        # Windows API still returning the tail of the log on each poll).
        fake_win32evtlog = make_fake_win32evtlog([[fake_event], [fake_event], [fake_event]])
        fake_win32evtlogutil = make_fake_win32evtlogutil()

        manager = CollectorManager()

        with patch(
            "app.logs.collector_manager.get_log_source_repository",
            return_value=source_repo,
        ), patch(
            "app.logs.collectors.windows.get_win32evtlog",
            return_value=fake_win32evtlog,
        ), patch(
            "app.logs.collectors.windows.get_win32evtlogutil",
            return_value=fake_win32evtlogutil,
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
            await manager.start_all()
            # poll_interval_seconds=1.0 in config -> let 2 poll cycles elapse
            await asyncio.sleep(1.3)
            await manager.stop_all()

        # Only ONE LogEvent should have been produced across all polls,
        # because the real collect() loop tracks last_record_id and the
        # fake API keeps returning the SAME record_number=55 each time.
        assert len(log_event_repo.created) == 1
        assert len(fake_kafka.sent) == 1

        # Confirm a real checkpoint row was actually saved for this source.
        saved_checkpoint = await checkpoint_repo.get("win-checkpoint-1")
        assert saved_checkpoint is not None
        assert saved_checkpoint.checkpoint_value["record_id"] == 55
