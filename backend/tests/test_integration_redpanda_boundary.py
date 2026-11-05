"""
CyberGuard AI - Redpanda Producer Boundary Integration Test (Step 3, Part 5)

Environment constraint (confirmed, not assumed): `docker ps`/`docker info`
fail in this environment - Docker Desktop is not running, so no live
Redpanda broker is reachable. Per the task's explicit fallback instruction
for this situation ("otherwise test real publish_log_event() serialization/
producer interface... Do NOT replace publish_log_event() with a fake
function merely to make the test pass"), this test exercises the REAL
chain:

    publish_log_event() (real)
            |
    log_event_to_security_event() (real)
            |
    EventProducer.publish() (real: topic resolution, to_json_dict(),
                              is_started check, logging)
            |
    EventProducer._producer.send_and_wait() <- ONLY THIS is faked (the
                                                 actual aiokafka network
                                                 call to the broker socket)

This is NOT a full end-to-end Redpanda integration test (no real broker is
involved) - it is the real serialization/producer-interface verification
the task permits as a fallback. The untested boundary is explicitly:
whether a real Redpanda broker actually accepts, stores, and makes
retrievable the exact bytes aiokafka's real send_and_wait() would transmit.
That boundary is NOT verified by this test and must be reported as such.

NOT mocked: publish_log_event(), log_event_to_security_event(),
EventProducer.publish(), EventProducer.is_started, redact_log_event().
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.logs.models import LogEvent, LogLevel, LogSourceType
from app.logs.event_bus_integration import (
    publish_log_event,
    publish_log_events_batch,
    log_event_to_security_event,
)
from app.event_bus.events import SecurityEvent
from app.event_bus.producer import EventProducer


class FakeSendResult:
    def __init__(self, partition: int = 0, offset: int = 7):
        self.partition = partition
        self.offset = offset


class FakeAIOKafkaProducer:
    """Fakes ONLY the aiokafka network call - the real broker socket
    boundary. Captures exactly what bytes/structure would have been sent
    to a real Redpanda broker."""

    def __init__(self):
        self.sent: list[dict] = []
        self.fail_next: bool = False

    async def send_and_wait(self, topic: str, value: dict, key=None):
        if self.fail_next:
            from aiokafka.errors import KafkaError
            raise KafkaError("Simulated broker unavailable")

        # Prove the value is genuinely JSON-serializable, the same
        # constraint a real AIOKafkaProducer's value_serializer enforces
        # (json.dumps(v).encode("utf-8") per producer.py's real config).
        wire_bytes = json.dumps(value).encode("utf-8")
        wire_key = key.encode("utf-8") if key else None

        self.sent.append({
            "topic": topic,
            "value": value,
            "key": key,
            "wire_bytes": wire_bytes,
            "wire_key": wire_key,
        })
        return FakeSendResult()


@pytest.fixture
def wired_producer():
    """Real EventProducer, with only its internal AIOKafkaProducer swapped
    for a fake that captures the wire payload instead of sending it."""
    producer = EventProducer()
    fake_kafka = FakeAIOKafkaProducer()
    producer._producer = fake_kafka
    producer._started = True

    with patch("app.logs.event_bus_integration.get_producer", return_value=producer), \
         patch("app.logs.event_bus_integration.get_event_bus_config",
               return_value=MagicMock(event_bus_enabled=True)):
        yield producer, fake_kafka


def make_log_event(**overrides) -> LogEvent:
    defaults = dict(
        source_id="redpanda-test-source",
        source_type=LogSourceType.LINUX_SSH,
        hostname="test-host-01",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.WARNING,
        message="Failed password for root from 203.0.113.5 port 22",
        raw_content="Oct  9 12:00:00 test-host-01 sshd[1]: Failed password for root "
                    "from 203.0.113.5 port 22 ssh2",
        extracted_fields={"username": "root", "source_ip": "203.0.113.5", "event_type": "ssh_failed"},
        tags=["linux", "authentication", "ssh_failed"],
        category="authentication",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


class TestRedpandaProducerBoundary:
    """Real publish_log_event() -> log_event_to_security_event() ->
    EventProducer.publish() chain, with only the aiokafka network send
    faked."""

    @pytest.mark.asyncio
    async def test_publish_log_event_reaches_broker_boundary_with_correct_shape(
        self, wired_producer
    ):
        producer, fake_kafka = wired_producer
        event = make_log_event()

        success = await publish_log_event(event)

        assert success is True
        assert len(fake_kafka.sent) == 1

        sent = fake_kafka.sent[0]
        assert sent["topic"] == "security-events"
        # Partition key: real publish_log_event() uses source_id as key.
        assert sent["key"] == "redpanda-test-source"
        assert sent["wire_key"] == b"redpanda-test-source"

        # The exact bytes a real broker socket would receive - proves
        # log_event_to_security_event()'s payload is genuinely
        # JSON-serializable (SecretStr/datetime/enum pitfalls would raise
        # here, not be silently swallowed).
        wire_payload = json.loads(sent["wire_bytes"])
        assert wire_payload["event_type"] == "log"
        assert wire_payload["source"] == "log_collector:linux_ssh"
        assert wire_payload["severity"] == "medium"  # WARNING -> MEDIUM per LOG_LEVEL_TO_SEVERITY
        assert wire_payload["payload"]["source_id"] == "redpanda-test-source"
        assert wire_payload["payload"]["hostname"] == "test-host-01"
        assert wire_payload["payload"]["extracted_fields"]["username"] == "root"
        assert wire_payload["payload"]["extracted_fields"]["source_ip"] == "203.0.113.5"

        # Confirms this is genuinely the real SecurityEvent envelope shape
        # (round-trips through the real pydantic model), not an ad-hoc dict.
        reconstructed = SecurityEvent(**wire_payload)
        assert reconstructed.event_type == "log"

    @pytest.mark.asyncio
    async def test_publish_log_event_applies_redaction_before_reaching_broker(
        self, wired_producer
    ):
        """Confirms the real redact_log_event() call inside
        publish_log_event() actually runs before the wire payload is built
        - a secret-looking value in raw_content must not reach the fake
        broker boundary unredacted."""
        producer, fake_kafka = wired_producer
        event = make_log_event(
            message="user admin authenticated with password=SuperSecret123!",
            raw_content="Oct  9 12:00:00 host sshd[1]: password=SuperSecret123! accepted",
        )

        await publish_log_event(event)

        wire_payload = fake_kafka.sent[0]["value"]
        serialized = json.dumps(wire_payload)
        assert "SuperSecret123!" not in serialized, (
            "Centralized redaction (redact_log_event) must strip secret-"
            "looking values before publish_log_event() reaches the "
            "producer boundary"
        )

    @pytest.mark.asyncio
    async def test_publish_log_event_returns_false_when_producer_not_started(
        self, wired_producer
    ):
        """Real is_started check - no live broker connection means
        publish must fail closed, not silently succeed."""
        producer, fake_kafka = wired_producer
        producer._started = False

        success = await publish_log_event(make_log_event())

        assert success is False
        assert len(fake_kafka.sent) == 0

    @pytest.mark.asyncio
    async def test_publish_log_event_returns_false_on_broker_error(self, wired_producer):
        """Simulated Redpanda-unavailable scenario (Part 9): the real
        KafkaError handling inside EventProducer.publish() must catch the
        error and return False, not raise or crash the caller."""
        producer, fake_kafka = wired_producer
        fake_kafka.fail_next = True

        success = await publish_log_event(make_log_event())

        assert success is False

    @pytest.mark.asyncio
    async def test_publish_log_events_batch_reaches_broker_for_each_event(
        self, wired_producer
    ):
        producer, fake_kafka = wired_producer
        events = [
            make_log_event(source_id="batch-1", message="event one"),
            make_log_event(source_id="batch-2", message="event two"),
            make_log_event(source_id="batch-3", message="event three"),
        ]

        success_count, failure_count = await publish_log_events_batch(events)

        assert success_count == 3
        assert failure_count == 0
        assert len(fake_kafka.sent) == 3
        sent_source_ids = {s["key"] for s in fake_kafka.sent}
        assert sent_source_ids == {"batch-1", "batch-2", "batch-3"}

    @pytest.mark.asyncio
    async def test_publish_log_events_batch_counts_partial_broker_failures(
        self, wired_producer
    ):
        """Part 9 (failure isolation at the publish layer): if the broker
        rejects one event mid-batch, the real publish_log_events_batch()
        loop must continue and accurately count successes vs failures,
        not abort the whole batch."""
        producer, fake_kafka = wired_producer

        original_send = fake_kafka.send_and_wait
        call_count = {"n": 0}

        async def flaky_send(topic, value, key=None):
            call_count["n"] += 1
            if call_count["n"] == 2:
                from aiokafka.errors import KafkaError
                raise KafkaError("Simulated transient broker error")
            return await original_send(topic, value, key)

        fake_kafka.send_and_wait = flaky_send

        events = [
            make_log_event(source_id="batch-a"),
            make_log_event(source_id="batch-b"),  # this one fails
            make_log_event(source_id="batch-c"),
        ]

        success_count, failure_count = await publish_log_events_batch(events)

        assert success_count == 2
        assert failure_count == 1

    def test_log_event_to_security_event_mapping_is_json_serializable(self):
        """Pure mapping-level check (no producer involved): the real
        conversion function alone must never produce a payload that fails
        JSON serialization, since that is the exact point a real broker
        send would blow up."""
        event = make_log_event()
        security_event = log_event_to_security_event(event)
        wire_dict = security_event.to_json_dict()

        # Must not raise - this is the real serializer aiokafka's
        # value_serializer uses (json.dumps(v).encode("utf-8")).
        json.dumps(wire_dict)

        assert wire_dict["payload"]["source_type"] == "linux_ssh"
