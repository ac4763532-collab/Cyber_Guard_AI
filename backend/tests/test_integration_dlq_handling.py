"""
CyberGuard AI - Dead Letter Queue / Failure Isolation Integration Test
(Step 3, Part 9)

Proves the REAL failure-isolation path inside EventConsumer, exercising all
three distinct failure branches of its real `_process_message()` method and
confirming each one reaches the real `_send_to_dlq()` -> real
`EventProducer.publish()` call with the correct `failure_type`:

    EventConsumer._process_message(record)  (real)
            |
    1) bad JSON / undecodable bytes -> failure_type="deserialization"
    2) valid JSON, fails SecurityEvent schema -> failure_type="validation"
    3) valid SecurityEvent, handler raises -> failure_type="processing"
            |
    EventConsumer._send_to_dlq(...)  (real: builds a real DeadLetterEvent,
                                       calls get_producer().publish(...))
            |
    EventProducer.publish()  (real: topic resolution, to_json_dict())
            |
    EventProducer._producer.send_and_wait()  <- ONLY THIS is faked (the
                                                 actual aiokafka network call)

This directly tests the task's "failure isolation" requirement: a single
malformed/invalid/handler-crashing message must not crash the consumer loop
and must be isolated onto Topic.DEAD_LETTER with enough context (original
topic/partition/offset, failure_reason, failure_type) to investigate later.

Explicit untested boundary (same category as Parts 5/6 - stated once, not
re-litigated): no live Redpanda broker and no real AIOKafkaConsumer
getmany()/background _consume_loop() are involved. `_process_message()` is
called directly with a fake aiokafka ConsumerRecord-shaped object - this is
the real per-message handler the real _consume_loop() would call after
getmany() returned a batch, so everything one hop downstream of the network
poll (deserialization, validation, handler dispatch, DLQ publish) is real.
Whether a real broker actually stores/delivers a DLQ message is NOT verified
here.

What is mocked (external boundary only):
- EventProducer._producer.send_and_wait - the actual aiokafka broker socket
  call, via app.event_bus.consumer.get_producer (the name as bound into
  consumer.py's own module namespace via `from app.event_bus.producer import
  get_producer` - the same name-binding pattern already identified as the
  correct patch target in Parts 3/5).

NOT mocked: EventConsumer (real, unmodified), EventConsumer._process_message(),
EventConsumer._send_to_dlq(), SecurityEvent.model_validate(), DeadLetterEvent,
EventProducer.publish().
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.event_bus.consumer import EventConsumer
from app.event_bus.events import DeadLetterEvent, SecurityEvent
from app.event_bus.producer import EventProducer
from app.event_bus.topics import Topic


class FakeSendResult:
    def __init__(self):
        self.partition = 0
        self.offset = 99


class FakeAIOKafkaProducer:
    """Fakes only the aiokafka network call - the real broker socket
    boundary. Captures exactly what a real DLQ publish would transmit."""

    def __init__(self):
        self.sent: list[dict] = []

    async def send_and_wait(self, topic: str, value: dict, key=None):
        wire_bytes = json.dumps(value).encode("utf-8")
        self.sent.append({"topic": topic, "value": value, "key": key, "wire_bytes": wire_bytes})
        return FakeSendResult()

    async def start(self):
        pass

    async def stop(self):
        pass


class FakeConsumerRecord:
    """Shape-compatible fake of an aiokafka ConsumerRecord - matching every
    attribute EventConsumer._process_message()/_send_to_dlq() reads."""

    def __init__(self, value, topic: str = "security-events", partition: int = 0, offset: int = 123):
        self.value = value
        self.topic = topic
        self.partition = partition
        self.offset = offset


@pytest.fixture
def wired_dlq_producer():
    """Real EventProducer with only its internal AIOKafkaProducer swapped
    for a fake. Patches app.event_bus.consumer.get_producer specifically -
    the name as bound into consumer.py's own module namespace via
    `from app.event_bus.producer import get_producer` - not
    app.event_bus.producer.get_producer, mirroring the exact patch-target
    bug already fixed in Part 3's test."""
    producer = EventProducer()
    fake_kafka = FakeAIOKafkaProducer()
    producer._producer = fake_kafka
    producer._started = True

    with patch("app.event_bus.consumer.get_producer", return_value=producer):
        yield producer, fake_kafka


def make_valid_security_event_dict(**overrides) -> dict:
    """A real SecurityEvent, serialized to the exact wire dict shape a real
    consumer would deserialize off the wire (round-trips through the real
    pydantic model, same as Part 5's wire-shape check)."""
    event = SecurityEvent(
        event_id="evt-dlq-test-1",
        event_type="log",
        schema_version=1,
        timestamp=datetime.now(timezone.utc),
        source="log_collector:linux_ssh",
        severity="medium",
        classification="authentication",
        risk_score=0,
        indicators=[],
        payload={
            "log_event_id": "le-1",
            "source_id": "dlq-test-source",
            "source_type": "linux_ssh",
            "hostname": "test-host",
            "message": "Failed password for root from 203.0.113.9",
            "raw_content": "Oct  9 00:00:00 test-host sshd[1]: Failed password for root "
                            "from 203.0.113.9 port 22 ssh2",
            "extracted_fields": {},
            "tags": [],
            "category": "authentication",
        },
    )
    wire_dict = event.to_json_dict()
    wire_dict.update(overrides)
    return wire_dict


class TestDeadLetterQueueFailureIsolation:
    """Real EventConsumer._process_message() exercised directly (bypassing
    only the network-poll leg), proving all three real failure branches
    correctly isolate a bad message onto Topic.DEAD_LETTER instead of
    crashing or silently dropping it."""

    @pytest.mark.asyncio
    async def test_malformed_json_record_sent_to_dlq_as_deserialization_failure(
        self, wired_dlq_producer
    ):
        """Real _process_message() must catch JSONDecodeError on genuinely
        undecodable bytes and route to _send_to_dlq() with
        failure_type="deserialization", not raise or crash the loop."""
        producer, fake_kafka = wired_dlq_producer

        handler_calls = []

        async def handler(event: SecurityEvent) -> None:
            handler_calls.append(event)

        consumer = EventConsumer(
            group_id="dlq-test",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
        )

        bad_record = FakeConsumerRecord(
            value=b"{not valid json at all!!!",
            topic="security-events",
            partition=2,
            offset=555,
        )

        # Must not raise - real _process_message() catches this internally.
        await consumer._process_message(bad_record)

        assert len(handler_calls) == 0, (
            "The real handler must never be invoked for an undecodable "
            "message"
        )
        assert len(fake_kafka.sent) == 1, (
            "Expected exactly one real DLQ publish via the real "
            "_send_to_dlq() -> EventProducer.publish() chain"
        )

        sent = fake_kafka.sent[0]
        assert sent["topic"] == Topic.DEAD_LETTER.value

        dlq_wire = sent["value"]
        # Confirms this is genuinely the real DeadLetterEvent envelope shape,
        # round-tripping through the real pydantic model.
        dlq_event = DeadLetterEvent(**dlq_wire)
        assert dlq_event.failure_type == "deserialization"
        assert dlq_event.original_topic == "security-events"
        assert dlq_event.original_partition == 2
        assert dlq_event.original_offset == 555
        assert "deserialization" in dlq_event.failure_reason.lower() or \
            "json" in dlq_event.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_schema_invalid_payload_sent_to_dlq_as_validation_failure(
        self, wired_dlq_producer
    ):
        """Real _process_message() must catch pydantic ValidationError when
        the JSON is well-formed but does not satisfy SecurityEvent's real
        schema, routing to _send_to_dlq() with failure_type="validation"."""
        producer, fake_kafka = wired_dlq_producer

        handler_calls = []

        async def handler(event: SecurityEvent) -> None:
            handler_calls.append(event)

        consumer = EventConsumer(
            group_id="dlq-test",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
        )

        # Valid JSON, but missing required SecurityEvent fields entirely
        # (no event_id/event_type/source/etc) - real model_validate() must
        # reject this.
        invalid_payload = {"this": "is not a security event", "foo": 123}
        bad_record = FakeConsumerRecord(
            value=json.dumps(invalid_payload).encode("utf-8"),
            topic="security-events",
            partition=0,
            offset=777,
        )

        await consumer._process_message(bad_record)

        assert len(handler_calls) == 0, (
            "The real handler must never be invoked for a schema-invalid "
            "event"
        )
        assert len(fake_kafka.sent) == 1
        sent = fake_kafka.sent[0]
        assert sent["topic"] == Topic.DEAD_LETTER.value

        dlq_event = DeadLetterEvent(**sent["value"])
        assert dlq_event.failure_type == "validation"
        assert dlq_event.original_offset == 777
        assert dlq_event.original_event_id == "unknown", (
            "event_id cannot be extracted from a payload that never "
            "contained one - real _process_message() defaults it to "
            "'unknown' before validation fails"
        )
        assert "validation" in dlq_event.failure_reason.lower() or \
            "field" in dlq_event.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_handler_exception_sent_to_dlq_as_processing_failure(
        self, wired_dlq_producer
    ):
        """Real _process_message() must catch an exception raised by the
        real downstream handler (e.g. handle_security_event ultimately
        raising) and route to _send_to_dlq() with
        failure_type="processing" - proving one bad event's handler crash
        does not take down the consumer loop or silently vanish."""
        producer, fake_kafka = wired_dlq_producer

        async def crashing_handler(event: SecurityEvent) -> None:
            raise RuntimeError("Simulated downstream agent/dispatch crash")

        consumer = EventConsumer(
            group_id="dlq-test",
            topics=[Topic.SECURITY_EVENTS],
            handler=crashing_handler,
        )

        valid_wire = make_valid_security_event_dict()
        good_record = FakeConsumerRecord(
            value=json.dumps(valid_wire).encode("utf-8"),
            topic="security-events",
            partition=1,
            offset=321,
        )

        # Must not raise - the real outer try/except around self._handler(event)
        # call must catch RuntimeError and isolate it via _send_to_dlq().
        await consumer._process_message(good_record)

        assert len(fake_kafka.sent) == 1, (
            "A handler exception on a schema-valid event must still "
            "produce exactly one real DLQ publish"
        )
        sent = fake_kafka.sent[0]
        assert sent["topic"] == Topic.DEAD_LETTER.value

        dlq_event = DeadLetterEvent(**sent["value"])
        assert dlq_event.failure_type == "processing"
        assert dlq_event.original_event_id == "evt-dlq-test-1", (
            "event_id IS extractable here (the payload parsed and "
            "validated fine before the handler raised), so the real code "
            "must carry it through to the DLQ record rather than "
            "defaulting to 'unknown'"
        )
        assert "Simulated downstream agent/dispatch crash" in dlq_event.failure_reason or \
            "handler" in dlq_event.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_one_bad_message_does_not_block_the_next_good_message(
        self, wired_dlq_producer
    ):
        """Failure isolation, proven across messages: processing a
        malformed record must not leave the real EventConsumer in a state
        that prevents a subsequent well-formed record from reaching the
        real handler normally (no shared broken state, no crashed loop)."""
        producer, fake_kafka = wired_dlq_producer

        handler_calls = []

        async def handler(event: SecurityEvent) -> None:
            handler_calls.append(event)

        consumer = EventConsumer(
            group_id="dlq-test",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
        )

        bad_record = FakeConsumerRecord(
            value=b"totally not json",
            topic="security-events",
            partition=0,
            offset=1,
        )
        good_record = FakeConsumerRecord(
            value=json.dumps(make_valid_security_event_dict()).encode("utf-8"),
            topic="security-events",
            partition=0,
            offset=2,
        )

        await consumer._process_message(bad_record)
        await consumer._process_message(good_record)

        assert len(handler_calls) == 1, (
            "The real handler must still run normally for the good "
            "message immediately after a bad one was isolated"
        )
        assert handler_calls[0].event_id == "evt-dlq-test-1"

        # Exactly one DLQ publish (for the bad record only) plus the good
        # record's normal handler path - never two DLQ publishes.
        assert len(fake_kafka.sent) == 1
        dlq_event = DeadLetterEvent(**fake_kafka.sent[0]["value"])
        assert dlq_event.failure_type == "deserialization"
        assert dlq_event.original_offset == 1

    @pytest.mark.asyncio
    async def test_dlq_publish_itself_failing_does_not_crash_process_message(
        self, wired_dlq_producer
    ):
        """Part 9's own failure-isolation requirement applied recursively:
        if the DLQ publish itself fails (e.g. producer not started / broker
        down), the real _send_to_dlq()'s own try/except must swallow that
        and _process_message() must still return normally, not raise."""
        producer, fake_kafka = wired_dlq_producer
        # Simulate the producer boundary itself being unavailable.
        producer._started = False

        async def handler(event: SecurityEvent) -> None:
            pass

        consumer = EventConsumer(
            group_id="dlq-test",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
        )

        bad_record = FakeConsumerRecord(value=b"not json", topic="security-events")

        # Must not raise even though the DLQ publish path itself cannot
        # reach a "started" producer.
        await consumer._process_message(bad_record)

        assert len(fake_kafka.sent) == 0, (
            "producer.is_started is False, so real _send_to_dlq() must "
            "skip the actual publish call entirely (per its real "
            "is_started check) rather than erroring"
        )
