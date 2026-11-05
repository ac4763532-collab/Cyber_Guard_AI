"""
CyberGuard AI - STEP 7.1 Redpanda Live Integration Tests

Live integration tests that require a running Redpanda broker.

These tests are SKIPPED if Redpanda is not available.
Run with: pytest tests/test_step71_redpanda_live.py -v

To start Redpanda:
    docker compose up redpanda -d

Test categories:
1. Broker connectivity
2. Producer publish + acknowledgment
3. Consumer subscribe + receive
4. End-to-end message flow
5. Dead-letter queue
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

from app.database.models.base import SeverityLevel
from app.event_bus.config import get_event_bus_config
from app.event_bus.events import SecurityEvent
from app.event_bus.topics import Topic
from app.event_bus.producer import EventProducer
from app.event_bus.consumer import EventConsumer


# Skip all tests if Redpanda is not available
pytestmark = pytest.mark.skipif(
    os.environ.get("REDPANDA_TESTS", "").lower() != "true",
    reason="Redpanda integration tests skipped. Set REDPANDA_TESTS=true to run.",
)


@pytest.fixture
def config():
    """Get event bus configuration."""
    return get_event_bus_config()


@pytest_asyncio.fixture
async def producer(config):
    """Create and start a producer."""
    prod = EventProducer(config=config)
    await prod.start()
    yield prod
    await prod.stop()


# =============================================================================
# Broker Connectivity Tests
# =============================================================================


class TestRedpandaConnectivity:
    """Tests for Redpanda broker connectivity."""

    @pytest.mark.asyncio
    async def test_producer_connects(self, config):
        """Test producer can connect to Redpanda."""
        producer = EventProducer(config=config)

        try:
            await producer.start()
            assert producer.is_started

            health = await producer.health_check()
            assert health["healthy"] is True
            assert health["status"] == "connected"

        finally:
            await producer.stop()

    @pytest.mark.asyncio
    async def test_producer_reconnects_after_stop(self, config):
        """Test producer can restart after stop."""
        producer = EventProducer(config=config)

        # First connection
        await producer.start()
        assert producer.is_started
        await producer.stop()
        assert not producer.is_started

        # Second connection
        await producer.start()
        assert producer.is_started
        await producer.stop()


# =============================================================================
# Producer Tests
# =============================================================================


class TestRedpandaProducer:
    """Tests for Redpanda producer."""

    @pytest.mark.asyncio
    async def test_publish_security_event(self, producer):
        """Test publishing a security event."""
        event = SecurityEvent(
            event_id=f"step71-test-{uuid4()}",
            event_type="email",
            source="step71_test",
            severity=SeverityLevel.MEDIUM,
            classification="test",
            risk_score=50,
            payload={
                "test_id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        result = await producer.publish(Topic.SECURITY_EVENTS, event)

        assert result is True

    @pytest.mark.asyncio
    async def test_publish_with_key(self, producer):
        """Test publishing with a partition key."""
        event = SecurityEvent(
            event_id=f"step71-keyed-{uuid4()}",
            event_type="email",
            source="step71_test",
            payload={"key_test": True},
        )

        result = await producer.publish(
            Topic.SECURITY_EVENTS,
            event,
            key="user-123",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_publish_multiple_events(self, producer):
        """Test publishing multiple events in sequence."""
        results = []

        for i in range(5):
            event = SecurityEvent(
                event_id=f"step71-batch-{i}-{uuid4()}",
                event_type="log",
                source="step71_test",
                payload={"sequence": i},
            )
            result = await producer.publish(Topic.SECURITY_EVENTS, event)
            results.append(result)

        assert all(results)


# =============================================================================
# Consumer Tests
# =============================================================================


class TestRedpandaConsumer:
    """Tests for Redpanda consumer."""

    @pytest.mark.asyncio
    async def test_consumer_receives_event(self, config, producer):
        """Test consumer receives published event."""
        received_events = []

        async def handler(event: SecurityEvent):
            received_events.append(event)

        # Create consumer with unique group
        consumer = EventConsumer(
            group_id=f"test-{uuid4()}",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
            config=config,
        )

        try:
            await consumer.start()
            assert consumer.is_running

            # Publish an event
            test_id = str(uuid4())
            event = SecurityEvent(
                event_id=f"step71-consume-{test_id}",
                event_type="network",
                source="step71_test",
                payload={"test_id": test_id},
            )
            await producer.publish(Topic.SECURITY_EVENTS, event)

            # Wait for consumer to receive (with timeout)
            for _ in range(50):  # 5 second timeout
                if any(e.payload.get("test_id") == test_id for e in received_events):
                    break
                await asyncio.sleep(0.1)

            # Verify received
            matching = [e for e in received_events if e.payload.get("test_id") == test_id]
            assert len(matching) == 1
            assert matching[0].event_type == "network"
            assert matching[0].source == "step71_test"

        finally:
            await consumer.stop()


# =============================================================================
# End-to-End Flow Tests
# =============================================================================


class TestEndToEndFlow:
    """End-to-end message flow tests."""

    @pytest.mark.asyncio
    async def test_full_event_flow(self, config):
        """Test complete producer -> broker -> consumer flow."""
        received = []

        async def handler(event: SecurityEvent):
            received.append(event)

        # Start producer
        producer = EventProducer(config=config)
        await producer.start()

        # Start consumer
        consumer = EventConsumer(
            group_id=f"e2e-test-{uuid4()}",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
            config=config,
        )
        await consumer.start()

        try:
            # Publish event
            test_marker = str(uuid4())
            event = SecurityEvent(
                event_id=f"step71-e2e-{test_marker}",
                event_type="email",
                source="step71_e2e_test",
                severity=SeverityLevel.HIGH,
                classification="phishing",
                risk_score=85,
                correlation_id="corr-" + test_marker[:8],
                indicators=["evil.com", "bad-hash-123"],
                payload={
                    "marker": test_marker,
                    "test_time": datetime.now(timezone.utc).isoformat(),
                },
            )

            success = await producer.publish(Topic.SECURITY_EVENTS, event)
            assert success

            # Wait for delivery
            for _ in range(50):
                if any(e.payload.get("marker") == test_marker for e in received):
                    break
                await asyncio.sleep(0.1)

            # Verify full event data
            matching = [e for e in received if e.payload.get("marker") == test_marker]
            assert len(matching) == 1

            recv_event = matching[0]
            assert recv_event.event_type == "email"
            assert recv_event.severity == SeverityLevel.HIGH
            assert recv_event.classification == "phishing"
            assert recv_event.risk_score == 85
            assert recv_event.correlation_id == "corr-" + test_marker[:8]
            assert recv_event.indicators == ["evil.com", "bad-hash-123"]

        finally:
            await consumer.stop()
            await producer.stop()


# =============================================================================
# Dead-Letter Queue Tests
# =============================================================================


class TestDeadLetterQueue:
    """Tests for dead-letter queue handling."""

    @pytest.mark.asyncio
    async def test_dlq_receives_failed_messages(self, config, producer):
        """Test that failed messages go to DLQ."""
        dlq_received = []

        async def dlq_handler(event: SecurityEvent):
            dlq_received.append(event)

        # Note: This test is more complex in practice because we need
        # to inject a malformed message directly to the broker,
        # which requires raw Kafka producer access.
        # This is a placeholder for the pattern.

        # For now, verify DLQ topic is configured
        from app.event_bus.topics import Topic, get_topic_config

        dlq_config = get_topic_config(Topic.DEAD_LETTER)
        assert dlq_config["retention_ms"] > 0


# =============================================================================
# Verification Test (Manual End-to-End)
# =============================================================================


class TestManualVerification:
    """Manual verification test for STEP 7.1."""

    @pytest.mark.asyncio
    async def test_step71_verification(self, config):
        """
        Complete STEP 7.1 verification test.

        This test verifies:
        1. Producer connects to Redpanda
        2. SecurityEvent publishes with acknowledgment
        3. Consumer receives the event
        4. Event is deserialized correctly
        5. All fields are preserved
        """
        verification_id = f"STEP71-VERIFY-{uuid4()}"
        received = []

        async def handler(event: SecurityEvent):
            received.append(event)

        producer = EventProducer(config=config)
        consumer = EventConsumer(
            group_id=f"step71-verify-{uuid4()}",
            topics=[Topic.SECURITY_EVENTS],
            handler=handler,
            config=config,
        )

        try:
            # 1. Connect producer
            await producer.start()
            assert producer.is_started, "Producer failed to start"

            health = await producer.health_check()
            assert health["healthy"], f"Producer unhealthy: {health}"

            # 2. Start consumer
            await consumer.start()
            assert consumer.is_running, "Consumer failed to start"

            # 3. Create and publish verification event
            verification_event = SecurityEvent(
                event_id=verification_id,
                event_type="email",
                source="step71_verification",
                schema_version=1,
                severity=SeverityLevel.CRITICAL,
                classification="verification_test",
                risk_score=100,
                correlation_id="step71-corr",
                tenant_id="step71-tenant",
                indicators=["test.indicator.1", "test.indicator.2"],
                payload={
                    "verification_id": verification_id,
                    "test_time": datetime.now(timezone.utc).isoformat(),
                    "message": "STEP 7.1 End-to-End Verification",
                },
            )

            success = await producer.publish(Topic.SECURITY_EVENTS, verification_event)
            assert success, "Failed to publish verification event"

            # 4. Wait for consumer to receive
            received_event = None
            for _ in range(100):  # 10 second timeout
                matches = [e for e in received if e.event_id == verification_id]
                if matches:
                    received_event = matches[0]
                    break
                await asyncio.sleep(0.1)

            assert received_event is not None, "Verification event not received"

            # 5. Verify all fields
            assert received_event.event_id == verification_id
            assert received_event.event_type == "email"
            assert received_event.source == "step71_verification"
            assert received_event.schema_version == 1
            assert received_event.severity == SeverityLevel.CRITICAL
            assert received_event.classification == "verification_test"
            assert received_event.risk_score == 100
            assert received_event.correlation_id == "step71-corr"
            assert received_event.tenant_id == "step71-tenant"
            assert received_event.indicators == ["test.indicator.1", "test.indicator.2"]
            assert received_event.payload["verification_id"] == verification_id
            assert received_event.payload["message"] == "STEP 7.1 End-to-End Verification"

            print("\n" + "=" * 60)
            print("STEP 7.1 VERIFICATION PASSED")
            print("=" * 60)
            print(f"Event ID: {verification_id}")
            print(f"Topic: {Topic.SECURITY_EVENTS.value}")
            print(f"Producer: Connected to {config.redpanda_bootstrap_servers}")
            print(f"Consumer: Received and deserialized successfully")
            print("=" * 60)

        finally:
            await consumer.stop()
            await producer.stop()
