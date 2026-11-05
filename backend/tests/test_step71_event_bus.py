"""
CyberGuard AI - STEP 7.1 Event Bus Integration Tests

Tests for Redpanda/Kafka event bus functionality.

Test categories:
1. Configuration tests
2. Event model tests
3. Producer tests (mocked broker)
4. Consumer tests (mocked broker)
5. Dispatcher integration tests
6. Dead-letter queue tests

Note: These tests use mocking for Kafka operations since the actual
Redpanda broker may not be available in CI. Integration tests with
a real broker are in test_step71_redpanda_live.py.
"""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.database.models.base import EventType, SeverityLevel
from app.event_bus.config import EventBusConfig, get_event_bus_config
from app.event_bus.events import EventEnvelope, SecurityEvent, DeadLetterEvent
from app.event_bus.topics import Topic, TOPIC_CONFIGS, get_topic_config
from app.event_bus.producer import EventProducer
from app.event_bus.consumer import EventConsumer


# =============================================================================
# Configuration Tests
# =============================================================================


class TestEventBusConfig:
    """Tests for EventBusConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = EventBusConfig()

        assert config.redpanda_bootstrap_servers == "localhost:9092"
        assert config.producer_acks == "all"
        assert config.producer_retries == 3
        assert config.consumer_group_prefix == "cyberguard"
        assert config.event_schema_version == 1
        assert config.event_bus_enabled is True

    def test_bootstrap_servers_list(self):
        """Test bootstrap servers parsing."""
        config = EventBusConfig(
            redpanda_bootstrap_servers="host1:9092,host2:9092,host3:9092"
        )

        assert config.bootstrap_servers_list == [
            "host1:9092",
            "host2:9092",
            "host3:9092",
        ]

    def test_cached_config(self):
        """Test config caching."""
        config1 = get_event_bus_config()
        config2 = get_event_bus_config()

        assert config1 is config2


# =============================================================================
# Topic Tests
# =============================================================================


class TestTopics:
    """Tests for topic definitions."""

    def test_topic_names(self):
        """Test topic enum values."""
        assert Topic.SECURITY_EVENTS.value == "security-events"
        assert Topic.DEAD_LETTER.value == "dead-letter"

    def test_topic_configs(self):
        """Test topic configurations exist."""
        assert Topic.SECURITY_EVENTS in TOPIC_CONFIGS
        assert Topic.DEAD_LETTER in TOPIC_CONFIGS

    def test_get_topic_config(self):
        """Test get_topic_config function."""
        config = get_topic_config(Topic.SECURITY_EVENTS)

        assert "num_partitions" in config
        assert "retention_ms" in config
        assert config["num_partitions"] == 3

    def test_dlq_longer_retention(self):
        """Test DLQ has longer retention than main topics."""
        security_config = get_topic_config(Topic.SECURITY_EVENTS)
        dlq_config = get_topic_config(Topic.DEAD_LETTER)

        assert dlq_config["retention_ms"] > security_config["retention_ms"]


# =============================================================================
# Event Model Tests
# =============================================================================


class TestEventEnvelope:
    """Tests for EventEnvelope model."""

    def test_event_envelope_defaults(self):
        """Test default values are set."""
        event = EventEnvelope(
            event_type="test",
            source="test_source",
        )

        assert event.event_id is not None
        assert len(event.event_id) == 36  # UUID format
        assert event.schema_version == 1
        assert event.timestamp is not None
        assert event.correlation_id is None
        assert event.tenant_id is None
        assert event.payload == {}

    def test_event_envelope_custom_values(self):
        """Test custom values are preserved."""
        event = EventEnvelope(
            event_id="custom-id",
            event_type="email",
            source="email_agent",
            schema_version=2,
            correlation_id="corr-123",
            tenant_id="tenant-1",
            payload={"key": "value"},
        )

        assert event.event_id == "custom-id"
        assert event.event_type == "email"
        assert event.source == "email_agent"
        assert event.schema_version == 2
        assert event.correlation_id == "corr-123"
        assert event.tenant_id == "tenant-1"
        assert event.payload == {"key": "value"}

    def test_event_envelope_to_json_dict(self):
        """Test JSON serialization."""
        event = EventEnvelope(
            event_type="test",
            source="test_source",
        )

        json_dict = event.to_json_dict()

        assert "event_id" in json_dict
        assert json_dict["event_type"] == "test"
        assert json_dict["source"] == "test_source"
        assert isinstance(json_dict["timestamp"], str)  # ISO format string

        # Verify it's JSON-serializable
        json.dumps(json_dict)


class TestSecurityEvent:
    """Tests for SecurityEvent model."""

    def test_security_event_defaults(self):
        """Test security-specific defaults."""
        event = SecurityEvent(
            event_type="email",
            source="email_agent",
        )

        assert event.severity == SeverityLevel.INFO
        assert event.classification is None
        assert event.risk_score == 0
        assert event.indicators == []

    def test_security_event_custom_values(self):
        """Test custom security values."""
        event = SecurityEvent(
            event_type="email",
            source="email_agent",
            severity=SeverityLevel.HIGH,
            classification="phishing",
            risk_score=85,
            indicators=["evil.com", "192.168.1.1"],
        )

        assert event.severity == SeverityLevel.HIGH
        assert event.classification == "phishing"
        assert event.risk_score == 85
        assert event.indicators == ["evil.com", "192.168.1.1"]

    def test_security_event_to_json_dict(self):
        """Test JSON serialization includes security fields."""
        event = SecurityEvent(
            event_type="email",
            source="email_agent",
            severity=SeverityLevel.CRITICAL,
            classification="malware",
            risk_score=95,
        )

        json_dict = event.to_json_dict()

        assert json_dict["severity"] == "critical"
        assert json_dict["classification"] == "malware"
        assert json_dict["risk_score"] == 95

        # Verify it's JSON-serializable
        json.dumps(json_dict)

    def test_risk_score_bounds(self):
        """Test risk_score validation."""
        # Valid scores
        SecurityEvent(event_type="test", source="test", risk_score=0)
        SecurityEvent(event_type="test", source="test", risk_score=100)

        # Invalid scores should raise
        with pytest.raises(ValueError):
            SecurityEvent(event_type="test", source="test", risk_score=-1)

        with pytest.raises(ValueError):
            SecurityEvent(event_type="test", source="test", risk_score=101)


class TestDeadLetterEvent:
    """Tests for DeadLetterEvent model."""

    def test_dlq_event_creation(self):
        """Test DLQ event with all fields."""
        dlq = DeadLetterEvent(
            original_topic="security-events",
            original_partition=0,
            original_offset=12345,
            original_event_id="event-123",
            failure_reason="JSON parse error",
            failure_type="deserialization",
            original_payload='{"broken": json',
        )

        assert dlq.dlq_id is not None
        assert dlq.original_topic == "security-events"
        assert dlq.original_partition == 0
        assert dlq.original_offset == 12345
        assert dlq.failure_type == "deserialization"

    def test_dlq_event_to_json_dict(self):
        """Test DLQ JSON serialization."""
        dlq = DeadLetterEvent(
            original_topic="security-events",
            failure_reason="Handler crashed",
            failure_type="processing",
        )

        json_dict = dlq.to_json_dict()

        assert "dlq_id" in json_dict
        assert json_dict["original_topic"] == "security-events"
        assert isinstance(json_dict["failed_at"], str)

        # Verify it's JSON-serializable
        json.dumps(json_dict)


# =============================================================================
# Producer Tests (Mocked)
# =============================================================================


class TestEventProducer:
    """Tests for EventProducer with mocked Kafka."""

    @pytest.fixture
    def disabled_config(self):
        """Config with event bus disabled."""
        return EventBusConfig(event_bus_enabled=False)

    @pytest.fixture
    def enabled_config(self):
        """Config with event bus enabled."""
        return EventBusConfig(event_bus_enabled=True)

    @pytest.mark.asyncio
    async def test_producer_disabled(self, disabled_config):
        """Test producer doesn't start when disabled."""
        producer = EventProducer(config=disabled_config)
        await producer.start()

        assert not producer.is_started

    @pytest.mark.asyncio
    async def test_producer_publish_when_not_started(self, enabled_config):
        """Test publish returns False when not started."""
        producer = EventProducer(config=enabled_config)

        event = SecurityEvent(event_type="test", source="test")
        result = await producer.publish(Topic.SECURITY_EVENTS, event)

        assert result is False

    @pytest.mark.asyncio
    async def test_producer_health_check_disabled(self, disabled_config):
        """Test health check when disabled."""
        producer = EventProducer(config=disabled_config)

        health = await producer.health_check()

        assert health["healthy"] is True
        assert health["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_producer_health_check_not_started(self, enabled_config):
        """Test health check when not started."""
        producer = EventProducer(config=enabled_config)

        health = await producer.health_check()

        assert health["healthy"] is False
        assert health["status"] == "not_started"

    @pytest.mark.asyncio
    async def test_producer_start_and_publish_mocked(self, enabled_config):
        """Test producer start and publish with mocked Kafka."""
        producer = EventProducer(config=enabled_config)

        # Mock the AIOKafkaProducer
        mock_kafka_producer = AsyncMock()
        mock_kafka_producer.start = AsyncMock()
        mock_kafka_producer.stop = AsyncMock()

        # Mock send_and_wait to return a record metadata
        mock_result = MagicMock()
        mock_result.partition = 0
        mock_result.offset = 42
        mock_kafka_producer.send_and_wait = AsyncMock(return_value=mock_result)

        with patch("app.event_bus.producer.AIOKafkaProducer", return_value=mock_kafka_producer):
            await producer.start()

            assert producer.is_started
            mock_kafka_producer.start.assert_called_once()

            # Test publish
            event = SecurityEvent(
                event_type="email",
                source="test",
                severity=SeverityLevel.HIGH,
            )
            result = await producer.publish(Topic.SECURITY_EVENTS, event)

            assert result is True
            mock_kafka_producer.send_and_wait.assert_called_once()

            # Verify topic
            call_kwargs = mock_kafka_producer.send_and_wait.call_args
            assert call_kwargs.kwargs["topic"] == "security-events"

            # Test stop
            await producer.stop()
            mock_kafka_producer.stop.assert_called_once()
            assert not producer.is_started


# =============================================================================
# Consumer Tests (Mocked)
# =============================================================================


class TestEventConsumer:
    """Tests for EventConsumer with mocked Kafka."""

    @pytest.fixture
    def disabled_config(self):
        """Config with event bus disabled."""
        return EventBusConfig(event_bus_enabled=False)

    @pytest.fixture
    def enabled_config(self):
        """Config with event bus enabled."""
        return EventBusConfig(event_bus_enabled=True)

    @pytest.fixture
    def mock_handler(self):
        """Mock event handler."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_consumer_disabled(self, disabled_config, mock_handler):
        """Test consumer doesn't start when disabled."""
        consumer = EventConsumer(
            group_id="test",
            topics=[Topic.SECURITY_EVENTS],
            handler=mock_handler,
            config=disabled_config,
        )
        await consumer.start()

        assert not consumer.is_started

    @pytest.mark.asyncio
    async def test_consumer_health_check_disabled(self, disabled_config, mock_handler):
        """Test health check when disabled."""
        consumer = EventConsumer(
            group_id="test",
            topics=[Topic.SECURITY_EVENTS],
            handler=mock_handler,
            config=disabled_config,
        )

        health = await consumer.health_check()

        assert health["healthy"] is True
        assert health["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_consumer_group_id_prefixed(self, enabled_config, mock_handler):
        """Test consumer group ID is prefixed."""
        consumer = EventConsumer(
            group_id="my-processor",
            topics=[Topic.SECURITY_EVENTS],
            handler=mock_handler,
            config=enabled_config,
        )

        assert consumer._group_id == "cyberguard-my-processor"


# =============================================================================
# Event ID Uniqueness Tests
# =============================================================================


class TestEventIdUniqueness:
    """Tests for event ID uniqueness (idempotency foundation)."""

    def test_event_ids_unique(self):
        """Test that generated event IDs are unique."""
        events = [
            SecurityEvent(event_type="test", source="test")
            for _ in range(100)
        ]

        event_ids = [e.event_id for e in events]

        assert len(set(event_ids)) == 100  # All unique

    def test_custom_event_id_preserved(self):
        """Test that custom event IDs are preserved."""
        custom_id = str(uuid4())
        event = SecurityEvent(
            event_id=custom_id,
            event_type="test",
            source="test",
        )

        assert event.event_id == custom_id


# =============================================================================
# Schema Version Tests
# =============================================================================


class TestSchemaVersion:
    """Tests for schema versioning."""

    def test_default_schema_version(self):
        """Test default schema version is 1."""
        event = SecurityEvent(event_type="test", source="test")

        assert event.schema_version == 1

    def test_custom_schema_version(self):
        """Test custom schema version is preserved."""
        event = SecurityEvent(
            event_type="test",
            source="test",
            schema_version=2,
        )

        assert event.schema_version == 2


# =============================================================================
# Integration Boundary Tests
# =============================================================================


class TestDispatcherIntegration:
    """Tests for dispatcher integration."""

    def test_event_type_to_agent_mapping(self):
        """Test event type to agent type mapping exists."""
        from app.event_bus.dispatcher_integration import EVENT_TO_AGENT
        from app.agents.base import AgentType

        assert EVENT_TO_AGENT["email"] == AgentType.EMAIL
        assert EVENT_TO_AGENT["log"] == AgentType.LOG
        assert EVENT_TO_AGENT["network"] == AgentType.NETWORK

    @pytest.mark.asyncio
    async def test_handle_security_event_unknown_type(self):
        """Test handler handles unknown event types gracefully."""
        from app.event_bus.dispatcher_integration import handle_security_event

        event = SecurityEvent(
            event_type="unknown_type",
            source="test",
        )

        # Should not raise, just log warning
        await handle_security_event(event)
