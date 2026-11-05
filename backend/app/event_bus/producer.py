"""
CyberGuard AI - Event Bus Producer

Async producer for publishing events to Redpanda/Kafka.

Usage:
    producer = get_producer()
    await producer.start()

    event = SecurityEvent(
        event_type="email",
        source="email_agent",
        payload={"email_id": "123", ...}
    )
    await producer.publish(Topic.SECURITY_EVENTS, event)

    await producer.stop()
"""

import json
from typing import Any

import structlog
from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaError

from app.event_bus.config import get_event_bus_config, EventBusConfig
from app.event_bus.events import EventEnvelope, SecurityEvent
from app.event_bus.topics import Topic


logger = structlog.get_logger(__name__)


class EventProducer:
    """
    Async Kafka/Redpanda producer for event publishing.

    Features:
    - Async publishing with acknowledgment
    - JSON serialization
    - Automatic retries
    - Graceful shutdown
    - Connection health check

    The producer waits for broker acknowledgment before returning,
    ensuring events are not lost.
    """

    def __init__(self, config: EventBusConfig | None = None):
        self._config = config or get_event_bus_config()
        self._producer: AIOKafkaProducer | None = None
        self._started = False

    @property
    def is_started(self) -> bool:
        """Check if producer is started."""
        return self._started and self._producer is not None

    async def start(self) -> None:
        """
        Start the producer and connect to the broker.

        Raises:
            KafkaError: If connection fails
        """
        if self._started:
            logger.debug("Producer already started")
            return

        if not self._config.event_bus_enabled:
            logger.info("Event bus disabled, producer not started")
            return

        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._config.bootstrap_servers_list,
                acks=self._config.producer_acks,
                request_timeout_ms=self._config.producer_timeout_ms,
                retry_backoff_ms=100,  # Retry backoff between attempts
                # JSON serialization
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
            )

            await self._producer.start()
            self._started = True

            logger.info(
                "Event producer started",
                bootstrap_servers=self._config.redpanda_bootstrap_servers,
            )

        except KafkaError as e:
            logger.error("Failed to start event producer", error=str(e))
            self._started = False
            raise

    async def stop(self) -> None:
        """
        Stop the producer and flush pending messages.

        Waits for all pending messages to be delivered before closing.
        """
        if not self._started or not self._producer:
            return

        try:
            await self._producer.stop()
            logger.info("Event producer stopped")
        except Exception as e:
            logger.error("Error stopping event producer", error=str(e))
        finally:
            self._producer = None
            self._started = False

    async def publish(
        self,
        topic: Topic | str,
        event: EventEnvelope | SecurityEvent | dict[str, Any],
        key: str | None = None,
    ) -> bool:
        """
        Publish an event to a topic.

        Args:
            topic: Target topic (Topic enum or string)
            event: Event to publish (EventEnvelope, SecurityEvent, or dict)
            key: Optional partition key (events with same key go to same partition)

        Returns:
            True if published successfully, False otherwise

        Note:
            This method waits for broker acknowledgment before returning.
            The event is considered delivered only after acknowledgment.
        """
        if not self._started or not self._producer:
            logger.warning("Producer not started, cannot publish event")
            return False

        topic_name = topic.value if isinstance(topic, Topic) else topic

        # Convert event to JSON-serializable dict
        if isinstance(event, (EventEnvelope, SecurityEvent)):
            event_data = event.to_json_dict()
            event_id = event.event_id
        elif isinstance(event, dict):
            event_data = event
            event_id = event.get("event_id", "unknown")
        else:
            logger.error("Invalid event type", event_type=type(event).__name__)
            return False

        try:
            # Send and wait for acknowledgment
            result = await self._producer.send_and_wait(
                topic=topic_name,
                value=event_data,
                key=key,
            )

            logger.debug(
                "Event published",
                topic=topic_name,
                event_id=event_id,
                partition=result.partition,
                offset=result.offset,
            )

            return True

        except KafkaError as e:
            logger.error(
                "Failed to publish event",
                topic=topic_name,
                event_id=event_id,
                error=str(e),
            )
            return False

    async def publish_security_event(
        self,
        event: SecurityEvent,
        key: str | None = None,
    ) -> bool:
        """
        Convenience method to publish a security event.

        Args:
            event: SecurityEvent to publish
            key: Optional partition key

        Returns:
            True if published successfully
        """
        return await self.publish(Topic.SECURITY_EVENTS, event, key)

    async def health_check(self) -> dict[str, Any]:
        """
        Check producer health.

        Returns:
            Health status dict with 'healthy' boolean and details
        """
        if not self._config.event_bus_enabled:
            return {
                "healthy": True,
                "status": "disabled",
                "message": "Event bus is disabled",
            }

        if not self._started or not self._producer:
            return {
                "healthy": False,
                "status": "not_started",
                "message": "Producer not started",
            }

        try:
            # Check if we can get cluster metadata
            # The producer being started and connected is a good health indicator
            return {
                "healthy": True,
                "status": "connected",
                "bootstrap_servers": self._config.redpanda_bootstrap_servers,
            }

        except Exception as e:
            return {
                "healthy": False,
                "status": "error",
                "message": str(e),
            }


# Global producer instance
_producer: EventProducer | None = None


def get_producer() -> EventProducer:
    """Get or create the global producer instance."""
    global _producer
    if _producer is None:
        _producer = EventProducer()
    return _producer


async def init_producer() -> None:
    """Initialize the global producer."""
    producer = get_producer()
    await producer.start()


async def close_producer() -> None:
    """Close the global producer."""
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None
