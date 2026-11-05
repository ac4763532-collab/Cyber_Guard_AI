"""
CyberGuard AI - Event Bus Consumer

Async consumer for processing events from Redpanda/Kafka.

Usage:
    consumer = EventConsumer(
        group_id="security-processor",
        topics=[Topic.SECURITY_EVENTS],
        handler=my_handler_function,
    )
    await consumer.start()
    # Consumer runs in background, processing messages
    await consumer.stop()

Handler function signature:
    async def handler(event: SecurityEvent) -> None:
        # Process the event
        pass
"""

import asyncio
import json
from typing import Any, Callable, Awaitable

import structlog
from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaError
from pydantic import ValidationError

from app.event_bus.config import get_event_bus_config, EventBusConfig
from app.event_bus.events import SecurityEvent, DeadLetterEvent
from app.event_bus.topics import Topic
from app.event_bus.producer import get_producer


logger = structlog.get_logger(__name__)


# Type alias for event handler
EventHandler = Callable[[SecurityEvent], Awaitable[None]]


class EventConsumer:
    """
    Async Kafka/Redpanda consumer for event processing.

    Features:
    - Consumer group support for scaling
    - Automatic offset management
    - Malformed message handling (DLQ)
    - Graceful shutdown
    - Reconnection on failure

    The consumer processes messages in a loop and calls the provided
    handler function for each valid event. Invalid messages are sent
    to the dead-letter queue.
    """

    def __init__(
        self,
        group_id: str,
        topics: list[Topic | str],
        handler: EventHandler,
        config: EventBusConfig | None = None,
    ):
        """
        Initialize consumer.

        Args:
            group_id: Consumer group ID (will be prefixed with config prefix)
            topics: List of topics to subscribe to
            handler: Async function to call for each event
            config: Optional configuration override
        """
        self._config = config or get_event_bus_config()
        self._group_id = f"{self._config.consumer_group_prefix}-{group_id}"
        self._topics = [t.value if isinstance(t, Topic) else t for t in topics]
        self._handler = handler

        self._consumer: AIOKafkaConsumer | None = None
        self._started = False
        self._running = False
        self._consume_task: asyncio.Task | None = None

    @property
    def is_started(self) -> bool:
        """Check if consumer is started."""
        return self._started and self._consumer is not None

    @property
    def is_running(self) -> bool:
        """Check if consumer is actively processing."""
        return self._running

    async def start(self) -> None:
        """
        Start the consumer and begin processing.

        This starts the consumer loop in a background task.
        """
        if self._started:
            logger.debug("Consumer already started", group_id=self._group_id)
            return

        if not self._config.event_bus_enabled:
            logger.info("Event bus disabled, consumer not started")
            return

        try:
            self._consumer = AIOKafkaConsumer(
                *self._topics,
                bootstrap_servers=self._config.bootstrap_servers_list,
                group_id=self._group_id,
                auto_offset_reset=self._config.consumer_auto_offset_reset,
                max_poll_records=self._config.consumer_max_poll_records,
                session_timeout_ms=self._config.consumer_session_timeout_ms,
                # Durability: offsets are committed manually in
                # _consume_loop(), only after the handler has returned
                # successfully for a given record. With auto-commit,
                # Kafka advances offsets on a background timer regardless
                # of whether the handler (and the finding-persistence it
                # triggers) actually completed - a crash mid-handler would
                # silently lose that event's analysis forever, with no
                # redelivery on restart. Manual commit means a crash or
                # handler exception simply leaves the offset uncommitted,
                # so the same record is redelivered after a restart;
                # FindingRepository's dedup-by-(event_id, rule_id) check
                # (see app/database/repositories/findings.py) makes that
                # redelivery safe rather than duplicating findings.
                enable_auto_commit=False,
                # JSON deserialization handled manually for error handling
                value_deserializer=lambda v: v,  # Keep as bytes
            )

            await self._consumer.start()
            self._started = True

            logger.info(
                "Event consumer started",
                group_id=self._group_id,
                topics=self._topics,
            )

            # Start the consume loop in background
            self._running = True
            self._consume_task = asyncio.create_task(
                self._consume_loop(),
                name=f"consumer-{self._group_id}",
            )

        except KafkaError as e:
            logger.error(
                "Failed to start event consumer",
                group_id=self._group_id,
                error=str(e),
            )
            self._started = False
            raise

    async def stop(self) -> None:
        """
        Stop the consumer gracefully.

        Waits for current message processing to complete before stopping.
        """
        if not self._started:
            return

        self._running = False

        # Wait for consume loop to finish
        if self._consume_task:
            self._consume_task.cancel()
            try:
                await self._consume_task
            except asyncio.CancelledError:
                pass
            self._consume_task = None

        # Stop the consumer
        if self._consumer:
            try:
                await self._consumer.stop()
                logger.info("Event consumer stopped", group_id=self._group_id)
            except Exception as e:
                logger.error(
                    "Error stopping event consumer",
                    group_id=self._group_id,
                    error=str(e),
                )
            finally:
                self._consumer = None
                self._started = False

    async def _consume_loop(self) -> None:
        """
        Main consume loop.

        Continuously polls for messages and processes them.
        Handles errors gracefully without crashing.

        Durability: with enable_auto_commit=False, offsets are committed
        explicitly here, per partition, only up through the last record
        in that partition's batch whose handler call succeeded (DLQ'd or
        otherwise-failed records are never committed). This means a
        malformed or failing record does not block commits for records
        that already completed successfully ahead of it in the same
        poll batch, while the failing record itself (and anything after
        it in that partition's batch) is left uncommitted for redelivery
        on the next poll/restart.
        """
        logger.info("Consumer loop started", group_id=self._group_id)

        while self._running and self._consumer:
            try:
                # Poll for messages with timeout
                messages = await self._consumer.getmany(
                    timeout_ms=1000,
                    max_records=self._config.consumer_max_poll_records,
                )

                for topic_partition, records in messages.items():
                    last_committed_offset: int | None = None

                    for record in records:
                        success = await self._process_message(record)
                        if success:
                            last_committed_offset = record.offset
                        else:
                            # Stop advancing commits for this partition at
                            # the first failure in this batch - the failed
                            # record (and anything after it) is redelivered
                            # on the next poll instead of being skipped.
                            break

                    if last_committed_offset is not None:
                        try:
                            await self._consumer.commit(
                                {topic_partition: last_committed_offset + 1}
                            )
                        except KafkaError as e:
                            logger.error(
                                "Failed to commit offset",
                                group_id=self._group_id,
                                topic=topic_partition.topic,
                                partition=topic_partition.partition,
                                offset=last_committed_offset,
                                error=str(e),
                            )

            except asyncio.CancelledError:
                logger.info("Consumer loop cancelled", group_id=self._group_id)
                break

            except KafkaError as e:
                logger.error(
                    "Kafka error in consumer loop",
                    group_id=self._group_id,
                    error=str(e),
                )
                # Wait before retry
                await asyncio.sleep(5)

            except Exception as e:
                logger.error(
                    "Unexpected error in consumer loop",
                    group_id=self._group_id,
                    error=str(e),
                    exc_info=True,
                )
                # Wait before retry
                await asyncio.sleep(1)

        logger.info("Consumer loop stopped", group_id=self._group_id)

    async def _process_message(self, record: Any) -> bool:
        """
        Process a single message.

        Deserializes the message, validates it, and calls the handler.
        Invalid messages are sent to the dead-letter queue.

        Returns:
            True if this record was fully handled (including a message
            that was deliberately routed to the DLQ as unprocessable -
            that is a terminal, not a transient, outcome, so the offset
            should still advance past it). False only when the handler
            itself raised and the record should be retried via
            redelivery (offset not committed) - see _consume_loop().
        """
        event_id = "unknown"

        try:
            # Deserialize JSON
            try:
                raw_value = record.value
                if isinstance(raw_value, bytes):
                    raw_value = raw_value.decode("utf-8")
                data = json.loads(raw_value)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                # Malformed message: not retryable (it will never parse
                # differently on redelivery). DLQ it and consider this
                # record done so one bad message can't block the queue.
                await self._send_to_dlq(
                    record=record,
                    failure_reason=f"JSON deserialization failed: {str(e)}",
                    failure_type="deserialization",
                )
                return True

            # Extract event_id if present
            event_id = data.get("event_id", "unknown")

            # Validate and create SecurityEvent
            try:
                event = SecurityEvent.model_validate(data)
            except ValidationError as e:
                # Also not retryable - schema mismatch won't resolve itself.
                await self._send_to_dlq(
                    record=record,
                    failure_reason=f"Event validation failed: {str(e)}",
                    failure_type="validation",
                    event_id=event_id,
                )
                return True

            # Check schema version compatibility
            if event.schema_version > self._config.event_schema_version:
                logger.warning(
                    "Event schema version newer than supported",
                    event_id=event_id,
                    event_version=event.schema_version,
                    supported_version=self._config.event_schema_version,
                )
                # Process anyway - forward compatibility

            # Call the handler. The handler (e.g. handle_security_event)
            # is responsible for its own bounded retry on transient
            # failures (see app/event_bus/dispatcher_integration.py) -
            # by the time an exception reaches here, retries within the
            # handler have already been exhausted. A failure that
            # survives those retries is therefore a terminal outcome for
            # now, not a reason to redeliver this record forever on every
            # future poll/restart - so it is DLQ'd (same as the
            # deserialization/validation branches above) and the offset
            # is allowed to advance past it, preserving full context
            # (original topic/partition/offset/payload) for investigation
            # instead of silently blocking the partition on one
            # persistently-failing event.
            try:
                await self._handler(event)

                logger.debug(
                    "Event processed",
                    event_id=event_id,
                    topic=record.topic,
                    partition=record.partition,
                    offset=record.offset,
                )
                return True

            except Exception as e:
                logger.error(
                    "Handler error after exhausting its own retries - "
                    "routing to DLQ as a terminal processing failure",
                    event_id=event_id,
                    error=str(e),
                )
                await self._send_to_dlq(
                    record=record,
                    failure_reason=f"Handler processing failed: {str(e)}",
                    failure_type="processing",
                    event_id=event_id,
                )
                return True

        except Exception as e:
            logger.error(
                "Unexpected error processing message",
                event_id=event_id,
                error=str(e),
                exc_info=True,
            )
            # Unknown failure mode (e.g. a bug in this method itself) -
            # treat as transient/retryable rather than silently acking,
            # consistent with "do not acknowledge before durable
            # processing is complete".
            return False

    async def _send_to_dlq(
        self,
        record: Any,
        failure_reason: str,
        failure_type: str,
        event_id: str | None = None,
    ) -> None:
        """
        Send a failed message to the dead-letter queue.

        Args:
            record: Original Kafka record
            failure_reason: Human-readable reason
            failure_type: Category (deserialization, validation, processing)
            event_id: Event ID if extractable
        """
        try:
            # Get original payload safely
            original_payload = None
            try:
                raw_value = record.value
                if isinstance(raw_value, bytes):
                    raw_value = raw_value.decode("utf-8", errors="replace")
                # Truncate to avoid huge DLQ messages
                if len(raw_value) > 10000:
                    original_payload = raw_value[:10000] + "...[truncated]"
                else:
                    original_payload = raw_value
            except Exception:
                pass

            dlq_event = DeadLetterEvent(
                original_topic=record.topic,
                original_partition=record.partition,
                original_offset=record.offset,
                original_event_id=event_id,
                failure_reason=failure_reason,
                failure_type=failure_type,
                original_payload=original_payload,
            )

            # Publish to DLQ
            producer = get_producer()
            if producer.is_started:
                await producer.publish(
                    Topic.DEAD_LETTER,
                    dlq_event.to_json_dict(),
                )

            logger.warning(
                "Message sent to DLQ",
                dlq_id=dlq_event.dlq_id,
                original_topic=record.topic,
                failure_type=failure_type,
                failure_reason=failure_reason,
            )

        except Exception as e:
            # DLQ publish failed - log but don't crash
            logger.error(
                "Failed to send message to DLQ",
                error=str(e),
                original_topic=record.topic,
            )

    async def health_check(self) -> dict[str, Any]:
        """
        Check consumer health.

        Returns:
            Health status dict
        """
        if not self._config.event_bus_enabled:
            return {
                "healthy": True,
                "status": "disabled",
                "message": "Event bus is disabled",
            }

        if not self._started or not self._consumer:
            return {
                "healthy": False,
                "status": "not_started",
                "message": "Consumer not started",
            }

        return {
            "healthy": self._running,
            "status": "running" if self._running else "stopped",
            "group_id": self._group_id,
            "topics": self._topics,
        }
