"""
CyberGuard AI - Event Bus

Redpanda/Kafka event streaming for real-time security event processing.

Components:
- Producer: Publishes security events to topics
- Consumer: Subscribes and processes events from topics
- Events: Common event envelope for all event types
- Config: Configuration for Redpanda connection
"""

from app.event_bus.config import EventBusConfig, get_event_bus_config
from app.event_bus.events import SecurityEvent, EventEnvelope, DeadLetterEvent
from app.event_bus.topics import Topic
from app.event_bus.producer import EventProducer, get_producer
from app.event_bus.consumer import EventConsumer

__all__ = [
    "EventBusConfig",
    "get_event_bus_config",
    "SecurityEvent",
    "EventEnvelope",
    "DeadLetterEvent",
    "Topic",
    "EventProducer",
    "get_producer",
    "EventConsumer",
]
