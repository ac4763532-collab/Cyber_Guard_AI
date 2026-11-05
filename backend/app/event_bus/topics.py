"""
CyberGuard AI - Event Bus Topics

Centralized topic definitions for Redpanda/Kafka.

Naming convention: <domain>-<purpose>
- security-events: Main security event stream
- dead-letter: Failed/malformed messages

Planned topics (not yet implemented):
- agent-tasks: Tasks dispatched to agents
- agent-results: Results from agent analysis
- correlations: Correlation events
- incidents: Incident lifecycle events
- alerts: Alert events
"""

from enum import Enum


class Topic(str, Enum):
    """Kafka/Redpanda topic definitions."""

    # Core topics (implemented)
    SECURITY_EVENTS = "security-events"
    DEAD_LETTER = "dead-letter"

    # Planned topics (not yet implemented)
    # AGENT_TASKS = "agent-tasks"
    # AGENT_RESULTS = "agent-results"
    # CORRELATIONS = "correlations"
    # INCIDENTS = "incidents"
    # ALERTS = "alerts"


# Topic configuration for admin operations
TOPIC_CONFIGS: dict[Topic, dict] = {
    Topic.SECURITY_EVENTS: {
        "num_partitions": 3,
        "replication_factor": 1,  # 1 for dev, 3 for production
        "retention_ms": 7 * 24 * 60 * 60 * 1000,  # 7 days
    },
    Topic.DEAD_LETTER: {
        "num_partitions": 1,
        "replication_factor": 1,
        "retention_ms": 30 * 24 * 60 * 60 * 1000,  # 30 days for investigation
    },
}


def get_topic_config(topic: Topic) -> dict:
    """Get configuration for a topic."""
    return TOPIC_CONFIGS.get(topic, {})
