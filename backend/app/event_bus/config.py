"""
CyberGuard AI - Event Bus Configuration

Configuration for Redpanda/Kafka connection.
All settings loaded from environment variables.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class EventBusConfig(BaseSettings):
    """Event bus configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Redpanda/Kafka connection
    redpanda_bootstrap_servers: str = Field(
        default="localhost:9092",
        description="Comma-separated list of bootstrap servers",
    )

    # Producer settings
    producer_acks: Literal["all", "0", "1"] = Field(
        default="all",
        description="Producer acknowledgment mode (all=wait for all replicas)",
    )
    producer_retries: int = Field(
        default=3,
        description="Number of retries for failed sends",
    )
    producer_timeout_ms: int = Field(
        default=30000,
        description="Producer request timeout in milliseconds",
    )

    # Consumer settings
    consumer_group_prefix: str = Field(
        default="cyberguard",
        description="Prefix for consumer group IDs",
    )
    consumer_auto_offset_reset: Literal["earliest", "latest"] = Field(
        default="earliest",
        description="Where to start consuming if no offset exists",
    )
    consumer_max_poll_records: int = Field(
        default=100,
        description="Maximum records per poll",
    )
    consumer_session_timeout_ms: int = Field(
        default=30000,
        description="Consumer session timeout",
    )

    # Event settings
    event_schema_version: int = Field(
        default=1,
        description="Current event schema version",
    )
    event_default_ttl_seconds: int = Field(
        default=86400 * 7,  # 7 days
        description="Default event retention TTL",
    )

    # Feature flags
    event_bus_enabled: bool = Field(
        default=True,
        description="Enable/disable event bus (for graceful degradation)",
    )

    @property
    def bootstrap_servers_list(self) -> list[str]:
        """Return bootstrap servers as a list."""
        return [s.strip() for s in self.redpanda_bootstrap_servers.split(",")]


@lru_cache
def get_event_bus_config() -> EventBusConfig:
    """Get cached event bus configuration."""
    return EventBusConfig()
