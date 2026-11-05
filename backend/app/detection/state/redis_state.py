"""
CyberGuard AI - Redis-Backed Detection State

STEP 8.2.1: Production-ready detection state management using Redis.

Features:
- Atomic operations for concurrent event processing
- Sorted sets for windowed event tracking with TTL
- Tenant isolation via key prefixes
- Safe failure handling (fail loudly, not silently)
- Multi-worker resilience

Key patterns:
- Sorted Set: Store events with timestamp as score for windowed queries
- TTL: Automatic expiration of old data
- Pipeline: Atomic multi-step operations

This module does NOT:
- Silently fall back to in-memory on Redis failure
- Allow cross-tenant data access
- Lose events on worker restart
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

import structlog
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

from app.config import get_settings


logger = structlog.get_logger(__name__)


class RedisUnavailableError(Exception):
    """Raised when Redis is unavailable and operation cannot proceed safely."""
    pass


class DetectionStateManager:
    """
    Redis-backed state manager for Windows detection rules.

    Provides:
    - Windowed event tracking using sorted sets
    - Atomic threshold checks
    - TTL-based automatic cleanup
    - Tenant-isolated keys
    - Idempotency tracking

    Key Format:
        detection:{tenant_id}:{rule_id}:{correlation_key}

    Example:
        detection:tenant-123:WIN-001:user@10.0.0.1
    """

    def __init__(self, redis_client: redis.Redis, tenant_id: str = "default"):
        """
        Initialize state manager.

        Args:
            redis_client: Async Redis client
            tenant_id: Tenant identifier for key isolation
        """
        self._redis = redis_client
        self._tenant_id = tenant_id
        self._connected = True

    def _key(self, rule_id: str, correlation_key: str) -> str:
        """Generate tenant-isolated Redis key."""
        # Hash correlation key to ensure consistent length and no special chars
        key_hash = hashlib.sha256(correlation_key.encode()).hexdigest()[:16]
        return f"detection:{self._tenant_id}:{rule_id}:{key_hash}"

    def _processed_key(self, rule_id: str, event_id: str) -> str:
        """Generate key for processed event tracking."""
        return f"processed:{self._tenant_id}:{rule_id}:{event_id}"

    async def _ensure_connected(self) -> None:
        """Verify Redis connection, raise if unavailable."""
        try:
            await self._redis.ping()
            self._connected = True
        except Exception as e:
            self._connected = False
            logger.error("Redis connection failed", error=str(e))
            raise RedisUnavailableError(f"Redis unavailable: {e}") from e

    # =========================================================================
    # Windowed Event Tracking (Sorted Sets)
    # =========================================================================

    async def add_event(
        self,
        rule_id: str,
        correlation_key: str,
        event_data: dict[str, Any],
        timestamp: datetime | None = None,
        window_seconds: int = 300,
    ) -> int:
        """
        Add an event to the windowed tracking set.

        Uses Redis sorted set with timestamp as score for efficient
        range queries. Old events outside the window are automatically
        removed.

        Args:
            rule_id: Detection rule identifier
            correlation_key: Key for grouping events (e.g., "user@ip")
            event_data: Event data to store
            timestamp: Event timestamp (defaults to now)
            window_seconds: TTL for the tracking window

        Returns:
            Number of events currently in the window

        Raises:
            RedisUnavailableError: If Redis is not available
        """
        await self._ensure_connected()

        key = self._key(rule_id, correlation_key)
        ts = timestamp or datetime.now(timezone.utc)
        score = ts.timestamp()

        # Serialize event data with unique ID to allow multiple events at same timestamp
        event_json = json.dumps({
            **event_data,
            "_ts": score,
            "_id": f"{score}:{hash(json.dumps(event_data, sort_keys=True)) % 10000000}",
        })

        # Calculate cutoff for window
        cutoff = score - window_seconds

        # Atomic pipeline: add event, remove old, count, set TTL
        async with self._redis.pipeline(transaction=True) as pipe:
            # Add event to sorted set
            pipe.zadd(key, {event_json: score})
            # Remove events outside window
            pipe.zremrangebyscore(key, "-inf", cutoff)
            # Count events in window
            pipe.zcard(key)
            # Set TTL (extend on each event)
            pipe.expire(key, window_seconds + 60)  # Extra buffer

            results = await pipe.execute()

        count = results[2]  # zcard result

        logger.debug(
            "Event added to detection window",
            rule_id=rule_id,
            correlation_key=correlation_key[:50],  # Truncate for logging
            count=count,
            window_seconds=window_seconds,
        )

        return count

    async def get_events_in_window(
        self,
        rule_id: str,
        correlation_key: str,
        window_seconds: int = 300,
    ) -> list[dict[str, Any]]:
        """
        Get all events within the time window.

        Args:
            rule_id: Detection rule identifier
            correlation_key: Correlation grouping key
            window_seconds: Window size in seconds

        Returns:
            List of event data dicts within the window
        """
        await self._ensure_connected()

        key = self._key(rule_id, correlation_key)
        now = time.time()
        cutoff = now - window_seconds

        # Get events with scores >= cutoff
        events_raw = await self._redis.zrangebyscore(key, cutoff, "+inf")

        events = []
        for event_json in events_raw:
            try:
                event = json.loads(event_json)
                # Remove internal tracking fields
                event.pop("_ts", None)
                event.pop("_id", None)
                events.append(event)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in detection state", key=key)

        return events

    async def count_events_in_window(
        self,
        rule_id: str,
        correlation_key: str,
        window_seconds: int = 300,
    ) -> int:
        """
        Count events within the time window.

        More efficient than get_events_in_window when only count is needed.
        """
        await self._ensure_connected()

        key = self._key(rule_id, correlation_key)
        now = time.time()
        cutoff = now - window_seconds

        return await self._redis.zcount(key, cutoff, "+inf")

    async def clear_events(
        self,
        rule_id: str,
        correlation_key: str,
    ) -> int:
        """
        Clear all events for a correlation key.

        Used after a detection triggers to reset the window
        (e.g., after successful login clears failure history).

        Returns:
            Number of events cleared
        """
        await self._ensure_connected()

        key = self._key(rule_id, correlation_key)
        count = await self._redis.zcard(key)
        await self._redis.delete(key)

        logger.debug(
            "Detection window cleared",
            rule_id=rule_id,
            correlation_key=correlation_key[:50],
            events_cleared=count,
        )

        return count

    # =========================================================================
    # Atomic Threshold Check
    # =========================================================================

    async def check_threshold_and_get_events(
        self,
        rule_id: str,
        correlation_key: str,
        threshold: int,
        window_seconds: int = 300,
    ) -> tuple[bool, list[dict[str, Any]]]:
        """
        Atomically check if threshold is reached and return events.

        This combines count check and event retrieval in a single
        operation to avoid race conditions.

        Args:
            rule_id: Detection rule identifier
            correlation_key: Correlation grouping key
            threshold: Number of events to trigger
            window_seconds: Window size in seconds

        Returns:
            Tuple of (threshold_reached: bool, events: list)
        """
        await self._ensure_connected()

        key = self._key(rule_id, correlation_key)
        now = time.time()
        cutoff = now - window_seconds

        # Pipeline: clean old, count, get events
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zcount(key, cutoff, "+inf")
            pipe.zrangebyscore(key, cutoff, "+inf")

            results = await pipe.execute()

        count = results[1]
        events_raw = results[2]

        threshold_reached = count >= threshold

        events = []
        for event_json in events_raw:
            try:
                event = json.loads(event_json)
                event.pop("_ts", None)
                event.pop("_id", None)
                events.append(event)
            except json.JSONDecodeError:
                pass

        return threshold_reached, events

    # =========================================================================
    # Idempotency Tracking
    # =========================================================================

    async def is_event_processed(
        self,
        rule_id: str,
        source_event_id: str,
    ) -> bool:
        """
        Check if an event has already been processed.

        Uses a simple key with TTL for idempotency tracking.
        """
        await self._ensure_connected()

        key = self._processed_key(rule_id, source_event_id)
        return await self._redis.exists(key) > 0

    async def mark_event_processed(
        self,
        rule_id: str,
        source_event_id: str,
        ttl_seconds: int = 86400,  # 24 hours default
    ) -> bool:
        """
        Mark an event as processed.

        Args:
            rule_id: Detection rule identifier
            source_event_id: Stable event identifier from source
            ttl_seconds: How long to remember (default 24h)

        Returns:
            True if newly marked, False if already existed
        """
        await self._ensure_connected()

        key = self._processed_key(rule_id, source_event_id)
        # SETNX returns True if key was set (new), False if existed
        result = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
        return result is True

    async def check_and_mark_processed(
        self,
        rule_id: str,
        source_event_id: str,
        ttl_seconds: int = 86400,
    ) -> bool:
        """
        Atomically check if processed and mark if not.

        Returns:
            True if event should be processed (was not seen before)
            False if event was already processed (skip)
        """
        # SETNX is atomic - returns True only if key was newly set
        return await self.mark_event_processed(rule_id, source_event_id, ttl_seconds)

    # =========================================================================
    # Finding Fingerprint
    # =========================================================================

    @staticmethod
    def compute_finding_fingerprint(
        rule_id: str,
        correlation_key: str,
        window_start: datetime,
        window_end: datetime,
    ) -> str:
        """
        Compute a deterministic fingerprint for a finding.

        The fingerprint uniquely identifies a finding based on:
        - Rule that triggered
        - What was correlated (user/ip/etc)
        - Time window (bucketed to avoid near-miss duplicates)

        This allows idempotent finding creation - replaying events
        generates the same fingerprint and can be deduplicated.

        Args:
            rule_id: Detection rule identifier
            correlation_key: What events were correlated by
            window_start: First event timestamp
            window_end: Last event timestamp

        Returns:
            Deterministic fingerprint string
        """
        # Bucket timestamps to nearest minute to handle slight timing variations
        start_bucket = window_start.replace(second=0, microsecond=0)
        end_bucket = window_end.replace(second=0, microsecond=0)

        fingerprint_data = f"{rule_id}:{correlation_key}:{start_bucket.isoformat()}:{end_bucket.isoformat()}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]

    async def is_finding_duplicate(
        self,
        fingerprint: str,
        ttl_seconds: int = 3600,  # 1 hour default
    ) -> bool:
        """
        Check if a finding with this fingerprint already exists.

        Uses Redis for fast lookup before hitting PostgreSQL.
        """
        await self._ensure_connected()

        key = f"finding:{self._tenant_id}:{fingerprint}"
        return await self._redis.exists(key) > 0

    async def mark_finding_created(
        self,
        fingerprint: str,
        finding_id: str,
        ttl_seconds: int = 3600,
    ) -> bool:
        """
        Mark a finding fingerprint as created.

        Returns:
            True if newly marked, False if already existed (duplicate)
        """
        await self._ensure_connected()

        key = f"finding:{self._tenant_id}:{fingerprint}"
        result = await self._redis.set(key, finding_id, ex=ttl_seconds, nx=True)
        return result is True

    # =========================================================================
    # Health & Diagnostics
    # =========================================================================

    async def health_check(self) -> dict[str, Any]:
        """Check Redis health and return diagnostics."""
        try:
            await self._redis.ping()
            info = await self._redis.info("memory")
            return {
                "status": "healthy",
                "tenant_id": self._tenant_id,
                "used_memory_human": info.get("used_memory_human", "unknown"),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "tenant_id": self._tenant_id,
                "error": str(e),
            }

    async def get_stats(self, rule_id: str) -> dict[str, Any]:
        """Get statistics for a rule's detection state."""
        await self._ensure_connected()

        pattern = f"detection:{self._tenant_id}:{rule_id}:*"
        cursor = 0
        keys = []

        while True:
            cursor, batch = await self._redis.scan(cursor, match=pattern, count=100)
            keys.extend(batch)
            if cursor == 0:
                break

        return {
            "rule_id": rule_id,
            "tenant_id": self._tenant_id,
            "active_correlations": len(keys),
        }


# =============================================================================
# Factory Functions
# =============================================================================

_state_manager: DetectionStateManager | None = None
_redis_pool: ConnectionPool | None = None


async def get_detection_state_manager(
    tenant_id: str = "default",
) -> DetectionStateManager:
    """
    Get or create the detection state manager.

    Args:
        tenant_id: Tenant identifier for isolation

    Returns:
        DetectionStateManager instance

    Raises:
        RedisUnavailableError: If Redis cannot be connected
    """
    global _state_manager, _redis_pool

    settings = get_settings()

    if _redis_pool is None:
        _redis_pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections=20,
            decode_responses=True,
        )

    redis_client = redis.Redis(connection_pool=_redis_pool)

    # Verify connection
    try:
        await redis_client.ping()
    except Exception as e:
        raise RedisUnavailableError(f"Cannot connect to Redis: {e}") from e

    return DetectionStateManager(redis_client, tenant_id)


async def close_detection_state() -> None:
    """Close Redis connections for detection state."""
    global _state_manager, _redis_pool

    if _redis_pool:
        await _redis_pool.disconnect()
        _redis_pool = None
    _state_manager = None
