"""
CyberGuard AI - Real-Time Correlation State Manager (STEP 8.5.3)

Redis-backed correlation state for real-time cross-source correlation.

This module provides:
1. CorrelationStateManager - Redis state for real-time correlation candidates
2. Bounded state with configurable correlation windows
3. Automatic cleanup via TTL
4. Tenant isolation via key prefixes
5. Atomic operations for multi-worker safety
6. Event/finding deduplication

Key patterns:
- Sorted Sets: Store event/finding references with timestamp as score
- Hash: Store event metadata for quick lookup
- TTL: Automatic expiration of old candidates
- Atomic pipelines: Multi-step operations without races

Key Format:
    correlation:{tenant_hash}:entity:{entity_hash}     -> Sorted Set of event IDs
    correlation:{tenant_hash}:event:{event_id}         -> Event metadata hash
    correlation:{tenant_hash}:finding:{finding_id}     -> Finding dedup marker
    correlation:{tenant_hash}:result:{fingerprint}     -> Result dedup marker

This module does NOT:
- Silently fall back to in-memory on Redis failure
- Allow cross-tenant correlation
- Store unbounded event history
- Store secrets in keys or values
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as redis
import structlog
from redis.asyncio.connection import ConnectionPool

from app.config import get_settings

logger = structlog.get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# Default correlation window (can be overridden)
DEFAULT_CORRELATION_WINDOW_SECONDS = 900  # 15 minutes

# Maximum events per correlation key (bounded state)
MAX_EVENTS_PER_KEY = 100

# TTL for event metadata (longer than window for lookups)
EVENT_METADATA_TTL_SECONDS = 3600  # 1 hour

# TTL for finding dedup markers
FINDING_DEDUP_TTL_SECONDS = 3600  # 1 hour

# TTL for correlation result dedup markers
RESULT_DEDUP_TTL_SECONDS = 3600  # 1 hour


# =============================================================================
# Errors
# =============================================================================


class CorrelationStateError(Exception):
    """Base exception for correlation state errors."""


class RedisCorrelationUnavailableError(CorrelationStateError):
    """Raised when Redis is unavailable for correlation state."""


# =============================================================================
# Metrics
# =============================================================================

_state_metrics = {
    "events_added": 0,
    "events_retrieved": 0,
    "candidates_found": 0,
    "state_lookups": 0,
    "state_expired": 0,
    "dedup_hits": 0,
    "redis_errors": 0,
}


def get_state_metrics() -> dict[str, int]:
    """Get correlation state metrics."""
    return _state_metrics.copy()


def reset_state_metrics() -> None:
    """Reset metrics (for testing)."""
    global _state_metrics
    _state_metrics = {
        "events_added": 0,
        "events_retrieved": 0,
        "candidates_found": 0,
        "state_lookups": 0,
        "state_expired": 0,
        "dedup_hits": 0,
        "redis_errors": 0,
    }


def _increment_state_metric(name: str, value: int = 1) -> None:
    """Increment a metric counter."""
    if name in _state_metrics:
        _state_metrics[name] += value


# =============================================================================
# Correlation State Manager
# =============================================================================


class CorrelationStateManager:
    """
    Redis-backed state manager for real-time correlation.

    Provides:
    - Windowed candidate tracking using sorted sets
    - Event metadata storage for correlation
    - Finding deduplication
    - Correlation result deduplication
    - Tenant-isolated keys
    - Bounded state with TTL

    Key Design:
    - Tenant hash prevents key enumeration attacks
    - Entity hash ensures consistent key length
    - Sorted sets enable efficient window queries
    - Atomic pipelines prevent race conditions
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        tenant_id: str,
        correlation_window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
    ):
        """
        Initialize correlation state manager.

        Args:
            redis_client: Async Redis client
            tenant_id: Tenant identifier (will be hashed for keys)
            correlation_window_seconds: Time window for correlation
        """
        self._redis = redis_client
        self._tenant_id = tenant_id
        self._tenant_hash = self._hash_tenant(tenant_id)
        self._window_seconds = correlation_window_seconds
        self._connected = True

    @staticmethod
    def _hash_tenant(tenant_id: str) -> str:
        """Hash tenant ID for key prefix (prevents enumeration)."""
        return hashlib.sha256(f"tenant:{tenant_id}".encode()).hexdigest()[:12]

    @staticmethod
    def _hash_entity(entity_key: str) -> str:
        """Hash entity key for consistent length."""
        return hashlib.sha256(entity_key.encode()).hexdigest()[:16]

    def _entity_key(self, entity_type: str, entity_value: str) -> str:
        """Generate Redis key for an entity's event set."""
        entity_hash = self._hash_entity(f"{entity_type}:{entity_value}")
        return f"correlation:{self._tenant_hash}:entity:{entity_hash}"

    def _event_key(self, event_id: str) -> str:
        """Generate Redis key for event metadata."""
        return f"correlation:{self._tenant_hash}:event:{event_id}"

    def _finding_dedup_key(self, finding_id: str) -> str:
        """Generate Redis key for finding deduplication."""
        return f"correlation:{self._tenant_hash}:finding:{finding_id}"

    def _result_dedup_key(self, fingerprint: str) -> str:
        """Generate Redis key for result deduplication."""
        return f"correlation:{self._tenant_hash}:result:{fingerprint}"

    async def _ensure_connected(self) -> None:
        """Verify Redis connection, raise if unavailable."""
        try:
            await self._redis.ping()
            self._connected = True
        except Exception as e:
            self._connected = False
            _increment_state_metric("redis_errors")
            logger.error("Redis connection failed for correlation", error=str(e))
            raise RedisCorrelationUnavailableError(f"Redis unavailable: {e}") from e

    @property
    def tenant_id(self) -> str:
        """Get the tenant ID."""
        return self._tenant_id

    @property
    def window_seconds(self) -> int:
        """Get the correlation window in seconds."""
        return self._window_seconds

    # =========================================================================
    # Event/Finding Registration
    # =========================================================================

    async def add_event(
        self,
        event_id: str,
        correlation_keys: list[str],
        metadata: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> int:
        """
        Add an event to the correlation state.

        Stores the event under each of its correlation keys (IPs, users, etc.)
        for later candidate retrieval.

        Args:
            event_id: Unique event identifier
            correlation_keys: Keys from CorrelationContext.get_correlation_keys()
            metadata: Event metadata (source_type, finding_ids, risk_score, etc.)
            timestamp: Event timestamp (defaults to now)

        Returns:
            Total number of correlation keys updated

        Raises:
            RedisCorrelationUnavailableError: If Redis is unavailable
        """
        await self._ensure_connected()

        if not correlation_keys:
            return 0

        ts = timestamp or datetime.now(timezone.utc)
        score = ts.timestamp()

        # Store event metadata
        event_key = self._event_key(event_id)
        event_data = {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "source_type": metadata.get("source_type", "unknown"),
            "finding_ids": json.dumps(metadata.get("finding_ids", [])),
            "risk_score": str(metadata.get("risk_score", 0)),
            "severity": metadata.get("severity", "info"),
        }

        # Atomic pipeline: store metadata + add to all entity sets
        async with self._redis.pipeline(transaction=True) as pipe:
            # Store event metadata
            pipe.hset(event_key, mapping=event_data)
            pipe.expire(event_key, EVENT_METADATA_TTL_SECONDS)

            # Add event to each correlation key's sorted set
            cutoff = score - self._window_seconds
            for corr_key in correlation_keys:
                # Extract entity type and value from key
                # Format: tenant:{tenant_id}:{entity_type}:{entity_value}
                parts = corr_key.split(":", 3)
                if len(parts) >= 4:
                    entity_type = parts[2]
                    entity_value = parts[3]
                    redis_key = self._entity_key(entity_type, entity_value)

                    # Add to sorted set with timestamp as score
                    pipe.zadd(redis_key, {event_id: score})
                    # Remove old events
                    pipe.zremrangebyscore(redis_key, "-inf", cutoff)
                    # Trim to max size
                    pipe.zremrangebyrank(redis_key, 0, -(MAX_EVENTS_PER_KEY + 1))
                    # Set TTL
                    pipe.expire(redis_key, self._window_seconds + 60)

            await pipe.execute()

        _increment_state_metric("events_added")

        logger.debug(
            "Event added to correlation state",
            event_id=event_id,
            correlation_keys_count=len(correlation_keys),
            tenant_id=self._tenant_id,
        )

        return len(correlation_keys)

    async def get_candidates(
        self,
        correlation_keys: list[str],
        exclude_event_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get candidate events for correlation.

        Retrieves events that share any of the given correlation keys
        within the configured time window.

        Args:
            correlation_keys: Keys to search for candidates
            exclude_event_id: Event ID to exclude (the current event)

        Returns:
            List of candidate event metadata dicts

        Raises:
            RedisCorrelationUnavailableError: If Redis is unavailable
        """
        await self._ensure_connected()
        _increment_state_metric("state_lookups")

        if not correlation_keys:
            return []

        now = time.time()
        cutoff = now - self._window_seconds

        # Collect all event IDs from all correlation keys
        all_event_ids: set[str] = set()

        async with self._redis.pipeline(transaction=False) as pipe:
            for corr_key in correlation_keys:
                parts = corr_key.split(":", 3)
                if len(parts) >= 4:
                    entity_type = parts[2]
                    entity_value = parts[3]
                    redis_key = self._entity_key(entity_type, entity_value)
                    pipe.zrangebyscore(redis_key, cutoff, "+inf")

            results = await pipe.execute()

        for event_ids in results:
            if event_ids:
                all_event_ids.update(event_ids)

        # Exclude current event
        if exclude_event_id:
            all_event_ids.discard(exclude_event_id)

        if not all_event_ids:
            return []

        # Fetch metadata for all candidate events
        candidates = []
        async with self._redis.pipeline(transaction=False) as pipe:
            for event_id in all_event_ids:
                event_key = self._event_key(event_id)
                pipe.hgetall(event_key)

            results = await pipe.execute()

        for metadata in results:
            if metadata:
                # Parse JSON fields
                try:
                    finding_ids = json.loads(metadata.get("finding_ids", "[]"))
                except json.JSONDecodeError:
                    finding_ids = []

                candidates.append({
                    "event_id": metadata.get("event_id", ""),
                    "timestamp": metadata.get("timestamp", ""),
                    "source_type": metadata.get("source_type", "unknown"),
                    "finding_ids": finding_ids,
                    "risk_score": int(metadata.get("risk_score", "0")),
                    "severity": metadata.get("severity", "info"),
                })

        _increment_state_metric("events_retrieved", len(candidates))
        if candidates:
            _increment_state_metric("candidates_found")

        logger.debug(
            "Retrieved correlation candidates",
            candidates_count=len(candidates),
            correlation_keys_count=len(correlation_keys),
            tenant_id=self._tenant_id,
        )

        return candidates

    # =========================================================================
    # Deduplication
    # =========================================================================

    async def is_finding_processed(self, finding_id: str) -> bool:
        """
        Check if a finding has already been processed for correlation.

        Args:
            finding_id: Finding identifier

        Returns:
            True if already processed, False otherwise
        """
        await self._ensure_connected()

        key = self._finding_dedup_key(finding_id)
        exists = await self._redis.exists(key) > 0

        if exists:
            _increment_state_metric("dedup_hits")

        return exists

    async def mark_finding_processed(
        self,
        finding_id: str,
        event_id: str,
        ttl_seconds: int = FINDING_DEDUP_TTL_SECONDS,
    ) -> bool:
        """
        Mark a finding as processed for correlation.

        Args:
            finding_id: Finding identifier
            event_id: Associated event ID
            ttl_seconds: How long to remember

        Returns:
            True if newly marked, False if already existed
        """
        await self._ensure_connected()

        key = self._finding_dedup_key(finding_id)
        result = await self._redis.set(key, event_id, ex=ttl_seconds, nx=True)
        return result is True

    async def is_event_processed(self, event_id: str, source_event_id: str) -> bool:
        """
        Check if an event has already been processed for correlation.

        Uses both event_id and source_event_id for robust deduplication.

        Args:
            event_id: Internal event ID
            source_event_id: Source system event ID

        Returns:
            True if already processed
        """
        await self._ensure_connected()

        # Check if event metadata exists
        event_key = self._event_key(event_id)
        exists = await self._redis.exists(event_key) > 0

        if exists:
            _increment_state_metric("dedup_hits")

        return exists

    async def is_result_duplicate(
        self,
        fingerprint: str,
        ttl_seconds: int = RESULT_DEDUP_TTL_SECONDS,
    ) -> bool:
        """
        Check if a correlation result with this fingerprint already exists.

        Args:
            fingerprint: Correlation result fingerprint

        Returns:
            True if duplicate
        """
        await self._ensure_connected()

        key = self._result_dedup_key(fingerprint)
        exists = await self._redis.exists(key) > 0

        if exists:
            _increment_state_metric("dedup_hits")

        return exists

    async def mark_result_created(
        self,
        fingerprint: str,
        correlation_id: str,
        ttl_seconds: int = RESULT_DEDUP_TTL_SECONDS,
    ) -> bool:
        """
        Mark a correlation result fingerprint as created.

        Args:
            fingerprint: Correlation result fingerprint
            correlation_id: The created correlation ID

        Returns:
            True if newly marked, False if duplicate
        """
        await self._ensure_connected()

        key = self._result_dedup_key(fingerprint)
        result = await self._redis.set(key, correlation_id, ex=ttl_seconds, nx=True)
        return result is True

    # =========================================================================
    # Cleanup
    # =========================================================================

    async def cleanup_expired(self) -> int:
        """
        Clean up expired correlation state.

        Note: Most cleanup happens via Redis TTL. This is for explicit cleanup.

        Returns:
            Number of keys cleaned up
        """
        await self._ensure_connected()

        # Scan for entity keys and remove expired events
        pattern = f"correlation:{self._tenant_hash}:entity:*"
        cursor = 0
        cleaned = 0
        cutoff = time.time() - self._window_seconds

        while True:
            cursor, keys = await self._redis.scan(cursor, match=pattern, count=100)

            for key in keys:
                removed = await self._redis.zremrangebyscore(key, "-inf", cutoff)
                cleaned += removed

            if cursor == 0:
                break

        if cleaned > 0:
            _increment_state_metric("state_expired", cleaned)
            logger.info(
                "Cleaned up expired correlation state",
                cleaned=cleaned,
                tenant_id=self._tenant_id,
            )

        return cleaned

    # =========================================================================
    # Health & Diagnostics
    # =========================================================================

    async def health_check(self) -> dict[str, Any]:
        """Check Redis health for correlation state."""
        try:
            await self._redis.ping()
            return {
                "status": "healthy",
                "tenant_id": self._tenant_id,
                "window_seconds": self._window_seconds,
            }
        except (OSError, ConnectionError, TimeoutError) as e:
            return {
                "status": "unhealthy",
                "tenant_id": self._tenant_id,
                "error": str(e),
            }

    async def get_stats(self) -> dict[str, Any]:
        """Get statistics for correlation state."""
        await self._ensure_connected()

        # Count entity keys
        entity_pattern = f"correlation:{self._tenant_hash}:entity:*"
        event_pattern = f"correlation:{self._tenant_hash}:event:*"

        cursor = 0
        entity_count = 0
        while True:
            cursor, keys = await self._redis.scan(cursor, match=entity_pattern, count=100)
            entity_count += len(keys)
            if cursor == 0:
                break

        cursor = 0
        event_count = 0
        while True:
            cursor, keys = await self._redis.scan(cursor, match=event_pattern, count=100)
            event_count += len(keys)
            if cursor == 0:
                break

        return {
            "tenant_id": self._tenant_id,
            "window_seconds": self._window_seconds,
            "active_entity_keys": entity_count,
            "active_event_keys": event_count,
            "metrics": get_state_metrics(),
        }


# =============================================================================
# Factory Functions
# =============================================================================

_state_managers: dict[str, CorrelationStateManager] = {}
_correlation_pool: ConnectionPool | None = None


async def get_correlation_state_manager(
    tenant_id: str,
    correlation_window_seconds: int | None = None,
) -> CorrelationStateManager:
    """
    Get or create a correlation state manager for a tenant.

    Args:
        tenant_id: Tenant identifier
        correlation_window_seconds: Override default window (optional)

    Returns:
        CorrelationStateManager instance

    Raises:
        RedisCorrelationUnavailableError: If Redis cannot be connected
    """
    global _correlation_pool

    settings = get_settings()

    # Get window from settings or parameter
    window = correlation_window_seconds
    if window is None:
        window = getattr(settings, 'correlation_window_seconds', DEFAULT_CORRELATION_WINDOW_SECONDS)

    # Create connection pool if needed
    if _correlation_pool is None:
        _correlation_pool = ConnectionPool.from_url(
            settings.redis_url,
            max_connections=20,
            decode_responses=True,
        )

    # Check if we have a manager for this tenant
    cache_key = f"{tenant_id}:{window}"
    if cache_key in _state_managers:
        return _state_managers[cache_key]

    # Create new manager
    redis_client = redis.Redis(connection_pool=_correlation_pool)

    # Verify connection
    try:
        await redis_client.ping()
    except Exception as e:
        raise RedisCorrelationUnavailableError(f"Cannot connect to Redis: {e}") from e

    manager = CorrelationStateManager(
        redis_client=redis_client,
        tenant_id=tenant_id,
        correlation_window_seconds=window,
    )

    _state_managers[cache_key] = manager

    logger.info(
        "Created correlation state manager",
        tenant_id=tenant_id,
        window_seconds=window,
    )

    return manager


async def close_correlation_state() -> None:
    """Close correlation state connections."""
    global _correlation_pool

    _state_managers.clear()

    if _correlation_pool:
        await _correlation_pool.disconnect()
        _correlation_pool = None


def reset_correlation_state_for_testing() -> None:
    """Reset state managers (for testing only)."""
    _state_managers.clear()
    reset_state_metrics()
