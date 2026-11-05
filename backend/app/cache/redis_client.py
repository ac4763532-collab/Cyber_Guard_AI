"""
CyberGuard AI - Redis Cache Client
Provides caching, rate limiting, and pub/sub functionality.
"""

import json
import hashlib
from datetime import timedelta
from typing import Any, Optional
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

try:
    # redis-py >= 8.0 only. Older pins (if ever downgraded) simply don't
    # have this concept, and MaintNotificationsConfig import failing must
    # never break Redis connectivity - fall back to not passing the kwarg
    # at all, which is this library version's own pre-8.0 default behavior.
    from redis.maint_notifications import MaintNotificationsConfig
except ImportError:  # pragma: no cover - depends on installed redis-py version
    MaintNotificationsConfig = None  # type: ignore[assignment,misc]

from app.config import get_settings


class RedisClient:
    """Async Redis client for caching and rate limiting."""

    _instance: Optional["RedisClient"] = None
    _pool: Optional[ConnectionPool] = None

    def __init__(self):
        self.settings = get_settings()
        self._client: Optional[redis.Redis] = None

    @classmethod
    async def get_instance(cls) -> "RedisClient":
        """Get singleton instance with connection pooling."""
        if cls._instance is None:
            cls._instance = cls()
            await cls._instance.connect()
        return cls._instance

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        if self._client is None:
            redis_url = getattr(self.settings, 'redis_url', 'redis://localhost:6379/0')

            pool_kwargs: dict[str, Any] = dict(
                max_connections=20,
                decode_responses=True,
                # Without explicit timeouts, a slow/black-holed (not just
                # refused) connection to Redis blocks the caller
                # indefinitely - there is no asyncio-level deadline on the
                # underlying socket operations otherwise.
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )

            # Bug fix ("Failed to enable maintenance notifications: unknown
            # subcommand 'MAINT_NOTIFICATIONS'" on every startup): redis-py
            # >= 8.0 sends `CLIENT MAINT_NOTIFICATIONS ON ...` on every new
            # connection by default (MaintNotificationsConfig.enabled=
            # "auto"). That subcommand is a feature of Redis Enterprise/
            # Cloud's active-active maintenance signaling - this project
            # runs against open-source Redis/Valkey (and the deployment
            # commonly points redis_url at Redpanda's bundled Redis-
            # compatible service too), neither of which implements it, so
            # the handshake always fails. redis-py's "auto" mode already
            # catches that failure and continues normally (connectivity was
            # never actually broken), it only logs the failure - but
            # explicitly setting enabled=False here stops the client from
            # ever sending a command the server is known not to support,
            # which is the correct fix (removing the cause) rather than
            # just raising a log level to hide the symptom. Guarded by the
            # availability import above so a redis-py version without this
            # module (< 8.0) still connects exactly as before.
            if MaintNotificationsConfig is not None:
                pool_kwargs["maint_notifications_config"] = MaintNotificationsConfig(
                    enabled=False,
                )

            self._pool = ConnectionPool.from_url(redis_url, **pool_kwargs)
            self._client = redis.Redis(connection_pool=self._pool)

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None
        if self._pool:
            await self._pool.disconnect()
            self._pool = None

    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if self._client is None:
            raise RuntimeError("Redis client not connected. Call connect() first.")
        return self._client

    # ==========================================
    # Basic Cache Operations
    # ==========================================

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        return await self.client.get(key)

    async def set(
        self,
        key: str,
        value: str,
        ttl: Optional[int] = None
    ) -> bool:
        """Set value with optional TTL (seconds)."""
        if ttl:
            return await self.client.setex(key, ttl, value)
        return await self.client.set(key, value)

    async def delete(self, key: str) -> int:
        """Delete key."""
        return await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        return await self.client.exists(key) > 0

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on key."""
        return await self.client.expire(key, seconds)

    # ==========================================
    # JSON Cache Operations
    # ==========================================

    async def get_json(self, key: str) -> Optional[Any]:
        """Get JSON value by key."""
        data = await self.get(key)
        if data:
            return json.loads(data)
        return None

    async def set_json(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """Set JSON value with optional TTL."""
        return await self.set(key, json.dumps(value), ttl)

    # ==========================================
    # Detection Caching
    # ==========================================

    @staticmethod
    def hash_data(data: Any) -> str:
        """Generate hash for detection data."""
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]

    async def cache_detection(
        self,
        data_hash: str,
        result: dict,
        ttl: int = 3600
    ) -> bool:
        """
        Cache detection result to avoid re-processing identical data.

        Args:
            data_hash: Hash of the input data
            result: Detection result to cache
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        key = f"detection:{data_hash}"
        return await self.set_json(key, result, ttl)

    async def get_cached_detection(self, data_hash: str) -> Optional[dict]:
        """Get cached detection result."""
        key = f"detection:{data_hash}"
        return await self.get_json(key)

    # ==========================================
    # LLM Response Caching
    # ==========================================

    async def cache_llm_response(
        self,
        prompt_hash: str,
        response: dict,
        ttl: int = 1800  # 30 minutes default
    ) -> bool:
        """Cache LLM analysis response."""
        key = f"llm:{prompt_hash}"
        return await self.set_json(key, response, ttl)

    async def get_cached_llm_response(self, prompt_hash: str) -> Optional[dict]:
        """Get cached LLM response."""
        key = f"llm:{prompt_hash}"
        return await self.get_json(key)

    # ==========================================
    # Rate Limiting
    # ==========================================

    async def rate_limit(
        self,
        key: str,
        limit: int,
        window: int
    ) -> tuple[bool, int]:
        """
        Check rate limit using sliding window.

        Args:
            key: Rate limit key (e.g., "rate:user:123")
            limit: Maximum requests allowed
            window: Time window in seconds

        Returns:
            Tuple of (allowed: bool, remaining: int)
        """
        full_key = f"ratelimit:{key}"

        # Use Redis pipeline for atomic operations
        pipe = self.client.pipeline()
        pipe.incr(full_key)
        pipe.ttl(full_key)
        results = await pipe.execute()

        current = results[0]
        ttl = results[1]

        # Set expiration on first request
        if ttl == -1:
            await self.client.expire(full_key, window)

        allowed = current <= limit
        remaining = max(0, limit - current)

        return allowed, remaining

    async def get_rate_limit_info(
        self,
        key: str,
        limit: int
    ) -> dict:
        """Get rate limit information for a key."""
        full_key = f"ratelimit:{key}"

        pipe = self.client.pipeline()
        pipe.get(full_key)
        pipe.ttl(full_key)
        results = await pipe.execute()

        current = int(results[0] or 0)
        ttl = max(0, results[1] or 0)

        return {
            "limit": limit,
            "remaining": max(0, limit - current),
            "used": current,
            "reset_in": ttl
        }

    # ==========================================
    # Session Management
    # ==========================================

    async def store_session(
        self,
        session_id: str,
        user_data: dict,
        ttl: int = 86400  # 24 hours
    ) -> bool:
        """Store user session data."""
        key = f"session:{session_id}"
        return await self.set_json(key, user_data, ttl)

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get user session data."""
        key = f"session:{session_id}"
        return await self.get_json(key)

    async def delete_session(self, session_id: str) -> int:
        """Delete user session."""
        key = f"session:{session_id}"
        return await self.delete(key)

    async def refresh_session(self, session_id: str, ttl: int = 86400) -> bool:
        """Refresh session TTL."""
        key = f"session:{session_id}"
        return await self.expire(key, ttl)

    # ==========================================
    # Pub/Sub for Real-time Events
    # ==========================================

    async def publish(self, channel: str, message: dict) -> int:
        """Publish message to channel."""
        return await self.client.publish(channel, json.dumps(message))

    async def subscribe(self, *channels: str):
        """Subscribe to channels. Returns pubsub object."""
        pubsub = self.client.pubsub()
        await pubsub.subscribe(*channels)
        return pubsub

    # ==========================================
    # Health Check
    # ==========================================

    async def health_check(self) -> dict:
        """Check Redis connection health."""
        try:
            await self.client.ping()
            info = await self.client.info("server")
            return {
                "status": "healthy",
                "redis_version": info.get("redis_version", "unknown"),
                "connected_clients": info.get("connected_clients", 0)
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global instance accessor
_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    """Get or create Redis client instance."""
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient()
        await _redis_client.connect()
    return _redis_client


async def close_redis_client() -> None:
    """Close Redis client connection."""
    global _redis_client
    if _redis_client:
        await _redis_client.disconnect()
        _redis_client = None
