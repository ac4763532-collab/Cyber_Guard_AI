"""
CyberGuard AI - Redis-Backed Rate Limiter

Provides reusable async rate limiting for external APIs.
Uses Redis for shared state across processes.

Features:
- Fixed-window rate limiting
- Atomic Redis operations
- Graceful degradation on Redis failure
- Optional bounded waiting
- No infinite waits
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

import structlog
from redis.asyncio import Redis

from app.config import get_settings


logger = structlog.get_logger(__name__)


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded and waiting is not enabled."""

    def __init__(self, key: str, limit: int, window_seconds: int, retry_after: int = 0):
        self.key = key
        self.limit = limit
        self.window_seconds = window_seconds
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for {key}: {limit} requests per {window_seconds}s. "
            f"Retry after {retry_after}s."
        )


class RedisRateLimiter:
    """
    Async Redis-backed rate limiter.

    Uses fixed-window counting with atomic Redis operations.
    Gracefully handles Redis failures by allowing requests through.
    """

    def __init__(self, redis_client: Optional[Redis] = None):
        self._redis = redis_client
        self._settings = get_settings()

    async def _get_redis(self) -> Optional[Redis]:
        """Get Redis client, initializing if needed."""
        if self._redis is not None:
            return self._redis

        try:
            self._redis = Redis.from_url(
                self._settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
            )
            # Test connection
            await asyncio.wait_for(self._redis.ping(), timeout=2.0)
            return self._redis
        except Exception as exc:
            logger.warning("Redis rate limiter initialization failed", error=str(exc))
            return None

    async def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        wait: bool = False,
        max_wait_seconds: float = 30.0,
    ) -> bool:
        """
        Try to acquire a rate limit token.

        Args:
            key: Unique identifier for the rate limit (e.g., "vt:ip")
            limit: Maximum requests allowed in the window
            window_seconds: Time window in seconds
            wait: If True, wait for a token to become available
            max_wait_seconds: Maximum time to wait (prevents infinite waits)

        Returns:
            True if request is allowed, False if limit exceeded and wait=False

        Raises:
            RateLimitExceeded: If limit exceeded, wait=False, and caller wants exception
        """
        redis = await self._get_redis()

        if redis is None:
            # Redis unavailable - allow request (fail open)
            logger.debug("Redis unavailable, allowing request", key=key)
            return True

        full_key = f"ratelimit:{key}"
        start_time = datetime.now(timezone.utc)
        waited = 0.0

        while True:
            try:
                # Atomic increment and get TTL
                pipe = redis.pipeline()
                pipe.incr(full_key)
                pipe.ttl(full_key)
                results = await pipe.execute()

                current_count = results[0]
                ttl = results[1]

                # Set expiration on first request in window
                if ttl == -1:
                    await redis.expire(full_key, window_seconds)
                    ttl = window_seconds

                if current_count <= limit:
                    # Request allowed
                    if waited > 0:
                        logger.debug(
                            "Rate limit token acquired after waiting",
                            key=key,
                            waited_seconds=round(waited, 2),
                        )
                    return True

                # Limit exceeded
                retry_after = max(1, ttl) if ttl > 0 else window_seconds

                if not wait:
                    logger.debug(
                        "Rate limit exceeded",
                        key=key,
                        limit=limit,
                        current=current_count,
                        retry_after=retry_after,
                    )
                    return False

                # Check if we've waited too long
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if elapsed >= max_wait_seconds:
                    logger.warning(
                        "Rate limit wait timeout",
                        key=key,
                        limit=limit,
                        waited_seconds=round(elapsed, 2),
                    )
                    return False

                # Wait and retry (bounded sleep)
                sleep_time = min(1.0, retry_after, max_wait_seconds - elapsed)
                await asyncio.sleep(sleep_time)
                waited = (datetime.now(timezone.utc) - start_time).total_seconds()

            except Exception as exc:
                logger.warning(
                    "Redis rate limit check failed, allowing request",
                    key=key,
                    error=str(exc),
                )
                return True

    async def get_remaining(self, key: str, limit: int) -> int:
        """Get remaining requests in the current window."""
        redis = await self._get_redis()

        if redis is None:
            return limit  # Assume full quota if Redis unavailable

        full_key = f"ratelimit:{key}"

        try:
            current = await redis.get(full_key)
            current_count = int(current) if current else 0
            return max(0, limit - current_count)
        except Exception:
            return limit

    async def get_reset_time(self, key: str) -> int:
        """Get seconds until the rate limit window resets."""
        redis = await self._get_redis()

        if redis is None:
            return 0

        full_key = f"ratelimit:{key}"

        try:
            ttl = await redis.ttl(full_key)
            return max(0, ttl) if ttl > 0 else 0
        except Exception:
            return 0

    async def check_daily_limit(
        self,
        key: str,
        daily_limit: int,
    ) -> bool:
        """
        Check a daily counter limit.

        Uses date-based key that auto-expires after 24 hours.

        Args:
            key: Base key (date will be appended)
            daily_limit: Maximum requests per day

        Returns:
            True if request is allowed
        """
        redis = await self._get_redis()

        if redis is None:
            return True

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        full_key = f"daily:{key}:{today}"

        try:
            pipe = redis.pipeline()
            pipe.incr(full_key)
            pipe.ttl(full_key)
            results = await pipe.execute()

            current_count = results[0]
            ttl = results[1]

            # Set expiration to end of day (24 hours from first request)
            if ttl == -1:
                await redis.expire(full_key, 86400)

            if current_count <= daily_limit:
                return True

            logger.warning(
                "Daily rate limit exceeded",
                key=key,
                limit=daily_limit,
                current=current_count,
            )
            return False

        except Exception as exc:
            logger.warning(
                "Redis daily limit check failed, allowing request",
                key=key,
                error=str(exc),
            )
            return True

    async def get_daily_remaining(self, key: str, daily_limit: int) -> int:
        """Get remaining daily requests."""
        redis = await self._get_redis()

        if redis is None:
            return daily_limit

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        full_key = f"daily:{key}:{today}"

        try:
            current = await redis.get(full_key)
            current_count = int(current) if current else 0
            return max(0, daily_limit - current_count)
        except Exception:
            return daily_limit


# Singleton instance
_rate_limiter: Optional[RedisRateLimiter] = None


def get_rate_limiter() -> RedisRateLimiter:
    """Get or create the rate limiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RedisRateLimiter()
    return _rate_limiter
