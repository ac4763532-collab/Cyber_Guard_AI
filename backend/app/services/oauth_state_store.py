"""
CyberGuard AI - Shared OAuth State Store

Redis-backed OAuth state storage for multi-process/multi-instance deployment.
Ensures OAuth CSRF protection works regardless of which backend instance
handles the callback.

Security:
- State is cryptographically random (secrets.token_urlsafe)
- TTL ensures automatic expiration (10 minutes)
- Atomic GETDEL ensures single-use consumption
- No sensitive tokens stored in state
- Redis failure does NOT fall back to insecure in-memory storage
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from pydantic import BaseModel, Field
from redis.asyncio import Redis

from app.config import get_settings


logger = structlog.get_logger(__name__)


# OAuth state TTL in seconds (10 minutes)
OAUTH_STATE_TTL = 600

# Redis key prefix for OAuth state
OAUTH_STATE_KEY_PREFIX = "oauth:state:"


class OAuthStateData(BaseModel):
    """OAuth state data stored in Redis."""

    state: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    redirect_after: Optional[str] = None


class OAuthStateStore:
    """
    Shared OAuth state storage using Redis.

    Provides:
    - Multi-instance safe state storage
    - Automatic TTL expiration
    - Atomic single-use consumption via GETDEL
    - Secure failure (no silent fallback to in-memory)

    Security:
    - State tokens are cryptographically random
    - State is single-use (consumed atomically)
    - State expires automatically after 10 minutes
    - No OAuth tokens stored in state (only CSRF data)
    - Redis failure returns error, not insecure fallback
    """

    def __init__(self):
        self._settings = get_settings()
        self._redis: Optional[Redis] = None
        self._connected = False

    async def _get_redis(self) -> Redis:
        """Get Redis connection, initializing if needed."""
        if self._redis is None:
            try:
                self._redis = Redis.from_url(
                    self._settings.redis_url,
                    decode_responses=True,
                )
                # Test connection
                await self._redis.ping()
                self._connected = True
                logger.debug("OAuth state store connected to Redis")
            except Exception as exc:
                self._connected = False
                logger.error(
                    "OAuth state store Redis connection failed",
                    error=str(exc),
                )
                raise RuntimeError(
                    "OAuth state storage unavailable. Redis connection failed."
                ) from exc

        return self._redis

    @property
    def is_available(self) -> bool:
        """Check if Redis is available for state storage."""
        return self._connected

    async def store(
        self,
        user_id: str,
        redirect_after: Optional[str] = None,
    ) -> OAuthStateData:
        """
        Store OAuth state in Redis.

        Args:
            user_id: User initiating the OAuth flow
            redirect_after: URL to redirect to after OAuth

        Returns:
            OAuthStateData with generated state token

        Raises:
            RuntimeError: If Redis is unavailable
        """
        redis = await self._get_redis()

        state_data = OAuthStateData(
            user_id=user_id,
            redirect_after=redirect_after,
        )

        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"

        # Store as JSON with TTL
        value = json.dumps({
            "user_id": state_data.user_id,
            "created_at": state_data.created_at.isoformat(),
            "redirect_after": state_data.redirect_after,
        })

        try:
            await redis.set(key, value, ex=OAUTH_STATE_TTL)

            logger.info(
                "OAuth state stored",
                user_id=user_id,
                # Never log the full state token
                state_prefix=state_data.state[:8],
                ttl_seconds=OAUTH_STATE_TTL,
            )

            return state_data

        except Exception as exc:
            logger.error(
                "Failed to store OAuth state",
                error=str(exc),
            )
            raise RuntimeError(
                "Failed to store OAuth state. Please try again."
            ) from exc

    async def consume(self, state: str) -> Optional[OAuthStateData]:
        """
        Validate and consume OAuth state atomically.

        Uses Redis GETDEL for atomic read-and-delete to ensure
        single-use even with concurrent requests.

        Args:
            state: State token from OAuth callback

        Returns:
            OAuthStateData if valid, None if invalid/expired/already-used

        Note:
            Returns None for any failure to avoid leaking information
            about state validity to potential attackers.
        """
        if not state:
            logger.warning("OAuth state validation failed: empty state")
            return None

        try:
            redis = await self._get_redis()
        except RuntimeError:
            # Redis unavailable - cannot validate
            logger.error("OAuth state validation failed: Redis unavailable")
            return None

        key = f"{OAUTH_STATE_KEY_PREFIX}{state}"

        try:
            # Atomic get-and-delete (single-use enforcement)
            value = await redis.getdel(key)

            if not value:
                logger.warning(
                    "OAuth state validation failed: not found or already used",
                    state_prefix=state[:8] if len(state) >= 8 else "short",
                )
                return None

            data = json.loads(value)

            # Parse created_at and check TTL (belt-and-suspenders with Redis TTL)
            created_at = datetime.fromisoformat(data["created_at"])
            age = datetime.now(timezone.utc) - created_at

            if age > timedelta(seconds=OAUTH_STATE_TTL):
                logger.warning(
                    "OAuth state validation failed: expired",
                    age_seconds=age.total_seconds(),
                    state_prefix=state[:8],
                )
                return None

            state_data = OAuthStateData(
                state=state,
                user_id=data["user_id"],
                created_at=created_at,
                redirect_after=data.get("redirect_after"),
            )

            logger.info(
                "OAuth state consumed",
                user_id=state_data.user_id,
                state_prefix=state[:8],
                age_seconds=int(age.total_seconds()),
            )

            return state_data

        except json.JSONDecodeError:
            logger.error(
                "OAuth state validation failed: corrupt data",
                state_prefix=state[:8] if len(state) >= 8 else "short",
            )
            return None
        except Exception as exc:
            logger.error(
                "OAuth state validation failed: unexpected error",
                error=str(exc),
            )
            return None

    async def exists(self, state: str) -> bool:
        """
        Check if state exists (without consuming).

        For testing/debugging only - normal flow should use consume().
        """
        if not state:
            return False

        try:
            redis = await self._get_redis()
            key = f"{OAUTH_STATE_KEY_PREFIX}{state}"
            return await redis.exists(key) > 0
        except Exception:
            return False

    async def delete(self, state: str) -> bool:
        """
        Explicitly delete a state (cleanup).

        Returns True if deleted, False if not found.
        """
        if not state:
            return False

        try:
            redis = await self._get_redis()
            key = f"{OAUTH_STATE_KEY_PREFIX}{state}"
            deleted = await redis.delete(key)
            return deleted > 0
        except Exception:
            return False

    async def health_check(self) -> dict:
        """Check Redis connection health for OAuth state store."""
        try:
            redis = await self._get_redis()
            await redis.ping()
            return {
                "status": "healthy",
                "store": "redis",
                "ttl_seconds": OAUTH_STATE_TTL,
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "store": "redis",
                "error": str(e),
            }


# Singleton instance
_oauth_state_store: Optional[OAuthStateStore] = None


def get_oauth_state_store() -> OAuthStateStore:
    """Get the OAuth state store singleton."""
    global _oauth_state_store
    if _oauth_state_store is None:
        _oauth_state_store = OAuthStateStore()
    return _oauth_state_store


async def reset_oauth_state_store() -> None:
    """Reset the singleton (for testing)."""
    global _oauth_state_store
    if _oauth_state_store and _oauth_state_store._redis:
        try:
            await _oauth_state_store._redis.close()
        except Exception:
            pass  # Ignore close errors (event loop may be closed)
    _oauth_state_store = None
