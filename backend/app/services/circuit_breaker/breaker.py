"""
CyberGuard AI - Circuit Breaker

Implements the circuit breaker pattern for external service resilience.
Uses Redis for shared state across processes.

States:
- CLOSED: Normal operation, requests pass through
- OPEN: Service is down, fail immediately
- HALF_OPEN: Testing if service recovered

Behavior:
- CLOSED: Track failures, open circuit after threshold
- OPEN: Reject requests immediately, transition to HALF_OPEN after cooldown
- HALF_OPEN: Allow one test request, close on success, open on failure
"""

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, TypeVar, Optional, Any

import structlog
from redis.asyncio import Redis

from app.config import get_settings


logger = structlog.get_logger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is rejected."""

    def __init__(self, service_name: str, retry_after: int = 0):
        self.service_name = service_name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker open for {service_name}. "
            f"Service temporarily unavailable. Retry after {retry_after}s."
        )


class CircuitBreaker:
    """
    Redis-backed circuit breaker for external services.

    Gracefully handles Redis failures by allowing requests through.
    """

    def __init__(
        self,
        service_name: str,
        failure_threshold: int = 5,
        recovery_timeout_seconds: int = 60,
        redis_client: Optional[Redis] = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            service_name: Unique name for the service (e.g., "virustotal")
            failure_threshold: Number of failures before opening circuit
            recovery_timeout_seconds: Seconds to wait before testing recovery
            redis_client: Optional Redis client (will create one if not provided)
        """
        self.service_name = service_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout_seconds
        self._redis = redis_client
        self._settings = get_settings()

        # Redis keys
        self._state_key = f"circuit:{service_name}:state"
        self._failures_key = f"circuit:{service_name}:failures"
        self._last_failure_key = f"circuit:{service_name}:last_failure"
        self._half_open_lock = f"circuit:{service_name}:half_open_lock"

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
            await asyncio.wait_for(self._redis.ping(), timeout=2.0)
            return self._redis
        except Exception as exc:
            logger.warning(
                "Circuit breaker Redis initialization failed",
                service=self.service_name,
                error=str(exc),
            )
            return None

    async def get_state(self) -> CircuitState:
        """Get current circuit state."""
        redis = await self._get_redis()

        if redis is None:
            return CircuitState.CLOSED  # Fail open if Redis unavailable

        try:
            state = await redis.get(self._state_key)

            if state == CircuitState.OPEN.value:
                # Check if recovery timeout has passed
                last_failure = await redis.get(self._last_failure_key)
                if last_failure:
                    elapsed = datetime.now(timezone.utc).timestamp() - float(last_failure)
                    if elapsed >= self.recovery_timeout:
                        # Transition to half-open
                        await self._set_state(CircuitState.HALF_OPEN)
                        return CircuitState.HALF_OPEN
                return CircuitState.OPEN

            elif state == CircuitState.HALF_OPEN.value:
                return CircuitState.HALF_OPEN

            return CircuitState.CLOSED

        except Exception as exc:
            logger.warning(
                "Circuit breaker state check failed",
                service=self.service_name,
                error=str(exc),
            )
            return CircuitState.CLOSED

    async def _set_state(self, state: CircuitState) -> None:
        """Set circuit state."""
        redis = await self._get_redis()
        if redis:
            try:
                # State expires after 24 hours to auto-recover from stale state
                await redis.setex(self._state_key, 86400, state.value)
            except Exception:
                pass

    async def record_success(self) -> None:
        """Record a successful request - reset failures and close circuit."""
        redis = await self._get_redis()
        if redis is None:
            return

        try:
            current_state = await self.get_state()

            if current_state == CircuitState.HALF_OPEN:
                # Success in half-open state - close circuit
                logger.info(
                    "Circuit breaker closing after successful recovery",
                    service=self.service_name,
                )

                # Step 10: Log circuit recovery
                try:
                    from app.logging import log_circuit_recovered
                    log_circuit_recovered(
                        service_name=self.service_name,
                        state=CircuitState.CLOSED.value,
                    )
                except Exception:
                    pass

            # Reset failures and close circuit
            pipe = redis.pipeline()
            pipe.delete(self._failures_key)
            pipe.delete(self._half_open_lock)
            pipe.setex(self._state_key, 86400, CircuitState.CLOSED.value)
            await pipe.execute()

        except Exception as exc:
            logger.warning(
                "Circuit breaker success recording failed",
                service=self.service_name,
                error=str(exc),
            )

    async def record_failure(self) -> None:
        """Record a failed request - increment failures, potentially open circuit."""
        redis = await self._get_redis()
        if redis is None:
            return

        try:
            current_state = await self.get_state()

            if current_state == CircuitState.HALF_OPEN:
                # Failure in half-open state - reopen circuit
                logger.warning(
                    "Circuit breaker reopening after failed recovery test",
                    service=self.service_name,
                )
                await self._open_circuit()
                return

            # Increment failure count
            pipe = redis.pipeline()
            pipe.incr(self._failures_key)
            pipe.expire(self._failures_key, self.recovery_timeout * 2)
            results = await pipe.execute()

            failure_count = results[0]

            if failure_count >= self.failure_threshold:
                logger.warning(
                    "Circuit breaker opening",
                    service=self.service_name,
                    failures=failure_count,
                    threshold=self.failure_threshold,
                )
                await self._open_circuit()

                # Step 10: Log security event
                try:
                    from app.logging import log_circuit_opened
                    log_circuit_opened(
                        service_name=self.service_name,
                        state=CircuitState.OPEN.value,
                        failure_count=failure_count,
                        reason=f"Exceeded failure threshold ({self.failure_threshold})",
                    )
                except Exception:
                    pass

        except Exception as exc:
            logger.warning(
                "Circuit breaker failure recording failed",
                service=self.service_name,
                error=str(exc),
            )

    async def _open_circuit(self) -> None:
        """Open the circuit."""
        redis = await self._get_redis()
        if redis is None:
            return

        try:
            pipe = redis.pipeline()
            pipe.setex(self._state_key, 86400, CircuitState.OPEN.value)
            pipe.set(self._last_failure_key, str(datetime.now(timezone.utc).timestamp()))
            pipe.expire(self._last_failure_key, self.recovery_timeout * 2)
            pipe.delete(self._half_open_lock)
            await pipe.execute()
        except Exception:
            pass

    async def allow_request(self) -> bool:
        """
        Check if a request should be allowed.

        Returns:
            True if request is allowed, False if circuit is open
        """
        state = await self.get_state()

        if state == CircuitState.CLOSED:
            return True

        if state == CircuitState.OPEN:
            # Calculate retry time
            redis = await self._get_redis()
            retry_after = self.recovery_timeout

            if redis:
                try:
                    last_failure = await redis.get(self._last_failure_key)
                    if last_failure:
                        elapsed = datetime.now(timezone.utc).timestamp() - float(last_failure)
                        retry_after = max(0, int(self.recovery_timeout - elapsed))
                except Exception:
                    pass

            logger.debug(
                "Circuit breaker rejecting request",
                service=self.service_name,
                state=state.value,
                retry_after=retry_after,
            )
            return False

        if state == CircuitState.HALF_OPEN:
            # Allow one request through for testing
            redis = await self._get_redis()
            if redis:
                try:
                    # Use a lock to ensure only one request tests
                    acquired = await redis.set(
                        self._half_open_lock,
                        "1",
                        nx=True,
                        ex=30,  # Lock expires after 30 seconds
                    )
                    if acquired:
                        logger.debug(
                            "Circuit breaker allowing test request",
                            service=self.service_name,
                        )
                        return True
                except Exception:
                    pass

            # Another request is already testing
            return False

        return True

    async def call(
        self,
        func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Execute a function with circuit breaker protection.

        Args:
            func: Async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The function result

        Raises:
            CircuitOpenError: If circuit is open
            Exception: Any exception from the function (after recording failure)
        """
        if not await self.allow_request():
            redis = await self._get_redis()
            retry_after = self.recovery_timeout

            if redis:
                try:
                    last_failure = await redis.get(self._last_failure_key)
                    if last_failure:
                        elapsed = datetime.now(timezone.utc).timestamp() - float(last_failure)
                        retry_after = max(0, int(self.recovery_timeout - elapsed))
                except Exception:
                    pass

            raise CircuitOpenError(self.service_name, retry_after)

        try:
            result = await func(*args, **kwargs)
            await self.record_success()
            return result

        except Exception as exc:
            await self.record_failure()
            raise


# Circuit breaker instances for each service
_circuit_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    service_name: str,
    failure_threshold: Optional[int] = None,
    recovery_timeout_seconds: Optional[int] = None,
) -> CircuitBreaker:
    """
    Get or create a circuit breaker for a service.

    Args:
        service_name: Unique service identifier
        failure_threshold: Override default failure threshold
        recovery_timeout_seconds: Override default recovery timeout

    Returns:
        CircuitBreaker instance
    """
    if service_name not in _circuit_breakers:
        settings = get_settings()

        # Use settings defaults if not overridden
        threshold = failure_threshold or getattr(
            settings, "external_circuit_failure_threshold", 5
        )
        timeout = recovery_timeout_seconds or getattr(
            settings, "external_circuit_recovery_seconds", 60
        )

        _circuit_breakers[service_name] = CircuitBreaker(
            service_name=service_name,
            failure_threshold=threshold,
            recovery_timeout_seconds=timeout,
        )

    return _circuit_breakers[service_name]
