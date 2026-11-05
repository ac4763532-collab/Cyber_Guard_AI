"""
CyberGuard AI - Retry and Timeout Utilities

Provides:
- retry_async: Decorator for retrying async functions with exponential backoff
- with_timeout: Wrapper for adding timeout to async operations
"""

import asyncio
import functools
from typing import Any, Callable, Optional, Type, TypeVar, Union

import structlog

logger = structlog.get_logger(__name__)

T = TypeVar("T")


def retry_async(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple[Type[Exception], ...] = (Exception,),
):
    """
    Decorator for retrying async functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        delay: Initial delay between retries in seconds (default: 1.0)
        backoff: Multiplier for delay after each retry (default: 2.0)
        exceptions: Tuple of exception types to retry on (default: (Exception,))

    Example:
        @retry_async(max_retries=3, delay=1.0, exceptions=(ConnectionError,))
        async def fetch_data():
            ...

    Retry sequence (max_retries=3, delay=1.0, backoff=2.0):
        attempt 1 -> fail -> wait 1s
        attempt 2 -> fail -> wait 2s
        attempt 3 -> fail -> wait 4s
        attempt 4 (final) -> fail -> raise

    Note:
        The original exception is preserved and re-raised after max retries.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Optional[Exception] = None
            current_delay = delay

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)

                except exceptions as exc:
                    last_exception = exc

                    if attempt < max_retries:
                        logger.warning(
                            "Retry attempt failed",
                            function=func.__name__,
                            attempt=attempt + 1,
                            max_retries=max_retries,
                            delay=current_delay,
                            error=str(exc),
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            "All retry attempts exhausted",
                            function=func.__name__,
                            attempts=max_retries + 1,
                            error=str(exc),
                        )

            # Re-raise the last exception after all retries exhausted
            if last_exception is not None:
                raise last_exception

            # This should never happen, but satisfy type checker
            raise RuntimeError("Unexpected retry loop exit")

        return wrapper

    return decorator


async def with_timeout(
    coro: Any,
    timeout_seconds: float,
    default: Optional[T] = None,
) -> Optional[T]:
    """
    Execute an async coroutine with a timeout.

    Args:
        coro: The coroutine to execute
        timeout_seconds: Maximum time to wait in seconds
        default: Value to return on timeout (default: None)

    Returns:
        The coroutine result, or default if timeout occurs

    Example:
        result = await with_timeout(
            fetch_data(),
            timeout_seconds=5.0,
            default={"status": "timeout"}
        )
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)

    except asyncio.TimeoutError:
        logger.warning(
            "Operation timed out",
            timeout_seconds=timeout_seconds,
        )
        return default

    except Exception as exc:
        logger.error(
            "Operation failed",
            error=str(exc),
        )
        raise


class RetryableError(Exception):
    """
    Exception that indicates an operation can be retried.

    Use this to wrap transient errors that should trigger retry logic.
    """

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        self.original_exception = original_exception
        super().__init__(message)


# Common transient exception types that are safe to retry
TRANSIENT_EXCEPTIONS: tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    asyncio.TimeoutError,
    RetryableError,
)
