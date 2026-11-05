"""
CyberGuard AI - Database Connection Manager

Manages PostgreSQL connections using psycopg3 (async).
Provides connection pooling and lifecycle management.

Note: The pool is bound to an event loop. If the running loop changes
(e.g., between pytest test modules), the pool automatically reinitializes.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import structlog
from psycopg_pool import AsyncConnectionPool
from psycopg import AsyncConnection
from psycopg.rows import dict_row

from app.config import get_settings


logger = structlog.get_logger(__name__)


class DatabaseManager:
    """
    Database connection manager with connection pooling.

    Usage:
        db = DatabaseManager()
        await db.initialize()

        async with db.connection() as conn:
            result = await conn.execute("SELECT 1")

        await db.close()

    Note:
        The pool is bound to the event loop that calls initialize().
        If the running loop changes, the pool is automatically
        reinitialized to avoid "Event loop is closed" errors.
    """

    def __init__(self):
        self._pool: AsyncConnectionPool | None = None
        self._initialized = False
        self._settings = get_settings()
        self._bound_loop: asyncio.AbstractEventLoop | None = None

    @property
    def is_initialized(self) -> bool:
        return self._initialized and self._pool is not None

    def _check_loop_changed(self) -> bool:
        """Check if the running event loop changed since pool creation."""
        if not self._bound_loop:
            return False
        try:
            current_loop = asyncio.get_running_loop()
            return current_loop is not self._bound_loop
        except RuntimeError:
            # No running loop
            return False

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        # If pool exists but loop changed, reset and reinitialize
        if self._initialized and self._check_loop_changed():
            logger.info("Event loop changed, reinitializing database pool")
            await self._force_reset()

        if self._initialized:
            return

        try:
            # Build connection string
            conninfo = (
                f"host={self._settings.db_host} "
                f"port={self._settings.db_port} "
                f"dbname={self._settings.db_name} "
                f"user={self._settings.db_user} "
                f"password={self._settings.db_password}"
            )

            self._pool = AsyncConnectionPool(
                conninfo=conninfo,
                min_size=2,
                max_size=10,
                kwargs={"row_factory": dict_row},
                open=False,
            )

            await self._pool.open()
            await self._pool.wait()

            # Track which loop this pool is bound to
            self._bound_loop = asyncio.get_running_loop()
            self._initialized = True

            logger.info(
                "Database pool initialized",
                host=self._settings.db_host,
                port=self._settings.db_port,
                database=self._settings.db_name,
            )

        except Exception as e:
            logger.error("Failed to initialize database pool", error=str(e))
            self._initialized = False
            raise

    async def _force_reset(self) -> None:
        """Force reset the pool (used when event loop changes)."""
        if self._pool:
            try:
                await self._pool.close()
            except Exception:
                pass  # Pool may be invalid on different loop
        self._pool = None
        self._initialized = False
        self._bound_loop = None

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            self._initialized = False
            self._bound_loop = None
            logger.info("Database pool closed")

    @asynccontextmanager
    async def connection(self) -> AsyncGenerator[AsyncConnection, None]:
        """Get a connection from the pool."""
        # Auto-reinitialize if loop changed
        if self._check_loop_changed():
            logger.debug("Event loop changed, reinitializing pool before connection")
            await self.initialize()

        if not self._pool:
            raise RuntimeError("Database not initialized")

        async with self._pool.connection() as conn:
            yield conn

    async def execute(
        self,
        query: str,
        params: tuple | dict | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a query and return results."""
        async with self.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, params)
                if cur.description:
                    return await cur.fetchall()
                return []

    async def execute_one(
        self,
        query: str,
        params: tuple | dict | None = None,
    ) -> dict[str, Any] | None:
        """Execute a query and return single result."""
        results = await self.execute(query, params)
        return results[0] if results else None

    async def execute_many(
        self,
        query: str,
        params_list: list[tuple | dict],
    ) -> int:
        """Execute a query with multiple parameter sets."""
        async with self.connection() as conn:
            async with conn.cursor() as cur:
                await cur.executemany(query, params_list)
                return cur.rowcount

    async def health_check(self) -> dict[str, Any]:
        """Check database health."""
        try:
            result = await self.execute_one("SELECT 1 as check, NOW() as timestamp")
            return {
                "status": "healthy",
                "connected": True,
                "timestamp": str(result["timestamp"]) if result else None,
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "connected": False,
                "error": str(e),
            }


# Global instance
_database: DatabaseManager | None = None


def get_database() -> DatabaseManager:
    """Get the global database manager."""
    global _database
    if _database is None:
        _database = DatabaseManager()
    return _database


def reset_database() -> None:
    """Reset the global database manager (for testing)."""
    global _database
    _database = None


async def init_database() -> None:
    """Initialize the global database."""
    db = get_database()
    await db.initialize()


async def close_database() -> None:
    """Close the global database."""
    global _database
    if _database:
        await _database.close()
        _database = None
