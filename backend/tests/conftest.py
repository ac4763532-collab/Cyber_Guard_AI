"""
CyberGuard AI - Test Configuration

Pytest fixtures and configuration for running tests with DB_ENABLED=true.
"""

import asyncio
import sys
import pytest
from fastapi.testclient import TestClient

# Fix Windows event loop for psycopg3
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


_db_initialized = False
_init_loop = None


def get_db_loop():
    """Get the event loop used for database operations."""
    global _init_loop
    return _init_loop


@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    """Initialize database connection pool before tests if DB_ENABLED."""
    global _db_initialized, _init_loop

    from app.config import get_settings

    settings = get_settings()
    if settings.db_enabled and not _db_initialized:
        _init_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_init_loop)

        async def _init():
            from app.database import init_database
            await init_database()

        _init_loop.run_until_complete(_init())
        _db_initialized = True

    yield

    # Cleanup: close database pool
    if settings.db_enabled and _db_initialized and _init_loop:
        async def _cleanup():
            from app.database import close_database
            await close_database()

        try:
            _init_loop.run_until_complete(_cleanup())
            _init_loop.close()
        except Exception:
            pass  # Ignore errors during cleanup


@pytest.fixture(scope="session")
def test_client(initialize_database):
    """
    One TestClient (one app lifespan, one DatabaseManager pool, one Redis
    connection) shared across the ENTIRE test session, for any module
    that needs real HTTP-level requests against DB-backed auth.

    Each `with TestClient(app) as c:` fully runs the app's lifespan,
    including init_database()/close_database() - a module- or
    function-scoped client fixture re-enters that lifespan once per
    module/test, and DatabaseManager's singleton pool was observed
    (reproduced directly, outside pytest, in the course of fixing
    tests/test_log_file_upload.py) to come out of a second rapid-fire
    open->close->reopen cycle in a broken state: is_initialized reports
    True, but the very next query still raises "Database not
    initialized". DatabaseManager's own loop-change handling
    (_check_loop_changed/_force_reset) is designed for the pool's bound
    loop changing *while the pool stays open*, not for tearing the pool
    all the way down and rebuilding it from a brand-new TestClient
    portal thread repeatedly within one process - that combination
    reliably orphans the previous pool's background scheduler/worker
    tasks ("Task was destroyed but it is pending!") and leaves the new
    one unusable. A real deployed server never opens/closes its pool
    between requests, so one TestClient for the whole session matches
    real usage and avoids the race rather than trying to make rapid
    full lifespan cycles robust (a pre-existing DatabaseManager/
    psycopg_pool fragility on Windows, out of scope to fix here).

    Does not replace any test module's own `client` fixture - existing
    modules (test_email_upload.py, test_incidents_api_auth.py, etc.)
    keep their own, unmodified. Only new modules that need to coexist
    with other DB-backed TestClient usage in the same session should
    depend on this one instead of defining their own.
    """
    from app.main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="session")
def rate_limit_disabled(test_client):
    """
    Disables the real, Redis-backed, IP-keyed slowapi rate limiter
    (app.middleware.rate_limit.limiter, app.state.limiter) for the
    duration of the test session.

    Only opt in from a test module that depends on this fixture
    explicitly - it does not run automatically and does not touch
    app/middleware/rate_limit.py's actual production limits. Needed by
    any module making enough rapid real HTTP requests against a
    rate-limited endpoint (e.g. the 30/minute default on
    POST /analysis/logs/upload) to legitimately trip the real limit
    across a shared test_client session - a correctness property of the
    limiter itself, not a bug in the endpoint or the tests, but not
    something a test suite should be bound by either.
    """
    from app.main import app

    original = app.state.limiter.enabled
    app.state.limiter.enabled = False
    yield
    app.state.limiter.enabled = original


@pytest.fixture
def db_test_user_viewer(initialize_database):
    """Get or create a viewer test user in the database."""
    from app.config import get_settings

    settings = get_settings()
    if not settings.db_enabled:
        # Fallback for non-DB mode
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate
        user_manager = get_user_manager()
        user = user_manager.get_user_by_username("viewer")
        if not user:
            user = user_manager.create_user(UserCreate(
                username="viewer",
                password="testpass123!",
                email="viewer@test.com",
                role=UserRole.VIEWER,
            ))
        return user

    # For DB mode: create a fresh loop and re-init pool
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _get_or_create():
        from app.database.connection import get_database
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate

        # Always re-initialize the pool on this loop
        db = get_database()
        try:
            await db.initialize()
        except Exception:
            pass  # May already be initialized

        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async("viewer")
        if not user:
            user = await user_manager.create_user_async(UserCreate(
                username="viewer",
                password="testpass123!",
                email="viewer@test.com",
                role=UserRole.VIEWER,
            ))
        return user

    return loop.run_until_complete(_get_or_create())


@pytest.fixture
def db_test_user_analyst(initialize_database):
    """Get or create an analyst test user in the database."""
    from app.config import get_settings

    settings = get_settings()
    if not settings.db_enabled:
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate
        user_manager = get_user_manager()
        user = user_manager.get_user_by_username("analyst")
        if not user:
            user = user_manager.create_user(UserCreate(
                username="analyst",
                password="testpass123!",
                email="analyst@test.com",
                role=UserRole.ANALYST,
            ))
        return user

    # For DB mode: create a fresh loop and re-init pool
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _get_or_create():
        from app.database.connection import get_database
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate

        # Always re-initialize the pool on this loop
        db = get_database()
        try:
            await db.initialize()
        except Exception:
            pass

        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async("analyst")
        if not user:
            user = await user_manager.create_user_async(UserCreate(
                username="analyst",
                password="testpass123!",
                email="analyst@test.com",
                role=UserRole.ANALYST,
            ))
        return user

    return loop.run_until_complete(_get_or_create())


@pytest.fixture
def db_test_user_viewer2(initialize_database):
    """Get or create a second viewer test user in the database."""
    from app.config import get_settings

    settings = get_settings()
    if not settings.db_enabled:
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate
        user_manager = get_user_manager()
        user = user_manager.get_user_by_username("viewer2")
        if not user:
            user = user_manager.create_user(UserCreate(
                username="viewer2",
                password="testpass123!",
                email="viewer2@test.com",
                role=UserRole.VIEWER,
            ))
        return user

    # For DB mode: create a fresh loop and re-init pool
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _get_or_create():
        from app.database.connection import get_database
        from app.auth import get_user_manager, UserRole
        from app.auth.models import UserCreate

        # Always re-initialize the pool on this loop
        db = get_database()
        try:
            await db.initialize()
        except Exception:
            pass

        user_manager = get_user_manager()
        user = await user_manager.get_user_by_username_async("viewer2")
        if not user:
            user = await user_manager.create_user_async(UserCreate(
                username="viewer2",
                password="testpass123!",
                email="viewer2@test.com",
                role=UserRole.VIEWER,
            ))
        return user

    return loop.run_until_complete(_get_or_create())
