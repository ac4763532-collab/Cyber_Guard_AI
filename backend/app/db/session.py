"""
CyberGuard AI — Database Engine and Session Management
============================================================================

Owns the process-wide SQLAlchemy ``Engine``, the session factory, and the
two public session-provider entry points:

    get_db()          — FastAPI dependency. One session per request.
    session_scope()   — context manager for background tasks, agents,
                        CLI scripts, and tests.

Design rules enforced here
--------------------------
1. **Lazy engine construction.** The ``Engine`` is not created at import
   time. Importing ``app.db.session`` never connects to PostgreSQL. The
   first call to ``get_db()`` or ``session_scope()`` builds the engine
   exactly once (guarded by a lock so concurrent first calls are safe).

2. **One session per request.** ``get_db()`` yields a ``Session`` and
   guarantees it is closed. A rollback occurs automatically if the request
   handler raises. **Commit is the caller's responsibility** — the router
   commits at the end of a successful handler. This keeps the transaction
   boundary explicit and prevents silent half-writes.

3. **No ORM imports.** This module imports only from ``app.core`` and
   ``sqlalchemy``. It never imports ``app.models`` — model classes import
   from ``app.db.base``, not from here. This keeps the dependency graph
   acyclic.

4. **Pool tuning is centralized.** Pool size, overflow, timeout, and
   recycle are read from ``settings`` exactly once. Services and endpoints
   do not tune the pool.

5. **PostgreSQL-specific tuning is optional.** ``application_name`` and
   ``statement_timeout`` are set via connect args, which are safely
   ignored if a future deployment uses a non-Postgres engine for tests.

Usage
-----
    # In a FastAPI route:
    from fastapi import Depends
    from sqlalchemy.orm import Session
    from app.db.session import get_db

    @router.get("/widgets")
    def list_widgets(db: Session = Depends(get_db)):
        widgets = db.execute(select(Widget)).scalars().all()
        db.commit()  # explicit
        return widgets

    # In a background task or agent:
    from app.db.session import session_scope

    def run_agent():
        with session_scope() as db:
            events = db.execute(select(Event).limit(100)).scalars().all()
            for event in events:
                process(event, db)

    # In a startup or health endpoint:
    from app.db.session import health_check

    if not health_check():
        raise RuntimeError("Database unreachable")

Why synchronous SQLAlchemy
--------------------------
The rest of the codebase — models, services, agents, collectors — is
written against the synchronous 2.0 API. Reasons:

  - Agents are CPU-bound (parsing, rules, ML) far more than DB-bound.
    Async buys little on the DB side.
  - Synchronous sessions make migrations, scripts, and tests trivial.
  - FastAPI runs sync endpoints in a thread pool, so the API stays
    non-blocking to the event loop.

If a future deployment needs true async I/O, the switch to
``async_sessionmaker`` and ``asyncpg`` is localized to this file.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.exceptions import DatabaseError
from app.core.logging import get_logger

logger = get_logger(__name__)


# ============================================================================
# LAZY ENGINE
# ============================================================================

#: Lock ensures concurrent first calls build exactly one engine.
_engine_lock: threading.RLock = threading.RLock()
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _build_connect_args() -> dict[str, object]:
    """
    Return PostgreSQL-specific connect args. These are ignored by non-PG
    engines, so tests using SQLite are unaffected.
    """
    args: dict[str, object] = {
        # Fast fail connection timeout (seconds) to prevent startup hangs if DB is offline.
        "connect_timeout": 10,
    }
    # Neon Serverless connection pooler (PgBouncer) rejects custom startup 'options'
    db_url = str(settings.DATABASE_URL)
    if "neon.tech" not in db_url and "pooler" not in db_url:
        args["application_name"] = "cyberguard-api"
        args["options"] = f"-c statement_timeout={settings.DB_POOL_TIMEOUT * 1000}"
    return args


def _build_engine() -> Engine:
    """
    Construct the SQLAlchemy engine from ``settings``.

    Reads (all from ``.env``):
        DATABASE_URL      — required
        DB_POOL_SIZE      — default 10
        DB_MAX_OVERFLOW   — default 20
        DB_POOL_TIMEOUT   — default 30 (seconds)
        DB_POOL_RECYCLE   — default 1800 (seconds)
        DB_ECHO           — default False

    Pool class is ``QueuePool`` (default) for a multi-threaded server. If a
    deployment uses a connection pooler such as PgBouncer in transaction
    mode, override by passing ``poolclass=NullPool`` — not done here to
    keep behavior predictable.
    """
    db_url = str(settings.DATABASE_URL)
    if db_url.startswith("postgresql://") and "+psycopg" not in db_url:
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    return create_engine(
        db_url,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE,
        pool_pre_ping=True,  # detect stale connections before use
        echo=settings.DB_ECHO,
        future=True,
        connect_args=_build_connect_args(),
    )


def get_engine() -> Engine:
    """
    Return the process-wide engine, building it lazily on first call.

    Thread-safe. Never returns ``None``. Importing this module does not
    connect; calling this function does (or, more precisely, allocating
    the engine does not connect, but the first session will).
    """
    global _engine
    if _engine is not None:
        return _engine

    with _engine_lock:
        if _engine is None:
            logger.info("Creating database engine", extra={"url": settings.safe_database_url()})
            _engine = _build_engine()
            logger.info("Database engine ready")
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """
    Return the process-wide session factory, building it lazily on first
    call. Thread-safe.
    """
    global _session_factory
    if _session_factory is not None:
        return _session_factory

    with _engine_lock:
        if _session_factory is None:
            engine = get_engine()
            _session_factory = sessionmaker(
                bind=engine,
                class_=Session,
                autoflush=False,
                autocommit=False,
                # Keep ORM objects usable after commit without lazy reload:
                expire_on_commit=False,
            )
    return _session_factory


# ============================================================================
# FASTAPI DEPENDENCY
# ============================================================================

def get_db() -> Iterator[Session]:
    """
    FastAPI dependency: yield one session per request, guarantee close.

    Transaction semantics
    ---------------------
    - **Automatic rollback on exception.** If the request handler raises,
      the ``except`` block rolls back any pending work before re-raising,
      so a partial transaction cannot be committed later by accident.
    - **No automatic commit.** The handler (or the service it calls) is
      responsible for calling ``db.commit()`` when the transaction should
      persist. This is intentional: a session that auto-committed would
      hide bugs where an endpoint returns an error response after some
      writes have already been flushed.
    - **Always closed.** The ``finally`` block closes the session, returning
      the connection to the pool regardless of success or failure.

    Adding to a route:

        @router.post("/x")
        def handler(db: Session = Depends(get_db)):
            ...
            db.commit()
            return ...
    """
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    except Exception:
        try:
            db.rollback()
        except Exception:
            logger.exception("Rollback failed after request exception")
        raise
    finally:
        try:
            db.close()
        except Exception:
            logger.exception("Session close failed")


# ============================================================================
# CONTEXT MANAGER (for background tasks, agents, scripts)
# ============================================================================

@contextmanager
def session_scope() -> Iterator[Session]:
    """
    Context manager wrapping a session with commit-on-success and
    rollback-on-exception. Intended for use **outside** a FastAPI request —
    agents, background workers, CLI scripts, tests.

    Behavior
    --------
    - On normal exit: ``commit()``, then ``close()``.
    - On exception:   ``rollback()``, then ``close()``, then re-raise.

    Usage:

        with session_scope() as db:
            db.add(SomeModel(...))
            # no explicit commit needed — scope does it
    """
    factory = get_session_factory()
    db = factory()
    try:
        yield db
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            logger.exception("Rollback failed inside session_scope")
        raise
    finally:
        try:
            db.close()
        except Exception:
            logger.exception("Session close failed inside session_scope")


# ============================================================================
# HEALTH & LIFECYCLE
# ============================================================================

def health_check() -> bool:
    """
    Return ``True`` if a trivial ``SELECT 1`` succeeds, ``False`` otherwise.

    Used by:
        - ``/health`` endpoint (returns 503 if False)
        - startup hook (raises ``DatabaseError`` if False)
        - diagnostic scripts

    Never raises. Fast connection check using direct engine connection
    to avoid QueuePool acquisition blocks.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(
            "Database health check failed: %s (%s)",
            type(exc).__name__,
            str(exc)[:300],
            extra={"error": type(exc).__name__, "detail": str(exc)[:200]},
        )
        return False


def require_database_ready() -> None:
    """
    Raise ``DatabaseError`` if the database is not reachable. Called from
    ``main.py`` at startup so the process fails fast rather than serving
    error responses for its entire lifetime.
    """
    if not health_check():
        raise DatabaseError(
            message=(
                "Database is not reachable. Verify DATABASE_URL in .env and "
                "that PostgreSQL is running."
            ),
            code="DATABASE_UNREACHABLE",
        )


def dispose_engine() -> None:
    """
    Dispose the engine and drop all pooled connections.

    Called from ``main.py`` on shutdown (``@app.on_event("shutdown")``).
    After this, the next ``get_engine()`` call would build a new engine —
    which is the correct behavior in tests and graceful restarts.
    """
    global _engine, _session_factory
    with _engine_lock:
        if _engine is not None:
            logger.info("Disposing database engine")
            _engine.dispose()
            _engine = None
            _session_factory = None


def reset_for_tests() -> None:
    """
    Tear down cached engine and session factory. Call in test setup/teardown
    after mutating ``DATABASE_URL`` via environment variables.
    """
    dispose_engine()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "get_engine",
    "get_session_factory",
    "get_db",
    "session_scope",
    "health_check",
    "require_database_ready",
    "dispose_engine",
    "reset_for_tests",
]