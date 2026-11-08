"""
CyberGuard AI — Database Layer
============================================================================

Owns the SQLAlchemy engine, session factory, declarative base, and
(transitively) the ORM models.

Dependency direction — strictly one-way
---------------------------------------
    app.core   →   app.db   →   app.models   →   app.schemas
                                          →   app.services
                                          →   app.agents
                                          →   app.api

This package imports from ``app.core`` only. It must **never** import from
``app.models``, ``app.schemas``, ``app.services``, or ``app.api``.

Submodules
----------
base.py
    ``Base`` — the SQLAlchemy 2.0 ``DeclarativeBase`` subclass, configured
    with an explicit constraint naming convention (``pk_``, ``fk_``,
    ``uq_``, ``ix_``, ``ck_``). This convention is essential for Alembic:
    without it, auto-generated constraint names are opaque hashes that
    cannot be referenced in future migrations.

session.py
    - ``engine`` — a lazily constructed ``Engine`` bound to ``DATABASE_URL``
      from ``app.core.config.settings``.
    - ``SessionLocal`` — the ``sessionmaker`` bound to ``engine``.
    - ``get_db()`` — the FastAPI dependency that yields a session per request
      and closes it reliably (context manager / generator).
    - ``session_scope()`` — a context manager for use outside FastAPI
      (background tasks, CLI scripts, agents running outside a request).

Rules enforced by this package
------------------------------
1. **Lazy engine construction.** The engine is not created until the first
   session is requested. This lets the app import cleanly in environments
   where PostgreSQL is not yet available (e.g. CI before migrations run),
   and prevents accidental connections at import time.

2. **One session per request.** The FastAPI dependency ``get_db()`` owns the
   transaction boundary. Endpoints and services receive a ``Session`` — they
   do not create one themselves.

3. **Commits belong to the caller.** Services may call ``session.flush()``
   to obtain IDs, but the *decision* to commit or rollback belongs to the
   request handler (the router) so partial failure can be handled coherently.

4. **No ORM imports here.** ``app.models`` imports ``Base`` from
   ``app.db.base`` directly. This package's ``__init__`` does not import
   models, so importing ``app.db`` does not trigger model class definition.

5. **Naming convention is not optional.** See ``app.db.base`` — constraint
   names matter for reversible migrations.

6. **Timestamps and IDs are the model's responsibility, not the session's.**
   Use ``server_default=func.now()`` and ``default=uuid4`` in the model
   definitions rather than relying on ORM event hooks.

Migration strategy
------------------
Alembic is configured to run against ``app.db.base.Base.metadata``. All
models must be imported (side-effectively) by ``app.models.__init__`` before
Alembic autogenerate is invoked, so their tables register in the metadata.
That import happens inside ``alembic/env.py``, not here.

Connection pooling
------------------
Pool size and overflow are tunable via ``DB_POOL_SIZE``, ``DB_MAX_OVERFLOW``,
``DB_POOL_TIMEOUT``, and ``DB_POOL_RECYCLE`` in ``.env``. The defaults are
chosen for a small production deployment. Scale up behind a connection
pooler (PgBouncer) if the API ever reaches sustained high concurrency.

Why not use ``async_sessionmaker`` / asyncpg
--------------------------------------------
The entire backend — agents, ingestion, services — is written against the
synchronous SQLAlchemy 2.0 API because:

- Agent tasks are CPU-bound (parsing, rule evaluation, ML) far more than
  they are DB-bound; async buys little on the DB side.
- Synchronous sessions make testing, migrations, and scripts trivial.
- FastAPI runs sync endpoints in a thread pool, so the API remains
  non-blocking to the event loop.

If a future deployment needs true async I/O against Postgres, the switch to
``async_sessionmaker`` and ``asyncpg`` is localized to this package — the
rest of the codebase does not need to change.
"""

from __future__ import annotations

# Intentionally no imports. See "No ORM imports here" above.

__all__: list[str] = []