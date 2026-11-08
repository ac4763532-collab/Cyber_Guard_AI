"""
CyberGuard AI — Alembic Migration Environment
============================================================================

The entry point Alembic executes for every migration command. Called by
`alembic revision`, `alembic upgrade`, `alembic downgrade`, `alembic
current`, `alembic history`, and `alembic stamp`.

Responsibilities
----------------
1. **Load configuration from `.env`** via `app.core.config.settings`.
2. **Override the decoy `sqlalchemy.url`** from `alembic.ini` with the
   real URL from settings.
3. **Import all ORM models** so that `Base.metadata` is fully populated
   before autogenerate runs. Without this, autogenerate sees zero tables
   and produces an empty migration.
4. **Configure autogenerate** with the right flags for PostgreSQL.
5. **Provide both `--sql` (offline) and connected (online) migration modes.**
6. **Fail loudly** if the model registry is empty (indicates a broken
   import in `app/models/__init__.py`).

Invocation
----------
    cd backend
    .venv\\Scripts\\Activate.ps1
    alembic current         # show current DB revision
    alembic history         # list all migrations
    alembic upgrade head    # apply pending migrations
    alembic revision --autogenerate -m "add table X"
    alembic downgrade -1    # roll back one revision

Environment
-----------
The `prepend_sys_path = .` setting in `alembic.ini` ensures `from app.*`
imports work when Alembic is invoked from `backend/`.

If you invoke Alembic from a different working directory and get
`ModuleNotFoundError: No module named 'app'`, either:
  - cd into `backend/` first (recommended), OR
  - add `backend/` to PYTHONPATH before invoking alembic.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Configure logging FIRST (before any imports that might log) ────────────
# Alembic's own loggers are configured from `alembic.ini`. Our app logging
# (app.core.logging) is deliberately NOT used here — migrations are a
# developer-facing operation, plain text is appropriate.
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# ── Load the real settings and Base ────────────────────────────────────────
# These imports must come AFTER the logging setup so that if the config is
# invalid, we get a clean log line (from Alembic) before the traceback.
from app.core.config import settings  # noqa: E402
from app.db.base import Base  # noqa: E402

# ── Import all models ──────────────────────────────────────────────────────
# `import app.models` triggers `models/__init__.py`, which imports every
# model file. Each import registers the model's table on `Base.metadata`.
#
# THIS IMPORT IS CRITICAL. If it is removed or commented out, autogenerate
# will produce empty migrations because Base.metadata will contain zero
# tables. Do not delete it under any circumstances.
#
# `# noqa: F401` tells linters "used for side effect only, not for symbols."
import app.models  # noqa: E402, F401

# ── Verify the model registry is non-empty ─────────────────────────────────
# If `app.models` imported successfully but the metadata is still empty,
# something is broken (e.g. a model file has a syntax error that Python
# swallows, or __init__.py stopped importing the models). Fail loudly
# rather than generate a silent empty migration.
if not Base.metadata.tables:
    raise RuntimeError(
        "No tables found in Base.metadata after importing app.models. "
        "This means either:\n"
        "  1. app/models/__init__.py failed to import the models, OR\n"
        "  2. A model file is missing a `__tablename__` attribute, OR\n"
        "  3. A model file has a runtime error caught by a broad try/except.\n"
        "\n"
        "Open app/models/__init__.py and verify every import is uncommented. "
        "Then run: python -c 'from app.db.base import Base; import app.models; "
        "print(sorted(Base.metadata.tables.keys()))'"
    )

# ── Override the decoy URL from alembic.ini ────────────────────────────────
# `alembic.ini` contains a placeholder URL ("__CONFIGURED_IN_ENV_PY__") so
# that Alembic's config parser has something to read at startup. Here we
# replace it with the real URL from settings.
#
# ConfigParser interpolation: any `%` in the URL (rare but possible in
# URL-encoded passwords) must be doubled to `%%`.
_real_url = str(settings.DATABASE_URL)
if "__CONFIGURED_IN_ENV_PY__" in _real_url:
    raise RuntimeError(
        "The DATABASE_URL contains the placeholder '__CONFIGURED_IN_ENV_PY__'. "
        "This means settings.DATABASE_URL was not overridden. Check that "
        "`.env` exists in `backend/` and contains a real DATABASE_URL value."
    )
config.set_main_option("sqlalchemy.url", _real_url.replace("%", "%%"))


# ── Target metadata ────────────────────────────────────────────────────────
# This is what Alembic compares the live DB against to generate migrations.
# Passing the full MetaData object (not a dict) preserves the naming
# convention configured in app.db.base, so constraint names in migrations
# match what the models declare.
target_metadata = Base.metadata


# ============================================================================
# OFFLINE MODE — `alembic upgrade head --sql`
# ============================================================================
# Generates SQL statements without connecting to the database. Useful for:
#   - Reviewing what a migration will do before running it
#   - Handing SQL to a DBA who needs to approve it
#   - Testing migration correctness in a sandbox
#
# No `Engine` is created. No connection is opened. The `url` parameter
# tells Alembic which dialect to emit SQL for.
# ============================================================================
def run_migrations_offline() -> None:
    """Run migrations in offline (SQL-generation) mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,          # inline Python values into SQL
        dialect_opts={"paramstyle": "named"},
        compare_type=True,           # detect column type changes
        compare_server_default=True, # detect default changes
        include_schemas=False,       # no PG schemas; everything in 'public'
        render_as_batch=False,       # Postgres doesn't need batch mode
    )

    with context.begin_transaction():
        context.run_migrations()


# ============================================================================
# ONLINE MODE — `alembic upgrade head`
# ============================================================================
# Connects to the database and executes migrations. This is what you'll use
# 99% of the time.
#
# - `pool.NullPool`: no connection pooling. Migrations are one-shot; the
#   connection is closed when the process exits. Pooled connections would
#   linger as zombie handles.
# - `transaction_per_migration=True`: each migration runs in its own
#   transaction. If migration N fails, migrations 1..N-1 stay applied.
#   Without this, a single failure would roll back the entire history,
#   which is catastrophic on a fresh DB.
# ============================================================================
def run_migrations_online() -> None:
    """Run migrations in online (connected) mode."""
    # Log which DB we're connecting to — password-masked via settings helper.
    # This line appears in Alembic's log output before migrations run, so
    # you can confirm you're pointed at the right database.
    import logging
    logging.getLogger("alembic").info(
        "CyberGuard AI — running migrations against %s",
        settings.safe_database_url(),
    )

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_schemas=False,
            render_as_batch=False,
            transaction_per_migration=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ============================================================================
# DISPATCH — offline vs online
# ============================================================================
# `context.is_offline_mode()` is True when Alembic was invoked with `--sql`.
# This is the canonical dispatch pattern recommended by Alembic's docs.
# ============================================================================
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()