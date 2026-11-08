"""
CyberGuard AI — SQLAlchemy Declarative Base
============================================================================

Defines the SQLAlchemy 2.0 ``DeclarativeBase`` subclass used by every ORM
model in the project, along with the three reusable mixins that carry
standard behavior (UUID primary keys, timestamps, soft delete) and the
explicit constraint naming convention that makes every Alembic migration
reversible.

Why the naming convention matters
---------------------------------
SQLAlchemy auto-generates constraint names when they are not provided.
Without a convention those names are opaque database-generated identifiers
that differ between environments and cannot be reliably referenced in later
migrations.

Example failure without a convention:

    1. First migration creates a unique constraint on users.email. The
       auto-generated name depends on the DB backend — Postgres might call
       it ``users_email_key``, while a fresh dev DB on another engine gets
       ``uq_9f8b1c2a``.

    2. Six months later, a migration needs to drop or alter that
       constraint. Because the name is not stable across environments, the
       migration either fails on a fresh database or silently targets the
       wrong constraint.

With the convention below, that same constraint is named ``uq_users_email``
everywhere, in every environment, forever — and the migration that drops it
will work.

The convention also enforces consistency in tracebacks, error messages, and
``\\d`` output in psql, which matters when a production incident is under
investigation and every detail is being read by people under pressure.

Rules enforced by this module
-----------------------------
1. **Every model inherits from ``Base``.** No independent
   ``declarative_base()`` calls anywhere in the codebase — that would
   produce a second ``MetaData`` object and break Alembic autogenerate.

2. **Every table has a primary key.** Enforced by convention and by
   ``UUIDPrimaryKeyMixin``. Models that need a natural or composite primary
   key may declare their own — they just skip the mixin.

3. **Timestamps are timezone-aware UTC.** Provided by ``TimestampMixin``.
   Naive datetimes are never used.

4. **Soft delete is opt-in.** Provided by ``SoftDeleteMixin``. Hard delete
   remains possible; this mixin provides the standard column and the
   ``is_deleted`` helper, nothing more.

5. **No imports from other ``app.*`` modules.** This module imports only
   from ``sqlalchemy`` and the Python standard library. It is a leaf in
   the ``app.db`` package.

6. **No connection is opened here.** The engine lives in
   ``app.db.session``. Importing ``Base`` does not connect to the database.

7. **PostgreSQL 13+ is required.** ``UUIDPrimaryKeyMixin`` uses the
   server-side ``gen_random_uuid()`` function, which is built in to
   PostgreSQL 13 and later. Older versions require the ``pgcrypto``
   extension; do not deploy on a version below 13 without adding it.

Usage
-----
    from sqlalchemy import String
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.base import (
        Base,
        UUIDPrimaryKeyMixin,
        TimestampMixin,
        SoftDeleteMixin,
    )

    class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
        __tablename__ = "users"

        email: Mapped[str] = mapped_column(String(320), unique=True)


    class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
        __tablename__ = "incidents"

        title: Mapped[str] = mapped_column(String(255))
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# ============================================================================
# NAMING CONVENTION
# ============================================================================
# Applied to every constraint on every table. Changes here require a
# migration to rename existing constraints — do not modify after the first
# production deployment.
#
# Available tokens:
#   %(table_name)s           — table name
#   %(referred_table_name)s  — table referenced by a foreign key
#   %(column_0_name)s        — first column name in the constraint
#   %(column_0_N_name)s      — all column names in the constraint, joined
#   %(constraint_name)s      — user-supplied name (required for CHECK)
#
# We use ``column_0_N_name`` for ``ix`` and ``uq`` so composite indexes get
# distinct names per column set. Without it, two different composite indexes
# starting with the same first column would collide.

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


# ============================================================================
# DECLARATIVE BASE
# ============================================================================

class Base(DeclarativeBase):
    """
    Root declarative base for every ORM model.

    Provides:
      - The shared ``MetaData`` object with the naming convention above.
        Alembic's ``target_metadata`` points at ``Base.metadata``.
      - A safe ``__repr__`` for debugging that never leaks sensitive
        columns (only the primary key is shown).
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:
        cls_name = type(self).__name__
        pk_value: Any = getattr(self, "id", None)
        if pk_value is not None:
            return f"<{cls_name} id={pk_value}>"
        return f"<{cls_name}>"


# ============================================================================
# UUID PRIMARY KEY MIXIN
# ============================================================================

class UUIDPrimaryKeyMixin:
    """
    Adds a UUID primary key ``id`` column.

    - Uses PostgreSQL native ``UUID`` type (not a string).
    - Defaults are generated both client-side (``uuid.uuid4``) and
      server-side (``gen_random_uuid()``). This means IDs are generated
      correctly even when rows are inserted outside the ORM — bulk loads,
      raw SQL, or another service writing to the same table.
    - Indexed automatically because it is the primary key; no explicit
      ``index=True`` needed.

    Requires PostgreSQL 13 or later for the server-side default.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )


# ============================================================================
# TIMESTAMP MIXIN
# ============================================================================

class TimestampMixin:
    """
    Adds ``created_at`` and ``updated_at`` columns.

    - Both columns are timezone-aware (``TIMESTAMPTZ`` in PostgreSQL).
    - ``created_at`` is set once at insert time and is not expected to
      change afterwards.
    - ``updated_at`` is set at insert time and refreshed on ORM update via
      ``onupdate=``. Writers that bypass the ORM — raw SQL, another
      service — must set ``updated_at`` themselves. For strict correctness
      in a multi-writer environment, add a database trigger via migration:

          CREATE OR REPLACE FUNCTION set_updated_at()
          RETURNS TRIGGER AS $$
          BEGIN
              NEW.updated_at = now();
              RETURN NEW;
          END;
          $$ LANGUAGE plpgsql;

          CREATE TRIGGER trg_<table>_updated_at
          BEFORE UPDATE ON <table>
          FOR EACH ROW EXECUTE FUNCTION set_updated_at();

      This module does not create triggers automatically because trigger
      creation is a database-level concern and should be applied via
      Alembic migrations, not ORM model definitions.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )


# ============================================================================
# SOFT DELETE MIXIN
# ============================================================================

class SoftDeleteMixin:
    """
    Adds a nullable ``deleted_at`` timestamp for soft deletion.

    Usage pattern:
        - Models using this mixin are not physically deleted by default.
        - Query layers should filter ``Model.deleted_at.is_(None)`` unless
          historical data is explicitly requested.
        - The service layer decides when to soft-delete. This mixin
          provides only the column and the ``is_deleted`` convenience
          property.

    Hard delete remains possible by calling ``session.delete(obj)``. This
    mixin does not prevent it — it just provides the standard column for
    soft-deletion workflows.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,
    )

    @property
    def is_deleted(self) -> bool:
        """True if the row has been soft-deleted."""
        return self.deleted_at is not None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "Base",
    "UUIDPrimaryKeyMixin",
    "TimestampMixin",
    "SoftDeleteMixin",
    "NAMING_CONVENTION",
]