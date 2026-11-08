"""
CyberGuard AI — Shared FastAPI Dependencies
============================================================================

The single import surface for endpoint dependencies. Routers do:

    from app.api.deps import (
        DBDep, PageDep, SortDep,
        get_db, get_pagination, get_sort,
        CurrentActiveUser, get_current_active_user,
        require_permission,
    )

Never:

    from app.db.session import get_db                     ❌
    from app.schemas.common import PageParams             ❌ (use deps)
    from app.auth.dependencies import get_current_user    ❌ (use deps)

Why this matters
----------------
- **Single point of change.** If session management becomes async, or
  pagination gains a cursor-based variant, this is the only file that
  needs to know.
- **Consistent defaults.** Every list endpoint uses the same
  ``DEFAULT_PAGE_SIZE``, ``MAX_PAGE_SIZE``, and ``DEFAULT_SORT_ORDER``.
- **Consistent OpenAPI docs.** Query parameters are documented the
  same way in every endpoint that uses pagination.

What's re-exported here
-----------------------
Infrastructure:
    ``get_db``             — SQLAlchemy session (from ``app.db.session``)
    ``DBDep``              — ``Annotated[Session, Depends(get_db)]``

Pagination & sorting:
    ``get_pagination``     — parses ``page``/``page_size`` query params
    ``get_sort``           — parses ``sort_by``/``sort_order`` query params
    ``PageDep``            — ``Annotated[PageParams, Depends(get_pagination)]``
    ``SortDep``            — ``Annotated[SortParams, Depends(get_sort)]``

Authentication:
    ``get_current_user``             — from ``app.auth.dependencies``
    ``get_current_active_user``      — from ``app.auth.dependencies``
    ``get_current_verified_user``    — from ``app.auth.dependencies``
    ``get_current_user_optional``    — from ``app.auth.dependencies``
    ``get_current_analyst``          — from ``app.auth.dependencies``
    ``get_current_super_admin``      — from ``app.auth.dependencies``
    ``require_permission``           — from ``app.auth.dependencies``
    ``require_any_permission``       — from ``app.auth.dependencies``
    ``CurrentUser``                  — ``Annotated[User, Depends(...)]``
    ``CurrentActiveUser``            — ``Annotated[User, Depends(...)]``
    ``CurrentVerifiedUser``          — ``Annotated[User, Depends(...)]``
    ``OptionalUser``                 — ``Annotated[User | None, Depends(...)]``
    ``CurrentAnalyst``               — ``Annotated[AnalystProfile, Depends(...)]``

The ``Annotated`` type aliases (``DBDep``, ``PageDep``, ``CurrentUser``,
...) let endpoints write:

    @router.get("/users")
    def list_users(
        db: DBDep,
        page: PageDep,
        user: CurrentActiveUser,
    ) -> PaginatedResponse[UserRead]:
        ...

Instead of:

    def list_users(
        db: Session = Depends(get_db),
        page: PageParams = Depends(get_pagination),
        user: User = Depends(get_current_active_user),
    ):
        ...

Both styles work. Prefer the ``Annotated`` style — it reads like a type
declaration, eliminates parameter-default repetition, and plays nicely
with FastAPI's introspection for OpenAPI generation.

What NOT to put here
--------------------
- Business logic (services)
- SQL queries (services)
- Model definitions (models)
- Response schemas (schemas)
- JWT encoding/decoding (app.auth.jwt, app.core.security)

This module is **pure dependency wiring** — it composes existing
primitives, it does not create new ones.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Query

# ── Session dependency (re-exported from app.db.session) ──────────────────
from app.db.session import get_db
from sqlalchemy.orm import Session

# ── Schema imports for pagination / sorting ───────────────────────────────
from app.core.constants import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_SORT_ORDER,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
    SORT_ORDERS,
)
from app.schemas.common import PageParams, SortParams

# ── Auth dependencies (re-exported from app.auth.dependencies) ────────────
from app.auth.dependencies import (
    get_current_active_user,
    get_current_analyst,
    get_current_super_admin,
    get_current_user,
    get_current_user_optional,
    get_current_verified_user,
    require_any_permission,
    require_permission,
)
from app.models.analyst import AnalystProfile
from app.models.user import User


# ============================================================================
# PAGINATION DEPENDENCY
# ============================================================================

def get_pagination(
    page: int = Query(
        default=1,
        ge=1,
        le=10_000,
        description="1-indexed page number (first page = 1).",
        examples=[1],
    ),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=MIN_PAGE_SIZE,
        le=MAX_PAGE_SIZE,
        description=f"Items per page ({MIN_PAGE_SIZE}–{MAX_PAGE_SIZE}).",
        examples=[DEFAULT_PAGE_SIZE],
    ),
) -> PageParams:
    """
    Parse pagination query parameters.

    Returns a ``PageParams`` instance with the derived ``offset`` and
    ``limit`` properties used by services.
    """
    return PageParams(page=page, page_size=page_size)


# ============================================================================
# SORT DEPENDENCY
# ============================================================================

def get_sort(
    sort_by: str | None = Query(
        default=None,
        max_length=64,
        description=(
            "Column to sort by. Validated per endpoint — unknown values "
            "return 422 from the endpoint's own check."
        ),
        examples=["created_at"],
    ),
    sort_order: str = Query(
        default=DEFAULT_SORT_ORDER,
        description=f"Sort direction: one of {SORT_ORDERS}.",
        examples=[DEFAULT_SORT_ORDER],
    ),
) -> SortParams:
    """
    Parse sort query parameters. Column validation is delegated to each
    endpoint (different resources expose different sortable columns).
    """
    return SortParams(sort_by=sort_by, sort_order=sort_order)


# ============================================================================
# ANNOTATED TYPE ALIASES
# ============================================================================
# Modern FastAPI style for cleaner endpoint signatures. Endpoints use
# these in parameter position without needing a `= Depends(...)` default.

# ─── Database ──────────────────────────────────────────────────────────────
DBDep = Annotated[Session, __import__("fastapi").Depends(get_db)]

# ─── Pagination & sorting ──────────────────────────────────────────────────
PageDep = Annotated[PageParams, __import__("fastapi").Depends(get_pagination)]
SortDep = Annotated[SortParams, __import__("fastapi").Depends(get_sort)]

# ─── Authentication ────────────────────────────────────────────────────────
CurrentUser = Annotated[
    User, __import__("fastapi").Depends(get_current_user)
]
CurrentActiveUser = Annotated[
    User, __import__("fastapi").Depends(get_current_active_user)
]
CurrentVerifiedUser = Annotated[
    User, __import__("fastapi").Depends(get_current_verified_user)
]
OptionalUser = Annotated[
    User | None, __import__("fastapi").Depends(get_current_user_optional)
]
CurrentAnalyst = Annotated[
    AnalystProfile, __import__("fastapi").Depends(get_current_analyst)
]
CurrentSuperAdmin = Annotated[
    User, __import__("fastapi").Depends(get_current_super_admin)
]


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Infrastructure
    "get_db",
    "DBDep",
    # Pagination & sorting
    "get_pagination",
    "get_sort",
    "PageDep",
    "SortDep",
    # Auth — functions
    "get_current_user",
    "get_current_active_user",
    "get_current_verified_user",
    "get_current_user_optional",
    "get_current_analyst",
    "get_current_super_admin",
    "require_permission",
    "require_any_permission",
    # Auth — Annotated aliases
    "CurrentUser",
    "CurrentActiveUser",
    "CurrentVerifiedUser",
    "OptionalUser",
    "CurrentAnalyst",
    "CurrentSuperAdmin",
]