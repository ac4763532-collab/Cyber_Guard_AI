"""
CyberGuard AI — API Package
============================================================================

The HTTP layer: FastAPI routers and endpoint handlers. Every other package
(models, schemas, services, agents) exists to serve what this package
exposes over HTTP.

Structure
---------
    app/api/
    ├── __init__.py         (this file — package marker, no imports)
    ├── deps.py             (shared FastAPI dependencies)
    └── v1/
        ├── __init__.py     (builds the api_router)
        ├── auth.py         (POST /auth/register, /login, /refresh, GET /auth/me)
        ├── users.py        (GET/PATCH /users/*)
        ├── organizations.py
        ├── workspaces.py
        ├── sources.py
        ├── events.py
        ├── findings.py
        ├── alerts.py
        ├── incidents.py
        ├── cases.py
        ├── evidence.py
        ├── conversations.py
        ├── notifications.py
        ├── reports.py
        └── admin.py

Routing model
-------------
Each v1 module defines its own ``router = APIRouter(...)``. The aggregator
in ``app/api/v1/__init__.py`` composes them into a single ``api_router``.
``main.py`` mounts ``api_router`` at ``API_PREFIX`` (``/api/v1``).

    main.py:
        app.include_router(api_router, prefix=API_PREFIX)

    api/v1/__init__.py:
        api_router = APIRouter()
        api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
        api_router.include_router(users.router, prefix="/users", tags=["users"])
        ...

    api/v1/auth.py:
        router = APIRouter()

        @router.post("/register", response_model=TokenResponse)
        def register(body: RegisterRequest) -> TokenResponse:
            ...

Design rules — every endpoint file follows these
------------------------------------------------
1. **Zero imports at package load.**
   ``import app.api`` must be a no-op. It must not trigger imports of
   ``main.py``, any router, or any DB session. Sub-modules are imported
   explicitly by callers (``from app.api.deps import get_db``,
   ``from app.api.v1 import api_router``).

2. **All shared dependencies live in ``app/api/deps.py``.**
   Endpoints do::

       from app.api.deps import get_db, get_pagination, get_sort

   NOT::

       from app.db.session import get_db                  ❌
       from app.schemas.common import PageParams          ❌ (use deps)

   The deps module re-exports with sensible FastAPI ``Depends()``
   wiring, so endpoint files stay decoupled from infrastructure.

3. **One router file per resource.**
   ``auth.py``, ``users.py``, ``cases.py`` — never a mega-file. A resource
   has its own file even if it has only one endpoint. This keeps PRs
   small and the routing tree obvious.

4. **Every endpoint raises ``CyberGuardError`` subclasses.**
   Never ``raise HTTPException(status_code=...)``. Never construct
   ``JSONResponse`` manually. The exception handler registered in
   ``main.py`` translates ``CyberGuardError`` subclasses into the
   standard ``ErrorResponse`` body with the right status code, error
   code, correlation ID, and details. This keeps error shapes consistent
   across the entire API, and makes it impossible for two endpoints to
   return 404 for the same problem in two different formats.

5. **Every response declares a ``response_model``.**
   FastAPI validates the response against the schema and excludes any
   fields not declared. This is the same security guarantee as
   ``UserRead`` from the schema layer — fields not in the response
   model cannot be serialized. No accidental `password_hash` in JSON.

6. **Every authenticated endpoint uses an auth dependency explicitly.**
   The dependency appears in the signature::

       def get_me(user: User = Depends(get_current_active_user)): ...

   Not in middleware. Not hidden. A reviewer scanning the file sees
   "this endpoint requires authentication" without reading the body.
   Anonymous endpoints use ``get_current_user_optional`` — also visible.

7. **Every endpoint declares its path, method, tags, and status codes.**
   No defaults. ``@router.get("/{id}", tags=["users"], status_code=200)``.
   OpenAPI docs come out clean because nothing is implicit.

8. **No business logic in this layer.**
   Endpoints are thin: parse input, call a service, translate the
   result. Anything more than ~15 lines of body is a code smell — the
   logic belongs in ``app.services``. This keeps routes testable without
   HTTP, and services testable without a database.

9. **No direct SQL in this layer.**
   Services receive a ``Session`` and execute queries. Endpoints never
   do ``db.execute(select(...))`` directly.

10. **No ``print()``, no ``logging.getLogger()`` in this layer.**
    Use ``get_logger(__name__)`` from ``app.core.logging``. Structured
    JSON logs, correlation IDs, redaction — all handled centrally.

Endpoint lifecycle
------------------
    Request arrives
        │
        ▼
    ┌────────────────────────────────────────────┐
    │  1. ASGI middleware (main.py)              │
    │     • CORS                                 │
    │     • request body size limit              │
    │     • correlation ID (from X-Correlation-ID│
    │       or fresh UUID)                       │
    │     • exception handler → ErrorResponse    │
    └────────────────────────────────────────────┘
        │
        ▼
    ┌────────────────────────────────────────────┐
    │  2. FastAPI route matching                 │
    │     • selects the endpoint                 │
    │     • resolves Depends() dependencies      │
    │     • validates request body against schema│
    │     • 422 if validation fails              │
    └────────────────────────────────────────────┘
        │
        ▼
    ┌────────────────────────────────────────────┐
    │  3. Dependencies resolved (in order)       │
    │     • get_db → SQLAlchemy Session          │
    │     • get_pagination → PageParams          │
    │     • get_current_active_user → User       │
    │     • require_permission(...) → (check)    │
    └────────────────────────────────────────────┘
        │
        ▼
    ┌────────────────────────────────────────────┐
    │  4. Endpoint handler body                  │
    │     • call one service method              │
    │     • build the response_model instance    │
    │     • return (or raise CyberGuardError)    │
    └────────────────────────────────────────────┘
        │
        ▼
    ┌────────────────────────────────────────────┐
    │  5. Response serialization                 │
    │     • response_model validates and strips  │
    │     • JSON encoded                         │
    │     • X-Correlation-ID echoed              │
    └────────────────────────────────────────────┘

What this package must NOT do
-----------------------------
- Business logic (→ ``app.services``)
- SQL queries (→ ``app.services``)
- JWT encoding/decoding (→ ``app.core.security`` / ``app.auth``)
- Direct DB session management (→ ``app.db.session`` via ``deps.get_db``)
- Model loading / validation (→ ``app.schemas``)
- Exception → HTTP translation (→ ``main.py``'s exception handler)

What lives in ``deps.py``
-------------------------
- ``get_db`` — re-export of ``app.db.session.get_db``
- ``get_pagination`` — returns a ``PageParams`` from query params
- ``get_sort`` — returns a ``SortParams`` from query params
- Future: rate-limit dependency, feature-flag dependency, request-timer

What lives in ``v1/__init__.py``
--------------------------------
- ``api_router`` — one ``APIRouter`` composed of all sub-routers

What lives in each ``v1/*.py``
------------------------------
- One ``router = APIRouter()``
- Endpoint functions decorated with ``@router.get``, ``@router.post``, etc.
- Request/response types from ``app.schemas``
- Service calls from ``app.services``
- Auth dependencies from ``app.auth.dependencies``
- No imports of ``app.models`` (endpoints return Pydantic DTOs, not ORM)

Versioning
----------
URL versioning: ``/api/v1/...``. When breaking changes are unavoidable,
a new ``v2`` sub-package is added with its own aggregator. ``v1`` stays
for at least one deprecation cycle (12 months).

Additive changes (new endpoints, new optional fields) do not bump the
version. Only breaking changes (removing endpoints, removing fields,
changing field types) do.
"""

from __future__ import annotations

# Intentionally no imports. See "Zero imports at package load" above.

__all__: list[str] = []