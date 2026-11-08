"""
CyberGuard AI — Core Package
============================================================================

Provides the foundational, cross-cutting primitives used by every other
part of the backend. Nothing in ``app.core`` may import from ``app.api``,
``app.services``, ``app.agents``, ``app.models``, or ``app.schemas``.
The dependency direction is strictly one-way:

    app.core   ←   app.db   ←   app.models   ←   app.schemas
                                            ←   app.services
                                            ←   app.agents
                                            ←   app.api

Submodules
----------
config.py
    Typed, validated application settings (Pydantic v2 ``BaseSettings``).
    Reads from ``.env`` and the process environment.
    Single shared instance: ``from app.core.config import settings``.

logging.py
    Structured JSON logging setup with request/correlation IDs.
    Single entry point: ``from app.core.logging import get_logger``.

exceptions.py
    Application-wide exception hierarchy rooted at ``CyberGuardError``.
    All API handlers translate these into HTTP responses.

security.py
    Password hashing (bcrypt) and JWT encode/decode primitives.
    No business logic — only cryptographic operations.

constants.py
    Shared constants: role names, status enumerations used across
    schemas and services, API prefixes, and fixed thresholds.

Design rules enforced by this package
-------------------------------------
1. **Explicit imports only.** Do not re-export submodule contents from
   this ``__init__``. Callers must import from the concrete module:

       from app.core.config import settings          ✅
       from app.core.logging import get_logger       ✅
       from app.core.exceptions import CyberGuardError  ✅

       from app.core import settings                 ❌
       from app.core import get_logger               ❌

   This avoids implicit import chains, keeps the import graph flat, and
   prevents cycles as the codebase grows.

2. **No I/O at import time** other than reading configuration. Files,
   sockets, databases, and message brokers are only touched from
   ``main.py`` startup hooks or explicit service calls.

3. **No logging side effects on import.** ``app.core.logging`` sets up
   handlers only when its ``configure_logging()`` function is called
   (from ``main.py``). Importing the module is side-effect free.

4. **Secrets never live in ``constants.py``.** All secrets come from
   ``settings`` (i.e. environment variables), never from source.

5. **Time zone correctness.** All datetimes are UTC, timezone-aware.
   Utilities for this live in ``app.utils.datetime_utils``.
"""

from __future__ import annotations

# Intentionally no imports. See "Explicit imports only" above.

__all__: list[str] = []