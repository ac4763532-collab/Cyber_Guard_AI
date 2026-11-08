"""
CyberGuard AI — Authentication Package
============================================================================

The authentication layer: "who is making this request?"

This package contains **only** authentication. Authorization (role/permission
checks) lives in ``app.services.authorization`` and is consumed by endpoints
via FastAPI dependencies.

Why separation matters
----------------------
Authentication and authorization are different concerns:

    Authentication  — prove identity         → HTTP 401 on failure
    Authorization   — grant or deny access   → HTTP 403 on failure

Mixing them causes subtle bugs. For example:

    - A suspended user with valid permissions still gets through
    - A Super Admin without the required permission is treated as
      anonymous
    - A deleted user's token stays valid because only permissions were
      checked, not account status
    - Audit logs lose track of "who" because identity resolution happens
      inside the authorization layer

Keeping them separate — different packages, different tests, different
failure modes — prevents the entire class of bugs.

Submodules
----------
jwt.py
    Thin wrappers around ``app.core.security`` for JWT operations that
    are specific to authentication flows:

        - ``decode_bearer_token(header_value)`` — parse "Bearer <token>"
        - ``verify_access_token(token)``        — decode + validate type
        - ``verify_refresh_token(token)``       — decode + validate type
        - ``build_token_response(user)``        — helper for login/register

    Never touches the database. Never checks permissions. Pure crypto.

dependencies.py
    FastAPI dependencies that resolve the current request's identity:

        - ``get_current_user``             — requires a valid token; 401
        - ``get_current_active_user``      — requires ACTIVE status; 403
        - ``get_current_verified_user``    — requires email verification; 403
        - ``get_current_user_optional``    — anonymous allowed; returns None
        - ``get_current_analyst``          — requires an analyst profile
        - ``get_current_super_admin``      — requires super admin role
        - ``require_permission(...)``      — returns a dependency factory

    Every dependency resolves the user via ``user_service`` (not raw
    SQL), sets the correlation ID, and raises a ``CyberGuardError``
    subclass on failure. The exception handler in ``main.py`` translates
    those into 401/403 responses with the standard ``ErrorResponse`` body.

Design rules enforced by this package
-------------------------------------
1. **No DB writes.** Auth reads the user; it never updates state.
   Login-side effects (last_login_at, failed_login_attempts, lockout)
   belong to ``user_service``.

2. **No permission checks.** Returning the authenticated user is the
   dependency's job. Whether that user can act is decided at the
   endpoint via ``require_permission(...)`` or in the service layer.

3. **Token decoding goes through ``app.core.security``.** Never import
   ``jose`` directly here. If the JWT algorithm, secret, or validation
   rules change, exactly one place changes.

4. **No re-exports.** Callers import from the concrete module::

       from app.auth.dependencies import get_current_active_user   ✅

       from app.auth import get_current_active_user                ❌

   This avoids implicit import chains, keeps the graph flat, and
   matches the pattern used by ``app.core``, ``app.db``, and
   ``app.schemas``.

5. **Every dependency is opt-in and explicitly named.**
   ``get_current_active_user`` is called out at the top of every
   protected endpoint so a reviewer can see the auth requirement
   without reading the body. There is no "magic default."

6. **Correlation IDs are set inside the dependency.**
   Every authenticated request gets a correlation ID, propagated from
   the request headers (``X-Correlation-ID``) or generated fresh.
   Audit logs written during the request can be joined to HTTP logs
   by that ID.

7. **Failures raise ``CyberGuardError`` subclasses.** No bare
   ``HTTPException``, no ``abort()``, no manual response construction.
   The exception handler in ``main.py`` is the single place that
   converts errors to HTTP responses. This keeps error shape
   consistent across the entire API.

Request lifecycle (authenticated)
---------------------------------
    Request arrives
        │
        ▼
    ┌───────────────────────────────────────────┐
    │  ASGI middleware                          │
    │   • extract or generate correlation ID    │
    │   • log request line                      │
    └───────────────────────────────────────────┘
        │
        ▼
    ┌───────────────────────────────────────────┐
    │  get_current_active_user (dependency)     │
    │   • parse Authorization header            │
    │   • decode JWT via app.core.security      │
    │   • load User via user_service            │
    │   • verify status == ACTIVE               │
    │   • set correlation ID in log context     │
    └───────────────────────────────────────────┘
        │
        ▼
    ┌───────────────────────────────────────────┐
    │  require_permission(...) (optional)       │
    │   • check role→permission mapping         │
    │   • check resource scope (tenant, case)   │
    │   • raise AuthorizationError if denied    │
    └───────────────────────────────────────────┘
        │
        ▼
    ┌───────────────────────────────────────────┐
    │  Endpoint handler                         │
    │   • receives authenticated User           │
    │   • performs the action                   │
    │   • writes an audit log                   │
    └───────────────────────────────────────────┘
        │
        ▼
    ┌───────────────────────────────────────────┐
    │  Response                                 │
    │   • serialized via *Read schema           │
    │   • correlation ID echoed in header       │
    └───────────────────────────────────────────┘

Anonymous lifecycle
-------------------
Endpoints that allow anonymous access use ``get_current_user_optional``.
It returns ``None`` when no Authorization header is present, and behaves
identically to ``get_current_user`` when one is. This lets endpoints
serve both authenticated and anonymous callers (e.g. health checks,
public feature flags, token refresh endpoint).

Where tokens are issued
-----------------------
Tokens are **not** issued by this package. The login and register
endpoints (``app.api.v1.auth``) call ``app.core.security.create_token_pair``
directly. This keeps ``app.auth`` focused on verification, not issuance —
symmetric concerns (encode/decode) live together in ``core.security``.
"""

from __future__ import annotations

# Intentionally no imports. See "No re-exports" above.

__all__: list[str] = []