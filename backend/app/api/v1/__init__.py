"""
CyberGuard AI — API v1 Router Aggregator
============================================================================

Composes every v1 sub-router into a single ``api_router``. ``main.py``
mounts that router at ``/api/v1``::

    from app.api.v1 import api_router
    app.include_router(api_router, prefix="/api/v1")

What's here
-----------
Just ``api_router``. Nothing else. Routers live in their own files
(``auth.py``, ``users.py``, ...) and are included here once they exist.

Router ownership
----------------
Each router file owns its ``prefix`` and ``tags``:

    # auth.py
    router = APIRouter(prefix="/auth", tags=["auth"])

    # users.py
    router = APIRouter(prefix="/users", tags=["users"])

The aggregator just calls ``include_router(router)`` — no prefix or tag
arguments. This makes each router portable: it can be moved to a v2
aggregator, mounted on a test app, or split into a separate service
without changing its internals.

Adding a router
---------------
When a new router file lands, uncomment two lines here:

    1. Its import:
        # from app.api.v1 import auth              →  from app.api.v1 import auth

    2. Its include_router() call:
        # api_router.include_router(auth.router)  →  api_router.include_router(auth.router)

The commented lines below are ordered to match the build sequence.
Uncomment them one at a time as files land.

Why imports are commented
-------------------------
Each router lives in its own file (Files 51+ of the build). Until the
file exists, ``from app.api.v1 import auth`` raises ``ImportError``.
Commented imports let ``main.py`` import and mount ``api_router``
**before** all routers are delivered. The app starts successfully with
an empty ``api_router`` — ``/docs`` shows the info page, ``/health``
works, and adding routes does not require restarting the app's import
graph.

Why no global auth dependency
-----------------------------
Some codebases add ``dependencies=[Depends(get_current_active_user)]``
on the aggregator, forcing auth on every route. We do not:

    - Health checks must be public
    - ``POST /auth/register`` and ``POST /auth/login`` must be public
    - ``POST /auth/refresh`` must be callable with only a refresh token
    - Some endpoints vary behavior based on whether the caller is
      authenticated (``get_current_user_optional``)

Auth is a per-endpoint decision, declared at the endpoint via
``Depends(get_current_active_user)``. A reviewer scanning a router file
sees exactly which endpoints are protected.

Route ordering
--------------
Routes are matched in registration order. Auth is included first so
``/auth/*`` appears first in Swagger. Not critical for functionality —
just nicer for readers of the docs.
"""

from __future__ import annotations

from fastapi import APIRouter


# ============================================================================
# THE AGGREGATOR
# ============================================================================

api_router = APIRouter()


# ============================================================================
# ROUTER INCLUDES
# ============================================================================
# Uncomment each block as its router file is delivered.
# Order matches the build sequence; reorder only if a dependency requires it.


# ── Authentication ─────────────────────────────────────────────────────────
# Endpoints: POST /auth/register, /auth/login, /auth/refresh, GET /auth/me
from app.api.v1 import auth
api_router.include_router(auth.router)


# ── Users ──────────────────────────────────────────────────────────────────
# Endpoints: GET /users/me, PATCH /users/me, (admin) GET /users/{id}
from app.api.v1 import users
api_router.include_router(users.router)


# ── Organizations ──────────────────────────────────────────────────────────
# Endpoints: POST /organizations, GET /organizations, ...
from app.api.v1 import organizations
api_router.include_router(organizations.router)


# ── Marketplace ────────────────────────────────────────────────────────────
from app.api.v1 import marketplace
api_router.include_router(marketplace.router)


# ── Workspaces ─────────────────────────────────────────────────────────────
# Endpoints: POST /workspaces, GET /workspaces, ...
from app.api.v1 import workspaces
api_router.include_router(workspaces.router)


# ── Sources (device enrollment) ────────────────────────────────────────────
# Endpoints: POST /sources, GET /sources, POST /enrollment, ...
from app.api.v1 import sources
api_router.include_router(sources.router)

# ── Collector (device enroll & heartbeat) ─────────────────────────
from app.api.v1 import collector
api_router.include_router(collector.router)
from app.api.v1 import collector_events
api_router.include_router(collector_events.router)


# ── Events (ingestion) ─────────────────────────────────────────────────────
# Endpoints: POST /events (collector), GET /events (list)
from app.api.v1 import events
api_router.include_router(events.router)


# ── Findings (agent output) ────────────────────────────────────────────────
# Endpoints: GET /findings, GET /findings/{id}
from app.api.v1 import findings
api_router.include_router(findings.router)


# ── Alerts ─────────────────────────────────────────────────────────────────
# Endpoints: GET /alerts, PATCH /alerts/{id}, GET /alerts/{id}/acknowledge
from app.api.v1 import alerts
api_router.include_router(alerts.router)


# ── Incidents ──────────────────────────────────────────────────────────────
# Endpoints: GET /incidents, POST /incidents, PATCH /incidents/{id}, ...
from app.api.v1 import incidents
api_router.include_router(incidents.router)


# ── Cases ──────────────────────────────────────────────────────────────────
# Endpoints: GET /cases, POST /cases, PATCH /cases/{id}, assignments, ...
from app.api.v1 import cases
api_router.include_router(cases.router)


# ── Evidence ───────────────────────────────────────────────────────────────
from app.api.v1 import evidence
api_router.include_router(evidence.router)
api_router.include_router(evidence.case_evidence_router)


# ── Conversations ──────────────────────────────────────────────────────────
from app.api.v1 import conversation as conversations
api_router.include_router(conversations.router)
api_router.include_router(conversations.case_conversations_router)
api_router.include_router(conversations.attachments_router)


# ── Notifications ──────────────────────────────────────────────────────────
# Endpoints: GET /notifications, PATCH /notifications/{id}/read, ...
from app.api.v1 import notifications
api_router.include_router(notifications.router)


# ── Reports ────────────────────────────────────────────────────────────────
# Endpoints: POST /reports, GET /reports, GET /reports/{id}/download
from app.api.v1 import reports
api_router.include_router(reports.router)


# ── Admin (super admin only) ───────────────────────────────────────────────
# Endpoints: GET /admin/analysts, POST /admin/analysts/{id}/verify, ...
from app.api.v1 import admin
api_router.include_router(admin.router)

# ── Rooms and Invitations (Direct join, membership) ─────────────────────────
from app.api.v1 import rooms
api_router.include_router(rooms.router)

api_router.include_router(rooms.invitation_router)

# ── Unified Device Management ──────────────────────────────────────────────
from app.api.v1 import devices
api_router.include_router(devices.router)

# ── Email Security & EML Ingestion ─────────────────────────────────────────
from app.api.v1 import email
api_router.include_router(email.router)

# ── Network Telemetry & Flow Monitoring ────────────────────────────────────
from app.api.v1 import network
api_router.include_router(network.router)

# ── Log Monitoring ─────────────────────────────────────────────────────────
from app.api.v1 import logs
api_router.include_router(logs.router)

# ── AI Security Assistant ──────────────────────────────────────────────────
from app.api.v1 import assistant
api_router.include_router(assistant.router)

# ── Live Dashboard Aggregations ────────────────────────────────────────────
from app.api.v1 import dashboard
api_router.include_router(dashboard.router)

# ── Direct User Messaging ──────────────────────────────────────────────────
from app.api.v1 import direct_messages
api_router.include_router(direct_messages.router)



# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["api_router"]
