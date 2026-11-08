"""
CyberGuard AI — Backend Application Package
============================================================================

A multi-agent cybersecurity platform providing real-time security monitoring,
threat detection, investigation, incident management, and protection for
individuals and organizations.

Package layout
--------------
    app.core       Configuration, logging, exceptions, security primitives
    app.db         SQLAlchemy engine, session factory, declarative base
    app.models     Database models (users, orgs, events, findings, incidents...)
    app.schemas    Pydantic request/response schemas
    app.services   Business logic (authorization, ingestion, dispatch, ...)
    app.api        FastAPI routers and shared dependencies
    app.agents     8 specialized detection / investigation agents
    app.auth       JWT primitives and FastAPI auth dependencies
    app.collectors Device collector registry and management
    app.utils      Shared utilities (datetime, IDs, validators)

Design rules enforced by this package
-------------------------------------
1. This module MUST NOT import any submodule at import time.
   Doing so causes circular imports as soon as ``app.api.v1`` or
   ``app.agents`` are imported. Submodules import directly from
   ``app.core.*`` and ``app.db.*``.

2. All runtime configuration is accessed through
   ``app.core.config.settings`` (a single, cached, typed object).

3. All logging goes through ``app.core.logging.get_logger(__name__)``.

4. All exceptions inherit from ``app.core.exceptions.CyberGuardError``.

5. No module outside ``app.db`` may create database sessions directly.
   Services accept a ``Session`` parameter — the API layer owns the
   transaction boundary.
"""

from __future__ import annotations

# ── Package metadata ────────────────────────────────────────────────────────
# These values are consumed by ``main.py`` when constructing the FastAPI app
# and are exposed by ``/health`` and ``/`` endpoints.

__version__: str = "0.1.0"

__title__: str = "CyberGuard AI"

__description__: str = (
    "A Multi-Agent System for Cybersecurity Threat Detection and Correlation. "
    "Real-time monitoring, specialized detection agents, cross-source "
    "correlation, AI-assisted investigation, incident management, and "
    "reporting for individuals and organizations."
)

__author__: str = "CyberGuard AI"

__license__: str = "Proprietary"

__url__: str = "https://cyberguard.local"


# ── Public exports ──────────────────────────────────────────────────────────
# Only metadata is exported. Submodules are imported explicitly by callers
# (e.g. ``from app.core.config import settings``) to keep import graphs clean.

__all__ = [
    "__version__",
    "__title__",
    "__description__",
    "__author__",
    "__license__",
    "__url__",
]