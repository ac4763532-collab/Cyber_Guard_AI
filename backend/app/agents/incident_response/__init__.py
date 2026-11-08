"""
CyberGuard AI — Incident Response Agent Package

The 7th of 8 agents. Converts alerts into managed incidents and routes
them to the best-fit analyst.

Two responsibilities
--------------------
    1. **Auto-create incident** — when an alert of HIGH or CRITICAL
       severity fires and no matching incident is open in the
       workspace, create one. Uses ``incident_service.create_incident``
       which is idempotent — if an incident with the same pattern
       already exists, it merges (occurrence_count++, alert_ids union).

    2. **Route to analyst** — find the best-fit verified analyst by
       specialization match and current capacity, then assign via
       ``incident_service.assign``. If no analyst is available, leave
       unassigned (admin can assign manually).

Invocation (different from the runtime-dispatched agents)
---------------------------------------------------------
This agent is NOT dispatched by the runtime. It's invoked from:

    - ``run_sweep(db)`` — periodic background sweep that finds recent
      HIGH/CRITICAL alerts without an incident and creates incidents.
      Called from a scheduled task in ``main.py`` every 60 seconds.

    - ``process(context)`` — single-alert version. Called directly from
      an admin endpoint (``POST /api/v1/admin/incidents/from-alert``)
      for manual triggering.

Config (from settings via runtime)
----------------------------------
    auto_create_severity_threshold: str     "high" | "critical" (default "high")
    max_cases_per_analyst: int              (default 20) — capacity cap
"""

from app.agents.incident_response.agent import IncidentResponseAgent

__all__ = ["IncidentResponseAgent"]