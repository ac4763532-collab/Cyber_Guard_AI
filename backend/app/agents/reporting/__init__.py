"""
CyberGuard AI — Reporting Agent Package

The 8th of 8 agents. Generates scheduled and on-demand security reports
by orchestrating ``report_service`` (File 88).

Unlike the other 7 agents, this one produces **reports**, not findings.
The ``AgentResult.findings`` list is always empty — the agent's output
is a set of ``SecurityReport`` rows created via ``report_service``.

Responsibilities
----------------
    1. **Scheduled reports** — daily, weekly, and monthly reports
       generated for every active workspace on a schedule. Called from
       a periodic task in ``main.py``.

    2. **On-demand reports** — a client explicitly requests a report
       via the API. ``report_service`` handles the request; this agent
       provides the ``process()`` interface for the runtime.

Schedule model
--------------
    daily     — every 24 hours, at 00:00 UTC
    weekly    — every Monday, at 00:00 UTC
    monthly   — 1st of each month, at 00:00 UTC

    The agent doesn't run its own scheduler. The parent process (the
    runtime thread or a separate cron) calls:

        agent.run_scheduled_reports(db, frequency="daily")

    The agent generates a report for every active workspace that
    doesn't already have a report of that frequency in the current
    period. This makes it idempotent — calling it twice in the same
    day produces one report per workspace, not two.

Orchestration, not reimplementation
-----------------------------------
Every report type the agent generates is built by
``report_service.generate_report`` — the actual PDF/CSV/JSON/HTML
generation is not duplicated here. The agent:

    - Decides which reports to generate
    - Requests them via ``report_service.request_report``
    - Triggers generation via ``report_service.generate_report``
    - Handles per-workspace failures (isolation)

This keeps the agent thin and the service as the single source of
truth for report content.

Public API:
    from app.agents.reporting import ReportingAgent
"""

from app.agents.reporting.agent import ReportingAgent

__all__ = ["ReportingAgent"]