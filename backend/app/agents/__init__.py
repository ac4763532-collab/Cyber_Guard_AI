"""
CyberGuard AI — Agent Subsystem
============================================================================

The 8 detection and investigation agents. This package is where raw
security data becomes findings, alerts, incidents, and reports.

The 8 agents
------------
    1. log_analysis         — Windows/Linux/web/DB logs (deterministic rules)
    2. email_analysis       — Phishing/URL/attachment analysis (rules + ML)
    3. network_analysis     — Traffic patterns (Zeek/Suricata/NetFlow)
    4. threat_intelligence  — External enrichment (VirusTotal, AbuseIPDB, etc.)
    5. ioc_correlation      — Cross-source correlation (graph-based)
    6. ai_analyst           — LLM-assisted investigation (evidence-grounded)
    7. incident_response    — NIST SP 800-61 lifecycle automation
    8. reporting            — PDF/CSV/JSON reports (already partially in
                              report_service.py — the agent wraps the service)

Architectural difference from services
--------------------------------------
Services (in `app.services`) are called from HTTP routers and run
synchronously in the request cycle. Agents are called from a **background
worker** (or from an event consumer) and run asynchronously outside the
request cycle.

This changes the failure model:

    Services:
        - Called synchronously from a route handler
        - Failures propagate to the HTTP client as 4xx/5xx
        - The request-scoped DB transaction rolls back
        - Retry is the client's responsibility (or the service's)

    Agents:
        - Called from a background loop
        - Failures must be **isolated per-agent** — one agent crashing
          must not stop the other 7
        - The runtime owns retry logic (exponential backoff)
        - Failures are logged, not returned to a caller
        - Retries that keep failing land in a dead-letter queue

Every agent follows the contract in this file. Deviating from it
(committing inside an agent, calling another agent directly, raising
non-`CyberGuardError` exceptions) breaks the runtime.

The processing pipeline
-----------------------
    Event ingested (event_ingestion.py)
        ↓
    Agent runtime picks up the event (see Phase I, File 110)
        ↓
    ┌──────────────────────────────────────────────────────────┐
    │  Dispatcher                                              │
    │                                                          │
    │  For each event:                                         │
    │    - Determine which agents apply (based on source_type, │
    │      event_type, capabilities)                           │
    │    - Call each applicable agent's .process(context)      │
    │    - Collect findings                                    │
    │    - Isolate failures (one agent failing → log + skip)   │
    └──────────────────────────────────────────────────────────┘
        ↓
    findings persisted via finding_service.create_finding
        ↓
    Correlation engine watches findings (File 115)
        ↓
    Alerts promoted (alert_service)
        ↓
    Incidents created (incident_response agent or manually)
        ↓
    Reports generated (reporting agent)

Agent contract
--------------
Every agent MUST follow these rules:

1. **Receive an `AgentContext`.**
   The runtime passes a context DTO containing the session, the event,
   the source, the workspace, the agent's own configuration, and any
   correlation state. Agents never query for these — they're given.

2. **Never commit. Never rollback.**
   The runtime owns the transaction. An agent that commits can leave
   the DB in an inconsistent state if a later agent fails.

   Agents may call `session.flush()` — this is required to get IDs for
   newly-created findings.

3. **Return `AgentResult`, not raw findings.**
   The result carries:
       - `findings`: list of `AgentFinding` ORM instances (already
         persisted via `finding_service.create_finding`)
       - `errors`: list of non-fatal errors encountered (logged by the
         runtime, do not abort other agents)
       - `metadata`: agent-specific timing/counts for observability

4. **Raise `AgentError` (or a subclass) on fatal failure.**
   The runtime catches `AgentError`, logs it, and moves to the next
   agent. Any other exception is treated as a bug and also caught, but
   logged at a higher severity.

   Do not raise `ValidationError`, `NotFoundError`, etc. from inside
   an agent's `process()` — those are for the HTTP layer. If you need
   to signal "this input can't be processed", use
   `AgentInputError` from `app.core.exceptions`.

5. **Be idempotent.**
   The same event processed twice must produce the same fingerprint
   for the same reasoning. `finding_service.create_finding` handles
   deduplication via fingerprint — the agent just calls it.

6. **Be stateless.**
   No in-memory caches, no class-level state, no singletons. Every bit
   of state lives in the DB or is passed through `AgentContext`.

   If an agent needs cross-event state (e.g. "has this IP been seen
   before?"), it queries the DB via the provided session.

7. **Enforce timeouts.**
   External API calls (VirusTotal, LLM, etc.) must have explicit
   timeouts. A hung request blocks the entire agent runtime. Default
   timeout: `settings.AGENT_TASK_TIMEOUT_SECONDS` (120s).

8. **Log with structure.**
   Use `get_logger(__name__)`. Include `finding_id`, `event_id`,
   `agent_name`, and any relevant identifiers in `extra={...}`. The
   runtime propagates the correlation ID.

9. **Never leak sensitive data.**
   Evidence data may contain PII, credentials, or exploit code. Log
   only counts and IDs, not raw content.

10. **Never call another agent directly.**
    Agents coordinate via the correlation engine and the DB, not by
    calling each other. If the log agent finds a suspicious IP, it
    does NOT call the threat-intel agent — it creates a finding with
    the IP, and the runtime dispatches the event to the threat-intel
    agent in a subsequent cycle (or the correlation engine links them).

    This is the fundamental design constraint that keeps the agents
    composable. Direct calls create tight coupling and make it
    impossible to reorder, disable, or run agents in parallel.

Deterministic logic vs LLM
--------------------------
The 8 agents split into two categories:

    Deterministic (1, 2, 3, 5, 7, 8):
        - Rules, thresholds, aggregates, graphs
        - Fully reproducible: same input → same output
        - The primary detection layer
        - NEVER uses an LLM

    LLM-assisted (4 = threat intel wrapper, 6 = AI Analyst):
        - Agent 4 calls external APIs (also deterministic outputs,
          but slow and rate-limited)
        - Agent 6 uses an LLM for *explanation only*
        - An LLM output is NEVER treated as a verified finding
        - The AI Analyst produces `FindingCategory.OTHER` findings
          that are labeled "AI-generated, requires human verification"
          and are NOT auto-promoted to alerts

This split is critical. The platform's trust model is:

    - Deterministic agents produce findings that can be promoted to
      alerts and incidents automatically
    - The AI Analyst produces advisory findings that a human must
      promote manually

Rationale from the handover: *"LLMs must assist the detection and
investigation system, not replace deterministic detection logic or
verified evidence."*

Dispatch model (how agents are selected)
----------------------------------------
Not every agent runs on every event. The dispatcher (File 110) selects
agents based on:

    event.category:
        - AUTHENTICATION → log_analysis, (threat_intel if IP present)
        - NETWORK → network_analysis, threat_intel
        - EMAIL → email_analysis, threat_intel
        - FILE → log_analysis, threat_intel (if hash present)

    event.severity:
        - INFO/LOW → log_analysis only (fast path)
        - MEDIUM+ → log_analysis + threat_intel
        - HIGH/CRITICAL → log_analysis + threat_intel + correlation

    source.capabilities:
        - If source doesn't declare `log_collection`, log_analysis
          is skipped for its events (even if category matches)

    agent-specific config:
        - If `AGENT_EXECUTION_ENABLED=false`, no agent runs
        - If a specific agent is disabled in settings, it's skipped
        - If the event was already processed by this agent (idempotency
          marker in the finding fingerprint), the agent runs but
          produces no new finding

The dispatch model is implemented in File 110. Agents do not select
themselves — they trust the dispatcher's decision.

Retry and dead-letter
---------------------
The runtime (File 110) implements:

    - Exponential backoff: 5s → 15s → 45s → 135s (configurable)
    - Max retries: `settings.AGENT_MAX_RETRIES` (default 3)
    - Dead letter: after max retries, the event is moved to the
      dead-letter topic (`KAFKA_TOPIC_DEAD_LETTER`) for manual review

    - Idempotency on retry: the finding fingerprint ensures a retried
      agent doesn't create duplicate findings. Even if the agent
      crashes AFTER `create_finding` succeeds, the next retry hits
      the dedup and produces no new finding.

Agent lifecycle phases (per event)
----------------------------------
    For a single event, per agent:

    1. **Skip check**: is this agent applicable? (dispatch decision)
    2. **Context construction**: build the `AgentContext` DTO
    3. **Process**: call `agent.process(context)`
    4. **Result collection**: append findings to the batch, log errors
    5. **Failure isolation**: `AgentError` → log + continue; other
       exceptions → log at CRITICAL + continue

    After all agents:
    6. **Batch persist**: findings are already in the session via
       `create_finding` — the runtime commits once at the end.

    On commit failure:
    7. **Rollback + retry**: the entire batch is rolled back and
       re-dispatched with backoff. Idempotency ensures no dupes.

Directory layout
----------------
    app/agents/
        __init__.py         (this file — design contract)
        base.py             (BaseAgent, AgentContext, AgentResult)
        dispatcher.py       (agent selection logic)
        runtime.py          (background worker loop)

        log_analysis/
            __init__.py
            agent.py        (LogAnalysisAgent — the class)
            rules.py        (rule definitions)
            detectors/      (per-rule detection logic)
                failed_login.py
                privilege_escalation.py
                unusual_login.py
                file_access.py
                account_modification.py

        email_analysis/
            __init__.py
            agent.py
            rules.py
            extractors/
                headers.py  (SPF/DKIM/DMARC parsing)
                urls.py     (URL extraction and analysis)
                attachments.py

        network_analysis/
            __init__.py
            agent.py
            rules.py

        threat_intelligence/
            __init__.py
            agent.py
            providers/
                virustotal.py
                abuseipdb.py
                nvd.py
                urlhaus.py

        ioc_correlation/
            __init__.py
            agent.py
            graph.py        (NetworkX-based correlation)

        ai_analyst/
            __init__.py
            agent.py
            prompts.py

        incident_response/
            __init__.py
            agent.py

        reporting/
            __init__.py
            agent.py

No imports here
---------------
This package's `__init__` intentionally imports nothing. Importing
`app.agents` must be a no-op. Every agent is imported explicitly by
the runtime — this keeps the import graph flat and prevents a broken
agent file from breaking everything (including the HTTP API, which
imports `app.main` → `app.api` → services → but NEVER agents).

The runtime is the ONLY place agents are imported. No service, no
router, no schema imports an agent. If an agent fails to import, only
the agent runtime fails — the entire HTTP API continues to serve
requests. This isolation is deliberate.
"""

from __future__ import annotations

# Intentionally no imports. See "No imports here" above.

__all__: list[str] = []