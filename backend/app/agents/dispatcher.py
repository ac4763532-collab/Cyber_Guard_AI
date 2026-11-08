"""
CyberGuard AI — Agent Dispatcher
============================================================================

The dispatcher decides **which agents run on which events**.

Agents themselves are pure functions — they don't decide to run. The
runtime asks the dispatcher "which agents apply here?", then dispatches
to each. This decoupling means:

    - Adding a new agent requires one line in the dispatcher
    - Changing dispatch rules doesn't touch any agent file
    - Testing an agent doesn't require running the dispatcher
    - Dispatch logic is testable independently of agent execution

Dispatch decision model
-----------------------
The dispatcher evaluates rules in order, from cheapest to most
expensive, and returns the selected agents:

    1. Global kill switch (AGENT_EXECUTION_ENABLED=false → empty list)
    2. Per-agent disable check (settings-based)
    3. Source capability check (does the source declare the required
       capability?)
    4. Category match (auth → log agent, network → network agent, etc.)
    5. Severity gate (INFO events skip expensive enrichment agents)
    6. Field presence (an IP-based rule needs a source_ip on the event)

If any stage excludes an agent, it's skipped. Agents passing all
stages are returned.

The dispatcher never instantiates agents — it returns agent *names*.
The runtime is responsible for constructing agent instances. This
keeps the dispatcher stateless (no agent instances held in memory
between dispatches) and testable (assert on returned names, not
on agent behavior).

Dispatch table (default)
------------------------
    event.category=AUTHENTICATION:
        → log_analysis
        → threat_intelligence  (if source_ip present AND severity >= MEDIUM)

    event.category=NETWORK:
        → network_analysis
        → threat_intelligence  (if destination_ip or source_ip present)

    event.category=EMAIL:
        → email_analysis
        → threat_intelligence  (if url / domain / hash present)

    event.category=FILE:
        → log_analysis
        → threat_intelligence  (if hash_md5 or hash_sha256 present)

    event.category=AUTHORIZATION:
        → log_analysis

    event.category=DATABASE:
        → log_analysis

    event.category=PROCESS:
        → log_analysis

    event.category=SYSTEM:
        → log_analysis

    event.category=OTHER:
        → log_analysis

    Always (if applicable):
        → ioc_correlation  (if any IOC fields present AND severity >= MEDIUM)
        → incident_response (if the correlation agent produced findings —
                              the dispatcher cannot decide this alone; the
                              runtime triggers incident_response separately)

    Never dispatched automatically:
        → ai_analyst     (manual trigger only — analyst invokes via API)
        → reporting      (manual trigger or scheduled — not per-event)

Severity gates
--------------
    INFO     → deterministic agents only (log, email, network)
    LOW      → deterministic agents only
    MEDIUM   → + threat_intelligence, ioc_correlation
    HIGH     → + everything applicable
    CRITICAL → + everything applicable

Rationale: enrichment (external API calls) costs money and latency.
Only enrich events that might matter.

Design rules
------------
1. **No agent instantiation.** The dispatcher returns names. The
   runtime constructs agents.

2. **No DB queries.** The dispatcher uses only the event's own fields
   and the source's capabilities. It never queries for "related events"
   or "prior findings" — that's the correlation agent's job.

3. **Deterministic.** Same event + same source → same dispatch decision
   every time. No randomness, no time-based logic. Testable.

4. **Cheap.** Runs once per event. Fast (microseconds). No I/O.

5. **Extensible.** Adding a new agent (e.g. "cloud_log_analysis") means:
       - Add name to `AGENT_NAMES` (File 10)
       - Add a dispatch rule below
       - Implement the agent
   Nothing else changes.

Public API
----------
    get_applicable_agents(event, source, settings) → list[str]

    The runtime calls this once per event and then constructs an
    instance of each returned agent.
"""

from __future__ import annotations

from typing import Iterable

from app.core.config import Settings
from app.core.constants import (
    AGENT_EMAIL_ANALYSIS,
    AGENT_IOC_CORRELATION,
    AGENT_LOG_ANALYSIS,
    AGENT_NETWORK_ANALYSIS,
    AGENT_THREAT_INTELLIGENCE,
)
from app.core.logging import get_logger
from app.models.enums import (
    EventCategory,
    EventSeverity,
)
from app.models.event import SecurityEvent
from app.models.source import SecuritySource


logger = get_logger(__name__)


# ============================================================================
# SEVERITY RANK (for gates)
# ============================================================================
# Duplicated from the finding model — but only as a small static dict here
# so the dispatcher doesn't import model internals.
_SEVERITY_RANK: dict[EventSeverity, int] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}


# ============================================================================
# CAPABILITY → AGENT MAPPING
# ============================================================================
# A source declares what it can collect. The dispatcher uses this to
# gate agents whose input requires specific capabilities.
#
# If a source doesn't declare a capability, the corresponding agent
# isn't dispatched — even if the event category would otherwise match.
# This prevents running the network agent on events from a source that
# doesn't actually monitor network traffic.

_AGENT_REQUIRED_CAPABILITY: dict[str, str | None] = {
    AGENT_LOG_ANALYSIS: "log_collection",
    AGENT_EMAIL_ANALYSIS: "email_scan",
    AGENT_NETWORK_ANALYSIS: "network_monitoring",
    AGENT_THREAT_INTELLIGENCE: None,   # works on any event with IOCs
    AGENT_IOC_CORRELATION: None,       # works on any event with IOCs
    # ai_analyst, incident_response, reporting are never auto-dispatched
}


# ============================================================================
# CATEGORY → PRIMARY AGENT MAPPING
# ============================================================================
# Each event category is "owned" by one primary deterministic agent.
# This is the agent that always runs (subject to capability + severity).

_CATEGORY_TO_PRIMARY_AGENT: dict[EventCategory, str] = {
    EventCategory.AUTHENTICATION: AGENT_LOG_ANALYSIS,
    EventCategory.AUTHORIZATION: AGENT_LOG_ANALYSIS,
    EventCategory.DATABASE: AGENT_LOG_ANALYSIS,
    EventCategory.FILE: AGENT_LOG_ANALYSIS,
    EventCategory.PROCESS: AGENT_LOG_ANALYSIS,
    EventCategory.SYSTEM: AGENT_LOG_ANALYSIS,
    EventCategory.OTHER: AGENT_LOG_ANALYSIS,
    EventCategory.NETWORK: AGENT_NETWORK_ANALYSIS,
    EventCategory.EMAIL: AGENT_EMAIL_ANALYSIS,
}


# ============================================================================
# IOC FIELD DETECTION
# ============================================================================
# An event carries indicators if any of these fields are non-None.
# Used to gate threat_intelligence and ioc_correlation.

def _event_has_iocs(event: SecurityEvent) -> bool:
    """Return True if the event has any IOC-bearing field set."""
    return bool(
        event.source_ip
        or event.destination_ip
        or event.domain
        or event.url
        or event.hash_md5
        or event.hash_sha256
        or event.email_address
    )


# ============================================================================
# DISPATCH
# ============================================================================

def get_applicable_agents(
    event: SecurityEvent,
    source: SecuritySource | None,
    settings: Settings,
) -> list[str]:
    """
    Return the list of agent names that should process ``event``.

    The returned list is:
        - Deduplicated (each agent appears at most once)
        - Ordered by dispatch stage: primary first, then enrichment,
          then correlation (the runtime may use this order for logging)
        - Empty if no agents apply (e.g. agents globally disabled)

    Parameters
    ----------
    event : SecurityEvent
        The event to analyze. Its ``category``, ``severity``, and IOC
        fields drive the decision.
    source : SecuritySource | None
        The producing source. Its ``capabilities`` gate agent selection.
        ``None`` if the source was hard-deleted — in that case,
        capability checks are skipped (assume the source declares
        everything it can, but the event exists so we process it).
    settings : Settings
        The application settings object — used for global toggles and
        per-agent disable flags.

    Returns
    -------
    list[str]
        Agent names, in dispatch order.
    """
    # ── Stage 1: global kill switch
    if not settings.AGENT_EXECUTION_ENABLED:
        return []

    selected: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        if name not in seen:
            selected.append(name)
            seen.add(name)

    severity_rank = _SEVERITY_RANK.get(event.severity, 0)
    has_iocs = _event_has_iocs(event)

    # ── Stage 2: primary deterministic agent for the event's category
    primary = _CATEGORY_TO_PRIMARY_AGENT.get(event.category)
    if primary is not None and _agent_is_enabled_and_capable(
        primary, source, settings,
    ):
        _add(primary)

    # ── Stage 3: threat intelligence (for any event with IOCs + MEDIUM+)
    if (
        has_iocs
        and severity_rank >= _SEVERITY_RANK[EventSeverity.MEDIUM]
        and _agent_is_enabled_and_capable(
            AGENT_THREAT_INTELLIGENCE, source, settings,
        )
    ):
        _add(AGENT_THREAT_INTELLIGENCE)

    # ── Stage 4: IOC correlation (for any event with IOCs + MEDIUM+)
    # Note: correlation is different from threat intel. Threat intel
    # *enriches* the IOC with external reputation. Correlation *links*
    # this event to other events across sources. Both can run.
    if (
        has_iocs
        and severity_rank >= _SEVERITY_RANK[EventSeverity.MEDIUM]
        and _agent_is_enabled_and_capable(
            AGENT_IOC_CORRELATION, source, settings,
        )
    ):
        _add(AGENT_IOC_CORRELATION)

    # ── Stage 5: AI analyst / incident response / reporting
    # Never dispatched automatically. See module docstring.
    # - ai_analyst: manual invocation via API endpoint
    # - incident_response: triggered by alert_service when an incident
    #   is created (or manually by an admin)
    # - reporting: scheduled or manual

    return selected


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _agent_is_enabled_and_capable(
    agent_name: str,
    source: SecuritySource | None,
    settings: Settings,
) -> bool:
    """
    Return True if the agent is enabled AND the source can supply
    the data the agent needs.

    "Enabled" checks per-agent settings (e.g. a future
    ``AGENT_LOG_ENABLED=false`` to disable log analysis during
    maintenance). Currently all agents default to enabled when
    ``AGENT_EXECUTION_ENABLED=true``.

    "Capable" checks that the source declares the required capability.
    If ``source`` is None (hard-deleted), the capability check is
    skipped — we process the event anyway (it was already ingested;
    refusing to analyze it wastes the data).
    """
    if not _agent_is_enabled(agent_name, settings):
        return False

    required = _AGENT_REQUIRED_CAPABILITY.get(agent_name)
    if required is None:
        return True  # no capability requirement

    if source is None:
        return True  # source gone — process anyway

    source_capabilities = set(source.capabilities or [])
    return required in source_capabilities


def _agent_is_enabled(agent_name: str, settings: Settings) -> bool:
    """
    Return True if the agent is enabled in settings.

    Currently, all agents are enabled whenever AGENT_EXECUTION_ENABLED
    is True. Future settings will add per-agent toggles for targeted
    disabling (e.g. ``AGENT_EMAIL_ANALYSIS_ENABLED=false`` during an
    email provider outage).

    The design intentionally keeps this function separate from the
    settings class so adding a new toggle later means one line here —
    no settings schema change required beyond the field itself.
    """
    # When per-agent toggles are added, this becomes:
    #   enabled_map = {
    #       AGENT_LOG_ANALYSIS: settings.AGENT_LOG_ANALYSIS_ENABLED,
    #       ...
    #   }
    #   return enabled_map.get(agent_name, True)
    return True


# ============================================================================
# PUBLIC HELPER — for testing / introspection
# ============================================================================

def describe_dispatch(
    event: SecurityEvent,
    source: SecuritySource | None,
    settings: Settings,
) -> dict:
    """
    Return a dict describing the dispatch decision and the reasoning
    behind it. Intended for tests and debugging — not called by the
    runtime.

    Example output:
        {
            "selected": ["log_analysis", "threat_intelligence"],
            "reasoning": {
                "event_category": "authentication",
                "event_severity": "high",
                "has_iocs": True,
                "source_capabilities": ["log_collection"],
                "primary_agent": "log_analysis",
                "threat_intel_selected": True,
                "correlation_selected": False,
            }
        }
    """
    selected = get_applicable_agents(event, source, settings)

    primary = _CATEGORY_TO_PRIMARY_AGENT.get(event.category)
    has_iocs = _event_has_iocs(event)
    severity_rank = _SEVERITY_RANK.get(event.severity, 0)
    medium_plus = severity_rank >= _SEVERITY_RANK[EventSeverity.MEDIUM]

    return {
        "selected": selected,
        "reasoning": {
            "event_category": event.category.value,
            "event_severity": event.severity.value,
            "has_iocs": has_iocs,
            "source_capabilities": list(source.capabilities or []) if source else None,
            "primary_agent": primary,
            "threat_intel_selected": AGENT_THREAT_INTELLIGENCE in selected,
            "correlation_selected": AGENT_IOC_CORRELATION in selected,
            "medium_plus_severity": medium_plus,
            "agents_globally_enabled": settings.AGENT_EXECUTION_ENABLED,
        },
    }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "get_applicable_agents",
    "describe_dispatch",
]