"""
CyberGuard AI — Agent Base Classes
============================================================================

The three foundational types every agent inherits or returns:

    AgentContext  — everything an agent needs, passed in by the runtime
    AgentResult   — what an agent returns (findings + errors + metadata)
    BaseAgent     — abstract base class with the shared helper surface

Why a context object (and not many parameters)
----------------------------------------------
An agent's process() method would otherwise take 6–8 parameters:

    process(db, event, source, workspace_id, config, correlation_state,
            deadline, correlation_id)

That's fragile — adding a new dependency (e.g. a threat-intel cache)
requires changing every agent's signature. It's also hard to test —
constructing a full context in a test is one call; building 8 keyword
arguments is error-prone.

The context DTO fixes both. It's frozen (fields can't be reassigned),
but the objects it *contains* (Session, ORM models) are mutable — the
session is meant to be used, not replaced.

Why AgentResult (and not just returning findings)
-------------------------------------------------
An agent may encounter multiple non-fatal errors during a single run —
one rule raised, a provider returned 429, a field was malformed. The
runtime needs to know about all of them to log, retry, or dead-letter.

Returning `list[AgentFinding]` would lose that information. Returning
findings and raising on any error would abort rules 2–10 when rule 1
fails.

AgentResult carries:
    findings  — persisted findings (may be empty)
    errors    — non-fatal errors (each is {stage, code, message})
    metadata  — timing, counts, agent-specific diagnostics

The runtime logs errors, commits findings, and never aborts other
agents based on one agent's errors.

Why BaseAgent (and not duck typing)
-----------------------------------
Every agent needs the same helpers:
    - Persist a finding via finding_service.create_finding
    - Check remaining time against a deadline
    - Log with consistent structure

Duplicating those in 8 agent files would be ~600 lines of near-identical
code. The base class provides them once.

The base is abstract — you cannot instantiate BaseAgent. Every concrete
agent implements process().

See `app/agents/__init__.py` for the 10-rule contract every agent must
follow.
"""

from __future__ import annotations

import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.constants import AGENT_NAMES
from app.core.exceptions import AgentError, AgentInputError
from app.core.logging import get_logger
from app.models.event import SecurityEvent
from app.models.finding import AgentFinding as _AgentFinding
from app.models.source import SecuritySource
from app.schemas.finding import FindingCreateInternal
from app.services import finding_service


logger = get_logger(__name__)


# ============================================================================
# CONTEXT
# ============================================================================

@dataclass(frozen=True)
class AgentContext:
    """
    Everything an agent needs to process one event.

    Frozen — the fields cannot be reassigned. But the objects they
    reference (Session, ORM models) are mutable and *should* be used
    as normal.
    """

    # ── DB session ──────────────────────────────────────────────────────
    db: Session
    """The request-scoped DB session. Agents flush() — never commit."""

    # ── The event being processed ──────────────────────────────────────
    event: SecurityEvent
    """The event to analyze. Never modified by agents."""

    source: Optional[SecuritySource]
    """The source that produced the event. None if the source was hard-deleted."""

    workspace_id: uuid.UUID
    """Tenant scope. Copied from event.workspace_id for convenience."""

    # ── Agent-specific config ──────────────────────────────────────────
    config: dict[str, Any] = field(default_factory=dict)
    """
    Agent-specific thresholds and options. Sourced from ``settings`` in
    the runtime, not queried by agents. Examples:

        log_analysis:
            {"failed_login_threshold": 5, "window_minutes": 10}

        email_analysis:
            {"suspicious_tld_score": 40, "max_attachment_bytes": 26214400}
    """

    # ── Cross-agent coordination state ────────────────────────────────
    correlation_state: dict[str, Any] = field(default_factory=dict)
    """
    Accumulated context from earlier agents in this batch. Read-only
    for the current agent.

    Example: if threat_intelligence ran first and cached the reputation
    of the event's source_ip, log_analysis can read
    correlation_state["ip_reputation"]["203.0.113.42"]["malicious"] to
    adjust its confidence.

    Agents MUST NOT write to correlation_state. The runtime owns it.
    """

    # ── Deadline ────────────────────────────────────────────────────────
    deadline_at: Optional[datetime] = None
    """
    The wall-clock time by which this agent must complete. Set by the
    runtime from ``AGENT_TASK_TIMEOUT_SECONDS``.

    Agents with long-running loops (e.g. iterating events) should call
    ``self._remaining_seconds(context)`` each iteration and bail early
    if it returns ≤ 0, raising ``AgentError`` with code
    ``AGENT_TIMEOUT``. This prevents the whole runtime from blocking on
    one slow agent.
    """

    # ── Trace context ───────────────────────────────────────────────────
    correlation_id: Optional[str] = None
    """
    Propagated from the HTTP request or ingestion path. Included in
    every log line via ``logger.info(..., extra={"correlation_id": ...})``.

    Agents should pass this on to external API calls (Vendor headers,
    LLM metadata) so that a single attack trace can be correlated
    across internal and external logs.
    """


# ============================================================================
# RESULT
# ============================================================================

@dataclass(frozen=True)
class AgentResult:
    """
    What an agent returns after processing one event.

    Frozen — the agent builds it once at the end of ``process()``.
    """

    findings: list[_AgentFinding] = field(default_factory=list)
    """
    Findings persisted by this agent during this run.

    A finding is "persisted" if ``finding_service.create_finding``
    returned it (whether newly created or merged into an existing one).
    Duplicates are still in this list — the caller can check
    ``occurrence_count > 1`` to detect that.

    Findings already live in the DB session. The runtime commits them
    at the end of the batch.
    """

    errors: list[dict[str, Any]] = field(default_factory=list)
    """
    Non-fatal errors encountered during processing.

    Each error is a dict:
        {
            "stage": "rule.failed_login_burst",  # which sub-step failed
            "code": "AGENT_INPUT_ERROR",         # AgentError code or exception type
            "message": "event_time missing",     # human-readable
            "traceback": "..."                   # optional, for unexpected errors
        }

    The runtime logs these and continues to the next agent. Non-fatal
    errors do NOT trigger a retry — they indicate bad input, not
    transient failure.
    """

    metadata: dict[str, Any] = field(default_factory=dict)
    """
    Agent-specific diagnostics. Not interpreted by the runtime — used
    for observability and debugging.

    Standard keys (agents should populate these):
        duration_ms: int
        events_examined: int
        rules_run: int
        findings_produced: int
        external_calls: int

    Additional keys are allowed and encouraged.
    """


# ============================================================================
# BASE AGENT
# ============================================================================

class BaseAgent:
    """
    Abstract base class for all 8 agents.

    Subclasses implement ``process()`` and inherit the shared helpers.
    """

    #: The agent's name — must be in ``AGENT_NAMES``. Subclasses override.
    name: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Parameters
        ----------
        config : dict | None
            Agent-specific configuration. Sourced by the runtime from
            ``settings`` (e.g. ``settings.LOG_AGENT_FAILED_LOGIN_THRESHOLD``
            becomes ``config["failed_login_threshold"]``).

            The base class stores this on ``self._config``. Subclasses
            typically read specific keys and set instance attributes
            during ``__init__`` (after calling super().__init__).
        """
        if not self.name:
            raise RuntimeError(
                f"{type(self).__name__} must set a class-level `name` "
                f"attribute. Valid names: {sorted(AGENT_NAMES)}"
            )
        if self.name not in AGENT_NAMES:
            raise RuntimeError(
                f"{type(self).__name__}.name={self.name!r} is not in "
                f"AGENT_NAMES. Valid: {sorted(AGENT_NAMES)}"
            )
        self._config: dict[str, Any] = dict(config or {})
        self._logger = get_logger(f"app.agents.{self.name}")

    # ── Abstract method ─────────────────────────────────────────────────

    def process(self, context: AgentContext) -> AgentResult:
        """
        Analyze one event and return findings.

        Every concrete agent implements this. The runtime calls it once
        per applicable event.

        Rules:
            - Must not commit. May flush.
            - Must not raise on non-fatal errors — collect them in the
              returned ``AgentResult.errors`` list instead.
            - May raise ``AgentInputError`` for fatal input problems
              (runtime logs and skips).
            - May raise ``AgentError`` subclasses for other fatal
              failures (runtime logs and skips).
            - Any other exception is treated as a bug by the runtime
              (logged at CRITICAL, agent marked unhealthy).

        Returns
        -------
        AgentResult
            May have empty findings, errors, and/or metadata.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement process()."
        )

    # ── Helper: persist a finding ───────────────────────────────────────

    def _make_finding(
        self,
        context: AgentContext,
        *,
        rule_id: str,
        title: str,
        severity: Any,
        category: Any,
        confidence: float,
        event_ids: list[uuid.UUID],
        evidence: dict[str, Any] | None = None,
        description: str | None = None,
        primary_event_id: uuid.UUID | None = None,
        mitre_techniques: list[str] | None = None,
        tags: list[str] | None = None,
        dedup_hint: str | None = None,
    ) -> _AgentFinding:
        """
        Persist a finding via ``finding_service.create_finding``.

        The agent builds a ``FindingCreateInternal`` DTO with sensible
        defaults filled in (workspace_id, source_id, agent_name from
        ``self.name``), and delegates to the service. The service
        computes the fingerprint, handles deduplication, and returns
        the persisted finding (newly created or merged).

        Parameters
        ----------
        context : AgentContext
            The context passed to ``process()``.

        rule_id : str
            Identifier of the specific rule that fired, e.g.
            ``"log.failed_login_burst"``. Combined with ``self.name``
            and ``dedup_hint`` to compute the finding fingerprint.

        title : str
            Human-readable title (shown on dashboards and alerts).

        severity, category, confidence : enums
            Standard finding classification fields.

        event_ids : list[UUID]
            The events this finding references. Required — a finding
            with no events is meaningless.

        evidence : dict | None
            Structured reasoning (thresholds, counts, field values).
            Size-capped by the service at 256 KB.

        description : str | None
            Longer narrative for the analyst.

        primary_event_id : UUID | None
            The "root" event for display. Defaults to ``event_ids[0]``.

        mitre_techniques : list[str] | None
            Optional MITRE ATT&CK technique IDs.

        tags : list[str] | None
            Optional free-form tags.

        dedup_hint : str | None
            Optional stable identifier (e.g. attacker IP) that
            determines what "the same finding" means for this rule.
            Two runs of the same rule with the same hint merge into
            one finding; different hints create separate findings.

        Returns
        -------
        AgentFinding
            The persisted ORM instance (new or existing).

        Raises
        ------
        AgentInputError
            If required fields are missing or invalid.
        """
        if not event_ids:
            raise AgentInputError(
                message=(
                    f"Agent {self.name!r} attempted to create a finding "
                    f"({rule_id!r}) with no event IDs."
                ),
                code="AGENT_FINDING_NO_EVENTS",
            )

        # Resolve primary_event_id default
        resolved_primary = primary_event_id or event_ids[0]

        dto = FindingCreateInternal(
            workspace_id=context.workspace_id,
            source_id=context.event.source_id,
            agent_name=self.name,
            rule_id=rule_id,
            severity=severity,
            category=category,
            confidence=confidence,
            title=title,
            description=description,
            primary_event_id=resolved_primary,
            event_ids=event_ids,
            evidence=evidence or {},
            mitre_techniques=mitre_techniques or [],
            tags=tags or [],
            dedup_hint=dedup_hint,
        )

        finding, was_created = finding_service.create_finding(context.db, dto=dto)

        self._logger.debug(
            "Finding %s",
            "created" if was_created else "merged",
            extra={
                "finding_id": str(finding.id),
                "rule_id": rule_id,
                "severity": severity.value if hasattr(severity, "value") else str(severity),
                "occurrence_count": finding.occurrence_count,
            },
        )

        return finding

    # ── Helper: time remaining ──────────────────────────────────────────

    def _remaining_seconds(self, context: AgentContext) -> float | None:
        """
        Return the number of seconds remaining before the deadline,
        or ``None`` if no deadline was set.

        Agents should call this in long-running loops and raise
        ``AgentError(code="AGENT_TIMEOUT")`` when it drops below an
        acceptable threshold (e.g. 2 seconds to leave time for cleanup).
        """
        if context.deadline_at is None:
            return None
        deadline = context.deadline_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        delta = (deadline - datetime.now(timezone.utc)).total_seconds()
        return delta

    # ── Helper: wrap unexpected exceptions ──────────────────────────────

    def _wrap_error(
        self,
        *,
        stage: str,
        exception: BaseException,
    ) -> dict[str, Any]:
        """
        Convert an exception into an ``AgentResult.errors`` entry.

        If the exception is an ``AgentError`` or ``AgentInputError``,
        use its ``code``. Otherwise use the exception type name and
        include a formatted traceback (agents must never log raw
        tracebacks — they may contain sensitive data from the event
        payload).
        """
        is_expected = isinstance(exception, AgentError)

        return {
            "stage": stage,
            "code": getattr(exception, "code", type(exception).__name__),
            "message": str(exception)[:500],
            "traceback": (
                None
                if is_expected
                else traceback.format_exc()[:2000]
            ),
        }

    # ── Helper: context summary for logging ─────────────────────────────

    def _context_summary(self, context: AgentContext) -> dict[str, Any]:
        """
        Return a compact dict suitable for ``extra={...}`` logging.

        Never includes event payload content — only IDs and high-level
        fields. This prevents accidental PII leakage in logs.
        """
        return {
            "agent": self.name,
            "event_id": str(context.event.id),
            "workspace_id": str(context.workspace_id),
            "source_id": (
                str(context.event.source_id)
                if context.event.source_id
                else None
            ),
            "event_type": context.event.event_type,
            "severity": (
                context.event.severity.value
                if hasattr(context.event.severity, "value")
                else str(context.event.severity)
            ),
            "correlation_id": context.correlation_id,
        }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AgentContext",
    "AgentResult",
    "BaseAgent",
]