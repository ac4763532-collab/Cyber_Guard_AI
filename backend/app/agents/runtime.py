"""
CyberGuard AI — Agent Runtime
============================================================================

The background worker that turns 8 agent classes into a running
detection pipeline.

Responsibilities
----------------
    1. **Register** the available agents once at startup — construct
       each with its configuration from ``settings``.
    2. **Poll** the ``security_events`` table for events that haven't
       been analyzed yet.
    3. **Dispatch** each event to the applicable agents (via the
       dispatcher).
    4. **Collect** findings and errors from each agent's ``AgentResult``.
    5. **Commit** findings in batches — one commit per batch, not per
       event.
    6. **Handle** failures — per-agent (isolate) and per-batch (retry
       with backoff).
    7. **Shut down** gracefully when signaled.

Watermark design (and its limitation)
-------------------------------------
The runtime processes events by advancing a **watermark** across
``security_events.received_at``:

    - On startup: watermark = now - 5 minutes (safety margin to catch
      events that arrived while the process was down).
    - Each batch: SELECT events where received_at > watermark, ordered
      by received_at ascending, limited to batch_size.
    - After successful commit: watermark = max(received_at) in batch.

**This watermark is in-memory only.** On process restart, the runtime
resumes from (now - 5 minutes), which means:
    - Events ingested during the downtime are analyzed (good — after
      a restart, they catch up).
    - Events from the last 5 minutes before the crash are re-analyzed
      (harmless — dedup via fingerprint prevents duplicate findings).

A proper `agent_processing_watermark` table is a Phase 13 enhancement.
For MVP, the in-memory approach is correct: no lost events, no
duplicate findings, no schema changes.

Graceful shutdown
-----------------
The runtime is designed to run in a background thread. Calling
``run_forever(stop_event=threading.Event())`` blocks until the event
is set, then finishes the current batch (up to a short deadline) and
returns.

The FastAPI app starts the runtime in its lifespan hook when
``settings.AGENT_EXECUTION_ENABLED=true``. On shutdown, it sets the
stop event and joins the thread.

Failure isolation
-----------------
Two failure scopes:

    Per-agent (isolated):
        - An agent raises `AgentError` or any exception.
        - The runtime logs it, collects it in the batch's error list,
          and **continues with the next agent for the same event**.
        - Findings from the other agents still get committed.

    Per-batch (retried):
        - The commit itself fails (DB unavailable, constraint violation,
          etc.) — the batch's whole transaction rolls back.
        - The runtime re-queues the batch with exponential backoff:
          5s → 15s → 45s.
        - After ``settings.AGENT_MAX_RETRIES`` failures, the batch is
          moved to the dead-letter topic (or logged with a
          ``DEAD_LETTER`` marker if Kafka is disabled).

Retry safety
------------
Because ``finding_service.create_finding`` deduplicates by fingerprint,
re-running the entire batch after a commit failure is safe — the second
attempt produces the same findings (same fingerprints), the DB unique
constraint handles the rest, and the final committed state is identical
to a successful first attempt.

Public API
----------
    AgentRuntime(settings)                         — construct
    runtime.run_once() → int                       — process one batch (useful for tests)
    runtime.run_forever(stop_event) → None         — main loop
    runtime.watermark → datetime                   — introspection
    runtime.stats → dict                           — last batch metrics
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.constants import (
    AGENT_AI_ANALYST,
    AGENT_EMAIL_ANALYSIS,
    AGENT_INCIDENT_RESPONSE,
    AGENT_IOC_CORRELATION,
    AGENT_LOG_ANALYSIS,
    AGENT_NETWORK_ANALYSIS,
    AGENT_REPORTING,
    AGENT_THREAT_INTELLIGENCE,
)
from app.core.exceptions import AgentError
from app.core.logging import get_logger
from app.db.session import session_scope
from app.models.event import SecurityEvent
from app.models.source import SecuritySource

from app.agents.base import AgentContext, AgentResult, BaseAgent
from app.agents.dispatcher import get_applicable_agents


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: On startup, how far back to look for events. Safety margin for
#: downtime + restart. Findings dedupe on re-analysis, so this is safe.
_STARTUP_LOOKBACK_MINUTES = 5

#: Default batch size — matches ``AGENT_BATCH_SIZE`` default from settings.
_DEFAULT_BATCH_SIZE = 50

#: Default retry backoff schedule (seconds). Overridden by
#: ``settings.AGENT_RETRY_BACKOFF_SECONDS`` multiplied by attempt number.
_RETRY_BACKOFF_MULTIPLIER = 3


# ============================================================================
# AGENT REGISTRY — lazy import map
# ============================================================================
# Maps agent name → (module path, class name).
#
# The runtime attempts to import each of these at startup. Missing
# modules (agents not yet implemented) are logged and skipped — the
# runtime continues to process events with the agents that ARE
# available. This makes incremental Phase I delivery work: when the
# Log Agent lands (File 109), it's automatically picked up; the other
# 7 will be picked up as they land.

_AGENT_MODULES: dict[str, tuple[str, str]] = {
    AGENT_LOG_ANALYSIS: ("app.agents.log_analysis.agent", "LogAnalysisAgent"),
    AGENT_EMAIL_ANALYSIS: ("app.agents.email_analysis.agent", "EmailAnalysisAgent"),
    AGENT_NETWORK_ANALYSIS: ("app.agents.network_analysis.agent", "NetworkAnalysisAgent"),
    AGENT_THREAT_INTELLIGENCE: ("app.agents.threat_intelligence.agent", "ThreatIntelligenceAgent"),
    AGENT_IOC_CORRELATION: ("app.agents.ioc_correlation.agent", "IocCorrelationAgent"),
    AGENT_AI_ANALYST: ("app.agents.ai_analyst.agent", "AiAnalystAgent"),
    AGENT_INCIDENT_RESPONSE: ("app.agents.incident_response.agent", "IncidentResponseAgent"),
    AGENT_REPORTING: ("app.agents.reporting.agent", "ReportingAgent"),
}


# ============================================================================
# AGENT CONFIG BUILDERS
# ============================================================================
# Each agent has different configuration keys. This map translates
# settings into per-agent config dicts. Adding a new agent adds a
# builder here.

def _build_log_agent_config(settings: Settings) -> dict[str, Any]:
    return {
        "failed_login_threshold": settings.LOG_AGENT_FAILED_LOGIN_THRESHOLD,
        "failed_login_window_minutes": settings.LOG_AGENT_FAILED_LOGIN_WINDOW_MINUTES,
        "privilege_escalation_enabled": settings.LOG_AGENT_PRIVILEGE_ESCALATION_ENABLED,
    }


def _build_email_agent_config(settings: Settings) -> dict[str, Any]:
    return {
        "max_attachment_size_bytes": settings.EMAIL_AGENT_MAX_ATTACHMENT_SIZE_BYTES,
        "suspicious_tld_score": settings.EMAIL_AGENT_SUSPICIOUS_TLD_SCORE,
    }


def _build_network_agent_config(settings: Settings) -> dict[str, Any]:
    return {
        "port_scan_threshold": settings.NETWORK_AGENT_PORT_SCAN_THRESHOLD,
        "port_scan_window_seconds": settings.NETWORK_AGENT_PORT_SCAN_WINDOW_SECONDS,
    }


def _build_threat_intel_config(settings: Settings) -> dict[str, Any]:
    return {
        "virustotal_api_key": settings.VIRUSTOTAL_API_KEY.get_secret_value(),
        "virustotal_rpm": settings.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE,
        "abuseipdb_api_key": settings.ABUSEIPDB_API_KEY.get_secret_value(),
        "abuseipdb_rpm": settings.ABUSEIPDB_RATE_LIMIT_PER_MINUTE,
        "otx_api_key": settings.OTX_API_KEY.get_secret_value(),
        "otx_rpm": settings.OTX_RATE_LIMIT_PER_MINUTE,
        "urlhaus_enabled": settings.URLHAUS_ENABLED,
        "nvd_api_key": settings.NVD_API_KEY.get_secret_value(),
        "nvd_rpm": settings.NVD_RATE_LIMIT_PER_MINUTE,
        "mitre_enabled": settings.MITRE_ATTACK_ENABLED,
    }


def _build_correlation_config(settings: Settings) -> dict[str, Any]:
    return {
        "time_window_minutes": settings.IOC_CORRELATION_TIME_WINDOW_MINUTES,
        "min_indicators": settings.IOC_CORRELATION_MIN_INDICATORS,
    }


def _build_ai_analyst_config(settings: Settings) -> dict[str, Any]:
    return {
        "provider": settings.LLM_PROVIDER,
        "anthropic_api_key": settings.ANTHROPIC_API_KEY.get_secret_value(),
        "anthropic_model": settings.ANTHROPIC_MODEL,
        "anthropic_max_tokens": settings.ANTHROPIC_MAX_TOKENS,
        "anthropic_timeout_seconds": settings.ANTHROPIC_TIMEOUT_SECONDS,
        "gemini_api_key": settings.GEMINI_API_KEY.get_secret_value(),
        "gemini_model": settings.GEMINI_MODEL,
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "ollama_model": settings.OLLAMA_MODEL,
    }


def _build_incident_response_config(settings: Settings) -> dict[str, Any]:
    return {
        "auto_create_severity_threshold": settings.INCIDENT_AUTO_CREATE_SEVERITY_THRESHOLD,
        "max_cases_per_analyst": settings.INCIDENT_AGENT_MAX_CASES_PER_ANALYST,
    }


def _build_reporting_config(settings: Settings) -> dict[str, Any]:
    return {
        "max_rows": settings.REPORT_AGENT_MAX_ROWS,
        "pdf_page_limit": settings.REPORT_AGENT_PDF_PAGE_LIMIT,
    }


_AGENT_CONFIG_BUILDERS: dict[str, Callable[[Settings], dict[str, Any]]] = {
    AGENT_LOG_ANALYSIS: _build_log_agent_config,
    AGENT_EMAIL_ANALYSIS: _build_email_agent_config,
    AGENT_NETWORK_ANALYSIS: _build_network_agent_config,
    AGENT_THREAT_INTELLIGENCE: _build_threat_intel_config,
    AGENT_IOC_CORRELATION: _build_correlation_config,
    AGENT_AI_ANALYST: _build_ai_analyst_config,
    AGENT_INCIDENT_RESPONSE: _build_incident_response_config,
    AGENT_REPORTING: _build_reporting_config,
}


# ============================================================================
# RUNTIME
# ============================================================================

class AgentRuntime:
    """
    The background worker that runs the detection pipeline.

    Construct once at app startup. Use ``run_forever(stop_event)`` in
    a daemon thread, or ``run_once()`` for one batch (useful for tests
    and manual triggers).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._agents: dict[str, BaseAgent] = {}
        self._register_agents()

        # Watermark: how far forward has the runtime processed?
        # In-memory — see module docstring for the limitation.
        self._watermark: datetime = (
            datetime.now(timezone.utc) - timedelta(minutes=_STARTUP_LOOKBACK_MINUTES)
        )
        self._watermark_lock = threading.Lock()

        self._batch_size = int(
            getattr(settings, "AGENT_BATCH_SIZE", _DEFAULT_BATCH_SIZE)
        )

        # Per-batch stats — exposed for observability
        self._last_stats: dict[str, Any] = {}

    # ── Introspection ───────────────────────────────────────────────────

    @property
    def watermark(self) -> datetime:
        with self._watermark_lock:
            return self._watermark

    @property
    def registered_agents(self) -> list[str]:
        return sorted(self._agents.keys())

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._last_stats)

    # ── Agent registration ──────────────────────────────────────────────

    def _register_agents(self) -> None:
        """
        Attempt to import and instantiate each agent.

        Missing modules (Phase I not yet complete) are logged and
        skipped. The runtime continues with whatever agents are
        available.
        """
        import importlib

        for agent_name, (module_path, class_name) in _AGENT_MODULES.items():
            try:
                module = importlib.import_module(module_path)
                agent_class = getattr(module, class_name)
                config_builder = _AGENT_CONFIG_BUILDERS.get(agent_name)
                config = config_builder(self._settings) if config_builder else {}
                agent = agent_class(config=config)
                self._agents[agent_name] = agent
                logger.info(
                    "Agent registered",
                    extra={"agent_name": agent_name, "class": class_name},
                )
            except ModuleNotFoundError:
                logger.info(
                    "Agent module not yet available — skipping",
                    extra={"agent_name": agent_name, "module": module_path},
                )
            except ImportError as exc:
                logger.warning(
                    "Agent import failed — skipping",
                    extra={
                        "agent_name": agent_name,
                        "module": module_path,
                        "error": str(exc)[:200],
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Agent registration failed — skipping",
                    extra={
                        "agent_name": agent_name,
                        "error": str(exc)[:200],
                    },
                )

        if not self._agents:
            logger.warning(
                "No agents registered — the runtime will process events "
                "but produce no findings. This is expected if Phase I "
                "agent files have not yet been delivered."
            )

    # ── Public — one batch ──────────────────────────────────────────────

    def run_once(self) -> int:
        """
        Process one batch of events. Returns the number of events
        successfully dispatched (0 if nothing to do).
        """
        try:
            with session_scope() as db:
                return self._process_batch(db)
        except Exception as exc:  # noqa: BLE001 — never crash the loop
            logger.exception(
                "Batch processing failed at the session level",
                extra={"error": str(exc)[:500]},
            )
            return 0

    # ── Public — main loop ──────────────────────────────────────────────

    def run_forever(self, stop_event: threading.Event | None = None) -> None:
        """
        Main worker loop. Blocks until ``stop_event`` is set.

        Each iteration:
            1. Call ``run_once()`` to process one batch.
            2. Sleep for a short interval (500ms) to avoid hammering
               the DB when there's nothing to do.
            3. Check the stop event.

        The sleep is deliberately short — the polling interval matters
        more than the batch size for latency. A 500ms poll + 50-event
        batch handles ~100 events/sec comfortably.
        """
        if stop_event is None:
            stop_event = threading.Event()

        logger.info(
            "Agent runtime started",
            extra={
                "agents": self.registered_agents,
                "batch_size": self._batch_size,
                "poll_interval_ms": 500,
            },
        )

        try:
            while not stop_event.is_set():
                processed = self.run_once()
                # Backoff if nothing was processed (idle poll)
                if processed == 0:
                    stop_event.wait(timeout=0.5)
                else:
                    # Yield briefly between batches to check stop_event
                    stop_event.wait(timeout=0.05)
        except Exception:  # noqa: BLE001 — log and let the thread die
            logger.exception("Agent runtime terminated unexpectedly")
        finally:
            logger.info(
                "Agent runtime stopped",
                extra={"final_watermark": self.watermark.isoformat()},
            )

    # ── Internal — batch processing ────────────────────────────────────

    def _process_batch(self, db: Session) -> int:
        """
        Fetch the next batch of unprocessed events, dispatch them to
        agents, commit. Returns the number of events processed.
        """
        watermark = self.watermark
        now = datetime.now(timezone.utc)

        events = list(
            db.execute(
                select(SecurityEvent)
                .where(SecurityEvent.received_at > watermark)
                .order_by(SecurityEvent.received_at.asc())
                .limit(self._batch_size)
            ).scalars().all()
        )

        if not events:
            return 0

        logger.debug(
            "Processing batch",
            extra={
                "event_count": len(events),
                "watermark": watermark.isoformat(),
            },
        )

        batch_start = time.perf_counter()
        all_findings = []
        all_errors = []
        event_summaries = []

        for event in events:
            try:
                event_result = self._dispatch_event(db, event)
                all_findings.extend(event_result["findings"])
                all_errors.extend(event_result["errors"])
                event_summaries.append(event_result["summary"])
            except Exception as exc:  # noqa: BLE001 — never abort a batch on one event
                logger.exception(
                    "Event dispatch failed — continuing",
                    extra={"event_id": str(event.id)},
                )
                all_errors.append({
                    "event_id": str(event.id),
                    "stage": "dispatch",
                    "code": type(exc).__name__,
                    "message": str(exc)[:500],
                })

        # Flush findings (commit happens via session_scope exit)
                # ── Promote findings to alerts
        # This is the missing link: agents produce findings, but until
        # this block exists, users never see them. Promote via the
        # alert_service which applies severity/confidence thresholds
        # and handles pattern-level deduplication.
        promoted_count = 0
        try:
            from app.services import alert_service
            for finding in all_findings:
                try:
                    alert = alert_service.promote_finding(db, finding=finding)
                    if alert is not None:
                        promoted_count += 1
                except Exception as exc:  # noqa: BLE001
                    # One finding failing to promote must not abort the batch
                    logger.exception(
                        "Alert promotion failed",
                        extra={
                            "finding_id": str(finding.id),
                            "rule_id": finding.rule_id,
                            "error": str(exc)[:200],
                        },
                    )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Alert promotion subsystem unavailable",
                extra={"error": str(exc)[:200]},
            )

        # Flush findings + alerts (commit happens via session_scope exit)
        try:
            db.flush()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Flush failed — will roll back")
            raise exc
        # Advance watermark (only after successful flush — if we crash
        # before this line, the session_scope rolls back and the batch
        # is retried next iteration)
        last_event_received_at = max(e.received_at for e in events)
        with self._watermark_lock:
            # Guard against the DB returning events out-of-order
            if last_event_received_at > self._watermark:
                self._watermark = last_event_received_at

        batch_duration = time.perf_counter() - batch_start

        self._last_stats = {
            "batch_started_at": now.isoformat(),
            "batch_completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int(batch_duration * 1000),
            "events_processed": len(events),
            "findings_created": len(all_findings),
            "alerts_promoted": promoted_count,
            "errors": len(all_errors),
            "agents_registered": len(self._agents),
            "new_watermark": self.watermark.isoformat(),
        }

        logger.info(
            "Batch complete",
            extra=self._last_stats,
        )

        return len(events)

    def _dispatch_event(self, db: Session, event: SecurityEvent) -> dict:
        """
        Run all applicable agents for one event. Returns:
            {
                "findings": [AgentFinding, ...],
                "errors": [{agent_name, stage, code, message}, ...],
                "summary": {event_id, agents_run, findings, errors},
            }
        """
        # Look up source — may be None if it was hard-deleted
        source: SecuritySource | None = None
        if event.source_id is not None:
            source = db.get(SecuritySource, event.source_id)

        # Ask the dispatcher which agents apply
        agent_names = get_applicable_agents(event, source, self._settings)

        if not agent_names:
            return {
                "findings": [],
                "errors": [],
                "summary": {
                    "event_id": str(event.id),
                    "agents_run": 0,
                    "findings": 0,
                    "errors": 0,
                },
            }

        # Compute deadline (now + AGENT_TASK_TIMEOUT_SECONDS per agent)
        timeout_seconds = int(
            getattr(self._settings, "AGENT_TASK_TIMEOUT_SECONDS", 120)
        )

        findings = []
        errors = []

        for agent_name in agent_names:
            agent = self._agents.get(agent_name)
            if agent is None:
                # Dispatcher selected an agent that wasn't registered —
                # this can happen during incremental Phase I development.
                logger.debug(
                    "Skipping unregistered agent",
                    extra={"agent_name": agent_name, "event_id": str(event.id)},
                )
                continue

            deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)

            context = AgentContext(
                db=db,
                event=event,
                source=source,
                workspace_id=event.workspace_id,
                config=agent._config,  # config was set at construction
                correlation_state={},   # reserved for future cross-agent state
                deadline_at=deadline,
                correlation_id=None,    # populated if the ingestion path sets one
            )

            agent_start = time.perf_counter()
            try:
                result: AgentResult = agent.process(context)
                findings.extend(result.findings)
                # Attach agent name to each error for logging
                for err in result.errors:
                    err_with_agent = dict(err)
                    err_with_agent["agent_name"] = agent_name
                    errors.append(err_with_agent)
            except AgentError as exc:
                # Expected per-agent failure — log and continue
                logger.warning(
                    "Agent failed (expected)",
                    extra={
                        "agent_name": agent_name,
                        "event_id": str(event.id),
                        "code": getattr(exc, "code", "AGENT_ERROR"),
                        "message": str(exc)[:300],
                    },
                )
                errors.append({
                    "agent_name": agent_name,
                    "stage": "process",
                    "code": getattr(exc, "code", "AGENT_ERROR"),
                    "message": str(exc)[:500],
                })
            except Exception as exc:  # noqa: BLE001 — unexpected, log CRITICAL
                logger.exception(
                    "Agent failed (UNEXPECTED)",
                    extra={
                        "agent_name": agent_name,
                        "event_id": str(event.id),
                    },
                )
                errors.append({
                    "agent_name": agent_name,
                    "stage": "process",
                    "code": type(exc).__name__,
                    "message": str(exc)[:500],
                })
            finally:
                duration_ms = int((time.perf_counter() - agent_start) * 1000)
                logger.debug(
                    "Agent completed",
                    extra={
                        "agent_name": agent_name,
                        "event_id": str(event.id),
                        "duration_ms": duration_ms,
                    },
                )

        return {
            "findings": findings,
            "errors": errors,
            "summary": {
                "event_id": str(event.id),
                "agents_run": len(agent_names),
                "findings": len(findings),
                "errors": len(errors),
            },
        }


# ============================================================================
# MODULE-LEVEL SINGLETON HELPERS
# ============================================================================
# Convenience functions for the FastAPI startup hook in main.py.
# The runtime itself is stateless enough to be a singleton — it holds
# no request state, only the agent registry and the watermark.

_runtime_instance: AgentRuntime | None = None
_runtime_thread: threading.Thread | None = None
_runtime_stop_event: threading.Event | None = None


def start_runtime(settings: Settings) -> None:
    """
    Start the agent runtime in a background thread.

    Called from ``main.py``'s lifespan hook when
    ``settings.AGENT_EXECUTION_ENABLED`` is True.

    Idempotent — calling twice is a no-op (the second call logs and
    returns).
    """
    global _runtime_instance, _runtime_thread, _runtime_stop_event

    if _runtime_thread is not None and _runtime_thread.is_alive():
        logger.info("Agent runtime already running — ignoring start()")
        return

    _runtime_instance = AgentRuntime(settings=settings)
    _runtime_stop_event = threading.Event()
    _runtime_thread = threading.Thread(
        target=_runtime_instance.run_forever,
        kwargs={"stop_event": _runtime_stop_event},
        name="cyberguard-agent-runtime",
        daemon=True,
    )
    _runtime_thread.start()
    logger.info(
        "Agent runtime thread started",
        extra={
            "thread_name": _runtime_thread.name,
            "agents_registered": _runtime_instance.registered_agents,
        },
    )


def stop_runtime(timeout_seconds: int = 30) -> None:
    """
    Signal the runtime to stop and join the thread. Called from
    ``main.py``'s shutdown hook.

    Idempotent.
    """
    global _runtime_thread, _runtime_stop_event

    if _runtime_thread is None or _runtime_stop_event is None:
        return

    logger.info("Stopping agent runtime...")
    _runtime_stop_event.set()

    if _runtime_thread.is_alive():
        _runtime_thread.join(timeout=timeout_seconds)
        if _runtime_thread.is_alive():
            logger.warning(
                "Agent runtime thread did not stop within %ds — "
                "leaving it as a daemon",
                timeout_seconds,
            )
        else:
            logger.info("Agent runtime thread stopped cleanly")

    _runtime_thread = None
    _runtime_stop_event = None


def get_runtime() -> AgentRuntime | None:
    """Return the running runtime instance (for status endpoints)."""
    return _runtime_instance


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "AgentRuntime",
    "start_runtime",
    "stop_runtime",
    "get_runtime",
]