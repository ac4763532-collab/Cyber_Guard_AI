"""
CyberGuard AI - Event Bus Dispatcher Integration

Integration boundary between the Redpanda event bus and the TaskDispatcher.

This module provides:
1. SecurityEventConsumer - Consumes security events and routes to dispatcher
2. publish_agent_result - Publishes agent results back to event bus

The consumer listens to the security-events topic and routes events
to the appropriate agent via the TaskDispatcher based on event_type.

STEP 8.2.2: Windows events (source_type=windows_event) are routed to the
specialized WindowsDetectionProcessor with Redis-backed detection rules.

Usage:
    # Start the consumer (typically in FastAPI lifespan)
    consumer = SecurityEventConsumer()
    await consumer.start()

    # Events are automatically routed:
    # security-events topic -> Consumer -> Dispatcher -> Agent
    # Windows events -> Consumer -> WindowsDetectionProcessor (Redis)

    # On shutdown
    await consumer.stop()
"""

import structlog

from app.agents.base import AgentResult, AgentType, Severity
from app.agents.dispatcher import get_dispatcher
from app.core.retry import TRANSIENT_EXCEPTIONS, retry_async
from app.database.models.base import EventStatus, EventType, FindingCreate, SeverityLevel
from app.database.repositories.events import get_event_repository
from app.database.repositories.findings import get_finding_repository
from app.event_bus.consumer import EventConsumer
from app.event_bus.events import SecurityEvent
from app.event_bus.producer import get_producer
from app.event_bus.topics import Topic

logger = structlog.get_logger(__name__)


# =============================================================================
# STEP 8.5.4.1: Common Finding Lifecycle Hook
# Phase 1 (Log Collection -> Automatic Detection): now also persists each
# Finding via FindingRepository BEFORE calling on_finding_created() -
# that function's own docstring already assumed persistence had happened,
# but nothing previously did it. This is the step that makes findings
# actually queryable via GET /events/{id}/findings instead of only ever
# existing transiently in-memory for the duration of this handler call.
# =============================================================================


async def _resolve_event_id_for_finding(
    event: SecurityEvent,
    category: EventType,
) -> str | None:
    """
    Resolve a real `events.id` to use as a Finding's event_id.

    findings.event_id has a hard foreign key to events.id, but
    log-sourced SecurityEvents only ever carry a log_events.id (set by
    app/logs/event_bus_integration.py's log_event_to_security_event())
    - no events row exists for them otherwise. Rather than relaxing that
    FK, this idempotently creates one minimal events row per log event
    (keyed by (source, log_event_id) - see EventRepository.
    get_or_create_from_log_event()), so persistence always has a real,
    FK-valid events.id to point at.

    `category` is the real event category (email/log/network) as derived
    by the caller via _category_for_event() - previously this call never
    passed event_type at all, so get_or_create_from_log_event()'s
    EventType.LOG default silently won for every finding regardless of
    its true source (the root cause of every event being miscategorized
    as "log" on the Events page, including genuine local_network_monitor
    telemetry and email findings).

    Returns None if no event id/payload is available to resolve from
    (callers must then skip persistence for that finding rather than
    inserting with a fabricated or missing event_id).
    """
    payload = event.payload or {}
    log_event_id = payload.get("log_event_id") or event.event_id
    if not log_event_id:
        return None

    tenant_id = event.tenant_id or payload.get("tenant_id") or payload.get("organization_id")

    try:
        event_repo = get_event_repository()
        events_row = await event_repo.get_or_create_from_log_event(
            source=event.source,
            log_event_id=str(log_event_id),
            tenant_id=tenant_id,
            raw_data=payload,
            event_type=category,
        )
        return events_row.id
    except (OSError, ValueError, RuntimeError) as e:
        logger.error(
            "Failed to resolve/create events row for finding persistence",
            event_id=event.event_id,
            error=str(e),
        )
        return None


async def _record_processed_event(
    event: SecurityEvent,
    category: EventType,
    *,
    success: bool,
    risk_score: int | None = None,
    severity: Severity | None = None,
    findings_count: int = 0,
) -> str | None:
    """
    Unconditionally record that this SecurityEvent was processed, creating
    (idempotently) an events row and advancing its status to
    completed/failed - independent of whether any findings resulted.

    Why this exists: previously the only place an events row was ever
    created on the bus-consumer path was _resolve_event_id_for_finding(),
    which only ran from inside _process_agent_findings(), which only ran
    when result.findings was non-empty. A clean email, a benign log line,
    or an unremarkable network connection therefore never got an events
    row at all - the Events page was a list of "things that triggered
    detection," not a genuine activity history. This function is called
    unconditionally (from handle_security_event(), once a real outcome -
    an AgentResult or equivalent - exists for the event), while
    _process_agent_findings() stays exactly as selective as it always was:
    findings/alerts/correlations are still only created when something was
    actually found.

    `success` distinguishes "processed cleanly, zero findings" from
    "processing itself failed" - BaseAgent.run() (app/agents/base.py)
    never raises, so a validation rejection and an analyze() exception both
    collapse into AgentResult(success=False, findings=[]); findings alone
    can't tell the two apart, only result.success can.

    Returns the resolved events.id (or None if it couldn't be
    resolved/created), so callers can pass it straight into
    _process_agent_findings() without re-resolving it.
    """
    events_id = await _resolve_event_id_for_finding(event, category)
    if events_id is None:
        return None

    try:
        await get_event_repository().update_status(
            event_id=events_id,
            status=EventStatus.COMPLETED if success else EventStatus.FAILED,
            risk_score=risk_score,
            severity=SeverityLevel(severity.value) if severity else None,
            findings_count=findings_count,
        )
    except (OSError, ValueError, RuntimeError) as e:
        # The events row itself still exists (created above) even if this
        # status update fails - log and move on rather than losing the
        # whole record over a non-fatal status-write error.
        logger.error(
            "Failed to update events row status after processing",
            event_id=event.event_id,
            events_id=events_id,
            error=str(e),
        )

    return events_id


async def _process_agent_findings(
    result: AgentResult,
    event: SecurityEvent,
    category: EventType,
    events_id: str | None,
) -> None:
    """
    Persist agent findings, then process them through the common finding
    lifecycle hook.

    This is the integration point for non-Windows sources (Linux/Web logs,
    local_network_monitor connection events, and email findings). Windows
    events are handled in windows_integration.py.

    Args:
        result: AgentResult with findings
        event: Original SecurityEvent
        category: Real event category (email/log/network) for the events
            row created from this finding - see _category_for_event().
        events_id: The events.id already resolved/created by
            _record_processed_event() for this SecurityEvent - passed in
            rather than re-resolved here, since that unconditional call now
            always runs first in handle_security_event().
    """
    if not result.findings:
        return

    # STEP 4 (Secure Ingestion + Tenant Isolation, Part 11): resolve
    # tenant_id from the envelope's own field first (now populated by
    # log_event_to_security_event()), then the payload copy, in that
    # order. Previously this fell back to the literal string
    # "default" whenever both were absent, which silently collapsed
    # every tenant-less event into one shared correlation bucket -
    # a real cross-tenant correlation bug. "unknown" is used instead
    # so a missing tenant is visibly distinguishable from a real
    # tenant that happens to be named "default", while still failing
    # open (not blocking correlation) to preserve existing behavior
    # for any event that genuinely has no tenant context yet.
    payload = event.payload or {}
    tenant_id = (
        event.tenant_id
        or payload.get("tenant_id")
        or payload.get("organization_id")
        or "unknown"
    )
    if tenant_id == "unknown":
        logger.warning(
            "SecurityEvent has no resolvable tenant_id - correlating "
            "under 'unknown' sentinel instead of silently defaulting",
            event_id=event.event_id,
            event_type=event.event_type,
        )

    # Phase 1: persist each finding before anything downstream runs. A
    # failure here is logged and that finding is skipped for correlation
    # too (correlating a finding that was never durably recorded would
    # produce an alert/incident with no traceable source finding) - but
    # one finding's persistence failure does not block the others in
    # the same batch.
    #
    # events_id was already resolved/created by _record_processed_event()
    # in handle_security_event() before this function was ever called -
    # not re-resolved here, since that call now always runs first
    # regardless of whether there are findings.
    finding_repo = get_finding_repository()
    persisted_count = 0

    for finding in result.findings:
        if events_id is None:
            logger.error(
                "Skipping finding persistence - no resolvable events.id",
                finding_id=finding.finding_id,
                event_id=event.event_id,
            )
            continue

        try:
            persisted_finding = await finding_repo.create(
                FindingCreate(
                    event_id=events_id,
                    detection_id=result.result_id,
                    finding_type="rule",
                    rule_id=finding.rule_id,
                    severity=finding.severity.value,
                    confidence=finding.confidence,
                    title=finding.name,
                    description=finding.description,
                    evidence={"items": finding.evidence, "metadata": finding.metadata},
                    mitre_tactics=[],
                    mitre_techniques=finding.mitre_techniques,
                    tenant_id=None if tenant_id == "unknown" else tenant_id,
                )
            )
            persisted_count += 1

            # Audit entry for finding creation. No user_id - this is an
            # automated detection, not an interactive action. Only IDs/
            # rule metadata are recorded, never finding.evidence (which
            # may embed raw log content) or description text.
            from app.services.audit import record_audit_event

            await record_audit_event(
                action="finding_created",
                entity_type="finding",
                entity_id=persisted_finding.id,
                user_id=None,
                new_value={
                    "event_id": events_id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                },
            )

            if persisted_finding.tenant_id and finding.severity in (Severity.HIGH, Severity.CRITICAL):
                try:
                    incident_result = await get_dispatcher().dispatch(
                        AgentType.INCIDENT_RESPONSE,
                        {
                            "finding_id": persisted_finding.id,
                            "tenant_id": persisted_finding.tenant_id,
                            "actor_id": None,
                        },
                    )
                    if incident_result.success:
                        logger.info(
                            "Qualifying finding processed by incident agent",
                            finding_id=persisted_finding.id,
                            incident_id=(incident_result.metadata or {}).get("incident_id"),
                        )
                    else:
                        logger.warning(
                            "Incident qualification did not complete",
                            finding_id=persisted_finding.id,
                            error=incident_result.error,
                        )
                except Exception as incident_error:
                    logger.warning(
                        "Incident qualification failed without blocking event processing",
                        finding_id=persisted_finding.id,
                        error=str(incident_error),
                    )
        except (OSError, ValueError, RuntimeError) as e:
            logger.error(
                "Failed to persist finding - continuing with remaining findings",
                finding_id=finding.finding_id,
                event_id=event.event_id,
                error=str(e),
            )

    logger.info(
        "Finding persistence complete",
        event_id=event.event_id,
        total_findings=len(result.findings),
        persisted=persisted_count,
    )

    try:
        from app.correlation.finding_lifecycle import on_finding_created

        # Create a simple log_event-like object for correlation
        log_event = _create_log_event_from_security_event(event)

        for finding in result.findings:
            try:
                lifecycle_result = await on_finding_created(
                    log_event=log_event,
                    finding=finding,
                    tenant_id=tenant_id,
                )

                if lifecycle_result.get("correlation_id"):
                    logger.info(
                        "Finding processed through lifecycle",
                        finding_id=finding.finding_id,
                        event_id=event.event_id,
                        correlation_id=lifecycle_result.get("correlation_id"),
                        alert_id=lifecycle_result.get("alert_id"),
                        source_type=lifecycle_result.get("source_type"),
                    )

            except (OSError, ValueError, RuntimeError) as e:
                # Fail-safe: log but don't block other findings
                logger.warning(
                    "Finding lifecycle error (non-fatal)",
                    finding_id=finding.finding_id,
                    error=str(e),
                )

    except ImportError:
        logger.debug("Finding lifecycle module not available")


def _create_log_event_from_security_event(event: SecurityEvent) -> object:
    """
    Create a LogEvent-like object from a SecurityEvent for correlation.

    This adapter allows non-Windows events to work with the correlation system.
    """
    payload = event.payload or {}

    class LogEventAdapter:
        """Adapter to make SecurityEvent work with correlation."""

        def __init__(self, se: SecurityEvent, pl: dict):
            self.event_id = se.event_id
            self.id = pl.get("log_event_id") or se.event_id
            self.source = se.source
            self.source_id = pl.get("source_id")
            self.source_event_id = pl.get("source_event_id")
            self.timestamp = se.timestamp

            # Determine source_type from payload or event_type
            raw_source = pl.get("source_type", se.event_type)
            self.source_type = _normalize_source_type(raw_source)

            # Extract correlation-relevant fields
            self.source_ip = pl.get("source_ip")
            self.user = pl.get("user") or pl.get("username")
            self.hostname = pl.get("hostname") or pl.get("host")
            self.session_id = pl.get("session_id")
            self.raw_data = pl

            # CorrelationContextExtractor._extract_generic (app/correlation/
            # context.py) reads log_event.extracted_fields directly - every
            # log-sourced SecurityEvent carries the real structured fields at
            # pl["extracted_fields"] (see log_event_to_security_event in
            # app/logs/event_bus_integration.py), so expose that dict here.
            # Falls back to the raw payload itself for event sources that
            # don't nest an extracted_fields key, so .get() lookups in
            # _extract_generic still see source_ip/user/etc. instead of {}.
            self.extracted_fields = pl.get("extracted_fields") or pl

    return LogEventAdapter(event, payload)


def _category_for_event(event: SecurityEvent, source_type: str | None) -> EventType:
    """
    Derive the real events.event_type for a finding's events row.

    Single place to decide "what category is this" so both call sites of
    _process_agent_findings() (the local_network_monitor interception
    branch and the generic EVENT_TO_AGENT dispatch branch, both in
    handle_security_event() below) agree. Reuses the same trusted-signal
    priority already established by _normalize_source_type() /
    finding_lifecycle._detect_source_type() for alerts.category: a
    structured source_type field first, the SecurityEvent's own
    event_type second, never free-text/display-label matching.

    - local_network_monitor telemetry is genuine network data, not a log
      line, even though its bus envelope carries event_type="log" (every
      log collector publishes that way - see log_event_to_security_event
      in app/logs/event_bus_integration.py). Must be tagged "network".
    - Any event whose own event_type is a valid EventType value (e.g.
      "email") is trusted as-is.
    - Everything else (Linux/Android/Windows/other free-text logs)
      defaults to "log", matching current/correct behavior for those
      sources.
    """
    if source_type == "local_network_monitor":
        return EventType.NETWORK
    if event.event_type in EventType._value2member_map_:
        return EventType(event.event_type)
    return EventType.LOG


def _normalize_source_type(source: str) -> object:
    """Normalize source type string to enum-like object."""
    from enum import Enum

    class SourceType(Enum):
        LINUX_SYSLOG = "linux_syslog"
        WEB_APPLICATION = "web_application"
        WINDOWS_EVENT = "windows_event"
        EMAIL = "email"
        NETWORK = "network"
        UNKNOWN = "unknown"

    source_lower = source.lower() if source else ""

    if "linux" in source_lower or "ssh" in source_lower or "syslog" in source_lower:
        return SourceType.LINUX_SYSLOG
    if "web" in source_lower or "application" in source_lower or "http" in source_lower:
        return SourceType.WEB_APPLICATION
    if "windows" in source_lower:
        return SourceType.WINDOWS_EVENT
    # Email/network findings reach this adapter via the generic
    # EVENT_TO_AGENT dispatch path (not a dedicated branch like Windows/
    # local_network_monitor above), so their raw_source here is the
    # SecurityEvent's event_type itself ("email"/"network" - email events'
    # payload has no "source_type" key, so _create_log_event_from_security_event's
    # `pl.get("source_type", se.event_type)` falls back to it). Without
    # these checks every email/network finding fell through to UNKNOWN,
    # which finding_lifecycle._detect_source_type then mapped to "other" -
    # silently mis-categorizing every email/network alert as log_security.
    if "email" in source_lower or "gmail" in source_lower:
        return SourceType.EMAIL
    if "network" in source_lower:
        return SourceType.NETWORK

    return SourceType.UNKNOWN


# =============================================================================
# Event to Agent Mapping
# =============================================================================
EVENT_TO_AGENT: dict[str, AgentType] = {
    EventType.EMAIL.value: AgentType.EMAIL,
    EventType.LOG.value: AgentType.LOG,
    EventType.NETWORK.value: AgentType.NETWORK,
}


async def handle_security_event(event: SecurityEvent) -> None:
    """
    Handler for security events from Redpanda.

    Routes events to the appropriate agent via the TaskDispatcher.
    STEP 8.2.2: Windows events are routed to Redis-backed detection.

    Args:
        event: SecurityEvent from the event bus
    """
    logger.info(
        "Processing security event from bus",
        event_id=event.event_id,
        event_type=event.event_type,
        source=event.source,
        severity=event.severity.value if event.severity else None,
    )

    # STEP 8.2.2: Route Windows events to specialized detection pipeline
    if event.event_type == "log":
        payload = event.payload or {}
        source_type = payload.get("source_type")

        if source_type == "windows_event":
            try:
                from app.detection.state.redis_state import RedisUnavailableError
                from app.detection.windows_integration import handle_windows_log_event

                # STEP 4 (Part 11): same fix as handle_security_event()
                # above - event.tenant_id (the trusted envelope field,
                # now populated upstream) takes precedence over the
                # payload copy, and an explicit "unknown" sentinel
                # replaces the old silent "default" fallback so a
                # missing tenant is never conflated with a real tenant
                # literally named "default".
                tenant_id = event.tenant_id or payload.get("tenant_id") or "unknown"
                if tenant_id == "unknown":
                    logger.warning(
                        "Windows SecurityEvent has no resolvable tenant_id "
                        "- processing under 'unknown' sentinel instead of "
                        "silently defaulting",
                        event_id=event.event_id,
                    )
                result = await handle_windows_log_event(event, tenant_id=tenant_id)
                if result:
                    logger.info(
                        "Windows event processed through detection pipeline",
                        event_id=event.event_id,
                        findings_count=result.get("findings_count", 0),
                        alerts_created=result.get("alerts_created", 0),
                    )
                    # Record this event unconditionally, same as every
                    # other source - previously no events row was ever
                    # created for a Windows SecurityEvent at all (Windows
                    # findings persist via a separate raw INSERT with
                    # event_id hardcoded NULL - see
                    # create_finding_with_dedup() in
                    # app/detection/windows_integration.py). success=True
                    # here because reaching this branch means
                    # handle_windows_log_event() completed its full
                    # findings/alerts loop without raising - its return
                    # dict has no success/error key to check instead.
                    await _record_processed_event(
                        event=event,
                        category=EventType.LOG,
                        success=True,
                        findings_count=result.get("findings_count", 0),
                    )
                    return  # Windows event handled

            except RedisUnavailableError as e:
                # Fail safely - do not silently fall back
                logger.error(
                    "Redis unavailable for Windows detection - event not processed",
                    event_id=event.event_id,
                    error=str(e),
                )
                # Re-raise to trigger DLQ/retry
                raise

            except ImportError:
                # Windows detection module not available - fall through to standard
                logger.debug("Windows detection module not available")

            except (OSError, ValueError, RuntimeError, KeyError) as e:
                logger.error(
                    "Error in Windows detection pipeline",
                    event_id=event.event_id,
                    error=str(e),
                )
                # Continue to standard processing as fallback

        elif source_type == "local_network_monitor":
            # The local network monitor collector publishes connection
            # tuples (local/remote addr+port, protocol, pid, process_name)
            # with event_type="log" like every other log collector - but
            # LogAgent only pattern-matches free-text log lines and
            # NetworkAgent.analyze() only knows how to interpret an active
            # nmap scan (requires target/scan_type/authorized). Neither
            # matches this payload's shape, so route it to
            # NetworkAgent.analyze_connection_event() directly instead of
            # through dispatcher.dispatch() - that always runs
            # BaseAgent.run(), which calls validate() first and would
            # reject this data (no "target" field to validate as an
            # IP/CIDR). This mirrors the Windows branch above: a
            # source-type-specific path that bypasses the generic
            # EVENT_TO_AGENT dispatch and returns directly.
            try:
                dispatcher = get_dispatcher()
                network_agent = dispatcher.get_agent(AgentType.NETWORK)

                if network_agent is None or not hasattr(
                    network_agent, "analyze_connection_event"
                ):
                    # NetworkAgent failed to import and a PlaceholderAgent
                    # was registered instead (see TaskDispatcher.__init__) -
                    # fall through to standard processing below rather than
                    # silently dropping the event.
                    logger.warning(
                        "NetworkAgent unavailable for connection event - "
                        "falling through to standard processing",
                        event_id=event.event_id,
                    )
                else:
                    tenant_id = event.tenant_id or payload.get("tenant_id") or "unknown"
                    if tenant_id == "unknown":
                        logger.warning(
                            "local_network_monitor SecurityEvent has no "
                            "resolvable tenant_id - processing under "
                            "'unknown' sentinel instead of silently "
                            "defaulting",
                            event_id=event.event_id,
                        )

                    extracted_fields = payload.get("extracted_fields", {})
                    result = await network_agent.analyze_connection_event(extracted_fields)

                    logger.info(
                        "Connection event processed by NetworkAgent",
                        event_id=event.event_id,
                        classification=result.classification,
                        risk_score=result.risk_score,
                        findings_count=len(result.findings),
                        success=result.success,
                    )

                    # Record this connection event unconditionally - a
                    # benign/unremarkable connection must still show up as
                    # a genuine activity record, not only ones that
                    # produced a finding.
                    events_id = await _record_processed_event(
                        event=event,
                        category=EventType.NETWORK,
                        success=result.success,
                        risk_score=result.risk_score,
                        severity=result.severity,
                        findings_count=len(result.findings),
                    )

                    if result.findings:
                        await _process_agent_findings(
                            result=result,
                            event=event,
                            category=EventType.NETWORK,
                            events_id=events_id,
                        )

                    return  # local_network_monitor event handled

            except (OSError, ValueError, RuntimeError, KeyError) as e:
                logger.error(
                    "Error processing local_network_monitor connection event",
                    event_id=event.event_id,
                    error=str(e),
                )
                # Continue to standard processing as fallback

    # Map event type to agent type
    agent_type = EVENT_TO_AGENT.get(event.event_type)

    if not agent_type:
        logger.warning(
            "No agent registered for event type",
            event_id=event.event_id,
            event_type=event.event_type,
        )
        return

    try:
        # Get dispatcher and route to agent
        dispatcher = get_dispatcher()

        payload = event.payload or {}

        if agent_type == AgentType.LOG:
            # LogAgent.validate()/analyze() require a "log_content" key.
            # event.payload (built by log_event_to_security_event) uses
            # "message"/"raw_content" instead - splatting it directly here
            # left every real log event failing validation with zero
            # findings. Map the same way handle_log_security_event() (in
            # app.logs.event_bus_integration) already does for its own
            # dispatch call, so this - the handler actually wired to the
            # consumer - produces the same correctly-shaped input.
            agent_data = {
                "log_content": payload.get("raw_content") or payload.get("message", ""),
                "log_type": payload.get("source_type", "auto"),
                "source_host": payload.get("hostname", "unknown"),
                "extracted_fields": payload.get("extracted_fields", {}),
                "tags": payload.get("tags", []),
                "_event_id": event.event_id,
                "_correlation_id": event.correlation_id,
                "_source": event.source,
            }
        else:
            # Prepare data for agent (payload + envelope metadata)
            agent_data = {
                **payload,
                "_event_id": event.event_id,
                "_correlation_id": event.correlation_id,
                "_source": event.source,
            }

        # Dispatch to agent, with a bounded retry for transient failures
        # only (e.g. a DB/connection hiccup inside the agent or its
        # downstream persistence) - not for validation-type failures,
        # which won't resolve themselves on retry and should fall straight
        # through to the except block below (DLQ via the consumer, since
        # that's a non-transient outcome). Reuses the existing
        # retry_async/TRANSIENT_EXCEPTIONS from app/core/retry.py rather
        # than building new retry logic, and is scoped to this one call -
        # not EventConsumer itself, which stays generic/retry-agnostic.
        @retry_async(max_retries=2, delay=0.5, backoff=2.0, exceptions=TRANSIENT_EXCEPTIONS)
        async def _dispatch_with_retry():
            return await dispatcher.dispatch(agent_type, agent_data)

        result = await _dispatch_with_retry()

        logger.info(
            "Security event processed",
            event_id=event.event_id,
            agent_type=agent_type.value,
            classification=result.classification,
            risk_score=result.risk_score,
            success=result.success,
        )

        # Record this event unconditionally - a clean email, a benign log
        # line, or anything else that processed successfully with zero
        # findings still gets a durable events row, so the Events page is
        # a genuine activity history and not only a list of things that
        # triggered detection.
        category = _category_for_event(event, payload.get("source_type"))
        events_id = await _record_processed_event(
            event=event,
            category=category,
            success=result.success,
            risk_score=result.risk_score,
            severity=result.severity,
            findings_count=len(result.findings),
        )

        # STEP 8.5.4.1: Process findings through common lifecycle hook
        # This triggers correlation → alert → incident for non-Windows sources
        if result.findings:
            await _process_agent_findings(
                result=result,
                event=event,
                category=category,
                events_id=events_id,
            )

        # Optionally publish result back to event bus
        # This is commented out to avoid circular publishing in this step
        # await publish_agent_result(event, result)

    except (OSError, ValueError, RuntimeError, KeyError) as e:
        logger.exception(
            "Failed to process security event after exhausting retries",
            event_id=event.event_id,
            event_type=event.event_type,
            error=str(e),
        )
        # Re-raise so _process_message() (app/event_bus/consumer.py) sees
        # this as a real failure and returns False - which keeps the
        # offset uncommitted for redelivery instead of advancing past a
        # record that was never actually processed. Swallowing the
        # exception here (the previous behavior) made the manual-commit
        # durability fix in consumer.py pointless: the handler would
        # return normally, _process_message() would report success, and
        # the offset would commit even though dispatch/persistence never
        # completed - the exact silent-data-loss failure mode the
        # manual-commit switch exists to prevent. By the time control
        # reaches here, the bounded retry on the dispatch call above has
        # already been exhausted for transient errors, so this is a
        # genuine, non-recovering failure (or a non-transient one that
        # was never retried) - the consumer's redelivery-then-DLQ-on-
        # repeated-failure path is still the right place for it to end
        # up, not this function.
        raise


async def publish_agent_result(
    original_event: SecurityEvent,
    result: AgentResult,
) -> bool:
    """
    Publish agent analysis result back to the event bus.

    This creates a new SecurityEvent with the result and publishes it.
    Can be used for downstream processing or alerting.

    Args:
        original_event: The event that was analyzed
        result: The agent's analysis result

    Returns:
        True if published successfully
    """
    producer = get_producer()

    if not producer.is_started:
        logger.warning("Producer not started, cannot publish result")
        return False

    # Create result event
    result_event = SecurityEvent(
        event_type=f"{original_event.event_type}_result",
        source=result.agent_type.value,
        correlation_id=original_event.correlation_id or original_event.event_id,
        severity=result.severity,
        classification=result.classification,
        risk_score=result.risk_score,
        indicators=result.indicators,
        payload={
            "original_event_id": original_event.event_id,
            "result_id": result.result_id,
            "findings_count": len(result.findings),
            "summary": result.summary,
            "recommendations": result.recommendations,
            "success": result.success,
            "error": result.error,
        },
    )

    return await producer.publish_security_event(result_event)


class SecurityEventConsumer:
    """
    Consumer for security events that routes to the TaskDispatcher.

    This is the main integration point between Redpanda and the agent system.
    """

    def __init__(self):
        self._consumer: EventConsumer | None = None

    async def start(self) -> None:
        """Start consuming security events."""
        self._consumer = EventConsumer(
            group_id="security-processor",
            topics=[Topic.SECURITY_EVENTS],
            handler=handle_security_event,
        )
        await self._consumer.start()

    async def stop(self) -> None:
        """Stop the consumer."""
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None

    @property
    def is_running(self) -> bool:
        """Check if consumer is running."""
        return self._consumer is not None and self._consumer.is_running


# Global consumer instance (optional - can also create per-worker)
_security_consumer: SecurityEventConsumer | None = None


def get_security_consumer() -> SecurityEventConsumer:
    """Get or create the global security event consumer."""
    global _security_consumer
    if _security_consumer is None:
        _security_consumer = SecurityEventConsumer()
    return _security_consumer


async def start_security_consumer() -> None:
    """Start the global security event consumer."""
    consumer = get_security_consumer()
    await consumer.start()


async def stop_security_consumer() -> None:
    """Stop the global security event consumer."""
    global _security_consumer
    if _security_consumer:
        await _security_consumer.stop()
        _security_consumer = None
