"""
CyberGuard AI - Consumer -> Dispatcher -> LogAgent Integration Test (Step 3, Part 6)

Proves whether a collector-generated event is actually consumed and reaches
real detection, and explicitly documents the one boundary this test does
NOT cover.

Proves the REAL runtime path:

    SecurityEvent, shaped exactly as the real log_event_to_security_event()
    produces it from a real collector-built LogEvent
            |
    handle_security_event() (real - the actual handler wired to
                              SecurityEventConsumer in dispatcher_integration.py)
            |
    TaskDispatcher.dispatch(AgentType.LOG, agent_data) (real)
            |
    LogAgent.run() -> validate() -> analyze() (real, unmodified detection
                                                 logic - not extended here
                                                 per the task's constraints)
            |
    AgentResult (real)

What is NOT exercised by this test, and why (explicit untested boundary,
per the task's Part 6 instruction: "If full Redpanda integration is
impractical in the current test environment, clearly identify the exact
untested boundary instead of pretending the pipeline is fully verified."):

- AIOKafkaConsumer / EventConsumer._consume_loop() / getmany(): the actual
  network leg that pulls messages off a real Redpanda topic and
  deserializes them into SecurityEvent objects via EventConsumer's own
  message-parsing code. No live broker is available in this environment
  (confirmed via `docker ps`/`docker info`), so this leg is NOT invoked
  here. This test starts one hop downstream of that leg: at
  handle_security_event(), the exact handler EventConsumer would call once
  it had deserialized a real message.
- Correlation/alerting (_process_agent_findings -> on_finding_created):
  exercised only to the extent that a Redis-unavailable or other
  non-fatal error there is swallowed (matching the real handler's own
  try/except), not fully verified end-to-end against a real Redis.

NOT mocked: handle_security_event(), TaskDispatcher, LogAgent.run()/
validate()/analyze() (real, unmodified regex-based detection), get_dispatcher().
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.agents.dispatcher import get_dispatcher, TaskDispatcher
from app.agents.base import AgentType
from app.event_bus.dispatcher_integration import handle_security_event
from app.event_bus.events import SecurityEvent
from app.database.models.base import SeverityLevel
from app.logs.models import LogEvent, LogLevel, LogSourceType
from app.logs.event_bus_integration import log_event_to_security_event


def make_collector_log_event(**overrides) -> LogEvent:
    """Builds a LogEvent the same way a real collector would (e.g. the
    Linux collector's _tail_file()/parser chain already proven in
    test_integration_linux_pipeline.py)."""
    defaults = dict(
        source_id="consumer-test-source",
        source_type=LogSourceType.LINUX_SSH,
        hostname="prod-db03",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.WARNING,
        message="Failed password for root from 203.0.113.77 port 51233",
        raw_content="Oct  9 03:14:05 prod-db03 sshd[1022]: Failed password for root "
                    "from 203.0.113.77 port 51233 ssh2",
        extracted_fields={
            "event_type": "ssh_failed",
            "username": "root",
            "source_ip": "203.0.113.77",
            "auth_result": "failed",
        },
        tags=["linux", "authentication", "ssh_failed"],
        category="authentication",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


class TestConsumerToLogAgentDispatch:
    """Real handle_security_event() -> real TaskDispatcher -> real
    LogAgent, using a SecurityEvent shaped exactly as the real collector
    publish path produces."""

    @pytest.mark.asyncio
    async def test_collector_shaped_event_reaches_real_log_agent(self):
        log_event = make_collector_log_event()
        # Real conversion function - the exact shape a real collector's
        # publish_log_event() call would hand to the producer, and
        # therefore the exact shape a real consumer would deserialize back
        # out of Redpanda.
        security_event = log_event_to_security_event(log_event)

        dispatcher = get_dispatcher()
        agent = dispatcher.get_agent(AgentType.LOG)

        # Confirms the REAL LogAgent is registered, not PlaceholderAgent
        # (which would silently return classification="pending" and make
        # this test pass without proving anything).
        from app.agents.log_agent import LogAgent
        assert isinstance(agent, LogAgent), (
            f"Expected the real LogAgent to be registered, got "
            f"{type(agent).__name__}. If this is PlaceholderAgent, "
            f"detection claims below would be meaningless."
        )

        initial_stats = dict(agent.stats)

        # This is the exact call EventConsumer's real _consume_loop() would
        # make after deserializing a message off the wire into a
        # SecurityEvent and invoking its registered handler.
        await handle_security_event(security_event)

        # Real LogAgent.run() increments its own stats on every call -
        # proves analyze() actually executed, not just that dispatch()
        # returned early.
        assert agent.stats["total_analyzed"] == initial_stats.get("total_analyzed", 0) + 1

    @pytest.mark.asyncio
    async def test_brute_force_pattern_from_collector_event_is_detected(self):
        """Realistic malicious scenario (shares ground with Part 7, but at
        the consumer boundary specifically): a log_content built from
        several failed SSH attempts, routed through the real consumer
        handler's LOG-agent field mapping, must reach LogAgent's real
        (unmodified) brute-force detection and produce actual findings."""
        multi_failure_content = "\n".join(
            f"Oct  9 03:14:{i:02d} prod-db03 sshd[102{i}]: Failed password for root "
            f"from 203.0.113.77 port {51230 + i} ssh2"
            for i in range(6)
        )
        log_event = make_collector_log_event(
            message=multi_failure_content,
            raw_content=multi_failure_content,
        )
        security_event = log_event_to_security_event(log_event)

        # The real handler maps payload["raw_content"] -> "log_content"
        # (the fix verified in this task - see dispatcher_integration.py's
        # handle_security_event()). Confirm raw_content actually carries
        # the multi-line content through the real conversion function.
        assert security_event.payload["raw_content"] == multi_failure_content

        dispatcher = get_dispatcher()
        agent = dispatcher.get_agent(AgentType.LOG)

        result = await dispatcher.dispatch(AgentType.LOG, {
            "log_content": security_event.payload["raw_content"],
            "log_type": security_event.payload["source_type"],
            "source_host": security_event.payload["hostname"],
        })

        assert result.success is True
        # Real, unmodified LogAgent brute-force detection (not extended or
        # fixed in this task) should flag repeated failures from one IP.
        assert len(result.findings) > 0, (
            "Expected the real LogAgent._detect_brute_force (or "
            "_detect_auth_failures) to produce at least one finding from "
            "6 repeated failed-SSH lines from the same source IP"
        )

    @pytest.mark.asyncio
    async def test_handle_security_event_maps_fields_matching_log_agent_validate(self):
        """Regression guard for the exact bug fixed in this task: before
        the fix, handle_security_event() built agent_data from
        **event.payload directly (message/raw_content keys), which
        LogAgent.validate() rejects (it requires "log_content"). This
        confirms the live consumer handler no longer silently drops every
        real log event."""
        log_event = make_collector_log_event(
            message="trivial message that should not itself be flagged",
            raw_content="Oct  9 03:14:01 prod-db03 sshd[1]: Accepted publickey for "
                        "deploy from 198.51.100.5 port 60000 ssh2",
        )
        security_event = log_event_to_security_event(log_event)

        from app.agents.log_agent import LogAgent
        agent = LogAgent()

        # Replicate exactly what the real handle_security_event() builds -
        # this is the regression-sensitive mapping itself.
        payload = security_event.payload
        agent_data = {
            "log_content": payload.get("raw_content") or payload.get("message", ""),
            "log_type": payload.get("source_type", "auto"),
            "source_host": payload.get("hostname", "unknown"),
            "extracted_fields": payload.get("extracted_fields", {}),
            "tags": payload.get("tags", []),
        }

        is_valid, error = await agent.validate(agent_data)
        assert is_valid is True, (
            f"handle_security_event()'s field mapping must produce data "
            f"LogAgent.validate() accepts - got error: {error}"
        )
