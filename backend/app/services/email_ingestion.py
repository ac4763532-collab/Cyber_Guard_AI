"""
CyberGuard AI - Email Event Bus Integration

Publishes email analysis requests onto the same Redpanda "security-events"
topic the log collectors already use (event_type="email"), so that
findings produced for an email are persisted (Finding row) and run through
the single authoritative on_finding_created() hook - individual alerting,
correlation, incidents, notifications - exactly like log-sourced findings
already do.

This module intentionally mirrors app/logs/event_bus_integration.py's
publish_log_event() shape and redaction discipline:
    - redact the payload before it ever reaches Redpanda (body/headers may
      contain credentials, tokens, or other sensitive strings pasted into
      a phishing email)
    - build a SecurityEvent envelope with the already-resolved, trusted
      tenant_id (never a silent "default" fallback)
    - publish via the shared EventBusProducer onto Topic.SECURITY_EVENTS

Architecture:
    POST /analysis/email or Gmail endpoints (manual, synchronous)
           |
           v dispatcher.dispatch_email()  (unchanged - immediate HTTP response)
    AgentResult returned to caller
           |
           v publish_email_event()  (new - this module, fire-and-forget)
    Redpanda (security-events, event_type="email")
           |
           v
    SecurityEventConsumer -> handle_security_event()
    (app/event_bus/dispatcher_integration.py)
           |
           v
    TaskDispatcher.dispatch(AgentType.EMAIL, ...) -> EmailAgent
           |
           v
    Finding persisted -> on_finding_created()
    (app/correlation/finding_lifecycle.py)
    -> individual alert (always, if severity threshold met)
    -> correlation -> separate correlated-threat alert (if a cross-finding
       relationship is found) - never replaces the individual alert

Both the manual synchronous call and the bus publish run for the SAME
analysis request, so the user's immediate response is unchanged while the
same finding also becomes durable and alertable.
"""

from typing import Any

import structlog

from app.event_bus.config import get_event_bus_config
from app.event_bus.events import SecurityEvent
from app.event_bus.producer import get_producer
from app.event_bus.topics import Topic
from app.logs.redaction import redact_dict, redact_string

logger = structlog.get_logger(__name__)


def _redact_email_payload(analysis_data: dict[str, Any]) -> dict[str, Any]:
    """
    Redact sensitive content out of an email analysis payload before it is
    published to Redpanda.

    Uses the generic redact_dict/redact_string helpers (not the log-specific
    redact_log_event wrapper, whose signature doesn't match an email's
    field shape). Redacts body and header *values* for secrets/credentials
    while leaving structural fields (sender, subject, urls, attachment
    metadata) intact, since those are exactly what EmailAgent and
    correlation need to analyze and link findings.
    """
    redacted = dict(analysis_data)

    body = redacted.get("body")
    if isinstance(body, str):
        redacted["body"] = redact_string(body)

    headers = redacted.get("headers")
    if isinstance(headers, dict):
        redacted["headers"] = redact_dict(headers)

    attachments = redacted.get("attachments")
    if isinstance(attachments, list):
        redacted["attachments"] = [
            redact_dict(att) if isinstance(att, dict) else att
            for att in attachments
        ]

    return redacted


async def publish_email_event(
    analysis_data: dict[str, Any],
    tenant_id: str,
    source: str,
) -> bool:
    """
    Publish an email analysis request to Redpanda for automatic processing.

    The email data is wrapped in a SecurityEvent envelope with
    event_type="email", routing it to EmailAgent via
    handle_security_event()'s existing EVENT_TO_AGENT mapping.

    Args:
        analysis_data: dict in the exact shape EmailAgent.analyze() /
            EmailAnalysisRequest.model_dump() expects (sender, recipient,
            subject, body, headers, urls, attachments, received_at).
        tenant_id: the already-resolved, trusted tenant identifier. Callers
            must not pass a fabricated/default value - findings and alerts
            are scoped by this and incorrect isolation here would leak
            across tenants in correlation.
        source: "manual" (POST /analysis/email) or "gmail" (Gmail
            endpoints) - carried through so findings/alerts can be
            attributed to how the email entered the system.

    Returns:
        True if published successfully, False otherwise (event bus
        disabled, producer not started, or publish failure). Callers
        should treat a False return as non-fatal - the synchronous
        analysis response the user sees does not depend on this.
    """
    config = get_event_bus_config()

    if not config.event_bus_enabled:
        logger.debug("Event bus disabled, skipping email event publish")
        return False

    redacted_data = _redact_email_payload(analysis_data)

    sender = redacted_data.get("sender") or ""

    # Gmail's own stable message id, when this analysis came from a Gmail
    # endpoint (see GmailParser.to_analysis_request(), which always sets
    # this key - it's absent for POST /analysis/email's manual payload).
    # Reusing the existing "log_event_id" payload key - the same one
    # log_event_to_security_event() already sets for log-sourced events -
    # means _resolve_event_id_for_finding() (app/event_bus/
    # dispatcher_integration.py) picks it up for free via its existing
    # `payload.get("log_event_id") or event.event_id` fallback, with no
    # changes needed there. Without this, every publish of the "same"
    # email got a fresh random event.event_id, so the (source,
    # source_event_id) unique index never actually deduplicated repeat
    # analyses of one physical message (e.g. "Analyze" then "Investigate"
    # on the same message, or the poller later re-seeing a manually
    # analyzed message).
    gmail_message_id = redacted_data.get("gmail_message_id")

    security_event = SecurityEvent(
        event_type="email",  # Routes to EmailAgent via dispatcher
        schema_version=1,
        source=f"email:{source}",
        tenant_id=tenant_id,
        payload={
            "sender": sender,
            "recipient": redacted_data.get("recipient"),
            "subject": redacted_data.get("subject"),
            "body": redacted_data.get("body"),
            "headers": redacted_data.get("headers"),
            "urls": redacted_data.get("urls"),
            "attachments": redacted_data.get("attachments"),
            # Previously omitted here even though GmailParser always
            # produces it - EmailAgent's SPF/DKIM/DMARC/header-chain
            # checks (_analyze_spf/_analyze_dkim/_analyze_dmarc/
            # _analyze_header_chain) read data.get("authentication"), so
            # without this key those checks were structurally unreachable
            # on this async/event-bus path even though the synchronous
            # dispatch_email() call powering the HTTP response has it -
            # the two analyses of the "same" email silently disagreed.
            "authentication": redacted_data.get("authentication"),
            "received_at": (
                redacted_data["received_at"].isoformat()
                if redacted_data.get("received_at")
                else None
            ),
            "source": source,
            "tenant_id": tenant_id,
            **({"log_event_id": gmail_message_id} if gmail_message_id else {}),
        },
    )

    producer = get_producer()
    if not producer.is_started:
        logger.warning("Producer not started, cannot publish email event")
        return False

    # Partition key: sender address, so repeated mail from the same sender
    # orders consistently within a partition (mirrors log collectors' use
    # of source_id/hostname as the key).
    key = sender or None

    success = await producer.publish(
        topic=Topic.SECURITY_EVENTS,
        event=security_event,
        key=key,
    )

    if success:
        logger.debug(
            "Published email event to Redpanda",
            source=source,
            tenant_id=tenant_id,
        )
    else:
        logger.error(
            "Failed to publish email event to Redpanda",
            source=source,
            tenant_id=tenant_id,
        )

    return success
