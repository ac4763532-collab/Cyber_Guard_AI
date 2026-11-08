"""
CyberGuard AI — Security Event Schemas
============================================================================

Request/response DTOs for the ``security_events`` table.

The event table is the highest-volume table in the platform. These
schemas are optimized for:

    - Ingestion speed (collectors send events fast, back-to-back)
    - Query flexibility (dashboard filters, agent queries)
    - Storage economy (lightweight list views, full read only when needed)

Design rules
------------
1. **Ingestion input is deliberately minimal.**
   ``EventIngestRequest`` accepts only the fields the collector
   actually knows. Everything else (workspace_id, source_id, fingerprint,
   received_at, findings_count) is server-computed.

2. **Fingerprint is never accepted from clients.**
   Computed by ``app.services.event_fingerprint`` from a canonical set
   of fields. Ensures dedup is correct regardless of what the collector
   sends.

3. **``event_time`` vs ``received_at`` distinction is preserved.**
   ``event_time`` is when it happened on the source (client-supplied).
   ``received_at`` is when the backend accepted it (server-set).
   Both are in ``EventRead``.

4. **``raw_payload`` is preserved.**
   Forensics needs the original bytes. ``EventRead`` includes it as an
   optional field — list endpoints drop it to save bytes, detail
   endpoints include it.

5. **Filter schema covers the dashboard's actual query patterns.**
   Not every column is filterable. Only the ones used by real UI
   queries: workspace, source, type, severity, category, time range,
   IP, username, hostname.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import EventCategory, EventSeverity
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_EVENT_TYPE_MAX = 64
_ACTION_MAX = 64
_OUTCOME_MAX = 32
_USERNAME_MAX = 255
_HOSTNAME_MAX = 255
_IP_MAX = 45
_PROCESS_NAME_MAX = 255
_DOMAIN_MAX = 253
_EMAIL_MAX = 320
_MD5_MAX = 32
_SHA256_MAX = 64
_URL_MAX = 2048
_FILE_PATH_MAX = 4096
_TAGS_MAX = 30

#: Bulk ingestion cap — one request carries at most this many events.
_BATCH_MAX = 500

#: Payload size caps.
_RAW_PAYLOAD_MAX_BYTES = 256 * 1024     # 256 KB per event
_NORMALIZED_PAYLOAD_MAX_BYTES = 64 * 1024  # 64 KB per event


# ============================================================================
# INGEST (collector → backend)
# ============================================================================

class EventIngestRequest(CyberGuardBaseSchema):
    """
    Single-event ingestion body for ``POST /events``.

    Minimal by design — only what a collector knows at the moment of
    emission. The backend derives workspace_id (from collector
    credential), source_id (from credential), fingerprint (from
    canonical fields), received_at (server time), and all counters.

    Security note: the collector authenticates via its
    ``SourceCredential`` in the request headers. ``X-Collector-Credential``
    and ``X-Collector-ID``. These are handled by the ingestion endpoint's
    dependencies, not by this schema.
    """

    event_time: datetime = Field(
        ...,
        description=(
            "When the event happened on the source (client-supplied). "
            "Must be timezone-aware. For forensic accuracy, prefer the "
            "source's own timestamp over 'now'. Backend rejects times "
            "more than 1 hour in the future."
        ),
    )

    event_type: str = Field(
        ...,
        min_length=1,
        max_length=_EVENT_TYPE_MAX,
        description="Free-form type string, e.g. 'failed_login', 'port_scan'.",
    )

    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Initial severity from the source.",
    )

    category: EventCategory = Field(
        default=EventCategory.OTHER,
        description="What kind of activity.",
    )

    action: str | None = Field(default=None, max_length=_ACTION_MAX)
    outcome: str | None = Field(default=None, max_length=_OUTCOME_MAX)

    # ── Entity fields (all optional) ─────────────────────────────────
    username: str | None = Field(default=None, max_length=_USERNAME_MAX)
    hostname: str | None = Field(default=None, max_length=_HOSTNAME_MAX)
    source_ip: str | None = Field(default=None, max_length=_IP_MAX)
    destination_ip: str | None = Field(default=None, max_length=_IP_MAX)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = Field(default=None, max_length=_PROCESS_NAME_MAX)
    process_id: int | None = Field(default=None, ge=0)
    file_path: str | None = Field(default=None, max_length=_FILE_PATH_MAX)
    url: str | None = Field(default=None, max_length=_URL_MAX)
    domain: str | None = Field(default=None, max_length=_DOMAIN_MAX)
    email_address: str | None = Field(default=None, max_length=_EMAIL_MAX)
    hash_md5: str | None = Field(default=None, max_length=_MD5_MAX)
    hash_sha256: str | None = Field(default=None, max_length=_SHA256_MAX)

    # ── Payloads ─────────────────────────────────────────────────────
    raw_payload: dict[str, Any] = Field(
        ...,
        description="The original event data as sent by the source.",
    )
    normalized_payload: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Optional standardized shape. If empty, the service derives "
            "a minimal normalized shape from the entity fields."
        ),
    )

    tags: list[str] = Field(default_factory=list, max_length=_TAGS_MAX)

    @field_validator("event_time")
    @classmethod
    def _validate_event_time(cls, v: datetime) -> datetime:
        from datetime import datetime as dt, timezone
        if v.tzinfo is None:
            raise ValueError(
                "event_time must be timezone-aware (use UTC). "
                "Naive datetimes are rejected — they are a known source "
                "of ingestion bugs."
            )
        now = dt.now(timezone.utc)
        max_future = now.timestamp() + 3600  # 1 hour in the future
        if v.timestamp() > max_future:
            raise ValueError(
                "event_time is more than 1 hour in the future. "
                "This usually indicates clock drift on the collector — "
                "check the device's time sync."
            )
        return v

    @field_validator("raw_payload")
    @classmethod
    def _validate_raw_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json
        try:
            size = len(json.dumps(v, default=str).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"raw_payload is not JSON-serializable: {exc}")
        if size > _RAW_PAYLOAD_MAX_BYTES:
            raise ValueError(
                f"raw_payload exceeds {_RAW_PAYLOAD_MAX_BYTES} bytes "
                f"when serialized (got {size}). The collector must trim."
            )
        return v

    @field_validator("normalized_payload")
    @classmethod
    def _validate_normalized_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json
        try:
            size = len(json.dumps(v, default=str).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"normalized_payload is not JSON-serializable: {exc}")
        if size > _NORMALIZED_PAYLOAD_MAX_BYTES:
            raise ValueError(
                f"normalized_payload exceeds {_NORMALIZED_PAYLOAD_MAX_BYTES} "
                f"bytes when serialized (got {size})"
            )
        return v

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each tag must be a string")
            stripped = item.strip().lower()
            if not stripped or stripped in seen:
                continue
            if len(stripped) > 64:
                raise ValueError("each tag must not exceed 64 characters")
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned


class EventBatchIngestRequest(CyberGuardBaseSchema):
    """
    Bulk ingestion body for ``POST /events/batch``.

    Collectors should prefer batch ingestion — 10x fewer round trips,
    less HTTP overhead, and better throughput under load. Per-event
    failures within a batch are reported individually in the response.
    """

    events: list[EventIngestRequest] = Field(
        ...,
        min_length=1,
        max_length=_BATCH_MAX,
        description=f"Events to ingest ({_BATCH_MAX} max per request).",
    )


class EventIngestResult(CyberGuardBaseSchema):
    """Per-event result for batch ingestion."""

    client_ref: str | None = Field(
        default=None,
        description=(
            "Optional client-supplied reference to correlate results "
            "with input events. If not provided, callers should use "
            "position in the array."
        ),
    )
    status: str = Field(
        ...,
        description="'ingested' | 'duplicate' | 'rejected' | 'error'.",
    )
    event_id: uuid.UUID | None = Field(
        default=None,
        description="UUID of the created event, if ingested.",
    )
    error_code: str | None = Field(
        default=None,
        description="Error code if rejected, e.g. 'DUPLICATE_FINGERPRINT'.",
    )
    error_message: str | None = Field(default=None)


class EventBatchIngestResponse(CyberGuardBaseSchema):
    """Response for batch ingestion."""

    total_received: int
    ingested: int
    duplicates: int
    rejected: int
    results: list[EventIngestResult]


# ============================================================================
# READ
# ============================================================================

class EventRead(TimestampedModel):
    """
    Full event view. Used by ``GET /events/{id}`` (detail).

    Includes both payloads — expensive but necessary for forensics.
    List endpoints use ``EventList`` which omits payloads.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    source_id: uuid.UUID | None = None

    event_time: datetime
    received_at: datetime

    severity: EventSeverity
    category: EventCategory
    event_type: str
    action: str | None = None
    outcome: str | None = None

    fingerprint: str

    # ── Entity fields ────────────────────────────────────────────────
    username: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    process_name: str | None = None
    process_id: int | None = None
    file_path: str | None = None
    url: str | None = None
    domain: str | None = None
    email_address: str | None = None
    hash_md5: str | None = None
    hash_sha256: str | None = None

    # ── Payloads ─────────────────────────────────────────────────────
    raw_payload: dict[str, Any]
    normalized_payload: dict[str, Any]
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )
    tags: list[str] = Field(default_factory=list)

    # ── Counters ─────────────────────────────────────────────────────
    findings_count: int = 0
    raw_payload_size_bytes: int = 0


class EventList(ORMModel):
    """
    Lightweight event view for lists and dashboards.

    Omits payloads (which can be hundreds of KB each), keeping list
    responses small. Fetch ``GET /events/{id}`` for full details.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    source_id: uuid.UUID | None = None
    event_time: datetime
    received_at: datetime
    severity: EventSeverity
    category: EventCategory
    event_type: str
    action: str | None = None
    outcome: str | None = None
    username: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    findings_count: int = 0


# ============================================================================
# FILTER
# ============================================================================

class EventFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /events``.

    Covers the actual query patterns used by the dashboard. Not every
    column is filterable — only the ones with real UI use.
    """

    source_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to events from a single source.",
    )

    event_type: str | None = Field(
        default=None,
        max_length=_EVENT_TYPE_MAX,
        description="Exact match on event_type.",
    )

    severity: EventSeverity | None = Field(
        default=None,
        description="Filter by severity.",
    )

    min_severity: EventSeverity | None = Field(
        default=None,
        description="Filter to severity >= this. Useful for 'show high or above'.",
    )

    category: EventCategory | None = Field(
        default=None,
        description="Filter by category.",
    )

    username: str | None = Field(
        default=None,
        max_length=_USERNAME_MAX,
        description="Exact match on username (case-insensitive).",
    )

    hostname: str | None = Field(
        default=None,
        max_length=_HOSTNAME_MAX,
        description="Exact match on hostname (case-insensitive).",
    )

    source_ip: str | None = Field(
        default=None,
        max_length=_IP_MAX,
        description="Exact match on source_ip.",
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=_IP_MAX,
        description="Exact match on destination_ip.",
    )

    has_findings: bool | None = Field(
        default=None,
        description="If True, only events with >= 1 finding. If False, only without.",
    )

    event_time_after: datetime | None = Field(
        default=None,
        description="Only events with event_time >= this.",
    )

    event_time_before: datetime | None = Field(
        default=None,
        description="Only events with event_time <= this.",
    )

    received_after: datetime | None = Field(
        default=None,
        description="Only events with received_at >= this.",
    )

    received_before: datetime | None = Field(
        default=None,
        description="Only events with received_at <= this.",
    )

    tags_any: list[str] | None = Field(
        default=None,
        description="Only events that have at least one of these tags.",
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventIngestRequest",
    "EventBatchIngestRequest",
    "EventIngestResult",
    "EventBatchIngestResponse",
    "EventRead",
    "EventList",
    "EventFilter",
]