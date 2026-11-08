"""
CyberGuard AI — Event Ingestion Service
============================================================================
Handles high-throughput ingestion of telemetry events from endpoint and
cloud collectors. Performs validation, fingerprint calculation, deduplication,
ORM persistence, and agent pipeline triggering.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.event import SecurityEvent
from app.models.source import SourceCredential, SecuritySource as DataSource
from app.schemas.event import EventIngestRequest

logger = get_logger(__name__)


@dataclass
class SingleIngestResult:
    status: str  # "ingested" | "duplicate" | "rejected"
    event_id: Optional[uuid.UUID] = None
    client_ref: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class BatchIngestResult:
    total_received: int = 0
    ingested: int = 0
    duplicates: int = 0
    rejected: int = 0
    results: List[SingleIngestResult] = field(default_factory=list)


def calculate_fingerprint(
    source_id: uuid.UUID,
    event_time: datetime,
    event_type: str,
    hostname: Optional[str],
    raw_payload: Optional[dict[str, Any]],
) -> str:
    """Calculate deterministic SHA256 fingerprint for deduplication."""
    hasher = hashlib.sha256()
    hasher.update(str(source_id).encode("utf-8"))
    hasher.update(event_time.isoformat().encode("utf-8"))
    hasher.update(event_type.encode("utf-8"))
    if hostname:
        hasher.update(hostname.strip().lower().encode("utf-8"))
    if raw_payload:
        try:
            hasher.update(json.dumps(raw_payload, sort_keys=True).encode("utf-8"))
        except (TypeError, ValueError):
            pass
    return hasher.hexdigest()


def ingest_single(
    db: Session,
    *,
    source: DataSource,
    credential: Optional[SourceCredential] = None,
    payload: EventIngestRequest,
    client_ref: Optional[str] = None,
) -> SingleIngestResult:
    """Ingest a single security event."""
    try:
        ev_time = payload.event_time or datetime.now(timezone.utc)
        ev_type = payload.event_type or "system.generic"
        fingerprint = calculate_fingerprint(
            source_id=source.id,
            event_time=ev_time,
            event_type=ev_type,
            hostname=payload.hostname,
            raw_payload=payload.raw_payload,
        )

        # Deduplication check
        existing = db.execute(
            select(SecurityEvent.id)
            .where(
                SecurityEvent.source_id == source.id,
                SecurityEvent.fingerprint == fingerprint,
            )
            .limit(1)
        ).scalar_one_or_none()

        if existing is not None:
            return SingleIngestResult(
                status="duplicate",
                event_id=existing,
                client_ref=client_ref,
            )

        # Raw payload size
        raw_size = 0
        if payload.raw_payload:
            try:
                raw_size = len(json.dumps(payload.raw_payload))
            except Exception:
                raw_size = 0

        event = SecurityEvent(
            id=uuid.uuid4(),
            workspace_id=source.workspace_id,
            source_id=source.id,
            event_time=ev_time,
            received_at=datetime.now(timezone.utc),
            severity=payload.severity or "informational",
            category=payload.category or "endpoint",
            event_type=ev_type,
            action=payload.action,
            outcome=payload.outcome or "unknown",
            fingerprint=fingerprint,
            username=payload.username,
            hostname=payload.hostname,
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            source_port=payload.source_port,
            destination_port=payload.destination_port,
            process_name=payload.process_name,
            process_id=payload.process_id,
            file_path=payload.file_path,
            url=payload.url,
            domain=payload.domain,
            email_address=payload.email_address,
            hash_md5=payload.hash_md5,
            hash_sha256=payload.hash_sha256,
            raw_payload=payload.raw_payload,
            normalized_payload=payload.normalized_payload,
            tags=payload.tags or [],
            raw_payload_size_bytes=raw_size,
        )

        db.add(event)
        db.flush()

        return SingleIngestResult(
            status="ingested",
            event_id=event.id,
            client_ref=client_ref,
        )

    except Exception as exc:
        logger.error("Failed to ingest event", exc_info=exc)
        return SingleIngestResult(
            status="rejected",
            client_ref=client_ref,
            error_code="INGESTION_ERROR",
            error_message=str(exc),
        )


def ingest_batch(
    db: Session,
    *,
    source: DataSource,
    credential: Optional[SourceCredential] = None,
    payloads: Sequence[EventIngestRequest],
) -> BatchIngestResult:
    """Ingest up to 500 events in batch."""
    batch_res = BatchIngestResult(total_received=len(payloads))

    for item in payloads:
        res = ingest_single(
            db,
            source=source,
            credential=credential,
            payload=item,
            client_ref=getattr(item, "client_ref", None),
        )
        batch_res.results.append(res)
        if res.status == "ingested":
            batch_res.ingested += 1
        elif res.status == "duplicate":
            batch_res.duplicates += 1
        else:
            batch_res.rejected += 1

    return batch_res
