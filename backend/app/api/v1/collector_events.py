"""
CyberGuard AI — Collector Events Ingestion Endpoint
============================================================================
Allows enrolled Windows and Linux endpoint collectors to submit authenticated
batches of telemetry events directly to the ingestion pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.deps import DBDep
from app.core.constants import HEADER_COLLECTOR_CREDENTIAL, HEADER_COLLECTOR_ID
from app.core.exceptions import CollectorAuthError, NotFoundError
from app.core.logging import get_logger
from app.models.source import SecuritySource as DataSource
from app.schemas.event import EventIngestRequest
from app.services import collector_credential_service, event_ingestion

logger = get_logger(__name__)

router = APIRouter(
    prefix="/collector",
    tags=["collector"],
)


class CollectorEventBatchRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    batch_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    events: List[EventIngestRequest]


class CollectorEventBatchResponse(BaseModel):
    batch_id: uuid.UUID
    total_received: int
    ingested: int
    duplicates: int
    rejected: int


@router.post(
    "/events",
    response_model=CollectorEventBatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest batch of security telemetry events from enrolled collector",
)
def ingest_collector_events(
    payload: CollectorEventBatchRequest,
    db: DBDep,
    x_collector_id: Annotated[Optional[str], Header(alias=HEADER_COLLECTOR_ID)] = None,
    x_collector_credential: Annotated[Optional[str], Header(alias=HEADER_COLLECTOR_CREDENTIAL)] = None,
) -> CollectorEventBatchResponse:
    if not x_collector_id or not x_collector_credential:
        raise CollectorAuthError("Missing collector authentication headers")

    try:
        collector_uuid = uuid.UUID(x_collector_id)
    except ValueError:
        raise CollectorAuthError("Invalid collector ID header format")

    verified = collector_credential_service.verify_credential(
        db,
        x_collector_credential,
    )
    if not verified:
        raise CollectorAuthError("Invalid or expired collector credential")

    source = verified.source

    # Update first telemetry progress checkpoint
    now_iso = datetime.now(timezone.utc).isoformat()
    if isinstance(source.config, dict):
        cfg = dict(source.config)
        prog = cfg.get("installation_progress", {})
        prog["first_telemetry_received"] = True
        prog["first_telemetry_at"] = prog.get("first_telemetry_at") or now_iso
        cfg["installation_progress"] = prog
        source.config = cfg
        flag_modified(source, "config")

    batch_res = event_ingestion.ingest_batch(
        db,
        source=source,
        payloads=payload.events,
    )
    if batch_res.ingested > 0:
        source.events_ingested_count = (source.events_ingested_count or 0) + batch_res.ingested
        source.last_event_at = datetime.now(timezone.utc)

    db.commit()

    return CollectorEventBatchResponse(
        batch_id=payload.batch_id,
        total_received=batch_res.total_received,
        ingested=batch_res.ingested,
        duplicates=batch_res.duplicates,
        rejected=batch_res.rejected,
    )
