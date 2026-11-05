"""
CyberGuard AI - Shared Ingestion-Key Authentication Primitives (STEP 9)

STEP 9 removed the web_application LogSourceType and, with it, this
module's own HTTP route (`POST /logs/web/ingest`, the `/keys` CRUD
routes, and `WebLogEntry`/`WebLogBatch`/`ingest_web_logs()`). Those were
specific to accepting externally-pushed web-application logs over HTTP
and are no longer reachable - router.py no longer includes a router from
this module at all.

What remains here, and why this file is kept rather than deleted:
- get_authenticated_key(): the X-Ingestion-Key API-key auth dependency,
  still reused by app/api/v1/logs.py's generic /logs/ingest and
  /logs/ingest/raw routes (those routes are NOT web-application-specific
  - they accept any source type whose owning key is bound to it).
- get_ingestion_key_repository(): re-exported for the same reason, and
  because tests/test_security_log_ingestion_tenant_isolation.py imports
  both of these names directly from this module.

This module intentionally defines no APIRouter and registers no routes.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import structlog

from app.auth.ingestion_keys import (
    IngestionApiKey,
    get_ingestion_key_repository,
)


logger = structlog.get_logger(__name__)


# API key header name - shared by every caller of get_authenticated_key.
API_KEY_HEADER = "X-Ingestion-Key"

api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


async def get_authenticated_key(
    api_key: str | None = Depends(api_key_header),
) -> IngestionApiKey:
    """
    Authenticate a request using the X-Ingestion-Key API key header.

    Raises 401 if the key is missing, invalid, or revoked. Used by
    app/api/v1/logs.py's generic ingestion routes.
    """
    if not api_key:
        logger.warning("Ingestion: missing API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing API key. Provide {API_KEY_HEADER} header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    repo = get_ingestion_key_repository()
    key = await repo.authenticate(api_key)

    if not key:
        logger.warning(
            "Ingestion: invalid API key",
            key_prefix=api_key[:11] if len(api_key) > 11 else "invalid",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return key
