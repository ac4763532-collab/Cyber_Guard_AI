"""
CyberGuard AI — Windows Collector API Client
============================================================================

HTTP client for the collector's communication with the CyberGuard
backend. Every network call the collector makes goes through this
module.

Endpoints used
--------------
    POST /api/v1/collector/enroll         — redeem enrollment token
    POST /api/v1/events                   — send one event
    POST /api/v1/events/batch             — send a batch of events
    POST /api/v1/collector/heartbeat      — send a heartbeat

Response types
--------------
Every method returns a typed result DTO (not raw dicts, not exceptions
on expected failures). Callers branch on the result — they don't
`try/except` around HTTP mechanics.

    EnrollResult         — enrollment attempt result
    SendResult           — single/batch send result
    HeartbeatResult      — heartbeat attempt result

Every result DTO has:
    - ``success: bool``        — did the operation succeed?
    - ``error_code: str | None`` — machine-readable failure category
    - ``error_message: str | None`` — human-readable
    - ``should_retry: bool``   — should the caller retry?
    - operation-specific fields (credential, event IDs, etc.)

Error categories
----------------
    NETWORK_ERROR          — connection refused, DNS failure, timeout
                             → should_retry=True
    SERVER_ERROR           — 5xx from backend
                             → should_retry=True
    RATE_LIMITED           — 429 from backend
                             → should_retry=True (with backoff)
    AUTH_ERROR             — 401/403, credential revoked/invalid
                             → should_retry=False (re-enroll)
    SOURCE_DISABLED        — source is disabled/paused/revoked on backend
                             → should_retry=False (user action required)
    VALIDATION_ERROR       — 4xx (event malformed)
                             → should_retry=False (bug in collector)
    UNKNOWN_ERROR          — anything else
                             → should_retry=False

This module never raises on HTTP-level failures. It only raises on
programming errors (invalid config, unregistered method called with
bad arguments).

Design rules
------------
1. **Never log the credential.** Every log line that mentions the
   request includes the URL, method, and status code — never headers.

2. **Timeouts everywhere.** Per-request timeout from config
   (``http_timeout_seconds``, default 30s). A hung request does not
   block the sender forever.

3. **Retry-After header support.** On 429, the backend may set
   ``Retry-After: <seconds>``. The client returns this in the result
   so the caller can honor it in its backoff loop.

4. **Compression-aware.** Requests send ``Accept-Encoding: gzip`` —
   httpx handles decompression transparently.

5. **No external dependencies beyond httpx.** No requests, no aiohttp,
   no urllib. One HTTP library, one mental model.

6. **Health check.** A separate ``probe_health()`` method performs a
   lightweight GET /health to test connectivity without sending
   credentials.

Usage
-----
    from config import CollectorConfig
    from api_client import ApiClient

    config = CollectorConfig.load()
    client = ApiClient(config)

    # Enroll
    result = client.enroll(
        plaintext_token="<enrollment token>",
        hostname="priya-laptop",
        os_version="Windows 11 23H2",
        agent_version="0.1.0",
        hardware_fingerprint="sha256:...",
    )
    if result.success:
        # Store the credential
        store_credential(config, result.plaintext_credential)
        config.save()
    elif result.should_retry:
        # Retry with backoff
        ...
    else:
        # Enrollment token invalid/expired — user must re-generate
        ...
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from config import CollectorConfig


logger = logging.getLogger(__name__)


# ============================================================================
# RESULT DTOs
# ============================================================================

@dataclass(frozen=True)
class EnrollResult:
    """
    Result of an enrollment attempt.

    On success:
        success              = True
        plaintext_credential = "cgc_..."  (store this!)
        credential_prefix    = "cgc_xxxx"  (for logging)
        expires_at           = ISO timestamp or None

    On failure:
        success      = False
        error_code   = one of the categories above
        should_retry = whether to retry
    """
    success: bool
    should_retry: bool = False
    error_code: str | None = None
    error_message: str | None = None
    retry_after_seconds: int | None = None

    # Success-only fields
    plaintext_credential: str | None = None
    credential_prefix: str | None = None
    credential_id: str | None = None
    expires_at: str | None = None
    heartbeat_interval_seconds: int = 60


@dataclass(frozen=True)
class SendResult:
    """
    Result of sending one event or a batch.

    On success:
        success       = True
        ingested      = number of events successfully ingested
        duplicates    = number of events rejected as duplicates
        rejected      = number of events rejected for validation/state

    On failure (network/server):
        success       = False
        error_code    = category
        should_retry  = True (for NETWORK_ERROR, SERVER_ERROR, RATE_LIMITED)
    """
    success: bool
    should_retry: bool = False
    error_code: str | None = None
    error_message: str | None = None
    retry_after_seconds: int | None = None

    # Success-only fields
    ingested: int = 0
    duplicates: int = 0
    rejected: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class HeartbeatResult:
    """
    Result of a heartbeat attempt.

    Heartbeats are best-effort — a transient failure doesn't stop the
    collector. A persistent 401/403 does (the credential is dead).
    """
    success: bool
    should_retry: bool = False
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class HealthProbeResult:
    """Result of a lightweight /health check."""
    reachable: bool
    status_code: int | None = None
    db_ok: bool | None = None
    error_message: str | None = None


# ============================================================================
# ERROR CLASSIFICATION
# ============================================================================

def _classify_http_error(status_code: int) -> tuple[str, bool]:
    """
    Map HTTP status → (error_code, should_retry).

    Never returns UNKNOWN_ERROR for a known status code.
    """
    if 200 <= status_code < 300:
        return ("", False)   # success — not called for 2xx

    if status_code == 401:
        return ("AUTH_ERROR", False)
    if status_code == 403:
        return ("AUTH_ERROR", False)   # Could be SOURCE_DISABLED — parsed from body
    if status_code == 404:
        # Endpoint not found — collector/backend version mismatch
        return ("VERSION_MISMATCH", False)
    if status_code == 413:
        return ("PAYLOAD_TOO_LARGE", False)
    if status_code == 422:
        return ("VALIDATION_ERROR", False)
    if status_code == 429:
        return ("RATE_LIMITED", True)
    if 500 <= status_code < 600:
        return ("SERVER_ERROR", True)

    return ("UNKNOWN_ERROR", False)


def _extract_error_from_body(
    response: httpx.Response,
) -> tuple[str | None, str | None]:
    """
    Extract (error_code, error_message) from a CyberGuard error response
    body. Returns (None, None) if the body isn't a CyberGuard-style
    error envelope.

    Expected shape:
        {"error": {"code": "COLLECTOR_AUTH_ERROR", "message": "..."}}
    """
    try:
        body = response.json()
    except Exception:
        return None, None

    if not isinstance(body, dict):
        return None, None
    err = body.get("error")
    if not isinstance(err, dict):
        return None, None
    return (
        err.get("code"),
        err.get("message"),
    )


# ============================================================================
# API CLIENT
# ============================================================================

class ApiClient:
    """
    HTTP client for the CyberGuard collector.

    Stateless — safe to instantiate multiple times. Each instance opens
    a new ``httpx.Client`` per request (not per instance), which is
    fine for the collector's request rate (a few per second at most).

    For higher throughput, a persistent client with connection pooling
    could be used — but the added complexity isn't worth it for MVP.
    """

    def __init__(self, config: "CollectorConfig") -> None:
        self._config = config
        self._backend_url = config.backend_url.rstrip("/")
        self._credential = config.credential   # encrypted blob
        self._timeout = float(config.http_timeout_seconds)

    # ── Enrollment ──────────────────────────────────────────────────────

    def enroll(
        self,
        *,
        plaintext_token: str,
        hostname: str | None = None,
        os_version: str | None = None,
        agent_version: str | None = None,
        hardware_fingerprint: str | None = None,
    ) -> EnrollResult:
        """
        Redeem an enrollment token for a long-lived credential.

        Sends POST /api/v1/collector/enroll with the token and device
        identity. On success, returns the plaintext credential for the
        caller to store (via ``credential_store.store_credential``).

        The plaintext credential is returned **exactly once** — the
        backend cannot retrieve it later.
        """
        url = f"{self._backend_url}/api/v1/collector/enroll"

        payload = {
            "token": plaintext_token,
            "collector_id": str(self._config.collector_id),
            "hostname": hostname or _get_hostname(),
            "os_version": os_version or _get_os_version(),
            "agent_version": agent_version or self._config.agent_version,
            "hardware_fingerprint": hardware_fingerprint,
        }

        logger.info(
            "Enrollment attempt",
            extra={
                "url": url,
                "collector_id": str(self._config.collector_id),
                "hostname": payload["hostname"],
            },
        )

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    url,
                    json=payload,
                    headers={"Accept": "application/json"},
                )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            return EnrollResult(
                success=False,
                should_retry=True,
                error_code="NETWORK_ERROR",
                error_message=f"{type(exc).__name__}: {str(exc)[:300]}",
            )

        duration_ms = int((time.perf_counter() - start) * 1000)
        logger.info(
            "Enrollment response",
            extra={
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        # ── Success (201)
        if response.status_code in (200, 201):
            try:
                body = response.json()
            except Exception:
                return EnrollResult(
                    success=False,
                    should_retry=True,
                    error_code="MALFORMED_RESPONSE",
                    error_message="Enrollment response was not valid JSON",
                )
            return EnrollResult(
                success=True,
                plaintext_credential=body.get("plaintext_credential"),
                credential_prefix=body.get("credential_prefix"),
                credential_id=body.get("collector_credential_id"),
                expires_at=body.get("expires_at"),
                heartbeat_interval_seconds=int(
                    body.get("heartbeat_interval_seconds", 60)
                ),
            )

        # ── Failure — classify
        error_code, error_message = _extract_error_from_body(response)
        category, should_retry = _classify_http_error(response.status_code)

        # Backend returned a specific code (e.g. ENROLLMENT_TOKEN_EXPIRED)
        # — use it in preference to the category, but keep the category
        # as the "why we retry or not" signal.
        if category == "AUTH_ERROR" and error_code in (
            "COLLECTOR_AUTH_ERROR",
            "COLLECTOR_REVOKED",
            "COLLECTOR_CREDENTIAL_HEADER_MISSING",
        ):
            should_retry = False   # credential dead — must re-enroll
        elif category == "AUTH_ERROR" and error_code in (
            "SOURCE_DISABLED",
            "SOURCE_REVOKED",
            "COLLECTION_PAUSED",
            "SOURCE_NOT_ACTIVE",
            "SOURCE_NOT_YET_ENROLLED",
        ):
            category = "SOURCE_DISABLED"
            should_retry = False

        retry_after = _parse_retry_after(response)

        return EnrollResult(
            success=False,
            should_retry=should_retry,
            error_code=error_code or category,
            error_message=(
                error_message
                or f"HTTP {response.status_code}: {response.text[:300]}"
            ),
            retry_after_seconds=retry_after,
        )

    # ── Event send ──────────────────────────────────────────────────────

    def send_event(self, event_payload: dict[str, Any]) -> SendResult:
        """
        Send one event via POST /api/v1/events.
        """
        return self._send_batch_internal(
            [event_payload],
            endpoint="/api/v1/events",
            is_batch=False,
        )

    def send_batch(self, event_payloads: list[dict[str, Any]]) -> SendResult:
        """
        Send a batch of events via POST /api/v1/events/batch.
        """
        return self._send_batch_internal(
            event_payloads,
            endpoint="/api/v1/events/batch",
            is_batch=True,
        )

    # ── Heartbeat ───────────────────────────────────────────────────────

    def heartbeat(
        self,
        *,
        hostname: str | None = None,
        queue_depth: int | None = None,
        cpu_percent: float | None = None,
        memory_percent: float | None = None,
    ) -> HeartbeatResult:
        """
        Send a heartbeat. Lightweight — used to keep the source's
        ``collector_connected`` indicator true.
        """
        if not self._credential:
            return HeartbeatResult(
                success=False,
                should_retry=False,
                error_code="NOT_ENROLLED",
                error_message="Cannot send heartbeat before enrollment",
            )

        url = f"{self._backend_url}/api/v1/collector/heartbeat"
        payload = {
            "collector_id": str(self._config.collector_id),
            "hostname": hostname or _get_hostname(),
        }
        if queue_depth is not None:
            payload["queue_depth"] = queue_depth
        if cpu_percent is not None:
            payload["cpu_percent"] = cpu_percent
        if memory_percent is not None:
            payload["memory_percent"] = memory_percent

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    url,
                    json=payload,
                    headers=self._auth_headers(),
                )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            logger.debug(
                "Heartbeat failed (network)",
                extra={"error": f"{type(exc).__name__}: {str(exc)[:200]}"},
            )
            return HeartbeatResult(
                success=False,
                should_retry=True,
                error_code="NETWORK_ERROR",
                error_message=f"{type(exc).__name__}: {str(exc)[:300]}",
            )

        duration_ms = int((time.perf_counter() - start) * 1000)

        if response.status_code in (200, 201, 204):
            logger.debug(
                "Heartbeat OK",
                extra={"duration_ms": duration_ms},
            )
            return HeartbeatResult(success=True)

        category, should_retry = _classify_http_error(response.status_code)
        error_code, error_message = _extract_error_from_body(response)

        logger.warning(
            "Heartbeat failed",
            extra={
                "status": response.status_code,
                "error_code": error_code,
                "should_retry": should_retry,
            },
        )

        return HeartbeatResult(
            success=False,
            should_retry=should_retry,
            error_code=error_code or category,
            error_message=(
                error_message
                or f"HTTP {response.status_code}: {response.text[:300]}"
            ),
        )

    # ── Health probe ────────────────────────────────────────────────────

    def probe_health(self) -> HealthProbeResult:
        """
        Quick health check — does not use credentials.

        Returns ``reachable=True`` if the backend responds at all (even
        with a 503 — that means the app is up but the DB is down).
        """
        url = f"{self._backend_url}/health"

        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(url)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            return HealthProbeResult(
                reachable=False,
                error_message=f"{type(exc).__name__}: {str(exc)[:200]}",
            )

        db_ok = None
        try:
            body = response.json()
            checks = body.get("checks") or {}
            db_info = checks.get("db") or {}
            db_ok = db_info.get("status") == "ok"
        except Exception:
            pass

        return HealthProbeResult(
            reachable=True,
            status_code=response.status_code,
            db_ok=db_ok,
        )

    # ── Internal ────────────────────────────────────────────────────────

    def _send_batch_internal(
        self,
        event_payloads: list[dict[str, Any]],
        *,
        endpoint: str,
        is_batch: bool,
    ) -> SendResult:
        """Shared implementation for single and batch sends."""
        if not self._credential:
            return SendResult(
                success=False,
                should_retry=False,
                error_code="NOT_ENROLLED",
                error_message="Cannot send events before enrollment",
            )

        if not event_payloads:
            return SendResult(success=True)

        url = f"{self._backend_url}{endpoint}"

        body: dict[str, Any]
        if is_batch:
            body = {"events": event_payloads}
        else:
            body = event_payloads[0]

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    url,
                    json=body,
                    headers=self._auth_headers(),
                )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
            logger.debug(
                "Send failed (network)",
                extra={
                    "count": len(event_payloads),
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                },
            )
            return SendResult(
                success=False,
                should_retry=True,
                error_code="NETWORK_ERROR",
                error_message=f"{type(exc).__name__}: {str(exc)[:300]}",
            )

        duration_ms = int((time.perf_counter() - start) * 1000)

        # ── Success
        if response.status_code in (200, 201, 204):
            result = self._parse_send_response(response, is_batch)
            logger.debug(
                "Send OK",
                extra={
                    "count": len(event_payloads),
                    "duration_ms": duration_ms,
                    "ingested": result.ingested,
                    "duplicates": result.duplicates,
                    "rejected": result.rejected,
                },
            )
            return result

        # ── Failure — classify
        category, should_retry = _classify_http_error(response.status_code)
        error_code, error_message = _extract_error_from_body(response)

        # Backend-specific failure codes that mean "don't retry, re-enroll"
        if error_code in (
            "COLLECTOR_AUTH_ERROR",
            "COLLECTOR_REVOKED",
            "COLLECTOR_CREDENTIAL_ROTATED",
            "COLLECTOR_CREDENTIAL_EXPIRED",
            "SOURCE_REVOKED",
        ):
            should_retry = False

        # Backend-specific failure codes that mean "source disabled/paused"
        if error_code in (
            "SOURCE_DISABLED",
            "COLLECTION_PAUSED",
            "SOURCE_NOT_ACTIVE",
        ):
            category = "SOURCE_DISABLED"
            should_retry = False

        retry_after = _parse_retry_after(response)

        logger.warning(
            "Send failed",
            extra={
                "count": len(event_payloads),
                "status": response.status_code,
                "error_code": error_code,
                "should_retry": should_retry,
                "duration_ms": duration_ms,
            },
        )

        return SendResult(
            success=False,
            should_retry=should_retry,
            error_code=error_code or category,
            error_message=(
                error_message
                or f"HTTP {response.status_code}: {response.text[:300]}"
            ),
            retry_after_seconds=retry_after,
        )

    def _parse_send_response(
        self,
        response: httpx.Response,
        is_batch: bool,
    ) -> SendResult:
        """Extract ingested/duplicates/rejected from a 2xx response."""
        try:
            body = response.json()
        except Exception:
            # Non-JSON 2xx — count it as success but assume 1 ingested
            return SendResult(
                success=True,
                ingested=1 if not is_batch else 0,
            )

        if is_batch:
            # Batch response: EventBatchIngestResponse shape
            return SendResult(
                success=True,
                ingested=int(body.get("ingested", 0)),
                duplicates=int(body.get("duplicates", 0)),
                rejected=int(body.get("rejected", 0)),
                results=list(body.get("results") or []),
            )
        else:
            # Single response: EventIngestResult shape
            status = body.get("status", "")
            if status == "ingested":
                return SendResult(success=True, ingested=1)
            elif status == "duplicate":
                return SendResult(success=True, duplicates=1)
            else:
                return SendResult(success=True, rejected=1)

    def _auth_headers(self) -> dict[str, str]:
        """Build the headers for authenticated collector requests."""
        return {
            "Accept": "application/json",
            "X-Collector-Credential": self._credential or "",
            "X-Collector-ID": str(self._config.collector_id),
        }


# ============================================================================
# HELPERS
# ============================================================================

def _parse_retry_after(response: httpx.Response) -> int | None:
    """Parse the Retry-After header (seconds form only)."""
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _get_hostname() -> str:
    """Best-effort hostname."""
    import socket
    try:
        return socket.gethostname()[:255]
    except Exception:
        return "unknown"


def _get_os_version() -> str:
    """Best-effort OS version."""
    import platform
    try:
        return f"{platform.system()} {platform.release()}"[:64]
    except Exception:
        return "unknown"


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ApiClient",
    "EnrollResult",
    "SendResult",
    "HeartbeatResult",
    "HealthProbeResult",
]