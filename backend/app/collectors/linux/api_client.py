"""
CyberGuard AI — Linux Collector API Client
============================================================================

HTTP client for the collector's communication with the CyberGuard
backend. Every network call the collector makes goes through this
module.

Identical to the Windows collector's ``api_client.py`` — same endpoints,
same result DTOs, same error classification, same retry semantics.
The only differences are in the three helper functions at the bottom:

    _get_hostname()      — prefers FQDN, falls back to short hostname
    _get_os_version()    — reads /etc/os-release for a real distro name
    _get_primary_mac()   — reads /sys/class/net/<iface>/address

Endpoints used
--------------
    POST /api/v1/collector/enroll         — redeem enrollment token
    POST /api/v1/events                   — send one event
    POST /api/v1/events/batch             — send a batch of events
    POST /api/v1/collector/heartbeat      — send a heartbeat

Response types
--------------
Every method returns a typed DTO, never raises on expected failures.

    EnrollResult         — success + credential, or error code + retry flag
    SendResult           — ingested / duplicates / rejected counts
    HeartbeatResult      — success / retry flag / error code
    HealthProbeResult    — reachable / db_ok / status_code

Error categories (identical to Windows)
---------------------------------------
    NETWORK_ERROR          → should_retry=True
    SERVER_ERROR           → should_retry=True
    RATE_LIMITED           → should_retry=True (with Retry-After)
    AUTH_ERROR             → should_retry=False (re-enroll)
    SOURCE_DISABLED        → should_retry=False (user action)
    VALIDATION_ERROR       → should_retry=False (bug in collector)
    VERSION_MISMATCH       → should_retry=False (upgrade collector)
    UNKNOWN_ERROR          → should_retry=False

Design rules (from the collector contract)
------------------------------------------
1. Never log the credential. Every log line uses URL, method, status
   code — never headers.
2. Timeouts on every request (``http_timeout_seconds``).
3. Retry-After honored on 429.
4. No external deps beyond httpx.
5. Never raises on HTTP failure — returns a typed DTO.

Usage
-----
    from config import CollectorConfig
    from api_client import ApiClient

    config = CollectorConfig.load()
    client = ApiClient(config)

    # Enroll
    result = client.enroll(plaintext_token="<token>")
    if result.success:
        store_credential(config, result.plaintext_credential)
        config.save()
    elif result.should_retry:
        # Network/server error — retry later
        ...
    else:
        # Bad token, expired, source disabled — operator action required
        ...
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
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
    """Result of an enrollment attempt."""
    success: bool
    should_retry: bool = False
    error_code: str | None = None
    error_message: str | None = None
    retry_after_seconds: int | None = None

    # Success-only
    plaintext_credential: str | None = None
    credential_prefix: str | None = None
    credential_id: str | None = None
    expires_at: str | None = None
    heartbeat_interval_seconds: int = 60


@dataclass(frozen=True)
class SendResult:
    """Result of sending one event or a batch."""
    success: bool
    should_retry: bool = False
    error_code: str | None = None
    error_message: str | None = None
    retry_after_seconds: int | None = None

    # Success-only
    ingested: int = 0
    duplicates: int = 0
    rejected: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class HeartbeatResult:
    """Result of a heartbeat attempt."""
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
    """Map HTTP status → (category, should_retry)."""
    if 200 <= status_code < 300:
        return ("", False)

    if status_code == 401:
        return ("AUTH_ERROR", False)
    if status_code == 403:
        return ("AUTH_ERROR", False)
    if status_code == 404:
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
    Extract (code, message) from a CyberGuard error envelope:

        {"error": {"code": "...", "message": "..."}}

    Returns (None, None) if the body doesn't match.
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
    return err.get("code"), err.get("message")


# ============================================================================
# API CLIENT
# ============================================================================

class ApiClient:
    """
    HTTP client for the Linux collector.

    Stateless except for the config reference. Safe to instantiate
    multiple times (e.g. one per thread — though the current
    architecture uses one shared instance).
    """

    def __init__(self, config: "CollectorConfig") -> None:
        self._config = config
        self._backend_url = config.backend_url.rstrip("/")
        self._credential = config.credential   # encrypted blob (used as-is by backend)
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

        The plaintext credential is returned **once** — after this
        call, only the backend's bcrypt hash exists. Callers must
        persist it (via ``credential_store.store_credential``)
        immediately.
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

        # ── Success
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

        # ── Failure
        error_code, error_message = _extract_error_from_body(response)
        category, should_retry = _classify_http_error(response.status_code)

        # Backend-specific codes override the generic classification
        if error_code in (
            "COLLECTOR_AUTH_ERROR",
            "COLLECTOR_REVOKED",
            "COLLECTOR_CREDENTIAL_HEADER_MISSING",
        ):
            should_retry = False
        elif error_code in (
            "SOURCE_DISABLED",
            "SOURCE_REVOKED",
            "COLLECTION_PAUSED",
            "SOURCE_NOT_ACTIVE",
            "SOURCE_NOT_YET_ENROLLED",
        ):
            category = "SOURCE_DISABLED"
            should_retry = False

        return EnrollResult(
            success=False,
            should_retry=should_retry,
            error_code=error_code or category,
            error_message=(
                error_message
                or f"HTTP {response.status_code}: {response.text[:300]}"
            ),
            retry_after_seconds=_parse_retry_after(response),
        )

    # ── Event send ──────────────────────────────────────────────────────

    def send_event(self, event_payload: dict[str, Any]) -> SendResult:
        """Send one event via POST /api/v1/events."""
        return self._send_internal(
            [event_payload],
            endpoint="/api/v1/events",
            is_batch=False,
        )

    def send_batch(self, event_payloads: list[dict[str, Any]]) -> SendResult:
        """Send a batch of events via POST /api/v1/events/batch."""
        return self._send_internal(
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
        Send a lightweight heartbeat. Keeps the source's
        ``last_heartbeat_at`` fresh on the backend — without it, the
        source goes "disconnected" after 5 minutes.
        """
        if not self._credential:
            return HeartbeatResult(
                success=False,
                should_retry=False,
                error_code="NOT_ENROLLED",
                error_message="Cannot send heartbeat before enrollment",
            )

        url = f"{self._backend_url}/api/v1/collector/heartbeat"
        payload: dict[str, Any] = {
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
            logger.debug("Heartbeat OK", extra={"duration_ms": duration_ms})
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
        Unauthenticated GET /health. Reachable=True means the backend
        responded at all (even a 503 — that means the app is up but
        DB is down).
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

    def _send_internal(
        self,
        event_payloads: list[dict[str, Any]],
        *,
        endpoint: str,
        is_batch: bool,
    ) -> SendResult:
        """Shared implementation for single + batch sends."""
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

        # ── Failure
        category, should_retry = _classify_http_error(response.status_code)
        error_code, error_message = _extract_error_from_body(response)

        if error_code in (
            "COLLECTOR_AUTH_ERROR",
            "COLLECTOR_REVOKED",
            "COLLECTOR_CREDENTIAL_ROTATED",
            "COLLECTOR_CREDENTIAL_EXPIRED",
            "SOURCE_REVOKED",
        ):
            should_retry = False
        elif error_code in (
            "SOURCE_DISABLED",
            "COLLECTION_PAUSED",
            "SOURCE_NOT_ACTIVE",
        ):
            category = "SOURCE_DISABLED"
            should_retry = False

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
            retry_after_seconds=_parse_retry_after(response),
        )

    def _parse_send_response(
        self,
        response: httpx.Response,
        is_batch: bool,
    ) -> SendResult:
        """Extract counts from a 2xx response body."""
        try:
            body = response.json()
        except Exception:
            return SendResult(
                success=True,
                ingested=1 if not is_batch else 0,
            )

        if is_batch:
            return SendResult(
                success=True,
                ingested=int(body.get("ingested", 0)),
                duplicates=int(body.get("duplicates", 0)),
                rejected=int(body.get("rejected", 0)),
                results=list(body.get("results") or []),
            )
        else:
            status = body.get("status", "")
            if status == "ingested":
                return SendResult(success=True, ingested=1)
            elif status == "duplicate":
                return SendResult(success=True, duplicates=1)
            else:
                return SendResult(success=True, rejected=1)

    def _auth_headers(self) -> dict[str, str]:
        """Headers for authenticated collector requests."""
        return {
            "Accept": "application/json",
            "X-Collector-Credential": self._credential or "",
            "X-Collector-ID": str(self._config.collector_id),
        }


# ============================================================================
# LINUX-SPECIFIC HELPERS
# ============================================================================

def _parse_retry_after(response: httpx.Response) -> int | None:
    """Parse the Retry-After header (seconds form)."""
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _get_hostname() -> str:
    """
    Best-effort hostname for enrollment.

    Prefers FQDN (``hostname -f``) if resolvable, falls back to
    short hostname. FQDN helps the backend distinguish devices in
    environments where short hostnames collide (e.g. many
    ``ubuntu-1`` VMs across different domains).
    """
    try:
        fqdn = socket.getfqdn()
        if fqdn and fqdn != "localhost":
            return fqdn[:255]
    except Exception:
        pass
    try:
        return socket.gethostname()[:255]
    except Exception:
        return "unknown"


def _get_os_version() -> str:
    """
    Return a human-readable OS description.

    Reads ``/etc/os-release`` (present on every modern Linux distro)
    and formats as ``<NAME> <VERSION_ID>``:

        "Ubuntu 22.04"
        "Debian GNU/Linux 12"
        "Red Hat Enterprise Linux 9.3"
        "Alpine Linux 3.19"

    Falls back to ``platform.platform()`` if ``/etc/os-release`` is
    missing or unparseable (e.g. very old distros, minimal containers).
    """
    os_release = Path("/etc/os-release")
    if os_release.exists():
        try:
            data: dict[str, str] = {}
            for line in os_release.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                data[key] = val

            name = data.get("NAME", "").strip()
            version = data.get("VERSION_ID", "").strip()
            if name and version:
                result = f"{name} {version}"
            elif name:
                result = name
            else:
                result = platform.platform()

            return result[:64]
        except Exception:
            pass

    try:
        return platform.platform()[:64]
    except Exception:
        return "Linux"


def _get_primary_mac() -> str | None:
    """
    Return the primary network interface's MAC address.

    The "primary" interface is the one with a default route — found
    by parsing ``/proc/net/route``. If that's not available, falls
    back to the first non-virtual interface in ``/sys/class/net/``
    that isn't ``lo``, ``docker0``, ``veth*``, or ``virbr*``.

    Returns None if nothing suitable is found (shouldn't happen on
    a normal system).
    """
    # Try /proc/net/route for the default-route interface
    route_file = Path("/proc/net/route")
    if route_file.exists():
        try:
            for line in route_file.read_text().splitlines()[1:]:
                fields = line.split("\t")
                if len(fields) >= 3:
                    iface = fields[0]
                    # Destination 00000000 (all zeros) = default route
                    if fields[1] == "00000000" and iface != "lo":
                        mac = _read_mac(iface)
                        if mac:
                            return mac
        except Exception:
            pass

    # Fallback: first non-virtual interface
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        try:
            for iface_dir in sorted(net_dir.iterdir()):
                iface = iface_dir.name
                if iface == "lo":
                    continue
                if iface.startswith(("veth", "docker", "virbr", "br-", "tun", "tap")):
                    continue
                mac = _read_mac(iface)
                if mac:
                    return mac
        except Exception:
            pass

    return None


def _read_mac(iface: str) -> str | None:
    """Read a MAC address from /sys/class/net/<iface>/address."""
    try:
        path = Path(f"/sys/class/net/{iface}/address")
        if not path.exists():
            return None
        mac = path.read_text().strip().lower()
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass
    return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ApiClient",
    "EnrollResult",
    "SendResult",
    "HeartbeatResult",
    "HealthProbeResult",
    # Re-exported for main.py's fingerprint helper
    "_get_hostname",
    "_get_os_version",
    "_get_primary_mac",
]