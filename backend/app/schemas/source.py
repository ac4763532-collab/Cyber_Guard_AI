"""
CyberGuard AI — Security Source Schemas
============================================================================

Request/response DTOs for the ``security_sources`` and
``source_credentials`` tables.

Design rules
------------
1. **Clients never set the 5 connection indicators.**
   ``collector_connected``, ``last_heartbeat_at``, ``collection_active``,
   ``last_event_at``, ``agent_processing_healthy`` are all computed by
   the backend. Create/Update schemas do not declare them. Only
   ``collection_active`` has a **dedicated** toggle endpoint.

2. **``source_key`` is auto-generated.**
   Format ``src-<8 hex>``. Not accepted from clients.

3. **``registered_by_id`` is set by the service** (to current user).

4. **``status`` is a lifecycle field, not client-settable via Update.**
   Enable/disable/revoke are dedicated endpoints with audit entries.

5. **``config`` is validated per source_type.** Today: permissive dict
   with documented expected keys. Tighten per-type when collectors land.

6. **``capabilities`` is a controlled vocabulary.**
   ``log_collection``, ``network_monitoring``, ``email_scan``,
   ``database_audit``, ``file_integrity``. Unknown values are rejected.

7. **Credentials are never returned in plaintext.**
   ``SourceCredentialRead`` exposes only ``credential_prefix`` (12 chars)
   — never the full credential. The plaintext is shown once at issuance,
   in ``SourceCredentialIssued`` (a Create-only response), then never again.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import (
    CredentialStatus,
    SourceStatus,
    SourceType,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_NAME_MAX = 120
_DESCRIPTION_MAX = 2000
_HOSTNAME_MAX = 255
_IP_MAX = 45
_OS_VERSION_MAX = 64
_AGENT_VERSION_MAX = 32
_CAPABILITIES_MAX = 20
_CONFIG_MAX_SIZE_BYTES = 32 * 1024

#: Controlled vocabulary for source capabilities.
_ALLOWED_CAPABILITIES = frozenset({
    "log_collection",
    "network_monitoring",
    "email_scan",
    "database_audit",
    "file_integrity",
    "process_monitoring",
    "registry_monitoring",
})

_IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_CREDENTIAL_PREFIX_PATTERN = re.compile(r"^cgc_[a-f0-9]{8}$")


# ============================================================================
# CREATE
# ============================================================================

class SecuritySourceCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /workspaces/{ws_id}/sources``.

    Registers a new source. The service:
      - generates ``source_key``
      - sets ``registered_by_id`` = current user
      - initializes all 5 connection indicators to their "not connected" state
      - sets ``status = PENDING_ENROLLMENT``
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=_NAME_MAX,
        description="Human-readable name shown in UI and reports.",
        examples=["Priya's Laptop"],
    )

    source_type: SourceType = Field(
        ...,
        description="Category of source (windows, linux, email, network, ...).",
    )

    description: str | None = Field(
        default=None,
        max_length=_DESCRIPTION_MAX,
    )

    capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "What this source can provide. Values must be from the "
            "controlled vocabulary: " + ", ".join(sorted(_ALLOWED_CAPABILITIES))
        ),
    )

    config: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Collector-specific configuration (e.g. Windows channel list, "
            "Linux log paths, network interface). Shape is validated per "
            "source_type by the service layer."
        ),
    )

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each capability must be a string")
            normalized = item.strip().lower()
            if not normalized:
                continue
            if normalized not in _ALLOWED_CAPABILITIES:
                raise ValueError(
                    f"Unknown capability: {normalized!r}. "
                    f"Allowed: {sorted(_ALLOWED_CAPABILITIES)}"
                )
            if normalized in seen:
                continue
            seen.add(normalized)
            cleaned.append(normalized)
        if len(cleaned) > _CAPABILITIES_MAX:
            raise ValueError(
                f"capabilities must not exceed {_CAPABILITIES_MAX} items"
            )
        return cleaned

    @field_validator("config")
    @classmethod
    def _validate_config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json
        try:
            serialized = json.dumps(v, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"config is not JSON-serializable: {exc}")
        if len(serialized.encode("utf-8")) > _CONFIG_MAX_SIZE_BYTES:
            raise ValueError(
                f"config exceeds {_CONFIG_MAX_SIZE_BYTES} bytes when serialized"
            )
        return v


# ============================================================================
# READ
# ============================================================================

class SecuritySourceRead(TimestampedModel):
    """
    Full source view including the 5 connection indicators.

    These indicators are what the UI uses to render the 7 device states
    from the interaction document (Not connected, Enrollment pending,
    Connected, No recent events, Disconnected, Disabled, Revoked).
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    source_key: str
    name: str
    description: str | None = None
    source_type: SourceType
    status: SourceStatus

    # ── The 5 connection indicators ──────────────────────────────────
    collector_connected: bool
    last_heartbeat_at: datetime | None = None
    collection_active: bool
    last_event_at: datetime | None = None
    agent_processing_healthy: bool

    # ── Device identity (reported by collector) ──────────────────────
    hostname: str | None = None
    ip_address: str | None = None
    os_version: str | None = None
    agent_version: str | None = None

    # ── Configuration ────────────────────────────────────────────────
    capabilities: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    # ── Counters ─────────────────────────────────────────────────────
    events_ingested_count: int = 0
    events_failed_count: int = 0

    # ── Computed ─────────────────────────────────────────────────────
    is_active: bool = Field(
        ..., description="True if status is ACTIVE."
    )
    is_healthy: bool = Field(
        ...,
        description="Composite health: ACTIVE + connected + collecting + agents OK.",
    )
    display_status: str = Field(
        ...,
        description=(
            "UI-ready status string. One of: 'enrollment_pending', "
            "'disabled', 'revoked', 'error', 'disconnected', "
            "'connected_not_collecting', 'connected_no_recent_events', "
            "'processing_degraded', 'connected'."
        ),
    )


class SecuritySourceList(ORMModel):
    """
    Lightweight source view for lists and pickers.
    """

    id: uuid.UUID
    source_key: str
    name: str
    source_type: SourceType
    status: SourceStatus
    collector_connected: bool
    last_event_at: datetime | None = None


# ============================================================================
# UPDATE
# ============================================================================

class SecuritySourceUpdate(CyberGuardBaseSchema):
    """
    Fields a source owner/admin can change. Every field optional.

    Cannot change (schema does not declare):
        - ``source_key`` — generated, immutable
        - ``status`` — dedicated enable/disable/revoke endpoints
        - ``collector_connected`` / ``last_heartbeat_at`` /
          ``last_event_at`` / ``agent_processing_healthy`` — server-computed
        - ``events_ingested_count`` / ``events_failed_count`` — server-managed
    """

    name: str | None = Field(default=None, min_length=1, max_length=_NAME_MAX)
    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)
    config: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Merged with existing config (not replaced). To remove a "
            "key, pass it with a null value."
        ),
    )
    capabilities: list[str] | None = None

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            raise ValueError("name must not be empty")
        return stripped

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each capability must be a string")
            normalized = item.strip().lower()
            if not normalized:
                continue
            if normalized not in _ALLOWED_CAPABILITIES:
                raise ValueError(f"Unknown capability: {normalized!r}")
            if normalized in seen:
                continue
            seen.add(normalized)
            cleaned.append(normalized)
        if len(cleaned) > _CAPABILITIES_MAX:
            raise ValueError(
                f"capabilities must not exceed {_CAPABILITIES_MAX} items"
            )
        return cleaned


class CollectionToggle(CyberGuardBaseSchema):
    """
    Request body for ``POST /sources/{id}/collection``.

    Turns event collection on or off. A connected source with
    ``collection_active=False`` still heartbeats but does not send
    events. This is the "pause monitoring without revoking credentials"
    workflow.
    """

    active: bool = Field(
        ...,
        description="True to enable collection, False to pause.",
    )

    reason: str | None = Field(
        default=None,
        max_length=500,
        description="Optional reason recorded in the audit log.",
    )


# ============================================================================
# FILTER
# ============================================================================

class SecuritySourceFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /sources``.
    """

    source_type: SourceType | None = None
    status: SourceStatus | None = None
    collector_connected: bool | None = None
    collection_active: bool | None = None

    name_contains: str | None = Field(
        default=None,
        max_length=_NAME_MAX,
        description="Case-insensitive substring match on name.",
    )

    @field_validator("name_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# CREDENTIAL SCHEMAS
# ============================================================================

class SourceCredentialRead(ORMModel):
    """
    Safe view of a source credential. Never includes the plaintext.
    """

    id: uuid.UUID
    source_id: uuid.UUID
    credential_prefix: str = Field(
        ...,
        description="First 12 chars of the credential, for log/UI identification.",
    )
    status: CredentialStatus
    description: str | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    is_active: bool = Field(..., description="True if currently usable.")
    is_revoked: bool = Field(..., description="True if revoked.")
    is_rotated: bool = Field(..., description="True if rotated.")
    is_expired: bool = Field(..., description="True if past expires_at.")


class SourceCredentialIssued(CyberGuardBaseSchema):
    """
    Response when a new credential is issued. **The only time the
    plaintext credential appears** in any API response — the client must
    capture it immediately and never expect to retrieve it again.
    """

    credential_id: uuid.UUID
    source_id: uuid.UUID
    plaintext_credential: str = Field(
        ...,
        description=(
            "Full credential. Shown ONCE at issuance. Store it in the "
            "collector's secure storage immediately. Cannot be retrieved."
        ),
    )
    credential_prefix: str = Field(
        ...,
        description="First 12 chars, for future log identification.",
    )
    expires_at: datetime | None = None


class SourceCredentialRotateRequest(CyberGuardBaseSchema):
    """Request body for credential rotation."""

    description: str | None = Field(
        default=None,
        max_length=500,
        description="Reason or note recorded on the new credential.",
    )


class SourceCredentialRevokeRequest(CyberGuardBaseSchema):
    """Request body for credential revocation."""

    reason: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Why the credential is being revoked. Recorded in audit.",
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecuritySourceCreate",
    "SecuritySourceRead",
    "SecuritySourceList",
    "SecuritySourceUpdate",
    "SecuritySourceFilter",
    "CollectionToggle",
    "SourceCredentialRead",
    "SourceCredentialIssued",
    "SourceCredentialRotateRequest",
    "SourceCredentialRevokeRequest",
]

class CollectorInstallationRead(BaseModel):
    """Read schema for CollectorCredential (installation record)."""
    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        use_enum_values=True,
    )

    id: uuid.UUID
    source_id: uuid.UUID
    collector_id: uuid.UUID
    status: str

    hostname: str | None = None
    os_version: str | None = None
    hardware_fingerprint: str | None = None
    installer_version: str | None = None

    enrolled_at: datetime
    last_heartbeat_at: datetime | None = None
    last_auth_at: datetime | None = None
    last_seen_ip: str | None = None
    last_rotated_at: datetime | None = None
    rotation_count: int = 0

    retired_at: datetime | None = None
    retirement_reason: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    # Computed
    is_active: bool = False
    is_retired: bool = False
    is_revoked: bool = False
