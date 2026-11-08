"""
CyberGuard AI — Security Source Endpoints
============================================================================

HTTP endpoints for source management: registration, lifecycle, enrollment
tokens, credential rotation, and installation tracking.

Two routers exported from this file:
    ``workspace_sources_router``  — /api/v1/workspaces/{ws_id}/sources
    ``router``                    — /api/v1/sources/*

Source creation is nested under the workspace path because a source
belongs to a workspace. Everything else is flat at ``/sources/{id}``
because source ID is globally unique.

The 5 connection indicators
---------------------------
``SecuritySourceRead`` includes all 5:
    collector_connected, last_heartbeat_at, collection_active,
    last_event_at, agent_processing_healthy

Plus a computed ``display_status`` that collapses them into the 7 UI
states from the interaction document. The frontend renders this
string; the backend owns the collapse logic so no client ever has to
reimplement it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, status
from pydantic import BaseModel, ConfigDict

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models.source import SourceCredential
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenIssued,
    EnrollmentTokenRead,
    EnrollmentTokenRevokeRequest,
)
from app.schemas.source import (
    CollectorInstallationRead,
    CollectionToggle,
    SecuritySourceCreate,
    SecuritySourceFilter,
    SecuritySourceList,
    SecuritySourceRead,
    SecuritySourceUpdate,
    SourceCredentialIssued,
    SourceCredentialRead,
    SourceCredentialRevokeRequest,
    SourceCredentialRotateRequest,
)
from app.services import (
    collector_credential_service,
    enrollment_service,
    source_service,
    workspace_service,
)


logger = get_logger(__name__)


# ============================================================================
# ROUTERS
# ============================================================================

workspace_sources_router = APIRouter(
    prefix="/workspaces",
    tags=["sources"],
)

router = APIRouter(
    prefix="/sources",
    tags=["sources"],
)


# ============================================================================
# SOURCE CREATION (nested under workspace)
# ============================================================================

@workspace_sources_router.post(
    "/{workspace_id}/sources",
    response_model=SecuritySourceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a security source in a workspace",
    description=(
        "Creates a source in PENDING_ENROLLMENT status. To activate, "
        "issue an enrollment token, run the collector on the device, "
        "and let the collector redeem the token."
    ),
)
def create_source(
    workspace_id: uuid.UUID,
    body: SecuritySourceCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> SecuritySourceRead:
    ws = workspace_service.get_by_id(db, workspace_id)
    source = source_service.create_source(
        db, actor=current_user, workspace=ws, payload=body,
    )
    db.commit()
    return SecuritySourceRead.model_validate(source)


@workspace_sources_router.get(
    "/{workspace_id}/sources",
    response_model=PaginatedResponse[SecuritySourceList],
    summary="List sources in a workspace",
)
def list_workspace_sources(
    workspace_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: SecuritySourceFilter = Depends(),
) -> PaginatedResponse[SecuritySourceList]:
    ws = workspace_service.get_by_id(db, workspace_id)
    sources, total = source_service.list_by_workspace(
        db, actor=current_user, workspace=ws, page=page, filters=filters,
    )
    return PaginatedResponse[SecuritySourceList](
        items=[SecuritySourceList.model_validate(s) for s in sources],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# SOURCE READ
# ============================================================================

@router.get(
    "/{source_id}",
    response_model=SecuritySourceRead,
    summary="Get a source by ID",
    description=(
        "Returns the full source including all 5 connection indicators "
        "and a computed `display_status` string for UI rendering."
    ),
)
def get_source(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    # Access check happens via workspace membership
    from app.services import authorization
    authorization.require_workspace_member(
        db, current_user, source.workspace_id,
    )
    return SecuritySourceRead.model_validate(source)


# ============================================================================
# SOURCE UPDATE
# ============================================================================

@router.patch(
    "/{source_id}",
    response_model=SecuritySourceRead,
    summary="Update a source",
    description=(
        "Update name, description, config, or capabilities. Cannot "
        "change status or connection indicators through this endpoint."
    ),
)
def update_source(
    source_id: uuid.UUID,
    body: SecuritySourceUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    updated = source_service.update_source(
        db, actor=current_user, source=source, payload=body,
    )
    db.commit()
    return SecuritySourceRead.model_validate(updated)


# ============================================================================
# COLLECTION TOGGLE
# ============================================================================

@router.post(
    "/{source_id}/collection",
    response_model=SecuritySourceRead,
    summary="Enable or disable event collection for a source",
    description=(
        "Toggles `collection_active`. When disabled, the collector keeps "
        "heartbeating (proving liveness) but events are rejected. This is "
        "the 'pause monitoring temporarily' workflow — NOT the same as "
        "disabling or revoking the source."
    ),
)
def toggle_collection(
    source_id: uuid.UUID,
    body: CollectionToggle,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    if body.active:
        updated = source_service.enable_collection(
            db, actor=current_user, source=source, reason=body.reason,
        )
    else:
        updated = source_service.disable_collection(
            db, actor=current_user, source=source, reason=body.reason,
        )
    db.commit()
    return SecuritySourceRead.model_validate(updated)


# ============================================================================
# LIFECYCLE — disable / re-enable / revoke
# ============================================================================

@router.post(
    "/{source_id}/disable",
    response_model=SecuritySourceRead,
    summary="Administratively disable a source",
    description=(
        "Sets status to DISABLED. The collector may still heartbeat, "
        "but events are rejected. Requires PERM_SOURCE_DISABLE."
    ),
)
def disable_source(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    updated = source_service.disable_source(
        db, actor=current_user, source=source, reason=reason,
    )
    db.commit()
    return SecuritySourceRead.model_validate(updated)


@router.post(
    "/{source_id}/re-enable",
    response_model=SecuritySourceRead,
    summary="Re-enable a disabled source",
)
def re_enable_source(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    updated = source_service.re_enable_source(
        db, actor=current_user, source=source,
    )
    db.commit()
    return SecuritySourceRead.model_validate(updated)


@router.post(
    "/{source_id}/revoke",
    response_model=SecuritySourceRead,
    summary="Permanently revoke a source",
    description=(
        "Terminal action. The source cannot be re-enabled. To restore "
        "monitoring for the same device, create a new source and "
        "re-enroll the collector."
    ),
)
def revoke_source(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: Annotated[str, Body(embed=True, min_length=1, max_length=500)],
) -> SecuritySourceRead:
    source = source_service.get_by_id(db, source_id)
    updated = source_service.revoke_source(
        db, actor=current_user, source=source, reason=reason,
    )
    db.commit()
    return SecuritySourceRead.model_validate(updated)


# ============================================================================
# ENROLLMENT TOKENS
# ============================================================================

@router.post(
    "/{source_id}/enrollment-tokens",
    response_model=EnrollmentTokenIssued,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a new enrollment token",
    description=(
        "Issues a short-lived token for a source in PENDING_ENROLLMENT "
        "status. **The plaintext token is returned exactly once** — the "
        "caller must display it to the user immediately (copy button, "
        "QR code, etc.). It cannot be retrieved later."
    ),
)
def issue_enrollment_token(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    body: EnrollmentTokenCreate | None = None,
) -> EnrollmentTokenIssued:
    source = source_service.get_by_id(db, source_id)
    ttl = body.ttl_minutes if body else None

    enrollment, plaintext = enrollment_service.create_enrollment_token(
        db, actor=current_user, source=source, ttl_minutes=ttl,
    )
    db.commit()

    return EnrollmentTokenIssued(
        enrollment_id=enrollment.id,
        source_id=source.id,
        plaintext_token=plaintext,
        token_prefix=enrollment.token_prefix,
        expires_at=enrollment.expires_at,
        seconds_until_expiry=enrollment.seconds_until_expiry,
    )


@router.get(
    "/{source_id}/enrollment-tokens",
    response_model=PaginatedResponse[EnrollmentTokenRead],
    summary="List enrollment tokens for a source",
)
def list_enrollment_tokens(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_redeemed: bool = Query(default=False),
) -> PaginatedResponse[EnrollmentTokenRead]:
    source = source_service.get_by_id(db, source_id)
    tokens, total = enrollment_service.list_tokens_for_source(
        db,
        actor=current_user,
        source=source,
        page=page,
        include_redeemed=include_redeemed,
    )
    return PaginatedResponse[EnrollmentTokenRead](
        items=[EnrollmentTokenRead.model_validate(t) for t in tokens],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{source_id}/enrollment-tokens/{token_id}/revoke",
    response_model=MessageResponse,
    summary="Revoke a pending enrollment token",
)
def revoke_enrollment_token(
    source_id: uuid.UUID,
    token_id: uuid.UUID,
    body: EnrollmentTokenRevokeRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageResponse:
    from app.models.enrollment import SourceEnrollment
    token = db.get(SourceEnrollment, token_id)
    if token is None or token.source_id != source_id:
        raise NotFoundError(
            message="Enrollment token not found.",
            code="ENROLLMENT_NOT_FOUND",
        )

    enrollment_service.revoke_token(
        db,
        actor=current_user,
        token=token,
        reason=body.reason,
    )
    db.commit()
    return MessageResponse(message="Enrollment token revoked.")


# ============================================================================
# CREDENTIALS
# ============================================================================

@router.get(
    "/{source_id}/credentials",
    response_model=PaginatedResponse[SourceCredentialRead],
    summary="List credentials for a source",
)
def list_source_credentials(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_inactive: bool = Query(default=False),
) -> PaginatedResponse[SourceCredentialRead]:
    source = source_service.get_by_id(db, source_id)
    creds, total = collector_credential_service.list_credentials_for_source(
        db,
        actor=current_user,
        source=source,
        page=page,
        include_inactive=include_inactive,
    )
    return PaginatedResponse[SourceCredentialRead](
        items=[SourceCredentialRead.model_validate(c) for c in creds],
        meta=PageMeta.build(total=total, params=page),
    )


@router.post(
    "/{source_id}/credentials/{credential_id}/rotate",
    response_model=SourceCredentialIssued,
    summary="Rotate a credential",
    description=(
        "Issues a new credential and marks the old one as ROTATED. The "
        "**plaintext of the new credential** is returned exactly once — "
        "the collector must save it and use it for subsequent requests. "
        "The old credential stops working immediately."
    ),
)
def rotate_credential(
    source_id: uuid.UUID,
    credential_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    body: SourceCredentialRotateRequest | None = None,
) -> SourceCredentialIssued:
    # Load the source (permission check happens via workspace)
    source = source_service.get_by_id(db, source_id)

    credential = db.get(SourceCredential, credential_id)
    if credential is None or credential.source_id != source_id:
        raise NotFoundError(
            message="Credential not found.",
            code="CREDENTIAL_NOT_FOUND",
        )

    issued = collector_credential_service.rotate_credential(
        db,
        actor=current_user,
        credential=credential,
        reason=body.description if body else None,
    )
    db.commit()

    return SourceCredentialIssued(
        credential_id=issued.credential_id,
        source_id=source.id,
        plaintext_credential=issued.plaintext_credential,
        credential_prefix=issued.credential_prefix,
        expires_at=issued.expires_at,
    )


@router.post(
    "/{source_id}/credentials/{credential_id}/revoke",
    response_model=MessageResponse,
    summary="Revoke a single credential",
    description=(
        "Revokes one credential without affecting other credentials on "
        "the same installation. Use this when a specific token is "
        "compromised but the device is otherwise healthy. To revoke "
        "everything on a device, revoke the installation instead."
    ),
)
def revoke_credential(
    source_id: uuid.UUID,
    credential_id: uuid.UUID,
    body: SourceCredentialRevokeRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> MessageResponse:
    credential = db.get(SourceCredential, credential_id)
    if credential is None or credential.source_id != source_id:
        raise NotFoundError(
            message="Credential not found.",
            code="CREDENTIAL_NOT_FOUND",
        )

    collector_credential_service.revoke_credential(
        db,
        actor=current_user,
        credential=credential,
        reason=body.reason,
    )
    db.commit()
    return MessageResponse(message="Credential revoked.")


# ============================================================================
# INSTALLATIONS
# ============================================================================

@router.get(
    "/{source_id}/installations",
    response_model=PaginatedResponse[CollectorInstallationRead],
    summary="List collector installations for a source",
    description=(
        "Returns one row per physical collector install. An installation "
        "can have multiple credentials over its lifetime (rotation), and "
        "a source can have multiple installations (reinstalls)."
    ),
)
def list_installations(
    source_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    include_inactive: bool = Query(default=False),
) -> PaginatedResponse[CollectorInstallationRead]:
    source = source_service.get_by_id(db, source_id)
    installations, total = collector_credential_service.list_installations_for_source(
        db,
        actor=current_user,
        source=source,
        page=page,
        include_inactive=include_inactive,
    )
    return PaginatedResponse[CollectorInstallationRead](
        items=[
            CollectorInstallationRead.model_validate(i) for i in installations
        ],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# INLINE SCHEMA — CollectorInstallationRead
# ============================================================================
# Belongs in app/schemas/collector_credential.py — extracted in cleanup
# pass. Until then, defined inline so this router is self-contained.

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


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "workspace_sources_router"]