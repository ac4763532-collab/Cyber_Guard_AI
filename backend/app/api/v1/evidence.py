"""
CyberGuard AI — Evidence Endpoints
============================================================================

Evidence upload, download, integrity, redaction, and legal hold.

Two routers exported from this file:
    ``case_evidence_router``  — /api/v1/cases/{case_id}/evidence/*
    ``router``                — /api/v1/evidence/*

Evidence belongs to a case (nested POST + LIST under the case), but
individual evidence operations (get, download, redact, delete) are flat
under `/evidence/{id}` because evidence ID is globally unique.

Multipart upload pattern
------------------------
FastAPI's ``UploadFile`` doesn't mix with Pydantic ``Body`` in the same
request — a ``multipart/form-data`` request can only carry ``File(...)``
and ``Form(...)`` parameters. This router accepts:

    - ``file: UploadFile``          — the binary content
    - ``original_filename: Form``   — client-supplied filename (for display)
    - ``evidence_type: Form``       — enum value
    - ``description: Form``         — optional text
    - ``sensitive: Form``           — optional boolean
    - ``access_grant_scope_required: Form`` — optional scope string

The endpoint constructs an ``EvidenceUploadMetadata`` from these and
passes both it and the read bytes to ``evidence_service.upload_evidence``.

This is the **only** router in the platform that handles multipart. The
same pattern will be reused for message attachments (File 99) and
report uploads (Phase M). Every other endpoint is JSON.

Binary download pattern
-----------------------
``GET /evidence/{id}/download`` returns a ``Response`` with the file
bytes and specific headers:

    Content-Type:            from the evidence row's mime_type
    Content-Disposition:     attachment; filename="..."
    Content-Length:          file size
    X-Content-Hash:          SHA-256 of the file bytes returned
    X-Integrity-Verified:    true / false

The ``X-Integrity-Verified`` header is the crucial signal — when the
file on disk has been tampered with, the response still streams (the
investigator must see what was changed), but the header is `false` and
the frontend shows a red banner.

Filename escaping in Content-Disposition is deliberate: the original
filename may contain quotes, non-ASCII characters, or newlines that
would break HTTP header parsing. We strip and quote-escape before
inserting.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    Query,
    Response,
    UploadFile,
    status,
)
from sqlalchemy import func, select

from app.api.deps import (
    CurrentActiveUser,
    DBDep,
    PageDep,
)
from app.core.exceptions import (
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.case import SecurityCase
from app.models.enums import (
    AccessGrantScope,
    EvidenceType,
)
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.evidence import (
    EvidenceAccessRequest,
    EvidenceFilter,
    EvidenceList,
    EvidenceRead,
    EvidenceRedactionRequest,
    EvidenceUpdate,
    EvidenceUploadMetadata,
)
from app.services import (
    authorization,
    case_service,
    evidence_service,
)


logger = get_logger(__name__)


#: Max upload size, mirrors the service constant (50 MB).
_MAX_UPLOAD_BYTES = 52_428_800


# ============================================================================
# ROUTERS
# ============================================================================

case_evidence_router = APIRouter(
    prefix="/cases",
    tags=["evidence"],
)

router = APIRouter(
    prefix="/evidence",
    tags=["evidence"],
)

@router.get(
    "",
    response_model=PaginatedResponse[EvidenceList],
    summary="List accessible evidence across all cases",
)
def list_all_evidence(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: EvidenceFilter = Depends(),
) -> PaginatedResponse[EvidenceList]:
    from app.models.evidence import Evidence
    from app.models.case import SecurityCase

    accessible_workspaces = authorization.get_user_workspaces(db, current_user)
    stmt = (
        select(Evidence)
        .join(SecurityCase, SecurityCase.id == Evidence.case_id)
        .where(
            Evidence.deleted_at.is_(None),
            (SecurityCase.workspace_id.in_(accessible_workspaces)) | (SecurityCase.assigned_to_user_id == current_user.id)
        )
        .order_by(Evidence.created_at.desc())
    )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.offset(page.offset).limit(page.page_size)).all()
    return PaginatedResponse[EvidenceList](
        items=[EvidenceList.model_validate(e) for e in items],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# INTERNAL — filename escaping for Content-Disposition
# ============================================================================

def _safe_content_disposition(filename: str) -> str:
    """
    Build a Content-Disposition header value that safely embeds the
    filename.

    RFC 6266 rules:
        - Use ``attachment`` disposition
        - ASCII ``filename=`` for legacy clients, with special chars
          replaced by ``_``
        - UTF-8 ``filename*=`` (RFC 5987) for modern clients that
          support it

    Strips quotes, newlines, and other control characters before use.
    """
    # Sanitize for ASCII fallback
    safe_ascii = "".join(
        c if (32 <= ord(c) < 127 and c not in ('"', '\\', ';')) else "_"
        for c in filename
    )
    if not safe_ascii:
        safe_ascii = "evidence"

    # UTF-8 encoding for the RFC 5987 variant
    from urllib.parse import quote
    utf8_encoded = quote(filename, safe="")

    return (
        f'attachment; filename="{safe_ascii}"; '
        f"filename*=UTF-8''{utf8_encoded}"
    )


# ============================================================================
# UPLOAD (multipart) — nested under /cases/{case_id}/evidence
# ============================================================================

@case_evidence_router.post(
    "/{case_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a piece of evidence to a case",
    description=(
        "Multipart upload. The file bytes are validated, SHA-256 hashed, "
        "and written to disk under a UUID-based filename. Requires "
        "`evidence:upload` permission (workspace EDITOR or the assigned "
        "analyst).\n\n"
        "**Max size**: 50 MB.\n"
        "**Allowed extensions**: pdf, txt, log, csv, json, xml, images, "
        "zip, tar, pcap, eml, msg, docx, xlsx, pptx. Executables and "
        "scripts are rejected.\n\n"
        "Returns the created evidence row (without the file bytes — "
        "download separately via GET /evidence/{id}/download)."
    ),
    responses={
        201: {"description": "Evidence uploaded."},
        400: {"description": "Invalid file (extension, size, empty)."},
        403: {"description": "Permission denied."},
        413: {"description": "File exceeds 50 MB."},
        422: {"description": "Metadata validation failed."},
    },
)
async def upload_evidence(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    file: UploadFile = File(
        ...,
        description="The evidence file. Max 50 MB.",
    ),
    original_filename: str = Form(
        ...,
        min_length=1,
        max_length=255,
        description="Client filename for display. The backend generates the stored name.",
    ),
    evidence_type: str = Form(
        default="file",
        description=(
            "file | log_snippet | network_capture | screenshot | "
            "email_artifact | other"
        ),
    ),
    description: str | None = Form(default=None, max_length=5000),
    sensitive: bool = Form(default=False),
    access_grant_scope_required: str = Form(
        default="evidence_read",
        description=(
            "Minimum grant scope required to view this evidence. "
            "Default evidence_read. Sensitive evidence may require "
            "full_case."
        ),
    ),
    tags: list[str] | None = Form(default=None),
) -> EvidenceRead:
    """
    Upload a piece of evidence.

    Reads the file into memory, validates size, parses the enum fields,
    and delegates to ``evidence_service.upload_evidence``.
    """
    # ── Load case + permission check
    case = case_service.get_by_id(db, case_id)

    # ── Parse enums from strings
    try:
        evidence_type_enum = EvidenceType(evidence_type.strip().lower())
    except ValueError:
        raise ValidationError(
            message=(
                f"Invalid evidence_type {evidence_type!r}. "
                f"Allowed: {[e.value for e in EvidenceType]}"
            ),
            code="EVIDENCE_TYPE_INVALID",
        )

    try:
        scope_enum = AccessGrantScope(access_grant_scope_required.strip().lower())
    except ValueError:
        raise ValidationError(
            message=(
                f"Invalid access_grant_scope_required "
                f"{access_grant_scope_required!r}."
            ),
            code="EVIDENCE_SCOPE_INVALID",
        )

    # ── Read bytes (bounded — reject before full read if Content-Length hint)
    file_bytes = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(file_bytes) > _MAX_UPLOAD_BYTES:
        raise ValidationError(
            message=f"File exceeds {_MAX_UPLOAD_BYTES} bytes.",
            code="EVIDENCE_FILE_TOO_LARGE",
        )

    # ── Build metadata DTO
    metadata = EvidenceUploadMetadata(
        original_filename=original_filename,
        evidence_type=evidence_type_enum,
        description=description,
        sensitive=sensitive,
        access_grant_scope_required=scope_enum,
        tags=tags or [],
    )

    evidence = evidence_service.upload_evidence(
        db,
        actor=current_user,
        case=case,
        file_bytes=file_bytes,
        metadata=metadata,
    )
    db.commit()

    logger.info(
        "Evidence uploaded via API",
        extra={
            "evidence_id": str(evidence.id),
            "case_id": str(case.id),
            "file_size_bytes": len(file_bytes),
            "actor_id": str(current_user.id),
        },
    )

    return EvidenceRead.model_validate(evidence)


# ============================================================================
# LIST — nested under /cases/{case_id}/evidence
# ============================================================================

@case_evidence_router.get(
    "/{case_id}/evidence",
    response_model=PaginatedResponse[EvidenceList],
    summary="List evidence attached to a case",
    description=(
        "Paginated list of non-deleted evidence for a case. Requires "
        "at least `CASE_READ` scope. **Does not return the file bytes** "
        "— fetch `GET /evidence/{id}/download` for that."
    ),
)
def list_case_evidence(
    case_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: EvidenceFilter = Depends(),
) -> PaginatedResponse[EvidenceList]:
    case = case_service.get_by_id(db, case_id)
    evidence, total = evidence_service.list_evidence_for_case(
        db,
        actor=current_user,
        case=case,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[EvidenceList](
        items=[EvidenceList.model_validate(e) for e in evidence],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{evidence_id}",
    response_model=EvidenceRead,
    summary="Get evidence detail",
    description=(
        "Full evidence metadata including `chain_of_custody`. Requires "
        "the access scope declared on the evidence row "
        "(`access_grant_scope_required`, typically `evidence_read`)."
    ),
)
def get_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)
    authorization.require_evidence_access(db, current_user, evidence)
    return EvidenceRead.model_validate(evidence)


# ============================================================================
# DOWNLOAD (binary response)
# ============================================================================

@router.get(
    "/{evidence_id}/download",
    summary="Download the evidence file",
    description=(
        "Streams the file bytes. **Verifies the SHA-256 hash on every "
        "download** — if the file on disk has been tampered with, "
        "`X-Integrity-Verified: false` is set and the evidence row is "
        "marked as compromised. The file is still returned (investigators "
        "must see tampered files to investigate the tampering).\n\n"
        "An 'accessed' entry is appended to the chain of custody. The "
        "download is not separately audited — the chain captures it."
    ),
    responses={
        200: {
            "description": "File bytes returned.",
            "headers": {
                "Content-Disposition": {"description": "Attachment filename"},
                "X-Content-Hash": {"description": "SHA-256 of the file bytes"},
                "X-Integrity-Verified": {"description": "true or false"},
            },
        },
        403: {"description": "Access denied or integrity compromised (still returns file)."},
        404: {"description": "Evidence not found."},
    },
)
def download_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> Response:
    evidence = evidence_service.get_by_id(db, evidence_id)

    result = evidence_service.prepare_download(
        db, actor=current_user, evidence=evidence,
    )
    db.commit()

    headers = {
        "Content-Disposition": _safe_content_disposition(result.original_filename),
        "Content-Length": str(len(result.file_bytes)),
        "X-Content-Hash": result.content_hash,
        "X-Integrity-Verified": "true" if result.verified else "false",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    logger.info(
        "Evidence downloaded",
        extra={
            "evidence_id": str(evidence_id),
            "file_size_bytes": len(result.file_bytes),
            "verified": result.verified,
            "actor_id": str(current_user.id),
        },
    )

    return Response(
        content=result.file_bytes,
        media_type=result.mime_type,
        headers=headers,
    )


# ============================================================================
# ACCESS RECORDING (metadata-only)
# ============================================================================

@router.post(
    "/{evidence_id}/access",
    response_model=EvidenceRead,
    summary="Record an access event without downloading",
    description=(
        "Appends an 'accessed' entry to the chain of custody. Used when "
        "the user opens the evidence metadata in the UI (before the "
        "actual file download). Records intent, not content."
    ),
)
def record_evidence_access(
    evidence_id: uuid.UUID,
    body: EvidenceAccessRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)
    updated = evidence_service.record_access(
        db,
        actor=current_user,
        evidence=evidence,
        notes=body.notes,
    )
    db.commit()
    return EvidenceRead.model_validate(updated)


# ============================================================================
# MANUAL INTEGRITY CHECK
# ============================================================================

@router.post(
    "/{evidence_id}/verify",
    response_model=EvidenceRead,
    summary="Manually verify evidence integrity",
    description=(
        "Re-computes the SHA-256 hash of the file on disk and compares "
        "it with the stored `content_hash`. Records the result in the "
        "chain of custody. If the check fails, the evidence is marked "
        "compromised (`integrity_verified=False`) and a `FAILURE`-outcome "
        "audit row is written.\n\n"
        "Typically triggered by an admin from a 'verify integrity' button."
    ),
)
def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    notes: str | None = Body(default=None, embed=True, max_length=500),
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)

    # Read the file to check integrity
    path = evidence.get_storage_path()
    if not path.exists() or not path.is_file():
        raise NotFoundError(
            message="Evidence file not found on disk.",
            code="EVIDENCE_FILE_MISSING",
        )

    import hashlib
    computed = hashlib.sha256(path.read_bytes()).hexdigest()
    passed = computed == evidence.content_hash

    updated = evidence_service.record_integrity_check(
        db,
        actor=current_user,
        evidence=evidence,
        passed=passed,
        notes=notes,
    )
    db.commit()
    return EvidenceRead.model_validate(updated)


# ============================================================================
# UPDATE (metadata)
# ============================================================================

@router.patch(
    "/{evidence_id}",
    response_model=EvidenceRead,
    summary="Update evidence metadata",
    description=(
        "Update description, tags, sensitive flag, or required access "
        "scope. Requires `FULL_CASE` scope. Cannot change the file "
        "content — use redaction for that."
    ),
)
def update_evidence(
    evidence_id: uuid.UUID,
    body: EvidenceUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)

    # Full-case scope required
    case = db.get(SecurityCase, evidence.case_id)
    if case is None:
        raise NotFoundError(
            message="Case for this evidence no longer exists.",
            code="CASE_NOT_FOUND",
        )
    authorization.require_case_access(
        db, current_user, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    updates = body.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(evidence, field, value)
    db.flush()
    db.commit()
    return EvidenceRead.model_validate(evidence)


# ============================================================================
# REDACTION
# ============================================================================

@router.post(
    "/{evidence_id}/redact",
    response_model=EvidenceRead,
    summary="Replace evidence content with a redacted version",
    description=(
        "**Not a partial update** — this replaces the file content. The "
        "original is moved to `{stored}.original` on disk, the redacted "
        "content takes the canonical filename, `content_hash` is updated "
        "to the redacted hash, and `original_content_hash` preserves the "
        "pre-redaction hash.\n\n"
        "Caller must supply the redacted bytes (either from an external "
        "redaction tool or as a multipart file). Requires `FULL_CASE` "
        "scope. Rejected if the evidence is already redacted or if the "
        "current file's integrity check fails (can't redact a file that "
        "was already tampered with)."
    ),
)
async def redact_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    redaction_notes: str = Form(
        ...,
        min_length=1,
        max_length=2000,
        description="Which fields were redacted and how.",
    ),
    redacted_file: UploadFile = File(
        ...,
        description="The redacted content (same format as the original).",
    ),
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)

    redacted_bytes = await redacted_file.read(_MAX_UPLOAD_BYTES + 1)
    if len(redacted_bytes) > _MAX_UPLOAD_BYTES:
        raise ValidationError(
            message=f"Redacted file exceeds {_MAX_UPLOAD_BYTES} bytes.",
            code="EVIDENCE_REDACTED_FILE_TOO_LARGE",
        )

    updated = evidence_service.redact_evidence(
        db,
        actor=current_user,
        evidence=evidence,
        redacted_bytes=redacted_bytes,
        redaction_notes=redaction_notes,
    )
    db.commit()
    return EvidenceRead.model_validate(updated)


# ============================================================================
# DELETE (soft)
# ============================================================================

@router.delete(
    "/{evidence_id}",
    response_model=MessageResponse,
    summary="Soft-delete evidence",
    description=(
        "Marks the evidence as deleted. The row stays in the DB and the "
        "file stays on disk (needed for retention and legal hold). Hard "
        "deletion happens via retention cleanup after the retention "
        "window. Requires `FULL_CASE` scope."
    ),
)
def delete_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> MessageResponse:
    evidence = evidence_service.get_by_id(db, evidence_id)
    evidence_service.delete_evidence(
        db,
        actor=current_user,
        evidence=evidence,
        reason=reason,
    )
    db.commit()
    return MessageResponse(message="Evidence marked for deletion.")
def delete_evidence(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> MessageResponse:
    """Soft-delete evidence."""
    evidence = evidence_service.get_by_id(db, evidence_id)
    evidence_service.delete_evidence(
        db,
        actor=current_user,
        evidence=evidence,
        reason=reason,
    )
    db.commit()
    return MessageResponse(message="Evidence marked for deletion.")


# ============================================================================
# LEGAL HOLD
# ============================================================================

@router.post(
    "/{evidence_id}/legal-hold",
    response_model=EvidenceRead,
    summary="Apply a legal hold",
    description=(
        "Prevents retention cleanup from deleting this evidence. Requires "
        "workspace OWNER or platform super admin. The `until` timestamp "
        "must be in the future."
    ),
)
def apply_legal_hold(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    until: datetime = Body(embed=True),
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)
    updated = evidence_service.apply_legal_hold(
        db,
        actor=current_user,
        evidence=evidence,
        until=until,
        reason=reason,
    )
    db.commit()
    return EvidenceRead.model_validate(updated)


@router.post(
    "/{evidence_id}/release-legal-hold",
    response_model=EvidenceRead,
    summary="Release a legal hold",
    description=(
        "Clears the legal hold. Same permission model as applying one "
        "(workspace OWNER or platform super admin)."
    ),
)
def release_legal_hold(
    evidence_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> EvidenceRead:
    evidence = evidence_service.get_by_id(db, evidence_id)
    updated = evidence_service.release_legal_hold(
        db,
        actor=current_user,
        evidence=evidence,
        reason=reason,
    )
    db.commit()
    return EvidenceRead.model_validate(updated)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router", "case_evidence_router"]