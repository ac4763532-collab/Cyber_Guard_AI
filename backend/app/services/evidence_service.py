"""
CyberGuard AI — Evidence Service
============================================================================

The evidence lifecycle: upload, storage, integrity verification, chain
of custody, download, redaction, and deletion.

Evidence is the most sensitive part of a case. Every file that lands
here must be:

    - **Integrity-protected**: SHA-256 hash computed at upload, verified
      on every access. A mismatch is a security event, not a bug.
    - **Chain-of-custody-tracked**: every access, verify, redaction, and
      export is recorded in an append-only audit trail.
    - **Access-controlled**: viewing evidence requires at least
      ``EVIDENCE_READ`` scope on the case (enforced by authorization).
      Sensitive evidence may require ``FULL_CASE``.
    - **Retention-controlled**: two-phase deletion. User delete →
      soft-delete immediately. Background job → hard-delete after
      retention window, respecting legal hold.

File storage
------------
Files are stored on disk at::

    {UPLOAD_DIR}/evidence/{workspace_id}/{case_id}/{stored_filename}

    ``stored_filename`` = ``<uuid>.<ext>`` — never the client's filename.
    This prevents path traversal, filename collisions, and unicode
    homograph attacks.

The path is computed by ``SecurityEvidence.get_storage_path()``, so the
storage backend can be swapped (S3, GCS) by changing one method — no
data migration needed.

Integrity verification model
----------------------------
Every read (download, preview, agent processing) re-computes the
SHA-256 of the file bytes on disk and compares to ``content_hash``:

    Match   → proceed normally
    Mismatch → mark ``integrity_verified=False``, log at WARNING,
               audit, **still return the file**

The last point is deliberate. If evidence has been tampered with,
the investigator needs to see *what* was tampered. Refusing access
hides the tampering. The UI shows a red banner: "This file has
failed integrity verification — do not trust its contents."

The audit trail records the mismatch, and the case is flagged for
human review.

Chain of custody
----------------
An append-only list in ``chain_of_custody`` JSONB:

    [
        {"at": "...", "action": "uploaded", "by_user_id": "...", "notes": "..."},
        {"at": "...", "action": "accessed", "by_user_id": "...", "ip_address": "..."},
        {"at": "...", "action": "verified", "notes": "SHA-256 confirmed"},
        {"at": "...", "action": "exported", "by_user_id": "...", "notes": "..."},
        {"at": "...", "action": "integrity_failed", "notes": "..."},
        {"at": "...", "action": "redacted", "by_user_id": "...", "notes": "..."},
    ]

Every action goes through ``_append_custody`` on the model. The service
never modifies prior entries — history is immutable.

Upload flow
-----------
    Endpoint (multipart/form-data):
        1. Reads UploadFile to bytes (or streams to disk in chunks)
        2. Validates metadata via EvidenceUploadMetadata
        3. Calls ``upload_evidence(db, actor, case, file_bytes, metadata)``
        4. Returns EvidenceRead

    Service:
        1. Validate extension against allow-list (schema already did this)
        2. Validate size cap
        3. Compute SHA-256
        4. Generate UUID-based stored_filename
        5. Write file to disk
        6. Create SecurityEvidence row (build() initializes chain)
        7. Audit: EVIDENCE_UPLOADED
        8. Return evidence

The upload is transactional in the DB sense, but the file write is not.
If the DB write fails after the file write, an orphan file is left on
disk. A background job (retention sweep) cleans these up by comparing
disk contents against DB rows — documented in the retention job, not
implemented in this service.

Download flow
-------------
    Endpoint calls ``prepare_download(db, actor, evidence)``:
        1. Verify case access (via authorization.require_evidence_access)
        2. Read file from disk
        3. Compute SHA-256
        4. Compare with stored hash
        5. On mismatch: mark compromised, audit, log WARNING
        6. Record "accessed" in chain
        7. Return (file_bytes, verified_bool, mime_type)

    Endpoint streams the bytes back to the client.

The service returns bytes, not a StreamingResponse — the endpoint owns
the response format. This keeps the service HTTP-agnostic (consistent
with the rest of the service layer).

Redaction flow
--------------
    ``redact_evidence``:
        1. Caller passes the redacted bytes (either from an external
           redaction tool, or from the service's own PII detection)
        2. Verify original hash (prove the file being redacted is
           the file we think it is)
        3. Move original to cold storage (``.original`` file)
        4. Write redacted content to ``stored_filename``
        5. Compute redacted hash, set as new ``content_hash``
        6. Preserve ``original_content_hash``
        7. Set ``redacted_at``, ``redacted_by_id``, ``redaction_notes``
        8. Append "redacted" to chain
        9. Audit

Two-phase deletion
------------------
    Soft delete (user action):
        - ``deleted_at`` set, excluded from queries
        - File on disk stays (needed for retention/legal hold)
        - Audited

    Hard delete (background job):
        - Only after retention window (``RETENTION_EVIDENCE_DAYS``)
        - Only if NOT under legal hold
        - Removes DB row AND file from disk
        - Audited via system actor

``delete_evidence(db, actor, evidence, reason)`` — the soft-delete entry point.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances (and file bytes for download).
4. Audit uploads, deletions, redactions, downloads with integrity
   failures. Do NOT audit every successful download — that would
   flood the log; the chain of custody captures each access.

Public API
----------
    upload_evidence(db, *, actor, case, file_bytes, metadata, request=None)
        → SecurityEvidence
    get_by_id(db, evidence_id)                            → SecurityEvidence
    list_evidence_for_case(db, *, actor, case, page, filters)
                                                          → (list, int)
    prepare_download(db, *, actor, evidence, request=None)
        → DownloadResult
    record_access(db, *, actor, evidence, notes=None, request=None)
                                                          → SecurityEvidence
    record_integrity_check(db, *, actor, evidence, passed, notes=None, ...)
                                                          → SecurityEvidence
    redact_evidence(db, *, actor, evidence, redacted_bytes, redaction_notes,
                    request=None)                         → SecurityEvidence
    delete_evidence(db, *, actor, evidence, reason, request=None)
                                                          → SecurityEvidence
    apply_legal_hold(db, *, actor, evidence, until, reason, request=None)
                                                          → SecurityEvidence
    release_legal_hold(db, *, actor, evidence, reason, request=None)
                                                          → SecurityEvidence

Usage
-----
    from app.services import evidence_service

    # In an upload endpoint:
    file_bytes = await upload_file.read()
    evidence = evidence_service.upload_evidence(
        db,
        actor=current_user,
        case=case,
        file_bytes=file_bytes,
        metadata=EvidenceUploadMetadata(
            original_filename=upload_file.filename,
            evidence_type=EvidenceType.EMAIL_ARTIFACT,
            description="Suspicious email received by alice",
            event_ids=[event.id],
        ),
        request=request,
    )
    db.commit()

    # In a download endpoint:
    result = evidence_service.prepare_download(
        db, actor=current_user, evidence=evidence, request=request,
    )
    db.commit()
    return Response(content=result.file_bytes, media_type=result.mime_type)
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthorizationError,
    CaseNotFoundError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.case import SecurityCase
from app.models.enums import AccessGrantScope, EvidenceType
from app.models.evidence import SecurityEvidence
from app.models.user import User
from app.schemas.common import PageParams
from app.schemas.evidence import EvidenceFilter, EvidenceUploadMetadata
from app.services import (
    audit_service,
    authorization,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Allowed file extensions. Must match the model's CHECK constraint.
_ALLOWED_EXTENSIONS = frozenset({
    ".pdf", ".txt", ".log", ".csv", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".zip", ".gz", ".tar",
    ".pcap", ".pcapng", ".eml", ".msg",
    ".docx", ".xlsx", ".pptx",
})

_DENIED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".sh",
    ".msi", ".scr", ".vbs", ".jar", ".com", ".app",
    ".php", ".phtml", ".jsp", ".asp", ".aspx", ".cgi",
    ".py", ".rb", ".pl", ".js",
})

_MAX_FILE_SIZE_BYTES = 52_428_800  # 50 MB — matches model CHECK


# ============================================================================
# RESULT DTYPES
# ============================================================================

@dataclass(frozen=True)
class DownloadResult:
    """Result of ``prepare_download`` — everything the endpoint needs."""
    file_bytes: bytes
    mime_type: str
    content_hash: str
    verified: bool
    original_filename: str


# ============================================================================
# INTERNAL — file operations
# ============================================================================

def _compute_sha256(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def _generate_stored_filename(extension: str) -> str:
    """
    Generate a UUID-based stored filename.

    Format: ``<uuid4-hex>.<ext>``. No underscores, no dots beyond the
    extension separator, no unicode. Safe for filesystems, S3 keys, and
    URLs.

    The 128-bit UUID4 namespace makes collisions impossible in practice.
    """
    ext = extension.lower().lstrip(".")
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex


def _validate_extension(original_filename: str) -> str:
    """
    Validate the extension against the allow-list and return the
    normalized extension (with leading dot).

    Raises ``ValidationError`` on:
        - Empty filename
        - Filename with path separators
        - Missing extension
        - Extension in ``_DENIED_EXTENSIONS``
        - Extension not in ``_ALLOWED_EXTENSIONS``
    """
    if not original_filename or not original_filename.strip():
        raise ValidationError(
            message="original_filename is required.",
            code="EVIDENCE_FILENAME_REQUIRED",
        )
    if "/" in original_filename or "\\" in original_filename:
        raise ValidationError(
            message="original_filename must not contain path separators.",
            code="EVIDENCE_FILENAME_INVALID",
        )
    if "." not in original_filename:
        raise ValidationError(
            message="Filename must have an extension.",
            code="EVIDENCE_EXTENSION_REQUIRED",
        )

    ext = "." + original_filename.rsplit(".", 1)[1].lower()

    if ext in _DENIED_EXTENSIONS:
        raise ValidationError(
            message=f"File extension {ext!r} is not permitted.",
            code="EVIDENCE_EXTENSION_DENIED",
            details={"extension": ext},
        )
    if ext not in _ALLOWED_EXTENSIONS:
        raise ValidationError(
            message=(
                f"File extension {ext!r} is not in the allowed set. "
                f"Allowed: {sorted(_ALLOWED_EXTENSIONS)}"
            ),
            code="EVIDENCE_EXTENSION_NOT_ALLOWED",
            details={"extension": ext, "allowed": sorted(_ALLOWED_EXTENSIONS)},
        )
    return ext


def _ensure_storage_dir(evidence: SecurityEvidence) -> Path:
    """
    Ensure the directory for this evidence exists, then return the
    full path where the file should be written.
    """
    path = evidence.get_storage_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _write_file(path: Path, data: bytes) -> None:
    """
    Write bytes to disk atomically.

    Writes to a ``.tmp`` file first, then renames — so a partial write
    never leaves a corrupt evidence file at the canonical path.
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    tmp_path.replace(path)


def _read_file(path: Path) -> bytes:
    """Read the file at the given path. Raises if missing."""
    if not path.exists() or not path.is_file():
        raise NotFoundError(
            message=f"Evidence file not found on disk: {path.name}",
            code="EVIDENCE_FILE_MISSING",
            details={"path": str(path.name)},
        )
    return path.read_bytes()


def _mime_from_extension(extension: str) -> str:
    """Return a best-guess MIME type from the file extension."""
    _MIME_MAP = {
        ".pdf": "application/pdf",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".csv": "text/csv",
        ".json": "application/json",
        ".xml": "application/xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".zip": "application/zip",
        ".gz": "application/gzip",
        ".tar": "application/x-tar",
        ".pcap": "application/vnd.tcpdump.pcap",
        ".pcapng": "application/x-pcapng",
        ".eml": "message/rfc822",
        ".msg": "application/vnd.ms-outlook",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
    return _MIME_MAP.get(extension.lower(), "application/octet-stream")


# ============================================================================
# INTERNAL — access check
# ============================================================================

def _require_evidence_access(
    db: Session,
    actor: User,
    evidence: SecurityEvidence,
    case: SecurityCase | None = None,
) -> None:
    """
    Verify the actor can access this evidence at the required scope.

    Delegates to ``authorization.require_evidence_access``, which
    enforces:
        - Case access at ``access_grant_scope_required`` (default
          ``EVIDENCE_READ``, may be ``FULL_CASE`` for sensitive
          evidence)
        - Handles assigned analyst / workspace role / active grant
          resolution
    """
    if case is None:
        case = db.get(SecurityCase, evidence.case_id)
        if case is None:
            raise CaseNotFoundError(
                message="The case for this evidence no longer exists.",
                details={"case_id": str(evidence.case_id)},
            )

    authorization.require_evidence_access(
        db, actor, evidence, case=case,
    )


# ============================================================================
# UPLOAD
# ============================================================================

def upload_evidence(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    file_bytes: bytes,
    metadata: EvidenceUploadMetadata,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Upload a new piece of evidence.

    Validates size, extension, and access. Computes SHA-256. Writes
    the file to disk. Creates the ``SecurityEvidence`` row with chain
    of custody initialized to ``[{"action": "uploaded"}]``.

    Access
    ------
    Requires ``EVIDENCE_UPLOAD`` permission — which for workspace
    members means they must have role that grants it (admin/analyst),
    OR they're the assigned analyst on the case.

    Size and type
    -------------
    - Max size: 50 MB (matches model CHECK constraint)
    - Extension: allow-listed (rejects exe/dll/sh and similar)
    - Filename: path separators rejected (schema-layer, repeated here
      as defense in depth)

    Returns
    -------
    SecurityEvidence
        The persisted evidence row with chain-of-custody initialized.

    Raises
    ------
    AuthorizationError
        If the actor cannot upload to this case.
    ValidationError
        If the file fails validation.
    """
    # ── 1. Access check
    authorization.check_permission(
        db, actor, "evidence:upload", workspace_id=case.workspace_id,
    )

    # If not workspace member, must be assigned analyst or have full_case grant
    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    if ws_role is None and case.assigned_to_id != actor.id:
        # Non-member non-assigned — must have full_case grant
        has_full = authorization.has_permission(
            db, actor, "evidence:upload", case=case,
        )
        if not has_full:
            raise AuthorizationError(
                message=(
                    "You do not have permission to upload evidence to "
                    "this case."
                ),
                code="EVIDENCE_UPLOAD_DENIED",
            )

    # ── 2. Validate the bytes
    if not file_bytes:
        raise ValidationError(
            message="File content is empty.",
            code="EVIDENCE_FILE_EMPTY",
        )
    if len(file_bytes) > _MAX_FILE_SIZE_BYTES:
        raise ValidationError(
            message=(
                f"File exceeds {_MAX_FILE_SIZE_BYTES} bytes "
                f"(got {len(file_bytes)})."
            ),
            code="EVIDENCE_FILE_TOO_LARGE",
            details={
                "max_bytes": _MAX_FILE_SIZE_BYTES,
                "actual_bytes": len(file_bytes),
            },
        )

    extension = _validate_extension(metadata.original_filename)
    content_hash = _compute_sha256(file_bytes)
    stored_filename = _generate_stored_filename(extension)

    # ── 3. Build the row (chain initialized to "uploaded")
    evidence = SecurityEvidence.build(
        workspace_id=case.workspace_id,
        case_id=case.id,
        original_filename=metadata.original_filename,
        stored_filename=stored_filename,
        content_hash=content_hash,
        file_size_bytes=len(file_bytes),
        evidence_type=metadata.evidence_type,
        uploaded_by_id=actor.id,
        description=metadata.description,
        mime_type=_mime_from_extension(extension),
        event_ids=[str(eid) for eid in (metadata.event_ids or [])],
        finding_ids=[str(fid) for fid in (metadata.finding_ids or [])],
        tags=metadata.tags or [],
        metadata={"source": "manual_upload"},
        sensitive=metadata.sensitive,
        access_grant_scope_required=metadata.access_grant_scope_required,
    )

    # ── 4. Write file to disk
    storage_path = _ensure_storage_dir(evidence)
    try:
        _write_file(storage_path, file_bytes)
    except OSError as exc:
        raise ValidationError(
            message=f"Failed to write file to storage: {exc}",
            code="EVIDENCE_STORAGE_ERROR",
        )

    # ── 5. Persist DB row
    db.add(evidence)
    db.flush()

    # ── 6. Audit
    audit_service.log_evidence_uploaded(
        db,
        user=actor,
        evidence_id=evidence.id,
        case_id=case.id,
        workspace_id=case.workspace_id,
        file_name=metadata.original_filename,
        file_size_bytes=len(file_bytes),
        request=request,
    )

    logger.info(
        "Evidence uploaded",
        extra={
            "evidence_id": str(evidence.id),
            "case_id": str(case.id),
            "file_size_bytes": len(file_bytes),
            "content_hash_prefix": content_hash[:12],
        },
    )

    return evidence


# ============================================================================
# READ
# ============================================================================

def get_by_id(db: Session, evidence_id: uuid.UUID) -> SecurityEvidence:
    """Fetch an evidence row. Does NOT check access — caller must."""
    evidence = db.get(SecurityEvidence, evidence_id)
    if evidence is None or evidence.deleted_at is not None:
        raise NotFoundError(
            message=f"Evidence {evidence_id} not found.",
            code="EVIDENCE_NOT_FOUND",
            details={"evidence_id": str(evidence_id)},
        )
    return evidence


def list_evidence_for_case(
    db: Session,
    *,
    actor: User,
    case: SecurityCase,
    page: PageParams,
    filters: EvidenceFilter | None = None,
) -> tuple[list[SecurityEvidence], int]:
    """
    List non-deleted evidence for a case.

    Requires at least ``CASE_READ`` scope on the case — this only
    returns metadata (filename, size, hash), not the file bytes.
    Actual file access requires ``EVIDENCE_READ``.
    """
    authorization.require_case_access(
        db, actor, case, minimum_scope=AccessGrantScope.CASE_READ,
    )

    stmt = select(SecurityEvidence).where(
        SecurityEvidence.case_id == case.id,
        SecurityEvidence.deleted_at.is_(None),
    )

    if filters is not None:
        if filters.evidence_type is not None:
            stmt = stmt.where(SecurityEvidence.evidence_type == filters.evidence_type)
        if filters.sensitive is not None:
            stmt = stmt.where(SecurityEvidence.sensitive == filters.sensitive)
        if filters.integrity_verified is not None:
            stmt = stmt.where(
                SecurityEvidence.integrity_verified == filters.integrity_verified
            )
        if filters.is_redacted is not None:
            if filters.is_redacted:
                stmt = stmt.where(SecurityEvidence.redacted_at.is_not(None))
            else:
                stmt = stmt.where(SecurityEvidence.redacted_at.is_(None))
        if filters.uploaded_by_id is not None:
            stmt = stmt.where(SecurityEvidence.uploaded_by_id == filters.uploaded_by_id)
        if filters.uploaded_after is not None:
            stmt = stmt.where(SecurityEvidence.created_at >= filters.uploaded_after)
        if filters.uploaded_before is not None:
            stmt = stmt.where(SecurityEvidence.created_at <= filters.uploaded_before)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(SecurityEvidence.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = list(db.execute(stmt).scalars().all())
    return rows, int(total)


# ============================================================================
# DOWNLOAD
# ============================================================================

def prepare_download(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    request: Any | None = None,
) -> DownloadResult:
    """
    Prepare the file bytes for download.

    Steps
    -----
    1. Access check (requires EVIDENCE_READ on the case, or
       FULL_CASE if evidence is marked sensitive with that requirement)
    2. Read the file from disk
    3. Compute SHA-256 and compare with stored hash
    4. On mismatch: mark compromised, audit, log WARNING — but STILL
       return the bytes (investigators need to see the tampered file)
    5. Append "accessed" (or "integrity_failed") to chain of custody
    6. Audit (only on integrity failure — successful access is
       captured in the chain, not the audit log)

    Returns
    -------
    DownloadResult
        File bytes, MIME type, current content hash, verified flag.
    """
    _require_evidence_access(db, actor, evidence)

    storage_path = evidence.get_storage_path()
    file_bytes = _read_file(storage_path)

    computed_hash = _compute_sha256(file_bytes)
    verified = computed_hash == evidence.content_hash

    if not verified:
        logger.warning(
            "Evidence integrity verification FAILED — returning tampered file",
            extra={
                "evidence_id": str(evidence.id),
                "case_id": str(evidence.case_id),
                "stored_hash_prefix": evidence.content_hash[:12],
                "computed_hash_prefix": computed_hash[:12],
                "file_size_bytes": len(file_bytes),
            },
        )
        evidence.integrity_verified = False
        evidence.last_integrity_check_at = datetime.now(timezone.utc)

        # Chain records the failure
        evidence.record_integrity_check(
            passed=False,
            by_user_id=actor.id,
            notes=(
                f"Integrity check on download FAILED. "
                f"Stored: {evidence.content_hash[:16]}... "
                f"Computed: {computed_hash[:16]}..."
            ),
        )

        # Audit the security event
        audit_service.log_action(
            db,
            actor=actor,
            action="evidence.integrity_failed",
            outcome=audit_service.AuditOutcome.FAILURE,
            target_type="evidence",
            target_id=evidence.id,
            workspace_id=evidence.workspace_id,
            request=request,
            notes=(
                f"File content does not match stored hash. "
                f"Evidence may have been tampered with on disk."
            ),
            metadata={
                "case_id": str(evidence.case_id),
                "stored_hash_prefix": evidence.content_hash[:12],
                "computed_hash_prefix": computed_hash[:12],
            },
        )
    else:
        # Normal access
        evidence.record_access(
            by_user_id=actor.id,
            ip_address=_extract_ip(request),
            notes="Downloaded via API",
        )
        evidence.last_integrity_check_at = datetime.now(timezone.utc)

    db.flush()

    # Use the stored mime type, or infer from extension as fallback
    mime = evidence.mime_type or _mime_from_extension(evidence.file_extension)

    return DownloadResult(
        file_bytes=file_bytes,
        mime_type=mime,
        content_hash=computed_hash,
        verified=verified,
        original_filename=evidence.original_filename,
    )


# ============================================================================
# CHAIN OF CUSTODY — explicit recording
# ============================================================================

def record_access(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Record an access event in the chain without requiring a download.

    Used when a user views the metadata-only preview or explicitly
    "opens" the evidence in the UI (before the file download). Records
    intent, not content.
    """
    _require_evidence_access(db, actor, evidence)

    evidence.record_access(
        by_user_id=actor.id,
        ip_address=_extract_ip(request),
        notes=notes,
    )
    db.flush()

    return evidence


def record_integrity_check(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    passed: bool,
    notes: str | None = None,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Record the result of a manual integrity check (e.g. triggered by an
    admin via a "verify integrity" button on the evidence detail page).
    """
    _require_evidence_access(db, actor, evidence)

    evidence.record_integrity_check(
        passed=passed,
        by_user_id=actor.id,
        notes=notes,
    )

    if not passed:
        # Audit failures at security-event level
        audit_service.log_action(
            db,
            actor=actor,
            action="evidence.integrity_failed",
            outcome=audit_service.AuditOutcome.FAILURE,
            target_type="evidence",
            target_id=evidence.id,
            workspace_id=evidence.workspace_id,
            request=request,
            notes=notes,
        )

    db.flush()
    return evidence


# ============================================================================
# REDACTION
# ============================================================================

def redact_evidence(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    redacted_bytes: bytes,
    redaction_notes: str,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Replace evidence content with a redacted version.

    Preserves the original file (moved to ``{stored}.original``) and
    the original hash (``original_content_hash``). Updates the
    canonical ``stored_filename`` file with the redacted content.

    The ``redacted_bytes`` must be the **already-redacted content** —
    this service does not perform redaction itself. The caller
    (endpoint or a future redaction service) prepares the bytes.

    Steps
    -----
    1. Access check (must have FULL_CASE to redact)
    2. Verify original file integrity (prove we're redacting the
       real file)
    3. Move original to ``{stored}.original``
    4. Write redacted bytes to ``{stored}``
    5. Update content_hash, original_content_hash, redacted_at, etc.
    6. Append "redacted" to chain
    7. Audit

    Idempotent? No — a second redaction call must be rejected. Redact
    once, replace the file, done. To re-redact, the analyst should
    upload a new version.
    """
    if evidence.redacted_at is not None:
        raise ValidationError(
            message="This evidence has already been redacted.",
            code="EVIDENCE_ALREADY_REDACTED",
            details={"redacted_at": evidence.redacted_at.isoformat()},
        )

    if not redaction_notes or not redaction_notes.strip():
        raise ValidationError(
            message="Redaction notes are required.",
            code="EVIDENCE_REDACTION_NOTES_REQUIRED",
        )

    if not redacted_bytes:
        raise ValidationError(
            message="Redacted content cannot be empty.",
            code="EVIDENCE_REDACTED_EMPTY",
        )

    # Require FULL_CASE for redaction
    case = db.get(SecurityCase, evidence.case_id)
    if case is None:
        raise CaseNotFoundError(
            message="The case for this evidence no longer exists.",
            details={"case_id": str(evidence.case_id)},
        )
    authorization.require_case_access(
        db, actor, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    # ── Verify original file integrity
    storage_path = evidence.get_storage_path()
    original_bytes = _read_file(storage_path)
    original_hash = _compute_sha256(original_bytes)

    if original_hash != evidence.content_hash:
        raise ValidationError(
            message=(
                "Cannot redact: the file on disk no longer matches the "
                "stored hash. The evidence may have been tampered with. "
                "Investigate before redacting."
            ),
            code="EVIDENCE_INTEGRITY_FAILED_BEFORE_REDACTION",
            details={
                "stored_hash_prefix": evidence.content_hash[:16],
                "computed_hash_prefix": original_hash[:16],
            },
        )

    # ── Move original to .original
    original_path = storage_path.with_suffix(storage_path.suffix + ".original")
    if not original_path.exists():
        try:
            original_path.write_bytes(original_bytes)
        except OSError as exc:
            raise ValidationError(
                message=f"Failed to archive original file: {exc}",
                code="EVIDENCE_REDACTION_STORAGE_ERROR",
            )

    # ── Write redacted content
    try:
        _write_file(storage_path, redacted_bytes)
    except OSError as exc:
        raise ValidationError(
            message=f"Failed to write redacted file: {exc}",
            code="EVIDENCE_REDACTION_STORAGE_ERROR",
        )

    redacted_hash = _compute_sha256(redacted_bytes)

    # ── Update the row
    evidence.mark_redacted(
        by_user_id=actor.id,
        new_content_hash=redacted_hash,
        notes=redaction_notes.strip(),
    )
    db.flush()

    # ── Audit
    audit_service.log_action(
        db,
        actor=actor,
        action="evidence.redacted",
        target_type="evidence",
        target_id=evidence.id,
        workspace_id=evidence.workspace_id,
        request=request,
        notes=redaction_notes.strip(),
        metadata={
            "case_id": str(evidence.case_id),
            "original_hash_prefix": original_hash[:12],
            "redacted_hash_prefix": redacted_hash[:12],
        },
    )

    logger.info(
        "Evidence redacted",
        extra={
            "evidence_id": str(evidence.id),
            "case_id": str(evidence.case_id),
            "original_hash_prefix": original_hash[:12],
            "redacted_hash_prefix": redacted_hash[:12],
        },
    )

    return evidence


# ============================================================================
# DELETE (soft)
# ============================================================================

def delete_evidence(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    reason: str,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Soft-delete evidence.

    Sets ``deleted_at``. The row stays in the DB (excluded from
    queries). The file on disk stays (needed for retention, legal
    hold, and audit).

    Hard deletion happens via the retention job (not in this service)
    after ``RETENTION_EVIDENCE_DAYS`` and only if no legal hold is
    active.

    Requires ``FULL_CASE`` scope on the case.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A deletion reason is required.",
            code="EVIDENCE_DELETE_REASON_REQUIRED",
        )

    if evidence.deleted_at is not None:
        return evidence  # idempotent

    case = db.get(SecurityCase, evidence.case_id)
    if case is None:
        raise CaseNotFoundError(
            message="The case for this evidence no longer exists.",
            details={"case_id": str(evidence.case_id)},
        )
    authorization.require_case_access(
        db, actor, case, minimum_scope=AccessGrantScope.FULL_CASE,
    )

    evidence.deleted_at = datetime.now(timezone.utc)
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="evidence.deleted",
        target_type="evidence",
        target_id=evidence.id,
        workspace_id=evidence.workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={"case_id": str(case.id)},
    )

    logger.info(
        "Evidence soft-deleted",
        extra={
            "evidence_id": str(evidence.id),
            "case_id": str(case.id),
        },
    )

    return evidence


# ============================================================================
# LEGAL HOLD
# ============================================================================

def apply_legal_hold(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    until: datetime,
    reason: str,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Apply a legal hold to evidence.

    During the hold, retention cleanup skips this evidence regardless
    of the standard retention policy. Setting/clearing legal hold
    requires admin permission — a normal user cannot.

    The ``until`` may be far in the future (e.g. 5 years for active
    litigation). The retention job checks
    ``legal_hold_until > now()`` before deleting.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A legal hold reason is required.",
            code="EVIDENCE_LEGAL_HOLD_REASON_REQUIRED",
        )

    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    if until <= datetime.now(timezone.utc):
        raise ValidationError(
            message="Legal hold expiry must be in the future.",
            code="EVIDENCE_LEGAL_HOLD_IN_PAST",
        )

    # Super admin or workspace owner can apply legal hold — no
    # intermediate roles, because it affects retention/compliance
    case = db.get(SecurityCase, evidence.case_id)
    if case is None:
        raise CaseNotFoundError(
            message="The case for this evidence no longer exists.",
            details={"case_id": str(evidence.case_id)},
        )

    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    is_ws_owner = (
        ws_role is not None and ws_role.value == "owner"
    )
    is_super_admin = authorization.is_super_admin(actor)
    if not (is_ws_owner or is_super_admin):
        raise AuthorizationError(
            message=(
                "Only workspace OWNER or platform super admin can apply "
                "a legal hold."
            ),
            code="LEGAL_HOLD_DENIED",
        )

    evidence.legal_hold_until = until
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="evidence.legal_hold.applied",
        target_type="evidence",
        target_id=evidence.id,
        workspace_id=evidence.workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={
            "case_id": str(case.id),
            "until": until.isoformat(),
        },
    )

    logger.info(
        "Legal hold applied to evidence",
        extra={
            "evidence_id": str(evidence.id),
            "until": until.isoformat(),
        },
    )

    return evidence


def release_legal_hold(
    db: Session,
    *,
    actor: User,
    evidence: SecurityEvidence,
    reason: str,
    request: Any | None = None,
) -> SecurityEvidence:
    """
    Release a legal hold. Same permission model as applying one.
    """
    if not reason or not reason.strip():
        raise ValidationError(
            message="A release reason is required.",
            code="EVIDENCE_LEGAL_HOLD_RELEASE_REASON_REQUIRED",
        )

    if evidence.legal_hold_until is None:
        return evidence  # idempotent

    case = db.get(SecurityCase, evidence.case_id)
    if case is None:
        raise CaseNotFoundError(
            message="The case for this evidence no longer exists.",
            details={"case_id": str(evidence.case_id)},
        )

    ws_role = authorization.get_user_workspace_role(
        db, actor, case.workspace_id,
    )
    is_ws_owner = (ws_role is not None and ws_role.value == "owner")
    is_super_admin = authorization.is_super_admin(actor)
    if not (is_ws_owner or is_super_admin):
        raise AuthorizationError(
            message="Only workspace OWNER or platform super admin can release a legal hold.",
            code="LEGAL_HOLD_DENIED",
        )

    evidence.legal_hold_until = None
    db.flush()

    audit_service.log_action(
        db,
        actor=actor,
        action="evidence.legal_hold.released",
        target_type="evidence",
        target_id=evidence.id,
        workspace_id=evidence.workspace_id,
        request=request,
        notes=reason.strip(),
        metadata={"case_id": str(case.id)},
    )

    return evidence


# ============================================================================
# INTERNAL — request context
# ============================================================================

def _extract_ip(request: Any | None) -> str | None:
    """Best-effort client IP from a FastAPI/Starlette request."""
    if request is None:
        return None
    try:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:45]
        if request.client:
            return request.client.host[:45]
    except Exception:  # noqa: BLE001
        pass
    return None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "DownloadResult",
    "upload_evidence",
    "get_by_id",
    "list_evidence_for_case",
    "prepare_download",
    "record_access",
    "record_integrity_check",
    "redact_evidence",
    "delete_evidence",
    "apply_legal_hold",
    "release_legal_hold",
]