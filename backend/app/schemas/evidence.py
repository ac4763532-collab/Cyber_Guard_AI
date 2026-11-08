"""
CyberGuard AI — Evidence Schemas
============================================================================

Request/response DTOs for the ``security_evidence`` table.

Evidence is the most sensitive part of a case. The schemas here reflect
that: every field is either server-computed (hash, stored filename,
size), or requires an explicit, specific input from the uploading user
(description, sensitivity, required access scope).

Design rules
------------
1. **Upload is multipart/form-data, not JSON.**
   The file bytes go over the wire as ``UploadFile`` — the client
   cannot supply ``content_hash`` or ``file_size_bytes``; the backend
   computes them from the actual bytes received. This is the entire
   point of the integrity pipeline: the client declares *what* they
   are uploading (filename, description), and the backend asserts
   *what arrived* (hash, size, extension).

2. **``stored_filename`` and ``content_hash`` never appear in the
   Create schema.**
   Both are server-computed. If a client could supply them, an
   attacker could forge a hash to bypass integrity verification.

3. **``access_grant_scope_required`` defaults to ``evidence_read``.**
   Sensitive evidence sets this to ``full_case`` — which means only
   users with a ``full_case`` grant on the case can view it. This is
   the mechanism that makes evidence access granular.

4. **``sensitive`` flag triggers extra UI confirmation.**
   A user opening sensitive evidence gets a warning dialog first. The
   flag is not a security control by itself — it's a signal to the UI.
   Actual enforcement is via ``access_grant_scope_required``.

5. **Chain of custody is append-only.**
   ``EvidenceChainOfCustodyEntry`` is a read-only view of the JSONB
   array. There is no schema for modifying or deleting entries — the
   service appends on every access, verify, redaction, or export.
   Immutability at the schema level.

6. **Redaction preserves the original.**
   ``EvidenceRedactionRequest`` triggers a hash-mutating operation:
   the service writes a redacted copy, updates ``content_hash``, and
   preserves ``original_content_hash``. The original file is kept in
   cold storage for legal-hold scenarios. This is not a "modify in
   place" — it is a documented, auditable transformation.

7. **No public list-all-endpoint.**
   Evidence is only accessible through a case. There is no
   ``GET /evidence`` — you must call ``GET /cases/{id}/evidence``.
   This is deliberate: enforcing "evidence belongs to a case" at the
   URL level makes access-control logic simpler and harder to bypass.

8. **Legal hold is read-only via API.**
   ``legal_hold_until`` can only be set by a super admin through a
   dedicated endpoint (in Phase H admin router). It is not part of
   Create or Update. Once set, retention jobs skip the evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import AccessGrantScope, EvidenceType
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_DESCRIPTION_MAX = 5000
_REDACTION_NOTES_MAX = 2000
_ACCESS_NOTES_MAX = 1000
_TAGS_MAX = 20
_EVENT_IDS_MAX = 1000
_FINDING_IDS_MAX = 500

#: Size caps — must match the model's CHECK constraint.
_MAX_FILE_SIZE_BYTES = 52_428_800  # 50 MB

#: Allowed evidence types.
_VALID_EVIDENCE_TYPES = frozenset(
    t.value for t in EvidenceType
)

#: Chain of custody action types (for ``EvidenceChainOfCustodyEntry``).
_CUSTODY_ACTIONS = frozenset({
    "uploaded",
    "verified",
    "integrity_failed",
    "accessed",
    "exported",
    "redacted",
})


# ============================================================================
# UPLOAD (create)
# ============================================================================

class EvidenceUploadMetadata(CyberGuardBaseSchema):
    """
    Metadata accompanying a file upload.

    The actual file is sent separately as ``UploadFile`` in a
    multipart/form-data request. This schema describes the
    **non-file** fields.

    ``original_filename`` is a UI-display field only — it is never used
    for storage. The backend generates a UUID-based stored filename.
    ``content_hash`` and ``file_size_bytes`` are computed from the
    bytes received, not accepted from the client.
    """

    original_filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description=(
            "Filename as reported by the client. Display-only — the "
            "backend stores the file under a UUID-based name to "
            "prevent path traversal. Extension is validated against "
            "an allow-list (exe/dll/sh/bat and similar are rejected)."
        ),
    )

    evidence_type: EvidenceType = Field(
        default=EvidenceType.FILE,
        description=(
            "file | log_snippet | network_capture | screenshot | "
            "email_artifact | other"
        ),
    )

    description: str | None = Field(
        default=None,
        max_length=_DESCRIPTION_MAX,
        description="Analyst note describing what this evidence shows.",
    )

    event_ids: list[uuid.UUID] = Field(
        default_factory=list,
        max_length=_EVENT_IDS_MAX,
        description="Events this evidence supports.",
    )
    finding_ids: list[uuid.UUID] = Field(
        default_factory=list,
        max_length=_FINDING_IDS_MAX,
        description="Findings this evidence supports.",
    )

    tags: list[str] = Field(default_factory=list, max_length=_TAGS_MAX)

    sensitive: bool = Field(
        default=False,
        description=(
            "If True, the UI shows a warning before displaying. "
            "Some policies require 'full_case' scope for sensitive "
            "evidence — set ``access_grant_scope_required`` "
            "accordingly."
        ),
    )

    access_grant_scope_required: AccessGrantScope = Field(
        default=AccessGrantScope.EVIDENCE_READ,
        description=(
            "Minimum grant scope to view this evidence. Default "
            "'evidence_read'. Sensitive evidence may require 'full_case'."
        ),
    )

    @field_validator("original_filename")
    @classmethod
    def _validate_filename(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("original_filename must not be empty")
        # Reject path separators — the client should send a bare name.
        if "/" in stripped or "\\" in stripped:
            raise ValueError(
                "original_filename must not contain path separators"
            )
        return stripped

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each tag must be a string")
            normalized = item.strip().lower()
            if not normalized or normalized in seen:
                continue
            if len(normalized) > 64:
                raise ValueError("each tag must not exceed 64 characters")
            seen.add(normalized)
            cleaned.append(normalized)
        return cleaned

    @field_validator("access_grant_scope_required")
    @classmethod
    def _validate_scope_for_sensitive(
        cls, v: AccessGrantScope, info
    ) -> AccessGrantScope:
        # Sensitive evidence must require at least evidence_read.
        # (full_case is fine, case_read is not — it wouldn't allow
        # viewing the file at all, defeating the point.)
        sensitive = info.data.get("sensitive", False)
        if sensitive and v == AccessGrantScope.CASE_READ:
            raise ValueError(
                "sensitive evidence must require at least "
                "'evidence_read' scope (not 'case_read')"
            )
        return v


# ============================================================================
# READ
# ============================================================================

class EvidenceChainOfCustodyEntry(ORMModel):
    """
    One entry in the chain of custody. Read-only view — the JSONB
    array is append-only at the service layer.
    """

    at: datetime
    action: str = Field(
        ...,
        description=(
            "uploaded | verified | integrity_failed | accessed | "
            "exported | redacted"
        ),
    )
    by_user_id: uuid.UUID | None = None
    ip_address: str | None = None
    notes: str | None = None

    @field_validator("action")
    @classmethod
    def _validate_action(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _CUSTODY_ACTIONS:
            # Accept unknown actions but don't fail — future actions
            # may be added without a schema migration.
            return normalized
        return normalized


class EvidenceRead(TimestampedModel):
    """
    Full evidence view. Returned by ``GET /evidence/{id}``.

    Includes the chain of custody — clients rendering evidence detail
    pages should display this in a "history" panel so users can see
    who accessed what and when.

    The **plaintext file is not returned here** — it's fetched via a
    separate ``GET /evidence/{id}/download`` endpoint which streams
    the bytes and records an "accessed" entry in the chain.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    case_id: uuid.UUID
    uploaded_by_id: uuid.UUID | None = None

    evidence_type: EvidenceType
    description: str | None = None

    original_filename: str
    stored_filename: str = Field(
        ...,
        description=(
            "UUID-based filename on disk. Never used to serve content "
            "directly — the download endpoint resolves the full path."
        ),
    )
    file_extension: str = ""
    mime_type: str | None = None
    file_size_bytes: int

    content_hash: str = Field(
        ...,
        description="SHA-256 of current file contents. Verified on every read.",
    )
    original_content_hash: str | None = Field(
        default=None,
        description=(
            "SHA-256 of pre-redaction file, if redaction occurred. "
            "Preserved for forensic recovery of the original."
        ),
    )

    integrity_verified: bool = True
    last_integrity_check_at: datetime | None = None

    sensitive: bool = False
    access_grant_scope_required: AccessGrantScope

    redacted_at: datetime | None = None
    redacted_by_id: uuid.UUID | None = None
    redaction_notes: str | None = None

    event_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    chain_of_custody: list[EvidenceChainOfCustodyEntry] = Field(
        default_factory=list,
    )

    legal_hold_until: datetime | None = None

    # Computed
    is_redacted: bool = Field(..., description="True if redaction was applied.")
    is_compromised: bool = Field(
        ..., description="True if integrity verification has failed."
    )
    is_sensitive: bool = Field(..., description="True if sensitive flag is set.")
    is_under_legal_hold: bool = Field(
        ..., description="True if legal_hold_until is in the future."
    )


class EvidenceList(ORMModel):
    """
    Lightweight evidence view for lists.

    Omits ``chain_of_custody`` and full ``metadata`` — both can be
    large. Fetch ``GET /evidence/{id}`` for full details.
    """

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_type: EvidenceType
    original_filename: str
    file_size_bytes: int
    mime_type: str | None = None
    sensitive: bool = False
    access_grant_scope_required: AccessGrantScope
    integrity_verified: bool = True
    is_redacted: bool = False
    created_at: datetime


# ============================================================================
# UPDATE
# ============================================================================

class EvidenceUpdate(CyberGuardBaseSchema):
    """
    Fields a case participant can change about a piece of evidence.

    Cannot change:
        - ``content_hash`` / ``original_content_hash`` — server-computed
        - ``stored_filename`` / ``file_extension`` / ``file_size_bytes``
          / ``mime_type`` — server-computed from the actual bytes
        - ``original_filename`` — set at upload, immutable
        - ``chain_of_custody`` — append-only via service
        - ``redacted_at`` / ``original_content_hash`` — set by
          dedicated redaction endpoint
        - ``legal_hold_until`` — super-admin only, dedicated endpoint

    Only descriptive and access-control fields are mutable.
    """

    description: str | None = Field(default=None, max_length=_DESCRIPTION_MAX)
    evidence_type: EvidenceType | None = None
    sensitive: bool | None = None
    access_grant_scope_required: AccessGrantScope | None = None
    tags: list[str] | None = Field(default=None, max_length=_TAGS_MAX)

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each tag must be a string")
            normalized = item.strip().lower()
            if not normalized or normalized in seen:
                continue
            if len(normalized) > 64:
                raise ValueError("each tag must not exceed 64 characters")
            seen.add(normalized)
            cleaned.append(normalized)
        return cleaned


# ============================================================================
# REDACTION
# ============================================================================

class EvidenceRedactionRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /evidence/{id}/redact``.

    **Not a partial update** — this triggers a full transform:

        1. Original file is archived to cold storage (unchanged).
        2. Redacted content is written to ``stored_filename``.
        3. ``content_hash`` is updated to the redacted hash.
        4. ``original_content_hash`` preserves the pre-redaction hash.
        5. ``redacted_at`` is set. ``redaction_notes`` is recorded.
        6. A ``redacted`` entry is appended to the chain of custody.

    The caller **must supply** the redacted content as an
    ``UploadFile`` alongside this metadata, OR the service performs
    redaction using its own PII detection (future feature).
    """

    redaction_notes: str = Field(
        ...,
        min_length=1,
        max_length=_REDACTION_NOTES_MAX,
        description=(
            "Which fields were redacted and how (e.g. 'masked emails "
            "and phone numbers'). Required for the audit trail."
        ),
    )

    @field_validator("redaction_notes")
    @classmethod
    def _clean_notes(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("redaction_notes must not be empty")
        return stripped


# ============================================================================
# ACCESS RECORDING
# ============================================================================

class EvidenceAccessRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /evidence/{id}/access``.

    Called when a user views the evidence. Records an "accessed" entry
    in the chain of custody. No state change to the file itself.

    The UI calls this when the user clicks "open evidence" — even
    before the file download completes, so the chain reflects intent.
    """

    notes: str | None = Field(
        default=None,
        max_length=_ACCESS_NOTES_MAX,
        description="Optional context about why the evidence was accessed.",
    )


# ============================================================================
# FILTER
# ============================================================================

class EvidenceFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /cases/{id}/evidence``.

    Evidence is always scoped to a case (there is no global evidence
    list). This filter operates within that scope.
    """

    evidence_type: EvidenceType | None = None
    sensitive: bool | None = None
    integrity_verified: bool | None = None
    is_redacted: bool | None = None

    uploaded_by_id: uuid.UUID | None = None

    uploaded_after: datetime | None = None
    uploaded_before: datetime | None = None

    tags_any: list[str] | None = Field(
        default=None,
        description="Only evidence with at least one of these tags.",
    )


# ============================================================================
# DOWNLOAD
# ============================================================================

class EvidenceDownloadInfo(CyberGuardBaseSchema):
    """
    Metadata about a downloadable evidence file. Returned when the
    client requests a download (headers of the streaming response).
    """

    evidence_id: uuid.UUID
    original_filename: str
    mime_type: str
    file_size_bytes: int
    content_hash: str

    verified_at_request: bool = Field(
        ...,
        description=(
            "True if the SHA-256 hash was re-verified at download time. "
            "If False, integrity_verified on the evidence row is now "
            "also False and an alert was written."
        ),
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EvidenceUploadMetadata",
    "EvidenceRead",
    "EvidenceList",
    "EvidenceUpdate",
    "EvidenceRedactionRequest",
    "EvidenceAccessRequest",
    "EvidenceFilter",
    "EvidenceDownloadInfo",
    "EvidenceChainOfCustodyEntry",
]