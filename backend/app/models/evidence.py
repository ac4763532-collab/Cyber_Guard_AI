"""
CyberGuard AI — Case Evidence
============================================================================

The ``security_evidence`` table: artefacts attached to security cases.

Evidence is the most sensitive part of a case. It requires three
properties that distinguish it from ordinary file uploads:

    1. Integrity      — must be provably the same file, byte for byte
    2. Chain of custody — every access, verification, modification recorded
    3. Access control — separate scope from case access

Design decisions
----------------
1. **``content_hash`` (SHA-256) is mandatory.**
   Computed at upload, stored, and re-verified on every read. If the hash
   mismatches the file on disk, the evidence is marked compromised
   (``integrity_verified=False``) and an audit entry is written. A NOT NULL
   constraint at the DB level makes it impossible to create evidence
   without a hash.

2. **``stored_filename`` is a UUID, not the user's filename.**
   The original filename is kept in ``original_filename`` (display only);
   the file on disk is ``<uuid>.<ext>``. This prevents path traversal
   attacks (``../../etc/passwd``), filename collisions, and unicode /
   homoglyph attacks.

3. **Storage path is derived, not stored.**
   The path is computed by ``get_storage_path()`` from the other fields.
   The file location can be relocated (e.g. to S3) by changing one method,
   not by updating thousands of rows.

4. **``chain_of_custody`` JSONB (append-only).**
   Every action is logged: upload, verify, integrity_failed, redact,
   export, access. Each entry has ``{at, action, by_user_id, ip_address,
   notes}``. The service appends; the model enforces a max entry count.

5. **``sensitive`` flag.**
   Some evidence (e.g. screenshots of private conversations) requires an
   additional warning UI before display. The service may require higher
   scope (``full_case``) for sensitive evidence — policy enforced at the
   authorization service, but the flag lives on the row.

6. **Redaction via soft-marking.**
   When PII is redacted, we keep the original file, mark ``redacted_at``
   on the row, and update ``content_hash`` to hash the redacted version.
   ``original_content_hash`` preserves the pre-redaction hash so the
   original file can always be re-identified.

7. **``event_ids`` and ``finding_ids`` JSONB.**
   Evidence often refers to specific events or findings. Storing them as
   arrays enables cross-navigation ("click event → see related evidence").

8. **``access_grant_scope_required`` enum.**
   Which ``AccessGrantScope`` is required to view this evidence. Default
   ``EVIDENCE_READ``. Sensitive evidence may require ``FULL_CASE``.

9. **``legal_hold_until``.**
   Evidence under legal hold cannot be deleted by the retention service,
   regardless of retention policy. Individual evidence pieces may be held
   even after the parent case is resolved.

10. **``SoftDeleteMixin`` IS used here.**
    Evidence retention is legally significant. A GDPR delete request:
        - soft-deletes immediately (excluded from queries, unreachable)
        - background job hard-deletes after retention window + no legal hold
    This two-phase deletion is a compliance requirement.

11. **File size cap enforced at DB level.**
    ``CHECK (file_size_bytes <= 52428800)`` (50 MB). The service enforces
    the same limit earlier (fail fast) but the DB check is defense-in-depth
    against a misbehaving upload path.

12. **File extension allow-list enforced at DB level.**
    Cannot upload ``.exe``, ``.dll``, ``.sh``, ``.bat``, etc. as evidence.
    Verified by a CHECK constraint against a documented set of extensions.

13. **``workspace_id`` denormalized.**
    Evidence belongs to a case, which belongs to a workspace. Denormalizing
    enables efficient tenant-scoped queries across all cases in a workspace
    without a JOIN. Kept in sync by the service.

14. **Timezone correctness everywhere.**

Usage
-----
    from app.models import SecurityEvidence
    from app.models.enums import AccessGrantScope, EvidenceType

    evidence = SecurityEvidence.build(
        workspace_id=case.workspace_id,
        case_id=case.id,
        uploaded_by_id=analyst.id,
        evidence_type=EvidenceType.EMAIL_ARTIFACT,
        original_filename="suspicious-email.eml",
        stored_filename="a1b2c3d4-....eml",
        content_hash="f" * 64,
        file_size_bytes=2_456_789,
        mime_type="message/rfc822",
        description="Phishing email received by alice@example.com",
        event_ids=["evt_1", "evt_2"],
        finding_ids=["fnd_1"],
        sensitive=False,
        access_grant_scope_required=AccessGrantScope.EVIDENCE_READ,
    )
    db.add(evidence)
    db.commit()

    # Analyst accesses to verify
    evidence.record_access(by_user_id=analyst.id, ip_address="203.0.113.42")

    # Chain of custody check
    print(evidence.chain_of_custody)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.db.base import (
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import (
    AccessGrantScope,
    EvidenceType,
    enum_column_type,
)


#: Allowed file extensions for evidence. Must match the CHECK constraint.
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".pdf", ".txt", ".log", ".csv", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".zip", ".gz", ".tar",
    ".pcap", ".pcapng", ".eml", ".msg",
    ".docx", ".xlsx", ".pptx",
})

#: Extensions explicitly rejected even if MIME type looks OK.
#: Defense in depth against server-side execution attempts.
_DENIED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".sh",
    ".msi", ".scr", ".vbs", ".jar", ".com", ".app",
    ".php", ".phtml", ".jsp", ".asp", ".aspx", ".cgi",
    ".py", ".rb", ".pl", ".js",
})

#: 50 MB cap. Matches MAX_UPLOAD_SIZE_BYTES default in config.
_MAX_FILE_SIZE_BYTES = 52_428_800

_MAX_FILENAME_LENGTH = 255
_MAX_STORED_FILENAME_LENGTH = 128
_MAX_MIME_LENGTH = 128
_MAX_DESCRIPTION_LENGTH = 5000
_MAX_HASH_LENGTH = 64
_MAX_IP_ADDRESS_LENGTH = 45
_MAX_EVENT_IDS = 1000
_MAX_FINDING_IDS = 500
_MAX_TAGS = 20
_MAX_CHAIN_ENTRIES = 500
_MAX_METADATA_BYTES = 64 * 1024

#: SHA-256 hex regex.
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

#: Valid evidence_type values enforced by CHECK constraint. Mirrors enum.
_VALID_EVIDENCE_TYPES = frozenset(EvidenceType.values())


class SecurityEvidence(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A piece of evidence attached to a security case.

    Files live on disk under
    ``static/uploads/evidence/{workspace_id}/{case_id}/{stored_filename}``.
    The path is not stored — it's computed by ``get_storage_path()``.

    Every row has a SHA-256 content hash that must be verified on access.
    The ``chain_of_custody`` JSONB records every interaction.
    """

    __tablename__ = "security_evidence"

    __table_args__ = (
        # SHA-256 hex format
        CheckConstraint(
            r"content_hash ~ '^[a-f0-9]{64}$'",
            name="content_hash_format",
        ),
        CheckConstraint(
            "original_content_hash IS NULL OR "
            r"original_content_hash ~ '^[a-f0-9]{64}$'",
            name="original_hash_format",
        ),
        # File size: positive, capped
        CheckConstraint(
            "file_size_bytes > 0 AND file_size_bytes <= 52428800",
            name="file_size_range",
        ),
        # Extension must be in the allowed set
        CheckConstraint(
            "file_extension = '' OR file_extension IN ("
            "'.pdf', '.txt', '.log', '.csv', '.json', '.xml', "
            "'.png', '.jpg', '.jpeg', '.gif', '.webp', "
            "'.zip', '.gz', '.tar', "
            "'.pcap', '.pcapng', '.eml', '.msg', "
            "'.docx', '.xlsx', '.pptx'"
            ")",
            name="file_extension_allowed",
        ),
        # Same filename within a case must be unique
        UniqueConstraint(
            "case_id",
            "stored_filename",
            name="uq_case_stored_filename",
        ),
        # Main case lookup
        Index(
            "ix_evidence_case_created",
            "case_id",
            "created_at",
        ),
        # Workspace-scoped queries
        Index(
            "ix_evidence_workspace_created",
            "workspace_id",
            "created_at",
        ),
        # Hash lookup for integrity dedup
        Index(
            "ix_evidence_content_hash",
            "content_hash",
        ),
        # Type filter
        Index(
            "ix_evidence_case_type",
            "case_id",
            "evidence_type",
        ),
    )

    # ─── Tenant & case ──────────────────────────────────────────────────
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Denormalized from case for efficient tenant-scoped queries.",
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning case. Deleting the case cascades its evidence.",
    )

    # ─── Upload attribution ─────────────────────────────────────────────
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who uploaded this evidence. NULL after user hard-delete.",
    )

    # ─── Classification ─────────────────────────────────────────────────
    evidence_type: Mapped[EvidenceType] = mapped_column(
        enum_column_type(EvidenceType),
        nullable=False,
        default=EvidenceType.FILE,
        server_default=EvidenceType.FILE.value,
        index=True,
        comment="file, log_snippet, network_capture, screenshot, "
                "email_artifact, other.",
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Analyst note describing what this evidence shows.",
    )

    # ─── File identity ──────────────────────────────────────────────────
    original_filename: Mapped[str] = mapped_column(
        String(_MAX_FILENAME_LENGTH),
        nullable=False,
        comment="Original filename as uploaded. For display only — never used for storage.",
    )

    stored_filename: Mapped[str] = mapped_column(
        String(_MAX_STORED_FILENAME_LENGTH),
        nullable=False,
        comment=(
            "UUID-based filename on disk. Prevents path traversal and "
            "filename collisions. Format: <uuid>.<ext>."
        ),
    )

    file_extension: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="",
        comment="Lowercase file extension including the leading dot.",
    )

    mime_type: Mapped[str | None] = mapped_column(
        String(_MAX_MIME_LENGTH),
        nullable=True,
        comment="Declared MIME type at upload time.",
    )

    file_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="File size in bytes. Capped at 50 MB by CHECK constraint.",
    )

    # ─── Integrity ──────────────────────────────────────────────────────
    content_hash: Mapped[str] = mapped_column(
        String(_MAX_HASH_LENGTH),
        nullable=False,
        comment="SHA-256 hex of current file contents. Verified on every read.",
    )

    original_content_hash: Mapped[str | None] = mapped_column(
        String(_MAX_HASH_LENGTH),
        nullable=True,
        comment=(
            "SHA-256 of the pre-redaction file, if redaction has occurred. "
            "Preserved for forensic recovery of the original."
        ),
    )

    integrity_verified: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
        server_default="true",
        comment=(
            "False if a hash check has ever failed. Once false, stays false "
            "until the incident is investigated and explicitly cleared by an admin."
        ),
    )

    last_integrity_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time content_hash was verified against the file on disk.",
    )

    # ─── Sensitivity & access ───────────────────────────────────────────
    sensitive: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
        server_default="false",
        comment=(
            "If True, the UI shows a warning modal before displaying. "
            "Some policies require 'full_case' scope for sensitive evidence."
        ),
    )

    access_grant_scope_required: Mapped[AccessGrantScope] = mapped_column(
        enum_column_type(
            AccessGrantScope, name="evidence_access_grant_scope_required"
        ),
        nullable=False,
        default=AccessGrantScope.EVIDENCE_READ,
        server_default=AccessGrantScope.EVIDENCE_READ.value,
        comment=(
            "Minimum grant scope to view this evidence. Defaults to "
            "evidence_read. Sensitive evidence may set full_case."
        ),
    )

    # ─── Redaction ──────────────────────────────────────────────────────
    redacted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When PII redaction was applied to the file contents.",
    )

    redacted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    redaction_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Which fields were redacted and how (e.g. 'masked emails, phones').",
    )

    # ─── Cross-references ───────────────────────────────────────────────
    event_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="UUIDs (as strings) of events this evidence supports.",
    )

    finding_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment="UUIDs (as strings) of findings this evidence supports.",
    )

    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
        comment="Extra structured data (EXIF, file headers, etc.).",
    )

    # ─── Chain of custody ───────────────────────────────────────────────
    chain_of_custody: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
        comment=(
            "Append-only log: [{at, action, by_user_id, ip_address, notes}]. "
            "Actions: uploaded, verified, integrity_failed, redacted, "
            "exported, accessed."
        ),
    )

    # ─── Legal hold ─────────────────────────────────────────────────────
    legal_hold_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment=(
            "If set and in the future, retention cleanup skips this evidence "
            "regardless of case-level retention policy."
        ),
    )

    # ====================================================================
    # VALIDATORS
    # ====================================================================

    @validates("content_hash", "original_content_hash")
    def _validate_hash(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValidationError(
                message=f"{key} must be a string",
                code="EVIDENCE_HASH_INVALID_TYPE",
            )
        normalized = value.strip().lower()
        if not _SHA256_PATTERN.match(normalized):
            raise ValidationError(
                message=f"{key} must be 64 lowercase hex characters",
                code="EVIDENCE_HASH_INVALID_FORMAT",
            )
        return normalized

    @validates("stored_filename")
    def _validate_stored_filename(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(
                message="stored_filename must be a non-empty string",
                code="EVIDENCE_STORED_FILENAME_INVALID",
            )
        stripped = value.strip()
        if len(stripped) > _MAX_STORED_FILENAME_LENGTH:
            raise ValidationError(
                message=f"stored_filename must not exceed {_MAX_STORED_FILENAME_LENGTH} characters",
                code="EVIDENCE_STORED_FILENAME_TOO_LONG",
            )
        # Reject any path separator or traversal sequence
        if "/" in stripped or "\\" in stripped or ".." in stripped:
            raise ValidationError(
                message=(
                    "stored_filename must not contain path separators or "
                    "traversal sequences"
                ),
                code="EVIDENCE_STORED_FILENAME_INVALID_FORMAT",
            )
        return stripped

    @validates("original_filename")
    def _validate_original_filename(self, _key: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(
                message="original_filename must be a non-empty string",
                code="EVIDENCE_ORIGINAL_FILENAME_INVALID",
            )
        stripped = value.strip()
        if len(stripped) > _MAX_FILENAME_LENGTH:
            raise ValidationError(
                message=f"original_filename must not exceed {_MAX_FILENAME_LENGTH} characters",
                code="EVIDENCE_ORIGINAL_FILENAME_TOO_LONG",
            )
        return stripped

    @validates("file_extension")
    def _validate_extension(self, _key: str, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(
                message="file_extension must be a string",
                code="EVIDENCE_EXTENSION_INVALID_TYPE",
            )
        lowered = value.strip().lower()
        if not lowered:
            return ""
        if not lowered.startswith("."):
            lowered = "." + lowered
        if lowered in _DENIED_EXTENSIONS:
            raise ValidationError(
                message=f"file extension {lowered!r} is not permitted for evidence",
                code="EVIDENCE_EXTENSION_DENIED",
            )
        if lowered not in _ALLOWED_EXTENSIONS:
            raise ValidationError(
                message=f"file extension {lowered!r} is not in the allowed set",
                code="EVIDENCE_EXTENSION_NOT_ALLOWED",
                details={"allowed": sorted(_ALLOWED_EXTENSIONS)},
            )
        return lowered

    @validates("evidence_type")
    def _validate_evidence_type(
        self, _key: str, value: EvidenceType | str
    ) -> EvidenceType:
        if isinstance(value, EvidenceType):
            return value
        if isinstance(value, str):
            try:
                return EvidenceType(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid evidence_type {value!r}",
                    code="EVIDENCE_TYPE_INVALID",
                    details={"allowed": list(EvidenceType.values())},
                ) from exc
        raise ValidationError(
            message="evidence_type must be an EvidenceType or string",
            code="EVIDENCE_TYPE_INVALID_TYPE",
        )

    @validates("access_grant_scope_required")
    def _validate_required_scope(
        self, _key: str, value: AccessGrantScope | str
    ) -> AccessGrantScope:
        if isinstance(value, AccessGrantScope):
            return value
        if isinstance(value, str):
            try:
                return AccessGrantScope(value)
            except ValueError as exc:
                raise ValidationError(
                    message=f"Invalid required scope {value!r}",
                    code="EVIDENCE_SCOPE_INVALID",
                    details={"allowed": list(AccessGrantScope.values())},
                ) from exc
        raise ValidationError(
            message="access_grant_scope_required must be an AccessGrantScope or string",
            code="EVIDENCE_SCOPE_INVALID_TYPE",
        )

    @validates("file_size_bytes")
    def _validate_file_size(self, _key: str, value: int) -> int:
        if not isinstance(value, int):
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValidationError(
                    message="file_size_bytes must be an integer",
                    code="EVIDENCE_SIZE_INVALID_TYPE",
                ) from exc
        if value <= 0:
            raise ValidationError(
                message="file_size_bytes must be positive",
                code="EVIDENCE_SIZE_NOT_POSITIVE",
            )
        if value > _MAX_FILE_SIZE_BYTES:
            raise ValidationError(
                message=f"file_size_bytes must not exceed {_MAX_FILE_SIZE_BYTES}",
                code="EVIDENCE_SIZE_TOO_LARGE",
            )
        return value

    @validates("event_ids", "finding_ids", "tags")
    def _validate_string_list(self, key: str, value: list[str] | None) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValidationError(
                message=f"{key} must be a list of strings",
                code="EVIDENCE_LIST_INVALID_TYPE",
                details={"field": key},
            )
        limit = {
            "event_ids": _MAX_EVENT_IDS,
            "finding_ids": _MAX_FINDING_IDS,
            "tags": _MAX_TAGS,
        }[key]
        if len(value) > limit:
            raise ValidationError(
                message=f"{key} must not exceed {limit} items",
                code="EVIDENCE_LIST_TOO_MANY",
                details={"field": key, "limit": limit},
            )
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(
                    message=f"each {key} item must be a string",
                    code="EVIDENCE_LIST_ITEM_INVALID_TYPE",
                )
            stripped = item.strip()
            if not stripped or stripped in seen:
                continue
            seen.add(stripped)
            cleaned.append(stripped)
        return cleaned

    # ====================================================================
    # CONSTRUCTION HELPER
    # ====================================================================

    @classmethod
    def build(
        cls,
        *,
        workspace_id: uuid.UUID,
        case_id: uuid.UUID,
        original_filename: str,
        stored_filename: str,
        content_hash: str,
        file_size_bytes: int,
        evidence_type: EvidenceType = EvidenceType.FILE,
        uploaded_by_id: uuid.UUID | None = None,
        description: str | None = None,
        mime_type: str | None = None,
        event_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        sensitive: bool = False,
        access_grant_scope_required: AccessGrantScope = AccessGrantScope.EVIDENCE_READ,
        legal_hold_until: datetime | None = None,
    ) -> "SecurityEvidence":
        """
        Construct a new evidence record with an initial chain-of-custody
        entry ("uploaded"). The caller must have already written the file
        to disk — this model does not touch the filesystem.
        """
        # Derive extension from original_filename
        ext = ""
        if "." in original_filename:
            ext = "." + original_filename.rsplit(".", 1)[1].lower()

        now = datetime.now(timezone.utc)

        chain = [
            {
                "at": now.isoformat(),
                "action": "uploaded",
                "by_user_id": str(uploaded_by_id) if uploaded_by_id else None,
                "ip_address": None,
                "notes": f"Uploaded as {original_filename}",
            }
        ]

        return cls(
            workspace_id=workspace_id,
            case_id=case_id,
            uploaded_by_id=uploaded_by_id,
            evidence_type=evidence_type,
            description=description,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_extension=ext,
            mime_type=mime_type,
            file_size_bytes=file_size_bytes,
            content_hash=content_hash,
            integrity_verified=True,
            last_integrity_check_at=now,
            sensitive=sensitive,
            access_grant_scope_required=access_grant_scope_required,
            event_ids=event_ids or [],
            finding_ids=finding_ids or [],
            tags=tags or [],
            metadata_json=metadata or {},
            chain_of_custody=chain,
            legal_hold_until=legal_hold_until,
        )

    # ====================================================================
    # STORAGE
    # ====================================================================

    def get_storage_path(self) -> Path:
        """
        Compute the on-disk path for this evidence.

        Layout:
            {UPLOAD_DIR}/evidence/{workspace_id}/{case_id}/{stored_filename}
        """
        base = Path(settings.UPLOAD_DIR).resolve()
        return (
            base / "evidence"
            / str(self.workspace_id)
            / str(self.case_id)
            / self.stored_filename
        )

    # ====================================================================
    # CHAIN OF CUSTODY
    # ====================================================================

    def record_access(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        notes: str | None = None,
    ) -> None:
        """Append an 'accessed' entry to the chain of custody."""
        self._append_custody(
            action="accessed",
            by_user_id=by_user_id,
            ip_address=ip_address,
            notes=notes,
        )

    def record_integrity_check(
        self,
        *,
        passed: bool,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """
        Record the result of an integrity check. If the check fails, the
        evidence is marked as unverified — it stays unverified until an
        admin explicitly clears it after investigation.
        """
        self.last_integrity_check_at = datetime.now(timezone.utc)
        if not passed:
            self.integrity_verified = False
        self._append_custody(
            action="verified" if passed else "integrity_failed",
            by_user_id=by_user_id,
            ip_address=None,
            notes=notes,
        )

    def record_export(
        self,
        *,
        by_user_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> None:
        """Append an 'exported' entry to the chain of custody."""
        self._append_custody(
            action="exported",
            by_user_id=by_user_id,
            ip_address=None,
            notes=notes,
        )

    def _append_custody(
        self,
        *,
        action: str,
        by_user_id: uuid.UUID | None,
        ip_address: str | None,
        notes: str | None,
    ) -> None:
        chain = list(self.chain_of_custody or [])
        if len(chain) >= _MAX_CHAIN_ENTRIES:
            raise ValidationError(
                message=(
                    f"chain_of_custody has reached the maximum of "
                    f"{_MAX_CHAIN_ENTRIES} entries — evidence row must be "
                    "rotated or archived"
                ),
                code="EVIDENCE_CHAIN_LIMIT_REACHED",
            )
        chain.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "by_user_id": str(by_user_id) if by_user_id else None,
            "ip_address": ip_address,
            "notes": notes,
        })
        self.chain_of_custody = chain

    # ====================================================================
    # REDACTION
    # ====================================================================

    def mark_redacted(
        self,
        *,
        by_user_id: uuid.UUID,
        new_content_hash: str,
        notes: str,
    ) -> None:
        """
        Mark the evidence as redacted. The caller is responsible for
        writing the redacted file to disk (same ``stored_filename``) and
        passing its SHA-256 as ``new_content_hash``. The original hash is
        preserved in ``original_content_hash``.
        """
        if self.redacted_at is not None:
            raise ValidationError(
                message="Evidence has already been redacted",
                code="EVIDENCE_ALREADY_REDACTED",
            )
        self.original_content_hash = self.content_hash
        self.content_hash = new_content_hash
        self.redacted_at = datetime.now(timezone.utc)
        self.redacted_by_id = by_user_id
        self.redaction_notes = notes.strip()
        self._append_custody(
            action="redacted",
            by_user_id=by_user_id,
            ip_address=None,
            notes=notes,
        )

    # ====================================================================
    # STATE PROPERTIES
    # ====================================================================

    @property
    def is_under_legal_hold(self) -> bool:
        """True if this evidence is under an active legal hold."""
        if self.legal_hold_until is None:
            return False
        hold = self.legal_hold_until
        if hold.tzinfo is None:
            hold = hold.replace(tzinfo=timezone.utc)
        return hold > datetime.now(timezone.utc)

    @property
    def is_redacted(self) -> bool:
        """True if this evidence has been redacted."""
        return self.redacted_at is not None

    @property
    def is_compromised(self) -> bool:
        """True if integrity verification has failed."""
        return not self.integrity_verified

    @property
    def is_sensitive(self) -> bool:
        """True if this evidence requires additional warnings before display."""
        return self.sensitive


# ============================================================================
# RELATIONSHIPS (added incrementally as child models land)
# ============================================================================
# from sqlalchemy.orm import relationship
# from typing import TYPE_CHECKING
#
# if TYPE_CHECKING:
#     from app.models.case import SecurityCase
#     from app.models.user import User
#
# class SecurityEvidence(...):
#     ...
#     case: Mapped["SecurityCase"] = relationship(
#         "SecurityCase", back_populates="evidence"
#     )
#     uploaded_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[uploaded_by_id]
#     )
#     redacted_by: Mapped["User | None"] = relationship(
#         "User", foreign_keys=[redacted_by_id]
#     )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "SecurityEvidence",
    "_ALLOWED_EXTENSIONS",
    "_DENIED_EXTENSIONS",
    "_MAX_FILE_SIZE_BYTES",
    "_MAX_FILENAME_LENGTH",
    "_MAX_STORED_FILENAME_LENGTH",
    "_MAX_MIME_LENGTH",
    "_MAX_DESCRIPTION_LENGTH",
    "_MAX_HASH_LENGTH",
    "_MAX_IP_ADDRESS_LENGTH",
    "_MAX_EVENT_IDS",
    "_MAX_FINDING_IDS",
    "_MAX_TAGS",
    "_MAX_CHAIN_ENTRIES",
    "_MAX_METADATA_BYTES",
    "_SHA256_PATTERN",
    "_VALID_EVIDENCE_TYPES",
]