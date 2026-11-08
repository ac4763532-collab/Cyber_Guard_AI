"""
CyberGuard AI — Security Report Schemas
============================================================================

Request/response DTOs for the ``security_reports`` table.

Reports are generated asynchronously. A client request enqueues a job
that a background worker picks up. The response is immediate
(status=queued) — the actual file appears later when the worker
completes.

Design rules
------------
1. **Create is a request, not a synchronous response.**
   ``ReportCreate`` describes what report the user wants. The service
   stores a ``queued`` row and returns ``ReportRead`` — the client
   polls ``GET /reports/{id}`` until ``generation_status=ready``.

2. **Reports are immutable artifacts.**
   ``ReportUpdate`` only allows ``title``, ``summary``, and ``shared_with``.
   Once ``generation_status=ready``, ``content_hash`` and other file
   metadata are frozen. Re-running a report creates a **new** row via
   ``regenerated_from_id`` — never overwrites.

3. **Multi-format reports share a ``report_group_id``.**
   A case investigation report often needs PDF (for client) and CSV
   (for internal). Both share the same ``report_group_id``, allowing
   clients to fetch "all files for report X" in one query.

4. **Download requires a specific endpoint.**
   ``GET /reports/{id}/download`` streams the file. The response
   updates ``download_count`` and ``last_downloaded_at``. The
   ``ReportRead`` itself never includes the file bytes.

5. **``shared_with`` is a JSONB array of user shares.**
   ``ReportShareRequest`` appends to it. Shared users get read access
   to the report even if they're not the requestor. Expiry is
   optional per share.

6. **Error info is exposed on the Read schema.**
   When ``generation_status=failed``, clients need ``error_code`` and
   ``error_message`` to display the failure. Both are exposed.

7. **No public list of every report.**
   Reports are scoped to the workspace. Global reports (daily/monthly)
   belong to the workspace they describe. ``GET /reports`` returns only
   the current workspace's reports — enforced by service, but the
   filter schema has ``workspace_id`` for admin override.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.models.enums import (
    ReportStatus,
    ReportType,
)
from app.schemas.common import (
    CyberGuardBaseSchema,
    ORMModel,
    TimestampedModel,
)


# ─── Constants ─────────────────────────────────────────────────────────────
_REPORT_FORMATS = frozenset({"pdf", "csv", "json", "html", "xlsx"})

_SCOPE_TYPES = frozenset({
    "workspace", "organization", "case", "incident",
    "analyst", "source", "custom",
})

#: Known section identifiers. Free-form at schema level — bound by
#: length only. The actual section set is defined per report_type by
#: the report agent.
_SECTION_MAX_LENGTH = 64
_SECTIONS_MAX = 50

_TITLE_MAX = 255
_SUMMARY_MAX = 5000
_ERROR_CODE_MAX = 64
_ERROR_MESSAGE_MAX = 5000
_SHARED_WITH_MAX = 100

#: Default retention (days) — matches model default.
_DEFAULT_EXPIRY_DAYS = 90


# ============================================================================
# CREATE (request generation)
# ============================================================================

class ReportCreate(CyberGuardBaseSchema):
    """
    Request body for ``POST /reports``.

    Describes what report the user wants. The service creates a
    ``queued`` row and returns immediately. A background worker
    generates the file asynchronously.

    The ``parameters`` field is the **reproducibility contract**.
    Every report row stores the exact parameters used to generate it,
    so a compliance auditor can regenerate byte-identical reports
    later.
    """

    report_type: ReportType = Field(
        ...,
        description=(
            "daily | weekly | monthly | incident | phishing | "
            "log_analysis | network | threat_intel | org_risk | "
            "analyst_performance | custom"
        ),
    )

    report_format: Literal["pdf", "csv", "json", "html", "xlsx"] = Field(
        default="pdf",
        description="Output format.",
    )

    title: str = Field(..., min_length=1, max_length=_TITLE_MAX)

    summary: str | None = Field(
        default=None,
        max_length=_SUMMARY_MAX,
        description="Optional human summary. Auto-generated if not provided.",
    )

    scope_type: Literal[
        "workspace", "organization", "case", "incident",
        "analyst", "source", "custom",
    ] = Field(
        default="workspace",
        description="What entity this report covers.",
    )

    scope_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "UUID of the scoped entity. NULL only for custom reports "
            "with a fully-specified parameters dict."
        ),
    )

    period_start_at: datetime | None = Field(
        default=None,
        description="Start of time window covered. NULL for point-in-time reports.",
    )
    period_end_at: datetime | None = Field(
        default=None,
        description="End of time window covered.",
    )

    sections: list[str] = Field(
        default_factory=list,
        max_length=_SECTIONS_MAX,
        description=(
            "Which sections to include: executive_summary, "
            "threat_landscape, timeline, evidence, recommendations, "
            "device_health, compliance_checklist, etc. Empty list "
            "means 'all sections appropriate for report_type'."
        ),
    )

    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Exact parameters used to generate. Preserved verbatim for "
            "reproducibility. Examples: {include_evidence: true, "
            "severity_floor: 'medium'}."
        ),
    )

    expires_in_days: int | None = Field(
        default=_DEFAULT_EXPIRY_DAYS,
        ge=1,
        le=3650,
        description=(
            "How many days until the report file expires. NULL = no "
            "expiry (not recommended). Max 10 years."
        ),
    )

    report_group_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If this is an additional format of an existing report, "
            "pass the original report's report_group_id so they share "
            "the same group. NULL = this is the first format."
        ),
    )

    regenerated_from_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If re-running an earlier report, points to the original. "
            "The system never overwrites — it creates a new row."
        ),
    )

    is_scheduled: bool = Field(
        default=False,
        description="True if this report was scheduled (not manual).",
    )

    @field_validator("title")
    @classmethod
    def _clean_title(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped

    @field_validator("sections")
    @classmethod
    def _validate_sections(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("each section must be a string")
            normalized = item.strip().lower()
            if not normalized or normalized in seen:
                continue
            if len(normalized) > _SECTION_MAX_LENGTH:
                raise ValueError(
                    f"each section must not exceed {_SECTION_MAX_LENGTH} characters"
                )
            seen.add(normalized)
            cleaned.append(normalized)
        return cleaned

    @field_validator("period_end_at")
    @classmethod
    def _validate_period(cls, v: datetime | None, info) -> datetime | None:
        if v is None:
            return None
        start = info.data.get("period_start_at")
        if start is not None and v < start:
            raise ValueError("period_end_at must be >= period_start_at")
        return v


# ============================================================================
# READ
# ============================================================================

class ReportRead(TimestampedModel):
    """
    Full report view. Returned by ``GET /reports/{id}``.

    Once ``generation_status=ready``, ``content_hash`` and other file
    metadata are populated. Before that, they are NULL.
    """

    id: uuid.UUID
    workspace_id: uuid.UUID
    report_group_id: uuid.UUID
    regenerated_from_id: uuid.UUID | None = None
    requested_by_id: uuid.UUID | None = None

    report_type: ReportType
    report_format: str
    title: str
    summary: str | None = None

    scope_type: str
    scope_id: uuid.UUID | None = None
    period_start_at: datetime | None = None
    period_end_at: datetime | None = None

    sections: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)

    generation_status: ReportStatus
    generation_started_at: datetime | None = None
    generation_completed_at: datetime | None = None
    generation_duration_seconds: int | None = None

    error_code: str | None = None
    error_message: str | None = None

    content_hash: str | None = None
    file_size_bytes: int | None = None
    page_count: int | None = None
    integrity_verified: bool = True
    last_integrity_check_at: datetime | None = None

    is_scheduled: bool = False
    schedule_id: uuid.UUID | None = None

    shared_with: list[dict[str, Any]] = Field(default_factory=list)

    download_count: int = 0
    last_downloaded_at: datetime | None = None

    expires_at: datetime | None = None
    legal_hold_until: datetime | None = None

    metadata_json: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias="metadata",
    )

    # Computed
    is_ready: bool = Field(..., description="True if generation_status is READY.")
    is_failed: bool = Field(..., description="True if generation_status is FAILED.")
    is_pending: bool = Field(..., description="True if QUEUED or GENERATING.")
    is_expired: bool = Field(..., description="True if past expires_at.")
    is_under_legal_hold: bool = Field(
        ..., description="True if legal_hold_until is in the future.",
    )
    is_regenerated: bool = Field(
        ..., description="True if this was created by re-running an earlier report.",
    )
    is_compromised: bool = Field(
        ..., description="True if integrity verification has failed.",
    )
    file_size_mb: float | None = Field(
        default=None,
        description="File size in MB, computed for display. NULL if not yet generated.",
    )


class ReportList(ORMModel):
    """
    Lightweight report view for list pages.

    Omits ``sections``, ``parameters``, ``metadata``, and ``shared_with``
    — all of which can be large. Fetch ``GET /reports/{id}`` for
    details.
    """

    id: uuid.UUID
    report_group_id: uuid.UUID
    report_type: ReportType
    report_format: str
    title: str
    scope_type: str
    scope_id: uuid.UUID | None = None
    generation_status: ReportStatus
    generation_started_at: datetime | None = None
    generation_completed_at: datetime | None = None
    file_size_bytes: int | None = None
    page_count: int | None = None
    download_count: int = 0
    is_scheduled: bool = False
    expires_at: datetime | None = None
    created_at: datetime


# ============================================================================
# UPDATE
# ============================================================================

class ReportUpdate(CyberGuardBaseSchema):
    """
    Fields a user can change about a report.

    Cannot change:
        - ``report_type`` / ``report_format`` / ``scope_*`` /
          ``parameters`` — regenerating creates a new row
        - ``content_hash`` / ``file_size_bytes`` / ``page_count`` /
          ``integrity_verified`` — server-computed
        - ``generation_status`` — service-controlled
        - ``expires_at`` — retention policy, admin-only

    Only presentation and sharing are mutable.
    """

    title: str | None = Field(default=None, min_length=1, max_length=_TITLE_MAX)
    summary: str | None = Field(default=None, max_length=_SUMMARY_MAX)

    @field_validator("title")
    @classmethod
    def _clean_title(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        if not stripped:
            raise ValueError("title must not be empty")
        return stripped


# ============================================================================
# SHARING
# ============================================================================

class ReportShareRequest(CyberGuardBaseSchema):
    """
    Request body for ``POST /reports/{id}/share``.

    Adds a specific user to the report's ``shared_with`` list. Sharing
    grants read access to the report file even if the user isn't the
    requestor or a workspace member.
    """

    user_id: uuid.UUID = Field(...)
    expires_at: datetime | None = Field(
        default=None,
        description=(
            "Optional time limit for the share. After expiry, the user "
            "can no longer download the report. Recommended for client "
            "sharing."
        ),
    )

    @field_validator("expires_at")
    @classmethod
    def _validate_expiry(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        from datetime import datetime as dt, timezone
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        if v <= dt.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return v


class ReportUnshareRequest(CyberGuardBaseSchema):
    """Request body for ``POST /reports/{id}/unshare``."""

    user_id: uuid.UUID = Field(...)


# ============================================================================
# FILTER
# ============================================================================

class ReportFilter(CyberGuardBaseSchema):
    """
    Query parameters for filtering ``GET /reports``.
    """

    report_type: ReportType | None = None
    report_format: str | None = Field(
        default=None,
        description="pdf | csv | json | html | xlsx",
    )
    generation_status: ReportStatus | None = None

    scope_type: str | None = None
    scope_id: uuid.UUID | None = None

    report_group_id: uuid.UUID | None = None
    requested_by_id: uuid.UUID | None = None

    is_scheduled: bool | None = None

    has_expired: bool | None = None

    created_after: datetime | None = None
    created_before: datetime | None = None

    title_contains: str | None = Field(
        default=None, max_length=_TITLE_MAX,
    )

    @field_validator("report_format")
    @classmethod
    def _validate_format(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _REPORT_FORMATS:
            raise ValueError(
                f"report_format must be one of {sorted(_REPORT_FORMATS)}"
            )
        return normalized

    @field_validator("scope_type")
    @classmethod
    def _validate_scope_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = v.strip().lower()
        if normalized not in _SCOPE_TYPES:
            raise ValueError(
                f"scope_type must be one of {sorted(_SCOPE_TYPES)}"
            )
        return normalized

    @field_validator("title_contains")
    @classmethod
    def _clean_contains(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


# ============================================================================
# DOWNLOAD INFO
# ============================================================================

class ReportDownloadInfo(CyberGuardBaseSchema):
    """
    Metadata about a downloadable report. Returned as response headers
    by ``GET /reports/{id}/download`` — the actual body is the file
    bytes.
    """

    report_id: uuid.UUID
    title: str
    report_format: str
    file_size_bytes: int
    content_hash: str

    verified_at_request: bool = Field(
        ...,
        description=(
            "True if the SHA-256 hash was re-verified at download time. "
            "If False, ``integrity_verified`` on the report row is now "
            "also False and an alert was written."
        ),
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ReportCreate",
    "ReportRead",
    "ReportList",
    "ReportUpdate",
    "ReportShareRequest",
    "ReportUnshareRequest",
    "ReportFilter",
    "ReportDownloadInfo",
]