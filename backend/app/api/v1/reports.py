"""
CyberGuard AI — Report Endpoints
============================================================================

Report request, listing, download, and sharing.

Eight endpoints:

    GET    /reports                 — list with filters
    GET    /reports/{id}            — detail
    POST   /reports                 — request generation (async, returns QUEUED)
    POST   /reports/{id}/generate   — synchronous trigger (dev/test/admin)
    GET    /reports/{id}/download   — binary download with integrity headers
    POST   /reports/{id}/share      — share with a user
    POST   /reports/{id}/unshare    — remove a share
    DELETE /reports/{id}            — soft delete

Async generation model
----------------------
``POST /reports`` creates a QUEUED row and returns immediately. Actual
generation happens in a background worker. For development and admin
override, ``POST /reports/{id}/generate`` triggers synchronous
generation inline — useful when:
    - Testing the flow without a worker running
    - Manually retrying a FAILED report
    - Admin needs a report "now" and can tolerate the blocking call

The synchronous endpoint is marked as such in Swagger and OpenAPI. It
can be disabled in production via a settings flag (future — for now
it's always available; the endpoint itself requires authentication and
respects all report permissions).

Binary download with integrity headers
--------------------------------------
The download endpoint returns the file bytes with the same integrity
signals as evidence:

    Content-Type:            from the report format (pdf, csv, json, html)
    Content-Disposition:     attachment with the report title as filename
    Content-Length:          file size
    X-Content-Hash:          SHA-256 of the file bytes returned
    X-Integrity-Verified:    "true" or "false"

The frontend renders a warning banner when the header is "false".
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Query,
    Response,
    status,
)

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
from app.schemas.common import (
    MessageResponse,
    PageMeta,
    PaginatedResponse,
)
from app.schemas.report import (
    ReportCreate,
    ReportFilter,
    ReportList,
    ReportRead,
    ReportShareRequest,
    ReportUnshareRequest,
    ReportUpdate,
)
from app.services import (
    authorization,
    report_service,
)


logger = get_logger(__name__)


router = APIRouter(
    prefix="/reports",
    tags=["reports"],
)


# ============================================================================
# INTERNAL — safe filename for Content-Disposition
# ============================================================================

def _safe_content_disposition(title: str, fmt: str) -> str:
    """
    Build a Content-Disposition header for a report download.

    Uses the report title with a format-derived extension. Same RFC 6266
    sanitization as evidence downloads.
    """
    # Strip characters not allowed in filenames
    safe = "".join(
        c if (32 <= ord(c) < 127 and c not in ('"', '\\', ';', '/', ':')) else "_"
        for c in title
    ) or "report"
    filename = f"{safe}.{fmt}"
    from urllib.parse import quote
    return (
        f'attachment; filename="{filename}"; '
        f"filename*=UTF-8''{quote(filename, safe='')}"
    )


# ============================================================================
# LIST
# ============================================================================

@router.get(
    "",
    response_model=PaginatedResponse[ReportList],
    summary="List reports",
    description=(
        "Paginated list of reports across the user's accessible "
        "workspaces. Requires `report:read` permission.\n\n"
        "Returns lightweight `ReportList` rows. Fetch `GET /reports/{id}` "
        "for full details including sections and parameters."
    ),
)
def list_reports(
    current_user: CurrentActiveUser,
    db: DBDep,
    page: PageDep,
    filters: ReportFilter = Depends(),
    workspace_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Filter to a specific workspace. If omitted, results span "
            "all workspaces the user is a member of."
        ),
    ),
) -> PaginatedResponse[ReportList]:
    if workspace_id is not None:
        authorization.check_permission(
            db, current_user, "report:read", workspace_id=workspace_id,
        )
        workspace_ids = [workspace_id]
    else:
        workspace_ids = authorization.get_user_workspaces(db, current_user)
        if not workspace_ids:
            return PaginatedResponse[ReportList](
                items=[], meta=PageMeta.build(total=0, params=page),
            )

    reports, total = report_service.list_reports(
        db,
        workspace_ids=workspace_ids,
        page=page,
        filters=filters,
    )

    return PaginatedResponse[ReportList](
        items=[ReportList.model_validate(r) for r in reports],
        meta=PageMeta.build(total=total, params=page),
    )


# ============================================================================
# DETAIL
# ============================================================================

@router.get(
    "/{report_id}",
    response_model=ReportRead,
    summary="Get a report by ID",
    description=(
        "Full report detail including generation status, sections, "
        "parameters, and sharing list. Requires `report:read` on the "
        "report's workspace, or that the user is a share recipient."
    ),
)
def get_report(
    report_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.get_by_id(db, report_id)

    # Access: requester, share recipient, or workspace member with report:read
    if report.requested_by_id != current_user.id:
        if not report_service._is_shared_with(report, current_user.id):
            authorization.check_permission(
                db, current_user, "report:read",
                workspace_id=report.workspace_id,
            )

    return ReportRead.model_validate(report)


# ============================================================================
# CREATE (request generation)
# ============================================================================

@router.post(
    "",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    summary="Request a report (async)",
    description=(
        "Queues a report for background generation. Returns immediately "
        "with `generation_status=queued`. The client should poll "
        "`GET /reports/{id}` until `generation_status=ready` (or "
        "`failed`), then download via `GET /reports/{id}/download`.\n\n"
        "Requires `report:create` permission. Supported formats: pdf, "
        "csv, json, html. XLSX is not yet supported (returns 400)."
    ),
    responses={
        201: {"description": "Report queued."},
        400: {"description": "Invalid request (bad format, missing scope_id, etc.)."},
        403: {"description": "Permission denied."},
    },
)
def request_report(
    body: ReportCreate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.request_report(
        db, actor=current_user, payload=body,
    )
    db.commit()

    logger.info(
        "Report requested via API",
        extra={
            "report_id": str(report.id),
            "report_type": body.report_type.value,
            "report_format": body.report_format,
            "actor_id": str(current_user.id),
        },
    )

    return ReportRead.model_validate(report)


# ============================================================================
# SYNCHRONOUS GENERATION
# ============================================================================

@router.post(
    "/{report_id}/generate",
    response_model=ReportRead,
    summary="Generate a report synchronously",
    description=(
        "**Development and admin override endpoint.** Triggers generation "
        "inline instead of waiting for the background worker.\n\n"
        "Use cases:\n"
        "- Testing without a worker running\n"
        "- Retrying a `failed` report after fixing the underlying issue\n"
        "- Admin needs a report immediately\n\n"
        "Blocks the request until generation completes (a few seconds for "
        "typical reports). Requires `report:create` permission and that "
        "the report is in `queued` or `failed` status."
    ),
)
def generate_report(
    report_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.get_by_id(db, report_id)

    authorization.check_permission(
        db, current_user, "report:create",
        workspace_id=report.workspace_id,
    )

    # Only allow regen from QUEUED or FAILED — don't clobber a READY report
    from app.models.enums import ReportStatus
    if report.generation_status == ReportStatus.READY:
        raise ValidationError(
            message=(
                "Report is already generated. To regenerate, create a "
                "new report with `regenerated_from_id` set to this one."
            ),
            code="REPORT_ALREADY_READY",
        )
    if report.generation_status == ReportStatus.GENERATING:
        raise ValidationError(
            message="Report is already being generated.",
            code="REPORT_GENERATING",
        )

    # If FAILED, reset to QUEUED so start_generation can proceed
    if report.generation_status == ReportStatus.FAILED:
        report.generation_status = ReportStatus.QUEUED
        db.flush()

    try:
        generated = report_service.generate_report(
            db, report=report, generated_by=current_user,
        )
        db.commit()
    except Exception:
        # generate_report flushes FAILED status internally — commit
        # that state so the client sees the failure
        db.commit()
        raise

    return ReportRead.model_validate(generated)


# ============================================================================
# DOWNLOAD (binary)
# ============================================================================

@router.get(
    "/{report_id}/download",
    summary="Download a generated report",
    description=(
        "Streams the report file bytes. **Verifies integrity on every "
        "download** — if the file on disk has been tampered with, "
        "`X-Integrity-Verified: false` is set and the report is marked "
        "compromised. The file is still returned (forensic value).\n\n"
        "Increments `download_count`. Requires the report to be in "
        "`ready` status."
    ),
    responses={
        200: {
            "description": "Report file returned.",
            "headers": {
                "Content-Disposition": {"description": "Attachment filename"},
                "X-Content-Hash": {"description": "SHA-256 of the bytes"},
                "X-Integrity-Verified": {"description": "true or false"},
            },
        },
        400: {"description": "Report is not ready."},
        403: {"description": "Access denied."},
        404: {"description": "Report not found."},
    },
)
def download_report(
    report_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> Response:
    report = report_service.get_by_id(db, report_id)

    result = report_service.prepare_download(
        db, actor=current_user, report=report,
    )
    db.commit()

    headers = {
        "Content-Disposition": _safe_content_disposition(
            result.title, result.report_format,
        ),
        "Content-Length": str(len(result.file_bytes)),
        "X-Content-Hash": result.content_hash,
        "X-Integrity-Verified": "true" if result.verified else "false",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }

    logger.info(
        "Report downloaded",
        extra={
            "report_id": str(report_id),
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
# UPDATE (metadata)
# ============================================================================

@router.patch(
    "/{report_id}",
    response_model=ReportRead,
    summary="Update report metadata",
    description=(
        "Update title or summary. Cannot change the report type, format, "
        "parameters, or content — those are immutable once the report is "
        "created. To regenerate with different parameters, create a new "
        "report with `regenerated_from_id` set to this one."
    ),
)
def update_report(
    report_id: uuid.UUID,
    body: ReportUpdate,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.get_by_id(db, report_id)

    # Only the requester or workspace owner can edit
    if report.requested_by_id != current_user.id:
        from app.models.enums import WorkspaceRole
        ws_role = authorization.get_user_workspace_role(
            db, current_user, report.workspace_id,
        )
        if ws_role != WorkspaceRole.OWNER:
            from app.core.exceptions import AuthorizationError
            raise AuthorizationError(
                message="You cannot edit this report.",
                code="REPORT_EDIT_DENIED",
            )

    updates = body.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(report, field, value)
    db.flush()
    db.commit()
    return ReportRead.model_validate(report)


# ============================================================================
# SHARING
# ============================================================================

@router.post(
    "/{report_id}/share",
    response_model=ReportRead,
    summary="Share a report with a user",
    description=(
        "Adds a specific user to the report's sharing list. Shared "
        "users get read access to the file even if they're not a "
        "workspace member. Optional `expires_at` auto-revokes the share "
        "after the deadline.\n\n"
        "Only the report's requester or a workspace OWNER can share it."
    ),
)
def share_report(
    report_id: uuid.UUID,
    body: ReportShareRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.get_by_id(db, report_id)
    updated = report_service.share_report(
        db,
        actor=current_user,
        report=report,
        user_id=body.user_id,
        expires_at=body.expires_at,
    )
    db.commit()
    return ReportRead.model_validate(updated)


@router.post(
    "/{report_id}/unshare",
    response_model=ReportRead,
    summary="Remove a user's share",
    description="Removes a user from the report's sharing list. Idempotent."
)
def unshare_report(
    report_id: uuid.UUID,
    body: ReportUnshareRequest,
    current_user: CurrentActiveUser,
    db: DBDep,
) -> ReportRead:
    report = report_service.get_by_id(db, report_id)
    updated = report_service.unshare_report(
        db,
        actor=current_user,
        report=report,
        user_id=body.user_id,
    )
    db.commit()
    return ReportRead.model_validate(updated)


# ============================================================================
# DELETE (soft)
# ============================================================================

@router.delete(
    "/{report_id}",
    response_model=MessageResponse,
    summary="Soft-delete a report",
    description=(
        "Marks the report as deleted. The row and file stay for retention "
        "until the retention cleanup removes them (respecting legal hold). "
        "Requires the report's requester or a workspace OWNER."
    ),
)
def delete_report(
    report_id: uuid.UUID,
    current_user: CurrentActiveUser,
    db: DBDep,
    reason: str = Body(embed=True, min_length=1, max_length=500),
) -> MessageResponse:
    report = report_service.get_by_id(db, report_id)
    report_service.delete_report(
        db,
        actor=current_user,
        report=report,
        reason=reason,
    )
    db.commit()
    return MessageResponse(message="Report marked for deletion.")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = ["router"]