"""
CyberGuard AI — Common Pydantic Schemas
============================================================================

Base schemas used by every other schema file. This is the foundation of
the schemas layer — consistency here means consistency everywhere.

What's here
-----------
    CyberGuardBaseSchema   — root base for all schemas
    ORMModel               — base for *Read schemas (from_attributes=True)
    TimestampedModel       — ORMModel + created_at/updated_at
    PageParams             — pagination query params
    SortParams             — sort query params
    PageMeta               — pagination response metadata
    PaginatedResponse[T]   — generic paginated response
    ErrorDetail            — structured error info
    ErrorResponse          — API error envelope
    SuccessResponse        — generic success envelope
    IdResponse             — {"id": "..."} response
    MessageResponse        — {"message": "..."} response
    IdParams               — path param wrapper

Design rules
------------
1. **`extra="forbid"` on the root base.** Any schema inheriting from
   `CyberGuardBaseSchema` rejects unknown fields by default. Prevents
   silent typos in client requests. *Read schemas override to
   `extra="ignore"` for forward compatibility with model changes.

2. **`from_attributes=True` on `ORMModel`.** Every *Read schema inherits
   this, so `UserRead.model_validate(user_orm)` works directly.

3. **`PaginatedResponse[T]` is generic.** Python 3.12 generic syntax.
   `PaginatedResponse[UserRead]` gives correctly typed items.

4. **`PageParams` computes offset/limit from page/page_size.** Services
   use offset/limit directly. Business logic never sees "page".

5. **`ErrorResponse` matches `CyberGuardError.to_dict()` format.**
   Consistent shape across the entire API.

6. **No DB, no imports from app.models.** This file imports only from
   `pydantic`, `app.core.constants`, and stdlib.

7. **Standard envelopes for common responses.** `MessageResponse` and
   `IdResponse` prevent API drift from ad-hoc `{"ok": true}`.

Usage
-----
    from app.schemas.common import (
        CyberGuardBaseSchema, ORMModel, TimestampedModel,
        PageParams, PaginatedResponse, PageMeta, ErrorResponse,
    )

    class UserCreate(CyberGuardBaseSchema):
        email: EmailStr
        password: str

    class UserRead(ORMModel):
        id: UUID
        email: EmailStr
        created_at: datetime

    @router.get("/users")
    def list_users(
        page: PageParams = Depends(),
    ) -> PaginatedResponse[UserRead]:
        ...
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    MIN_PAGE_SIZE,
    SORT_ORDERS,
)


# ============================================================================
# BASE SCHEMAS
# ============================================================================

class CyberGuardBaseSchema(BaseModel):
    """
    Root base for every request schema.

    Enforces:
        - `extra="forbid"` — reject unknown fields
        - `str_strip_whitespace=True` — trim leading/trailing whitespace
        - `validate_assignment=True` — re-validate on attribute assignment
        - `use_enum_values=True` — serialize enums as their string value
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=True,
        populate_by_name=True,   # allow field aliases
        from_attributes=False,   # request schemas don't come from ORM
    )


class ORMModel(BaseModel):
    """
    Base for *Read schemas. Enables `from_attributes=True` so a
    SQLAlchemy model instance can be passed to `model_validate()`.

    Overrides `extra` to `"ignore"` so new model fields that a Read
    schema hasn't declared yet are silently dropped (forward compat).
    """

    model_config = ConfigDict(
        extra="ignore",
        use_enum_values=True,
        populate_by_name=True,
        from_attributes=True,
    )


class TimestampedModel(ORMModel):
    """
    Read base with `created_at` and `updated_at` fields.

    Most *Read schemas inherit from this instead of `ORMModel` directly.
    Schemas that don't want timestamps (e.g. lightweight List variants)
    stay on plain `ORMModel`.
    """

    created_at: datetime = Field(
        ..., description="Row creation timestamp (UTC)"
    )

    updated_at: datetime | None = Field(
        None, description="Row last-updated timestamp (UTC)"
    )


# ============================================================================
# PAGINATION
# ============================================================================

class PageParams(BaseModel):
    """
    Query parameters for paginated endpoints.

    Usage in an endpoint:
        @router.get("/users")
        def list_users(page: PageParams = Depends()):
            users = svc.list_users(offset=page.offset, limit=page.limit)
            return build_page(users, page, total)

    Attributes
    ----------
    page : int
        1-indexed page number (first page = 1).
    page_size : int
        Items per page. Capped at MAX_PAGE_SIZE (default 200).
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    page: int = Field(
        default=1,
        ge=1,
        le=10_000,
        description="1-indexed page number",
    )

    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=MIN_PAGE_SIZE,
        le=MAX_PAGE_SIZE,
        description="Items per page",
    )

    @property
    def offset(self) -> int:
        """SQL OFFSET (0-indexed). Services use this directly."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """SQL LIMIT. Services use this directly."""
        return self.page_size


class SortParams(BaseModel):
    """
    Query parameters for sorting.

    The `sort_by` value must be validated against an allowlist in each
    endpoint (it's a column name — SQL injection risk if used raw).
    Only `sort_order` is validated here against the closed set.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    sort_by: str | None = Field(
        default=None,
        max_length=64,
        description="Column to sort by. Validated per endpoint.",
    )

    sort_order: str = Field(
        default="desc",
        description="Sort direction: 'asc' or 'desc'",
    )

    @field_validator("sort_order")
    @classmethod
    def _validate_sort_order(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in SORT_ORDERS:
            raise ValueError(f"sort_order must be one of {SORT_ORDERS}")
        return normalized


class PageMeta(BaseModel):
    """
    Pagination metadata returned in every paginated response.

    Includes pre-computed `has_next` / `has_prev` so frontend clients
    don't need math.
    """

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0, description="Total items across all pages")
    page: int = Field(..., ge=1, description="Current page (1-indexed)")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total pages")

    @classmethod
    def build(cls, total: int, params: PageParams) -> "PageMeta":
        """
        Construct from a total count and the query parameters.
        Handles the `total=0` edge case (total_pages=0, has_next=False).
        """
        total_pages = math.ceil(total / params.page_size) if total > 0 else 0
        return cls(
            total=total,
            page=params.page,
            page_size=params.page_size,
            total_pages=total_pages,
        )

    @property
    def has_next(self) -> bool:
        """True if there are more pages after this one."""
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        """True if there are pages before this one."""
        return self.page > 1


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Standard envelope for paginated list responses.

    Usage:
        return PaginatedResponse[UserRead](
            items=[UserRead.model_validate(u) for u in users],
            meta=PageMeta.build(total=total, params=page),
        )
    """

    model_config = ConfigDict(extra="forbid")

    items: list[T] = Field(..., description="Items in this page")
    meta: PageMeta = Field(..., description="Pagination metadata")


# ============================================================================
# ERROR & STATUS RESPONSES
# ============================================================================

class ErrorDetail(BaseModel):
    """
    Structured error information.

    Matches the shape produced by `CyberGuardError.to_dict()` so the
    exception handler's output validates against this schema.
    """

    model_config = ConfigDict(extra="forbid")

    code: str = Field(
        ..., description="Machine-readable error code (e.g. 'AUTH_INVALID_TOKEN')"
    )
    message: str = Field(
        ..., description="Human-readable error message"
    )
    details: dict[str, Any] | None = Field(
        None,
        description="Optional structured details (fields, thresholds, etc.)",
    )
    correlation_id: str | None = Field(
        None,
        description="Request correlation ID for trace joins",
    )


class ErrorResponse(BaseModel):
    """
    Envelope for error responses.

    Every error returned by the API has this shape:
        {
            "error": {
                "code": "...",
                "message": "...",
                "details": {...} or null,
                "correlation_id": "..." or null
            }
        }

    The FastAPI exception handler for `CyberGuardError` produces this
    automatically — do not construct ErrorResponse manually in endpoints.
    """

    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail


class SuccessResponse(BaseModel):
    """
    Generic success envelope for operations without a specific payload
    (DELETE, acknowledgement, etc.).

    Prefer this over ad-hoc `{"ok": true}` / `{"success": 1}` shapes.
    """

    model_config = ConfigDict(extra="forbid")

    success: bool = Field(default=True)
    message: str | None = Field(default=None)


class IdResponse(BaseModel):
    """
    Response containing just an ID (for create operations where the
    client only needs the new entity's id).
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="ID of the created entity")


class MessageResponse(BaseModel):
    """
    Response containing just a message (for status operations).
    """

    model_config = ConfigDict(extra="forbid")

    message: str


# ============================================================================
# PATH PARAMETER HELPER
# ============================================================================

class IdParams(BaseModel):
    """
    Path parameter wrapper for endpoints that take a UUID ID.

    Used as:
        @router.get("/users/{id}")
        def get_user(path: IdParams = Depends()):
            return svc.get_user(path.id)
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(..., description="Entity UUID")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Base schemas
    "CyberGuardBaseSchema",
    "ORMModel",
    "TimestampedModel",
    # Pagination
    "PageParams",
    "SortParams",
    "PageMeta",
    "PaginatedResponse",
    # Responses
    "ErrorDetail",
    "ErrorResponse",
    "SuccessResponse",
    "IdResponse",
    "MessageResponse",
    # Path params
    "IdParams",
]