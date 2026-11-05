"""Typed persistence contract for tenant-scoped security incidents and reports."""

from datetime import datetime
from typing import Any
from enum import Enum

from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    """Incident lifecycle states."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINMENT_IN_PROGRESS = "containment_in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    id: str
    tenant_id: str
    fingerprint: str
    title: str
    description: str
    severity: str
    status: str
    finding_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime


class IncidentCreate(BaseModel):
    tenant_id: str
    fingerprint: str
    title: str
    description: str
    severity: str
    finding_id: str
    event_id: str
    recommendations: list[str] = Field(default_factory=list)
    created_by: str | None = None


class ReportStatus(str, Enum):
    """Report generation status."""
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, Enum):
    """Report output format."""
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"


class Report(BaseModel):
    """A generated security report."""
    id: str
    tenant_id: str
    report_type: str
    title: str
    description: str | None = None
    generated_by: str
    period_start: datetime | None = None
    period_end: datetime | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    narrative: str | None = None
    file_path: str | None = None
    file_format: ReportFormat = ReportFormat.JSON
    file_size_bytes: int | None = None
    status: ReportStatus = ReportStatus.COMPLETED
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime


class ReportCreate(BaseModel):
    """Schema for creating a report."""
    tenant_id: str
    report_type: str
    title: str
    description: str | None = None
    generated_by: str
    period_start: datetime | None = None
    period_end: datetime | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    narrative: str | None = None
    file_format: ReportFormat = ReportFormat.JSON
