"""
CyberGuard AI - Database Models Package

Exports all database models for easy importing.
"""

# Base models (existing)
from app.database.models.base import (
    EventType,
    EventStatus,
    SeverityLevel,
    AlertStatus,
    Event,
    EventCreate,
    Finding,
    FindingStatus,
    FindingCreate,
    FindingQuery,
    Alert,
    AlertCreate,
    AlertUpdate,
    IOCRecord,
    NotificationChannel,
    NotificationStatus,
    Notification,
    NotificationCreate,
)

# Step 12: Feedback models
from app.database.models.feedback import (
    FeedbackType,
    FeedbackStatus,
    EmailFeedback,
    AnalysisHistory,
)
from app.database.models.incidents import (
    Incident,
    IncidentCreate,
    IncidentStatus,
    Report,
    ReportCreate,
    ReportStatus,
    ReportFormat,
)

__all__ = [
    # Base models
    "EventType",
    "EventStatus",
    "SeverityLevel",
    "AlertStatus",
    "Event",
    "EventCreate",
    "Finding",
    "FindingStatus",
    "FindingCreate",
    "FindingQuery",
    "Alert",
    "AlertCreate",
    "AlertUpdate",
    "IOCRecord",
    "NotificationChannel",
    "NotificationStatus",
    "Notification",
    "NotificationCreate",
    # Step 12 models
    "FeedbackType",
    "FeedbackStatus",
    "EmailFeedback",
    "AnalysisHistory",
    "Incident",
    "IncidentCreate",
    "IncidentStatus",
    "Report",
    "ReportCreate",
    "ReportStatus",
    "ReportFormat",
]
