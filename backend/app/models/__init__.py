"""
CyberGuard AI — Model Registry
============================================================================
Imports every ORM model class so that Alembic and SQLAlchemy discover all tables.
"""

from __future__ import annotations

# ── 1. Users
from app.models.user import User

# ── 2. Organizations
from app.models.organization import Organization

# ── 3. Workspaces
from app.models.workspace import Workspace

# ── 4. Memberships
from app.models.membership import OrganizationMembership, WorkspaceMembership

# ── 5. Analyst profiles
from app.models.analyst import AnalystProfile

# ── 6. Security sources
from app.models.source import SecuritySource, SourceCredential

# ── 7. Source enrollments
from app.models.enrollment import SourceEnrollment

# ── 8. Collector credentials
from app.models.collector_credential import CollectorCredential

# ── 9. Security events
from app.models.event import SecurityEvent

# ── 10. Agent findings
from app.models.finding import AgentFinding

# ── 11. Security alerts
from app.models.alert import SecurityAlert

# ── 12. Security incidents
from app.models.incident import SecurityIncident, IncidentEventLink

# ── 13. Security cases
from app.models.case import SecurityCase, CaseAssignment, CaseAccessGrant

# ── 14. Evidence
from app.models.evidence import SecurityEvidence

# ── 15. Conversations
from app.models.conversation import (
    CaseConversation,
    CaseMessage,
    MessageAttachment,
)

# ── 16. Notifications
from app.models.notification import Notification

# ── 17. Reports
from app.models.report import SecurityReport

# ── 18. Organization invitations
from app.models.invitation import OrganizationInvitation

# ── 19. Marketplace
from app.models.marketplace import (
    AnalystServiceOffering,
    ServicePurchase,
    PaymentTransaction,
)

# ── 20. Audit logs
from app.models.audit import SecurityAuditLog

# ── 21. Rooms
from app.models.room import Room, RoomMember, RoomInvitation, RoomMessage
from app.models.direct_message import DirectMessage

__all__: list[str] = [
    "User",
    "Organization",
    "Workspace",
    "OrganizationMembership",
    "WorkspaceMembership",
    "AnalystProfile",
    "SecuritySource",
    "SourceCredential",
    "SourceEnrollment",
    "CollectorCredential",
    "SecurityEvent",
    "AgentFinding",
    "SecurityAlert",
    "SecurityIncident",
    "IncidentEventLink",
    "SecurityCase",
    "CaseAssignment",
    "CaseAccessGrant",
    "SecurityEvidence",
    "CaseConversation",
    "CaseMessage",
    "MessageAttachment",
    "Notification",
    "SecurityReport",
    "OrganizationInvitation",
    "AnalystServiceOffering",
    "ServicePurchase",
    "PaymentTransaction",
    "SecurityAuditLog",
    "Room",
    "RoomMember",
    "RoomInvitation",
    "RoomMessage",
    "DirectMessage",
]
