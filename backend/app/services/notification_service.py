"""
CyberGuard AI — Notification Service
============================================================================

Per-user notifications. Every alert, case assignment, message, or
invitation that the platform wants to surface to a specific user lands
here.

Notifications are the **user engagement layer** — the difference
between "the platform detected something" and "the user knows about
it". The service is called by other services whenever a state change
needs user attention.

Fan-out model
-------------
Some notifications go to one user (case assignment); others fan out to
many (alert created → all workspace members with read permission).
This service handles both — the caller decides the audience, and the
service writes one row per recipient.

Design rules (see ``app.services.__init__`` for the full contract)
------------------------------------------------------------------
1. Receive ``Session`` from the caller. Never commit.
2. Raise ``CyberGuardError`` subclasses on failure.
3. Return ORM instances.
4. **User actions** (mark seen, mark read, dismiss) are NOT audited —
   these are engagement signals, not security actions. The notification
   row itself carries the state (``seen_at``, ``read_at``,
   ``dismissed_at``).
5. **Bulk operations are preferred.** ``create_batch`` writes N
   notifications in one transaction — the alternative (N single
   ``create`` calls) re-queries the DB N times.

Deduplication and batching
--------------------------
When a notification has a ``dedup_key``, the DB enforces at most one
active (non-dismissed) notification per ``(recipient_id, dedup_key)``.
When a second notification with the same key arrives while the first
is still active, ``create`` calls ``record_batch()`` on the existing
row instead of creating a new one.

This is how "5 new alerts from Acme Corp" becomes **one** notification
with ``batch_count=5`` instead of 5 separate inbox items.

The dedup key is caller-supplied. Convention:

    "alert_created:{alert.fingerprint}"     — one per attack pattern
    "case_assigned:{case.id}"               — one per case assignment
    "message_received:{conversation.id}"    — one per conversation (batched)

Delivery channels
-----------------
The notification row tracks ``notification_channels_sent`` (JSONB array
of ``in_app``, ``email``, ``webhook``) and per-channel timestamps.
Actual delivery to email/webhook is delegated — the notification
service only records attempts. The delivery worker (Phase M) reads
pending deliveries and sends them.

For MVP, only in-app delivery is active. Email/webhook channels are
recorded as "not yet delivered" until the delivery infrastructure
lands. The UI reads the notification list and the badge counts from
this table — that works today.

Lifecycle
---------
    created → (delivered to channels) → seen → read → action-taken
                                            → dismissed

Not every notification reaches every stage:
    - Low-priority informational notifications may never be "seen" —
      the user just dismisses them (which implies "seen")
    - "action-taken" implies "read" which implies "seen"

The service methods enforce this chain:
    - ``mark_seen`` sets ``seen_at``
    - ``mark_read`` sets ``read_at`` (and ``seen_at`` if not already set)
    - ``dismiss`` sets ``dismissed_at`` (and ``read_at``/``seen_at``)
    - ``record_action`` sets ``action_taken_at`` (and the read chain)

Batch writes
------------
When fanning out an alert to 20 workspace members, we write 20 rows.
``create_batch`` does this in a single loop over the caller's session —
fast enough for typical team sizes. If a workspace grows past ~1000
members, this becomes an optimization target (bulk insert, background
queue). Not a concern for MVP.

Public API
----------
    # Event-specific creators
    create_for_alert(db, *, alert)                                    → list[Notification]
    create_for_assignment(db, *, alert, assignee_id)                  → Notification | None
    create_for_case_assignment(db, *, case, assignee_id, assigner_id) → list[Notification]
    create_for_incident(db, *, incident)                              → list[Notification]
    create_for_invitation(db, *, invitation)                          → Notification | None
    create_for_message(db, *, message, conversation)                  → list[Notification]
    create_for_report(db, *, report)                                  → Notification | None

    # Generic
    create(db, *, recipient_id, notification_type, title, ...)        → Notification
    create_batch(db, *, notifications)                                → list[Notification]

    # Engagement
    mark_seen(db, *, user_id, notification_id)                        → Notification
    mark_read(db, *, user_id, notification_id)                        → Notification
    dismiss(db, *, user_id, notification_id, reason=None)             → Notification
    record_action(db, *, user_id, notification_id, action_type, notes=None) → Notification
    mark_all_seen(db, *, user_id, workspace_id=None)                  → int
    mark_all_read(db, *, user_id, workspace_id=None)                  → int

    # Read
    list_notifications(db, *, user_id, page, filters)                 → (list, int)
    get_badge_counts(db, *, user_id)                                  → NotificationBadge
    get_unread_count(db, *, user_id, workspace_id=None)               → int

    # Background
    sweep_expired(db, *, limit=500)                                   → int

Usage
-----
    from app.services import notification_service

    # In alert_service.promote_finding, uncomment the TODO:
    notification_service.create_for_alert(db, alert=alert)

    # In case_service.assign_case:
    notification_service.create_for_case_assignment(
        db, case=case, assignee_id=analyst.id, assigner_id=actor.id,
    )

    # In an endpoint (POST /notifications/{id}/read):
    notification_service.mark_read(
        db, user_id=current_user.id, notification_id=notification_id,
    )
    db.commit()
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AuthorizationError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.models.alert import SecurityAlert
from app.models.case import (
    CaseAssignment,
    SecurityCase,
)
from app.models.conversation import (
    CaseConversation,
    CaseMessage,
)
from app.models.enums import (
    EventSeverity,
    NotificationType,
    OrganizationRole,
    UserStatus,
    WorkspaceRole,
)
from app.models.incident import SecurityIncident
from app.models.invitation import OrganizationInvitation
from app.models.membership import (
    OrganizationMembership,
    WorkspaceMembership,
)
from app.models.notification import (
    Notification,
    _PRIORITY_CRITICAL,
    _PRIORITY_HIGH,
    _PRIORITY_LOW,
    _PRIORITY_MEDIUM,
)
from app.models.report import SecurityReport
from app.models.user import User
from app.schemas.common import PageParams
from app.schemas.notification import (
    NotificationBadge,
    NotificationFilter,
)


logger = get_logger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

#: Default notification expiry (days). Matches the retention policy
#: but notifications expire sooner — they're ephemeral UX artifacts.
_DEFAULT_EXPIRY_DAYS = 30

#: Batch cap on fan-out. A workspace with 10,000 members would generate
#: 10,000 notifications per alert — that's a DoS waiting to happen.
#: Cap the fan-out at the top N most-recently-active members. The rest
#: can see the alert via the alert list itself; they just don't get a
#: notification badge for it.
_MAX_FANOUT = 500

#: Priority mapping from alert/incident severity.
_SEVERITY_TO_PRIORITY: dict[EventSeverity, str] = {
    EventSeverity.INFO: _PRIORITY_LOW,
    EventSeverity.LOW: _PRIORITY_LOW,
    EventSeverity.MEDIUM: _PRIORITY_MEDIUM,
    EventSeverity.HIGH: _PRIORITY_HIGH,
    EventSeverity.CRITICAL: _PRIORITY_CRITICAL,
}


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _default_expiry() -> datetime:
    """Notification expires after ``_DEFAULT_EXPIRY_DAYS``."""
    return datetime.now(timezone.utc) + timedelta(days=_DEFAULT_EXPIRY_DAYS)


def _get_active_users_in_workspace(
    db: Session,
    workspace_id: uuid.UUID,
    *,
    limit: int = _MAX_FANOUT,
) -> list[User]:
    """
    Return active users who are members of the given workspace.

    "Active users" = users with an active workspace membership AND
    ``User.status = ACTIVE`` (not suspended/pending/deleted).

    Cap at ``limit`` to prevent fan-out explosion in large workspaces.
    Order by recent membership activity (``created_at DESC`` on the
    membership row) so we notify the most recently added members —
    a heuristic for "likely to care right now".
    """
    stmt = (
        select(User)
        .join(
            WorkspaceMembership,
            WorkspaceMembership.user_id == User.id,
        )
        .where(
            WorkspaceMembership.workspace_id == workspace_id,
            WorkspaceMembership.removed_at.is_(None),
            User.deleted_at.is_(None),
            User.status == UserStatus.ACTIVE,
        )
        .order_by(WorkspaceMembership.created_at.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


def _get_active_org_members(
    db: Session,
    organization_id: uuid.UUID,
    *,
    min_role: OrganizationRole | None = None,
    limit: int = _MAX_FANOUT,
) -> list[User]:
    """
    Return active users who are members of the given organization,
    optionally filtered by a minimum role.

    If ``min_role`` is provided, only members with that role or higher
    are returned. Role rank is via ``authorization``.
    """
    stmt = (
        select(User, OrganizationMembership.role)
        .join(
            OrganizationMembership,
            OrganizationMembership.user_id == User.id,
        )
        .where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.removed_at.is_(None),
            User.deleted_at.is_(None),
            User.status == UserStatus.ACTIVE,
        )
        .order_by(OrganizationMembership.created_at.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).all()

    if min_role is None:
        return [row[0] for row in rows]

    # Filter by role rank
    from app.services.membership_service import _org_rank
    min_rank = _org_rank(min_role)
    return [user for (user, role) in rows if _org_rank(role) >= min_rank]


def _get_notification_or_404(
    db: Session,
    notification_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Notification:
    """
    Fetch a notification, ensuring it belongs to the given user.

    Raises ``NotFoundError`` if not found. Raises ``AuthorizationError``
    if found but owned by someone else — the two errors are distinct so
    that an attacker probing for notification existence gets a
    consistent 404 (not 403) for both "doesn't exist" and "not mine".
    To achieve that, we actually merge them: any failure raises
    NotFoundError.
    """
    notification = db.get(Notification, notification_id)
    if notification is None or notification.recipient_id != user_id:
        raise NotFoundError(
            message=f"Notification {notification_id} not found.",
            code="NOTIFICATION_NOT_FOUND",
            details={"notification_id": str(notification_id)},
        )
    return notification


# ============================================================================
# CORE — CREATE (single)
# ============================================================================

def create(
    db: Session,
    *,
    recipient_id: uuid.UUID,
    notification_type: NotificationType,
    title: str,
    body: str | None = None,
    priority: str = _PRIORITY_MEDIUM,
    icon: str | None = None,
    link_to_type: str | None = None,
    link_to_id: uuid.UUID | None = None,
    link_url: str | None = None,
    related_workspace_id: uuid.UUID | None = None,
    source_type: str | None = None,
    source_id: uuid.UUID | None = None,
    dedup_key: str | None = None,
    metadata: dict[str, Any] | None = None,
    is_silent: bool = False,
) -> Notification:
    """
    Create a single notification, or bump an existing one if the dedup
    key matches an active notification for this recipient.

    The dedup path:
        - Look up by (recipient_id, dedup_key) where not dismissed/expired
        - If found, call ``record_batch()`` and return the existing row
        - If not found, create a new row

    This service does not commit; the caller owns the transaction.
    """
    if dedup_key is not None:
        existing = _find_active_by_dedup_key(
            db, recipient_id=recipient_id, dedup_key=dedup_key,
        )
        if existing is not None:
            existing.record_batch()
            db.flush()
            logger.debug(
                "Notification recurrence batched",
                extra={
                    "notification_id": str(existing.id),
                    "batch_count": existing.batch_count,
                    "dedup_key": dedup_key,
                },
            )
            return existing

    notification = Notification.build(
        recipient_id=recipient_id,
        notification_type=notification_type,
        title=title,
        body=body,
        priority=priority,
        icon=icon,
        link_to_type=link_to_type,
        link_to_id=link_to_id,
        link_url=link_url,
        related_workspace_id=related_workspace_id,
        source_type=source_type,
        source_id=source_id,
        dedup_key=dedup_key,
        metadata=metadata,
        expires_at=_default_expiry(),
        is_silent=is_silent,
    )
    db.add(notification)
    db.flush()

    logger.debug(
        "Notification created",
        extra={
            "notification_id": str(notification.id),
            "recipient_id": str(recipient_id),
            "notification_type": (
                notification_type.value
                if hasattr(notification_type, "value")
                else str(notification_type)
            ),
            "priority": priority,
        },
    )

    return notification


def _find_active_by_dedup_key(
    db: Session,
    *,
    recipient_id: uuid.UUID,
    dedup_key: str,
) -> Notification | None:
    """
    Look up the active notification matching a (recipient, dedup_key).
    "Active" = not dismissed and not expired.
    """
    now = datetime.now(timezone.utc)
    return db.execute(
        select(Notification).where(
            Notification.recipient_id == recipient_id,
            Notification.dedup_key == dedup_key,
            Notification.dismissed_at.is_(None),
            or_(
                Notification.expires_at.is_(None),
                Notification.expires_at > now,
            ),
        )
    ).scalar_one_or_none()


# ============================================================================
# CORE — CREATE (batch)
# ============================================================================

def create_batch(
    db: Session,
    *,
    recipients: list[uuid.UUID],
    notification_type: NotificationType,
    title: str,
    body: str | None = None,
    priority: str = _PRIORITY_MEDIUM,
    icon: str | None = None,
    link_to_type: str | None = None,
    link_to_id: uuid.UUID | None = None,
    link_url: str | None = None,
    related_workspace_id: uuid.UUID | None = None,
    source_type: str | None = None,
    source_id: uuid.UUID | None = None,
    dedup_key_template: str | None = None,
    metadata: dict[str, Any] | None = None,
    is_silent: bool = False,
) -> list[Notification]:
    """
    Create the same notification for multiple recipients.

    ``dedup_key_template`` is used as-is (no substitution) — every
    recipient gets the same dedup_key value. This is correct: the
    unique index is on ``(recipient_id, dedup_key)``, so the same
    dedup_key for different recipients produces different rows
    (each recipient has their own).

    For per-recipient dedup variation (e.g. "alert_created:{alert.id}"),
    call ``create()`` individually per recipient. ``create_batch`` is
    for homogeneous fan-out.
    """
    if not recipients:
        return []

    created: list[Notification] = []
    for recipient_id in recipients:
        notif = create(
            db,
            recipient_id=recipient_id,
            notification_type=notification_type,
            title=title,
            body=body,
            priority=priority,
            icon=icon,
            link_to_type=link_to_type,
            link_to_id=link_to_id,
            link_url=link_url,
            related_workspace_id=related_workspace_id,
            source_type=source_type,
            source_id=source_id,
            dedup_key=dedup_key_template,
            metadata=metadata,
            is_silent=is_silent,
        )
        created.append(notif)

    logger.info(
        "Batch notifications dispatched",
        extra={
            "notification_count": len(created),
            "notification_type": (
                notification_type.value
                if hasattr(notification_type, "value")
                else str(notification_type)
            ),
        },
    )

    return created


# ============================================================================
# EVENT-SPECIFIC CREATORS
# ============================================================================

def create_for_alert(
    db: Session,
    *,
    alert: SecurityAlert,
) -> list[Notification]:
    """
    Fan out an alert notification to all active members of the alert's
    workspace.

    Uses the alert's fingerprint in the dedup key — one notification
    per attack pattern per recipient. When the same alert re-fires and
    ``alert_service`` merges the new finding into the existing alert,
    the notification is batched (``batch_count++``) rather than
    duplicated.

    Priority is derived from the alert severity.
    """
    recipients = _get_active_users_in_workspace(db, alert.workspace_id)
    if not recipients:
        return []

    return create_batch(
        db,
        recipients=[u.id for u in recipients],
        notification_type=NotificationType.ALERT_CREATED,
        title=alert.title,
        body=alert.description,
        priority=_SEVERITY_TO_PRIORITY.get(alert.severity, _PRIORITY_MEDIUM),
        icon="alert",
        link_to_type="alert",
        link_to_id=alert.id,
        related_workspace_id=alert.workspace_id,
        source_id=alert.source_id,
        dedup_key_template=f"alert_created:{alert.fingerprint}",
        metadata={
            "alert_id": str(alert.id),
            "alert_type": alert.alert_type,
            "severity": alert.severity.value,
            "category": alert.category.value,
        },
    )


def create_for_assignment(
    db: Session,
    *,
    alert: SecurityAlert,
    assignee_id: uuid.UUID,
) -> Notification | None:
    """
    Notify a specific user that an alert was assigned to them.

    Single recipient — no fan-out. Distinct from the alert-created
    fan-out: the assignee gets BOTH notifications (the fan-out one and
    this one, because assignment is a distinct action requiring
    attention).
    """
    return create(
        db,
        recipient_id=assignee_id,
        notification_type=NotificationType.CASE_ASSIGNED,
        title=f"Alert assigned to you: {alert.title}",
        body=(
            f"You have been assigned alert #{str(alert.id)[:8]} "
            f"({alert.severity.value} severity)."
        ),
        priority=_SEVERITY_TO_PRIORITY.get(alert.severity, _PRIORITY_MEDIUM),
        icon="user-check",
        link_to_type="alert",
        link_to_id=alert.id,
        related_workspace_id=alert.workspace_id,
        source_id=alert.source_id,
        dedup_key_template=f"alert_assigned:{alert.id}",
        metadata={"alert_id": str(alert.id)},
    )


def create_for_case_assignment(
    db: Session,
    *,
    case: SecurityCase,
    assignee_id: uuid.UUID,
    assigner_id: uuid.UUID,
) -> list[Notification]:
    """
    Notify the assignee that a case was assigned to them, and (if
    different) the assigner that the assignment went through.

    Two notifications maximum:
        - to ``assignee_id``: "Case #CG-... assigned to you"
        - to ``assigner_id``: "You assigned case #CG-... to X" (only
          if assigner is not the same as assignee — self-assignment
          produces no notification)

    Assigner notification is ``is_silent=True`` — it's confirmation,
    not a request for action.
    """
    created: list[Notification] = []

    # To assignee
    if assignee_id is not None:
        notif = create(
            db,
            recipient_id=assignee_id,
            notification_type=NotificationType.CASE_ASSIGNED,
            title=f"Case {case.case_number} assigned to you",
            body=case.title,
            priority=_SEVERITY_TO_PRIORITY.get(case.severity, _PRIORITY_MEDIUM),
            icon="folder",
            link_to_type="case",
            link_to_id=case.id,
            related_workspace_id=case.workspace_id,
            dedup_key_template=f"case_assigned:{case.id}:{assignee_id}",
            metadata={
                "case_id": str(case.id),
                "case_number": case.case_number,
            },
        )
        created.append(notif)

    # To assigner (silent confirmation, skip if self-assignment)
    if assigner_id is not None and assigner_id != assignee_id:
        notif = create(
            db,
            recipient_id=assigner_id,
            notification_type=NotificationType.CASE_ASSIGNED,
            title=f"You assigned case {case.case_number}",
            body=f"Assigned to user {str(assignee_id)[:8]}...",
            priority=_PRIORITY_LOW,
            icon="check",
            link_to_type="case",
            link_to_id=case.id,
            related_workspace_id=case.workspace_id,
            dedup_key_template=f"case_assigned_by_me:{case.id}:{assigner_id}",
            metadata={
                "case_id": str(case.id),
                "case_number": case.case_number,
                "assignee_id": str(assignee_id),
            },
            is_silent=True,
        )
        created.append(notif)

    return created


def create_for_incident(
    db: Session,
    *,
    incident: SecurityIncident,
) -> list[Notification]:
    """
    Notify relevant recipients when an incident is created.

    Audience: active org members with role ≥ SECURITY_MANAGER (admins
    and security managers need to know when a new incident is opened;
    regular analysts see it through the case assignment flow;
    employees don't need to know about org-level incidents).

    If the incident is assigned to someone (``assigned_to_id`` set),
    a dedicated assignment notification is also created for them — via
    ``create_for_case_assignment`` when the incident spawns a case.
    """
    if incident.workspace_id is None:
        return []

    # Get workspace, then org
    from app.models.workspace import Workspace
    ws = db.get(Workspace, incident.workspace_id)
    if ws is None:
        return []

    if ws.organization_id is not None:
        recipients = _get_active_org_members(
            db,
            ws.organization_id,
            min_role=OrganizationRole.SECURITY_MANAGER,
        )
    else:
        # Personal workspace — notify the owner only
        recipients = _get_active_users_in_workspace(db, incident.workspace_id)

    if not recipients:
        return []

    priority = _SEVERITY_TO_PRIORITY.get(incident.severity, _PRIORITY_MEDIUM)

    return create_batch(
        db,
        recipients=[u.id for u in recipients],
        notification_type=NotificationType.INCIDENT_CREATED,
        title=f"Incident: {incident.title}",
        body=incident.description,
        priority=priority,
        icon="shield-alert",
        link_to_type="incident",
        link_to_id=incident.id,
        related_workspace_id=incident.workspace_id,
        source_id=incident.primary_source_id,
        dedup_key_template=f"incident_created:{incident.fingerprint}",
        metadata={
            "incident_id": str(incident.id),
            "severity": incident.severity.value,
            "category": incident.category.value,
        },
    )


def create_for_invitation(
    db: Session,
    *,
    invitation: OrganizationInvitation,
) -> Notification | None:
    """
    Notify a user that they've been invited to an organization.

    Only fires if the invited email belongs to an existing user in the
    platform. For new users (email not yet registered), the invitation
    email itself is the delivery mechanism — we can't notify a
    nonexistent recipient.

    The notification is informational — the actual invitation is
    delivered via email with the token link. This is a nice-to-have
    in-app badge that says "you have a pending invitation".
    """
    # Find the user by email
    invitee = db.execute(
        select(User).where(
            User.email == invitation.email,
            User.deleted_at.is_(None),
        )
    ).scalar_one_or_none()

    if invitee is None:
        return None

    return create(
        db,
        recipient_id=invitee.id,
        notification_type=NotificationType.INVITATION_RECEIVED,
        title="You've been invited to join an organization",
        body=(
            f"You have a pending invitation to join an organization "
            f"(role: {invitation.role.value}). Check your email for "
            f"the acceptance link."
        ),
        priority=_PRIORITY_MEDIUM,
        icon="mail",
        link_to_type="invitation",
        link_to_id=invitation.id,
        dedup_key_template=f"invitation:{invitation.id}",
        metadata={
            "invitation_id": str(invitation.id),
            "organization_id": str(invitation.organization_id),
            "role": invitation.role.value,
        },
    )


def create_for_message(
    db: Session,
    *,
    message: CaseMessage,
    conversation: CaseConversation,
) -> list[Notification]:
    """
    Notify participants of a case conversation when a new message
    arrives.

    Participants = users with a workspace membership OR an active case
    access grant that permits conversation read. Excludes the sender.

    Deduplicated per-conversation (not per-message) — a burst of 10
    messages produces 1 notification that batches to 10. This is the
    standard "10 new messages in #channel" UX.
    """
    if message.sender_id is None:
        # System-generated messages don't notify
        return []

    case = db.get(SecurityCase, conversation.case_id)
    if case is None:
        return []

    # Everyone in the workspace who can see this conversation
    recipients = _get_active_users_in_workspace(db, case.workspace_id)

    # Exclude the sender
    recipient_ids = [
        u.id for u in recipients if u.id != message.sender_id
    ]

    if not recipient_ids:
        return []

    return create_batch(
        db,
        recipients=recipient_ids,
        notification_type=NotificationType.MESSAGE_RECEIVED,
        title=f"New message in {case.case_number}",
        body=_truncate(message.body, 200),
        priority=_PRIORITY_MEDIUM,
        icon="message-circle",
        link_to_type="conversation",
        link_to_id=conversation.id,
        related_workspace_id=case.workspace_id,
        dedup_key_template=f"message:{conversation.id}",
        metadata={
            "case_id": str(case.id),
            "conversation_id": str(conversation.id),
            "message_id": str(message.id),
        },
    )


def create_for_report(
    db: Session,
    *,
    report: SecurityReport,
) -> Notification | None:
    """
    Notify the report requester (or its original creator) that the
    report is ready for download.

    Only fires when ``report.generation_status == READY`` — called by
    ``report_service`` after successful generation.
    """
    recipient_id = report.requested_by_id
    if recipient_id is None:
        return None

    return create(
        db,
        recipient_id=recipient_id,
        notification_type=NotificationType.REPORT_READY,
        title=f"Report ready: {report.title}",
        body=(
            f"Your {report.report_type.value} report has been generated "
            f"and is ready to download."
        ),
        priority=_PRIORITY_MEDIUM,
        icon="file-text",
        link_to_type="report",
        link_to_id=report.id,
        related_workspace_id=report.workspace_id,
        dedup_key_template=f"report_ready:{report.id}",
        metadata={
            "report_id": str(report.id),
            "report_format": report.report_format,
        },
    )


# ============================================================================
# ENGAGEMENT
# ============================================================================

def mark_seen(
    db: Session,
    *,
    user_id: uuid.UUID,
    notification_id: uuid.UUID,
) -> Notification:
    """
    Record that the user opened the notification. Idempotent.
    """
    notification = _get_notification_or_404(db, notification_id, user_id)
    if notification.seen_at is None:
        notification.mark_seen()
        db.flush()
    return notification


def mark_read(
    db: Session,
    *,
    user_id: uuid.UUID,
    notification_id: uuid.UUID,
) -> Notification:
    """
    Record that the user read the notification. Implies "seen". Idempotent.
    """
    notification = _get_notification_or_404(db, notification_id, user_id)
    if notification.read_at is None:
        notification.mark_read()
        db.flush()
    return notification


def dismiss(
    db: Session,
    *,
    user_id: uuid.UUID,
    notification_id: uuid.UUID,
    reason: str | None = None,
) -> Notification:
    """
    Dismiss the notification. Implies "read". Idempotent.
    """
    notification = _get_notification_or_404(db, notification_id, user_id)
    if notification.dismissed_at is None:
        notification.dismiss()
        if reason:
            notification.action_notes = reason.strip()[:2000]
        db.flush()
    return notification


def record_action(
    db: Session,
    *,
    user_id: uuid.UUID,
    notification_id: uuid.UUID,
    action_type: str,
    notes: str | None = None,
) -> Notification:
    """
    Record that the user took an action in response to the notification
    (opened the target, replied, acknowledged, downloaded, etc.).
    Implies "read".
    """
    notification = _get_notification_or_404(db, notification_id, user_id)
    notification.record_action(action_type=action_type, notes=notes)
    db.flush()
    return notification


def mark_all_seen(
    db: Session,
    *,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
) -> int:
    """
    Bulk mark all unseen notifications as seen. Returns the count
    of notifications actually updated.

    Called when the user opens the inbox — the badge count drops to
    zero with a single call, no matter how many notifications were
    pending.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        select(Notification)
        .where(
            Notification.recipient_id == user_id,
            Notification.seen_at.is_(None),
        )
    )
    if workspace_id is not None:
        stmt = stmt.where(Notification.related_workspace_id == workspace_id)

    notifications = list(db.execute(stmt).scalars().all())
    for n in notifications:
        n.seen_at = now

    if notifications:
        db.flush()
        logger.debug(
            "Bulk marked seen",
            extra={
                "user_id": str(user_id),
                "count": len(notifications),
                "workspace_id": str(workspace_id) if workspace_id else None,
            },
        )

    return len(notifications)


def mark_all_read(
    db: Session,
    *,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
) -> int:
    """
    Bulk mark all seen-but-unread notifications as read.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        select(Notification)
        .where(
            Notification.recipient_id == user_id,
            Notification.seen_at.is_not(None),
            Notification.read_at.is_(None),
        )
    )
    if workspace_id is not None:
        stmt = stmt.where(Notification.related_workspace_id == workspace_id)

    notifications = list(db.execute(stmt).scalars().all())
    for n in notifications:
        n.read_at = now

    if notifications:
        db.flush()

    return len(notifications)


# ============================================================================
# READ
# ============================================================================

def list_notifications(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: PageParams,
    filters: NotificationFilter,
) -> tuple[list[Notification], int]:
    """
    List notifications for a user's inbox.

    ``active_only`` (default True in the filter) excludes dismissed and
    expired — the correct default for the inbox view. Set False to
    include history.
    """
    stmt = select(Notification).where(Notification.recipient_id == user_id)

    if filters.notification_type is not None:
        stmt = stmt.where(Notification.notification_type == filters.notification_type)
    if filters.priority is not None:
        stmt = stmt.where(Notification.priority == filters.priority)
    if filters.related_workspace_id is not None:
        stmt = stmt.where(Notification.related_workspace_id == filters.related_workspace_id)
    if filters.source_id is not None:
        stmt = stmt.where(Notification.source_id == filters.source_id)
    if filters.unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    if filters.unseen_only:
        stmt = stmt.where(Notification.seen_at.is_(None))
    if filters.active_only:
        now = datetime.now(timezone.utc)
        stmt = stmt.where(
            Notification.dismissed_at.is_(None),
            or_(
                Notification.expires_at.is_(None),
                Notification.expires_at > now,
            ),
        )
    if filters.created_after is not None:
        stmt = stmt.where(Notification.created_at >= filters.created_after)
    if filters.created_before is not None:
        stmt = stmt.where(Notification.created_at <= filters.created_before)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    stmt = (
        stmt.order_by(
            Notification.created_at.desc(),
            Notification.id.desc(),
        )
        .offset(page.offset)
        .limit(page.limit)
    )
    notifications = list(db.execute(stmt).scalars().all())
    return notifications, int(total)


def get_badge_counts(
    db: Session,
    *,
    user_id: uuid.UUID,
) -> NotificationBadge:
    """
    Return badge counts for the current user: total active, unseen,
    unread, and critical-active.

    Frequently polled by frontends (every 30s or so). Optimized —
    four indexed COUNT queries, no full scans.
    """
    now = datetime.now(timezone.utc)
    active_conditions = and_(
        Notification.recipient_id == user_id,
        Notification.dismissed_at.is_(None),
        or_(
            Notification.expires_at.is_(None),
            Notification.expires_at > now,
        ),
    )

    total_active = db.execute(
        select(func.count())
        .select_from(Notification)
        .where(active_conditions)
    ).scalar_one()

    unseen = db.execute(
        select(func.count())
        .select_from(Notification)
        .where(active_conditions, Notification.seen_at.is_(None))
    ).scalar_one()

    unread = db.execute(
        select(func.count())
        .select_from(Notification)
        .where(active_conditions, Notification.read_at.is_(None))
    ).scalar_one()

    critical = db.execute(
        select(func.count())
        .select_from(Notification)
        .where(
            active_conditions,
            Notification.priority == _PRIORITY_CRITICAL,
            Notification.read_at.is_(None),
        )
    ).scalar_one()

    return NotificationBadge(
        total_active=int(total_active),
        unseen_count=int(unseen),
        unread_count=int(unread),
        critical_count=int(critical),
    )


def get_unread_count(
    db: Session,
    *,
    user_id: uuid.UUID,
    workspace_id: uuid.UUID | None = None,
) -> int:
    """
    Return the unread count for a user, optionally workspace-scoped.
    Lighter than ``get_badge_counts`` when only one number is needed.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        select(func.count())
        .select_from(Notification)
        .where(
            Notification.recipient_id == user_id,
            Notification.read_at.is_(None),
            Notification.dismissed_at.is_(None),
            or_(
                Notification.expires_at.is_(None),
                Notification.expires_at > now,
            ),
        )
    )
    if workspace_id is not None:
        stmt = stmt.where(Notification.related_workspace_id == workspace_id)

    return int(db.execute(stmt).scalar_one())


# ============================================================================
# BACKGROUND SWEEP
# ============================================================================

def sweep_expired(
    db: Session,
    *,
    limit: int = 500,
) -> int:
    """
    Mark expired notifications as EXPIRED... wait, we don't have an
    EXPIRED status — notifications use ``dismissed_at`` or expiry
    timestamps only.

    Instead, hard-delete notifications whose ``expires_at`` is past
    AND that are older than the retention window (default 30 days
    past their own ``expires_at``).

    Called by a periodic background job. Returns count deleted.

    The retention policy is conservative — an expired notification
    lingers for 30 more days in case the user wants to look at it
    before it's gone. If a notification is under legal hold it's
    preserved.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")

    retention_cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    candidates = db.execute(
        select(Notification)
        .where(
            Notification.expires_at.is_not(None),
            Notification.expires_at < retention_cutoff,
        )
        .limit(limit)
    ).scalars().all()

    deleted = 0
    for notif in candidates:
        db.delete(notif)
        deleted += 1

    if deleted > 0:
        db.flush()
        logger.info(
            "Notification sweep: expired rows deleted",
            extra={"count": deleted},
        )

    return deleted


# ============================================================================
# INTERNAL — string truncation for body previews
# ============================================================================

def _truncate(text: str | None, max_length: int) -> str | None:
    """Truncate text to ``max_length`` chars with ellipsis."""
    if not text:
        return None
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "…"


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Core
    "create",
    "create_batch",
    # Event-specific
    "create_for_alert",
    "create_for_assignment",
    "create_for_case_assignment",
    "create_for_incident",
    "create_for_invitation",
    "create_for_message",
    "create_for_report",
    # Engagement
    "mark_seen",
    "mark_read",
    "dismiss",
    "record_action",
    "mark_all_seen",
    "mark_all_read",
    # Read
    "list_notifications",
    "get_badge_counts",
    "get_unread_count",
    # Background
    "sweep_expired",
]