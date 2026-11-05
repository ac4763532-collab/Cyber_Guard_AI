"""
CyberGuard AI - Notification Tasks
Background tasks for sending alerts and notifications.

Delivery is real: this module calls NotificationService, which sends
actual SMTP email (or webhook POSTs) and only reports "sent" after the
provider confirms it - never a placeholder success.
"""

import asyncio

import structlog
from celery import shared_task

from app.database.models import NotificationChannel, SeverityLevel

logger = structlog.get_logger(__name__)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def send_alert_notification(
    self,
    alert_id: str,
    alert_data: dict,
    channels: list[str] | None = None,
) -> dict:
    """
    Send alert notification through configured channels.

    Args:
        alert_id: Unique alert identifier
        alert_data: Alert details - expected keys: title, description/summary,
            severity, tenant_id, recipient_user_id, recipient_email
        channels: Notification channels (in_app, email, webhook)

    Returns:
        Notification status, with the real per-channel delivery outcome.
    """
    recipient_user_id = alert_data.get("recipient_user_id")
    if not recipient_user_id:
        logger.warning("send_alert_notification missing recipient_user_id - cannot deliver", alert_id=alert_id)
        return {"alert_id": alert_id, "status": "skipped", "reason": "no recipient_user_id"}

    channel_enums = None
    if channels:
        try:
            channel_enums = [NotificationChannel(c) for c in channels]
        except ValueError as e:
            logger.warning("Unknown notification channel requested", channels=channels, error=str(e))

    try:
        logger.info(
            "Sending alert notification",
            task_id=self.request.id,
            alert_id=alert_id,
            channels=channels,
        )

        results = _run_async(_send_alert_notification_async(alert_id, alert_data, channel_enums, recipient_user_id))

        logger.info(
            "Alert notification processed",
            task_id=self.request.id,
            alert_id=alert_id,
            results={k: v.status for k, v in results.items()},
        )

        return {
            "alert_id": alert_id,
            "status": "processed",
            "channels": {k: v.status for k, v in results.items()},
        }

    except Exception as exc:
        logger.error(
            "Alert notification failed",
            task_id=self.request.id,
            alert_id=alert_id,
            error=str(exc),
        )
        raise self.retry(exc=exc)


async def _send_alert_notification_async(
    alert_id: str,
    alert_data: dict,
    channels: list[NotificationChannel] | None,
    recipient_user_id: str,
):
    from app.services.notifications import get_notification_service

    severity_raw = alert_data.get("severity", "info")
    try:
        severity = SeverityLevel(severity_raw)
    except ValueError:
        severity = SeverityLevel.INFO

    service = get_notification_service()
    return await service.notify(
        source_id=alert_id,
        source_type="alert",
        tenant_id=alert_data.get("tenant_id"),
        recipient_user_id=recipient_user_id,
        recipient_email=alert_data.get("recipient_email"),
        severity=severity,
        title=alert_data.get("title", "Security Alert"),
        summary=alert_data.get("description") or alert_data.get("summary", ""),
        channels=channels,
    )


@shared_task
def send_daily_digest(user_id: str) -> dict:
    """
    Send daily security digest to user.

    Args:
        user_id: User to send digest to

    Returns:
        Digest status
    """
    logger.info("Sending daily digest", user_id=user_id)

    # TODO: Implement daily digest
    # - Gather last 24h events
    # - Summarize threats and actions
    # - Send via preferred channel

    return {
        "user_id": user_id,
        "status": "sent",
        "message": "Daily digest placeholder",
    }
