"""
CyberGuard AI - Notification Delivery Service

Real outbound delivery for alert notifications, replacing the
former placeholder stubs in app/tasks/notifications.py.

Honesty principle: a notification is only ever marked "sent" after the
underlying provider (SMTP server) accepts it. If SMTP is not configured,
or the send fails, the notification is recorded as "failed" with the
real error - never silently treated as delivered.

Channels:
- in_app: no external send - just a persisted Notification row the
  frontend inbox polls/reads. "Delivery" is simply the DB write.
- email: real SMTP send via stdlib smtplib, run off the event loop in a
  thread executor (keeps this async-safe without adding a new dependency).
- webhook: real HTTP POST via httpx, wrapped in a circuit breaker.

Never includes raw logs, credentials, or full email bodies in the sent
content - only the short `summary` text the caller already redacted.
"""

from __future__ import annotations

import asyncio
import hashlib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx
import structlog

from app.config import get_settings
from app.database.models import (
    Notification,
    NotificationChannel,
    NotificationCreate,
    SeverityLevel,
)
from app.database.repositories.notifications import get_notification_repository
from app.services.circuit_breaker.breaker import get_circuit_breaker

logger = structlog.get_logger(__name__)


def compute_notification_fingerprint(*, source_id: str, channel: str) -> str:
    """
    Deterministic dedup key for a notification: the same underlying
    alert notifying the same channel again produces the same
    fingerprint, so the repository's UNIQUE constraint prevents a
    duplicate send instead of relying on application-level checks alone.
    """
    raw = f"{source_id}:{channel}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class NotificationService:
    """Delivers notifications for alerts across channels."""

    def __init__(self):
        self.settings = get_settings()
        self.repo = get_notification_repository()

    @property
    def smtp_configured(self) -> bool:
        return bool(self.settings.smtp_host)

    async def notify(
        self,
        *,
        source_id: str,
        source_type: str,  # "alert"
        tenant_id: str | None,
        recipient_user_id: str,
        recipient_email: str | None,
        severity: SeverityLevel,
        title: str,
        summary: str,
        channels: list[NotificationChannel] | None = None,
    ) -> dict[str, Notification]:
        """
        Queue and attempt delivery of a notification across the given
        channels (default: in-app always, plus email if an address is
        available and SMTP is configured).

        Returns a dict of channel -> the resulting Notification row
        (post-delivery-attempt), so callers can inspect real status.
        """
        if channels is None:
            channels = [NotificationChannel.IN_APP]
            if recipient_email:
                channels.append(NotificationChannel.EMAIL)

        results: dict[str, Notification] = {}

        for channel in channels:
            fingerprint = compute_notification_fingerprint(source_id=source_id, channel=channel.value)

            create = NotificationCreate(
                alert_id=source_id if source_type == "alert" else None,
                tenant_id=tenant_id,
                recipient_user_id=recipient_user_id,
                recipient_address=recipient_email if channel == NotificationChannel.EMAIL else None,
                channel=channel,
                severity=severity,
                title=title,
                summary=summary,
                fingerprint=fingerprint,
            )

            notification = await self.repo.create(create)
            if notification is None:
                # Should not happen - create() falls back to get_by_fingerprint
                # on conflict - but guard defensively.
                logger.warning("Notification create returned None", source_id=source_id, channel=channel.value)
                continue

            if notification.status != "pending":
                # Already processed (deduplicated re-delivery attempt).
                results[channel.value] = notification
                continue

            if channel == NotificationChannel.IN_APP:
                # Persisting the row IS the delivery for in-app.
                updated = await self.repo.mark_sent(notification.id)
                results[channel.value] = updated or notification

            elif channel == NotificationChannel.EMAIL:
                results[channel.value] = await self._deliver_email(notification, recipient_email)

            elif channel == NotificationChannel.WEBHOOK:
                results[channel.value] = await self._deliver_webhook(notification)

        return results

    async def _deliver_email(self, notification: Notification, recipient_email: str | None) -> Notification:
        """Send one notification by email via SMTP, recording the real outcome."""
        if not recipient_email:
            return await self.repo.mark_failed(notification.id, "No recipient email address on file") or notification

        if not self.smtp_configured:
            return await self.repo.mark_failed(
                notification.id, "SMTP not configured (smtp_host is unset) - email delivery unavailable"
            ) or notification

        try:
            await asyncio.get_running_loop().run_in_executor(
                None, self._send_smtp_sync, recipient_email, notification
            )
            logger.info("Email notification sent", notification_id=notification.id, to=recipient_email)
            return await self.repo.mark_sent(notification.id) or notification
        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            logger.error("Email notification failed", notification_id=notification.id, error=str(e))
            return await self.repo.mark_failed(notification.id, str(e)) or notification

    def _send_smtp_sync(self, recipient_email: str, notification: Notification) -> None:
        """Blocking SMTP send - must run in a thread executor, never on the event loop."""
        s = self.settings
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{notification.severity.upper()}] {notification.title}"
        msg["From"] = f"{s.smtp_from_name} <{s.smtp_from_address}>"
        msg["To"] = recipient_email

        body = (
            f"{notification.title}\n\n"
            f"Severity: {notification.severity.upper()}\n\n"
            f"{notification.summary}\n\n"
            "This is an automated security notification from CyberGuard AI. "
            "Do not reply to this message."
        )
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds) as server:
            if s.smtp_use_tls:
                server.starttls()
            if s.smtp_username:
                server.login(s.smtp_username, s.smtp_password)
            server.sendmail(s.smtp_from_address, [recipient_email], msg.as_string())

    async def _deliver_webhook(self, notification: Notification) -> Notification:
        """POST one notification to a configured webhook URL via a circuit breaker."""
        webhook_url = self.settings.notification_webhook_url
        if not webhook_url:
            return await self.repo.mark_failed(notification.id, "No webhook URL configured") or notification

        breaker = get_circuit_breaker("notification_webhook", failure_threshold=5, recovery_timeout_seconds=60)
        if not await breaker.allow_request():
            return await self.repo.mark_failed(notification.id, "Webhook circuit breaker open") or notification

        payload: dict[str, Any] = {
            "id": notification.id,
            "title": notification.title,
            "summary": notification.summary,
            "severity": notification.severity,
            "alert_id": notification.alert_id,
        }

        try:
            async with httpx.AsyncClient(timeout=self.settings.smtp_timeout_seconds) as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
            await breaker.record_success()
            return await self.repo.mark_sent(notification.id) or notification
        except (httpx.HTTPError, OSError) as e:
            await breaker.record_failure()
            logger.error("Webhook notification failed", notification_id=notification.id, error=str(e))
            return await self.repo.mark_failed(notification.id, str(e)) or notification


_notification_service: NotificationService | None = None


def get_notification_service() -> NotificationService:
    """Get the singleton notification service."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service
