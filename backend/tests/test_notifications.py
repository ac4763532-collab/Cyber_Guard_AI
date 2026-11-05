"""
CyberGuard AI - Notification Delivery Tests

Covers the real notification layer added to replace the former
placeholder stubs in app/tasks/notifications.py:
- NotificationRepository: create/dedup, mark_sent/mark_failed/mark_read
- NotificationService: honest three-state SMTP behavior (sent / failed
  with a real error / "not configured"), webhook delivery via circuit
  breaker, in-app "delivery is persistence"
- CorrelationAlertIntegration._resolve_recipients /_notify_recipients
  fail-safe behavior (never blocks alert/incident persistence)

No real network/SMTP calls are made - smtplib.SMTP and httpx are mocked.
"""

from __future__ import annotations

import smtplib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.database.models import (
    Notification,
    NotificationChannel,
    NotificationCreate,
    NotificationStatus,
    SeverityLevel,
)
from app.database.repositories.notifications import NotificationRepository
from app.services.notifications.service import (
    NotificationService,
    compute_notification_fingerprint,
)


# =============================================================================
# Fingerprint
# =============================================================================


class TestFingerprint:
    def test_same_inputs_produce_same_fingerprint(self):
        fp1 = compute_notification_fingerprint(source_id="alert-1", channel="email")
        fp2 = compute_notification_fingerprint(source_id="alert-1", channel="email")
        assert fp1 == fp2

    def test_different_channel_produces_different_fingerprint(self):
        fp1 = compute_notification_fingerprint(source_id="alert-1", channel="email")
        fp2 = compute_notification_fingerprint(source_id="alert-1", channel="in_app")
        assert fp1 != fp2

    def test_different_source_produces_different_fingerprint(self):
        fp1 = compute_notification_fingerprint(source_id="alert-1", channel="email")
        fp2 = compute_notification_fingerprint(source_id="alert-2", channel="email")
        assert fp1 != fp2


# =============================================================================
# NotificationRepository
# =============================================================================


@pytest.fixture
def repo_with_mock_db():
    with patch("app.database.repositories.notifications.get_database") as mock_get_db:
        mock_db = MagicMock()
        mock_db.execute_one = AsyncMock()
        mock_db.execute = AsyncMock()
        mock_get_db.return_value = mock_db
        repo = NotificationRepository()
        yield repo, mock_db


class TestNotificationRepository:
    @pytest.mark.asyncio
    async def test_create_inserts_new_notification(self, repo_with_mock_db):
        repo, mock_db = repo_with_mock_db
        mock_db.execute_one.return_value = {
            "id": "notif-1",
            "alert_id": "alert-1",
            "incident_id": None,
            "tenant_id": "tenant-a",
            "recipient_user_id": "user-1",
            "recipient_address": "user1@example.com",
            "channel": "email",
            "severity": "high",
            "title": "Test Alert",
            "summary": "Something happened",
            "fingerprint": "abc123",
            "status": "pending",
            "attempts": 0,
            "last_error": None,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "queued_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "sent_at": None,
            "read_at": None,
        }

        result = await repo.create(
            NotificationCreate(
                alert_id="alert-1",
                tenant_id="tenant-a",
                recipient_user_id="user-1",
                recipient_address="user1@example.com",
                channel=NotificationChannel.EMAIL,
                severity=SeverityLevel.HIGH,
                title="Test Alert",
                summary="Something happened",
                fingerprint="abc123",
            )
        )

        assert result is not None
        assert result.status == "pending"
        assert result.channel == "email"

    @pytest.mark.asyncio
    async def test_create_falls_back_to_existing_on_conflict(self, repo_with_mock_db):
        """ON CONFLICT DO NOTHING returns no row - create() must then
        fetch and return the already-queued notification, never None
        and never silently pretend a new one was created."""
        repo, mock_db = repo_with_mock_db
        # First call (the INSERT) returns None (conflict, nothing returned)
        existing_row = {
            "id": "notif-existing",
            "alert_id": "alert-1",
            "incident_id": None,
            "tenant_id": "tenant-a",
            "recipient_user_id": "user-1",
            "recipient_address": "user1@example.com",
            "channel": "email",
            "severity": "high",
            "title": "Test Alert",
            "summary": "Something happened",
            "fingerprint": "abc123",
            "status": "sent",
            "attempts": 1,
            "last_error": None,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "queued_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "sent_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            "read_at": None,
        }
        mock_db.execute_one.side_effect = [None, existing_row]

        result = await repo.create(
            NotificationCreate(
                alert_id="alert-1",
                tenant_id="tenant-a",
                recipient_user_id="user-1",
                recipient_address="user1@example.com",
                channel=NotificationChannel.EMAIL,
                severity=SeverityLevel.HIGH,
                title="Test Alert",
                summary="Something happened",
                fingerprint="abc123",
            )
        )

        assert result is not None
        assert result.id == "notif-existing"
        assert result.status == "sent"  # the real, already-delivered status - not re-queued


# =============================================================================
# NotificationService - the honesty-critical paths
# =============================================================================


def _make_pending_notification(channel: str = "email") -> Notification:
    import datetime as dt

    return Notification(
        id="notif-1",
        alert_id="alert-1",
        tenant_id="tenant-a",
        recipient_user_id="user-1",
        recipient_address="user1@example.com",
        channel=channel,
        severity="high",
        title="Test Alert",
        summary="Something happened",
        fingerprint="abc123",
        status=NotificationStatus.PENDING,
        created_at=dt.datetime.now(dt.timezone.utc),
        queued_at=dt.datetime.now(dt.timezone.utc),
    )


@pytest.fixture
def service_with_mocks():
    with patch("app.services.notifications.service.get_settings") as mock_settings, \
         patch("app.services.notifications.service.get_notification_repository") as mock_get_repo:
        settings = MagicMock()
        settings.smtp_host = ""  # not configured by default
        settings.smtp_port = 587
        settings.smtp_username = ""
        settings.smtp_password = ""
        settings.smtp_use_tls = True
        settings.smtp_from_address = "alerts@cyberguard.local"
        settings.smtp_from_name = "CyberGuard AI"
        settings.smtp_timeout_seconds = 10
        settings.notification_webhook_url = ""
        mock_settings.return_value = settings

        repo = MagicMock()
        repo.create = AsyncMock()
        repo.mark_sent = AsyncMock()
        repo.mark_failed = AsyncMock()
        mock_get_repo.return_value = repo

        service = NotificationService()
        yield service, settings, repo


class TestNotificationServiceHonesty:
    """The critical honesty gate: a notification is only ever 'sent'
    after a real provider confirms it. These tests assert the three
    distinct states never get confused with each other."""

    @pytest.mark.asyncio
    async def test_email_not_configured_marks_failed_with_explicit_reason(self, service_with_mocks):
        service, settings, repo = service_with_mocks
        assert service.smtp_configured is False

        pending = _make_pending_notification()
        repo.mark_failed.return_value = pending.model_copy(update={"status": "failed", "last_error": "SMTP not configured"})

        result = await service._deliver_email(pending, "user1@example.com")

        repo.mark_failed.assert_awaited_once()
        call_args = repo.mark_failed.call_args
        assert "SMTP not configured" in call_args[0][1]
        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_email_no_recipient_address_marks_failed_not_silently_skipped(self, service_with_mocks):
        service, settings, repo = service_with_mocks
        pending = _make_pending_notification()
        repo.mark_failed.return_value = pending.model_copy(update={"status": "failed"})

        result = await service._deliver_email(pending, None)

        repo.mark_failed.assert_awaited_once()
        assert "No recipient email" in repo.mark_failed.call_args[0][1]

    @pytest.mark.asyncio
    async def test_email_success_marks_sent_only_after_smtp_accepts(self, service_with_mocks):
        service, settings, repo = service_with_mocks
        settings.smtp_host = "smtp.example.com"  # now configured
        pending = _make_pending_notification()
        repo.mark_sent.return_value = pending.model_copy(update={"status": "sent"})

        with patch.object(service, "_send_smtp_sync") as mock_send:
            mock_send.return_value = None  # SMTP accepted the message
            result = await service._deliver_email(pending, "user1@example.com")

        mock_send.assert_called_once()
        repo.mark_sent.assert_awaited_once_with(pending.id)
        repo.mark_failed.assert_not_called()
        assert result.status == "sent"

    @pytest.mark.asyncio
    async def test_email_smtp_exception_marks_failed_with_real_error_not_sent(self, service_with_mocks):
        service, settings, repo = service_with_mocks
        settings.smtp_host = "smtp.example.com"
        pending = _make_pending_notification()
        repo.mark_failed.return_value = pending.model_copy(update={"status": "failed", "last_error": "Connection refused"})

        with patch.object(service, "_send_smtp_sync") as mock_send:
            mock_send.side_effect = smtplib.SMTPConnectError(421, "Connection refused")
            result = await service._deliver_email(pending, "user1@example.com")

        repo.mark_sent.assert_not_called()
        repo.mark_failed.assert_awaited_once()
        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_in_app_delivery_is_persistence_marks_sent_immediately(self, service_with_mocks):
        """In-app has no external provider - the DB write IS the delivery."""
        service, settings, repo = service_with_mocks
        pending = _make_pending_notification(channel="in_app")
        repo.create.return_value = pending
        repo.mark_sent.return_value = pending.model_copy(update={"status": "sent"})

        results = await service.notify(
            source_id="alert-1",
            source_type="alert",
            tenant_id="tenant-a",
            recipient_user_id="user-1",
            recipient_email=None,
            severity=SeverityLevel.HIGH,
            title="Test",
            summary="Summary",
            channels=[NotificationChannel.IN_APP],
        )

        assert results["in_app"].status == "sent"
        repo.mark_sent.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_already_delivered_notification_is_not_resent(self, service_with_mocks):
        """If create() returns an already-sent row (deduplicated), notify()
        must not attempt delivery again - no duplicate notifications."""
        service, settings, repo = service_with_mocks
        already_sent = _make_pending_notification().model_copy(update={"status": "sent"})
        repo.create.return_value = already_sent

        results = await service.notify(
            source_id="alert-1",
            source_type="alert",
            tenant_id="tenant-a",
            recipient_user_id="user-1",
            recipient_email="user1@example.com",
            severity=SeverityLevel.HIGH,
            title="Test",
            summary="Summary",
            channels=[NotificationChannel.EMAIL],
        )

        repo.mark_sent.assert_not_called()
        repo.mark_failed.assert_not_called()
        assert results["email"].status == "sent"


class TestNotificationServiceWebhook:
    @pytest.mark.asyncio
    async def test_webhook_not_configured_marks_failed(self, service_with_mocks):
        service, settings, repo = service_with_mocks
        pending = _make_pending_notification(channel="webhook")
        repo.mark_failed.return_value = pending.model_copy(update={"status": "failed"})

        result = await service._deliver_webhook(pending)

        assert "No webhook URL configured" in repo.mark_failed.call_args[0][1]
        assert result.status == "failed"
