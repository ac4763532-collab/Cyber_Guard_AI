"""CyberGuard AI - Notification delivery service."""

from app.services.notifications.service import (
    NotificationService,
    get_notification_service,
)

__all__ = ["NotificationService", "get_notification_service"]
