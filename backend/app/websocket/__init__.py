"""
CyberGuard AI - WebSocket Package

Real-time event streaming for dashboard updates.
"""

from app.websocket.manager import (
    ConnectionManager,
    get_connection_manager,
)
from app.websocket.events import (
    WSEventType,
    WSEvent,
    broadcast_event,
    broadcast_alert,
)

__all__ = [
    "ConnectionManager",
    "get_connection_manager",
    "WSEventType",
    "WSEvent",
    "broadcast_event",
    "broadcast_alert",
]
