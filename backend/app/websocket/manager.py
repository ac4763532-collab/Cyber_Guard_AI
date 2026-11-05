"""
CyberGuard AI - WebSocket Connection Manager

Manages WebSocket connections for real-time updates.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect
import structlog


logger = structlog.get_logger(__name__)


class ConnectionManager:
    """
    WebSocket connection manager.

    Handles:
    - Client connections/disconnections
    - Broadcasting messages to all clients
    - Channel-based subscriptions
    - Connection health monitoring
    """

    def __init__(self):
        # Active connections: connection_id -> WebSocket
        self._connections: dict[str, WebSocket] = {}

        # Channel subscriptions: channel -> set of connection_ids
        self._channels: dict[str, set[str]] = {
            "alerts": set(),
            "events": set(),
            "agents": set(),
            "system": set(),
        }

        # Connection metadata
        self._metadata: dict[str, dict[str, Any]] = {}

        # Tenant-scoped index: tenant_id -> set of connection_ids. Populated
        # only for connections that resolved to a real tenant_id (see
        # app/websocket/auth.py's resolve_tenant_scope) - admin connections
        # (tenant_id is None) are intentionally never added here, since
        # broadcast_to_tenant() exists specifically for tenant-scoped alert
        # delivery, not an admin all-tenants view. This is additive: every
        # existing channel-based broadcast()/broadcast_to_channels() path
        # is untouched and keeps working exactly as before.
        self._tenant_connections: dict[str, set[str]] = {}

        logger.info("WebSocket ConnectionManager initialized")

    async def connect(
        self,
        websocket: WebSocket,
        channels: list[str] | None = None,
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
    ) -> str:
        """
        Accept a new WebSocket connection.

        Args:
            websocket: The WebSocket connection
            channels: Optional list of channels to subscribe to
            user_id: Authenticated user id for this connection, if any.
                Optional/keyword-only so existing callers that don't pass
                it keep working unchanged.
            tenant_id: Tenant this connection is scoped to for
                broadcast_to_tenant() delivery (None = unscoped/admin).

        Returns:
            Connection ID
        """
        await websocket.accept()

        connection_id = str(uuid4())
        self._connections[connection_id] = websocket

        # Store metadata
        self._metadata[connection_id] = {
            "connected_at": datetime.now(timezone.utc),
            "channels": [],
            "messages_sent": 0,
            "user_id": user_id,
            "tenant_id": tenant_id,
        }

        if tenant_id is not None:
            self._tenant_connections.setdefault(tenant_id, set()).add(connection_id)

        # Subscribe to channels
        subscribe_channels = channels or ["system", "alerts"]
        for channel in subscribe_channels:
            await self.subscribe(connection_id, channel)

        logger.info(
            "WebSocket connected",
            connection_id=connection_id,
            channels=subscribe_channels,
            user_id=user_id,
            tenant_id=tenant_id,
        )

        # Send welcome message
        await self.send_personal(connection_id, {
            "type": "connected",
            "connection_id": connection_id,
            "channels": subscribe_channels,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return connection_id

    async def disconnect(self, connection_id: str) -> None:
        """Disconnect a client."""
        if connection_id in self._connections:
            # Remove from all channels
            for channel in self._channels.values():
                channel.discard(connection_id)

            # Remove from the tenant index (if it was ever added)
            metadata = self._metadata.get(connection_id)
            tenant_id = metadata.get("tenant_id") if metadata else None
            if tenant_id is not None:
                tenant_set = self._tenant_connections.get(tenant_id)
                if tenant_set is not None:
                    tenant_set.discard(connection_id)
                    if not tenant_set:
                        del self._tenant_connections[tenant_id]

            # Remove connection
            del self._connections[connection_id]

            # Remove metadata
            if connection_id in self._metadata:
                del self._metadata[connection_id]

            logger.info("WebSocket disconnected", connection_id=connection_id)

    async def subscribe(self, connection_id: str, channel: str) -> bool:
        """Subscribe a connection to a channel."""
        if channel not in self._channels:
            self._channels[channel] = set()

        self._channels[channel].add(connection_id)

        if connection_id in self._metadata:
            if channel not in self._metadata[connection_id]["channels"]:
                self._metadata[connection_id]["channels"].append(channel)

        return True

    async def unsubscribe(self, connection_id: str, channel: str) -> bool:
        """Unsubscribe a connection from a channel."""
        if channel in self._channels:
            self._channels[channel].discard(connection_id)

            if connection_id in self._metadata:
                if channel in self._metadata[connection_id]["channels"]:
                    self._metadata[connection_id]["channels"].remove(channel)

            return True
        return False

    async def send_personal(
        self,
        connection_id: str,
        message: dict[str, Any],
    ) -> bool:
        """Send a message to a specific connection."""
        websocket = self._connections.get(connection_id)
        if websocket:
            try:
                await websocket.send_json(message)
                if connection_id in self._metadata:
                    self._metadata[connection_id]["messages_sent"] += 1
                return True
            except Exception as e:
                logger.error(
                    "Failed to send message",
                    connection_id=connection_id,
                    error=str(e),
                )
                await self.disconnect(connection_id)
        return False

    async def broadcast(
        self,
        message: dict[str, Any],
        channel: str | None = None,
    ) -> int:
        """
        Broadcast a message to all connections or a specific channel.

        Returns:
            Number of clients that received the message
        """
        sent_count = 0

        if channel:
            # Send to channel subscribers
            connection_ids = list(self._channels.get(channel, set()))
        else:
            # Send to all connections
            connection_ids = list(self._connections.keys())

        for connection_id in connection_ids:
            if await self.send_personal(connection_id, message):
                sent_count += 1

        return sent_count

    async def broadcast_to_channels(
        self,
        message: dict[str, Any],
        channels: list[str],
    ) -> int:
        """Broadcast to multiple channels."""
        sent_count = 0
        seen_connections: set[str] = set()

        for channel in channels:
            for connection_id in self._channels.get(channel, set()):
                if connection_id not in seen_connections:
                    if await self.send_personal(connection_id, message):
                        sent_count += 1
                        seen_connections.add(connection_id)

        return sent_count

    async def broadcast_to_tenant(
        self,
        message: dict[str, Any],
        tenant_id: str,
        channel: str | None = None,
    ) -> int:
        """
        Broadcast a message only to connections scoped to `tenant_id`
        (connections authenticated via app/websocket/auth.py with a real
        organization_id - admin connections, which resolve to tenant_id
        None, are never in `_tenant_connections` and so never receive
        tenant-scoped broadcasts through this method).

        Args:
            message: Message payload to send
            tenant_id: Only connections indexed under this tenant receive it
            channel: If given, further restrict to this channel's
                subscribers (e.g. "alerts") - connections that are in the
                tenant but unsubscribed from the channel are skipped.

        Returns:
            Number of clients that received the message
        """
        tenant_connection_ids = self._tenant_connections.get(tenant_id, set())

        if channel is not None:
            channel_subscriber_ids = self._channels.get(channel, set())
            target_ids = tenant_connection_ids & channel_subscriber_ids
        else:
            target_ids = set(tenant_connection_ids)

        sent_count = 0
        for connection_id in target_ids:
            if await self.send_personal(connection_id, message):
                sent_count += 1

        return sent_count

    def get_connection_count(self) -> int:
        """Get total number of active connections."""
        return len(self._connections)

    def get_channel_counts(self) -> dict[str, int]:
        """Get subscriber count per channel."""
        return {
            channel: len(subscribers)
            for channel, subscribers in self._channels.items()
        }

    def get_statistics(self) -> dict[str, Any]:
        """Get WebSocket statistics."""
        return {
            "total_connections": len(self._connections),
            "channels": self.get_channel_counts(),
            "total_messages_sent": sum(
                m.get("messages_sent", 0)
                for m in self._metadata.values()
            ),
        }


# Singleton instance
_manager: ConnectionManager | None = None


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager."""
    global _manager
    if _manager is None:
        _manager = ConnectionManager()
    return _manager
