"""
CyberGuard AI - WebSocket Endpoint

WebSocket route for real-time dashboard updates.
"""

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import structlog

from app.websocket.auth import authenticate_websocket, resolve_tenant_scope
from app.websocket.manager import get_connection_manager


logger = structlog.get_logger(__name__)

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    channels: str = Query("system,alerts", description="Comma-separated channels"),
    token: str | None = Query(None, description="JWT from POST /auth/login"),
):
    """
    WebSocket endpoint for real-time updates.

    Channels:
    - system: System status and health updates
    - alerts: New alerts and alert updates
    - events: Security event stream
    - agents: Agent status updates

    Authentication: browsers cannot set a custom Authorization header on a
    WebSocket upgrade, so the same JWT issued by POST /auth/login is passed
    as a `token` query parameter instead. A missing/invalid/expired token,
    or an inactive user, closes the socket with code 4401 before accept()
    is ever called - no channel subscription or welcome message is sent to
    an unauthenticated client.

    Example client connection:
        ws://localhost:8000/api/v1/ws?channels=alerts&token=<jwt>
    """
    user = await authenticate_websocket(token)
    if user is None:
        await websocket.close(code=4401, reason="Unauthorized")
        return

    tenant_id = resolve_tenant_scope(user)

    manager = get_connection_manager()

    # Parse channels
    channel_list = [c.strip() for c in channels.split(",") if c.strip()]

    # Accept connection
    connection_id = await manager.connect(
        websocket,
        channel_list,
        user_id=user.id,
        tenant_id=tenant_id,
    )

    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_json()

            # Handle client commands
            await handle_client_message(connection_id, data, manager)

    except WebSocketDisconnect:
        await manager.disconnect(connection_id)
    except Exception as e:
        logger.error("WebSocket error", connection_id=connection_id, error=str(e))
        await manager.disconnect(connection_id)


async def handle_client_message(
    connection_id: str,
    data: dict[str, Any],
    manager,
) -> None:
    """Handle incoming client messages."""
    message_type = data.get("type", "")

    if message_type == "ping":
        # Respond to ping
        await manager.send_personal(connection_id, {
            "type": "pong",
            "timestamp": data.get("timestamp"),
        })

    elif message_type == "subscribe":
        # Subscribe to channel
        channel = data.get("channel")
        if channel:
            await manager.subscribe(connection_id, channel)
            await manager.send_personal(connection_id, {
                "type": "subscribed",
                "channel": channel,
            })

    elif message_type == "unsubscribe":
        # Unsubscribe from channel
        channel = data.get("channel")
        if channel:
            await manager.unsubscribe(connection_id, channel)
            await manager.send_personal(connection_id, {
                "type": "unsubscribed",
                "channel": channel,
            })

    elif message_type == "status":
        # Return connection status
        stats = manager.get_statistics()
        await manager.send_personal(connection_id, {
            "type": "status",
            "stats": stats,
        })


@router.get("/ws/stats", tags=["WebSocket"])
async def get_websocket_stats() -> dict[str, Any]:
    """Get WebSocket connection statistics."""
    manager = get_connection_manager()
    return manager.get_statistics()
