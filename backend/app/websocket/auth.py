"""
CyberGuard AI - WebSocket Authentication

Browsers cannot set a custom `Authorization` header on a native WebSocket
upgrade request, so the handshake is authenticated via a `token` query
parameter carrying the same JWT issued by POST /auth/login instead. This
mirrors app.auth.jwt.get_current_active_user's checks (decode -> look up
the live user row -> require is_active) but cannot raise HTTPException -
there is no HTTP response cycle to attach one to on a WS upgrade - so the
caller (app/api/v1/ws.py) is responsible for closing the socket with a
4401 code when this returns None.
"""

import structlog

from app.auth.jwt import verify_token
from app.auth.models import User, UserRole


logger = structlog.get_logger(__name__)


async def authenticate_websocket(token: str | None) -> User | None:
    """
    Resolve the connecting user from a query-param JWT.

    Returns None if the token is missing, invalid/expired, or the
    resolved user no longer exists / is inactive. Never raises - the
    caller must close the WebSocket itself (accept() has not been called
    yet at this point, so the connection is rejected before any channel
    subscription or welcome message).
    """
    if not token:
        return None

    token_data = verify_token(token)
    if not token_data:
        return None

    # Local import to avoid import-time cycles between app.websocket and
    # app.auth (same pattern already used elsewhere in this codebase for
    # lazy service lookups).
    from app.auth.users import get_user_manager

    user = await get_user_manager().get_user_async(token_data.user_id)
    if not user or not user.is_active:
        return None

    return user


def resolve_tenant_scope(user: User) -> str | None:
    """
    Resolve the tenant_id a WebSocket connection should be scoped to.

    None means "unscoped" (admin - sees every tenant's broadcasts, same
    semantics as get_authorized_tenant_ids' tenant_ids=None for admins).
    Any other role is scoped to their own organization_id, which is
    always read from the live User row (never trusted from client
    input) - matching the existing get_authorized_tenant_ids idiom in
    app/api/v1/logs.py.
    """
    if user.role == UserRole.ADMIN:
        return None
    return user.organization_id
