"""
CyberGuard AI - Gmail OAuth Service

Handles Google OAuth 2.0 flow for Gmail API access.
Only requests READ-ONLY permissions for defensive security analysis.

Security:
- Tokens stored encrypted in database (not localStorage)
- Access tokens refreshed automatically
- Only gmail.readonly scope requested
- No send/delete/modify permissions
- OAuth state stored in Redis for multi-instance safety
"""

import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlencode

import httpx
import structlog
from pydantic import BaseModel, Field

from app.config import get_settings


logger = structlog.get_logger(__name__)


class GmailTokens(BaseModel):
    """OAuth tokens for Gmail API access."""

    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_at: datetime
    scope: str = ""

    def is_expired(self) -> bool:
        """Check if access token is expired (with 5 min buffer)."""
        return datetime.now(timezone.utc) >= (self.expires_at - timedelta(minutes=5))


class GmailUserInfo(BaseModel):
    """Gmail user information from OAuth."""

    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    verified_email: bool = False


class OAuthState(BaseModel):
    """OAuth state for CSRF protection (legacy - used for in-memory fallback only)."""

    state: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    redirect_after: Optional[str] = None


class GmailOAuthService:
    """
    Gmail OAuth 2.0 Service.

    Handles the complete OAuth flow:
    1. Generate authorization URL
    2. Exchange code for tokens
    3. Refresh expired tokens
    4. Revoke access

    Security:
    - CSRF protection via state parameter (stored in Redis for multi-instance)
    - Only read-only Gmail scope
    - Tokens never exposed to frontend
    - OAuth state is single-use and expires automatically
    """

    # Google OAuth endpoints
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"

    def __init__(self):
        self.settings = get_settings()
        # In-memory fallback ONLY for development when Redis unavailable
        # Production MUST use Redis - see generate_auth_url_async
        self._pending_states: dict[str, OAuthState] = {}
        self._use_redis = True  # Default to Redis; set False only for explicit dev mode

        # Validate configuration
        if not self.settings.google_client_id or not self.settings.google_client_secret:
            logger.warning("Google OAuth not configured - Gmail integration disabled")

    @property
    def is_configured(self) -> bool:
        """Check if Google OAuth is properly configured."""
        return bool(
            self.settings.google_client_id and
            self.settings.google_client_secret
        )

    @property
    def scopes(self) -> list[str]:
        """Get Gmail API scopes (read-only only)."""
        return self.settings.gmail_scopes.split(",")

    async def generate_auth_url_async(
        self,
        user_id: str,
        redirect_after: Optional[str] = None
    ) -> tuple[str, str]:
        """
        Generate OAuth authorization URL with Redis-backed state storage.

        Args:
            user_id: Internal user ID to associate with tokens
            redirect_after: URL to redirect to after OAuth complete

        Returns:
            Tuple of (auth_url, state_token)

        Raises:
            ValueError: If Google OAuth not configured
            RuntimeError: If Redis unavailable (no silent fallback in production)
        """
        if not self.is_configured:
            raise ValueError("Google OAuth not configured")

        # Use shared Redis state store for multi-instance safety
        from app.services.oauth_state_store import get_oauth_state_store

        state_store = get_oauth_state_store()
        state_data = await state_store.store(
            user_id=user_id,
            redirect_after=redirect_after,
        )

        # Build authorization URL
        params = {
            "client_id": self.settings.google_client_id,
            "redirect_uri": self.settings.google_redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state_data.state,
            "access_type": "offline",  # Get refresh token
            "prompt": "consent",  # Always show consent screen for refresh token
        }

        auth_url = f"{self.AUTH_URL}?{urlencode(params)}"

        logger.info(
            "Generated Gmail OAuth URL",
            user_id=user_id,
            scopes=self.scopes,
            state_store="redis",
        )

        return auth_url, state_data.state

    def generate_auth_url(
        self,
        user_id: str,
        redirect_after: Optional[str] = None
    ) -> tuple[str, str]:
        """
        Generate OAuth authorization URL (sync version - legacy).

        DEPRECATED: Use generate_auth_url_async for production.
        This sync version uses in-memory state which is NOT safe
        for multi-instance deployments.

        Args:
            user_id: Internal user ID to associate with tokens
            redirect_after: URL to redirect to after OAuth complete

        Returns:
            Tuple of (auth_url, state_token)
        """
        if not self.is_configured:
            raise ValueError("Google OAuth not configured")

        # Generate state for CSRF protection (in-memory - dev only)
        oauth_state = OAuthState(
            user_id=user_id,
            redirect_after=redirect_after
        )
        self._pending_states[oauth_state.state] = oauth_state

        # Build authorization URL
        params = {
            "client_id": self.settings.google_client_id,
            "redirect_uri": self.settings.google_redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": oauth_state.state,
            "access_type": "offline",  # Get refresh token
            "prompt": "consent",  # Always show consent screen for refresh token
        }

        auth_url = f"{self.AUTH_URL}?{urlencode(params)}"

        logger.info(
            "Generated Gmail OAuth URL",
            user_id=user_id,
            scopes=self.scopes,
            state_store="in-memory (dev only)",
        )

        return auth_url, oauth_state.state

    async def validate_state_async(self, state: str) -> Optional[OAuthState]:
        """
        Validate OAuth state parameter using Redis (async, multi-instance safe).

        Uses atomic GETDEL to ensure single-use consumption.

        Args:
            state: State token from callback

        Returns:
            OAuthState if valid, None otherwise
        """
        from app.services.oauth_state_store import get_oauth_state_store

        state_store = get_oauth_state_store()
        state_data = await state_store.consume(state)

        if not state_data:
            return None

        # Convert to legacy OAuthState format for compatibility
        return OAuthState(
            state=state_data.state,
            user_id=state_data.user_id,
            created_at=state_data.created_at,
            redirect_after=state_data.redirect_after,
        )

    def validate_state(self, state: str) -> Optional[OAuthState]:
        """
        Validate OAuth state parameter (sync version - legacy).

        DEPRECATED: Use validate_state_async for production.
        This sync version uses in-memory state which is NOT safe
        for multi-instance deployments.

        Args:
            state: State token from callback

        Returns:
            OAuthState if valid, None otherwise
        """
        oauth_state = self._pending_states.pop(state, None)

        if not oauth_state:
            logger.warning("Invalid OAuth state", state=state[:8] + "..." if len(state) >= 8 else "short")
            return None

        # Check if state is too old (10 minutes max)
        age = datetime.now(timezone.utc) - oauth_state.created_at
        if age > timedelta(minutes=10):
            logger.warning("OAuth state expired", age_minutes=age.total_seconds() / 60)
            return None

        return oauth_state

    async def exchange_code(self, code: str) -> GmailTokens:
        """
        Exchange authorization code for tokens.

        Args:
            code: Authorization code from OAuth callback

        Returns:
            GmailTokens with access and refresh tokens
        """
        if not self.is_configured:
            raise ValueError("Google OAuth not configured")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.settings.google_client_id,
                    "client_secret": self.settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.settings.google_redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )

            if response.status_code != 200:
                error_data = response.json()
                logger.error(
                    "Token exchange failed",
                    status=response.status_code,
                    error=error_data.get("error"),
                    description=error_data.get("error_description")
                )
                raise ValueError(f"Token exchange failed: {error_data.get('error_description', 'Unknown error')}")

            data = response.json()

        # Calculate expiration time
        expires_in = data.get("expires_in", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        tokens = GmailTokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_at=expires_at,
            scope=data.get("scope", "")
        )

        logger.info(
            "Gmail tokens obtained",
            has_refresh_token=bool(tokens.refresh_token),
            expires_in=expires_in
        )

        return tokens

    async def refresh_tokens(self, refresh_token: str) -> GmailTokens:
        """
        Refresh expired access token.

        Args:
            refresh_token: Refresh token from initial OAuth

        Returns:
            New GmailTokens with fresh access token
        """
        if not self.is_configured:
            raise ValueError("Google OAuth not configured")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.settings.google_client_id,
                    "client_secret": self.settings.google_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )

            if response.status_code != 200:
                error_data = response.json()
                logger.error(
                    "Token refresh failed",
                    status=response.status_code,
                    error=error_data.get("error")
                )
                raise ValueError(f"Token refresh failed: {error_data.get('error_description', 'Unknown error')}")

            data = response.json()

        expires_in = data.get("expires_in", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        tokens = GmailTokens(
            access_token=data["access_token"],
            refresh_token=refresh_token,  # Keep original refresh token
            token_type=data.get("token_type", "Bearer"),
            expires_at=expires_at,
            scope=data.get("scope", "")
        )

        logger.info("Gmail tokens refreshed", expires_in=expires_in)

        return tokens

    async def get_user_info(self, access_token: str) -> GmailUserInfo:
        """
        Get user info from access token.

        Args:
            access_token: Valid access token

        Returns:
            GmailUserInfo with email and name
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )

            if response.status_code != 200:
                raise ValueError("Failed to get user info")

            data = response.json()

        return GmailUserInfo(
            email=data.get("email", ""),
            name=data.get("name"),
            picture=data.get("picture"),
            verified_email=data.get("verified_email", False)
        )

    async def revoke_access(self, token: str) -> bool:
        """
        Revoke OAuth access.

        Args:
            token: Access token or refresh token to revoke

        Returns:
            True if revoked successfully
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.REVOKE_URL,
                params={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0
            )

        success = response.status_code == 200

        if success:
            logger.info("Gmail access revoked")
        else:
            logger.warning("Gmail revocation failed", status=response.status_code)

        return success


# Singleton instance
_oauth_service: Optional[GmailOAuthService] = None


def get_gmail_oauth_service() -> GmailOAuthService:
    """Get the global Gmail OAuth service."""
    global _oauth_service
    if _oauth_service is None:
        _oauth_service = GmailOAuthService()
    return _oauth_service
