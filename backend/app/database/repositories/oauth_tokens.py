"""
CyberGuard AI - OAuth Token Repository

Database operations for encrypted OAuth tokens.
Tokens are encrypted before storage and decrypted only when needed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.database.connection import get_database
from app.services.token_encryption import get_token_encryption_service


logger = structlog.get_logger(__name__)


class OAuthToken:
    """OAuth token record from database."""

    def __init__(
        self,
        id: str,
        user_id: str,
        provider: str,
        provider_account_id: str | None,
        encrypted_access_token: str,
        encrypted_refresh_token: str | None,
        token_type: str,
        expires_at: datetime | None,
        scopes: str | None,
        created_at: datetime,
        updated_at: datetime,
    ):
        self.id = id
        self.user_id = user_id
        self.provider = provider
        self.provider_account_id = provider_account_id
        self.encrypted_access_token = encrypted_access_token
        self.encrypted_refresh_token = encrypted_refresh_token
        self.token_type = token_type
        self.expires_at = expires_at
        self.scopes = scopes
        self.created_at = created_at
        self.updated_at = updated_at


class OAuthTokenRepository:
    """
    Repository for OAuth token database operations.

    Security:
    - Tokens encrypted before storage
    - Decryption only on explicit request
    - Never logs token values
    - Parameterized queries only
    """

    def __init__(self):
        self.db = get_database()
        self._encryption = get_token_encryption_service()

    async def store(
        self,
        user_id: str,
        provider: str,
        access_token: str,
        refresh_token: str | None,
        token_type: str,
        expires_at: datetime | None,
        scopes: str | None,
        provider_account_id: str | None = None,
    ) -> OAuthToken:
        """
        Store or update OAuth tokens for a user.

        Encrypts tokens before storage. Uses UPSERT to handle
        reconnection (one token per user per provider).
        """
        now = datetime.now(timezone.utc)

        # Encrypt sensitive tokens
        encrypted_access = self._encryption.encrypt(access_token)
        encrypted_refresh = self._encryption.encrypt(refresh_token) if refresh_token else None

        query = """
            INSERT INTO oauth_tokens (
                id, user_id, provider, provider_account_id,
                encrypted_access_token, encrypted_refresh_token,
                token_type, expires_at, scopes,
                created_at, updated_at
            )
            VALUES (
                %(id)s, %(user_id)s, %(provider)s, %(provider_account_id)s,
                %(encrypted_access_token)s, %(encrypted_refresh_token)s,
                %(token_type)s, %(expires_at)s, %(scopes)s,
                %(created_at)s, %(updated_at)s
            )
            ON CONFLICT (user_id, provider) DO UPDATE SET
                provider_account_id = EXCLUDED.provider_account_id,
                encrypted_access_token = EXCLUDED.encrypted_access_token,
                encrypted_refresh_token = COALESCE(EXCLUDED.encrypted_refresh_token, oauth_tokens.encrypted_refresh_token),
                token_type = EXCLUDED.token_type,
                expires_at = EXCLUDED.expires_at,
                scopes = EXCLUDED.scopes,
                updated_at = EXCLUDED.updated_at
            RETURNING *
        """

        result = await self.db.execute_one(query, {
            "id": str(uuid4()),
            "user_id": user_id,
            "provider": provider,
            "provider_account_id": provider_account_id,
            "encrypted_access_token": encrypted_access,
            "encrypted_refresh_token": encrypted_refresh,
            "token_type": token_type,
            "expires_at": expires_at,
            "scopes": scopes,
            "created_at": now,
            "updated_at": now,
        })

        logger.info(
            "OAuth token stored",
            user_id=user_id,
            provider=provider,
            has_refresh=bool(refresh_token),
        )

        return self._row_to_token(result)

    async def get_by_user(self, user_id: str, provider: str = "google") -> OAuthToken | None:
        """Get OAuth token record for a user (tokens remain encrypted)."""
        query = """
            SELECT * FROM oauth_tokens
            WHERE user_id = %(user_id)s AND provider = %(provider)s
        """
        result = await self.db.execute_one(query, {
            "user_id": user_id,
            "provider": provider,
        })
        return self._row_to_token(result) if result else None

    async def get_decrypted_tokens(
        self,
        user_id: str,
        provider: str = "google",
    ) -> tuple[str, str | None, datetime | None] | None:
        """
        Get decrypted tokens for API use.

        Returns:
            Tuple of (access_token, refresh_token, expires_at) or None if not found
        """
        token_record = await self.get_by_user(user_id, provider)
        if not token_record:
            return None

        try:
            access_token = self._encryption.decrypt(token_record.encrypted_access_token)
            refresh_token = (
                self._encryption.decrypt(token_record.encrypted_refresh_token)
                if token_record.encrypted_refresh_token else None
            )
            return access_token, refresh_token, token_record.expires_at
        except ValueError:
            logger.error("Failed to decrypt tokens", user_id=user_id, provider=provider)
            return None

    async def update_access_token(
        self,
        user_id: str,
        provider: str,
        access_token: str,
        expires_at: datetime | None,
    ) -> bool:
        """Update access token after refresh (keeps existing refresh token)."""
        encrypted_access = self._encryption.encrypt(access_token)

        query = """
            UPDATE oauth_tokens
            SET encrypted_access_token = %(encrypted_access_token)s,
                expires_at = %(expires_at)s,
                updated_at = %(updated_at)s
            WHERE user_id = %(user_id)s AND provider = %(provider)s
            RETURNING id
        """

        result = await self.db.execute_one(query, {
            "user_id": user_id,
            "provider": provider,
            "encrypted_access_token": encrypted_access,
            "expires_at": expires_at,
            "updated_at": datetime.now(timezone.utc),
        })

        if result:
            logger.info("OAuth access token refreshed", user_id=user_id, provider=provider)

        return bool(result)

    async def delete(self, user_id: str, provider: str = "google") -> bool:
        """Delete OAuth tokens for a user (disconnect)."""
        query = """
            DELETE FROM oauth_tokens
            WHERE user_id = %(user_id)s AND provider = %(provider)s
            RETURNING id
        """

        result = await self.db.execute_one(query, {
            "user_id": user_id,
            "provider": provider,
        })

        if result:
            logger.info("OAuth token deleted", user_id=user_id, provider=provider)

        return bool(result)

    async def list_by_provider(self, provider: str = "google") -> list[OAuthToken]:
        """
        List every stored token record for a provider (tokens remain
        encrypted - callers decrypt per-record as needed).

        Used by background pollers (e.g. the Gmail poller) that must
        iterate every connected account on each cycle rather than look up
        one known user_id, since there is no other way to discover which
        users have connected a given provider.
        """
        query = """
            SELECT * FROM oauth_tokens
            WHERE provider = %(provider)s
        """
        results = await self.db.execute(query, {"provider": provider})
        return [self._row_to_token(row) for row in results]

    async def get_by_provider_account(
        self,
        provider: str,
        provider_account_id: str,
    ) -> OAuthToken | None:
        """Get token by provider account (e.g., Gmail email address)."""
        query = """
            SELECT * FROM oauth_tokens
            WHERE provider = %(provider)s AND provider_account_id = %(provider_account_id)s
        """
        result = await self.db.execute_one(query, {
            "provider": provider,
            "provider_account_id": provider_account_id,
        })
        return self._row_to_token(result) if result else None

    def _row_to_token(self, row: dict[str, Any]) -> OAuthToken:
        """Convert database row to OAuthToken (tokens remain encrypted)."""
        return OAuthToken(
            id=str(row["id"]),
            user_id=str(row["user_id"]),
            provider=row["provider"],
            provider_account_id=row.get("provider_account_id"),
            encrypted_access_token=row["encrypted_access_token"],
            encrypted_refresh_token=row.get("encrypted_refresh_token"),
            token_type=row.get("token_type", "Bearer"),
            expires_at=row.get("expires_at"),
            scopes=row.get("scopes"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


# Singleton
_oauth_token_repo: OAuthTokenRepository | None = None


def get_oauth_token_repository() -> OAuthTokenRepository:
    """Get the OAuth token repository."""
    global _oauth_token_repo
    if _oauth_token_repo is None:
        _oauth_token_repo = OAuthTokenRepository()
    return _oauth_token_repo
