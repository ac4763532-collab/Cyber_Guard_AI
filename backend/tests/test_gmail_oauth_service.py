"""
CyberGuard AI - Gmail OAuth Service Tests

Covers GmailOAuthService's token exchange, refresh, user-info lookup, and
revocation against Google's OAuth endpoints. All HTTP calls are mocked via
httpx.AsyncClient.post/get patches (same pattern as test_network_intel.py) -
no real network traffic and no real Google credentials are used.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.gmail.oauth import GmailOAuthService, GmailTokens


def _make_service(client_id="test-client-id", client_secret="test-client-secret"):
    """Build a GmailOAuthService with OAuth configured, without touching
    real app settings - patches get_settings() for just the fields the
    service reads."""
    settings = MagicMock()
    settings.google_client_id = client_id
    settings.google_client_secret = client_secret
    settings.google_redirect_uri = "http://localhost:8000/api/v1/gmail/oauth/callback"
    settings.gmail_scopes = "https://www.googleapis.com/auth/gmail.readonly,openid,email"

    with patch("app.services.gmail.oauth.get_settings", return_value=settings):
        service = GmailOAuthService()
    return service


def _mock_response(status_code: int, payload: dict):
    response = MagicMock()
    response.status_code = status_code
    response.json = MagicMock(return_value=payload)
    return response


# =============================================================================
# Configuration
# =============================================================================

class TestIsConfigured:
    def test_configured_when_both_set(self):
        service = _make_service()
        assert service.is_configured is True

    def test_not_configured_when_client_id_missing(self):
        service = _make_service(client_id="")
        assert service.is_configured is False

    def test_not_configured_when_secret_missing(self):
        service = _make_service(client_secret="")
        assert service.is_configured is False

    def test_scopes_parsed_from_csv(self):
        service = _make_service()
        assert service.scopes == [
            "https://www.googleapis.com/auth/gmail.readonly",
            "openid",
            "email",
        ]


# =============================================================================
# Authorization URL generation
# =============================================================================

class TestGenerateAuthUrl:
    @pytest.mark.asyncio
    async def test_generate_auth_url_async_builds_valid_google_url(self):
        service = _make_service()

        mock_state_store = MagicMock()
        mock_state_data = MagicMock()
        mock_state_data.state = "fake-state-token"
        mock_state_store.store = AsyncMock(return_value=mock_state_data)

        with patch(
            "app.services.oauth_state_store.get_oauth_state_store",
            return_value=mock_state_store,
        ):
            auth_url, state = await service.generate_auth_url_async(
                user_id="alice", redirect_after="/analysis/email"
            )

        assert auth_url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        assert "client_id=test-client-id" in auth_url
        assert "response_type=code" in auth_url
        assert "access_type=offline" in auth_url
        assert "prompt=consent" in auth_url
        assert "state=fake-state-token" in auth_url
        assert state == "fake-state-token"
        mock_state_store.store.assert_awaited_once_with(
            user_id="alice", redirect_after="/analysis/email"
        )

    @pytest.mark.asyncio
    async def test_generate_auth_url_async_raises_when_not_configured(self):
        service = _make_service(client_id="")
        with pytest.raises(ValueError, match="not configured"):
            await service.generate_auth_url_async(user_id="alice")


# =============================================================================
# Token exchange
# =============================================================================

class TestExchangeCode:
    @pytest.mark.asyncio
    async def test_exchange_code_success(self):
        service = _make_service()
        payload = {
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
        }

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=_mock_response(200, payload)),
        ):
            tokens = await service.exchange_code("fake-auth-code")

        assert isinstance(tokens, GmailTokens)
        assert tokens.access_token == "fake-access-token"
        assert tokens.refresh_token == "fake-refresh-token"
        assert tokens.scope == "https://www.googleapis.com/auth/gmail.readonly"
        assert tokens.is_expired() is False

    @pytest.mark.asyncio
    async def test_exchange_code_failure_raises(self):
        service = _make_service()
        error_payload = {"error": "invalid_grant", "error_description": "Bad code"}

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=_mock_response(400, error_payload)),
        ):
            with pytest.raises(ValueError, match="Bad code"):
                await service.exchange_code("expired-or-reused-code")

    @pytest.mark.asyncio
    async def test_exchange_code_raises_when_not_configured(self):
        service = _make_service(client_secret="")
        with pytest.raises(ValueError, match="not configured"):
            await service.exchange_code("fake-auth-code")


# =============================================================================
# Token refresh
# =============================================================================

class TestRefreshTokens:
    @pytest.mark.asyncio
    async def test_refresh_tokens_success_keeps_refresh_token(self):
        service = _make_service()
        payload = {
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
        }

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=_mock_response(200, payload)),
        ):
            tokens = await service.refresh_tokens("original-refresh-token")

        assert tokens.access_token == "new-access-token"
        # Google's refresh response normally omits refresh_token - the
        # original one must be preserved, not dropped.
        assert tokens.refresh_token == "original-refresh-token"

    @pytest.mark.asyncio
    async def test_refresh_tokens_failure_raises(self):
        service = _make_service()
        error_payload = {"error": "invalid_grant", "error_description": "Token revoked"}

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=_mock_response(400, error_payload)),
        ):
            with pytest.raises(ValueError, match="Token refresh failed"):
                await service.refresh_tokens("revoked-refresh-token")


# =============================================================================
# User info
# =============================================================================

class TestGetUserInfo:
    @pytest.mark.asyncio
    async def test_get_user_info_success(self):
        service = _make_service()
        payload = {
            "email": "analyst@example.com",
            "name": "Security Analyst",
            "picture": "https://example.com/pic.jpg",
            "verified_email": True,
        }

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "get",
            AsyncMock(return_value=_mock_response(200, payload)),
        ):
            user_info = await service.get_user_info("fake-access-token")

        assert user_info.email == "analyst@example.com"
        assert user_info.verified_email is True

    @pytest.mark.asyncio
    async def test_get_user_info_failure_raises(self):
        service = _make_service()

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "get",
            AsyncMock(return_value=_mock_response(401, {"error": "invalid_token"})),
        ):
            with pytest.raises(ValueError, match="Failed to get user info"):
                await service.get_user_info("expired-access-token")


# =============================================================================
# Revocation
# =============================================================================

class TestRevokeAccess:
    @pytest.mark.asyncio
    async def test_revoke_access_success(self):
        service = _make_service()
        response = MagicMock()
        response.status_code = 200

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=response),
        ):
            result = await service.revoke_access("fake-token")

        assert result is True

    @pytest.mark.asyncio
    async def test_revoke_access_failure_returns_false_not_raise(self):
        service = _make_service()
        response = MagicMock()
        response.status_code = 400

        with patch.object(
            httpx_async_client_module().AsyncClient,
            "post",
            AsyncMock(return_value=response),
        ):
            result = await service.revoke_access("already-revoked-token")

        assert result is False


# =============================================================================
# GmailTokens.is_expired
# =============================================================================

class TestGmailTokensExpiry:
    def test_not_expired_when_far_in_future(self):
        tokens = GmailTokens(
            access_token="a",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert tokens.is_expired() is False

    def test_expired_when_in_past(self):
        tokens = GmailTokens(
            access_token="a",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        assert tokens.is_expired() is True

    def test_expired_within_five_minute_buffer(self):
        # Still "fresh" by wall clock, but inside the 5-minute refresh
        # buffer - should be treated as expired so callers refresh early
        # rather than racing an in-flight API call against real expiry.
        tokens = GmailTokens(
            access_token="a",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        )
        assert tokens.is_expired() is True


def httpx_async_client_module():
    """Import httpx lazily so the module-level patch targets the same
    httpx.AsyncClient class that app.services.gmail.oauth imports."""
    import httpx

    return httpx
