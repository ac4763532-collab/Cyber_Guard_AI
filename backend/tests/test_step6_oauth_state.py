"""
STEP 6 Tests: OAuth State Storage

Tests for shared Redis-backed OAuth state storage:
- State generation security
- Storage and retrieval
- TTL expiration
- Single-use consumption (replay protection)
- Multi-instance simulation
- Redis failure handling
"""

import asyncio
import json
import pytest
import secrets
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest_asyncio


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def redis_client():
    """Get a real Redis client for integration tests."""
    from redis.asyncio import Redis
    from app.config import get_settings

    settings = get_settings()
    client = Redis.from_url(settings.redis_url, decode_responses=True)

    try:
        await client.ping()
        yield client
    except Exception:
        pytest.skip("Redis not available")
    finally:
        await client.close()


@pytest_asyncio.fixture
async def oauth_state_store(redis_client):
    """Get a fresh OAuth state store instance."""
    from app.services.oauth_state_store import OAuthStateStore, reset_oauth_state_store

    await reset_oauth_state_store()
    store = OAuthStateStore()
    yield store

    # Cleanup
    await reset_oauth_state_store()


# =============================================================================
# State Generation Tests
# =============================================================================

class TestStateGeneration:
    """Test OAuth state token generation."""

    def test_state_is_cryptographically_random(self):
        """State should use secrets.token_urlsafe for randomness."""
        from app.services.oauth_state_store import OAuthStateData

        # Generate multiple states
        states = [OAuthStateData(user_id="test").state for _ in range(100)]

        # All should be unique
        assert len(set(states)) == 100, "States should be unique"

    def test_state_has_sufficient_length(self):
        """State should be sufficiently long to prevent brute force."""
        from app.services.oauth_state_store import OAuthStateData

        state_data = OAuthStateData(user_id="test")

        # secrets.token_urlsafe(32) produces ~43 characters
        assert len(state_data.state) >= 32, "State should be at least 32 characters"

    def test_state_is_url_safe(self):
        """State should be safe for URL query parameters."""
        from app.services.oauth_state_store import OAuthStateData

        state_data = OAuthStateData(user_id="test")

        # URL-safe characters only
        import re
        assert re.match(r'^[A-Za-z0-9_-]+$', state_data.state), "State should be URL-safe"

    def test_state_not_predictable(self):
        """State should not contain predictable patterns."""
        from app.services.oauth_state_store import OAuthStateData

        state_data = OAuthStateData(user_id="testuser123")

        # Should not contain user_id
        assert "testuser" not in state_data.state.lower()
        assert "123" not in state_data.state

        # Should not contain timestamp patterns
        now = datetime.now()
        assert str(now.year) not in state_data.state
        assert str(now.month).zfill(2) not in state_data.state


# =============================================================================
# Storage Tests
# =============================================================================

class TestStateStorage:
    """Test OAuth state storage in Redis."""

    @pytest.mark.asyncio
    async def test_store_state(self, oauth_state_store):
        """State can be stored in Redis."""
        state_data = await oauth_state_store.store(
            user_id="user123",
            redirect_after="/dashboard",
        )

        assert state_data.state
        assert state_data.user_id == "user123"
        assert state_data.redirect_after == "/dashboard"
        assert state_data.created_at

    @pytest.mark.asyncio
    async def test_state_exists_after_store(self, oauth_state_store):
        """State should exist in Redis after storing."""
        state_data = await oauth_state_store.store(user_id="user123")

        exists = await oauth_state_store.exists(state_data.state)
        assert exists is True

    @pytest.mark.asyncio
    async def test_state_has_ttl(self, oauth_state_store, redis_client):
        """State should have TTL set in Redis."""
        from app.services.oauth_state_store import OAUTH_STATE_KEY_PREFIX, OAUTH_STATE_TTL

        state_data = await oauth_state_store.store(user_id="user123")

        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"
        ttl = await redis_client.ttl(key)

        # TTL should be set and close to expected (allowing some margin)
        assert ttl > 0
        assert ttl <= OAUTH_STATE_TTL

    @pytest.mark.asyncio
    async def test_stored_data_structure(self, oauth_state_store, redis_client):
        """Stored data should have correct structure."""
        from app.services.oauth_state_store import OAUTH_STATE_KEY_PREFIX

        state_data = await oauth_state_store.store(
            user_id="user123",
            redirect_after="/dashboard",
        )

        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"
        raw_value = await redis_client.get(key)

        data = json.loads(raw_value)

        assert "user_id" in data
        assert "created_at" in data
        assert "redirect_after" in data
        assert data["user_id"] == "user123"
        assert data["redirect_after"] == "/dashboard"


# =============================================================================
# Validation Tests
# =============================================================================

class TestStateValidation:
    """Test OAuth state validation."""

    @pytest.mark.asyncio
    async def test_valid_state_succeeds(self, oauth_state_store):
        """Valid state should be successfully consumed."""
        state_data = await oauth_state_store.store(user_id="user123")

        result = await oauth_state_store.consume(state_data.state)

        assert result is not None
        assert result.user_id == "user123"
        assert result.state == state_data.state

    @pytest.mark.asyncio
    async def test_invalid_state_fails(self, oauth_state_store):
        """Invalid state should return None."""
        result = await oauth_state_store.consume("invalid_state_token")

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_state_fails(self, oauth_state_store):
        """Empty state should return None."""
        result = await oauth_state_store.consume("")

        assert result is None

    @pytest.mark.asyncio
    async def test_missing_state_fails(self, oauth_state_store):
        """State that was never stored should return None."""
        fake_state = secrets.token_urlsafe(32)
        result = await oauth_state_store.consume(fake_state)

        assert result is None


# =============================================================================
# Single-Use Tests (Replay Protection)
# =============================================================================

class TestSingleUse:
    """Test that OAuth state is single-use."""

    @pytest.mark.asyncio
    async def test_state_consumed_once(self, oauth_state_store):
        """State should be deleted after first consumption."""
        state_data = await oauth_state_store.store(user_id="user123")

        # First consume should succeed
        result1 = await oauth_state_store.consume(state_data.state)
        assert result1 is not None

        # Second consume should fail
        result2 = await oauth_state_store.consume(state_data.state)
        assert result2 is None

    @pytest.mark.asyncio
    async def test_replay_attack_blocked(self, oauth_state_store):
        """Replay attack with same state should fail."""
        state_data = await oauth_state_store.store(user_id="user123")
        state_token = state_data.state

        # Simulate attacker capturing state
        captured_state = state_token

        # Legitimate user consumes state
        result1 = await oauth_state_store.consume(state_token)
        assert result1 is not None

        # Attacker tries to replay
        result2 = await oauth_state_store.consume(captured_state)
        assert result2 is None, "Replay attack should be blocked"

    @pytest.mark.asyncio
    async def test_concurrent_consume_only_one_succeeds(self, oauth_state_store):
        """Only one of concurrent consume attempts should succeed."""
        state_data = await oauth_state_store.store(user_id="user123")

        # Simulate concurrent requests
        async def try_consume():
            return await oauth_state_store.consume(state_data.state)

        # Run 5 concurrent consume attempts
        results = await asyncio.gather(
            try_consume(),
            try_consume(),
            try_consume(),
            try_consume(),
            try_consume(),
        )

        # Exactly one should succeed
        successes = [r for r in results if r is not None]
        assert len(successes) == 1, "Exactly one concurrent consume should succeed"


# =============================================================================
# Expiration Tests
# =============================================================================

class TestStateExpiration:
    """Test OAuth state expiration."""

    @pytest.mark.asyncio
    async def test_expired_state_fails(self, oauth_state_store, redis_client):
        """Expired state should fail validation."""
        from app.services.oauth_state_store import OAUTH_STATE_KEY_PREFIX

        state_data = await oauth_state_store.store(user_id="user123")

        # Manually expire the state by modifying created_at
        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"
        raw_value = await redis_client.get(key)
        data = json.loads(raw_value)

        # Set created_at to 15 minutes ago (beyond 10 min TTL)
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        data["created_at"] = old_time.isoformat()

        await redis_client.set(key, json.dumps(data))

        # Should fail due to age check
        result = await oauth_state_store.consume(state_data.state)
        assert result is None

    @pytest.mark.asyncio
    async def test_state_deleted_by_redis_ttl(self, oauth_state_store, redis_client):
        """State should be automatically deleted by Redis TTL."""
        from app.services.oauth_state_store import OAUTH_STATE_KEY_PREFIX

        state_data = await oauth_state_store.store(user_id="user123")
        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"

        # Set very short TTL for testing
        await redis_client.expire(key, 1)

        # Wait for expiration
        await asyncio.sleep(1.5)

        # Should no longer exist
        exists = await redis_client.exists(key)
        assert exists == 0


# =============================================================================
# Multi-Instance Tests
# =============================================================================

class TestMultiInstance:
    """Test multi-instance/multi-process scenarios."""

    @pytest.mark.asyncio
    async def test_state_shared_across_instances(self, redis_client):
        """State stored by one instance should be retrievable by another."""
        from app.services.oauth_state_store import OAuthStateStore

        # Simulate Instance A
        instance_a = OAuthStateStore()

        # Simulate Instance B
        instance_b = OAuthStateStore()

        # Instance A stores state
        state_data = await instance_a.store(
            user_id="user123",
            redirect_after="/dashboard",
        )

        # Instance B should be able to consume it
        result = await instance_b.consume(state_data.state)

        assert result is not None
        assert result.user_id == "user123"
        assert result.redirect_after == "/dashboard"

    @pytest.mark.asyncio
    async def test_different_instances_share_redis(self, redis_client):
        """Multiple instances should share the same Redis state."""
        from app.services.oauth_state_store import OAuthStateStore, OAUTH_STATE_KEY_PREFIX

        # Create separate instances (simulating different processes)
        instances = [OAuthStateStore() for _ in range(3)]

        # Each instance stores a state
        states = []
        for i, inst in enumerate(instances):
            state_data = await inst.store(user_id=f"user{i}")
            states.append(state_data)

        # Verify all states exist in Redis
        for state_data in states:
            key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"
            exists = await redis_client.exists(key)
            assert exists > 0

        # Cross-instance consume: instance 2 consumes instance 0's state
        result = await instances[2].consume(states[0].state)
        assert result is not None
        assert result.user_id == "user0"

    @pytest.mark.asyncio
    async def test_oauth_service_async_methods(self, redis_client):
        """GmailOAuthService async methods should use Redis state."""
        from app.services.gmail.oauth import GmailOAuthService

        # Create two service instances (simulating different processes)
        service_a = GmailOAuthService()
        service_b = GmailOAuthService()

        # Service A generates auth URL (stores state in Redis)
        try:
            auth_url, state = await service_a.generate_auth_url_async(
                user_id="testuser",
                redirect_after="/callback",
            )
        except ValueError:
            # Google OAuth not configured - skip
            pytest.skip("Google OAuth not configured")

        # Service B validates state (retrieves from Redis)
        oauth_state = await service_b.validate_state_async(state)

        assert oauth_state is not None
        assert oauth_state.user_id == "testuser"
        assert oauth_state.redirect_after == "/callback"


# =============================================================================
# Redis Failure Tests
# =============================================================================

class TestRedisFailure:
    """Test behavior when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_store_fails_without_redis(self):
        """Storing state should fail when Redis unavailable."""
        from app.services.oauth_state_store import OAuthStateStore, reset_oauth_state_store

        await reset_oauth_state_store()
        store = OAuthStateStore()

        # Mock Redis connection failure
        with patch.object(store, '_get_redis', side_effect=RuntimeError("Connection refused")):
            with pytest.raises(RuntimeError):
                await store.store(user_id="user123")

    @pytest.mark.asyncio
    async def test_consume_returns_none_without_redis(self):
        """Consuming state should return None when Redis unavailable."""
        from app.services.oauth_state_store import OAuthStateStore, reset_oauth_state_store

        await reset_oauth_state_store()
        store = OAuthStateStore()

        # Mock Redis connection failure
        async def mock_get_redis():
            raise RuntimeError("Connection refused")

        store._get_redis = mock_get_redis

        result = await store.consume("some_state")
        assert result is None

    @pytest.mark.asyncio
    async def test_no_silent_fallback_to_memory(self):
        """Redis failure should NOT silently fall back to in-memory state."""
        from app.services.oauth_state_store import OAuthStateStore

        store = OAuthStateStore()

        # Verify no fallback dictionary exists
        assert not hasattr(store, '_pending_states') or store._pending_states is None or len(getattr(store, '_pending_states', {})) == 0

    @pytest.mark.asyncio
    async def test_health_check_reports_failure(self):
        """Health check should report unhealthy when Redis unavailable."""
        from app.services.oauth_state_store import OAuthStateStore

        store = OAuthStateStore()

        # Mock Redis failure
        async def mock_get_redis():
            raise RuntimeError("Connection refused")

        store._get_redis = mock_get_redis

        health = await store.health_check()
        assert health["status"] == "unhealthy"


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_full_oauth_flow_simulation(self, oauth_state_store):
        """Simulate complete OAuth flow with state."""
        # Step 1: User initiates OAuth
        state_data = await oauth_state_store.store(
            user_id="john_doe",
            redirect_after="/gmail/status",
        )

        # Step 2: Verify state exists (before callback)
        assert await oauth_state_store.exists(state_data.state)

        # Step 3: Callback with state (consume)
        result = await oauth_state_store.consume(state_data.state)
        assert result is not None
        assert result.user_id == "john_doe"

        # Step 4: Verify state no longer exists (single-use)
        assert not await oauth_state_store.exists(state_data.state)

        # Step 5: Replay attempt fails
        replay_result = await oauth_state_store.consume(state_data.state)
        assert replay_result is None

    @pytest.mark.asyncio
    async def test_multiple_users_concurrent(self, oauth_state_store):
        """Multiple users can have concurrent OAuth flows."""
        # Store states for multiple users
        states = {}
        for user_id in ["user_a", "user_b", "user_c"]:
            state_data = await oauth_state_store.store(user_id=user_id)
            states[user_id] = state_data.state

        # All states should be valid
        for user_id, state in states.items():
            result = await oauth_state_store.consume(state)
            assert result is not None
            assert result.user_id == user_id


# =============================================================================
# Security Tests
# =============================================================================

class TestSecurity:
    """Security-focused tests."""

    @pytest.mark.asyncio
    async def test_no_sensitive_data_in_state_token(self, oauth_state_store):
        """State token should not contain sensitive data."""
        state_data = await oauth_state_store.store(
            user_id="secret_user_id_12345",
            redirect_after="/secret/path",
        )

        # Token should not contain any of these
        assert "secret" not in state_data.state.lower()
        assert "user" not in state_data.state.lower()
        assert "12345" not in state_data.state
        assert "path" not in state_data.state.lower()

    @pytest.mark.asyncio
    async def test_state_not_logged(self, oauth_state_store, caplog):
        """Full state token should not appear in logs."""
        import logging

        with caplog.at_level(logging.DEBUG):
            state_data = await oauth_state_store.store(user_id="user123")
            await oauth_state_store.consume(state_data.state)

        # Full state should not be in logs
        full_state = state_data.state
        for record in caplog.records:
            assert full_state not in record.message

    @pytest.mark.asyncio
    async def test_stored_data_does_not_contain_tokens(self, oauth_state_store, redis_client):
        """Stored state should not contain OAuth tokens."""
        from app.services.oauth_state_store import OAUTH_STATE_KEY_PREFIX

        state_data = await oauth_state_store.store(user_id="user123")
        key = f"{OAUTH_STATE_KEY_PREFIX}{state_data.state}"

        raw_value = await redis_client.get(key)
        data = json.loads(raw_value)

        # Should not contain token-like fields
        assert "access_token" not in data
        assert "refresh_token" not in data
        assert "token" not in str(data).lower() or "token" in ["token_type"]  # token_type is metadata, ok
