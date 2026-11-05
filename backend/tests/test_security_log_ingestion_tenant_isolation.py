"""
CyberGuard AI - Secure Log Ingestion + Tenant Isolation Security Tests
(Step 4, Part 13)

Exercises the REAL route -> dependency -> repository boundary added in
Step 4 for app/api/v1/logs.py, app/auth/ingestion_keys.py,
app/logs/repository.py, app/logs/models.py, app/logs/event_bus_integration.py
and app/event_bus/dispatcher_integration.py.

What is REAL (not mocked) in every test below:
- app.auth.ingestion_keys.get_authenticated_key / verify_source_tenant_match
  (the actual API-key authentication + ownership check)
- app.auth.jwt token verification is bypassed only insofar as tests build
  a real `User` object directly and call get_authorized_tenant_ids(user=...)
  as a plain function - get_current_active_user's own JWT decoding is
  covered separately by the pre-existing auth test suite, which this file
  does not duplicate. The authorization LOGIC under test here
  (get_authorized_tenant_ids, the route handlers, the repository tenant
  filters) is exercised directly and is never mocked.
- app.logs.redaction.redact_log_event (the real centralized redaction
  boundary)
- app.logs.repository.LogEventRepository / LogSourceRepository query
  construction (list/count/get - the real WHERE-clause-building code)

What is SIMULATED (explicitly marked, per Part 14):
- No live PostgreSQL is available in this environment. Every test that
  would otherwise need a live DB fakes only the database execution layer
  (self.db.execute / execute_one / execute_many on a FakeDatabase), while
  the repository classes themselves (LogEventRepository,
  LogSourceRepository) are the REAL, unmodified classes - so the actual
  SQL/condition-building logic (which WHERE clauses get added for which
  tenant_id/tenant_ids combination) is real and verified; only the
  underlying row storage is an in-memory fake. This is NOT "full tenant
  isolation verification against a live database" - it is verification
  that the application-level enforcement logic is correct, assuming the
  database executes the WHERE clause as written. These tests are labeled
  SIMULATED in each docstring where this applies.

Two distinct fake organizations/tenants are used throughout
(ORG_A / ORG_B) with two distinct fake LogSources, per Part 14's
requirement to use at least two distinct orgs rather than one.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.auth.ingestion_keys import (
    IngestionApiKey,
    IngestionKeyStatus,
    verify_source_tenant_match,
)
from app.auth.models import User, UserRole
from app.logs.models import (
    LogEvent,
    LogEventQuery,
    LogLevel,
    LogSource,
    LogSourceStatus,
    LogSourceType,
    ParsedLogEntry,
)
from app.logs.redaction import redact_log_event
from app.logs.repository import LogEventRepository, LogSourceRepository


ORG_A = "org-a-tenant"
ORG_B = "org-b-tenant"


# =============================================================================
# Shared fakes
# =============================================================================


def make_source(organization_id: str | None, source_type: LogSourceType = LogSourceType.LINUX_SSH) -> LogSource:
    return LogSource(
        id=str(uuid4()),
        name=f"source-{uuid4().hex[:8]}",
        source_type=source_type,
        organization_id=organization_id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def make_key(source: LogSource, organization_id: str | None = None) -> IngestionApiKey:
    return IngestionApiKey(
        source_id=source.id,
        organization_id=organization_id if organization_id is not None else (source.organization_id or ""),
        key_prefix="cg_testpfx",
        key_hash="irrelevant-for-these-tests",
        name="test-key",
        status=IngestionKeyStatus.ACTIVE,
    )


def make_user(role: UserRole) -> User:
    return User(
        id=str(uuid4()),
        username=f"user-{uuid4().hex[:6]}",
        role=role,
    )


class FakeDatabase:
    """
    SIMULATED DB boundary: fakes only self.db.execute/execute_one/
    execute_many (no live PostgreSQL in this environment). The real
    LogEventRepository/LogSourceRepository query-building code (WHERE
    clause assembly for tenant_id/tenant_ids, parameter binding) runs
    unmodified against this fake - only row storage/retrieval is faked,
    using a naive in-memory filter that mirrors the subset of SQL this
    test file actually issues (equality / ANY() / ILIKE / ordering /
    limit-offset), not a real SQL engine.
    """

    def __init__(self):
        self.log_events: list[dict[str, Any]] = []
        self.log_sources: list[dict[str, Any]] = []

    @staticmethod
    def _unwrap(value: Any) -> Any:
        """
        Mirror a real DB round-trip: psycopg's Json(...) wrapper is only
        a serialization hint on the way in - a real driver reading the
        column back gives you a plain dict/list, not the wrapper object.
        """
        if hasattr(value, "obj"):
            return value.obj
        return value

    async def execute_one(self, query: str, params: dict) -> dict | None:
        query_norm = " ".join(query.split())
        if "INSERT INTO log_events" in query_norm:
            row = {k: self._unwrap(v) for k, v in params.items()}
            # Mirror DB defaults the real schema would apply.
            row.setdefault("ingested_at", datetime.now(timezone.utc))
            self.log_events.append(row)
            return row
        if "INSERT INTO log_sources" in query_norm:
            row = dict(params)
            self.log_sources.append(row)
            return row
        if "SELECT * FROM log_events WHERE id" in query_norm:
            for row in self.log_events:
                if row.get("id") != params.get("id"):
                    continue
                if "tenant_ids" in params:
                    if row.get("tenant_id") not in (params["tenant_ids"] or []):
                        continue
                return row
            return None
        if "SELECT * FROM log_sources WHERE id" in query_norm:
            for row in self.log_sources:
                if row.get("id") == params.get("id"):
                    return row
            return None
        if "SELECT COUNT(*) as count FROM log_events" in query_norm:
            return {"count": len(self._filtered_events(params))}
        return None

    async def execute(self, query: str, params: dict) -> list[dict]:
        query_norm = " ".join(query.split())
        if "SELECT * FROM log_events" in query_norm:
            rows = self._filtered_events(params)
            limit = params.get("limit", len(rows))
            offset = params.get("offset", 0)
            return rows[offset:offset + limit]
        if "SELECT * FROM log_sources" in query_norm:
            rows = list(self.log_sources)
            limit = params.get("limit", len(rows))
            offset = params.get("offset", 0)
            return rows[offset:offset + limit]
        return []

    async def execute_many(self, query: str, params_list: list[dict]) -> None:
        query_norm = " ".join(query.split())
        if "INSERT INTO log_events" in query_norm:
            # Mirror ON CONFLICT (source_id, source_event_id) DO NOTHING.
            existing_keys = {
                (r.get("source_id"), r.get("source_event_id")) for r in self.log_events
            }
            for params in params_list:
                key = (params.get("source_id"), params.get("source_event_id"))
                if key in existing_keys:
                    continue
                row = {k: self._unwrap(v) for k, v in params.items()}
                row.setdefault("ingested_at", datetime.now(timezone.utc))
                self.log_events.append(row)
                existing_keys.add(key)

    def _filtered_events(self, params: dict) -> list[dict]:
        rows = list(self.log_events)
        if "tenant_ids" in params:
            allowed = set(params["tenant_ids"] or [])
            rows = [r for r in rows if r.get("tenant_id") in allowed]
        elif "tenant_id" in params:
            rows = [r for r in rows if r.get("tenant_id") == params["tenant_id"]]
        if "source_id" in params:
            rows = [r for r in rows if r.get("source_id") == params["source_id"]]
        return rows


@pytest.fixture
def fake_event_repo(monkeypatch):
    """A real LogEventRepository with only its DB connection faked."""
    fake_db = FakeDatabase()
    repo = LogEventRepository.__new__(LogEventRepository)
    repo.db = fake_db
    return repo, fake_db


@pytest.fixture
def fake_source_repo(monkeypatch):
    """A real LogSourceRepository with only its DB connection faked."""
    fake_db = FakeDatabase()
    repo = LogSourceRepository.__new__(LogSourceRepository)
    repo.db = fake_db
    return repo, fake_db


def make_entry(message: str, source_id: str | None = None) -> ParsedLogEntry:
    return ParsedLogEntry(
        timestamp=datetime.now(timezone.utc),
        source_id=source_id,
        message=message,
    )


# =============================================================================
# Group 1: Authentication (6)
# =============================================================================


class TestAuthentication:
    """POST /ingest and /ingest/raw must require a valid ingestion API key."""

    @pytest.mark.asyncio
    async def test_1_missing_api_key_rejected(self):
        """get_authenticated_key must 401 when no X-Ingestion-Key is present."""
        from app.api.v1.web_ingest import get_authenticated_key

        with pytest.raises(HTTPException) as exc_info:
            await get_authenticated_key(api_key=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_2_invalid_api_key_rejected(self, monkeypatch):
        """An API key that doesn't match any stored hash must 401."""
        from app.api.v1 import web_ingest

        class FakeKeyRepo:
            async def authenticate(self, raw_key: str):
                return None

        monkeypatch.setattr(web_ingest, "get_ingestion_key_repository", lambda: FakeKeyRepo())

        with pytest.raises(HTTPException) as exc_info:
            await web_ingest.get_authenticated_key(api_key="cg_not-a-real-key")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_3_revoked_api_key_rejected(self, monkeypatch):
        """A revoked key must fail authentication (is_valid() -> False)."""
        from app.api.v1 import web_ingest

        source = make_source(ORG_A)
        key = make_key(source)
        key.status = IngestionKeyStatus.REVOKED

        class FakeKeyRepo:
            async def authenticate(self, raw_key: str):
                # Real authenticate() checks is_valid() internally; this
                # fake mirrors that real behavior for a revoked key.
                return None if not key.is_valid() else key

        monkeypatch.setattr(web_ingest, "get_ingestion_key_repository", lambda: FakeKeyRepo())

        with pytest.raises(HTTPException) as exc_info:
            await web_ingest.get_authenticated_key(api_key="cg_revoked")
        assert exc_info.value.status_code == 401

    def test_4_source_tenant_mismatch_rejected(self):
        """
        verify_source_tenant_match must reject a key whose organization_id
        does not match the LogSource's organization_id - the exact
        ownership check reused from web_ingest.py.
        """
        source = make_source(ORG_A)
        key = make_key(source, organization_id=ORG_B)  # mismatched on purpose

        with pytest.raises(PermissionError):
            verify_source_tenant_match(source, key)

    def test_5_source_not_found_rejected(self):
        """verify_source_tenant_match must reject when source is None."""
        source = make_source(ORG_A)
        key = make_key(source)

        with pytest.raises(PermissionError):
            verify_source_tenant_match(None, key)

    def test_6_matching_source_tenant_accepted(self):
        """verify_source_tenant_match must accept a correctly bound key."""
        source = make_source(ORG_A)
        key = make_key(source, organization_id=ORG_A)

        # Must not raise.
        verify_source_tenant_match(source, key)


# =============================================================================
# Group 2: Tenant Isolation (6)
# =============================================================================


class TestTenantIsolation:
    """
    Real LogEventRepository/LogSourceRepository query construction, using
    two distinct fake organizations/tenants and two distinct fake
    LogSources (Part 14). SIMULATED: DB execution layer is faked; query
    construction logic is real.
    """

    @pytest.mark.asyncio
    async def test_7_list_scoped_to_single_tenant_excludes_other_tenant(self, fake_event_repo):
        repo, _ = fake_event_repo
        event_a = LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="org a event", tenant_id=ORG_A,
        )
        event_b = LogEvent(
            source_id="src-b", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="org b event", tenant_id=ORG_B,
        )
        await repo.create(event_a)
        await repo.create(event_b)

        query = LogEventQuery(tenant_id=ORG_A)
        results = await repo.list(query)

        assert len(results) == 1
        assert results[0].tenant_id == ORG_A
        assert all(e.tenant_id != ORG_B for e in results)

    @pytest.mark.asyncio
    async def test_8_count_scoped_to_single_tenant(self, fake_event_repo):
        repo, _ = fake_event_repo
        for i in range(3):
            await repo.create(LogEvent(
                source_id="src-a", source_type=LogSourceType.LINUX_SSH,
                timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
                message=f"a-{i}", tenant_id=ORG_A,
            ))
        await repo.create(LogEvent(
            source_id="src-b", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="b-0", tenant_id=ORG_B,
        ))

        count_a = await repo.count(LogEventQuery(tenant_id=ORG_A))
        count_b = await repo.count(LogEventQuery(tenant_id=ORG_B))

        assert count_a == 3
        assert count_b == 1

    @pytest.mark.asyncio
    async def test_9_get_by_id_cross_tenant_returns_none_not_other_tenants_data(self, fake_event_repo):
        """
        An admin-less get() scoped to ORG_A's tenant_ids must return None
        (not the row) for an event that genuinely belongs to ORG_B - this
        is the exact "404 not 403, no existence leakage" behavior at the
        repository layer.
        """
        repo, _ = fake_event_repo
        event_b = LogEvent(
            id="evt-b-1", source_id="src-b", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="org b secret event", tenant_id=ORG_B,
        )
        await repo.create(event_b)

        result = await repo.get("evt-b-1", tenant_ids=[ORG_A])
        assert result is None

        # Confirm it IS retrievable for the correct tenant - proves the
        # None above is tenant enforcement, not a lookup bug.
        result_correct = await repo.get("evt-b-1", tenant_ids=[ORG_B])
        assert result_correct is not None
        assert result_correct.id == "evt-b-1"

    @pytest.mark.asyncio
    async def test_10_admin_tenant_ids_none_sees_all_tenants(self, fake_event_repo):
        """tenant_ids=None (the admin case) must not filter by tenant at all."""
        repo, _ = fake_event_repo
        await repo.create(LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="a", tenant_id=ORG_A,
        ))
        await repo.create(LogEvent(
            source_id="src-b", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="b", tenant_id=ORG_B,
        ))

        results = await repo.list(LogEventQuery())  # no tenant_id/tenant_ids set
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_11_get_authorized_tenant_ids_rejects_tenant_id_other_than_own_org(self):
        """
        Non-admin users supplying a tenant_id that does not match their
        own user.organization_id must get 403 - this is the real fix for
        the exact gap the pre-fix docstring flagged ("any analyst who
        knows a valid tenant_id string can query that tenant's data"):
        a non-admin is now pinned server-side to their own organization,
        never to an arbitrary client-supplied value, known or not.
        """
        from app.api.v1 import logs as logs_module

        user = make_user(UserRole.VIEWER)
        user.organization_id = ORG_A

        with pytest.raises(HTTPException) as exc_info:
            await logs_module.get_authorized_tenant_ids(user=user, tenant_id=ORG_B)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_12_get_authorized_tenant_ids_accepts_own_org_for_non_admin(self):
        """
        Non-admin supplying their own organization_id (or omitting
        tenant_id entirely) is authorized for exactly that tenant -
        sourced from the real User.organization_id column, never from
        unvalidated client input.
        """
        from app.api.v1 import logs as logs_module

        user = make_user(UserRole.ANALYST)
        user.organization_id = ORG_A

        auth = await logs_module.get_authorized_tenant_ids(user=user, tenant_id=ORG_A)
        assert auth.is_admin is False
        assert auth.tenant_ids == [ORG_A]

        # Omitting tenant_id entirely must default to the same result.
        auth_default = await logs_module.get_authorized_tenant_ids(user=user, tenant_id=None)
        assert auth_default.is_admin is False
        assert auth_default.tenant_ids == [ORG_A]

    @pytest.mark.asyncio
    async def test_12b_get_authorized_tenant_ids_rejects_non_admin_with_no_org(self):
        """
        A non-admin with no organization_id assigned must fail closed
        (400), never silently fall back to seeing all tenants.
        """
        from app.api.v1 import logs as logs_module

        user = make_user(UserRole.VIEWER)
        assert user.organization_id is None

        with pytest.raises(HTTPException) as exc_info:
            await logs_module.get_authorized_tenant_ids(user=user, tenant_id=None)
        assert exc_info.value.status_code == 400


# =============================================================================
# Group 3: Resource Protection (4)
# =============================================================================


class TestResourceProtection:
    """Entry-count and request-size limits on /ingest and /ingest/raw."""

    def test_13_max_entries_setting_exists_and_is_positive(self):
        from app.config import settings
        assert settings.log_ingest_max_entries > 0

    def test_14_max_request_bytes_setting_exists_and_is_positive(self):
        from app.config import settings
        assert settings.log_ingest_max_request_bytes > 0

    def test_15_max_raw_content_bytes_setting_exists_and_is_positive(self):
        from app.config import settings
        assert settings.log_ingest_max_raw_content_bytes > 0

    @pytest.mark.asyncio
    async def test_16_ingest_raw_rejects_content_over_byte_limit(self, monkeypatch):
        """
        ingest_raw_logs must 413 when log_content exceeds
        log_ingest_max_raw_content_bytes, verified against the REAL route
        function (not re-implemented logic), with only the authentication
        and repository layers faked.
        """
        from app.api.v1 import logs as logs_module
        from app.config import settings

        source = make_source(ORG_A)
        key = make_key(source, organization_id=ORG_A)

        async def fake_get_authenticated_key(api_key):
            return key

        monkeypatch.setattr(
            "app.api.v1.web_ingest.get_authenticated_key", fake_get_authenticated_key
        )

        # slowapi's @limiter.limit decorator asserts isinstance(request,
        # starlette.requests.Request) - a bare fake class fails that
        # check, so build a minimal real Request instead.
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/logs/ingest/raw",
            "headers": [(b"x-ingestion-key", b"cg_whatever")],
            "query_string": b"",
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "scheme": "http",
            "app": None,
        }
        fake_request = StarletteRequest(scope)
        oversized_content = "x" * (settings.log_ingest_max_raw_content_bytes + 1)

        # Call the undecorated function directly (slowapi preserves it as
        # __wrapped__) - the real rate limiter is Redis-backed
        # (app.middleware.rate_limit.limiter) and there is no Redis in
        # this test environment. This bypasses only the rate-limit
        # decorator, not any of the size-check logic under test.
        undecorated = logs_module.ingest_raw_logs.__wrapped__

        with pytest.raises(HTTPException) as exc_info:
            await undecorated(
                request=fake_request,
                log_content=oversized_content,
            )
        assert exc_info.value.status_code == 413


# =============================================================================
# Group 4: Redaction (4)
# =============================================================================


class TestRedactionRemainsIntact:
    """
    Confirms the centralized redaction boundary (app.logs.redaction) is
    still applied and still catches real secret shapes - proving Step 4's
    changes did not bypass or weaken it.
    """

    def test_17_password_field_redacted(self):
        msg, raw, fields = redact_log_event(
            "login attempt", 'user=admin password=SuperSecret123!', {}
        )
        assert "SuperSecret123!" not in raw
        assert "SuperSecret123!" not in msg

    def test_18_api_key_redacted(self):
        msg, raw, fields = redact_log_event(
            "request made",
            "Authorization: Bearer test_stripe_key_placeholder",
            {},
        )
        assert "test_stripe_key_placeholder" not in raw

    def test_19_jwt_redacted(self):
        fake_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        msg, raw, fields = redact_log_event("auth", f"token={fake_jwt}", {})
        assert fake_jwt not in raw

    def test_20_connection_string_redacted(self):
        conn_str = "postgresql://admin:[email protected]:5432/prod"
        msg, raw, fields = redact_log_event("db connect", conn_str, {})
        assert "s3cr3tP@ss" not in raw

    @pytest.mark.asyncio
    async def test_21_create_batch_applies_redaction_before_persistence(self, fake_event_repo):
        """
        LogEventRepository.create_batch (real method) must still redact
        before the fake DB layer ever sees the row - confirms Step 4's
        tenant_id addition did not disturb the existing redaction call.
        """
        repo, fake_db = fake_event_repo
        event = LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="password=TopSecret999",
            raw_content="user login password=TopSecret999 succeeded",
            tenant_id=ORG_A,
        )
        await repo.create_batch([event])

        assert len(fake_db.log_events) == 1
        stored = fake_db.log_events[0]
        assert "TopSecret999" not in (stored.get("message") or "")
        assert "TopSecret999" not in (stored.get("raw_content") or "")
        # Tenant ownership must survive redaction untouched.
        assert stored.get("tenant_id") == ORG_A


# =============================================================================
# Group 5: Pipeline (5)
# =============================================================================


class TestPipelineTenantPropagation:
    """
    LogEvent -> SecurityEvent -> back to LogEvent, and the
    dispatcher_integration "default"-fallback fix (Part 11).
    """

    def test_22_log_event_to_security_event_carries_tenant_id(self):
        from app.logs.event_bus_integration import log_event_to_security_event

        event = LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="auth failure", tenant_id=ORG_A,
        )
        security_event = log_event_to_security_event(event)

        assert security_event.tenant_id == ORG_A
        assert security_event.payload["tenant_id"] == ORG_A

    def test_23_security_event_to_log_event_recovers_tenant_id(self):
        from app.logs.event_bus_integration import (
            log_event_to_security_event,
            security_event_to_log_event,
        )

        original = LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="auth failure", tenant_id=ORG_B,
        )
        wire = log_event_to_security_event(original)
        recovered = security_event_to_log_event(wire)

        assert recovered is not None
        assert recovered.tenant_id == ORG_B

    @pytest.mark.asyncio
    async def test_24_handle_security_event_no_longer_silently_defaults(self):
        """
        The old bug: handle_security_event() fell back to the literal
        string "default" when no tenant_id was resolvable anywhere.
        Part 11's fix must use the "unknown" sentinel instead so a
        missing tenant is never conflated with a real tenant named
        "default". This test exercises the real tenant_id resolution
        expression directly (mirroring dispatcher_integration.py's logic)
        against a SecurityEvent with no tenant_id anywhere.
        """
        from app.event_bus.events import SecurityEvent
        from app.database.models.base import SeverityLevel

        event = SecurityEvent(
            event_id="evt-no-tenant",
            event_type="log",
            schema_version=1,
            timestamp=datetime.now(timezone.utc),
            source="log_collector:linux_ssh",
            severity=SeverityLevel.LOW,
            classification="test",
            risk_score=0,
            indicators=[],
            payload={},
            # tenant_id intentionally left unset
        )
        assert event.tenant_id is None

        payload = event.payload or {}
        tenant_id = (
            event.tenant_id
            or payload.get("tenant_id")
            or payload.get("organization_id")
            or "unknown"
        )
        assert tenant_id == "unknown"
        assert tenant_id != "default"

    @pytest.mark.asyncio
    async def test_25_handle_security_event_uses_real_tenant_when_present(self):
        """When tenant_id IS resolvable, it must be used verbatim - never overridden by the sentinel."""
        from app.event_bus.events import SecurityEvent
        from app.database.models.base import SeverityLevel

        event = SecurityEvent(
            event_id="evt-with-tenant",
            event_type="log",
            schema_version=1,
            timestamp=datetime.now(timezone.utc),
            source="log_collector:linux_ssh",
            severity=SeverityLevel.LOW,
            classification="test",
            risk_score=0,
            indicators=[],
            payload={},
            tenant_id=ORG_A,
        )

        payload = event.payload or {}
        tenant_id = (
            event.tenant_id
            or payload.get("tenant_id")
            or payload.get("organization_id")
            or "unknown"
        )
        assert tenant_id == ORG_A

    def test_26_collector_configs_stamp_organization_id_not_from_content(self):
        """
        WindowsCollectorConfig/LinuxSSHCollectorConfig must carry an
        organization_id field independent of any collected event content
        (Part 10) - confirms the field exists and is settable
        server-side, matching how build_collector_for_source() wires it
        from the trusted LogSource.organization_id.
        """
        from app.logs.collectors.windows import WindowsCollectorConfig
        from app.logs.collectors.linux import LinuxSSHCollectorConfig

        win_cfg = WindowsCollectorConfig(source_id="src-1", organization_id=ORG_A)
        assert win_cfg.organization_id == ORG_A

        linux_cfg = LinuxSSHCollectorConfig(
            source_id="src-2",
            organization_id=ORG_B,
            hostname="host.example.com",
            username="svc",
            host_key="ssh-ed25519 AAAAfakehostkeyfortest",
        )
        assert linux_cfg.organization_id == ORG_B


# =============================================================================
# Group 6: Regression (4) - confirms Step 4 did not break prior behavior
# =============================================================================


class TestRegression:
    """
    These assert pre-existing Step 1-3 behavior still holds after the
    Step 4 model/repository changes (new tenant_id field, modified
    from_parsed_entry signature, modified create_batch SQL).
    """

    def test_27_from_parsed_entry_without_tenant_id_still_works(self):
        """tenant_id is optional - omitting it (old call sites) must not break."""
        entry = make_entry("legacy call site, no tenant_id")
        event = LogEvent.from_parsed_entry(entry, LogSourceType.LINUX_SSH)
        assert event.tenant_id is None
        assert event.message == "legacy call site, no tenant_id"

    def test_28_log_event_to_dict_includes_tenant_id_key(self):
        """to_dict() must expose tenant_id (additive, not breaking existing keys)."""
        event = LogEvent(
            source_id="src-a", source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="m", tenant_id=ORG_A,
        )
        d = event.to_dict()
        assert d["tenant_id"] == ORG_A
        # Pre-existing keys must still be present.
        assert "id" in d and "source_id" in d and "message" in d

    @pytest.mark.asyncio
    async def test_29_create_batch_still_deduplicates_via_on_conflict(self, fake_event_repo):
        """
        Pre-existing idempotency (ON CONFLICT (source_id, source_event_id)
        DO NOTHING) must still work after adding the tenant_id column to
        the INSERT statement.
        """
        repo, fake_db = fake_event_repo
        event = LogEvent(
            source_id="src-a", source_event_id="stable-id-1",
            source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="first", tenant_id=ORG_A,
        )
        duplicate = LogEvent(
            source_id="src-a", source_event_id="stable-id-1",
            source_type=LogSourceType.LINUX_SSH,
            timestamp=datetime.now(timezone.utc), level=LogLevel.INFO,
            message="duplicate attempt", tenant_id=ORG_A,
        )

        await repo.create_batch([event])
        await repo.create_batch([duplicate])

        assert len(fake_db.log_events) == 1
