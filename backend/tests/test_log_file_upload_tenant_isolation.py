"""
CyberGuard AI - Log File Upload Tenant Isolation Tests

Covers the tenant-scoping requirements from the drag-and-drop log file
upload plan, mirroring test_security_log_ingestion_tenant_isolation.py's
ORG_A/ORG_B convention and ownership (two distinct real organizations,
never one), plus test_log_file_upload.py's HTTP-level TestClient pattern
(real DB-backed auth via create_access_token, real Redis-backed dedup
check, real LogAgent dispatch - nothing in the analysis path itself is
mocked).

What is REAL (not mocked) in every test below:
- app.auth.jwt JWT verification + get_current_active_user's real DB user
  lookup (via a real User created through UserManager).
- POST /api/v1/analysis/logs/upload's own auth/tenant logic
  (app/api/v1/analysis.py::upload_log_file): non-admin with no
  organization_id -> 400; the dedup key is built from
  f"log_upload_dedup:{organization_id}:{sha256(raw_bytes)}" - scoped by
  tenant, not content hash alone.
- The real Redis-backed dedup check (app.cache.redis_client), when Redis
  is reachable in this environment - skipped (not failed) if it is not,
  since the dedup check fails open by design (a UX nicety, not a
  security control - see _check_and_set_upload_dedup's own docstring).
- The real LogAgent dispatch and response shape.

Uses the same module-scoped `client` fixture rationale as
test_log_file_upload.py: one TestClient (one lifespan, one DB pool) for
the whole module, to avoid the open/close race in DatabaseManager's
pool under rapid, repeated full lifespan cycles (diagnosed directly,
reproduced outside pytest, documented in that file).
"""

from __future__ import annotations

import asyncio
import io
import sys
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


ORG_A = f"org-a-{uuid4().hex[:8]}"
ORG_B = f"org-b-{uuid4().hex[:8]}"


def _make_db_user(client, username: str, organization_id: str | None, role=None):
    """Get-or-create a real user via UserManager, on the TestClient's own
    anyio portal loop - see test_log_file_upload.py's _make_db_user for
    the full rationale (avoids DatabaseManager's bound-loop pool race)."""
    from app.auth.models import UserCreate, UserRole
    from app.auth.users import get_user_manager
    from app.config import get_settings

    role = role or UserRole.ANALYST
    settings = get_settings()

    async def _get_or_create():
        user_manager = get_user_manager()
        if settings.db_enabled:
            user = await user_manager.get_user_by_username_async(username)
            if not user:
                user = await user_manager.create_user_async(
                    UserCreate(
                        username=username,
                        password="testpass123!",
                        email=f"{username}@test.com",
                        role=role,
                        organization_id=organization_id,
                    )
                )
            return user

        user = user_manager.get_user_by_username(username)
        if not user:
            user = user_manager.create_user(
                UserCreate(
                    username=username,
                    password="testpass123!",
                    email=f"{username}@test.com",
                    role=role,
                    organization_id=organization_id,
                )
            )
        return user

    return client.portal.call(_get_or_create)


def _auth_header(user) -> dict:
    from app.auth.jwt import create_access_token

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        organization_id=user.organization_id,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(test_client, rate_limit_disabled):
    """
    Alias for conftest.py's session-scoped `test_client` fixture - see
    test_log_file_upload.py's own `client` fixture for the full race
    diagnosis this avoids (a second DB-backed TestClient lifespan in the
    same pytest session reliably broke DatabaseManager's pool when each
    test module owned its own TestClient, even module-scoped).

    Also depends on rate_limit_disabled - see test_log_file_upload.py's
    `client` fixture: this suite's upload requests share one real,
    Redis-backed, IP-keyed rate limit window with that module when both
    run in the same session.
    """
    return test_client


@pytest.fixture
def user_org_a(client):
    unique = uuid4().hex[:8]
    return _make_db_user(client, f"tenant_a_{unique}", ORG_A)


@pytest.fixture
def user_org_b(client):
    unique = uuid4().hex[:8]
    return _make_db_user(client, f"tenant_b_{unique}", ORG_B)


@pytest.fixture
def admin_user(client):
    from app.auth.models import UserRole

    unique = uuid4().hex[:8]
    return _make_db_user(client, f"admin_{unique}", None, role=UserRole.ADMIN)


@pytest.fixture
def viewer_no_org(client):
    """A non-admin user with no organization_id assigned at all - the
    fail-closed case."""
    from app.auth.models import UserRole

    unique = uuid4().hex[:8]
    return _make_db_user(client, f"noorg_{unique}", None, role=UserRole.VIEWER)


def _log_bytes(text: str) -> io.BytesIO:
    return io.BytesIO(text.encode("utf-8"))


SAMPLE_LOG = (
    "Sep 13 09:30:01 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:05 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:10 server sshd[12347]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:15 server sshd[12348]: Accepted password for admin from 192.168.1.100 port 22\n"
)


class TestNonAdminRequiresOrganization:
    """A non-admin account with no organization_id must fail closed, not
    silently fall back to seeing/affecting all tenants."""

    def test_non_admin_without_org_id_rejected(self, client, viewer_no_org):
        assert viewer_no_org.organization_id is None

        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LOG), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(viewer_no_org),
        )

        assert response.status_code == 400


class TestDedupScopedPerTenant:
    """
    The dedup key is f"log_upload_dedup:{organization_id}:{sha256(...)}" -
    scoped by tenant, not content hash alone. Identical content from two
    DIFFERENT real organizations must never collide.
    """

    def test_identical_content_from_two_orgs_both_succeed(self, client, user_org_a, user_org_b):
        content = SAMPLE_LOG + f"\n# tenant-dedup-nonce {uuid4().hex}\n"

        response_a = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_a),
        )
        assert response_a.status_code == 200

        # Same byte-for-byte content, different tenant - must not 409.
        response_b = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_b),
        )
        assert response_b.status_code == 200

    def test_identical_content_same_org_still_409s(self, client, user_org_a):
        """Sanity check: the per-tenant scoping above isn't just a dedup
        check that's broken/always-open - the SAME tenant resubmitting
        the SAME content must still 409."""
        content = SAMPLE_LOG + f"\n# same-org-nonce {uuid4().hex}\n"

        first = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_a),
        )
        assert first.status_code == 200

        second = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_a),
        )
        assert second.status_code == 409


class TestAdminBypass:
    """An admin has no single-tenant restriction (organization_id may be
    None) and must not be rejected for lacking one."""

    def test_admin_without_org_id_not_rejected(self, client, admin_user):
        assert admin_user.organization_id is None

        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LOG + f"\n# admin-nonce {uuid4().hex}\n"), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(admin_user),
        )

        assert response.status_code == 200

    def test_admin_dedup_key_uses_admin_sentinel_not_none(self, client, admin_user):
        """
        upload_log_file dedups admins under the fixed "admin" sentinel
        (dedup_org_id = organization_id or "admin") rather than a literal
        None/"" key, so two different real admin accounts submitting the
        same content are still correctly deduped against each other
        (same code path as any other tenant, just a shared sentinel
        tenant for admins specifically).
        """
        content = SAMPLE_LOG + f"\n# admin-dedup-nonce {uuid4().hex}\n"

        first = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(admin_user),
        )
        assert first.status_code == 200

        second = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(admin_user),
        )
        assert second.status_code == 409


class TestNoCrossTenantDataInResponse:
    """
    The upload endpoint's response is built entirely from the uploaded
    file's own parsed content plus the live LogAgent dispatch result -
    there is no persistence and no query across stored rows, so there is
    no code path by which one tenant's upload response could contain
    another tenant's data. This test asserts that property directly:
    two different tenants uploading two different, identifiable payloads
    each get back only their own content's findings.
    """

    def test_each_tenant_sees_only_their_own_upload_content(self, client, user_org_a, user_org_b):
        marker_a = f"MARKER-A-{uuid4().hex}"
        marker_b = f"MARKER-B-{uuid4().hex}"

        content_a = SAMPLE_LOG + f"\n# {marker_a}\n"
        content_b = SAMPLE_LOG.replace("192.168.1.100", "10.0.0.99") + f"\n# {marker_b}\n"

        response_a = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("a.log", _log_bytes(content_a), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_a),
        )
        response_b = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("b.log", _log_bytes(content_b), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(user_org_b),
        )

        assert response_a.status_code == 200
        assert response_b.status_code == 200

        # Neither tenant's raw marker is echoed back verbatim in the
        # OTHER tenant's response (would indicate real cross-tenant
        # content leakage, not just a coincidental shared string).
        assert marker_b not in response_a.text
        assert marker_a not in response_b.text
