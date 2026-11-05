"""
CyberGuard AI - Drag-and-Drop Log File Upload Endpoint Tests

HTTP-level tests for POST /api/v1/analysis/logs/upload, using FastAPI's
TestClient against the real app (real DB-backed auth when available in
this environment, real Redis-backed dedup check, real LogAgent dispatch -
nothing in the analysis path itself is mocked except where explicitly
noted per test).

Mirrors the structure/conventions of test_email_upload.py (HTTP-level,
in-test fixture bytes, no committed binaries) and
test_incidents_api_auth.py (create_access_token + a real DB-backed test
user via UserManager, not dependency_overrides - nothing else in this
suite uses that convention).
"""

from __future__ import annotations

import asyncio
import io
import sys
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

# Windows event loop fix for psycopg3 - same fix applied in every other
# test module in this suite that touches the database.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _make_db_user(client, username: str, organization_id: str | None, role=None):
    """
    Get-or-create a real user via UserManager.

    Runs on the TestClient's own anyio portal - the exact event loop its
    app lifespan (DB pool, Redis client) is bound to - rather than
    spinning up a separate asyncio loop per call. tests/conftest.py's
    db_test_user_* fixtures use a dedicated per-fixture loop instead, but
    that pattern only works set once per test; this module creates several
    distinct org-scoped users across many tests in the same session, and a
    fresh loop per call fights the DatabaseManager singleton's "pool is
    bound to one loop" invariant (its own module docstring), leaving the
    pool bound to a loop a later call then closes - "Database not
    initialized" everywhere after. Routing through client.portal avoids
    that entirely by never leaving the lifespan's loop.
    """
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
    Alias for conftest.py's session-scoped `test_client` fixture, kept
    under this module's existing `client` name so every test function
    below didn't need renaming.

    A module-scoped (or function-scoped) TestClient here was tried and
    rejected: each `with TestClient(app) as c:` fully runs the app's
    lifespan (init_database()/close_database()), and when a SECOND
    DB-backed TestClient module/test runs afterward in the same pytest
    session, DatabaseManager's singleton pool was observed (reproduced
    directly, outside pytest) to come out of that second open-close
    cycle broken: is_initialized reports True, but the very next query
    still raises "Database not initialized" - a real race in repeated
    rapid-fire open/close cycles across short-lived TestClient portal
    threads, not a bug in this file's fixtures. One TestClient for the
    whole test session (test_client, conftest.py) matches how a real
    deployed server actually behaves (it never closes its pool between
    requests) and avoids the race entirely.

    Also depends on rate_limit_disabled: this module alone makes enough
    real requests against POST /analysis/logs/upload's real 30/minute
    Redis-backed limiter, now funneled through one shared session-wide
    TestClient/IP key, to legitimately trip it - a correctness property
    of the limiter, not something this test suite should be bound by.
    """
    return test_client


@pytest.fixture
def auth_user(client):
    """A single real test user, unique per test run, scoped to its own org."""
    unique = uuid4().hex[:8]
    return _make_db_user(client, f"loguploader_{unique}", f"org-upload-{unique}")


def _log_bytes(text: str) -> io.BytesIO:
    return io.BytesIO(text.encode("utf-8"))


SAMPLE_LINUX_LOG = (
    "Sep 13 09:30:01 server sshd[12345]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:05 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:10 server sshd[12347]: Failed password for admin from 192.168.1.100 port 22\n"
    "Sep 13 09:30:15 server sshd[12348]: Accepted password for admin from 192.168.1.100 port 22\n"
)


class TestValidUploads:
    def test_valid_log_file_returns_200_with_findings_shape(self, client, auth_user):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
            data={"source_type_hint": "linux_ssh"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "auth.log"
        assert data["preview_only"] is False
        assert data["parsed_event_count"] == 4
        assert data["detected_source_type"] == "linux_ssh"
        assert "classification" in data
        assert "severity" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_jsonl_upload_is_parsed_and_analyzed(self, client, auth_user):
        jsonl_content = "\n".join(
            [
                '{"timestamp": "2024-01-15T10:30:00", "level": "warning", "message": "Failed password for root from 10.0.0.5"}',
                '{"timestamp": "2024-01-15T10:30:05", "level": "warning", "message": "Failed password for root from 10.0.0.5"}',
                '{"timestamp": "2024-01-15T10:30:10", "level": "info", "message": "Accepted password for root from 10.0.0.5"}',
            ]
        )
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("events.jsonl", _log_bytes(jsonl_content), "application/jsonl")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["parsed_event_count"] == 3
        assert data["skipped_line_count"] == 0

    def test_json_array_upload_is_parsed_and_analyzed(self, client, auth_user):
        json_content = (
            '[{"message": "Failed password for admin from 10.0.0.9"}, '
            '{"message": "Accepted password for admin from 10.0.0.9"}]'
        )
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("events.json", _log_bytes(json_content), "application/json")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["parsed_event_count"] == 2

    def test_csv_upload_is_parsed_and_analyzed(self, client, auth_user):
        csv_content = (
            "timestamp,level,message\n"
            "2024-01-15T10:30:00,warning,Failed password for admin from 10.0.0.9\n"
            "2024-01-15T10:30:05,info,Accepted password for admin from 10.0.0.9\n"
        )
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("events.csv", _log_bytes(csv_content), "text/csv")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["parsed_event_count"] == 2


class TestPreviewOnly:
    def test_preview_only_skips_dispatcher_and_omits_analysis_fields(self, client, auth_user, monkeypatch):
        """
        preview_only=True must not call the dispatcher at all - mocked and
        asserted not-called, per the plan.
        """
        from app.agents.dispatcher import TaskDispatcher

        called = {"value": False}
        original_dispatch = TaskDispatcher.dispatch

        async def _spy_dispatch(self, agent_type, data):
            called["value"] = True
            return await original_dispatch(self, agent_type, data)

        monkeypatch.setattr(TaskDispatcher, "dispatch", _spy_dispatch)

        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
            data={"source_type_hint": "linux_ssh", "preview_only": "true"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["preview_only"] is True
        assert data["classification"] is None
        assert data["findings"] == []
        assert called["value"] is False, "dispatcher.dispatch must not be called when preview_only=True"

    def test_preview_only_does_not_trigger_dedup_check(self, client, auth_user):
        """Submitting the same file twice with preview_only=True must never 409."""
        for _ in range(2):
            response = client.post(
                "/api/v1/analysis/logs/upload",
                files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
                data={"source_type_hint": "linux_ssh", "preview_only": "true"},
                headers=_auth_header(auth_user),
            )
            assert response.status_code == 200


class TestInvalidInput:
    def test_invalid_extension_returns_400(self, client, auth_user):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("malware.exe", _log_bytes("not a log"), "application/octet-stream")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400

    def test_oversized_file_returns_413(self, client, auth_user):
        from app.config import settings

        oversized = "A" * (settings.log_upload_max_file_size_bytes + 1024)
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("big.log", _log_bytes(oversized), "text/plain")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 413

    def test_empty_file_returns_400(self, client, auth_user):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("empty.log", _log_bytes(""), "text/plain")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400

    def test_malformed_csv_no_message_column_returns_400(self, client, auth_user):
        csv_content = "foo,bar\n1,2\n3,4\n"
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("bad.csv", _log_bytes(csv_content), "text/csv")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400

    def test_json_with_no_valid_records_returns_400(self, client, auth_user):
        json_content = '[{"foo": "bar"}, {"baz": "qux"}]'
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("norecords.json", _log_bytes(json_content), "application/json")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400

    def test_invalid_json_returns_400_not_500(self, client, auth_user):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("broken.json", _log_bytes("{not valid json"), "application/json")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400

    def test_invalid_source_type_hint_returns_400(self, client, auth_user):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
            data={"source_type_hint": "not_a_real_type"},
            headers=_auth_header(auth_user),
        )
        assert response.status_code == 400


class TestAuthentication:
    def test_missing_auth_returns_401(self, client):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
            data={"source_type_hint": "auto"},
        )
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, client):
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(SAMPLE_LINUX_LOG), "text/plain")},
            data={"source_type_hint": "auto"},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401


class TestDuplicateSubmission:
    def test_identical_resubmission_returns_409(self, client, auth_user):
        content = SAMPLE_LINUX_LOG + f"\n# nonce {uuid4().hex}\n"
        files = {"file": ("auth.log", _log_bytes(content), "text/plain")}
        data = {"source_type_hint": "auto"}
        headers = _auth_header(auth_user)

        first = client.post("/api/v1/analysis/logs/upload", files=files, data=data, headers=headers)
        assert first.status_code == 200

        second = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data=data,
            headers=headers,
        )
        assert second.status_code == 409

    def test_different_content_from_same_user_does_not_409(self, client, auth_user):
        headers = _auth_header(auth_user)
        first = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("a.log", _log_bytes(SAMPLE_LINUX_LOG + f"\n# {uuid4().hex}\n"), "text/plain")},
            data={"source_type_hint": "auto"},
            headers=headers,
        )
        second = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("b.log", _log_bytes(SAMPLE_LINUX_LOG + f"\n# {uuid4().hex}\n"), "text/plain")},
            data={"source_type_hint": "auto"},
            headers=headers,
        )
        assert first.status_code == 200
        assert second.status_code == 200


class TestAnalysisFailure:
    def test_dispatcher_failure_returns_500_without_leaking_raw_content(self, client, auth_user, monkeypatch):
        from app.agents.dispatcher import TaskDispatcher

        async def _boom(self, agent_type, data):
            raise RuntimeError("simulated agent failure")

        monkeypatch.setattr(TaskDispatcher, "dispatch", _boom)

        secret_marker = f"SECRET-MARKER-{uuid4().hex}"
        content = f"{SAMPLE_LINUX_LOG}\n# {secret_marker}\n"

        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("auth.log", _log_bytes(content), "text/plain")},
            data={"source_type_hint": "auto"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 500
        assert secret_marker not in response.text


class TestWindowsHandling:
    def test_windows_xml_event_is_parsed_with_real_fidelity(self, client, auth_user):
        xml_content = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System>"
            "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>"
            "<EventID>4625</EventID>"
            "<Version>0</Version>"
            "<Level>4</Level>"
            "<Task>12544</Task>"
            "<Keywords>0x8010000000000000</Keywords>"
            "<TimeCreated SystemTime='2024-01-15T10:30:00.000000Z'/>"
            "<EventRecordID>12345</EventRecordID>"
            "<Channel>Security</Channel>"
            "<Computer>DC01.corp.local</Computer>"
            "</System>"
            "<EventData>"
            "<Data Name='TargetUserName'>admin</Data>"
            "<Data Name='IpAddress'>192.168.1.100</Data>"
            "</EventData>"
            "</Event>"
        )
        # .xml is not in log_file_parser.ALLOWED_EXTENSIONS - the design
        # (per app/services/log_file_parser.py's _looks_like_windows_event_xml)
        # sniffs content, not the extension, to route to the real Windows
        # XML parser. ".log" matches how a real Windows export is often
        # named, and is a supported extension.
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("security.log", _log_bytes(xml_content), "application/xml")},
            data={"source_type_hint": "windows"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["detected_source_type"] == "windows"
        assert data["parsed_event_count"] == 1

    def test_windows_plain_text_uses_generic_fallback_flag(self, client, auth_user):
        plain_text = (
            "2024-01-15 10:30:00 ERROR Failed login for admin from 192.168.1.100\n"
            "2024-01-15 10:30:05 INFO Successful login for admin from 192.168.1.100\n"
        )
        response = client.post(
            "/api/v1/analysis/logs/upload",
            files={"file": ("winlog.log", _log_bytes(plain_text), "text/plain")},
            data={"source_type_hint": "windows"},
            headers=_auth_header(auth_user),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["detected_source_type"] == "windows_generic_fallback"
        assert data["parsed_event_count"] == 2
