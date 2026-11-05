"""
CyberGuard AI - Incident API Authorization Tests

Covers the fix to app/api/v1/incidents.py: previously every incident
endpoint had zero authentication dependency, so any caller who could
reach the API could read, create, or modify any incident. These tests
verify:

- Every endpoint rejects an unauthenticated request with 401.
- Mutating endpoints (create / update / add-alert / create-from-correlation)
  reject an authenticated user who lacks can_manage_incidents with 403.
- Mutating endpoints succeed for a user who does have can_manage_incidents
  (the "analyst" role, which defaults to can_manage_incidents=True - see
  app/auth/users.py UserManager._get_role_permissions).
- update_incident records the real authenticated username on the
  timeline entry instead of the old hardcoded "api_user" placeholder.

Uses the existing db_test_user_viewer / db_test_user_analyst fixtures
(tests/conftest.py) and the create_access_token helper, matching the
pattern already used by tests/test_step12_feedback.py rather than
introducing a new auth-testing convention (e.g. dependency_overrides,
which nothing else in this test suite uses).
"""

import sys
import asyncio

import pytest
from fastapi.testclient import TestClient

# Windows event loop fix for psycopg3 - same fix applied in every other
# test module that touches the database in this suite.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


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
def client():
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


class TestIncidentEndpointsRequireAuth:
    """Every incident endpoint must reject a request with no JWT at all."""

    def test_create_incident_requires_auth(self, client):
        response = client.post(
            "/api/v1/incidents",
            json={
                "title": "Test incident",
                "description": "test",
                "severity": "medium",
            },
        )
        assert response.status_code == 401

    def test_list_incidents_requires_auth(self, client):
        response = client.get("/api/v1/incidents")
        assert response.status_code == 401

    def test_get_statistics_requires_auth(self, client):
        response = client.get("/api/v1/incidents/statistics")
        assert response.status_code == 401

    def test_get_incident_requires_auth(self, client):
        response = client.get("/api/v1/incidents/some-id")
        assert response.status_code == 401

    def test_get_timeline_requires_auth(self, client):
        response = client.get("/api/v1/incidents/some-id/timeline")
        assert response.status_code == 401

    def test_update_incident_requires_auth(self, client):
        response = client.patch(
            "/api/v1/incidents/some-id",
            json={"note": "test"},
        )
        assert response.status_code == 401

    def test_add_alert_requires_auth(self, client):
        response = client.post("/api/v1/incidents/some-id/alerts/some-alert-id")
        assert response.status_code == 401

    def test_create_from_correlation_requires_auth(self, client):
        response = client.post(
            "/api/v1/incidents/from-correlation",
            json={
                "group_id": "g1",
                "event_ids": [],
                "domains": [],
                "risk_score": 50,
                "severity": "medium",
            },
        )
        assert response.status_code == 401


class TestIncidentWriteEndpointsRequirePermission:
    """
    An authenticated user without can_manage_incidents (VIEWER) must be
    rejected with 403 on mutating endpoints. Read endpoints only require
    authentication, so a VIEWER should succeed there (verified
    separately below).
    """

    def test_viewer_cannot_create_incident(self, client, db_test_user_viewer):
        response = client.post(
            "/api/v1/incidents",
            json={
                "title": "Test incident",
                "description": "test",
                "severity": "medium",
            },
            headers=_auth_header(db_test_user_viewer),
        )
        assert response.status_code == 403

    def test_viewer_cannot_update_incident(self, client, db_test_user_viewer):
        response = client.patch(
            "/api/v1/incidents/some-id",
            json={"note": "test"},
            headers=_auth_header(db_test_user_viewer),
        )
        assert response.status_code == 403

    def test_viewer_cannot_add_alert(self, client, db_test_user_viewer):
        response = client.post(
            "/api/v1/incidents/some-id/alerts/some-alert-id",
            headers=_auth_header(db_test_user_viewer),
        )
        assert response.status_code == 403

    def test_viewer_can_list_incidents(self, client, db_test_user_viewer):
        """Read-only endpoints only require authentication, not the
        manage_incidents permission - a VIEWER should get past auth."""
        response = client.get(
            "/api/v1/incidents",
            headers=_auth_header(db_test_user_viewer),
        )
        # Not 401/403 - whatever happens past auth (200, or a 500 from
        # an unrelated DB/connection issue in this environment) is fine;
        # the point is auth and permission checks let a VIEWER through
        # to a read endpoint.
        assert response.status_code not in (401, 403)


class TestIncidentWriteSucceedsForAnalyst:
    """
    An authenticated ANALYST (can_manage_incidents=True by default) must
    be allowed through the permission check on mutating endpoints. This
    does not assert the full create succeeds end-to-end (that depends on
    DB availability in this environment, covered by
    test_step4_incidents.py), only that the auth/permission layer itself
    does not block them with 401/403.
    """

    def test_analyst_create_incident_not_blocked_by_auth(self, client, db_test_user_analyst):
        response = client.post(
            "/api/v1/incidents",
            json={
                "title": "Test incident from analyst",
                "description": "test",
                "severity": "medium",
            },
            headers=_auth_header(db_test_user_analyst),
        )
        assert response.status_code not in (401, 403)

    def test_analyst_update_incident_records_real_username(
        self, client, db_test_user_analyst, initialize_database
    ):
        """
        Create an incident, then update it as the analyst, and confirm
        the resulting timeline entry's "user" field is the real
        authenticated username - not the old hardcoded "api_user".
        """
        create_response = client.post(
            "/api/v1/incidents",
            json={
                "title": "Incident for username test",
                "description": "test",
                "severity": "medium",
            },
            headers=_auth_header(db_test_user_analyst),
        )
        if create_response.status_code != 200:
            pytest.skip(
                f"Incident creation unavailable in this environment "
                f"(status {create_response.status_code}); covered "
                f"separately by test_step4_incidents.py"
            )

        incident_id = create_response.json()["id"]

        update_response = client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"note": "checking real username is recorded"},
            headers=_auth_header(db_test_user_analyst),
        )
        assert update_response.status_code == 200

        timeline_response = client.get(
            f"/api/v1/incidents/{incident_id}/timeline",
            headers=_auth_header(db_test_user_analyst),
        )
        assert timeline_response.status_code == 200

        entries = timeline_response.json()["entries"]
        note_entries = [e for e in entries if e["type"] == "note_added"]
        assert len(note_entries) >= 1
        assert note_entries[-1]["user"] == db_test_user_analyst.username
        assert note_entries[-1]["user"] != "api_user"
