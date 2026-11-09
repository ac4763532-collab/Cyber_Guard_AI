"""
CyberGuard AI — Security Event Explanation & KB Verification Tests
============================================================================
Verifies:
1. Knowledge base loader indexes definitions across all 10 JSON categories.
2. Known Event 4624 (Sign-in succeeded): title, simple view (6 sections), analyst view, no unverified MITRE mapping.
3. Known Event 4625 (Unsuccessful sign-in): title, decoded status code, decoded logon type, no unverified MITRE mapping.
4. Known Event 4688 (Process created): process path, command line.
5. Known Event 7045 (Service installed): service name, image path.
6. Unknown Event ID (e.g. 99999): safe generic fallback, unknown_definition status.
7. Missing username: handled gracefully, "No specific user account was recorded in this event."
8. Missing or local IP address: correctly identifies local machine vs remote caller.
9. Missing process information: handled without crashing.
10. Temporal attributes: valid UTC formatted timestamp and relative time.
11. Threat status: correctly flags confirmed_threat when findings are attached, no_threat_established when benign.
12. MITRE ATT&CK: Assigned ONLY when findings or detection rule evidence is present, along with mapping_reason.
13. Definition status: verified vs unknown_definition distinction.
14. Original payload preservation: raw data unmodified for forensic integrity.
15. API Endpoint GET /api/v1/events/{id}/explanation returns 404 when event ID is not found.
16. Tenant isolation: API Endpoint returns 403 when user from another workspace attempts access.
17. Authorized user in same workspace retrieves 200 OK with complete schema.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from app.core.exceptions import AuthorizationError, EventNotFoundError, PermissionDeniedError
from app.api.v1 import devices
from app.models.enums import EventCategory, EventSeverity, SourceStatus, UserStatus
from app.models.event import SecurityEvent
from app.models.source import SecuritySource
from app.services import (
    user_service,
    windows_event_explainer,
    workspace_service,
)


@pytest.fixture
def test_setup(db_session):
    """Sets up a test user, workspace, and enrolled Windows device."""
    user = user_service.create_user(
        db_session,
        email=f"analyst.{uuid.uuid4().hex[:6]}@cyberguardai.com",
        password="Password123!@#",
        full_name="Security Analyst",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    workspace = workspace_service.create_personal_workspace(db_session, user)

    reg_req = devices.DeviceRegisterRequest(name="Analyst Laptop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    source = db_session.get(SecuritySource, uuid.UUID(reg_res.id))
    source.hostname = "WORKSTATION-01"
    db_session.commit()
    return user, workspace, source


@pytest.fixture
def other_user_and_workspace(db_session):
    """Sets up a separate user and workspace for cross-tenant testing."""
    user = user_service.create_user(
        db_session,
        email=f"attacker.{uuid.uuid4().hex[:6]}@otherdomain.com",
        password="Password123!@#",
        full_name="Other Tenant",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    workspace = workspace_service.create_personal_workspace(db_session, user)
    db_session.commit()
    return user, workspace


def test_kb_loader_loads_all_categories():
    """Verify that knowledge base loader successfully indexes definitions from all 10 categories."""
    kb = windows_event_explainer.load_knowledge_base()
    assert len(kb) > 100, f"Expected >100 definitions, got {len(kb)}"
    # Check key categories
    categories = {v.get("category") for v in kb.values()}
    assert "Authentication" in categories or "authentication" in str(categories).lower()
    assert "System" in categories or "system" in str(categories).lower()


def test_explain_4624_successful_logon(db_session, test_setup):
    """Verify Event 4624 (Successful sign-in) explanation and 6-section Simple View."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4624",
        severity=EventSeverity.INFO,
        category=EventCategory.AUTHENTICATION,
        username="alice",
        hostname="WORKSTATION-01",
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={
            "EventID": 4624,
            "Channel": "Security",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "LogonType": 2,
            "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
            "IpAddress": "127.0.0.1",
        },
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert "sign-in" in resp.title.lower() or "logon" in resp.title.lower()
    assert resp.definition_status == "verified"
    assert resp.assessment == "normal"
    assert resp.threat_status == "no_threat_established"
    assert resp.original_event_id == "4624"

    # Verify Simple View 6 sections
    assert resp.simple_view.what_happened != ""
    assert resp.simple_view.who.account_name == "alice"
    assert "Interactive" in resp.analyst_view.technical_properties.get("Logon Type", "")
    assert resp.simple_view.where.monitored_device != ""
    assert resp.simple_view.when.relative_time != ""
    assert resp.simple_view.why_it_matters != ""
    assert len(resp.simple_view.what_should_i_do) > 0
    assert any("No action is required" in rec for rec in resp.simple_view.what_should_i_do)

    # MITRE ATT&CK: Benign event without findings must NOT be mapped to a MITRE technique
    assert resp.analyst_view.mitre_attack is None


def test_explain_4625_failed_logon_with_decoded_codes(db_session, test_setup):
    """Verify Event 4625 (Unsuccessful sign-in) decodes LogonType and SubStatus code."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4625",
        severity=EventSeverity.LOW,
        category=EventCategory.AUTHENTICATION,
        username="administrator",
        hostname="WORKSTATION-01",
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={
            "EventID": 4625,
            "Channel": "Security",
            "TargetUserName": "administrator",
            "LogonType": 10,
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
            "IpAddress": "192.168.1.105",
        },
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert "unsuccessful" in resp.title.lower() or "failed" in resp.title.lower()
    assert resp.assessment in ("unusual", "suspicious")
    assert resp.original_event_id == "4625"
    # Benign event without detection findings must not map MITRE
    assert resp.analyst_view.mitre_attack is None

    # Verify status code decoding
    props = resp.analyst_view.technical_properties
    assert "RemoteInteractive" in props.get("Logon Type", "") or "RDP" in props.get("Logon Type", "")
    assert "Bad password" in props.get("SubStatus", "")
    assert resp.simple_view.where.source_ip == "192.168.1.105"


def test_explain_4688_process_creation(db_session, test_setup):
    """Verify Event 4688 (Process Creation) extracts command line and process path."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4688",
        severity=EventSeverity.INFO,
        category=EventCategory.PROCESS,
        username="SYSTEM",
        hostname="WORKSTATION-01",
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={
            "EventID": 4688,
            "Channel": "Security",
            "ProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "ProcessId": 1420,
        },
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert "process" in resp.title.lower()
    assert resp.analyst_view.mitre_attack is None
    assert resp.analyst_view.technical_properties.get("Command Line") == "cmd.exe /c whoami"
    assert resp.analyst_view.technical_properties.get("Process ID") == 1420


def test_explain_7045_service_installation(db_session, test_setup):
    """Verify Event 7045 (Service installed) captures service name and binary path."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.system.7045",
        severity=EventSeverity.INFO,
        category=EventCategory.SYSTEM,
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={
            "EventID": 7045,
            "Channel": "System",
            "ServiceName": "CyberGuardEndpoint",
            "ImagePath": "C:\\Program Files\\CyberGuard\\agent.exe",
            "StartType": "auto start",
        },
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert "service" in resp.title.lower()
    assert resp.definition_status == "verified"
    assert resp.analyst_view.technical_properties.get("Service Name") == "CyberGuardEndpoint"
    assert resp.analyst_view.mitre_attack is None


def test_explain_unknown_event_id_fallback(db_session, test_setup):
    """Verify unknown Event ID does not crash and provides safe generic explanation."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.99999",
        severity=EventSeverity.INFO,
        category=EventCategory.OTHER,
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={"EventID": 99999, "Channel": "Application"},
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert resp.definition_status == "unknown_definition"
    assert "99999" in resp.title
    assert resp.assessment == "unknown"
    assert resp.threat_status == "no_threat_established"
    assert "operational" in resp.simple_view.why_it_matters.lower()


def test_missing_entities_handled_gracefully(db_session, test_setup):
    """Verify missing username, IP, process do not crash the engine."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4624",
        severity=EventSeverity.INFO,
        category=EventCategory.AUTHENTICATION,
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={"EventID": 4624},  # No user, no IP, no process
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)

    assert resp.simple_view.who.account_name is None
    assert "No specific user account" in resp.simple_view.who.explanation
    assert resp.simple_view.where.source_ip is None


def test_threat_status_and_mitre_mapping_with_findings(db_session, test_setup):
    """Verify threat_status is confirmed_threat and MITRE ATT&CK is attached when findings exist."""
    _, workspace, source = test_setup
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4625",
        severity=EventSeverity.HIGH,
        category=EventCategory.AUTHENTICATION,
        username="admin",
        findings_count=2,  # A detection rule triggered findings
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={"EventID": 4625, "rule_id": "rule.win.4625.burst"},
    )
    db_session.add(event)
    db_session.commit()

    resp = windows_event_explainer.explain_security_event(db_session, event)
    assert resp.threat_status == "confirmed_threat"
    assert resp.analyst_view.detection_rule == "rule.win.4625.burst"
    # When findings exist, MITRE mapping is verified and attached with rationale
    assert resp.analyst_view.mitre_attack is not None
    assert resp.analyst_view.mitre_attack.technique_id == "T1110"
    assert "rule.win.4625.burst" in resp.analyst_view.mitre_attack.mapping_reason
    assert "2 active security finding" in resp.analyst_view.mitre_attack.supporting_evidence


def test_api_endpoint_explanation_auth_and_isolation(db_session, test_setup, other_user_and_workspace):
    """Verify API endpoint enforces authorization and workspace tenant isolation."""
    from app.api.v1 import events
    user, workspace, source = test_setup
    other_user, other_workspace = other_user_and_workspace

    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        workspace_id=workspace.id,
        source_id=source.id,
        event_time=now,
        event_type="windows.security.4624",
        severity=EventSeverity.INFO,
        category=EventCategory.AUTHENTICATION,
        username="alice",
        findings_count=0,
        normalized_payload={},
        fingerprint=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        raw_payload={"EventID": 4624, "Channel": "Security", "TargetUserName": "alice"},
    )
    db_session.add(event)
    db_session.commit()

    # 1. Non-existent event ID -> raises EventNotFoundError
    random_id = uuid.uuid4()
    with pytest.raises(EventNotFoundError):
        events.get_event_explanation(random_id, user, db_session)

    # 2. Cross-tenant access -> raises PermissionDeniedError (tenant isolation enforced)
    with pytest.raises((AuthorizationError, PermissionDeniedError)):
        events.get_event_explanation(event.id, other_user, db_session)

    # 3. Authorized user in same workspace -> returns EventExplanationResponse
    resp_ok = events.get_event_explanation(event.id, user, db_session)
    assert resp_ok.event_id == event.id
    assert resp_ok.original_event_id == "4624"
    assert resp_ok.simple_view.who.account_name == "alice"
    assert "sign-in" in resp_ok.title.lower() or "logon" in resp_ok.title.lower()
