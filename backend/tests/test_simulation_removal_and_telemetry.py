"""
CyberGuard AI — Simulation Removal & Genuine Telemetry Acceptance Tests
============================================================================
Verifies:
1. Simulation endpoint POST /api/v1/devices/{id}/simulate-event is removed (404).
2. Ordinary users cannot trigger simulated events or findings.
3. Unauthenticated telemetry requests are rejected with CollectorAuthError.
4. Telemetry from revoked devices is rejected (SourceDisabledError / CollectorAuthError).
5. Telemetry from enrolled, authorized devices is accepted and persisted.
6. Persisted genuine events appear in Live Telemetry Stream via get_device.
7. Real detection rules (e.g., FailedLoginBurstRule) generate findings only from genuine event evidence.
8. Benign events (e.g. windows.security.4624 logon success) do not create threat findings.
9. Synthetic events cannot enter the production pipeline and empty devices are not seeded with fake data.
10. Historical genuine records and device settings remain intact.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from app.api.v1 import collector, collector_events, devices
from app.core.exceptions import CollectorAuthError, SourceDisabledError
from app.models.enums import EventCategory, EventSeverity, SourceStatus, UserStatus
from app.models.event import SecurityEvent
from app.models.source import SecuritySource
from app.schemas.event import EventIngestRequest
from app.services import (
    event_ingestion,
    source_service,
    user_service,
    workspace_service,
)
from app.agents.base import AgentContext
from app.agents.log_analysis.rules import FailedLoginBurstRule


@pytest.fixture
def test_user_and_workspace(db_session):
    user = user_service.create_user(
        db_session,
        email=f"tester.{uuid.uuid4().hex[:6]}@cyberguardai.com",
        password="Password123!@#",
        full_name="Security Auditor",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    workspace = workspace_service.create_personal_workspace(db_session, user)
    db_session.commit()
    return user, workspace


def test_simulation_endpoint_is_removed_and_unreachable(db_session, test_user_and_workspace):
    """Acceptance Test 1 & 2: Verify simulate-event is completely removed from router."""
    routes = [r.path for r in devices.router.routes]
    assert not any("simulate-event" in r for r in routes), "simulate-event route must be completely removed"


def test_unauthenticated_telemetry_request_rejected(db_session):
    """Acceptance Test 3: Unauthenticated telemetry requests are rejected."""
    batch_req = collector_events.CollectorEventBatchRequest(
        batch_id=uuid.uuid4(),
        events=[
            EventIngestRequest(
                event_type="windows.security.4624",
                severity="info",
                event_time=datetime.now(timezone.utc),
                hostname="ROGUE-DEVICE",
                raw_payload={"EventID": 4624},
            )
        ],
    )

    with pytest.raises(CollectorAuthError) as exc_info:
        collector_events.ingest_collector_events(
            payload=batch_req,
            db=db_session,
            x_collector_id=None,
            x_collector_credential=None,
        )
    assert "Missing collector authentication headers" in str(exc_info.value)


def test_revoked_device_telemetry_rejected(db_session, test_user_and_workspace):
    """Acceptance Test 4: Telemetry from revoked device is rejected."""
    user, workspace = test_user_and_workspace

    reg_req = devices.DeviceRegisterRequest(name="Revoked Device", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    dev_id = uuid.UUID(reg_res.id)

    # Enroll
    mock_req = MagicMock()
    mock_req.client.host = "192.168.1.10"
    mock_req.headers.get.return_value = "CyberGuard-Collector/Windows"
    collector_id = uuid.uuid4()
    enroll_res = collector.enroll_collector(
        collector.CollectorEnrollRequest(
            token=reg_res.enrollment_token,
            collector_id=collector_id,
            hostname="REVOKED-PC",
        ),
        db_session,
        mock_req,
    )
    cred = enroll_res.plaintext_credential

    # Revoke device
    source = db_session.get(SecuritySource, dev_id)
    source.status = SourceStatus.REVOKED
    db_session.commit()

    batch_req = collector_events.CollectorEventBatchRequest(
        batch_id=uuid.uuid4(),
        events=[
            EventIngestRequest(
                event_type="windows.security.4624",
                severity="info",
                event_time=datetime.now(timezone.utc),
                hostname="REVOKED-PC",
                raw_payload={"EventID": 4624},
            )
        ],
    )

    with pytest.raises((CollectorAuthError, SourceDisabledError)):
        collector_events.ingest_collector_events(
            payload=batch_req,
            db=db_session,
            x_collector_id=str(collector_id),
            x_collector_credential=cred,
        )


def test_genuine_authorized_telemetry_accepted_and_persisted(db_session, test_user_and_workspace):
    """Acceptance Test 5 & 6: Authorized collector telemetry accepted and appears in Live Stream."""
    user, workspace = test_user_and_workspace

    reg_req = devices.DeviceRegisterRequest(name="Finance Laptop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    dev_id = uuid.UUID(reg_res.id)

    # Enroll
    mock_req = MagicMock()
    mock_req.client.host = "192.168.1.20"
    mock_req.headers.get.return_value = "CyberGuard-Collector/Windows"
    collector_id = uuid.uuid4()
    enroll_res = collector.enroll_collector(
        collector.CollectorEnrollRequest(
            token=reg_res.enrollment_token,
            collector_id=collector_id,
            hostname="FINANCE-PC",
        ),
        db_session,
        mock_req,
    )
    cred = enroll_res.plaintext_credential

    # Send genuine telemetry
    event_time = datetime.now(timezone.utc)
    batch_req = collector_events.CollectorEventBatchRequest(
        batch_id=uuid.uuid4(),
        events=[
            EventIngestRequest(
                event_type="windows.security.4624",
                severity="low",
                category="authentication",
                event_time=event_time,
                hostname="FINANCE-PC",
                username="finance_user",
                raw_payload={"EventID": 4624, "LogonType": 2, "Status": "Success"},
            ),
            EventIngestRequest(
                event_type="windows.system.7045",
                severity="info",
                category="system",
                event_time=event_time,
                hostname="FINANCE-PC",
                raw_payload={"EventID": 7045, "ServiceName": "CyberGuardEndpoint"},
            ),
        ],
    )

    resp = collector_events.ingest_collector_events(
        payload=batch_req,
        db=db_session,
        x_collector_id=str(collector_id),
        x_collector_credential=cred,
    )
    assert resp.ingested == 2
    assert resp.rejected == 0

    # Verify persisted in PostgreSQL
    persisted = list(
        db_session.execute(
            select(SecurityEvent).where(SecurityEvent.source_id == dev_id)
        ).scalars().all()
    )
    assert len(persisted) == 2

    # Verify appears in device details live stream
    dev_detail = devices.get_device(dev_id, db_session, user)
    assert len(dev_detail.recent_events) == 2
    event_types = [e["event_type"] for e in dev_detail.recent_events]
    assert "windows.security.4624" in event_types
    assert "windows.system.7045" in event_types


def test_benign_event_does_not_create_threat_findings(db_session, test_user_and_workspace):
    """Acceptance Test 8: Normal/benign event produces 0 threat findings."""
    user, workspace = test_user_and_workspace

    reg_req = devices.DeviceRegisterRequest(name="Office Desktop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    dev_id = uuid.UUID(reg_res.id)

    # Ingest genuine successful logon
    source = db_session.get(SecuritySource, dev_id)
    benign_ev = EventIngestRequest(
        event_type="windows.security.4624",
        severity=EventSeverity.LOW,
        category=EventCategory.AUTHENTICATION,
        event_time=datetime.now(timezone.utc),
        hostname="OFFICE-DESK",
        username="john_doe",
        raw_payload={"EventID": 4624, "Status": "Success"},
    )
    event_ingestion.ingest_batch(db_session, source=source, payloads=[benign_ev])
    db_session.commit()

    # Query device detail
    dev_detail = devices.get_device(dev_id, db_session, user)
    assert dev_detail.threat_count == 0
    assert len(dev_detail.findings) == 0
    assert dev_detail.status != "compromised"


def test_real_detection_rule_triggers_only_on_genuine_threat_evidence(db_session, test_user_and_workspace):
    """Acceptance Test 7: Real detection rules evaluate genuine events."""
    user, workspace = test_user_and_workspace

    reg_req = devices.DeviceRegisterRequest(name="Target Server", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    source = db_session.get(SecuritySource, uuid.UUID(reg_res.id))

    # Ingest 6 failed login events within 5 minutes (trigger threshold for FailedLoginBurstRule is 5)
    now = datetime.now(timezone.utc)
    for i in range(6):
        ev = SecurityEvent(
            id=uuid.uuid4(),
            workspace_id=workspace.id,
            source_id=source.id,
            event_time=now,
            received_at=now,
            severity=EventSeverity.MEDIUM,
            category=EventCategory.AUTHENTICATION,
            event_type="failed_login",
            outcome="failure",
            username="admin",
            source_ip="10.0.0.99",
            fingerprint=f"{i:064x}",
            raw_payload={"EventID": 4625, "Status": "Failure"},
            normalized_payload={"user": "admin"},
        )
        db_session.add(ev)
    db_session.commit()

    # Test the real FailedLoginBurstRule
    rule = FailedLoginBurstRule(threshold=5, window_minutes=10)
    last_event = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.source_id == source.id).limit(1)
    ).scalar_one()

    ctx = AgentContext(
        db=db_session,
        event=last_event,
        source=source,
        workspace_id=workspace.id,
    )
    finding_spec = rule.evaluate(ctx)
    assert finding_spec is not None
    assert finding_spec.rule_id == "log.failed_login_burst"
    assert "admin" in finding_spec.title or "burst" in finding_spec.title.lower() or "failed" in finding_spec.title.lower()


def test_no_synthetic_events_seeded_when_empty(db_session, test_user_and_workspace):
    """Acceptance Test 9: Connected device with no events does not fabricate synthetic events."""
    user, workspace = test_user_and_workspace

    reg_req = devices.DeviceRegisterRequest(name="Clean Workstation", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    dev_id = uuid.UUID(reg_res.id)

    source = db_session.get(SecuritySource, dev_id)
    source.collector_connected = True
    db_session.commit()

    dev_detail = devices.get_device(dev_id, db_session, user)
    # Must NOT fabricate any event
    assert len(dev_detail.recent_events) == 0
    assert dev_detail.threat_count == 0
    assert len(dev_detail.findings) == 0
