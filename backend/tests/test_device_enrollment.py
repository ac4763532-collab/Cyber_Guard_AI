"""
CyberGuard AI — Device Connection & Enrollment Unit & Integration Tests
============================================================================
Verifies Phase 1 Non-Technical Device Connection Workflow:
1. Device registration with short-lived, single-use token.
2. Verified installer download & integrity headers (SHA-256).
3. Live 8-checkpoint installation progress tracking.
4. Token redemption & credential provisioning.
5. Authenticated collector heartbeat & online state transition.
6. First telemetry event batch ingestion.
7. Device settings update (rename & collection active toggle).
8. Device disconnection & credential revocation.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from app.api.v1 import collector, collector_events, devices
from app.models.enums import SourceStatus, UserStatus
from app.schemas.event import EventIngestRequest
from app.services import collector_credential_service, user_service, workspace_service


@pytest.fixture
def test_user_and_workspace(db_session):
    user = user_service.create_user(
        db_session,
        email=f"alice.tech.{uuid.uuid4().hex[:6]}@example.com",
        password="Password123!@#",
        full_name="Alice Tech",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    workspace = workspace_service.create_personal_workspace(db_session, user)
    db_session.commit()
    return user, workspace


def test_device_enrollment_lifecycle_phase1(db_session, test_user_and_workspace):
    user, workspace = test_user_and_workspace

    # 1. Register Windows Device
    reg_req = devices.DeviceRegisterRequest(name="Alice Laptop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)

    device_uuid = uuid.UUID(reg_res.id)
    token = reg_res.enrollment_token
    assert reg_res.name == "Alice Laptop"
    assert reg_res.status == "pending"
    assert reg_res.installer_download_url.endswith(f"/api/v1/devices/{reg_res.id}/installer")
    assert reg_res.publisher == "CyberGuard Security Technologies Ltd. (Digitally Signed)"
    assert reg_res.sha256_checksum is not None
    assert len(token) >= 32

    # 2. Check initial enrollment status (all checkpoints False)
    status_res1 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res1.status == "pending"
    assert status_res1.installer_downloaded is False
    assert status_res1.collector_connected is False
    assert len(status_res1.collection_permissions) > 0

    # 3. Download installer
    dl_res = devices.download_installer(device_uuid, db_session, token=token, os="windows")
    assert dl_res.headers.get("X-Publisher") == "CyberGuard Security Technologies Ltd."
    assert dl_res.headers.get("X-Installer-Version") == "1.0.0"
    assert dl_res.headers.get("X-Checksum-SHA256") is not None

    # Checkpoint 1 (installer_downloaded) is now True
    status_res2 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res2.installer_downloaded is True
    assert status_res2.installer_downloaded_at is not None

    # 4. Installer reports startup and installed checkpoints
    cp_res1 = devices.record_install_progress(
        device_uuid,
        devices.InstallProgressRequest(token=token, stage="started"),
        db_session,
    )
    assert cp_res1["status"] == "ok"

    cp_res2 = devices.record_install_progress(
        device_uuid,
        devices.InstallProgressRequest(token=token, stage="installed"),
        db_session,
    )
    assert cp_res2["status"] == "ok"

    status_res3 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res3.installation_started is True
    assert status_res3.collector_installed is True

    # 5. Collector redeems one-time enrollment token
    collector_id = uuid.uuid4()
    mock_request = MagicMock()
    mock_request.client.host = "192.168.1.50"
    mock_request.headers.get.return_value = "CyberGuard-Collector/Windows"

    enroll_req = collector.CollectorEnrollRequest(
        token=token,
        collector_id=collector_id,
        hostname="ALICE-PC",
        os_version="Windows 11 Pro",
        agent_version="1.0.0",
    )
    enroll_res = collector.enroll_collector(enroll_req, db_session, mock_request)
    credential = enroll_res.plaintext_credential
    assert credential.startswith("cgc_")

    # Checkpoint 4 & 5 (device_authenticated & device_enrolled) are now True
    status_res4 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res4.device_authenticated is True
    assert status_res4.device_enrolled is True

    # 6. Service starts and sends first heartbeat
    cp_res3 = devices.record_install_progress(
        device_uuid,
        devices.InstallProgressRequest(token=token, stage="service_started"),
        db_session,
    )
    assert cp_res3["status"] == "ok"

    verified = collector_credential_service.verify_credential(db_session, credential)
    hb_req = collector.CollectorHeartbeatRequest(
        collector_id=collector_id,
        hostname="ALICE-PC",
        queue_depth=0,
        cpu_percent=2.5,
        memory_percent=38.0,
    )
    hb_res = collector.heartbeat_collector(hb_req, db_session, verified)
    assert hb_res.status == "ok"

    # Device is now ONLINE
    status_res5 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res5.status == "online"
    assert status_res5.collector_connected is True
    assert status_res5.first_heartbeat_received is True

    # 7. Collector sends first telemetry event batch
    event_batch_req = collector_events.CollectorEventBatchRequest(
        batch_id=uuid.uuid4(),
        events=[
            EventIngestRequest(
                event_type="windows.security.4624",
                severity="info",
                event_time=datetime.now(timezone.utc),
                hostname="ALICE-PC",
                raw_payload={"EventID": 4624, "User": "Alice"},
            )
        ],
    )
    batch_res = collector_events.ingest_collector_events(
        event_batch_req,
        db_session,
        x_collector_id=str(collector_id),
        x_collector_credential=credential,
    )
    assert batch_res.ingested >= 1

    # Checkpoint 8 (first_telemetry_received) is now True
    status_res6 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res6.first_telemetry_received is True
    assert status_res6.events_received >= 1

    # 8. Rename device and pause collection
    patch_req = devices.DeviceUpdateRequest(
        name="Alice Workstation Pro",
        collection_active=False,
    )
    patch_res = devices.update_device(device_uuid, patch_req, db_session, user)
    assert patch_res["name"] == "Alice Workstation Pro"
    assert patch_res["collection_active"] is False

    # 9. Disconnect and revoke device
    revoke_res = devices.revoke_device(device_uuid, db_session, user)
    assert revoke_res["status"] == "revoked"

    # Verify device status is revoked
    status_res7 = devices.get_enrollment_status(device_uuid, db_session, user)
    assert status_res7.status == "revoked"
    assert status_res7.collector_connected is False

    # 10. Confirm revoked credentials CANNOT upload events or send heartbeats
    with pytest.raises(Exception):
        collector_credential_service.verify_credential(db_session, credential)

    with pytest.raises(Exception):
        collector_events.ingest_collector_events(
            event_batch_req,
            db_session,
            x_collector_id=str(collector_id),
            x_collector_credential=credential,
        )


def test_invalid_and_expired_tokens(db_session, test_user_and_workspace):
    user, workspace = test_user_and_workspace
    mock_request = MagicMock()
    mock_request.client.host = "192.168.1.51"
    mock_request.headers.get.return_value = "CyberGuard-Collector/1.0"

    # 1. Invalid token rejection
    bad_req = collector.CollectorEnrollRequest(
        token="totally-bogus-token-random-value-1234567890",
        collector_id=uuid.uuid4(),
        hostname="ATTACKER-PC",
    )
    with pytest.raises(Exception):
        collector.enroll_collector(bad_req, db_session, mock_request)

    # 2. Expired token rejection
    reg_req = devices.DeviceRegisterRequest(name="Bob Laptop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    token = reg_res.enrollment_token

    # Expire token directly in DB
    from app.models.enrollment import SourceEnrollment
    from datetime import timedelta
    tok_obj = db_session.execute(
        select(SourceEnrollment).where(SourceEnrollment.source_id == uuid.UUID(reg_res.id))
    ).scalars().first()
    tok_obj.expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    with pytest.raises(Exception):
        collector.enroll_collector(
            collector.CollectorEnrollRequest(
                token=token,
                collector_id=uuid.uuid4(),
                hostname="EXPIRED-PC",
            ),
            db_session,
            mock_request,
        )


def test_reused_token_protection(db_session, test_user_and_workspace):
    user, workspace = test_user_and_workspace
    mock_request = MagicMock()
    mock_request.client.host = "192.168.1.52"
    mock_request.headers.get.return_value = "CyberGuard-Collector/1.0"

    reg_req = devices.DeviceRegisterRequest(name="Charlie Laptop", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    token = reg_res.enrollment_token

    enroll_req = collector.CollectorEnrollRequest(
        token=token,
        collector_id=uuid.uuid4(),
        hostname="CHARLIE-PC",
    )
    # First redemption succeeds
    res1 = collector.enroll_collector(enroll_req, db_session, mock_request)
    assert res1.plaintext_credential.startswith("cgc_")

    # Second redemption with same token MUST be rejected
    with pytest.raises(Exception):
        collector.enroll_collector(enroll_req, db_session, mock_request)


def test_duplicate_events_and_cross_tenant_isolation(db_session, test_user_and_workspace):
    user_a, workspace_a = test_user_and_workspace

    user_b = user_service.create_user(
        db_session,
        email=f"bob.security.{uuid.uuid4().hex[:6]}@example.com",
        password="Password123!@#",
        full_name="Bob Tenant",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    workspace_b = workspace_service.create_personal_workspace(db_session, user_b)
    db_session.commit()

    # User A registers a device
    reg_req = devices.DeviceRegisterRequest(name="Tenant A Machine", os_type="linux")
    reg_res = devices.register_device(reg_req, db_session, user_a)
    dev_id = uuid.UUID(reg_res.id)
    token = reg_res.enrollment_token

    # Enroll
    mock_request = MagicMock()
    mock_request.client.host = "10.0.0.1"
    mock_request.headers.get.return_value = "CyberGuard-Linux"
    cid = uuid.uuid4()
    enroll_res = collector.enroll_collector(
        collector.CollectorEnrollRequest(
            token=token,
            collector_id=cid,
            hostname="TENANT-A-SRV",
        ),
        db_session,
        mock_request,
    )
    cred = enroll_res.plaintext_credential

    # Ingest event 1
    ev_time = datetime.now(timezone.utc)
    ev = EventIngestRequest(
        event_type="linux.security.ssh",
        severity="info",
        event_time=ev_time,
        hostname="TENANT-A-SRV",
        raw_payload={"msg": "first ssh attempt"},
    )
    b_res1 = collector_events.ingest_collector_events(
        collector_events.CollectorEventBatchRequest(batch_id=uuid.uuid4(), events=[ev]),
        db_session,
        x_collector_id=str(cid),
        x_collector_credential=cred,
    )
    assert b_res1.ingested == 1
    assert b_res1.duplicates == 0

    # Ingest EXACT duplicate event
    b_res2 = collector_events.ingest_collector_events(
        collector_events.CollectorEventBatchRequest(batch_id=uuid.uuid4(), events=[ev]),
        db_session,
        x_collector_id=str(cid),
        x_collector_credential=cred,
    )
    assert b_res2.duplicates == 1
    assert b_res2.ingested == 0

    # Cross-tenant check: User B attempts to access or modify User A's device
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        devices.get_device(dev_id, db_session, user_b)

    with pytest.raises(HTTPException):
        devices.update_device(dev_id, devices.DeviceUpdateRequest(name="Hacked Name"), db_session, user_b)

    with pytest.raises(HTTPException):
        devices.revoke_device(dev_id, db_session, user_b)


def test_collector_runtime_endpoints(db_session, test_user_and_workspace):
    user, workspace = test_user_and_workspace

    # Health check
    h = collector.collector_health()
    assert h["status"] == "healthy"
    assert h["service"] == "CyberGuard Collector Gateway"

    # Update check
    u = collector.check_collector_update(os="windows", current_version="1.0.0")
    assert u["latest_version"] == "1.0.0"
    assert u["sha256"] is not None

    # Config retrieval with verified credential
    reg_req = devices.DeviceRegisterRequest(name="DevBox", os_type="windows")
    reg_res = devices.register_device(reg_req, db_session, user)
    mock_request = MagicMock()
    mock_request.client.host = "10.0.0.2"
    mock_request.headers.get.return_value = "CyberGuard-Windows"
    cid = uuid.uuid4()
    enroll_res = collector.enroll_collector(
        collector.CollectorEnrollRequest(token=reg_res.enrollment_token, collector_id=cid, hostname="DEVBOX"),
        db_session,
        mock_request,
    )
    cred = enroll_res.plaintext_credential
    verified = collector_credential_service.verify_credential(db_session, cred)

    cfg = collector.get_collector_config(verified)
    assert cfg["source_name"] == "DevBox"
    assert cfg["collection_active"] is True
    assert "Security" in cfg["monitored_channels"]

    # Graceful collector self-revocation
    rev = collector.revoke_collector(db_session, verified)
    assert rev["status"] == "revoked"
