"""
CyberGuard AI — Device Connection & Enrollment End-to-End Tests
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
import pytest
from app.models.enums import UserStatus, SourceStatus
from app.services import user_service, workspace_service
from app.api.deps import get_current_active_user


@pytest.fixture
def auth_user_and_headers(db_session, client):
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

    # Override get_current_active_user
    client.app.dependency_overrides[get_current_active_user] = lambda: user
    yield user, workspace
    client.app.dependency_overrides.pop(get_current_active_user, None)


def test_device_enrollment_lifecycle_phase1(client, db_session, auth_user_and_headers):
    user, workspace = auth_user_and_headers

    # 1. Register Windows Device
    reg_res = client.post(
        "/api/v1/devices",
        json={"name": "Alice Laptop", "os_type": "windows"},
    )
    assert reg_res.status_code == 201, reg_res.text
    reg_data = reg_res.json()
    device_id = reg_data["id"]
    token = reg_data["enrollment_token"]
    assert reg_data["name"] == "Alice Laptop"
    assert reg_data["status"] == "pending"
    assert reg_data["installer_download_url"].endswith(f"/api/v1/devices/{device_id}/installer")
    assert reg_data["publisher"] == "CyberGuard Security Technologies Ltd. (Digitally Signed)"
    assert reg_data["sha256_checksum"] is not None
    assert token.startswith("enr-")

    # 2. Check initial enrollment status (all checkpoints False)
    status_res = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["status"] == "pending"
    assert status_data["installer_downloaded"] is False
    assert status_data["collector_connected"] is False
    assert len(status_data["collection_permissions"]) > 0

    # 3. Download installer
    dl_res = client.get(f"/api/v1/devices/{device_id}/installer?os=windows")
    assert dl_res.status_code == 200
    assert dl_res.headers.get("x-publisher") == "CyberGuard Security Technologies Ltd."
    assert dl_res.headers.get("x-installer-version") == "1.0.0"
    assert dl_res.headers.get("x-checksum-sha256") is not None

    # Checkpoint 1 (installer_downloaded) is now True
    status_res2 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res2.json()["installer_downloaded"] is True
    assert status_res2.json()["installer_downloaded_at"] is not None

    # 4. Installer reports startup and installed checkpoints
    cp_res1 = client.post(
        f"/api/v1/devices/{device_id}/install-progress",
        json={"token": token, "stage": "started"},
    )
    assert cp_res1.status_code == 200

    cp_res2 = client.post(
        f"/api/v1/devices/{device_id}/install-progress",
        json={"token": token, "stage": "installed"},
    )
    assert cp_res2.status_code == 200

    status_res3 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res3.json()["installation_started"] is True
    assert status_res3.json()["collector_installed"] is True

    # 5. Collector redeems one-time enrollment token
    collector_uuid = str(uuid.uuid4())
    enroll_res = client.post(
        "/api/v1/collector/enroll",
        json={
            "token": token,
            "collector_id": collector_uuid,
            "hostname": "ALICE-PC",
            "os_version": "Windows 11 Pro",
            "agent_version": "1.0.0",
        },
    )
    assert enroll_res.status_code == 201, enroll_res.text
    enroll_data = enroll_res.json()
    credential = enroll_data["plaintext_credential"]
    assert credential.startswith("cgc_")

    # Checkpoint 4 & 5 (device_authenticated & device_enrolled) are now True
    status_res4 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res4.json()["device_authenticated"] is True
    assert status_res4.json()["device_enrolled"] is True

    # 6. Service starts and sends first heartbeat
    cp_res3 = client.post(
        f"/api/v1/devices/{device_id}/install-progress",
        json={"token": token, "stage": "service_started"},
    )
    assert cp_res3.status_code == 200

    hb_res = client.post(
        "/api/v1/collector/heartbeat",
        headers={
            "X-Collector-ID": collector_uuid,
            "X-Collector-Credential": credential,
        },
        json={
            "collector_id": collector_uuid,
            "hostname": "ALICE-PC",
            "queue_depth": 0,
            "cpu_percent": 3.2,
            "memory_percent": 41.5,
        },
    )
    assert hb_res.status_code == 200

    # Device is now ONLINE
    status_res5 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res5.json()["status"] == "online"
    assert status_res5.json()["collector_connected"] is True
    assert status_res5.json()["first_heartbeat_received"] is True

    # 7. Collector sends first telemetry event batch
    event_id = str(uuid.uuid4())
    batch_res = client.post(
        "/api/v1/collector/events",
        headers={
            "X-Collector-ID": collector_uuid,
            "X-Collector-Credential": credential,
        },
        json={
            "batch_id": str(uuid.uuid4()),
            "events": [
                {
                    "event_id": event_id,
                    "event_type": "windows.security.4624",
                    "severity": "low",
                    "timestamp": "2026-11-09T12:00:00Z",
                    "title": "Windows Logon Event",
                    "raw_payload": {"EventID": 4624, "User": "Alice"},
                }
            ],
        },
    )
    assert batch_res.status_code == 200
    assert batch_res.json()["ingested"] >= 1

    # Checkpoint 8 (first_telemetry_received) is now True
    status_res6 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res6.json()["first_telemetry_received"] is True
    assert status_res6.json()["events_received"] >= 1

    # 8. Rename device and pause collection
    patch_res = client.patch(
        f"/api/v1/devices/{device_id}",
        json={"name": "Alice Workstation Pro", "collection_active": False},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "Alice Workstation Pro"
    assert patch_res.json()["collection_active"] is False

    # 9. Disconnect and revoke device
    revoke_res = client.post(f"/api/v1/devices/{device_id}/revoke")
    assert revoke_res.status_code == 200

    # Verify device status is revoked
    status_res7 = client.get(f"/api/v1/devices/{device_id}/enrollment-status")
    assert status_res7.json()["status"] == "revoked"
    assert status_res7.json()["collector_connected"] is False
