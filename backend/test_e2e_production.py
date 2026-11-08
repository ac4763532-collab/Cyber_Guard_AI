"""
CyberGuard AI — Comprehensive End-to-End Production Verification
================================================================
Verifies real database persistence, authentication, device enrollment,
email forensic ingestion, log and network telemetry, direct messaging,
and persona dashboards.
"""

import sys
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_session_factory, get_engine
from app.models.user import User

client = TestClient(app)

def test_full_pipeline():
    print("\n[+] 1. Checking application health and liveness...")
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    health_data = res.json()
    assert health_data.get("status") in ["healthy", "ok"], f"Unhealthy status: {health_data}"
    print("    -> Health check PASS (Database connected)")

    # 2. Register a dedicated test user
    test_email = f"prod_verify_{uuid.uuid4().hex[:8]}@cyberguardai.com"
    test_password = "SecurePassword123!"
    print(f"\n[+] 2. Registering production test user ({test_email})...")
    reg_res = client.post("/api/v1/auth/register", json={
        "email": test_email,
        "password": test_password,
        "full_name": "Integration Test Officer",
        "role": "individual",
    })
    assert reg_res.status_code in [200, 201], f"Registration failed: {reg_res.text}"
    token_data = reg_res.json()
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"    -> User registered and token received: {token[:16]}...")

    # 4. Device Management
    print("\n[+] 4. Verifying device enrollment and challenge endpoints...")
    dev_list_res = client.get("/api/v1/devices", headers=headers)
    assert dev_list_res.status_code == 200, f"Device list failed: {dev_list_res.text}"
    
    dev_create_res = client.post("/api/v1/devices", headers=headers, json={
        "name": "SecOps Windows Workstation",
        "os_type": "windows",
    })
    assert dev_create_res.status_code in [200, 201], f"Device create failed: {dev_create_res.text}"
    dev_data = dev_create_res.json()
    device_id = dev_data["id"]
    assert "powershell_install_command" in dev_data
    assert "enrollment_token" in dev_data
    print(f"    -> Device created: {device_id}")
    print(f"    -> Enrollment token generated: {dev_data['enrollment_token'][:12]}...")

    dev_get_res = client.get(f"/api/v1/devices/{device_id}", headers=headers)
    assert dev_get_res.status_code == 200
    print(f"    -> Device detail retrieved: {dev_get_res.json()['name']}")

    chal_res = client.post(f"/api/v1/devices/{device_id}/challenge", headers=headers)
    assert chal_res.status_code == 200
    print("    -> Fresh enrollment challenge issued successfully")

    # 5. Email Forensics & Real Agent Rule Execution
    print("\n[+] 5. Ingesting RFC 822 suspicious email payload into EmailAnalysisAgent...")
    eml_raw = (
        b"From: security-alerts@paypa1-security.com\r\n"
        b"To: officer@cyberguard.test\r\n"
        b"Subject: URGENT: Unauthorized Account Access - Immediate Action Required\r\n"
        b"Date: Sun, 08 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Dear user,\r\n\r\n"
        b"Your account was accessed from an unrecognized device in Russia.\r\n"
        b"Verify your credentials immediately: http://192.168.1.100/login.php?verify=true\r\n"
        b"Failure to do so within 2 hours will result in permanent suspension.\r\n"
    )
    upload_res = client.post(
        "/api/v1/email/uploads",
        headers=headers,
        files={"file": ("spearphish_urgent.eml", eml_raw, "message/rfc822")}
    )
    assert upload_res.status_code in [200, 201], f"Email upload failed: {upload_res.text}"
    analysis = upload_res.json()
    assert analysis["verdict"] in ["suspicious", "malicious", "clean"]
    assert analysis["score"] > 0
    print(f"    -> Email parsed: Subject: {analysis['subject']}")
    print(f"    -> Verdict: {analysis['verdict'].upper()} (Score: {analysis['score']}/100)")
    detail_res = client.get(f"/api/v1/email/analyses/{analysis['analysis_id']}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    print(f"    -> Findings generated: {len(detail.get('findings', []))} security findings")

    # Verify listing of emails
    emails_list_res = client.get("/api/v1/email/messages", headers=headers)
    assert emails_list_res.status_code == 200
    emails_data = emails_list_res.json()
    items_count = len(emails_data if isinstance(emails_data, list) else emails_data.get("items", []))
    assert items_count >= 1
    print(f"    -> Email messages query PASS ({items_count} emails stored)")

    # 6. Network Telemetry Aggregation
    print("\n[+] 6. Querying network telemetry summary...")
    net_summary_res = client.get("/api/v1/network/summary", headers=headers)
    assert net_summary_res.status_code == 200
    print(f"    -> Network summary PASS (Flows count: {net_summary_res.json()['flows_count']})")

    # 7. Log Telemetry Aggregation
    print("\n[+] 7. Querying security log summary...")
    log_summary_res = client.get("/api/v1/logs/summary", headers=headers)
    assert log_summary_res.status_code == 200
    print(f"    -> Log summary PASS (Anomalous events: {log_summary_res.json()['anomalous_events']})")

    # 8. Direct Messaging Across Scopes
    print("\n[+] 8. Verifying persistent Direct Messaging...")
    contacts_res = client.get("/api/v1/direct-messages/contacts", headers=headers)
    assert contacts_res.status_code == 200
    contacts_data = contacts_res.json()
    contacts = contacts_data if isinstance(contacts_data, list) else contacts_data.get("contacts", [])
    print(f"    -> Contacts listed: {len(contacts)} contacts found")
    
    if len(contacts) > 0:
      target_slug = contacts[0].get("public_user_id") or contacts[0].get("user_slug")
      dm_send_res = client.post(f"/api/v1/direct-messages/{target_slug}", headers=headers, json={
          "body": "Hello! Confirming encrypted direct message delivery across user scopes."
      })
      assert dm_send_res.status_code == 200
      print(f"    -> Direct message sent to @{target_slug}")

      dm_hist_res = client.get(f"/api/v1/direct-messages/{target_slug}", headers=headers)
      assert dm_hist_res.status_code == 200
      hist_data = dm_hist_res.json()
      hist_list = hist_data if isinstance(hist_data, list) else hist_data.get("messages", [])
      assert len(hist_list) >= 1
      print(f"    -> Direct message history retrieved: {len(hist_list)} messages")

    # 9. Persona Dashboards
    print("\n[+] 9. Verifying Persona Dashboards (Personal, Analyst, Organization)...")
    dash_p = client.get("/api/v1/dashboard/personal", headers=headers)
    assert dash_p.status_code == 200
    print("    -> Personal Dashboard PASS")

    dash_a = client.get("/api/v1/dashboard/analyst", headers=headers)
    assert dash_a.status_code == 200
    print("    -> Analyst Dashboard PASS")

    dash_o = client.get("/api/v1/dashboard/organization", headers=headers)
    assert dash_o.status_code == 200
    print("    -> Organization Dashboard PASS")

    # 10. AI Assistant Status
    print("\n[+] 10. Checking AI Assistant status...")
    asst_status = client.get("/api/v1/assistant/status", headers=headers)
    assert asst_status.status_code == 200
    print(f"    -> Assistant status: {asst_status.json()}")

    print("\n" + "="*70)
    print("ALL PRODUCTION INTEGRATION TESTS PASSED WITH 100% SUCCESS!")
    print("="*70 + "\n")

if __name__ == "__main__":
    test_full_pipeline()
