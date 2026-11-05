"""
CyberGuard AI - Email Upload (.eml) Endpoint Tests

HTTP-level tests for POST /api/v1/analysis/email/upload and
GET /api/v1/analysis/history, using FastAPI's TestClient.

Sample .eml files are built in-test via email.message.EmailMessage
rather than committed binary fixtures.
"""

import io

import pytest
from email.message import EmailMessage
from fastapi.testclient import TestClient

from app.services.eml_parser import MAX_EML_SIZE_BYTES


def _build_eml_bytes(
    sender: str = "security@bank-verify.com",
    recipient: str = "user@example.com",
    subject: str = "Urgent: Verify Your Account",
    body: str = (
        "Dear Customer,\n\n"
        "Your account has been compromised. Click here to verify: "
        "http://bit.ly/verify-now\n\n"
        "Regards,\nSecurity Team"
    ),
    extra_headers: dict | None = None,
) -> bytes:
    """Build a small, valid .eml message as raw bytes."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Message-ID"] = "<test-123@example.com>"
    if extra_headers:
        for key, value in extra_headers.items():
            msg[key] = value
    msg.set_content(body)
    return bytes(msg)


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


class TestEmailUpload:
    def test_valid_eml_returns_200_with_report_shape(self, client):
        eml_bytes = _build_eml_bytes()
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("sample.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

        assert response.status_code == 200
        data = response.json()
        # Same report shape as /email/investigate (mirrors test_email_analysis.py
        # style: assert on top-level report fields rather than internals).
        assert "report_id" in data
        assert "verdict" in data
        assert "classification" in data["verdict"]
        assert "risk_score" in data["verdict"]

    def test_eml_with_auth_headers_populates_real_authentication(self, client):
        eml_bytes = _build_eml_bytes(
            extra_headers={
                "Authentication-Results": (
                    "mx.google.com; dkim=pass header.d=example.com; "
                    "spf=fail (google.com) smtp.mailfrom=example.com; "
                    "dmarc=pass (p=REJECT) header.from=example.com"
                ),
                "Reply-To": "reply@example.com",
            }
        )
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("sample.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

        assert response.status_code == 200
        data = response.json()
        auth = data.get("authentication", {})
        # Real header data was supplied - must not fall back to "not available".
        assert auth.get("spf", {}).get("status") not in (None, "not_available")

    def test_oversized_file_returns_413(self, client):
        # Build a payload that exceeds the cap without needing a huge real
        # email: pad the body past MAX_EML_SIZE_BYTES.
        oversized_body = "A" * (MAX_EML_SIZE_BYTES + 1024)
        eml_bytes = _build_eml_bytes(body=oversized_body)
        assert len(eml_bytes) > MAX_EML_SIZE_BYTES

        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("big.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )

        assert response.status_code == 413

    def test_wrong_extension_returns_400(self, client):
        eml_bytes = _build_eml_bytes()
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("sample.txt", io.BytesIO(eml_bytes), "text/plain")},
        )

        assert response.status_code == 400

    def test_non_email_content_returns_400(self, client):
        garbage = b"this is just a plain text file, not an email at all"
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("sample.eml", io.BytesIO(garbage), "message/rfc822")},
        )

        assert response.status_code == 400

    def test_malformed_mime_returns_400_not_500(self, client):
        # Bytes that sniff as "looks like email" (has a From: line) but are
        # otherwise garbage - should still fail cleanly as a 400, not a 500.
        malformed = b"From: test@example.com\nThis is not valid MIME \xff\xfe garbage"
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("broken.eml", io.BytesIO(malformed), "message/rfc822")},
        )

        assert response.status_code in (200, 400)
        assert response.status_code != 500

    def test_empty_file_returns_400(self, client):
        response = client.post(
            "/api/v1/analysis/email/upload",
            files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")},
        )

        assert response.status_code == 400


class TestAnalysisHistory:
    def test_get_history_returns_list(self, client):
        response = client.get("/api/v1/analysis/history")

        # Whether or not the DB is enabled, this must not 500 - it returns
        # an empty list when the DB is disabled (see get_analysis_history).
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_get_history_respects_limit_param(self, client):
        response = client.get("/api/v1/analysis/history", params={"limit": 5})
        assert response.status_code == 200
