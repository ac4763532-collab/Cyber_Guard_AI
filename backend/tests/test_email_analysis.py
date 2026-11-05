"""
CyberGuard AI - Email Analysis Test Cases

Synthetic test cases for email security analysis verification.
Each test case validates specific detection capabilities.
"""

import pytest
from datetime import datetime, timezone

# Test data for email analysis


# =============================================================================
# TEST 1: Normal/Benign Email
# =============================================================================
TEST_BENIGN_EMAIL = {
    "sender": "john.smith@acme-corp.com",
    "recipient": "jane.doe@company.com",
    "subject": "Q3 Budget Review Meeting",
    "body": """Hi Jane,

I wanted to follow up on our discussion about the Q3 budget review.

Can we schedule a meeting for next Tuesday at 2pm? Let me know if that works for you.

Best regards,
John Smith
Finance Manager
ACME Corporation
""",
    "headers": {
        "From": "John Smith <john.smith@acme-corp.com>",
        "To": "jane.doe@company.com",
        "Message-ID": "<abc123@mail.acme-corp.com>",
    },
    "expected": {
        "classification": "benign",
        "risk_level": "low",
        "min_risk_score": 0,
        "max_risk_score": 25,
    }
}


# =============================================================================
# TEST 2: Urgency Only
# =============================================================================
TEST_URGENCY_EMAIL = {
    "sender": "notifications@service.com",
    "recipient": "user@example.com",
    "subject": "URGENT: Action Required Within 24 Hours",
    "body": """Dear Customer,

URGENT ACTION REQUIRED!

Your service subscription will expire within 24 hours unless you take immediate action.

Act now to avoid service interruption.

Thank you,
Service Team
""",
    "expected": {
        "findings": ["urgency"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 3: Credential Request
# =============================================================================
TEST_CREDENTIAL_REQUEST = {
    "sender": "support@secure-service.com",
    "recipient": "user@example.com",
    "subject": "Password Reset Required",
    "body": """Dear User,

We need you to confirm your password to continue using our service.

Please enter your username and password at the link below:

Click here to verify your account.

Best regards,
Support Team
""",
    "expected": {
        "findings": ["credential"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 4: Brand Impersonation
# =============================================================================
TEST_BRAND_IMPERSONATION = {
    "sender": "security@paypa1-secure.xyz",
    "recipient": "user@example.com",
    "subject": "PayPal: Security Alert",
    "body": """Dear PayPal Customer,

We have detected unusual activity on your PayPal account.

Please verify your account immediately.

PayPal Security Team
""",
    "expected": {
        "findings": ["brand", "impersonation"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 5: Suspicious URL
# =============================================================================
TEST_SUSPICIOUS_URL = {
    "sender": "notification@service.com",
    "recipient": "user@example.com",
    "subject": "Your document is ready",
    "body": """Hello,

Your document has been processed. Click below to view:

https://suspicious-login.xyz/document/view?id=12345

Thank you.
""",
    "urls": ["https://suspicious-login.xyz/document/view?id=12345"],
    "expected": {
        "findings": ["url", "suspicious"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 6: URL Shortener
# =============================================================================
TEST_URL_SHORTENER = {
    "sender": "promo@marketing.com",
    "recipient": "user@example.com",
    "subject": "Special Offer Inside!",
    "body": """Hi there!

Check out our special offer: http://bit.ly/special-offer-2024

Limited time only!
""",
    "urls": ["http://bit.ly/special-offer-2024"],
    "expected": {
        "findings": ["shortener", "url"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 7: @ URL Deception
# =============================================================================
TEST_AT_URL_DECEPTION = {
    "sender": "alert@service.com",
    "recipient": "user@example.com",
    "subject": "Important Update",
    "body": """Click here to update your settings:

https://google.com@evil-site.com/login

Thank you.
""",
    "urls": ["https://google.com@evil-site.com/login"],
    "expected": {
        "findings": ["deceptive", "url"],
        "severity": "critical",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 8: Display URL vs Href Mismatch
# =============================================================================
TEST_DISPLAY_HREF_MISMATCH = {
    "sender": "support@company.com",
    "recipient": "user@example.com",
    "subject": "Account Update",
    "body": """Please click the link below:

<a href="https://evil-phishing-site.com/steal">https://microsoft.com/security</a>

Thank you.
""",
    "body_html": """<html><body>
<p>Please click the link below:</p>
<a href="https://evil-phishing-site.com/steal">https://microsoft.com/security</a>
</body></html>""",
    "expected": {
        "findings": ["mismatch", "display"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 9: Reply-To Mismatch
# =============================================================================
TEST_REPLY_TO_MISMATCH = {
    "sender": "ceo@company.com",
    "recipient": "employee@company.com",
    "subject": "Wire Transfer Request",
    "body": """Hi,

I need you to process an urgent wire transfer.

Reply to confirm.

Thanks,
CEO
""",
    "headers": {
        "From": "CEO <ceo@company.com>",
        "Reply-To": "attacker@external-domain.xyz",
    },
    "expected": {
        "findings": ["reply-to", "mismatch"],
        "severity": "high",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 10: Dangerous Attachment
# =============================================================================
TEST_DANGEROUS_ATTACHMENT = {
    "sender": "colleague@company.com",
    "recipient": "user@company.com",
    "subject": "Invoice Attached",
    "body": """Hi,

Please find the invoice attached.

Best regards.
""",
    "attachments": [
        {
            "filename": "invoice.exe",
            "mime_type": "application/x-msdownload",
            "size": 12345,
        }
    ],
    "expected": {
        "findings": ["dangerous", "attachment", "executable"],
        "severity": "critical",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 11: MIME Mismatch
# =============================================================================
TEST_MIME_MISMATCH = {
    "sender": "hr@company.com",
    "recipient": "user@company.com",
    "subject": "New Policy Document",
    "body": """Please review the attached policy document.""",
    "attachments": [
        {
            "filename": "policy.pdf",
            "mime_type": "application/x-executable",
            "size": 5000,
        }
    ],
    "expected": {
        "findings": ["mime", "mismatch"],
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 12: Macro-Enabled Document
# =============================================================================
TEST_MACRO_DOCUMENT = {
    "sender": "vendor@supplier.com",
    "recipient": "purchasing@company.com",
    "subject": "Updated Price List",
    "body": """Please find our updated price list attached.

Enable macros to view the interactive content.
""",
    "attachments": [
        {
            "filename": "price_list.xlsm",
            "mime_type": "application/vnd.ms-excel.sheet.macroEnabled.12",
            "size": 25000,
        }
    ],
    "expected": {
        "findings": ["macro"],
        "severity": "high",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 13: Double Extension
# =============================================================================
TEST_DOUBLE_EXTENSION = {
    "sender": "sender@domain.com",
    "recipient": "user@company.com",
    "subject": "Document for review",
    "body": """Please see attached.""",
    "attachments": [
        {
            "filename": "document.pdf.exe",
            "mime_type": "application/pdf",
            "size": 15000,
        }
    ],
    "expected": {
        "findings": ["double", "extension"],
        "severity": "critical",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 14: IP-based URL
# =============================================================================
TEST_IP_URL = {
    "sender": "alert@service.com",
    "recipient": "user@example.com",
    "subject": "Action Required",
    "body": """Click here to continue:

http://192.168.1.100/login/verify

Thanks.
""",
    "urls": ["http://192.168.1.100/login/verify"],
    "expected": {
        "findings": ["ip", "url"],
        "severity": "high",
        "min_findings_count": 1,
    }
}


# =============================================================================
# TEST 15: Phishing Combo (Multiple Indicators)
# =============================================================================
TEST_PHISHING_COMBO = {
    "sender": "security@microsoft-verify.xyz",
    "recipient": "user@company.com",
    "subject": "URGENT: Your Microsoft Account Has Been Compromised!",
    "body": """Dear Microsoft Customer,

We have detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account: http://bit.ly/ms-verify-now

Please provide your username and password to complete verification.

Microsoft Security Team
""",
    "urls": ["http://bit.ly/ms-verify-now"],
    "headers": {
        "Reply-To": "attacker@different-domain.com",
    },
    "expected": {
        "classification": "phishing",
        "risk_level": "critical",
        "min_risk_score": 70,
        "min_findings_count": 4,
    }
}


# =============================================================================
# ALL TEST CASES
# =============================================================================
ALL_TEST_CASES = [
    ("benign", TEST_BENIGN_EMAIL),
    ("urgency", TEST_URGENCY_EMAIL),
    ("credential_request", TEST_CREDENTIAL_REQUEST),
    ("brand_impersonation", TEST_BRAND_IMPERSONATION),
    ("suspicious_url", TEST_SUSPICIOUS_URL),
    ("url_shortener", TEST_URL_SHORTENER),
    ("at_url_deception", TEST_AT_URL_DECEPTION),
    ("display_href_mismatch", TEST_DISPLAY_HREF_MISMATCH),
    ("reply_to_mismatch", TEST_REPLY_TO_MISMATCH),
    ("dangerous_attachment", TEST_DANGEROUS_ATTACHMENT),
    ("mime_mismatch", TEST_MIME_MISMATCH),
    ("macro_document", TEST_MACRO_DOCUMENT),
    ("double_extension", TEST_DOUBLE_EXTENSION),
    ("ip_url", TEST_IP_URL),
    ("phishing_combo", TEST_PHISHING_COMBO),
]


def get_test_case(name: str) -> dict:
    """Get a test case by name."""
    for test_name, test_data in ALL_TEST_CASES:
        if test_name == name:
            return test_data
    raise ValueError(f"Test case not found: {name}")


def validate_result(result: dict, expected: dict) -> list[str]:
    """
    Validate analysis result against expected values.

    Returns list of validation errors (empty if all pass).
    """
    errors = []

    # Check classification
    if "classification" in expected:
        if result.get("classification") != expected["classification"]:
            errors.append(
                f"Classification mismatch: expected {expected['classification']}, "
                f"got {result.get('classification')}"
            )

    # Check risk level
    if "risk_level" in expected:
        risk_score = result.get("risk_score", 0)
        expected_level = expected["risk_level"]

        # Determine actual level from score
        if risk_score >= 80:
            actual_level = "critical"
        elif risk_score >= 60:
            actual_level = "high"
        elif risk_score >= 30:
            actual_level = "medium"
        else:
            actual_level = "low"

        if actual_level != expected_level:
            errors.append(
                f"Risk level mismatch: expected {expected_level}, got {actual_level} (score: {risk_score})"
            )

    # Check risk score range
    if "min_risk_score" in expected:
        if result.get("risk_score", 0) < expected["min_risk_score"]:
            errors.append(
                f"Risk score too low: expected >= {expected['min_risk_score']}, "
                f"got {result.get('risk_score')}"
            )

    if "max_risk_score" in expected:
        if result.get("risk_score", 0) > expected["max_risk_score"]:
            errors.append(
                f"Risk score too high: expected <= {expected['max_risk_score']}, "
                f"got {result.get('risk_score')}"
            )

    # Check findings count
    if "min_findings_count" in expected:
        findings_count = len(result.get("findings", []))
        if findings_count < expected["min_findings_count"]:
            errors.append(
                f"Too few findings: expected >= {expected['min_findings_count']}, "
                f"got {findings_count}"
            )

    # Check for specific findings (by keyword in name)
    if "findings" in expected:
        finding_names = [f.get("name", "").lower() for f in result.get("findings", [])]
        all_names_str = " ".join(finding_names)

        for expected_keyword in expected["findings"]:
            if expected_keyword.lower() not in all_names_str:
                errors.append(f"Expected finding keyword not found: {expected_keyword}")

    # Check severity
    if "severity" in expected:
        # Check if any finding has the expected severity
        severities = [f.get("severity", "").lower() for f in result.get("findings", [])]
        if expected["severity"] not in severities and result.get("severity") != expected["severity"]:
            errors.append(
                f"Expected severity {expected['severity']} not found in findings"
            )

    return errors
