"""
CyberGuard AI - Email Security Agent

Specialized agent for detecting phishing, malicious content,
and suspicious patterns in emails.

Detection Methods:
1. Sender analysis (domain reputation, spoofing)
2. Reply-To mismatch detection
3. URL analysis (shortened links, suspicious domains)
4. Content analysis (urgency, credential requests)
5. Attachment analysis
6. IOC extraction
7. Rule-based pattern matching
8. Risk scoring
9. SPF/DKIM/DMARC authentication analysis (Phase 3)
10. Email header chain analysis (Phase 3)

Classification Output:
- benign: No threats detected
- suspicious: Some indicators present but not conclusive
- phishing: High-confidence phishing attempt
- malicious: Contains malware indicators or known bad IOCs
"""

import re
import hashlib
from typing import Any
from urllib.parse import urlparse
from datetime import datetime, timezone

from app.ml.classifier import predict as ml_predict, load_models, get_model_status

from app.agents.base import (
    BaseAgent,
    AgentType,
    AgentStatus,
    AgentResult,
    Finding,
    Severity,
)


# =============================================================================
# Known Indicators and Patterns
# =============================================================================

# Commonly abused free email providers for phishing
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "yandex.com", "gmx.com", "zoho.com",
}

# URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at",
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".link", ".info", ".online",
    ".site", ".website", ".space", ".tech", ".store", ".live",
}

# High-risk file extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".ws", ".wsf", ".msc", ".msi", ".msp", ".hta",
    ".cpl", ".jar", ".ps1", ".psm1", ".reg", ".lnk", ".iso", ".img",
}

# Macro-enabled document extensions
MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".xlam", ".ppam", ".sldm",
}

# Archive extensions (can hide malware)
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".arj", ".lzh", ".ace",
}

# Disk image extensions (often used for malware delivery)
DISK_IMAGE_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".vhdx", ".dmg",
}

# Urgency and social engineering phrases
URGENCY_PHRASES = [
    r"urgent",
    r"immediate\s+action",
    r"account\s+(suspend|terminat|block|lock)",
    r"verify\s+(your|account|identity)",
    r"confirm\s+(your|account|identity)",
    r"within\s+\d+\s+hours?",
    r"act\s+now",
    r"limited\s+time",
    r"expire[sd]?\s+(soon|today|tomorrow)",
    r"unusual\s+(activity|sign[\s-]?in|login)",
    r"unauthorized\s+(access|activity)",
    r"security\s+alert",
    r"your\s+account\s+has\s+been",
    r"failure\s+to\s+(verify|respond|confirm)",
]

# Credential request phrases
CREDENTIAL_PHRASES = [
    r"enter\s+(your\s+)?(password|credentials|login)",
    r"(password|login)\s+reset",
    r"confirm\s+(your\s+)?(password|credentials)",
    r"(update|verify)\s+(your\s+)?(account|payment)",
    r"click\s+(here|below|the\s+link)",
    r"sign[\s-]?in\s+to\s+(your\s+)?account",
    r"log[\s-]?in\s+immediately",
]

# Sensitive brands commonly impersonated
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "netflix", "bank", "wells fargo", "chase", "citi", "hsbc",
    "dropbox", "docusign", "linkedin", "twitter", "instagram",
    "dhl", "fedex", "ups", "usps", "irs", "social security",
]


# =============================================================================
# Email Authentication Result Patterns
# =============================================================================

# SPF result patterns
SPF_RESULTS = {
    "pass": ("SPF passed", Severity.INFO, 0),
    "fail": ("SPF failed - sender IP not authorized", Severity.HIGH, 20),
    "softfail": ("SPF soft fail - sender IP may not be authorized", Severity.MEDIUM, 10),
    "neutral": ("SPF neutral - no policy defined", Severity.LOW, 5),
    "none": ("No SPF record found", Severity.MEDIUM, 8),
    "temperror": ("SPF temporary error", Severity.LOW, 3),
    "permerror": ("SPF permanent error - invalid record", Severity.MEDIUM, 7),
}

# DKIM result patterns
DKIM_RESULTS = {
    "pass": ("DKIM signature valid", Severity.INFO, 0),
    "fail": ("DKIM signature invalid - email may be modified", Severity.HIGH, 20),
    "neutral": ("DKIM neutral", Severity.LOW, 3),
    "none": ("No DKIM signature", Severity.MEDIUM, 8),
    "temperror": ("DKIM temporary error", Severity.LOW, 3),
    "permerror": ("DKIM permanent error", Severity.MEDIUM, 7),
}

# DMARC result patterns
DMARC_RESULTS = {
    "pass": ("DMARC passed", Severity.INFO, 0),
    "fail": ("DMARC failed - authentication failed", Severity.CRITICAL, 25),
    "none": ("No DMARC policy", Severity.MEDIUM, 10),
    "quarantine": ("DMARC quarantine policy triggered", Severity.HIGH, 15),
    "reject": ("DMARC reject policy - should not be delivered", Severity.CRITICAL, 25),
}


# =============================================================================
# Email Security Agent
# =============================================================================

class EmailAgent(BaseAgent):
    """
    Email Security Agent for phishing and malicious email detection.
    """

    agent_type = AgentType.EMAIL
    agent_name = "Email Security Agent"
    agent_version = "0.1.0"

    def __init__(self):
        super().__init__()
        self._status = AgentStatus.ONLINE

        # Initialize ML classifier.
        # If the model cannot be loaded, the existing rule-based
        # detection continues to work normally.
        try:
            self._ml_available = load_models()
            self._ml_status = get_model_status()
        except Exception:
            self._ml_available = False
            self._ml_status = {
                "loaded": False,
                "model": "tfidf_logistic_regression",
                "error": "ML model initialization failed",
            }

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate email data."""
        if not data.get("sender"):
            return False, "Sender is required"
        if not data.get("subject"):
            return False, "Subject is required"
        if not data.get("body"):
            return False, "Body is required"
        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        """Analyze email for security threats."""
        findings: list[Finding] = []
        indicators: list[str] = []
        recommendations: list[str] = []

        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        headers = data.get("headers") or {}  # Handle None explicitly
        urls = data.get("urls") or []  # Handle None explicitly
        attachments = data.get("attachments") or []  # Handle None explicitly

        # Extract URLs from body if not provided
        if not urls:
            urls = self._extract_urls(body)

        # Run all detection methods
        findings.extend(self._analyze_sender(sender, headers))
        findings.extend(self._check_reply_to_mismatch(sender, headers))
        findings.extend(self._analyze_urls(urls))
        findings.extend(self._analyze_content(subject, body))
        findings.extend(self._analyze_attachments(attachments))
        findings.extend(self._check_brand_impersonation(sender, subject, body))

        # Phase 3: Email authentication analysis
        auth_results = data.get("authentication") or {}
        findings.extend(self._analyze_spf(auth_results, headers))
        findings.extend(self._analyze_dkim(auth_results, headers))
        findings.extend(self._analyze_dmarc(auth_results, headers))
        findings.extend(self._analyze_header_chain(headers))

        # ML detection
        # The ML classifier is an additional signal and does not replace
        # the existing rule-based detection engine.
        ml_result = None

        if self._ml_available:
            try:
                ml_result = ml_predict(
                    sender=sender,
                    subject=subject,
                    body=body,
                )

                if ml_result.get("model_loaded") and ml_result.get("is_malicious"):
                    probability = float(ml_result.get("probability", 0.0))

                    if probability >= 0.90:
                        ml_severity = Severity.HIGH
                    elif probability >= 0.70:
                        ml_severity = Severity.HIGH
                    else:
                        ml_severity = Severity.MEDIUM

                    findings.append(
                        Finding(
                            rule_id="ML-001",
                            name="ML phishing detection",
                            description=(
                                "Machine learning classifier detected "
                                "malicious email characteristics."
                            ),
                            severity=ml_severity,
                            confidence=float(
                                ml_result.get("confidence", probability)
                            ),
                            evidence=[
                                f"ML malicious probability: {probability:.2%}",
                                f"Classification threshold: {ml_result.get('threshold', 0.5):.2f}",
                            ],
                            recommendations=[
                                "Review the email using the rule-based findings and ML evidence.",
                                "Do not interact with links or attachments until the email is verified.",
                            ],
                            metadata={
                                "model": ml_result.get(
                                    "model",
                                    "tfidf_logistic_regression"
                                ),
                                "probability": probability,
                                "threshold": ml_result.get("threshold", 0.5),
                            },
                        )
                    )

            except Exception:
                # ML failure must never break the existing rule engine.
                ml_result = None

        # Extract IOCs
        indicators = self._extract_iocs(sender, body, urls)

        # Calculate classification and risk score
        classification, severity, confidence, risk_score = self._calculate_risk(findings)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, classification)

        # Build summary
        summary = self._build_summary(classification, findings, indicators)

        # Create input hash for deduplication
        input_hash = hashlib.sha256(
            f"{sender}|{subject}|{body}".encode()
        ).hexdigest()[:16]

        return self._create_result(
            classification=classification,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            indicators=indicators,
            recommendations=recommendations,
        )

    # -------------------------------------------------------------------------
    # Detection Methods
    # -------------------------------------------------------------------------

    def _analyze_sender(self, sender: str, headers: dict) -> list[Finding]:
        """Analyze sender for suspicious characteristics."""
        findings = []

        # Extract email from "Name <email>" format
        email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
        if not email_match:
            findings.append(Finding(
                rule_id="EMAIL-001",
                name="Invalid sender format",
                description="Sender email address could not be parsed",
                severity=Severity.MEDIUM,
                confidence=0.9,
                evidence=[f"Sender: {sender}"],
                recommendations=["Verify sender identity through alternative channels"],
            ))
            return findings

        email = email_match.group().lower()
        domain = email.split("@")[1] if "@" in email else ""

        # Check for free email provider claiming to be organization
        if domain in FREE_EMAIL_DOMAINS:
            findings.append(Finding(
                rule_id="EMAIL-002",
                name="Free email provider",
                description="Email from free provider claiming organizational communication",
                severity=Severity.LOW,
                confidence=0.6,
                evidence=[f"Domain: {domain}"],
                recommendations=["Verify sender is legitimate before taking action"],
            ))

        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(Finding(
                    rule_id="EMAIL-003",
                    name="Suspicious top-level domain",
                    description=f"Sender uses suspicious TLD: {tld}",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    evidence=[f"Domain: {domain}"],
                    mitre_techniques=["T1566.001"],
                    recommendations=["Treat with caution, verify sender identity"],
                ))
                break

        # Check for lookalike domain (basic check)
        for brand in IMPERSONATED_BRANDS:
            if brand in domain and brand not in email.split("@")[0]:
                # Brand in domain but sender doesn't seem legitimate
                if not self._is_legitimate_brand_domain(domain, brand):
                    findings.append(Finding(
                        rule_id="EMAIL-004",
                        name="Potential domain spoofing",
                        description=f"Domain appears to impersonate: {brand}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        evidence=[f"Domain: {domain}", f"Impersonated brand: {brand}"],
                        mitre_techniques=["T1566.001", "T1036"],
                        recommendations=["Do not click any links", "Report as phishing"],
                    ))

        return findings

    def _check_reply_to_mismatch(self, sender: str, headers: dict) -> list[Finding]:
        """Check for Reply-To header mismatch."""
        findings = []

        reply_to = headers.get("Reply-To", "") or headers.get("reply-to", "")
        if not reply_to:
            return findings

        # Extract domains
        sender_match = re.search(r'@([\w\.-]+)', sender.lower())
        reply_match = re.search(r'@([\w\.-]+)', reply_to.lower())

        if sender_match and reply_match:
            sender_domain = sender_match.group(1)
            reply_domain = reply_match.group(1)

            if sender_domain != reply_domain:
                findings.append(Finding(
                    rule_id="EMAIL-005",
                    name="Reply-To domain mismatch",
                    description="Reply-To header points to different domain than sender",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence=[
                        f"Sender domain: {sender_domain}",
                        f"Reply-To domain: {reply_domain}",
                    ],
                    mitre_techniques=["T1566.001"],
                    recommendations=[
                        "Do not reply to this email",
                        "Verify sender through official channels",
                    ],
                ))

        return findings

    def _analyze_urls(self, urls: list[str]) -> list[Finding]:
        """Analyze URLs for suspicious characteristics."""
        findings = []

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # Check for URL shorteners
                for shortener in URL_SHORTENERS:
                    if shortener in domain:
                        findings.append(Finding(
                            rule_id="URL-001",
                            name="URL shortener detected",
                            description=f"Email contains shortened URL that hides true destination",
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            evidence=[f"URL: {url}"],
                            mitre_techniques=["T1566.002"],
                            recommendations=["Expand URL before clicking", "Verify destination"],
                        ))
                        break

                # Check for IP address URLs
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    findings.append(Finding(
                        rule_id="URL-002",
                        name="IP-based URL",
                        description="URL uses IP address instead of domain name",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence=[f"URL: {url}"],
                        mitre_techniques=["T1566.002"],
                        recommendations=["Do not click - IP-based URLs are rarely legitimate"],
                    ))

                # Check for suspicious TLD in URL
                for tld in SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        findings.append(Finding(
                            rule_id="URL-003",
                            name="Suspicious URL domain",
                            description=f"URL uses suspicious TLD: {tld}",
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            evidence=[f"URL: {url}"],
                            recommendations=["Verify URL is legitimate before clicking"],
                        ))
                        break

                # Check for @ in URL (credential harvesting trick)
                if "@" in url and parsed.username:
                    findings.append(Finding(
                        rule_id="URL-004",
                        name="Deceptive URL structure",
                        description="URL contains @ symbol to hide true destination",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        evidence=[f"URL: {url}"],
                        mitre_techniques=["T1566.002"],
                        recommendations=["Do not click - this is a URL spoofing technique"],
                    ))

            except Exception:
                continue

        return findings

    def _analyze_content(self, subject: str, body: str) -> list[Finding]:
        """Analyze email content for social engineering indicators."""
        findings = []
        combined = f"{subject} {body}".lower()

        # Check for urgency phrases
        urgency_matches = []
        for pattern in URGENCY_PHRASES:
            if re.search(pattern, combined, re.IGNORECASE):
                urgency_matches.append(pattern)

        if urgency_matches:
            severity = Severity.HIGH if len(urgency_matches) >= 3 else Severity.MEDIUM
            findings.append(Finding(
                rule_id="CONTENT-001",
                name="Urgency language detected",
                description=f"Email uses urgency tactics common in phishing ({len(urgency_matches)} patterns found)",
                severity=severity,
                confidence=min(0.5 + len(urgency_matches) * 0.1, 0.9),
                evidence=[f"Matched: {m}" for m in urgency_matches[:5]],
                mitre_techniques=["T1566.001"],
                recommendations=["Verify urgency through official channels before acting"],
            ))

        # Check for credential request phrases
        credential_matches = []
        for pattern in CREDENTIAL_PHRASES:
            if re.search(pattern, combined, re.IGNORECASE):
                credential_matches.append(pattern)

        if credential_matches:
            findings.append(Finding(
                rule_id="CONTENT-002",
                name="Credential request detected",
                description="Email requests credentials or sensitive information",
                severity=Severity.HIGH,
                confidence=min(0.6 + len(credential_matches) * 0.1, 0.95),
                evidence=[f"Matched: {m}" for m in credential_matches[:5]],
                mitre_techniques=["T1566.001", "T1598"],
                recommendations=[
                    "Never enter credentials via email links",
                    "Navigate to sites directly via bookmarks",
                ],
            ))

        return findings

    def _analyze_attachments(self, attachments: list[dict]) -> list[Finding]:
        """Analyze attachment metadata for suspicious files."""
        findings = []

        for attachment in attachments:
            filename = attachment.get("filename", "").lower()
            mime_type = attachment.get("mime_type", "").lower()
            size = attachment.get("size", 0)

            # Check for dangerous extensions
            for ext in DANGEROUS_EXTENSIONS:
                if filename.endswith(ext):
                    findings.append(Finding(
                        rule_id="ATTACH-001",
                        name="Dangerous attachment type",
                        description=f"Email contains potentially dangerous file type: {ext}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        evidence=[f"Filename: {filename}"],
                        mitre_techniques=["T1566.001", "T1204.002"],
                        recommendations=[
                            "Do not open this attachment",
                            "Report to security team",
                            "Delete the email",
                        ],
                    ))
                    break

            # Check for macro-enabled documents
            for ext in MACRO_EXTENSIONS:
                if filename.endswith(ext):
                    findings.append(Finding(
                        rule_id="ATTACH-003",
                        name="Macro-enabled document",
                        description=f"Email contains macro-enabled document: {ext}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence=[f"Filename: {filename}"],
                        mitre_techniques=["T1566.001", "T1204.002", "T1059.005"],
                        recommendations=[
                            "Do not enable macros if prompted",
                            "Verify sender before opening",
                            "Scan with antivirus before opening",
                        ],
                    ))
                    break

            # Check for password-protected archives
            if any(filename.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
                # Check if password is mentioned in email (common malware tactic)
                findings.append(Finding(
                    rule_id="ATTACH-004",
                    name="Archive attachment",
                    description="Email contains archive file that may hide malicious content",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    evidence=[f"Filename: {filename}"],
                    mitre_techniques=["T1566.001", "T1027"],
                    recommendations=[
                        "Scan archive contents before extracting",
                        "Be suspicious if password is in email body",
                    ],
                ))

            # Check for disk image files
            if any(filename.endswith(ext) for ext in DISK_IMAGE_EXTENSIONS):
                findings.append(Finding(
                    rule_id="ATTACH-005",
                    name="Disk image attachment",
                    description="Email contains disk image file - increasingly used for malware delivery",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    evidence=[f"Filename: {filename}"],
                    mitre_techniques=["T1566.001", "T1553.005"],
                    recommendations=[
                        "Disk images can bypass security controls",
                        "Do not mount without scanning first",
                    ],
                ))

            # Check for double extension trick (e.g., document.pdf.exe)
            if re.search(r'\.\w+\.\w+$', filename):
                parts = filename.rsplit(".", 2)
                if len(parts) >= 2:
                    final_ext = f".{parts[-1]}"
                    if final_ext in DANGEROUS_EXTENSIONS or final_ext in MACRO_EXTENSIONS:
                        findings.append(Finding(
                            rule_id="ATTACH-002",
                            name="Double extension detected",
                            description="Attachment uses double extension to hide true file type",
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            evidence=[f"Filename: {filename}"],
                            mitre_techniques=["T1036.007"],
                            recommendations=["Do not open - this is a malware distribution technique"],
                        ))

            # Check MIME type vs extension mismatch
            if mime_type and filename:
                ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
                mime_ext_map = {
                    "application/pdf": [".pdf"],
                    "application/msword": [".doc", ".docx"],
                    "application/vnd.ms-excel": [".xls", ".xlsx"],
                    "application/x-executable": [".exe", ".dll"],
                    "application/x-dosexec": [".exe", ".dll"],
                    "text/html": [".html", ".htm"],
                    "application/javascript": [".js"],
                }

                for mime, expected_exts in mime_ext_map.items():
                    if mime in mime_type and ext and ext not in expected_exts:
                        findings.append(Finding(
                            rule_id="ATTACH-006",
                            name="MIME type mismatch",
                            description=f"File extension doesn't match MIME type",
                            severity=Severity.HIGH,
                            confidence=0.75,
                            evidence=[
                                f"Filename: {filename}",
                                f"MIME type: {mime_type}",
                                f"Expected extensions: {expected_exts}",
                            ],
                            mitre_techniques=["T1036.008"],
                            recommendations=["File may be disguised - treat with caution"],
                        ))
                        break

            # Check for unusually large attachments (potential data exfil or bloated malware)
            if size > 25 * 1024 * 1024:  # 25MB
                findings.append(Finding(
                    rule_id="ATTACH-007",
                    name="Unusually large attachment",
                    description=f"Attachment is unusually large ({size / (1024*1024):.1f} MB)",
                    severity=Severity.LOW,
                    confidence=0.5,
                    evidence=[f"Size: {size} bytes"],
                    recommendations=["Verify sender and need for such large attachment"],
                ))

        return findings

    def _check_brand_impersonation(self, sender: str, subject: str, body: str) -> list[Finding]:
        """Check for brand impersonation attempts."""
        findings = []
        combined = f"{subject} {body}".lower()

        for brand in IMPERSONATED_BRANDS:
            if brand in combined:
                # Check if sender domain matches brand
                sender_lower = sender.lower()
                if brand not in sender_lower:
                    findings.append(Finding(
                        rule_id="BRAND-001",
                        name="Potential brand impersonation",
                        description=f"Email mentions '{brand}' but sender domain doesn't match",
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        evidence=[f"Brand mentioned: {brand}", f"Sender: {sender}"],
                        mitre_techniques=["T1566.001", "T1036"],
                        recommendations=[f"Verify communication is from official {brand} channels"],
                    ))
                    break

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text."""
        url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))

    def _extract_iocs(self, sender: str, body: str, urls: list[str]) -> list[str]:
        """Extract indicators of compromise."""
        iocs = []

        # Extract sender domain
        email_match = re.search(r'@([\w\.-]+)', sender)
        if email_match:
            iocs.append(email_match.group(1))

        # Extract domains from URLs
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    iocs.append(parsed.netloc)
            except Exception:
                continue

        # Extract IPs from body
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, body)
        iocs.extend(ips)

        return list(set(iocs))

    def _is_legitimate_brand_domain(self, domain: str, brand: str) -> bool:
        """Basic check if domain appears legitimate for a brand."""
        legitimate_patterns = {
            "paypal": ["paypal.com"],
            "amazon": ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
            "microsoft": ["microsoft.com", "office.com", "outlook.com"],
            "google": ["google.com", "gmail.com"],
            "apple": ["apple.com", "icloud.com"],
            "facebook": ["facebook.com", "fb.com"],
            "netflix": ["netflix.com"],
        }
        patterns = legitimate_patterns.get(brand, [])
        return any(domain.endswith(p) for p in patterns)

    def _calculate_risk(self, findings: list[Finding]) -> tuple[str, Severity, float, int]:
        """Calculate overall classification, severity, confidence, and risk score."""
        if not findings:
            return "benign", Severity.INFO, 0.95, 5

        # Count findings by severity
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

        # Calculate risk score (0-100)
        risk_score = min(100, (
            critical_count * 30 +
            high_count * 15 +
            medium_count * 5 +
            len(findings) * 2
        ))

        # Determine classification
        if critical_count > 0 or risk_score >= 75:
            classification = "phishing" if critical_count > 0 else "malicious"
            severity = Severity.CRITICAL
            confidence = min(0.95, 0.7 + critical_count * 0.1)
        elif high_count >= 2 or risk_score >= 50:
            classification = "phishing"
            severity = Severity.HIGH
            confidence = min(0.9, 0.6 + high_count * 0.1)
        elif high_count > 0 or medium_count >= 2 or risk_score >= 25:
            classification = "suspicious"
            severity = Severity.MEDIUM
            confidence = min(0.8, 0.5 + (high_count + medium_count) * 0.1)
        else:
            classification = "suspicious"
            severity = Severity.LOW
            confidence = 0.6

        return classification, severity, confidence, risk_score

    def _generate_recommendations(self, findings: list[Finding], classification: str) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        if classification in ("phishing", "malicious"):
            recommendations.extend([
                "Do not click any links in this email",
                "Do not download or open any attachments",
                "Report this email to your security team",
                "Delete the email from your inbox",
            ])
        elif classification == "suspicious":
            recommendations.extend([
                "Verify sender identity through official channels",
                "Do not enter credentials or sensitive information",
                "If urgent, contact the organization directly via known contact info",
            ])

        # Add unique recommendations from findings
        for finding in findings:
            for rec in finding.recommendations:
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:10]  # Limit to top 10

    def _build_summary(self, classification: str, findings: list[Finding], indicators: list[str]) -> str:
        """Build human-readable summary."""
        if classification == "benign":
            return "No significant security threats detected in this email."

        finding_summary = ", ".join(f.name for f in findings[:3])
        if len(findings) > 3:
            finding_summary += f" and {len(findings) - 3} more"

        return (
            f"Email classified as {classification.upper()}. "
            f"Detected {len(findings)} security indicator(s): {finding_summary}. "
            f"Extracted {len(indicators)} IOC(s) for threat intelligence."
        )

    # -------------------------------------------------------------------------
    # Phase 3: Email Authentication Analysis
    # -------------------------------------------------------------------------

    def _analyze_spf(self, auth_results: dict, headers: dict) -> list[Finding]:
        """Analyze SPF authentication results."""
        findings = []

        # Get SPF result from auth_results or parse from headers
        spf_value = auth_results.get("spf", "")
        # Handle both dict format {"result": "pass"} and string format "pass"
        if isinstance(spf_value, dict):
            spf_result = spf_value.get("result", "").lower()
        else:
            spf_result = str(spf_value).lower() if spf_value else ""

        if not spf_result or spf_result == "unknown":
            # Try to parse from Authentication-Results header
            auth_header = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
            spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1).lower()

        if not spf_result:
            return findings

        if spf_result in SPF_RESULTS:
            desc, severity, risk_add = SPF_RESULTS[spf_result]

            if severity != Severity.INFO:
                evidence = [f"SPF result: {spf_result}"]

                # Extract SPF details if available. auth_results["spf"] itself
                # is normally a flat string (see EmailAuthResult.spf), so the
                # domain lives in a separate "spf_domain" key - except when
                # some upstream caller passes the dict-shaped format this
                # function also accepts (checked above), where it's nested
                # under spf_value["domain"]. Calling .get("domain") straight on
                # auth_results["spf"] crashed with AttributeError whenever that
                # value was a plain string, i.e. for any non-"pass" SPF result.
                if isinstance(spf_value, dict):
                    spf_domain = spf_value.get("domain", "")
                else:
                    spf_domain = auth_results.get("spf_domain", "")
                if spf_domain:
                    evidence.append(f"SPF domain: {spf_domain}")

                findings.append(Finding(
                    rule_id="AUTH-SPF-001",
                    name=f"SPF {spf_result.upper()}",
                    description=desc,
                    severity=severity,
                    confidence=0.9,
                    evidence=evidence,
                    mitre_techniques=["T1566.001"] if severity in (Severity.HIGH, Severity.CRITICAL) else [],
                    recommendations=[
                        "Verify sender is legitimate",
                        "SPF failure indicates the sending server may not be authorized",
                    ] if severity != Severity.INFO else [],
                ))

        return findings

    def _analyze_dkim(self, auth_results: dict, headers: dict) -> list[Finding]:
        """Analyze DKIM authentication results."""
        findings = []

        # Get DKIM result from auth_results or parse from headers
        dkim_value = auth_results.get("dkim", "")
        # Handle both dict format {"result": "pass"} and string format "pass"
        if isinstance(dkim_value, dict):
            dkim_result = dkim_value.get("result", "").lower()
        else:
            dkim_result = str(dkim_value).lower() if dkim_value else ""

        if not dkim_result or dkim_result == "unknown":
            auth_header = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
            dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1).lower()

        if not dkim_result:
            return findings

        if dkim_result in DKIM_RESULTS:
            desc, severity, risk_add = DKIM_RESULTS[dkim_result]

            if severity != Severity.INFO:
                evidence = [f"DKIM result: {dkim_result}"]

                # Extract DKIM selector/domain if available. Same shape issue
                # as SPF above: auth_results["dkim"] is normally a flat string
                # (EmailAuthResult.dkim), so .get("selector"/"domain") on it
                # crashed with AttributeError for any non-"pass" DKIM result.
                # EmailAuthResult has no selector field - domain lives in
                # "dkim_domain" when dkim_value isn't the dict-shaped format.
                if isinstance(dkim_value, dict):
                    dkim_selector = dkim_value.get("selector", "")
                    dkim_domain = dkim_value.get("domain", "")
                else:
                    dkim_selector = ""
                    dkim_domain = auth_results.get("dkim_domain", "")
                if dkim_selector:
                    evidence.append(f"DKIM selector: {dkim_selector}")
                if dkim_domain:
                    evidence.append(f"DKIM domain: {dkim_domain}")

                findings.append(Finding(
                    rule_id="AUTH-DKIM-001",
                    name=f"DKIM {dkim_result.upper()}",
                    description=desc,
                    severity=severity,
                    confidence=0.85,
                    evidence=evidence,
                    mitre_techniques=["T1566.001"] if severity in (Severity.HIGH, Severity.CRITICAL) else [],
                    recommendations=[
                        "Email content may have been tampered with",
                        "Verify sender through alternative channels",
                    ] if severity != Severity.INFO else [],
                ))

        return findings

    def _analyze_dmarc(self, auth_results: dict, headers: dict) -> list[Finding]:
        """Analyze DMARC authentication results."""
        findings = []

        # Get DMARC result from auth_results or parse from headers
        dmarc_value = auth_results.get("dmarc", "")
        # Handle both dict format {"result": "pass"} and string format "pass"
        if isinstance(dmarc_value, dict):
            dmarc_result = dmarc_value.get("result", "").lower()
        else:
            dmarc_result = str(dmarc_value).lower() if dmarc_value else ""

        if not dmarc_result or dmarc_result == "unknown":
            auth_header = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
            dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).lower()

        if not dmarc_result:
            return findings

        if dmarc_result in DMARC_RESULTS:
            desc, severity, risk_add = DMARC_RESULTS[dmarc_result]

            if severity != Severity.INFO:
                evidence = [f"DMARC result: {dmarc_result}"]

                # Extract DMARC policy if available. Same shape issue as SPF
                # and DKIM above: auth_results["dmarc"] is normally a flat
                # string (EmailAuthResult.dmarc), so .get("policy") on it
                # crashed with AttributeError for any non-"pass" DMARC result.
                # EmailAuthResult has no policy field for the flat-string case,
                # so there's nothing to recover there - only honor it when the
                # dict-shaped format was actually passed in.
                if isinstance(dmarc_value, dict):
                    dmarc_policy = dmarc_value.get("policy", "")
                else:
                    dmarc_policy = ""
                if dmarc_policy:
                    evidence.append(f"DMARC policy: {dmarc_policy}")

                findings.append(Finding(
                    rule_id="AUTH-DMARC-001",
                    name=f"DMARC {dmarc_result.upper()}",
                    description=desc,
                    severity=severity,
                    confidence=0.95,
                    evidence=evidence,
                    mitre_techniques=["T1566.001", "T1036"] if severity in (Severity.HIGH, Severity.CRITICAL) else [],
                    recommendations=[
                        "DMARC failure is a strong indicator of spoofing",
                        "Do not trust this email's claimed sender",
                        "Report as phishing attempt",
                    ] if severity in (Severity.HIGH, Severity.CRITICAL) else [],
                ))

        return findings

    def _analyze_header_chain(self, headers: dict) -> list[Finding]:
        """Analyze email header chain for anomalies."""
        findings = []

        # Get Received headers (mail path)
        received_headers = headers.get("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]

        if not received_headers:
            return findings

        # Check for excessive hops (potential relay abuse)
        if len(received_headers) > 10:
            findings.append(Finding(
                rule_id="HEADER-001",
                name="Excessive mail hops",
                description=f"Email passed through {len(received_headers)} servers - unusual routing",
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence=[f"Number of Received headers: {len(received_headers)}"],
                recommendations=["Excessive hops may indicate mail relay abuse or evasion"],
            ))

        # Check for suspicious patterns in Received headers
        suspicious_patterns = []
        for received in received_headers:
            received_lower = received.lower()

            # Check for localhost/private IPs in public mail path
            if re.search(r'from\s+localhost|from\s+127\.0\.0\.1|from\s+\[127\.', received_lower):
                suspicious_patterns.append("localhost in mail path")

            # Check for mismatched timestamps (future dates)
            date_match = re.search(r';\s*(.+)$', received)
            if date_match:
                try:
                    # Basic check for obviously wrong dates
                    if "2099" in date_match.group(1) or "1970" in date_match.group(1):
                        suspicious_patterns.append("Invalid timestamp in header")
                except Exception:
                    pass

        if suspicious_patterns:
            findings.append(Finding(
                rule_id="HEADER-002",
                name="Suspicious header patterns",
                description="Email headers contain suspicious patterns",
                severity=Severity.MEDIUM,
                confidence=0.75,
                evidence=list(set(suspicious_patterns)),
                mitre_techniques=["T1566.001"],
                recommendations=["Headers may be forged - treat with caution"],
            ))

        # Check X-Originating-IP for suspicious IPs
        originating_ip = headers.get("X-Originating-IP", "") or headers.get("x-originating-ip", "")
        if originating_ip:
            # Strip brackets if present
            ip = re.sub(r'[\[\]]', '', originating_ip).strip()

            # Check if it's a private IP (shouldn't appear in external email)
            if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', ip):
                findings.append(Finding(
                    rule_id="HEADER-003",
                    name="Private IP in originating header",
                    description="X-Originating-IP contains private IP address",
                    severity=Severity.LOW,
                    confidence=0.6,
                    evidence=[f"X-Originating-IP: {ip}"],
                    recommendations=["May indicate internal relay or header manipulation"],
                ))

        # Check for missing Message-ID (common in spam/phishing)
        message_id = headers.get("Message-ID", "") or headers.get("message-id", "")
        if not message_id:
            findings.append(Finding(
                rule_id="HEADER-004",
                name="Missing Message-ID",
                description="Email lacks Message-ID header - common in bulk/automated mail",
                severity=Severity.LOW,
                confidence=0.5,
                evidence=["No Message-ID header found"],
                recommendations=["Legitimate emails typically have Message-ID headers"],
            ))

        # Check Return-Path vs From mismatch
        return_path = headers.get("Return-Path", "") or headers.get("return-path", "")
        from_header = headers.get("From", "") or headers.get("from", "")

        if return_path and from_header:
            rp_domain = re.search(r'@([\w\.-]+)', return_path)
            from_domain = re.search(r'@([\w\.-]+)', from_header)

            if rp_domain and from_domain:
                if rp_domain.group(1).lower() != from_domain.group(1).lower():
                    findings.append(Finding(
                        rule_id="HEADER-005",
                        name="Return-Path domain mismatch",
                        description="Return-Path domain differs from From domain",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        evidence=[
                            f"Return-Path domain: {rp_domain.group(1)}",
                            f"From domain: {from_domain.group(1)}",
                        ],
                        mitre_techniques=["T1566.001"],
                        recommendations=["Bounces will go to different domain - potential phishing indicator"],
                    ))

        return findings




