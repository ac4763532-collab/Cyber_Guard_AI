"""
CyberGuard AI - Email Security Agent (Refactored)

Specialized agent for detecting phishing, malicious content,
and suspicious patterns in emails.

Key Improvements:
1. Proper URL classification (NORMAL, TRACKING, CDN, SHORTENER, etc.)
2. Correct TLD detection using public suffix approach
3. Separate BRAND_MENTION vs BRAND_IMPERSONATION
4. Artifacts vs IOCs distinction
5. Proper authentication status (PASS/FAIL/UNKNOWN)
6. Weighted risk scoring with positive signals
7. Clear verdicts (BENIGN, SUSPICIOUS, PHISHING, MALICIOUS, UNKNOWN)
"""

import re
import hashlib
from typing import Any
from urllib.parse import urlparse
from datetime import datetime, timezone

from app.agents.base import (
    BaseAgent,
    AgentType,
    AgentStatus,
    AgentResult,
    Finding,
    Severity,
)
from app.ml.classifier import predict as ml_predict, load_models, get_model_status
from app.services.email_auth.service import authenticate_email
from app.services.url_analysis.service import analyze_urls as analyze_urls_safe

from app.core.email_enums import (
    URLCategory,
    AnalysisStatus,
    Verdict,
    BrandDetectionType,
    AuthResult,
    URL_SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    IMPERSONATED_BRANDS,
    LEGITIMATE_BRAND_DOMAINS,
)
from app.core.domain_utils import (
    extract_domain_info,
    classify_url,
    is_suspicious_tld,
    is_legitimate_brand_domain,
    get_domain_brand,
    is_url_shortener,
)


# =============================================================================
# Constants
# =============================================================================

# Free email providers (not necessarily suspicious, just noted)
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "yandex.com", "gmx.com", "zoho.com",
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

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".cab", ".arj", ".lzh", ".ace",
}

# Disk image extensions
DISK_IMAGE_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".vhdx", ".dmg",
}

# Urgency phrases (social engineering)
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
    r"sign[\s-]?in\s+to\s+(your\s+)?account",
    r"log[\s-]?in\s+immediately",
]

# Authentication result mappings with risk weights
AUTH_RISK_WEIGHTS = {
    # SPF
    "spf": {
        "pass": (-5, Severity.INFO, "SPF passed - sender IP authorized"),
        "fail": (20, Severity.HIGH, "SPF failed - sender IP not authorized"),
        "softfail": (10, Severity.MEDIUM, "SPF soft fail"),
        "neutral": (0, Severity.LOW, "SPF neutral"),
        "none": (5, Severity.LOW, "No SPF record"),
        "temperror": (2, Severity.LOW, "SPF temporary error"),
        "permerror": (5, Severity.MEDIUM, "SPF permanent error"),
    },
    # DKIM
    "dkim": {
        "pass": (-5, Severity.INFO, "DKIM signature valid"),
        "fail": (20, Severity.HIGH, "DKIM signature invalid"),
        "neutral": (0, Severity.LOW, "DKIM neutral"),
        "none": (5, Severity.LOW, "No DKIM signature"),
        "temperror": (2, Severity.LOW, "DKIM temporary error"),
        "permerror": (5, Severity.MEDIUM, "DKIM permanent error"),
    },
    # DMARC
    "dmarc": {
        "pass": (-10, Severity.INFO, "DMARC passed"),
        "fail": (25, Severity.CRITICAL, "DMARC failed"),
        "none": (8, Severity.MEDIUM, "No DMARC policy"),
        "quarantine": (15, Severity.HIGH, "DMARC quarantine triggered"),
        "reject": (25, Severity.CRITICAL, "DMARC reject policy"),
    },
}


# =============================================================================
# Email Security Agent
# =============================================================================

class EmailAgent(BaseAgent):
    """
    Email Security Agent for phishing and malicious email detection.

    Produces structured analysis with:
    - Proper URL categorization
    - Artifacts vs IOCs separation
    - Weighted risk scoring
    - Clear verdicts
    """

    agent_type = AgentType.EMAIL
    agent_name = "Email Security Agent"
    agent_version = "2.0.0"  # Major version bump for refactor

    def __init__(self):
        super().__init__()
        self._status = AgentStatus.ONLINE

        # Initialize ML classifier.
        # If the ML model cannot be loaded, rule-based detection
        # continues to work normally.
        try:
            self._ml_available = load_models()
            self._ml_status = get_model_status()
        except Exception as e:
            self._ml_available = False
            self._ml_status = {
                "loaded": False,
                "model": "tfidf_logistic_regression",
                "error": str(e),
            }

    async def validate(self, data: dict[str, Any]) -> tuple[bool, str | None]:
        """Validate email data."""
        # At minimum need subject or body
        if not data.get("subject") and not data.get("body"):
            return False, "Subject or body is required"
        return True, None

    async def analyze(self, data: dict[str, Any]) -> AgentResult:
        """Analyze email for security threats."""
        findings: list[Finding] = []
        artifacts: dict[str, list[str]] = {
            "urls": [],
            "domains": [],
            "ips": [],
            "emails": [],
            "hashes": [],
        }
        iocs: list[str] = []  # Only confirmed/suspicious indicators
        trust_signals: list[str] = []
        recommendations: list[str] = []

        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        headers = data.get("headers") or {}
        urls = data.get("urls") or []
        attachments = data.get("attachments") or []

        # Extract URLs from body if not provided
        if not urls:
            urls = self._extract_urls(body)

        # Store URLs as artifacts (NOT IOCs by default)
        artifacts["urls"] = list(set(urls))

        # Run all detection methods
        sender_findings, sender_artifacts, sender_iocs = self._analyze_sender(sender, headers)
        findings.extend(sender_findings)
        artifacts["domains"].extend(sender_artifacts.get("domains", []))
        artifacts["emails"].extend(sender_artifacts.get("emails", []))
        iocs.extend(sender_iocs)

        findings.extend(self._check_reply_to_mismatch(sender, headers))

        url_findings, url_trust_signals = self._analyze_urls_v2(urls)
        findings.extend(url_findings)
        trust_signals.extend(url_trust_signals)

        # Enhanced Safe Link Analysis
        # Runs URL expansion, local pattern checks, Safe Browsing, and VirusTotal.
        if urls:
            try:
                safe_link_results = await analyze_urls_safe(urls)
                safe_link_findings = self._build_safe_link_findings(safe_link_results)
                findings.extend(safe_link_findings)
            except Exception:
                # Safe Link Analysis must never break email analysis.
                safe_link_results = []

        # Extract domains from URLs as artifacts
        for url in urls:
            domain_info = extract_domain_info(url)
            if domain_info and not domain_info.is_ip:
                artifacts["domains"].append(domain_info.registered_domain)
            elif domain_info and domain_info.is_ip:
                artifacts["ips"].append(domain_info.full_domain)

        findings.extend(self._analyze_content(subject, body))
        findings.extend(self._analyze_attachments(attachments))

        # Brand analysis with proper MENTION vs IMPERSONATION separation
        brand_findings = self._analyze_brand_context(sender, subject, body)
        findings.extend(brand_findings)

	    # Email authentication analysis
        # Priority:
        # 1. Authentication data supplied by Gmail/API
        # 2. Authentication-Results headers
        # 3. Direct SPF/DKIM/DMARC verification
        auth_results = data.get("authentication") or {}
        raw_email = data.get("raw_email")

        try:
            unified_auth = authenticate_email(
                sender=sender,
                headers=headers,
                raw_email=raw_email,
                authentication=auth_results,
            )

            # Convert unified authentication results into the structure
            # already expected by _analyze_authentication().
            auth_results = {
                "spf": unified_auth.get("spf", {}),
                "dkim": unified_auth.get("dkim", {}),
                "dmarc": unified_auth.get("dmarc", {}),
            }

        except Exception:
            # Authentication failure must never break email analysis.
            auth_results = data.get("authentication") or {}

        auth_findings, auth_trust = self._analyze_authentication(
            auth_results,
            headers,
        )
        findings.extend(auth_findings)
        trust_signals.extend(auth_trust)


        # Header chain analysis
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

        # Promote suspicious artifacts to IOCs based on findings
        iocs.extend(self._promote_to_iocs(findings, artifacts))

        # Deduplicate
        artifacts = {k: list(set(v)) for k, v in artifacts.items()}
        iocs = list(set(iocs))

        # Calculate verdict and risk score with weighted evidence
        verdict, severity, confidence, risk_score = self._calculate_verdict(
            findings, trust_signals
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, verdict.value)

        # Build summary
        summary = self._build_summary(verdict, findings, iocs, trust_signals)

        # For backward compatibility, use indicators field for IOCs
        result = self._create_result(
            classification=verdict.value,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            indicators=iocs,
            recommendations=recommendations,
        )

        # Add extra data as metadata on the result object
        # Since AgentResult doesn't have extra_data, we store in individual findings metadata
        # Or we can access it via the artifacts dict we built
        # For now, the artifacts and trust_signals are available via the findings evidence

        return result

    # -------------------------------------------------------------------------
    # Sender Analysis
    # -------------------------------------------------------------------------

    def _analyze_sender(
        self, sender: str, headers: dict
    ) -> tuple[list[Finding], dict[str, list[str]], list[str]]:
        """
        Analyze sender for suspicious characteristics.

        Returns:
            Tuple of (findings, artifacts, iocs)
        """
        findings = []
        artifacts: dict[str, list[str]] = {"domains": [], "emails": []}
        iocs = []

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
            return findings, artifacts, iocs

        email = email_match.group().lower()
        artifacts["emails"].append(email)

        domain_info = extract_domain_info(email)
        if not domain_info:
            return findings, artifacts, iocs

        domain = domain_info.registered_domain
        artifacts["domains"].append(domain)

        # Check for free email provider (informational only, not a finding)
        # This is just noted, not flagged as suspicious

        # Check for suspicious TLD
        if is_suspicious_tld(domain_info):
            findings.append(Finding(
                rule_id="EMAIL-003",
                name="Suspicious sender TLD",
                description=f"Sender uses frequently-abused TLD: .{domain_info.public_suffix}",
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence=[f"Domain: {domain}"],
                mitre_techniques=["T1566.001"],
                recommendations=["Treat with caution, verify sender identity"],
            ))
            iocs.append(domain)

        return findings, artifacts, iocs

    def _check_reply_to_mismatch(self, sender: str, headers: dict) -> list[Finding]:
        """Check for Reply-To header mismatch (BEC indicator)."""
        findings = []

        reply_to = headers.get("Reply-To", "") or headers.get("reply-to", "")
        if not reply_to:
            return findings

        sender_info = extract_domain_info(sender)
        reply_info = extract_domain_info(reply_to)

        if sender_info and reply_info and not sender_info.is_ip and not reply_info.is_ip:
            # Only flag if registered domains are different
            # (subdomains of the same domain are OK)
            sender_registered = sender_info.registered_domain.lower()
            reply_registered = reply_info.registered_domain.lower()

            if sender_registered != reply_registered:
                findings.append(Finding(
                    rule_id="EMAIL-005",
                    name="Reply-To domain mismatch",
                    description="Reply-To header points to different domain than sender",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence=[
                        f"Sender domain: {sender_registered}",
                        f"Reply-To domain: {reply_registered}",
                    ],
                    mitre_techniques=["T1566.001"],
                    recommendations=[
                        "Do not reply to this email",
                        "Verify sender through official channels",
                    ],
                ))

        return findings

    # -------------------------------------------------------------------------
    # URL Analysis (v2 - with proper categorization)
    # -------------------------------------------------------------------------

    def _analyze_urls_v2(self, urls: list[str]) -> tuple[list[Finding], list[str]]:
        """
        Analyze URLs with proper categorization.

        Does NOT flag:
        - CDN URLs as suspicious
        - Tracking URLs as IOCs
        - Normal URLs with query parameters as shorteners

        Returns:
            Tuple of (findings, trust_signals)
        """
        findings = []
        trust_signals = []
        seen_domains = set()

        for url in urls:
            category, reasons = classify_url(url)
            domain_info = extract_domain_info(url)

            if not domain_info:
                continue

            domain = domain_info.registered_domain if not domain_info.is_ip else domain_info.full_domain

            # Avoid duplicate findings for same domain
            finding_key = f"{category}:{domain}"
            if finding_key in seen_domains:
                continue
            seen_domains.add(finding_key)

            if category == URLCategory.MALICIOUS:
                findings.append(Finding(
                    rule_id="URL-MALICIOUS",
                    name="Malicious URL structure",
                    description=reasons[0] if reasons else "Malicious URL detected",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence=[f"URL: {url[:200]}"] + reasons,
                    mitre_techniques=["T1566.002"],
                    recommendations=["Do not click - malicious URL structure"],
                ))

            elif category == URLCategory.SHORTENER:
                findings.append(Finding(
                    rule_id="URL-001",
                    name="URL shortener detected",
                    description=f"Email contains shortened URL from {domain}",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    evidence=[f"URL: {url[:200]}"] + reasons,
                    mitre_techniques=["T1566.002"],
                    recommendations=["Expand URL before clicking to verify destination"],
                ))

            elif category == URLCategory.SUSPICIOUS:
                if domain_info.is_ip:
                    findings.append(Finding(
                        rule_id="URL-002",
                        name="IP-based URL",
                        description="URL uses IP address instead of domain name",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence=[f"URL: {url[:200]}"],
                        mitre_techniques=["T1566.002"],
                        recommendations=["Do not click - IP-based URLs are rarely legitimate in emails"],
                    ))
                else:
                    findings.append(Finding(
                        rule_id="URL-003",
                        name="Suspicious URL",
                        description=reasons[0] if reasons else "URL has suspicious characteristics",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        evidence=[f"URL: {url[:200]}"] + reasons,
                        recommendations=["Verify URL is legitimate before clicking"],
                    ))

            elif category == URLCategory.TRACKING:
                # Not a finding - just informational
                trust_signals.append(f"Contains tracking link ({domain}) - common in newsletters")

            elif category == URLCategory.CDN:
                # Not a finding - positive signal
                trust_signals.append(f"Uses legitimate CDN ({domain})")

            elif category == URLCategory.UNSUBSCRIBE:
                # Positive signal - legitimate emails have unsubscribe links
                trust_signals.append("Contains unsubscribe link")

            elif category == URLCategory.AUTHENTICATION:
                # Note but don't flag - could be legitimate or phishing
                pass

            elif category == URLCategory.REDIRECT:
                # Note redirect URLs but don't automatically flag
                findings.append(Finding(
                    rule_id="URL-REDIRECT",
                    name="Redirect URL detected",
                    description="URL contains redirect parameter",
                    severity=Severity.LOW,
                    confidence=0.5,
                    evidence=[f"URL: {url[:200]}"],
                    recommendations=["Verify final destination before clicking"],
                ))

        return findings, trust_signals

    # -------------------------------------------------------------------------
    # Content Analysis
    # -------------------------------------------------------------------------

    def _analyze_content(self, subject: str, body: str) -> list[Finding]:
        """Analyze email content for social engineering indicators."""
        findings = []
        combined = f"{subject} {body}".lower()

        # Check for urgency phrases
        urgency_matches = []
        for pattern in URGENCY_PHRASES:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                urgency_matches.append(match.group(0))

        if urgency_matches:
            # Only flag if multiple urgency indicators
            if len(urgency_matches) >= 2:
                severity = Severity.HIGH if len(urgency_matches) >= 3 else Severity.MEDIUM
                findings.append(Finding(
                    rule_id="CONTENT-001",
                    name="Urgency language detected",
                    description=f"Email uses multiple urgency tactics ({len(urgency_matches)} patterns)",
                    severity=severity,
                    confidence=min(0.4 + len(urgency_matches) * 0.15, 0.85),
                    evidence=[f"Matched: {m}" for m in urgency_matches[:5]],
                    mitre_techniques=["T1566.001"],
                    recommendations=["Verify urgency through official channels before acting"],
                ))

        # Check for credential request phrases
        credential_matches = []
        for pattern in CREDENTIAL_PHRASES:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                credential_matches.append(match.group(0))

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

    # -------------------------------------------------------------------------
    # Attachment Analysis
    # -------------------------------------------------------------------------

    def _analyze_attachments(self, attachments: list[dict]) -> list[Finding]:
        """Analyze attachment metadata for suspicious files."""
        findings = []

        for attachment in attachments:
            filename = attachment.get("filename", "").lower()
            mime_type = attachment.get("mime_type", "").lower()

            if not filename:
                continue

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
                        ],
                    ))
                    break

            # Check for double extension trick
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
                            recommendations=["Do not open - malware distribution technique"],
                        ))

            # Check for disk images
            if any(filename.endswith(ext) for ext in DISK_IMAGE_EXTENSIONS):
                findings.append(Finding(
                    rule_id="ATTACH-005",
                    name="Disk image attachment",
                    description="Email contains disk image file - used for malware delivery",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    evidence=[f"Filename: {filename}"],
                    mitre_techniques=["T1566.001", "T1553.005"],
                    recommendations=["Disk images can bypass security controls"],
                ))

        return findings

    # -------------------------------------------------------------------------
    # Brand Analysis (MENTION vs IMPERSONATION)
    # -------------------------------------------------------------------------

    def _analyze_brand_context(self, sender: str, subject: str, body: str) -> list[Finding]:
        """
        Analyze brand mentions with proper context.

        Distinguishes between:
        - BRAND_MENTION: Brand mentioned but sender is legitimate
        - BRAND_IMPERSONATION: Brand mentioned with evidence of impersonation
        """
        findings = []
        combined = f"{subject} {body}".lower()
        sender_lower = sender.lower()

        sender_domain_info = extract_domain_info(sender)
        sender_domain = sender_domain_info.registered_domain if sender_domain_info and not sender_domain_info.is_ip else ""

        for brand in IMPERSONATED_BRANDS:
            if brand not in combined:
                continue

            # Check if sender is legitimate for this brand
            if is_legitimate_brand_domain(sender_domain, brand):
                # Legitimate sender - no finding
                continue

            # Brand mentioned but sender doesn't match
            # Now check for IMPERSONATION indicators (not just mention)
            impersonation_indicators = []

            # 1. Brand in sender domain but not legitimate (typosquatting)
            if brand in sender_domain and not is_legitimate_brand_domain(sender_domain, brand):
                impersonation_indicators.append(f"Sender domain '{sender_domain}' mimics {brand}")

            # 2. Credential request + brand mention = likely impersonation
            has_credential_request = any(
                re.search(p, combined, re.IGNORECASE) for p in CREDENTIAL_PHRASES
            )
            if has_credential_request:
                impersonation_indicators.append(f"Requests credentials while mentioning {brand}")

            # 3. Urgency + brand mention = suspicious
            has_urgency = sum(1 for p in URGENCY_PHRASES if re.search(p, combined, re.IGNORECASE)) >= 2
            if has_urgency:
                impersonation_indicators.append(f"Urgency language while mentioning {brand}")

            # 4. Account/security alert language
            alert_patterns = [
                r"your\s+" + brand + r"\s+account",
                r"account\s+(has\s+been|is|was)\s+(suspended|blocked|locked|compromised)",
                r"verify\s+your\s+" + brand,
                r"unusual\s+activity.*" + brand,
            ]
            for pattern in alert_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    impersonation_indicators.append(f"Account alert language targeting {brand}")
                    break

            if impersonation_indicators:
                # This is IMPERSONATION
                findings.append(Finding(
                    rule_id="BRAND-002",
                    name=f"Potential {brand.title()} impersonation",
                    description=f"Email impersonates {brand.title()} with deceptive indicators",
                    severity=Severity.HIGH,
                    confidence=min(0.5 + len(impersonation_indicators) * 0.15, 0.9),
                    evidence=[f"Sender: {sender}"] + impersonation_indicators,
                    mitre_techniques=["T1566.001", "T1036"],
                    recommendations=[
                        f"Do not trust this email as {brand.title()}",
                        f"Navigate to {brand}.com directly if action needed",
                    ],
                ))
            # If no impersonation indicators, it's just a mention - don't flag
            # (e.g., newsletter discussing Microsoft, forum email mentioning Google)

        return findings

    # -------------------------------------------------------------------------
    # Authentication Analysis
    # -------------------------------------------------------------------------

    def _analyze_authentication(
        self, auth_results: dict, headers: dict
    ) -> tuple[list[Finding], list[str]]:
        """
        Analyze email authentication (SPF, DKIM, DMARC).

        Returns:
            Tuple of (findings, trust_signals)
        """
        findings = []
        trust_signals = []

        for auth_type in ["spf", "dkim", "dmarc"]:
            result = self._get_auth_result(auth_results, headers, auth_type)

            if result == AuthResult.UNKNOWN.value or result == "":
                continue

            weights = AUTH_RISK_WEIGHTS.get(auth_type, {})
            if result in weights:
                risk_weight, severity, description = weights[result]

                if auth_type == "dmarc":
                    dmarc_data = auth_results.get("dmarc", {})

                    if isinstance(dmarc_data, dict):
                        policy = str(
                            dmarc_data.get("policy", "")
                        ).lower()

                        if result == "fail" and policy == "none":
                            risk_weight = 8
                            severity = Severity.MEDIUM
                            description = (
                                "DMARC authentication failed, "
                                "but the domain policy is p=none."
                            )

                if auth_type == "dmarc":
                    dmarc_data = auth_results.get("dmarc", {})

                    if isinstance(dmarc_data, dict):
                        policy = str(
                            dmarc_data.get("policy", "")
                        ).lower()

                        if result == "fail" and policy == "none":
                            risk_weight = 8
                            severity = Severity.MEDIUM
                            description = (
                                "DMARC authentication failed, "
                                "but the domain policy is p=none."
                            )

                if risk_weight < 0:
                    # Positive signal
                    trust_signals.append(f"{auth_type.upper()} {result}")
                elif severity != Severity.INFO:
                    findings.append(Finding(
                        rule_id=f"AUTH-{auth_type.upper()}-001",
                        name=f"{auth_type.upper()} {result.upper()}",
                        description=description,
                        severity=severity,
                        confidence=0.9 if auth_type == "dmarc" else 0.85,
                        evidence=[f"{auth_type.upper()} result: {result}"],
                        mitre_techniques=["T1566.001"] if severity in (Severity.HIGH, Severity.CRITICAL) else [],
                        recommendations=[
                            "Verify sender through alternative channels",
                        ] if severity != Severity.INFO else [],
                    ))

        return findings, trust_signals

    def _get_auth_result(self, auth_results: dict, headers: dict, auth_type: str) -> str:
        """Extract authentication result from auth_results or headers."""
        value = auth_results.get(auth_type, "")

        # Handle both dict format {"result": "pass"} and string format "pass"
        if isinstance(value, dict):
            result = value.get("result", "").lower()
        else:
            result = str(value).lower() if value else ""

        if not result or result == "unknown":
            # Try to parse from Authentication-Results header
            auth_header = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
            match = re.search(rf'{auth_type}=(\w+)', auth_header, re.IGNORECASE)
            if match:
                result = match.group(1).lower()

        return result

    # -------------------------------------------------------------------------
    # Header Chain Analysis
    # -------------------------------------------------------------------------

    def _analyze_header_chain(self, headers: dict) -> list[Finding]:
        """Analyze email header chain for anomalies."""
        findings = []

        # Get Received headers
        received_headers = headers.get("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]

        # Check for excessive hops
        if len(received_headers) > 10:
            findings.append(Finding(
                rule_id="HEADER-001",
                name="Excessive mail hops",
                description=f"Email passed through {len(received_headers)} servers",
                severity=Severity.LOW,
                confidence=0.6,
                evidence=[f"Number of Received headers: {len(received_headers)}"],
                recommendations=["May indicate mail relay abuse"],
            ))

        # Check Return-Path vs From mismatch
        return_path = headers.get("Return-Path", "") or headers.get("return-path", "")
        from_header = headers.get("From", "") or headers.get("from", "")

        if return_path and from_header:
            rp_info = extract_domain_info(return_path)
            from_info = extract_domain_info(from_header)

            if rp_info and from_info and not rp_info.is_ip and not from_info.is_ip:
                if rp_info.registered_domain != from_info.registered_domain:
                    findings.append(Finding(
                        rule_id="HEADER-005",
                        name="Return-Path domain mismatch",
                        description="Return-Path domain differs from From domain",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        evidence=[
                            f"Return-Path domain: {rp_info.registered_domain}",
                            f"From domain: {from_info.registered_domain}",
                        ],
                        mitre_techniques=["T1566.001"],
                        recommendations=["Bounces will go to different domain"],
                    ))

        return findings

    # -------------------------------------------------------------------------
    # IOC Promotion
    # -------------------------------------------------------------------------

    def _promote_to_iocs(self, findings: list[Finding], artifacts: dict[str, list[str]]) -> list[str]:
        """
        Promote artifacts to IOCs for threat intelligence lookup.

        Strategy:
        - Always include IPs (always worth checking)
        - Always include file hashes (always worth checking)
        - Include domains/URLs from suspicious/malicious findings
        - Include external domains (non-CDN, non-tracking) for lookup
        """
        iocs = set()  # Use set to avoid duplicates

        # Always include IPs - they're always worth checking
        for ip in artifacts.get("ips", []):
            if ip and len(ip) < 50:
                iocs.add(ip)

        # Always include file hashes - they're always worth checking
        for file_hash in artifacts.get("hashes", []):
            if file_hash and len(file_hash) in (32, 40, 64):  # MD5, SHA1, SHA256
                iocs.add(file_hash)

        # Include domains/URLs from findings evidence
        for finding in findings:
            if finding.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM):
                for evidence in finding.evidence:
                    # Extract domain/URL from evidence
                    if "Domain:" in evidence or "URL:" in evidence:
                        parts = evidence.split(":", 1)
                        if len(parts) > 1:
                            value = parts[1].strip()
                            if value and len(value) < 200:
                                iocs.add(value)

        # Include suspicious/external domains for threat intel enrichment
        # Skip common CDN/tracking domains that would clutter results
        skip_domains = {
            "google.com", "googleapis.com", "gstatic.com",
            "gmail.com", "googlemail.com",  # Email providers
            "facebook.com", "fbcdn.net",
            "twitter.com", "twimg.com", "x.com",
            "linkedin.com", "licdn.com",
            "microsoft.com", "office.com", "outlook.com", "hotmail.com", "live.com",
            "apple.com", "icloud.com",
            "amazon.com", "amazonaws.com", "cloudfront.net",
            "cloudflare.com", "cloudflare-dns.com",
            "akamai.net", "akamaized.net",
            "doubleclick.net", "googlesyndication.com",
            "yahoo.com", "ymail.com",  # Yahoo
        }

        for domain in artifacts.get("domains", []):
            if domain and len(domain) < 100:
                # Skip known safe/noisy domains
                domain_lower = domain.lower()
                if not any(domain_lower.endswith(f".{skip}") or domain_lower == skip for skip in skip_domains):
                    iocs.add(domain)

        # Include URLs that look suspicious (limit to avoid noise)
        suspicious_url_count = 0
        for url in artifacts.get("urls", []):
            if suspicious_url_count >= 5:  # Limit URL lookups
                break
            if url and len(url) < 500:
                # Prioritize non-standard URLs
                url_lower = url.lower()
                if not any(safe in url_lower for safe in ["google.com", "microsoft.com", "apple.com"]):
                    iocs.add(url)
                    suspicious_url_count += 1

        return list(iocs)[:20]  # Limit to 20 IOCs max for API efficiency

    # -------------------------------------------------------------------------
    # Verdict Calculation
    # -------------------------------------------------------------------------

    def _calculate_verdict(
        self, findings: list[Finding], trust_signals: list[str]
    ) -> tuple[Verdict, Severity, float, int]:
        """
        Calculate verdict with weighted evidence and trust signals.

        Trust signals can reduce risk score.
        """
        if not findings:
            # No findings + trust signals = confident benign
            confidence = min(0.7 + len(trust_signals) * 0.05, 0.95)
            return Verdict.BENIGN, Severity.INFO, confidence, 5

        # Count by severity
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        # Calculate base risk score
        risk_score = (
            critical_count * 30 +
            high_count * 15 +
            medium_count * 7 +
            low_count * 2
        )

        # Apply trust signal discounts (up to -20 points)
        trust_discount = min(len(trust_signals) * 5, 20)
        risk_score = max(0, risk_score - trust_discount)

        # Cap at 100
        risk_score = min(100, risk_score)

        # Determine verdict
        if critical_count > 0:
            # Check if it's phishing-specific (impersonation, credentials)
            has_phishing_indicators = any(
                "impersonation" in f.name.lower() or "credential" in f.name.lower()
                for f in findings if f.severity == Severity.CRITICAL
            )
            verdict = Verdict.PHISHING if has_phishing_indicators else Verdict.MALICIOUS
            severity = Severity.CRITICAL
            confidence = min(0.7 + critical_count * 0.1, 0.95)
        elif high_count >= 2 or risk_score >= 50:
            verdict = Verdict.PHISHING
            severity = Severity.HIGH
            confidence = min(0.6 + high_count * 0.1, 0.9)
        elif high_count > 0 or medium_count >= 2 or risk_score >= 25:
            verdict = Verdict.SUSPICIOUS
            severity = Severity.MEDIUM
            confidence = min(0.5 + (high_count + medium_count) * 0.1, 0.8)
        elif medium_count > 0 or low_count > 1:
            verdict = Verdict.SUSPICIOUS
            severity = Severity.LOW
            confidence = 0.5
        else:
            verdict = Verdict.BENIGN
            severity = Severity.INFO
            confidence = 0.7

        return verdict, severity, confidence, risk_score

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _extract_urls(self, text: str) -> list[str]:
        """Extract URLs from text."""
        url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))

    def _generate_recommendations(self, findings: list[Finding], verdict: str) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        if verdict in ("phishing", "malicious"):
            recommendations.extend([
                "Do not click any links in this email",
                "Do not download or open any attachments",
                "Report this email to your security team",
                "Delete the email from your inbox",
            ])
        elif verdict == "suspicious":
            recommendations.extend([
                "Verify sender identity through official channels",
                "Do not enter credentials or sensitive information",
                "Contact the organization directly via known contact info",
            ])

        # Add unique recommendations from findings
        seen = set(recommendations)
        for finding in findings:
            for rec in finding.recommendations:
                if rec not in seen:
                    recommendations.append(rec)
                    seen.add(rec)

        return recommendations[:10]

    def _build_summary(
        self, verdict: Verdict, findings: list[Finding], iocs: list[str], trust_signals: list[str]
    ) -> str:
        """Build human-readable summary."""
        if verdict == Verdict.BENIGN:
            base = "No significant security threats detected."
            if trust_signals:
                base += f" Positive signals: {', '.join(trust_signals[:3])}."
            return base

        finding_names = [f.name for f in findings[:3]]
        summary = (
            f"Email classified as {verdict.value.upper()}. "
            f"Detected {len(findings)} indicator(s): {', '.join(finding_names)}"
        )
        if len(findings) > 3:
            summary += f" and {len(findings) - 3} more"
        summary += "."

        if iocs:
            summary += f" {len(iocs)} confirmed IOC(s) extracted."

        return summary



