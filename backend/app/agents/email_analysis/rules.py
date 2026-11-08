"""
CyberGuard AI — Email Analysis Detection Rules
============================================================================

Six deterministic detection rules for the Email Analysis Agent.

Rule interface
--------------
    evaluate(context: AgentContext, payload: dict) -> FindingSpec | None

The payload is the extracted email structure (see agent.py docstring).
Rules check payload fields defensively — missing fields → return None.

The 6 rules
-----------
    1. SpoofedAuthRule          (email.spoofed_auth)
    2. SuspiciousUrlRule        (email.suspicious_url)
    3. AttachmentAnomalyRule    (email.dangerous_attachment)
    4. SenderImpersonationRule  (email.sender_impersonation)
    5. PhishingLanguageRule     (email.phishing_language)
    6. ReplyToMismatchRule      (email.reply_to_mismatch)
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.agents.base import AgentContext
from app.models.enums import EventSeverity, FindingCategory


# ============================================================================
# FINDING SPEC (identical shape to log agent's — duplicated for isolation)
# ============================================================================

@dataclass(frozen=True)
class FindingSpec:
    rule_id: str
    title: str
    severity: EventSeverity
    category: FindingCategory
    confidence: float
    event_ids: list[uuid.UUID]
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str | None = None
    primary_event_id: uuid.UUID | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    dedup_hint: str | None = None

    def as_kwargs(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
            "event_ids": self.event_ids,
            "evidence": self.evidence,
            "description": self.description,
            "primary_event_id": self.primary_event_id,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
            "dedup_hint": self.dedup_hint,
        }


class BaseRule:
    name: str = ""

    def evaluate(
        self, context: AgentContext, payload: dict
    ) -> FindingSpec | None:
        raise NotImplementedError


# ============================================================================
# HELPERS
# ============================================================================

def _extract_email_address(raw: str | None) -> str | None:
    """Extract 'user@host' from '"Name" <user@host>' format."""
    if not raw or not isinstance(raw, str):
        return None
    match = re.search(r"<([^>]+)>", raw)
    if match:
        return match.group(1).strip().lower()
    raw = raw.strip().lower()
    return raw if "@" in raw else None


def _extract_domain(raw: str | None) -> str | None:
    addr = _extract_email_address(raw)
    if addr and "@" in addr:
        return addr.split("@", 1)[1]
    return None


def _extract_display_name(raw: str | None) -> str | None:
    """Extract display name from '"Name" <addr>' or 'Name <addr>'."""
    if not raw or not isinstance(raw, str):
        return None
    match = re.match(r'^\s*"?([^"<]+)"?\s*<', raw)
    if match:
        return match.group(1).strip().lower()
    return None


def _extract_urls(payload: dict) -> list[str]:
    """Return all URLs from payload['urls'], or extract from body fields."""
    urls: list[str] = []
    listed = payload.get("urls")
    if isinstance(listed, list):
        urls.extend(u for u in listed if isinstance(u, str) and u.strip())
    if not urls:
        for body_key in ("body_text", "body_html", "body"):
            body = payload.get(body_key)
            if isinstance(body, str):
                urls.extend(re.findall(r"https?://[^\s\"'<>]+", body))
    # Dedupe, keep order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _extract_domain_from_url(url: str) -> str | None:
    """Best-effort domain extraction — no urllib dependency for speed."""
    m = re.match(r"^https?://([^/:]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else None


# ============================================================================
# RULE 1 — SPF/DKIM/DMARC failure
# ============================================================================

class SpoofedAuthRule(BaseRule):
    """
    Fires when any of SPF, DKIM, or DMARC fails on the incoming email.

    Reads from ``payload['headers']['Authentication-Results']`` (standard
    Gmail/Outlook/Exchange header). Fails the whole message if ANY of the
    three protocols fails, with severity scaling by how many failed.

    MITRE: T1656 (Impersonation), T1585.002 (Email Accounts)
    """
    name = "email.spoofed_auth"

    _FAILURE_RE = re.compile(
        r"(spf|dkim|dmarc)\s*=\s*(fail|softfail|none|neutral|permerror|temperror)",
        re.IGNORECASE,
    )

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            return None
        auth_results = headers.get("Authentication-Results") or headers.get("authentication-results") or ""
        if not isinstance(auth_results, str) or not auth_results.strip():
            return None

        failures = [
            {"protocol": m.group(1).upper(), "result": m.group(2).lower()}
            for m in self._FAILURE_RE.finditer(auth_results)
        ]
        if not failures:
            return None

        # Confidence and severity by failure count
        count = len(failures)
        if count >= 2:
            severity = EventSeverity.HIGH
            confidence = 0.90
        else:
            severity = EventSeverity.MEDIUM
            confidence = 0.75

        protocols = sorted({f["protocol"] for f in failures})

        return FindingSpec(
            rule_id=self.name,
            title=f"Email authentication failed: {', '.join(protocols)}",
            severity=severity,
            category=FindingCategory.PHISHING,
            confidence=confidence,
            event_ids=[context.event.id],
            evidence={
                "failed_protocols": failures,
                "auth_results_header": auth_results[:500],
                "from_address": _extract_email_address(headers.get("From") or headers.get("from")),
            },
            description=(
                f"Email failed authentication for: {', '.join(protocols)}. "
                f"This is a strong indicator of spoofing or forwarding through "
                f"an unauthorized server."
            ),
            mitre_techniques=["T1656"],
            dedup_hint=f"from={headers.get('From') or 'unknown'}",
        )


# ============================================================================
# RULE 2 — Suspicious URL
# ============================================================================

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "rebrand.ly", "shorturl.at",
    "cutt.ly", "shorte.st", "tiny.cc", "rb.gy",
}

_SKETCHY_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".click", ".link", ".country",
    ".gq", ".tk", ".ml", ".cf", ".ga", ".work", ".date", ".review",
    ".loan", ".win", ".bid", ".stream", ".download", ".men",
    ".cam", ".rest", ".monster", ".quest", ".cyou", ".buzz",
}


class SuspiciousUrlRule(BaseRule):
    """
    Fires when the email body contains URLs that look suspicious:

        - Known URL shortener domains (bit.ly, tinyurl.com, ...)
        - IP-literal URLs (http://192.0.2.1/path)
        - Sketchy TLDs (.zip, .top, .xyz, ...)
        - Username-in-URL credential-harvesting pattern
          (https://paypal.com@attacker.com)

    Severity depends on how many distinct issues match.

    MITRE: T1566.002 (Phishing: Spearphishing Link)
    """
    name = "email.suspicious_url"

    def __init__(self, suspicious_tld_score: int = 40) -> None:
        # Reserved for future ML-score integration
        self._tld_score = suspicious_tld_score

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        urls = _extract_urls(payload)
        if not urls:
            return None

        issues: list[dict[str, Any]] = []
        for url in urls[:50]:  # cap to prevent payload amplification
            domain = _extract_domain_from_url(url)
            if not domain:
                continue

            if domain in _SHORTENER_DOMAINS:
                issues.append({"type": "url_shortener", "url": url, "domain": domain})
                continue
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
                issues.append({"type": "ip_literal", "url": url, "domain": domain})
                continue
            if any(domain.endswith(tld) for tld in _SKETCHY_TLDS):
                issues.append({"type": "sketchy_tld", "url": url, "domain": domain})
                continue
            # Credential-harvesting pattern: userinfo@host where userinfo looks like a domain
            if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
                issues.append({"type": "userinfo_trick", "url": url, "domain": domain})

        if not issues:
            return None

        types = sorted({i["type"] for i in issues})
        severity = EventSeverity.HIGH if len(issues) >= 3 else EventSeverity.MEDIUM
        confidence = min(0.95, 0.65 + 0.10 * len(issues))

        return FindingSpec(
            rule_id=self.name,
            title=f"Suspicious URL(s) in email ({len(issues)} issue(s))",
            severity=severity,
            category=FindingCategory.PHISHING,
            confidence=confidence,
            event_ids=[context.event.id],
            evidence={
                "issues": issues[:20],
                "issue_types": types,
                "total_urls": len(urls),
            },
            description=(
                f"Found {len(issues)} suspicious URL(s) in the email body: "
                + ", ".join(types)
                + "."
            ),
            mitre_techniques=["T1566.002"],
            dedup_hint=f"domains={','.join(sorted({i['domain'] for i in issues}))[:200]}",
        )


# ============================================================================
# RULE 3 — Dangerous attachment
# ============================================================================

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".msix", ".hta", ".cpl",
    ".jar", ".lnk", ".reg",
}

_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}

_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"}


class AttachmentAnomalyRule(BaseRule):
    """
    Fires when the email has attachments that are:

        - Dangerous executables (.exe, .scr, .bat, ...)
        - Macro-enabled documents (.docm, .xlsm, ...)
        - Double-extension disguises (invoice.pdf.exe)
        - Archives (potential payload delivery)
        - Oversized (configurable cap)

    MITRE: T1566.001 (Phishing: Spearphishing Attachment),
           T1204.002 (Malicious File)
    """
    name = "email.dangerous_attachment"

    def __init__(self, max_attachment_size_bytes: int = 26214400) -> None:
        self._max_size = max_attachment_size_bytes

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        attachments = payload.get("attachments") or []
        if not isinstance(attachments, list) or not attachments:
            return None

        findings: list[dict[str, Any]] = []
        for att in attachments:
            if not isinstance(att, dict):
                continue
            filename = str(att.get("filename") or "").lower()
            size = att.get("size_bytes") or 0
            try:
                size = int(size)
            except (TypeError, ValueError):
                size = 0

            reasons: list[str] = []

            # Dangerous extension (check final extension)
            if "." in filename:
                final_ext = "." + filename.rsplit(".", 1)[-1]
                if final_ext in _DANGEROUS_EXTENSIONS:
                    reasons.append(f"dangerous_extension:{final_ext}")

            # Double extension
            parts = filename.split(".")
            if len(parts) >= 3:
                prev_ext = "." + parts[-2]
                if prev_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx",
                                ".jpg", ".jpeg", ".png", ".txt", ".csv"):
                    reasons.append(f"double_extension:{prev_ext}{parts[-1] and '.' + parts[-1]}")

            # Macro-enabled
            if "." in filename:
                final_ext = "." + filename.rsplit(".", 1)[-1]
                if final_ext in _MACRO_EXTENSIONS:
                    reasons.append(f"macro_enabled:{final_ext}")

            # Archive
            if "." in filename:
                final_ext = "." + filename.rsplit(".", 1)[-1]
                if final_ext in _ARCHIVE_EXTENSIONS:
                    reasons.append(f"archive:{final_ext}")

            # Oversized
            if size > self._max_size:
                reasons.append(f"oversized:{size}")

            if reasons:
                findings.append({
                    "filename": filename,
                    "size_bytes": size,
                    "reasons": reasons,
                })

        if not findings:
            return None

        has_dangerous = any(
            any(r.startswith("dangerous_extension:") or r.startswith("double_extension:")
                for r in f["reasons"])
            for f in findings
        )
        severity = EventSeverity.HIGH if has_dangerous else EventSeverity.MEDIUM
        confidence = 0.90 if has_dangerous else 0.70

        return FindingSpec(
            rule_id=self.name,
            title=f"Suspicious email attachment ({len(findings)} flagged)",
            severity=severity,
            category=FindingCategory.PHISHING,
            confidence=confidence,
            event_ids=[context.event.id],
            evidence={
                "attachments": findings[:10],
                "total_attachments": len(attachments),
            },
            description=(
                f"{len(findings)} attachment(s) matched dangerous patterns "
                f"(executable, macro, or double-extension). Do not open."
            ),
            mitre_techniques=["T1566.001", "T1204.002"],
            dedup_hint=f"files={','.join(sorted({f['filename'] for f in findings}))[:200]}",
        )


# ============================================================================
# RULE 4 — Sender impersonation
# ============================================================================

class SenderImpersonationRule(BaseRule):
    """
    Fires when the display name of the sender is a known brand, but the
    email is not from that brand's domain.

    Example:
        From: "PayPal Support <support@paypal-secure.xyz>"
        → display name says PayPal, domain is not paypal.com → HIGH

    MITRE: T1656 (Impersonation)
    """
    name = "email.sender_impersonation"

    _KNOWN_BRANDS = {
        "paypal", "apple", "microsoft", "google", "amazon", "netflix",
        "facebook", "instagram", "linkedin", "twitter", "dropbox",
        "adobe", "docusign", "coinbase", "binance", "chase", "wellsfargo",
        "bankofamerica", "citibank", "hsbc", "barclays", "santander",
    }

    _KNOWN_BRAND_DOMAINS = {
        "paypal": ("paypal.com",),
        "apple": ("apple.com", "icloud.com"),
        "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com"),
        "google": ("google.com", "gmail.com"),
        "amazon": ("amazon.com", "amazon.in", "amazon.co.uk"),
        "netflix": ("netflix.com",),
        "facebook": ("facebook.com", "fb.com"),
        "linkedin": ("linkedin.com",),
        "dropbox": ("dropbox.com",),
        "adobe": ("adobe.com",),
        "docusign": ("docusign.com", "docusign.net"),
        "coinbase": ("coinbase.com",),
        "chase": ("chase.com",),
    }

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            return None

        from_header = headers.get("From") or headers.get("from")
        display = _extract_display_name(from_header)
        from_addr = _extract_email_address(from_header)
        from_domain = _extract_domain(from_header)

        if not display or not from_domain:
            return None

        display_lower = display.lower()
        matched_brand = None
        for brand in self._KNOWN_BRANDS:
            if brand in display_lower:
                matched_brand = brand
                break

        if not matched_brand:
            return None

        allowed_domains = self._KNOWN_BRAND_DOMAINS.get(matched_brand, ())
        if not allowed_domains:
            # We know the brand but don't have a domain list — can't verify
            return None

        is_legitimate = any(
            from_domain == d or from_domain.endswith("." + d)
            for d in allowed_domains
        )
        if is_legitimate:
            return None

        return FindingSpec(
            rule_id=self.name,
            title=f"Spoofed {matched_brand.title()} sender",
            severity=EventSeverity.HIGH,
            category=FindingCategory.PHISHING,
            confidence=0.88,
            event_ids=[context.event.id],
            evidence={
                "brand": matched_brand,
                "display_name": display,
                "from_address": from_addr,
                "from_domain": from_domain,
                "expected_domains": list(allowed_domains),
            },
            description=(
                f"Display name '{display}' references {matched_brand.title()} "
                f"but sender domain '{from_domain}' is not one of "
                f"{', '.join(allowed_domains)}."
            ),
            mitre_techniques=["T1656"],
            dedup_hint=f"brand={matched_brand}|domain={from_domain}",
        )


# ============================================================================
# RULE 5 — Phishing language
# ============================================================================

class PhishingLanguageRule(BaseRule):
    """
    Fires when the email body contains classic phishing-language signals:

        - Urgency ("urgent", "within 24 hours", "act now")
        - Credential requests ("verify your account", "confirm password")
        - Financial lures ("wire transfer", "you've won", "claim refund")
        - Threat language ("suspended", "unlock your account", "avoid")

    Confidence scales with how many categories matched.

    MITRE: T1566.002 (Spearphishing Link)
    """
    name = "email.phishing_language"

    _CATEGORIES = {
        "urgency": [
            "urgent", "immediate action", "act now", "within 24 hours",
            "within 48 hours", "expire", "last chance", "final notice",
            "time-sensitive", "asap",
        ],
        "credential": [
            "verify your account", "confirm your identity",
            "confirm your password", "click to verify",
            "update your payment", "re-enter your", "validate your account",
            "unlock your account", "reactivate your account",
        ],
        "financial": [
            "wire transfer", "you've won", "you have won", "claim your refund",
            "tax refund", "inheritance", "unclaimed funds", "bank details",
            "gift card", "bitcoin", "cryptocurrency payment",
        ],
        "threat": [
            "account will be suspended", "account has been suspended",
            "avoid suspension", "failure to respond", "legal action",
            "unauthorized access", "someone has accessed",
        ],
    }

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        body_parts: list[str] = []
        for key in ("body_text", "body", "body_html", "subject"):
            v = payload.get(key)
            if isinstance(v, str):
                body_parts.append(v)
        headers = payload.get("headers") or {}
        if isinstance(headers, dict):
            subj = headers.get("Subject") or headers.get("subject")
            if isinstance(subj, str):
                body_parts.append(subj)

        if not body_parts:
            return None

        body_lower = " ".join(body_parts).lower()
        if len(body_lower) < 20:
            return None

        matched: dict[str, list[str]] = {}
        for category, phrases in self._CATEGORIES.items():
            hits = [p for p in phrases if p in body_lower]
            if hits:
                matched[category] = hits

        if not matched:
            return None

        category_count = len(matched)
        severity = (
            EventSeverity.HIGH if category_count >= 3
            else EventSeverity.MEDIUM if category_count == 2
            else EventSeverity.LOW
        )
        confidence = min(0.90, 0.55 + 0.10 * category_count)

        return FindingSpec(
            rule_id=self.name,
            title=f"Phishing language signals ({category_count} categories)",
            severity=severity,
            category=FindingCategory.PHISHING,
            confidence=confidence,
            event_ids=[context.event.id],
            evidence={
                "matched_categories": {k: v[:5] for k, v in matched.items()},
                "category_count": category_count,
            },
            description=(
                f"Email body matched {category_count} phishing-language "
                f"categories: {', '.join(matched.keys())}."
            ),
            mitre_techniques=["T1566.002"],
            dedup_hint=f"categories={','.join(sorted(matched.keys()))}",
        )


# ============================================================================
# RULE 6 — Reply-To mismatch
# ============================================================================

class ReplyToMismatchRule(BaseRule):
    """
    Fires when the Reply-To header's domain doesn't match the From
    header's domain.

    This is a classic BEC (Business Email Compromise) signal — the
    attacker sets Reply-To to their own mailbox so replies go to them
    even though the From header looks legitimate.

    MITRE: T1656 (Impersonation), T1585.002 (Email Accounts)
    """
    name = "email.reply_to_mismatch"

    def evaluate(self, context: AgentContext, payload: dict) -> FindingSpec | None:
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            return None

        from_domain = _extract_domain(headers.get("From") or headers.get("from"))
        reply_domain = _extract_domain(
            headers.get("Reply-To") or headers.get("reply-to")
        )

        if not from_domain or not reply_domain:
            return None

        if from_domain == reply_domain:
            return None

        return FindingSpec(
            rule_id=self.name,
            title=f"Reply-To domain mismatch ({reply_domain})",
            severity=EventSeverity.MEDIUM,
            category=FindingCategory.PHISHING,
            confidence=0.70,
            event_ids=[context.event.id],
            evidence={
                "from_domain": from_domain,
                "reply_to_domain": reply_domain,
            },
            description=(
                f"From domain '{from_domain}' does not match Reply-To domain "
                f"'{reply_domain}'. Replies will be routed to an unexpected "
                f"address — a common business email compromise signal."
            ),
            mitre_techniques=["T1656", "T1585.002"],
            dedup_hint=f"from={from_domain}|reply={reply_domain}",
        )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "FindingSpec",
    "BaseRule",
    "SpoofedAuthRule",
    "SuspiciousUrlRule",
    "AttachmentAnomalyRule",
    "SenderImpersonationRule",
    "PhishingLanguageRule",
    "ReplyToMismatchRule",
]