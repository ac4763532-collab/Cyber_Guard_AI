"""
CyberGuard AI - Gmail Email Parser

Parses Gmail messages into a normalized format for security analysis.
Extracts headers, body, URLs, attachments, and authentication results.

This is a deterministic parser - no LLM involved.
Uses Python email libraries for reliable MIME parsing.
"""

import re
import base64
import hashlib
from datetime import datetime
from typing import Optional, Any
from urllib.parse import urlparse, unquote
from email import message_from_bytes
from email.utils import parsedate_to_datetime

import structlog
from pydantic import BaseModel, Field

from app.services.gmail.client import GmailMessage


logger = structlog.get_logger(__name__)


class EmailHeader(BaseModel):
    """Parsed email header."""
    name: str
    value: str
    raw: str = ""


class EmailAuthResult(BaseModel):
    """Email authentication result (SPF/DKIM/DMARC)."""
    spf: str = "unknown"  # pass, fail, softfail, neutral, none, unknown
    dkim: str = "unknown"
    dmarc: str = "unknown"
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""
    raw_results: str = ""


class ExtractedURL(BaseModel):
    """URL extracted from email."""
    url: str
    domain: str = ""
    scheme: str = ""
    display_text: str = ""  # What user sees (may differ from actual URL)
    is_shortened: bool = False
    is_ip_based: bool = False
    is_suspicious: bool = False
    location: str = "body"  # body, html, header


class ExtractedAttachment(BaseModel):
    """Attachment metadata."""
    filename: str
    mime_type: str = ""
    size: int = 0
    attachment_id: Optional[str] = None
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    is_dangerous_type: bool = False
    has_double_extension: bool = False


class ParsedEmail(BaseModel):
    """
    Fully parsed email ready for security analysis.

    This is the normalized format that feeds into the analysis pipeline.
    """

    # Source identification
    source: str = "gmail"
    gmail_message_id: str = ""
    gmail_thread_id: str = ""

    # Basic fields
    sender: str = ""
    sender_email: str = ""
    sender_name: str = ""
    recipients: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date: Optional[datetime] = None

    # Reply-To analysis (important for phishing detection)
    reply_to: str = ""
    reply_to_email: str = ""
    return_path: str = ""
    return_path_email: str = ""

    # Message IDs
    message_id: str = ""

    # Full headers (for deep analysis)
    headers: dict[str, str] = Field(default_factory=dict)

    # Authentication results
    authentication: EmailAuthResult = Field(default_factory=EmailAuthResult)

    # Received chain (for infrastructure analysis)
    received_chain: list[str] = Field(default_factory=list)

    # Body content
    body_plain: str = ""
    body_html: str = ""

    # Extracted URLs
    urls: list[ExtractedURL] = Field(default_factory=list)

    # Attachments
    attachments: list[ExtractedAttachment] = Field(default_factory=list)

    # Analysis metadata
    parsed_at: datetime = Field(default_factory=datetime.utcnow)
    has_html: bool = False
    has_attachments: bool = False
    url_count: int = 0


class GmailParser:
    """
    Gmail email parser for security analysis.

    Extracts and normalizes:
    - Headers (From, To, Reply-To, Return-Path, etc.)
    - Authentication results (SPF, DKIM, DMARC)
    - Received chain
    - Body (plain text and HTML)
    - URLs (with display text comparison)
    - Attachments (with hash calculation)
    """

    # URL shortener domains
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "tiny.cc", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at",
        "rebrand.ly", "bl.ink", "short.io", "v.gd", "clck.ru"
    }

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
        ".js", ".jse", ".ws", ".wsf", ".msc", ".msi", ".msp", ".hta",
        ".cpl", ".jar", ".ps1", ".psm1", ".reg", ".lnk", ".iso", ".img",
        ".dll", ".sys", ".drv", ".ocx", ".gadget", ".mde", ".adp",
    }

    def __init__(self):
        pass

    def parse(self, gmail_message: GmailMessage) -> ParsedEmail:
        """
        Parse Gmail message into normalized format.

        Args:
            gmail_message: GmailMessage from Gmail client

        Returns:
            ParsedEmail ready for security analysis
        """
        # Extract sender info
        sender_email, sender_name = self._parse_email_address(gmail_message.sender)

        # Extract reply-to
        reply_to_email, _ = self._parse_email_address(gmail_message.reply_to)

        # Extract return-path
        return_path_email, _ = self._parse_email_address(gmail_message.return_path)

        # Parse authentication results
        auth_results = self._parse_authentication(gmail_message.headers)

        # Extract received chain
        received_chain = self._extract_received_chain(gmail_message.headers)

        # Extract URLs from body
        urls = self._extract_urls(
            gmail_message.body_plain,
            gmail_message.body_html
        )

        # Parse attachments
        attachments = self._parse_attachments(gmail_message.attachments)

        parsed = ParsedEmail(
            source="gmail",
            gmail_message_id=gmail_message.id,
            gmail_thread_id=gmail_message.thread_id,
            sender=gmail_message.sender,
            sender_email=sender_email,
            sender_name=sender_name,
            recipients=gmail_message.to,
            cc=gmail_message.cc,
            subject=gmail_message.subject,
            date=gmail_message.date,
            reply_to=gmail_message.reply_to,
            reply_to_email=reply_to_email,
            return_path=gmail_message.return_path,
            return_path_email=return_path_email,
            message_id=gmail_message.message_id,
            headers=gmail_message.headers,
            authentication=auth_results,
            received_chain=received_chain,
            body_plain=gmail_message.body_plain,
            body_html=gmail_message.body_html,
            urls=urls,
            attachments=attachments,
            has_html=bool(gmail_message.body_html),
            has_attachments=bool(attachments),
            url_count=len(urls)
        )

        logger.info(
            "Email parsed",
            message_id=gmail_message.id,
            sender=sender_email,
            urls=len(urls),
            attachments=len(attachments)
        )

        return parsed

    def parse_raw(self, raw_mime: bytes, message_id: str = "", thread_id: str = "") -> ParsedEmail:
        """
        Parse raw MIME email.

        Args:
            raw_mime: Raw MIME message bytes
            message_id: Gmail message ID (optional)
            thread_id: Gmail thread ID (optional)

        Returns:
            ParsedEmail
        """
        msg = message_from_bytes(raw_mime)

        # Extract headers
        headers = {}
        for key in msg.keys():
            headers[key.lower()] = msg[key]

        # Extract sender
        sender = headers.get("from", "")
        sender_email, sender_name = self._parse_email_address(sender)

        # Extract recipients
        to_raw = headers.get("to", "")
        recipients = [addr.strip() for addr in to_raw.split(",") if addr.strip()]

        cc_raw = headers.get("cc", "")
        cc = [addr.strip() for addr in cc_raw.split(",") if addr.strip()]

        # Extract reply-to and return-path
        reply_to = headers.get("reply-to", "")
        reply_to_email, _ = self._parse_email_address(reply_to)

        return_path = headers.get("return-path", "")
        return_path_email, _ = self._parse_email_address(return_path)

        # Parse date
        date = None
        if "date" in headers:
            try:
                date = parsedate_to_datetime(headers["date"])
            except Exception:
                pass

        # Parse authentication
        auth_results = self._parse_authentication(headers)

        # Extract received chain
        received_chain = self._extract_received_chain(headers)

        # Extract body
        body_plain = ""
        body_html = ""
        attachments_raw = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    payload = part.get_payload(decode=True) or b""
                    attachments_raw.append({
                        "filename": part.get_filename() or "attachment",
                        "mime_type": content_type,
                        "size": len(payload),
                        "content": payload
                    })
                elif content_type == "text/plain" and not body_plain:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_plain = payload.decode("utf-8", errors="replace")
                elif content_type == "text/html" and not body_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode("utf-8", errors="replace")
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                if content_type == "text/html":
                    body_html = payload.decode("utf-8", errors="replace")
                else:
                    body_plain = payload.decode("utf-8", errors="replace")

        # Extract URLs
        urls = self._extract_urls(body_plain, body_html)

        # Parse attachments with hashes
        attachments = []
        for att in attachments_raw:
            content = att.get("content", b"")
            attachments.append(ExtractedAttachment(
                filename=att["filename"],
                mime_type=att["mime_type"],
                size=att["size"],
                sha256=hashlib.sha256(content).hexdigest() if content else "",
                sha1=hashlib.sha1(content).hexdigest() if content else "",
                md5=hashlib.md5(content).hexdigest() if content else "",
                is_dangerous_type=self._is_dangerous_extension(att["filename"]),
                has_double_extension=self._has_double_extension(att["filename"])
            ))

        return ParsedEmail(
            source="gmail",
            gmail_message_id=message_id,
            gmail_thread_id=thread_id,
            sender=sender,
            sender_email=sender_email,
            sender_name=sender_name,
            recipients=recipients,
            cc=cc,
            subject=headers.get("subject", ""),
            date=date,
            reply_to=reply_to,
            reply_to_email=reply_to_email,
            return_path=return_path,
            return_path_email=return_path_email,
            message_id=headers.get("message-id", ""),
            headers=headers,
            authentication=auth_results,
            received_chain=received_chain,
            body_plain=body_plain,
            body_html=body_html,
            urls=urls,
            attachments=attachments,
            has_html=bool(body_html),
            has_attachments=bool(attachments),
            url_count=len(urls)
        )

    def _parse_email_address(self, raw: str) -> tuple[str, str]:
        """
        Parse email address from various formats.

        Handles:
        - "Name <email@domain.com>"
        - "<email@domain.com>"
        - "email@domain.com"

        Returns:
            Tuple of (email, name)
        """
        if not raw:
            return "", ""

        raw = raw.strip()

        # Try "Name <email>" format
        match = re.match(r'^(.+?)\s*<([^>]+)>$', raw)
        if match:
            name = match.group(1).strip().strip('"\'')
            email = match.group(2).strip().lower()
            return email, name

        # Try "<email>" format
        match = re.match(r'^<([^>]+)>$', raw)
        if match:
            return match.group(1).strip().lower(), ""

        # Try plain email
        match = re.search(r'[\w\.\-\+]+@[\w\.\-]+\.\w+', raw)
        if match:
            return match.group().lower(), ""

        return "", ""

    def _parse_authentication(self, headers: dict[str, str]) -> EmailAuthResult:
        """
        Parse SPF, DKIM, DMARC from Authentication-Results header.

        Example header:
        Authentication-Results: mx.google.com;
            dkim=pass header.d=example.com;
            spf=pass (google.com: ...) smtp.mailfrom=example.com;
            dmarc=pass (p=REJECT) header.from=example.com
        """
        auth_results = headers.get("authentication-results", "")

        result = EmailAuthResult(raw_results=auth_results)

        if not auth_results:
            return result

        # Parse SPF
        spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_results, re.I)
        if spf_match:
            result.spf = spf_match.group(1).lower()

        # Parse DKIM
        dkim_match = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror)', auth_results, re.I)
        if dkim_match:
            result.dkim = dkim_match.group(1).lower()

        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(pass|fail|none|temperror|permerror)', auth_results, re.I)
        if dmarc_match:
            result.dmarc = dmarc_match.group(1).lower()

        # Extract domains
        spf_domain_match = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_results, re.I)
        if spf_domain_match:
            result.spf_domain = spf_domain_match.group(1)

        dkim_domain_match = re.search(r'header\.d=([^\s;]+)', auth_results, re.I)
        if dkim_domain_match:
            result.dkim_domain = dkim_domain_match.group(1)

        return result

    def _extract_received_chain(self, headers: dict[str, str]) -> list[str]:
        """Extract Received headers for infrastructure analysis."""
        received = []

        # Headers might have multiple "received" values
        # In our dict format, they may be combined or we need to handle specially
        for key, value in headers.items():
            if key.lower() == "received":
                # Split if combined with newlines
                parts = value.split("\n")
                received.extend([p.strip() for p in parts if p.strip()])

        return received

    def _extract_urls(self, body_plain: str, body_html: str) -> list[ExtractedURL]:
        """
        Extract all URLs from email body.

        Also compares display text vs actual href in HTML to detect deceptive links.
        """
        urls: list[ExtractedURL] = []
        seen_urls: set[str] = set()

        # Extract from plain text
        plain_urls = re.findall(
            r'https?://[^\s<>"\')\]\}]+|www\.[^\s<>"\')\]\}]+',
            body_plain
        )

        for url in plain_urls:
            if url not in seen_urls:
                seen_urls.add(url)
                urls.append(self._analyze_url(url, "", "plain"))

        # Extract from HTML with href and display text comparison
        if body_html:
            # Find all anchor tags
            href_pattern = re.compile(
                r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                re.IGNORECASE | re.DOTALL
            )

            for match in href_pattern.finditer(body_html):
                href = match.group(1)
                display = re.sub(r'<[^>]+>', '', match.group(2)).strip()

                if href not in seen_urls and href.startswith(('http://', 'https://')):
                    seen_urls.add(href)
                    urls.append(self._analyze_url(href, display, "html"))

            # Also find URLs not in anchor tags
            all_html_urls = re.findall(
                r'https?://[^\s<>"\')\]\}]+',
                body_html
            )
            for url in all_html_urls:
                if url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(self._analyze_url(url, "", "html"))

        return urls

    def _analyze_url(self, url: str, display_text: str, location: str) -> ExtractedURL:
        """Analyze a single URL for suspicious characteristics."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check if IP-based
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))

            # Check if shortened
            is_shortened = any(s in domain for s in self.URL_SHORTENERS)

            # Check for suspicious patterns
            is_suspicious = (
                is_ip or
                is_shortened or
                "@" in url or  # URL credential injection
                parsed.scheme != "https" or
                len(domain) > 50 or
                domain.count(".") > 5
            )

            # Check display text mismatch (potential deceptive link)
            if display_text:
                display_lower = display_text.lower()
                # If display looks like a URL but differs from actual
                if re.match(r'https?://', display_lower) or re.match(r'www\.', display_lower):
                    display_domain = re.search(r'(?:https?://)?(?:www\.)?([^/\s]+)', display_lower)
                    if display_domain:
                        displayed_domain = display_domain.group(1)
                        if displayed_domain != domain and not domain.endswith(displayed_domain):
                            is_suspicious = True

            return ExtractedURL(
                url=url,
                domain=domain,
                scheme=parsed.scheme,
                display_text=display_text,
                is_shortened=is_shortened,
                is_ip_based=is_ip,
                is_suspicious=is_suspicious,
                location=location
            )

        except Exception:
            return ExtractedURL(
                url=url,
                is_suspicious=True,
                location=location
            )

    def _parse_attachments(self, attachments: list[dict[str, Any]]) -> list[ExtractedAttachment]:
        """Parse attachment metadata."""
        parsed = []

        for att in attachments:
            filename = att.get("filename", "attachment")

            parsed.append(ExtractedAttachment(
                filename=filename,
                mime_type=att.get("mime_type", ""),
                size=att.get("size", 0),
                attachment_id=att.get("attachment_id"),
                is_dangerous_type=self._is_dangerous_extension(filename),
                has_double_extension=self._has_double_extension(filename)
            ))

        return parsed

    def _is_dangerous_extension(self, filename: str) -> bool:
        """Check if file has dangerous extension."""
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in self.DANGEROUS_EXTENSIONS)

    def _has_double_extension(self, filename: str) -> bool:
        """Check for double extension trick (e.g., document.pdf.exe)."""
        parts = filename.rsplit(".", 2)
        if len(parts) >= 3:
            final_ext = f".{parts[-1].lower()}"
            return final_ext in self.DANGEROUS_EXTENSIONS
        return False

    def to_analysis_request(self, parsed: ParsedEmail) -> dict[str, Any]:
        """
        Convert ParsedEmail to format expected by existing EmailAgent.

        This bridges the Gmail parser output to the existing analysis pipeline.
        """
        return {
            "sender": parsed.sender,
            "recipient": parsed.recipients[0] if parsed.recipients else "",
            "subject": parsed.subject,
            "body": parsed.body_plain or parsed.body_html,
            "headers": {
                "From": parsed.sender,
                "To": ", ".join(parsed.recipients),
                "Reply-To": parsed.reply_to,
                "Return-Path": parsed.return_path,
                "Subject": parsed.subject,
                "Message-ID": parsed.message_id,
                "Date": parsed.date.isoformat() if parsed.date else "",
                "Authentication-Results": parsed.authentication.raw_results,
                **{k: v for k, v in parsed.headers.items()}
            },
            "urls": [url.url for url in parsed.urls],
            "attachments": [
                {
                    "filename": att.filename,
                    "mime_type": att.mime_type,
                    "size": att.size,
                    "sha256": att.sha256,
                }
                for att in parsed.attachments
            ],
            # Extended fields for Gmail-specific analysis
            "gmail_message_id": parsed.gmail_message_id,
            "authentication": parsed.authentication.model_dump(),
            "urls_detailed": [url.model_dump() for url in parsed.urls],
            "received_chain": parsed.received_chain,
        }
