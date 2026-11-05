"""
CyberGuard AI - .eml File Parser

Parses user-uploaded raw .eml (RFC 822 / MIME) files into the same
field shape the manual-input and Gmail investigation paths already use,
so an uploaded file feeds the existing analysis pipeline unchanged.

Uses the legacy `email.message_from_bytes` API to stay consistent with
app/services/gmail/parser.py, which parses raw MIME the same way.

This is a deterministic parser - no LLM involved.
"""

import re
from datetime import datetime
from typing import Any
from email import message_from_bytes
from email.utils import parsedate_to_datetime

import structlog


logger = structlog.get_logger(__name__)

# 10 MB upload cap (user-confirmed). Shared conceptually with the frontend's
# matching client-side constant in EmailDropzone.tsx - keep both in sync if
# this value ever changes.
MAX_EML_SIZE_BYTES = 10 * 1024 * 1024

# Headers that, if at least one is present, make raw bytes plausibly an
# actual email rather than an arbitrary file that merely has a .eml name.
_SNIFF_HEADERS = ("from", "received", "message-id", "date", "subject")

# Same URL pattern used by app/services/gmail/parser.py for consistency.
_URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]\}]+|www\.[^\s<>"\')\]\}]+')
_HTML_TAG_PATTERN = re.compile(r'<[^>]+>')


class EmlParseError(ValueError):
    """Raised when uploaded bytes are not a well-formed, parseable .eml file."""


def parse_email_address(raw: str) -> str:
    """Extract a bare email address from 'Name <email>' / '<email>' / plain forms."""
    if not raw:
        return ""
    raw = raw.strip()

    match = re.match(r'^.+?\s*<([^>]+)>$', raw)
    if match:
        return match.group(1).strip().lower()

    match = re.match(r'^<([^>]+)>$', raw)
    if match:
        return match.group(1).strip().lower()

    match = re.search(r'[\w.\-+]+@[\w.\-]+\.\w+', raw)
    if match:
        return match.group().lower()

    return ""


def _extract_urls_from_text(body_plain: str, body_html: str) -> list[str]:
    """Extract URLs from plain + HTML body, matching the Gmail parser's approach."""
    urls: list[str] = []
    seen: set[str] = set()

    for url in _URL_PATTERN.findall(body_plain or ""):
        if url not in seen:
            seen.add(url)
            urls.append(url)

    if body_html:
        for url in _URL_PATTERN.findall(body_html):
            if url not in seen:
                seen.add(url)
                urls.append(url)

    return urls


def validate_eml_upload(filename: str, raw_bytes: bytes) -> None:
    """
    Validate an uploaded file before attempting to parse it as .eml.

    Raises EmlParseError with a user-facing message on any failure.
    Callers are expected to map EmlParseError to HTTP 400, and to check
    size against MAX_EML_SIZE_BYTES themselves (so they can return 413
    instead of 400 for oversize - this function assumes size is already
    within bounds).
    """
    if not filename or not filename.lower().endswith(".eml"):
        raise EmlParseError("File must have a .eml extension")

    if not raw_bytes:
        raise EmlParseError("Uploaded file is empty")

    # Don't trust the extension alone - sniff for at least one header that
    # a real email would have. A quick lowercase scan of the first chunk
    # (headers always appear before any blank line / body) is sufficient
    # and avoids a full parse just to validate.
    head = raw_bytes[:8192].decode("utf-8", errors="ignore").lower()
    if not any(f"\n{h}:" in f"\n{head}" for h in _SNIFF_HEADERS):
        raise EmlParseError(
            "File does not appear to be a valid email (no recognizable headers found)"
        )


def parse_eml_bytes(raw_bytes: bytes) -> dict[str, Any]:
    """
    Parse raw .eml bytes into the field shape EmailAnalysisRequest expects.

    Returns a dict with: sender, recipient, subject, body, headers, urls,
    attachments (metadata only), received_at.

    Raises EmlParseError on malformed MIME so the caller can return 400
    instead of a 500.
    """
    try:
        msg = message_from_bytes(raw_bytes)
    except Exception as e:
        raise EmlParseError(f"Could not parse email: {e}") from e

    headers: dict[str, str] = {}
    for key in msg.keys():
        headers[key] = msg[key]

    sender_raw = headers.get("From") or headers.get("from", "")
    subject = headers.get("Subject") or headers.get("subject", "")
    to_raw = headers.get("To") or headers.get("to", "")
    recipient = to_raw.split(",")[0].strip() if to_raw else None

    received_at = None
    date_raw = headers.get("Date") or headers.get("date")
    if date_raw:
        try:
            received_at = parsedate_to_datetime(date_raw)
        except Exception:
            received_at = None

    body_plain = ""
    body_html = ""
    attachments: list[dict[str, Any]] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    payload = part.get_payload(decode=True) or b""
                    attachments.append({
                        "filename": part.get_filename() or "attachment",
                        "mime_type": content_type,
                        "size": len(payload),
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
    except Exception as e:
        raise EmlParseError(f"Could not read email body/attachments: {e}") from e

    body = body_plain or (
        _HTML_TAG_PATTERN.sub(" ", body_html).strip() if body_html else ""
    )

    if not sender_raw:
        raise EmlParseError("Email is missing a From header")
    if not body:
        raise EmlParseError("Email has no readable body content")

    urls = _extract_urls_from_text(body_plain, body_html)

    return {
        "sender": sender_raw,
        "recipient": recipient,
        "subject": subject or "(no subject)",
        "body": body,
        "headers": headers,
        "urls": urls or None,
        "attachments": attachments or None,
        "received_at": received_at,
    }
