"""
CyberGuard AI - Gmail API Client

Wrapper for Gmail API operations.
Provides secure, read-only access to Gmail messages for security analysis.

Security:
- Read-only operations only
- No send/delete/modify capabilities
- Rate limiting handled
- Token refresh automatic
"""

import base64
from datetime import datetime, timezone
from typing import Optional, Any
from email import message_from_bytes

import httpx
import structlog
from pydantic import BaseModel, Field

from app.services.gmail.oauth import GmailTokens, GmailOAuthService, get_gmail_oauth_service


logger = structlog.get_logger(__name__)


class GmailMessageHeader(BaseModel):
    """Email header from Gmail API."""
    name: str
    value: str


class GmailMessagePart(BaseModel):
    """Message part (body or attachment)."""
    part_id: str = ""
    mime_type: str = ""
    filename: str = ""
    body_data: Optional[str] = None  # Base64 encoded
    body_size: int = 0
    attachment_id: Optional[str] = None
    parts: list["GmailMessagePart"] = Field(default_factory=list)


class GmailMessageSummary(BaseModel):
    """Summary of a Gmail message for listing."""
    id: str
    thread_id: str
    snippet: str = ""
    subject: str = ""
    sender: str = ""
    date: Optional[datetime] = None
    label_ids: list[str] = Field(default_factory=list)
    is_unread: bool = False
    has_attachments: bool = False


class GmailMessage(BaseModel):
    """Full Gmail message with headers and body."""
    id: str
    thread_id: str
    label_ids: list[str] = Field(default_factory=list)
    snippet: str = ""

    # Parsed headers
    subject: str = ""
    sender: str = ""  # From header
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: str = ""
    return_path: str = ""
    date: Optional[datetime] = None
    message_id: str = ""  # Message-ID header

    # All headers for analysis
    headers: dict[str, str] = Field(default_factory=dict)

    # Body content
    body_plain: str = ""
    body_html: str = ""

    # Attachments metadata
    attachments: list[dict[str, Any]] = Field(default_factory=list)

    # Raw message (for deep analysis)
    raw: Optional[str] = None  # Base64 encoded raw MIME

    # Internal date
    internal_date: Optional[int] = None  # Unix timestamp ms


class GmailListResponse(BaseModel):
    """Response from listing Gmail messages."""
    messages: list[GmailMessageSummary] = Field(default_factory=list)
    next_page_token: Optional[str] = None
    result_size_estimate: int = 0


class GmailClient:
    """
    Gmail API Client for security analysis.

    Provides read-only access to Gmail messages:
    - List messages with filters
    - Get message details
    - Get raw MIME message
    - Get attachments
    - Search messages

    All operations are read-only for defensive security analysis.
    """

    BASE_URL = "https://gmail.googleapis.com/gmail/v1"

    def __init__(self, tokens: GmailTokens, user_id: str = "me"):
        """
        Initialize Gmail client.

        Args:
            tokens: OAuth tokens for API access
            user_id: Gmail user ID (default "me" for authenticated user)
        """
        self.tokens = tokens
        self.user_id = user_id
        self._oauth_service = get_gmail_oauth_service()

    async def _ensure_valid_token(self) -> str:
        """Ensure we have a valid access token, refreshing if needed."""
        if self.tokens.is_expired() and self.tokens.refresh_token:
            logger.info("Refreshing expired Gmail token")
            self.tokens = await self._oauth_service.refresh_tokens(self.tokens.refresh_token)
        return self.tokens.access_token

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        timeout: float = 30.0
    ) -> dict:
        """Make authenticated request to Gmail API."""
        access_token = await self._ensure_valid_token()

        url = f"{self.BASE_URL}/users/{self.user_id}/{endpoint}"

        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                params=params,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=timeout
            )

            if response.status_code == 401:
                # Token might be invalid, try refresh
                if self.tokens.refresh_token:
                    self.tokens = await self._oauth_service.refresh_tokens(self.tokens.refresh_token)
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers={"Authorization": f"Bearer {self.tokens.access_token}"},
                        timeout=timeout
                    )

            if response.status_code != 200:
                error_data = response.json() if response.content else {}
                logger.error(
                    "Gmail API error",
                    status=response.status_code,
                    error=error_data.get("error", {}).get("message")
                )
                raise ValueError(f"Gmail API error: {response.status_code}")

            return response.json()

    async def list_messages(
        self,
        query: Optional[str] = None,
        max_results: int = 20,
        page_token: Optional[str] = None,
        label_ids: Optional[list[str]] = None,
        include_spam_trash: bool = False
    ) -> GmailListResponse:
        """
        List Gmail messages.

        Args:
            query: Gmail search query (e.g., "from:example.com subject:urgent")
            max_results: Maximum messages to return (1-500)
            page_token: Token for pagination
            label_ids: Filter by label IDs (e.g., ["INBOX", "UNREAD"])
            include_spam_trash: Include spam and trash

        Returns:
            GmailListResponse with message summaries
        """
        params = {
            "maxResults": min(max_results, 500),
            "includeSpamTrash": str(include_spam_trash).lower()
        }

        if query:
            params["q"] = query
        if page_token:
            params["pageToken"] = page_token
        if label_ids:
            params["labelIds"] = ",".join(label_ids)

        data = await self._request("GET", "messages", params)

        messages = []
        for msg in data.get("messages", []):
            # Get basic info for each message
            try:
                summary = await self._get_message_summary(msg["id"])
                messages.append(summary)
            except Exception as e:
                logger.warning("Failed to get message summary", message_id=msg["id"], error=str(e))

        return GmailListResponse(
            messages=messages,
            next_page_token=data.get("nextPageToken"),
            result_size_estimate=data.get("resultSizeEstimate", 0)
        )

    async def _get_message_summary(self, message_id: str) -> GmailMessageSummary:
        """Get message summary with minimal API calls."""
        data = await self._request(
            "GET",
            f"messages/{message_id}",
            params={"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"]}
        )

        headers = {h["name"].lower(): h["value"] for h in data.get("payload", {}).get("headers", [])}

        # Parse date
        date = None
        if "date" in headers:
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(headers["date"])
            except Exception:
                pass

        # Check for attachments
        has_attachments = self._check_has_attachments(data.get("payload", {}))

        return GmailMessageSummary(
            id=data["id"],
            thread_id=data["threadId"],
            snippet=data.get("snippet", ""),
            subject=headers.get("subject", "(No Subject)"),
            sender=headers.get("from", "Unknown"),
            date=date,
            label_ids=data.get("labelIds", []),
            is_unread="UNREAD" in data.get("labelIds", []),
            has_attachments=has_attachments
        )

    def _check_has_attachments(self, payload: dict) -> bool:
        """Check if message has attachments."""
        if payload.get("filename"):
            return True
        for part in payload.get("parts", []):
            if self._check_has_attachments(part):
                return True
        return False

    async def get_message(
        self,
        message_id: str,
        include_raw: bool = False
    ) -> GmailMessage:
        """
        Get full Gmail message.

        Args:
            message_id: Gmail message ID
            include_raw: Include raw MIME message for deep analysis

        Returns:
            GmailMessage with full details
        """
        format_type = "raw" if include_raw else "full"

        data = await self._request(
            "GET",
            f"messages/{message_id}",
            params={"format": format_type}
        )

        if include_raw and "raw" in data:
            # Parse from raw MIME
            return self._parse_raw_message(data)
        else:
            # Parse from structured payload
            return self._parse_payload_message(data)

    def _parse_raw_message(self, data: dict) -> GmailMessage:
        """Parse message from raw MIME format."""
        raw_bytes = base64.urlsafe_b64decode(data["raw"])
        msg = message_from_bytes(raw_bytes)

        # Extract headers
        headers = {}
        for key in msg.keys():
            headers[key.lower()] = msg[key]

        # Extract body
        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    attachments.append({
                        "filename": part.get_filename() or "attachment",
                        "mime_type": content_type,
                        "size": len(part.get_payload(decode=True) or b""),
                    })
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_plain = payload.decode("utf-8", errors="replace")
                elif content_type == "text/html":
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

        # Parse date
        date = None
        if "date" in headers:
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(headers["date"])
            except Exception:
                pass

        # Parse recipients
        to_list = [addr.strip() for addr in headers.get("to", "").split(",") if addr.strip()]
        cc_list = [addr.strip() for addr in headers.get("cc", "").split(",") if addr.strip()]

        return GmailMessage(
            id=data["id"],
            thread_id=data["threadId"],
            label_ids=data.get("labelIds", []),
            snippet=data.get("snippet", ""),
            subject=headers.get("subject", ""),
            sender=headers.get("from", ""),
            to=to_list,
            cc=cc_list,
            reply_to=headers.get("reply-to", ""),
            return_path=headers.get("return-path", ""),
            date=date,
            message_id=headers.get("message-id", ""),
            headers=headers,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            raw=data.get("raw"),
            internal_date=int(data.get("internalDate", 0))
        )

    def _parse_payload_message(self, data: dict) -> GmailMessage:
        """Parse message from Gmail API payload format."""
        payload = data.get("payload", {})

        # Extract headers
        headers = {}
        for h in payload.get("headers", []):
            headers[h["name"].lower()] = h["value"]

        # Extract body
        attachments = []
        body_plain, body_html = self._extract_body_parts(payload, attachments)

        # If body not in parts, check payload directly
        if not body_plain and not body_html:
            body_data = payload.get("body", {}).get("data")
            if body_data:
                decoded = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
                if payload.get("mimeType") == "text/html":
                    body_html = decoded
                else:
                    body_plain = decoded

        # Parse date
        date = None
        if "date" in headers:
            try:
                from email.utils import parsedate_to_datetime
                date = parsedate_to_datetime(headers["date"])
            except Exception:
                pass

        # Parse recipients
        to_list = [addr.strip() for addr in headers.get("to", "").split(",") if addr.strip()]
        cc_list = [addr.strip() for addr in headers.get("cc", "").split(",") if addr.strip()]

        return GmailMessage(
            id=data["id"],
            thread_id=data["threadId"],
            label_ids=data.get("labelIds", []),
            snippet=data.get("snippet", ""),
            subject=headers.get("subject", ""),
            sender=headers.get("from", ""),
            to=to_list,
            cc=cc_list,
            reply_to=headers.get("reply-to", ""),
            return_path=headers.get("return-path", ""),
            date=date,
            message_id=headers.get("message-id", ""),
            headers=headers,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            internal_date=int(data.get("internalDate", 0))
        )

    def _extract_body_parts(
        self,
        part: dict,
        attachments: list
    ) -> tuple[str, str]:
        """Recursively extract body and attachments from message parts."""
        body_plain = ""
        body_html = ""
        mime_type = part.get("mimeType", "")

        if part.get("filename"):
            attachments.append({
                "filename": part["filename"],
                "mime_type": mime_type,
                "size": part.get("body", {}).get("size", 0),
                "attachment_id": part.get("body", {}).get("attachmentId"),
            })
        elif mime_type == "text/plain":
            body_data = part.get("body", {}).get("data")
            if body_data:
                body_plain = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")
        elif mime_type == "text/html":
            body_data = part.get("body", {}).get("data")
            if body_data:
                body_html = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="replace")

        # Recurse into parts
        for sub_part in part.get("parts", []):
            bp, bh = self._extract_body_parts(sub_part, attachments)
            if bp and not body_plain:
                body_plain = bp
            if bh and not body_html:
                body_html = bh

        return body_plain, body_html

    async def get_attachment(
        self,
        message_id: str,
        attachment_id: str
    ) -> bytes:
        """
        Get attachment content.

        Args:
            message_id: Gmail message ID
            attachment_id: Attachment ID from message

        Returns:
            Raw attachment bytes
        """
        data = await self._request(
            "GET",
            f"messages/{message_id}/attachments/{attachment_id}"
        )

        return base64.urlsafe_b64decode(data["data"])

    async def search_messages(
        self,
        query: str,
        max_results: int = 50
    ) -> GmailListResponse:
        """
        Search Gmail messages.

        Args:
            query: Gmail search query
            max_results: Maximum results

        Returns:
            GmailListResponse with matching messages

        Example queries:
            - "from:suspicious@domain.com"
            - "subject:urgent action required"
            - "has:attachment filename:pdf"
            - "after:2024/01/01 before:2024/02/01"
            - "is:unread"
        """
        return await self.list_messages(query=query, max_results=max_results)

    async def get_profile(self) -> dict:
        """Get Gmail profile information."""
        return await self._request("GET", "profile")

    async def history_list(
        self,
        start_history_id: str,
        max_results: int = 100,
        page_token: Optional[str] = None,
        history_types: Optional[list[str]] = None,
    ) -> dict:
        """
        List mailbox changes since start_history_id (Gmail's incremental
        sync endpoint - GET users.history.list).

        Used by the automatic Gmail poller (app/services/gmail/poller.py)
        to fetch only new/changed messages per cycle instead of re-listing
        the whole mailbox. Raises ValueError (via _request) on a non-200
        response, including the 404 Gmail returns when start_history_id
        is too old/expired (history is only retained for a limited time)
        - callers must catch that and fall back to list_messages() with a
        bounded lookback, never retry history_list() blindly in that case.

        Args:
            start_history_id: resume point, from a prior history_list()
                response's historyId, or from get_profile()'s historyId
                on first connect (there is nothing to resume from before
                that).
            max_results: max history records per page (Gmail max 500).
            page_token: pagination token from a previous response.
            history_types: filter to specific change types, e.g.
                ["messageAdded"] to ignore label-only changes. Defaults to
                Gmail's own default (all types) when omitted.

        Returns:
            Raw Gmail API response dict with "history" (list of change
            records), optional "nextPageToken", and "historyId" (the new
            high-water mark to persist for the next poll).
        """
        params: dict[str, Any] = {
            "startHistoryId": start_history_id,
            "maxResults": min(max_results, 500),
        }
        if page_token:
            params["pageToken"] = page_token
        if history_types:
            params["historyTypes"] = history_types

        return await self._request("GET", "history", params)
