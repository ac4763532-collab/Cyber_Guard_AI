"""
CyberGuard AI — Windows Event Log Reader
============================================================================

Reads Windows Event Log channels (Security, System, Application) and
yields raw events as Python dicts.

Design goals
------------
1. **Incremental** — only reads events since the last checkpoint. Uses
   the Windows Event Log record number (``RecordNumber``) as the
   bookmark. On restart, resumes from the last successfully-read record.

2. **Resilient** — if a channel becomes unavailable (e.g. Security log
   requires admin privileges), logs a warning and skips it. The other
   channels continue.

3. **Bounded** — reads at most ``max_events_per_poll`` per channel per
   poll. Prevents one huge burst from blocking the reader thread.

4. **Extracted, not normalized** — this module returns the raw
   ``win32evtlog.EvtSystem`` object fields as a dict. The normalizer
   (``event_normalizer.py``) converts them to CyberGuard's shape.

Prerequisites
-------------
- Windows (raises ``RuntimeError`` on other platforms)
- ``pywin32`` package installed (``pip install pywin32``)
- **Administrator privileges** to read the Security log. System and
  Application logs are readable by regular users but usually contain
  less security-relevant data.

The collector service (installed via ``install_service.ps1``) runs as
LocalSystem, which has the required privileges.

Checkpoint semantics
--------------------
The last-read record number per channel is stored in memory. To
survive restarts, ``main.py`` should persist it to ``config.json``
(field ``checkpoints`` — not yet in config.py; add via override at
save time). For MVP, the reader restarts from "now" on every start —
this means events during the process's downtime are missed. Acceptable
for a first-release collector; the fix is a Phase 13 enhancement to
persist checkpoints.

Query format (XPath)
--------------------
Windows Event Log accepts XPath queries for filtering. We use:

    *[System[(EventRecordID > <checkpoint>)]]

which returns events with a record number greater than the checkpoint,
ordered by record number ascending. This is the standard incremental-
read pattern.

For the first read (no checkpoint), we use a time-based filter:

    *[System[TimeCreated[@SystemTime >= '<ISO-8601>']]]

This avoids returning the entire historical log on first run. Default:
last 5 minutes.

Event dict shape
----------------
Each yielded dict contains:

    {
        "channel": "Security",           # Security | System | Application
        "record_number": 12345,          # Windows EventRecordID
        "event_id": 4625,                # Windows EventID (the numeric code)
        "level": 2,                      # 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
        "time_created": "2026-11-07T14:23:45.123456Z",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "computer": "PRIYA-LAPTOP",
        "message": "...",                # Full text (may be None if not rendered)
        "xml": "<Event>...</Event>",     # Raw XML (for forensic detail)
        "properties": {                  # Extracted from EventData
            "SubjectUserName": "alice",
            "IpAddress": "203.0.113.42",
            ...
        },
        "user_data": {...},              # Extracted from UserData (rare)
    }

The normalizer (``event_normalizer.py``) inspects these fields to
produce CyberGuard's normalized shape (severity, category, source_ip,
username, etc.).

Usage
-----
    from event_log_reader import EventLogReader

    reader = EventLogReader(
        channels=["Security", "System", "Application"],
        max_events_per_poll=500,
        event_ids_to_capture=[],   # empty = all
    )

    for event_dict in reader.poll():
        # event_dict is a dict ready for the queue
        queue.enqueue(event_dict)

The reader is **not thread-safe** — one instance per channel-set,
called from one thread. The collector's architecture uses one reader
thread.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator


logger = logging.getLogger(__name__)


#: Platform check at import time — fail fast if we're on non-Windows.
if sys.platform != "win32":
    raise RuntimeError(
        "event_log_reader requires Windows. Current platform: "
        f"{sys.platform}. The collector cannot read Windows Event Logs "
        "on non-Windows systems."
    )

#: pywin32 import — fail fast with a clear message if not installed.
try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
except ImportError as exc:
    raise RuntimeError(
        "pywin32 is required to read Windows Event Logs. "
        "Install it with: pip install pywin32"
    ) from exc


# ============================================================================
# CONSTANTS
# ============================================================================

#: Windows Event Log "level" numeric → human string. Used by the
#: normalizer; included here for reference.
_LEVEL_NAMES: dict[int, str] = {
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

#: On first read (no checkpoint), look back this many minutes. Avoids
#: loading the entire historical log.
_FIRST_READ_LOOKBACK_MINUTES = 5

#: XML namespace used in the Event XML structure.
_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# ============================================================================
# READER
# ============================================================================

class EventLogReader:
    """
    Reads Windows Event Log channels and yields raw events as dicts.

    One instance per channel-set. Not thread-safe.
    """

    def __init__(
        self,
        *,
        channels: list[str] | None = None,
        max_events_per_poll: int = 500,
        event_ids_to_capture: list[int] | None = None,
    ) -> None:
        self._channels = list(channels or ["Security", "System", "Application"])
        self._max_events_per_poll = max(1, min(5000, int(max_events_per_poll)))
        self._event_ids_to_capture = set(event_ids_to_capture or [])
        self._checkpoints: dict[str, int] = {}   # channel → last record number

    # ── Public API ─────────────────────────────────────────────────────

    def poll(self) -> Iterator[dict[str, Any]]:
        """
        Poll all channels once. Yields event dicts as they're read.

        Stops yielding after ``max_events_per_poll`` events (across all
        channels). The next call to ``poll()`` continues from where
        this one left off (via checkpoints).
        """
        total_yielded = 0

        for channel in self._channels:
            if total_yielded >= self._max_events_per_poll:
                break

            remaining = self._max_events_per_poll - total_yielded

            try:
                for event_dict in self._read_channel(channel, limit=remaining):
                    yield event_dict
                    total_yielded += 1
                    if total_yielded >= self._max_events_per_poll:
                        return
            except Exception as exc:  # noqa: BLE001
                # A channel being unreadable (permissions, disabled) does
                # not stop the other channels.
                logger.warning(
                    "Failed to read channel — skipping",
                    extra={
                        "channel": channel,
                        "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                    },
                )
                continue

    # ── Internal ───────────────────────────────────────────────────────

    def _read_channel(
        self,
        channel: str,
        *,
        limit: int,
    ) -> Iterator[dict[str, Any]]:
        """
        Read one channel incrementally. Yields up to ``limit`` events.
        Updates the checkpoint after each successfully-read event.
        """
        checkpoint = self._checkpoints.get(channel, 0)
        query = self._build_query(channel, checkpoint)

        logger.debug(
            "Reading channel",
            extra={
                "channel": channel,
                "checkpoint": checkpoint,
                "limit": limit,
            },
        )

        # Open the channel. This can raise if:
        #   - The channel doesn't exist
        #   - Insufficient privileges (Security log without admin)
        #   - The service is stopped
        flags = win32evtlog.EvtQueryChannelPath

        try:
            query_handle = win32evtlog.EvtQuery(channel, flags, query)
        except pywintypes.error as exc:
            if "Access is denied" in str(exc) or exc.winerror == 5:
                logger.error(
                    "Access denied reading channel — collector must run "
                    "as Administrator or LocalSystem",
                    extra={"channel": channel},
                )
            raise

        batch: list[dict[str, Any]] = []
        read_count = 0
        last_record_number = checkpoint

        while read_count < limit:
            try:
                events = win32evtlog.EvtNext(query_handle, 50)
            except pywintypes.error as exc:
                logger.warning(
                    "EvtNext failed — ending channel read",
                    extra={
                        "channel": channel,
                        "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                    },
                )
                break

            if not events:
                # End of current query result
                break

            for event_handle in events:
                if read_count >= limit:
                    break

                try:
                    event_dict = self._parse_event(channel, event_handle)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Skipping unparseable event",
                        extra={
                            "channel": channel,
                            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                        },
                    )
                    continue

                if event_dict is None:
                    continue

                # Apply EventID filter
                event_id = event_dict.get("event_id")
                if (
                    self._event_ids_to_capture
                    and event_id not in self._event_ids_to_capture
                ):
                    # Skip but advance checkpoint (we read it, we just
                    # don't forward it)
                    rn = event_dict.get("record_number")
                    if rn is not None:
                        last_record_number = max(last_record_number, rn)
                    continue

                # Advance checkpoint
                rn = event_dict.get("record_number")
                if rn is not None:
                    last_record_number = max(last_record_number, rn)

                yield event_dict
                read_count += 1

        # Update checkpoint after channel read
        if last_record_number > checkpoint:
            self._checkpoints[channel] = last_record_number

        logger.debug(
            "Channel read complete",
            extra={
                "channel": channel,
                "events_read": read_count,
                "new_checkpoint": self._checkpoints.get(channel, checkpoint),
            },
        )

    def _build_query(self, channel: str, checkpoint: int) -> str:
        """
        Build the XPath query for incremental read.

        With checkpoint: record number filter
        Without: time-based filter (last N minutes)
        """
        if checkpoint > 0:
            return f"*[System[(EventRecordID > {checkpoint})]]"

        # First read — bounded time window
        lookback = datetime.now(timezone.utc) - timedelta(
            minutes=_FIRST_READ_LOOKBACK_MINUTES
        )
        iso = lookback.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return f"*[System[TimeCreated[@SystemTime >= '{iso}']]]"

    def _parse_event(
        self,
        channel: str,
        event_handle: Any,
    ) -> dict[str, Any] | None:
        """
        Convert a ``win32evtlog.EvtHandle`` to a dict.

        Uses ``EvtRender`` to get the XML representation, then parses
        it with ElementTree to extract structured fields.
        """
        try:
            xml_string = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml,
            )
        except pywintypes.error as exc:
            logger.debug(
                "EvtRender failed",
                extra={"error": str(exc)[:200]},
            )
            return None

        if not xml_string:
            return None

        return _parse_event_xml(channel, xml_string)


# ============================================================================
# XML PARSING
# ============================================================================

def _parse_event_xml(channel: str, xml_string: str) -> dict[str, Any] | None:
    """
    Parse the Windows Event XML into a dict.

    Handles both EventData (with named Data elements) and UserData
    (with arbitrary nested structure) formats.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return None

    # Strip XML namespace for easier querying
    def _strip_ns(tag: str) -> str:
        return tag.replace(_XML_NS, "") if tag.startswith(_XML_NS) else tag

    def _find(path: str) -> Any:
        # Try with namespace, then without
        el = root.find(path)
        if el is None:
            stripped_path = "/".join(_strip_ns(p) for p in path.split("/"))
            for child in root.iter():
                if _strip_ns(child.tag) == stripped_path.split("/")[-1]:
                    return child
        return el

    system_el = root.find(f"{_XML_NS}System")
    if system_el is None:
        # Fallback — try without namespace
        for child in root:
            if _strip_ns(child.tag) == "System":
                system_el = child
                break

    if system_el is None:
        return None

    def _child_text(parent: Any, name: str) -> str | None:
        if parent is None:
            return None
        for child in parent:
            if _strip_ns(child.tag) == name:
                return child.text
        return None

    def _child_attr(parent: Any, name: str, attr: str) -> str | None:
        if parent is None:
            return None
        for child in parent:
            if _strip_ns(child.tag) == name:
                return child.get(attr)
        return None

    # ── System fields
    event_id_str = _child_text(system_el, "EventID")
    try:
        event_id = int(event_id_str) if event_id_str else None
    except (ValueError, TypeError):
        event_id = None

    record_number_str = _child_text(system_el, "EventRecordID")
    try:
        record_number = int(record_number_str) if record_number_str else None
    except (ValueError, TypeError):
        record_number = None

    level_str = _child_text(system_el, "Level")
    try:
        level = int(level_str) if level_str else None
    except (ValueError, TypeError):
        level = None

    time_created = _child_attr(system_el, "TimeCreated", "SystemTime")

    provider_el = None
    for child in system_el:
        if _strip_ns(child.tag) == "Provider":
            provider_el = child
            break
    provider_name = provider_el.get("Name") if provider_el is not None else None

    computer = _child_text(system_el, "Computer")

    # ── EventData (named Data elements)
    properties: dict[str, Any] = {}
    for child in root:
        if _strip_ns(child.tag) == "EventData":
            for data_el in child:
                if _strip_ns(data_el.tag) != "Data":
                    continue
                name = data_el.get("Name")
                if name:
                    properties[name] = data_el.text
                else:
                    # Unnamed Data — rare, but occurs in some events
                    pass
            break

    # ── UserData (arbitrary nested structure — flatten to dict)
    user_data: dict[str, Any] = {}
    for child in root:
        if _strip_ns(child.tag) == "UserData":
            for sub in child:
                # sub is e.g. <EventXML xmlns="Event_1234">
                for inner in sub:
                    inner_name = _strip_ns(inner.tag)
                    if inner.text and inner.text.strip():
                        user_data[inner_name] = inner.text.strip()
                    for attr_name, attr_val in inner.attrib.items():
                        user_data[f"{inner_name}.{attr_name}"] = attr_val
            break

    # ── Message (rendered text) — optional; can be slow, so try but
    #     don't fail if it errors
    message: str | None = None
    try:
        # EvtFormatMessage is available via win32evtlogutil but
        # requires the event handle, not XML. We skip for speed.
        # The normalizer works from structured fields, not the
        # human-readable message.
        pass
    except Exception:  # noqa: BLE001
        pass

    return {
        "channel": channel,
        "record_number": record_number,
        "event_id": event_id,
        "level": level,
        "time_created": time_created,
        "provider_name": provider_name,
        "computer": computer,
        "message": message,
        "xml": xml_string,
        "properties": properties,
        "user_data": user_data,
    }


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "EventLogReader",
    "_LEVEL_NAMES",
]