"""
CyberGuard AI - Log File Upload Parser

Parses an uploaded log file (`.log`/`.txt`/`.csv`/`.json`/`.jsonl`) into
normalized log lines that can be fed straight into the existing LogAgent
dispatcher - the same `dispatcher.dispatch(AgentType.LOG, {"log_content": ...})`
call already used by POST /analysis/logs and POST /logs/ingest/raw.

Design goals (see the approved plan, STEP: drag-and-drop log upload):
- Reuse the real, existing per-line collector parsers (Linux, Android) where
  possible rather than inventing a second parsing system.
- Windows plain-text uploads get an honest, clearly-flagged best-effort
  fallback - WindowsEventParser only understands live win32evtlog objects
  or genuine Event Log XML, so a `.log`/`.txt`/`.csv` "Windows" upload cannot
  be parsed with real fidelity. Only actual Event Log XML content gets the
  real parser.
- CSV/JSON/JSONL are new formats with no existing parser anywhere in this
  codebase - these are intentionally small, defensive, proportional parsers
  for already-structured log exports, not a general-purpose data pipeline.
- Never raise out of a single bad line/record - malformed records are
  skipped and counted, not fatal, unless *zero* usable records result.
- Never log or embed the full raw file content in exception messages -
  only counts, filenames, and short safe excerpts where unavoidable.

This is a deterministic, non-ML module - no model loading, no inference.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Literal
from xml.etree import ElementTree as ET

import structlog

from app.logs.collectors.android import parse_logcat_line
from app.logs.collectors.windows import WindowsEventParser
from app.logs.parsers.linux_ssh import parse_linux_log_line

logger = structlog.get_logger(__name__)

SourceTypeHint = Literal["windows", "linux_ssh", "android", "auto"]

ALLOWED_EXTENSIONS = (".log", ".txt", ".csv", ".json", ".jsonl")

# Extensions whose content is always treated as plain text lines rather
# than attempting structured CSV/JSON parsing.
_PLAIN_TEXT_EXTENSIONS = (".log", ".txt")

# Column/key names (case-insensitive) that plausibly hold the log message.
_MESSAGE_KEYS = ("message", "msg", "log", "description", "event", "text")
_TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "datetime")
_LEVEL_KEYS = ("level", "severity", "loglevel")

# Keys under which a JSON object's record LIST might be nested, e.g.
# {"events": [...]}  rather than a bare top-level array.
_JSON_LIST_KEYS = ("events", "logs", "entries", "records")

# Windows numeric Level codes (System/Level in Event XML), per the Windows
# Event Log schema - matches WindowsEventParser's own raw integer output.
_WINDOWS_LEVEL_NAMES = {1: "CRITICAL", 2: "ERROR", 3: "WARNING", 4: "INFO", 5: "DEBUG"}

# Binary/archive mime types libmagic may report for a disguised upload
# (e.g. a renamed .exe saved as "notes.log"). Content this clearly
# non-text is rejected outright rather than fed to a text parser.
_REJECTED_MIME_PREFIXES = (
    "application/x-executable",
    "application/x-dosexec",
    "application/x-elf",
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar",
    "application/x-tar",
    "application/gzip",
    "application/vnd.microsoft.portable-executable",
    "application/octet-stream",
)


class LogFileParseError(ValueError):
    """Raised when an uploaded file cannot be safely parsed as a log file."""


class ParsedLogFile:
    """Result of parsing an uploaded log file into normalized lines."""

    def __init__(
        self,
        synthetic_log_content: str,
        detected_source_type: str,
        parsed_event_count: int,
        skipped_line_count: int,
        preview_events: list[dict[str, Any]],
        encoding_fallback_used: bool,
    ) -> None:
        self.synthetic_log_content = synthetic_log_content
        self.detected_source_type = detected_source_type
        self.parsed_event_count = parsed_event_count
        self.skipped_line_count = skipped_line_count
        self.preview_events = preview_events
        self.encoding_fallback_used = encoding_fallback_used


def validate_extension(filename: str) -> str:
    """Return the lowercase extension if allowed, else raise LogFileParseError."""
    name = (filename or "").lower()
    for ext in ALLOWED_EXTENSIONS:
        if name.endswith(ext):
            return ext
    raise LogFileParseError(
        f"Unsupported file extension. Supported formats: {', '.join(ALLOWED_EXTENSIONS)}"
    )


def validate_content_type(raw_bytes: bytes, filename: str) -> None:
    """
    Soft content-sniffing check using libmagic.

    Rejects clearly-binary/archive content disguised with a text-ish
    extension (e.g. a renamed .exe). A `.log`/`.csv`/`.json` file
    legitimately reports as text/plain or similar under magic, so this is
    not an allowlist gate - only a reject-list for obviously wrong content.
    Never raises on magic itself being unavailable/erroring - fails open
    on the *check*, not on the upload (the real content handling later
    will fail safely regardless, e.g. via decode errors).
    """
    try:
        import magic

        mime_type = magic.from_buffer(raw_bytes[:4096], mime=True).lower()
    except Exception:
        return

    if any(mime_type.startswith(prefix) for prefix in _REJECTED_MIME_PREFIXES):
        raise LogFileParseError(
            f"File content does not look like a text log file (detected type: {mime_type})"
        )


def _decode_text(raw_bytes: bytes) -> tuple[str, bool]:
    """
    Decode uploaded bytes to text.

    Tries strict UTF-8 first; falls back to UTF-8 with replacement
    characters rather than crashing on non-UTF-8 content (e.g. legacy
    Windows code pages). No chardet/charset-normalizer dependency is
    added - this is a documented, deliberate limitation, not silent data
    loss: callers see `encoding_fallback_used=True` when this path is hit.
    """
    try:
        return raw_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw_bytes.decode("utf-8", errors="replace"), True


def _first_present(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    lower_map = {str(k).lower(): v for k, v in d.items()}
    for key in keys:
        if key in lower_map and lower_map[key] not in (None, ""):
            return lower_map[key]
    return None


def _best_effort_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.utcfromtimestamp(float(value)).isoformat()
        except (ValueError, OSError, OverflowError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text  # keep the raw string rather than discard a plausible timestamp


def _record_to_line(record: dict[str, Any]) -> str | None:
    """Map one structured record (from JSON/JSONL/CSV) to {timestamp, level, message} and
    render a synthetic plain-text log line LogAgent's regex parser can read.
    Returns None if the record has no recognizable message - skipped, not fatal."""
    message = _first_present(record, _MESSAGE_KEYS)
    if message in (None, ""):
        return None

    timestamp = _best_effort_timestamp(_first_present(record, _TIMESTAMP_KEYS))
    level = _first_present(record, _LEVEL_KEYS) or "info"

    ts_part = timestamp or datetime.utcnow().isoformat()
    return f"{ts_part} {str(level).upper()} {message}"


def _parse_jsonl(text: str) -> tuple[list[str], int]:
    lines: list[str] = []
    skipped = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            skipped += 1
            continue
        if not isinstance(record, dict):
            skipped += 1
            continue
        line = _record_to_line(record)
        if line is None:
            skipped += 1
            continue
        lines.append(line)
    return lines, skipped


def _extract_json_records(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    if isinstance(parsed, dict):
        for key in _JSON_LIST_KEYS:
            value = parsed.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return [parsed]
    return []


def _parse_json(text: str) -> tuple[list[str], int]:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        raise LogFileParseError(f"File is not valid JSON: {e}") from e

    records = _extract_json_records(parsed)
    lines: list[str] = []
    skipped = 0
    for record in records:
        line = _record_to_line(record)
        if line is None:
            skipped += 1
            continue
        lines.append(line)
    return lines, skipped


def _parse_csv(text: str) -> tuple[list[str], int]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise LogFileParseError("CSV file has no header row")

    header_lower = {str(h).strip().lower() for h in reader.fieldnames if h}
    if not any(key in header_lower for key in _MESSAGE_KEYS):
        raise LogFileParseError(
            "CSV has no recognizable log-message column "
            f"(expected one of: {', '.join(_MESSAGE_KEYS)})"
        )

    lines: list[str] = []
    skipped = 0
    for row in reader:
        if row is None:
            skipped += 1
            continue
        line = _record_to_line({k: v for k, v in row.items() if k})
        if line is None:
            skipped += 1
            continue
        lines.append(line)
    return lines, skipped


def _looks_like_windows_event_xml(text: str) -> bool:
    head = text.lstrip()[:512]
    return ("<Event" in head or head.startswith("<?xml")) and "<EventID" in text[:4096]


def _parse_windows_xml(text: str) -> tuple[list[str], int]:
    """
    Parse genuine Windows Event Log XML export: either a single <Event>
    document, or multiple <Event> elements concatenated/wrapped. Each
    parsed event is rendered as a synthetic log line.
    """
    lines: list[str] = []
    skipped = 0

    # Try as one well-formed XML doc with (potentially) multiple <Event> children.
    try:
        root = ET.fromstring(text)
        candidates = [root] if root.tag.split("}")[-1] == "Event" else list(root)
    except ET.ParseError:
        # Not one well-formed doc - fall back to scanning for individual
        # <Event ...>...</Event> fragments (e.g. newline-concatenated export).
        candidates = []
        start = 0
        while True:
            start_idx = text.find("<Event", start)
            if start_idx == -1:
                break
            end_idx = text.find("</Event>", start_idx)
            if end_idx == -1:
                break
            end_idx += len("</Event>")
            fragment = text[start_idx:end_idx]
            try:
                candidates.append(ET.fromstring(fragment))
            except ET.ParseError:
                skipped += 1
            start = end_idx

    for element in candidates:
        xml_fragment = ET.tostring(element, encoding="unicode")
        parsed = WindowsEventParser.parse_event_xml(xml_fragment)
        if not parsed:
            skipped += 1
            continue

        time_created = parsed.get("time_created")
        ts_part = time_created.isoformat() if hasattr(time_created, "isoformat") else datetime.utcnow().isoformat()
        level_name = _WINDOWS_LEVEL_NAMES.get(parsed.get("level"), "INFO")

        event_data = parsed.get("event_data") or {}
        detail = ", ".join(f"{k}={v}" for k, v in list(event_data.items())[:6])
        computer = parsed.get("computer") or "unknown-host"
        provider = parsed.get("provider_name") or "Windows"
        message = (
            f"{provider} EventID={parsed.get('event_id')} on {computer}"
            + (f" ({detail})" if detail else "")
        )
        lines.append(f"{ts_part} {level_name} {message}")

    if not candidates:
        skipped += 1

    return lines, skipped


def _parse_plain_text_for_hint(
    text: str, source_type_hint: SourceTypeHint
) -> tuple[list[str], int, str]:
    """
    Parse plain-text (.log/.txt) content using the real per-line parser
    matching the declared source type where one exists (Linux, Android).
    Falls back to a generic pass-through for Windows/auto, since there is
    no verified plain-text Windows parser - lines are kept as-is (LogAgent's
    own regex rules run on them regardless) but detected_source_type is
    flagged so the caller can surface the limitation honestly.
    """
    raw_lines = [l for l in text.splitlines() if l.strip()]
    if source_type_hint == "linux_ssh":
        kept: list[str] = []
        skipped = 0
        for line in raw_lines:
            entry = parse_linux_log_line(line)
            if entry is None:
                skipped += 1
                kept.append(line)  # still feed LogAgent's own regexes, just not "parsed"
            else:
                kept.append(line)
        return kept, skipped, "linux_ssh"

    if source_type_hint == "android":
        kept = []
        skipped = 0
        for line in raw_lines:
            parsed = parse_logcat_line(line, max_line_length=4096)
            if parsed is None:
                skipped += 1
            kept.append(line)
        return kept, skipped, "android"

    if source_type_hint == "windows":
        # No verified plain-text Windows parser exists - honest fallback,
        # not claimed as full support. Lines are still passed through so
        # LogAgent's own detection rules can run on them.
        return raw_lines, 0, "windows_generic_fallback"

    return raw_lines, 0, "auto"


def parse_log_file(
    raw_bytes: bytes,
    filename: str,
    source_type_hint: SourceTypeHint = "auto",
    max_preview_events: int = 20,
) -> ParsedLogFile:
    """
    Validate and parse an uploaded log file into normalized synthetic log
    content ready for `dispatcher.dispatch(AgentType.LOG, {"log_content": ...})`.

    Raises LogFileParseError (caller maps to HTTP 400) if the file cannot
    be safely parsed or contains zero usable records. Never raises for a
    single bad line/record within an otherwise-valid file - those are
    counted in skipped_line_count.
    """
    if not raw_bytes:
        raise LogFileParseError("Uploaded file is empty")

    ext = validate_extension(filename)
    validate_content_type(raw_bytes, filename)
    text, encoding_fallback_used = _decode_text(raw_bytes)

    if not text.strip():
        raise LogFileParseError("Uploaded file has no readable content")

    detected_source_type = source_type_hint
    skipped = 0

    if ext in _PLAIN_TEXT_EXTENSIONS:
        if source_type_hint == "windows" and _looks_like_windows_event_xml(text):
            lines, skipped = _parse_windows_xml(text)
            detected_source_type = "windows"
        else:
            lines, skipped, detected_source_type = _parse_plain_text_for_hint(
                text, source_type_hint
            )
    elif ext == ".jsonl":
        lines, skipped = _parse_jsonl(text)
    elif ext == ".json":
        if source_type_hint == "windows" and _looks_like_windows_event_xml(text):
            lines, skipped = _parse_windows_xml(text)
            detected_source_type = "windows"
        else:
            lines, skipped = _parse_json(text)
    elif ext == ".csv":
        lines, skipped = _parse_csv(text)
    else:  # pragma: no cover - validate_extension already restricts this
        raise LogFileParseError("Unsupported file extension")

    if not lines:
        raise LogFileParseError(
            "No valid log records found in file (all lines/records were "
            "empty, malformed, or missing a recognizable message field)"
        )

    preview_events = [{"line": line} for line in lines[:max_preview_events]]

    return ParsedLogFile(
        synthetic_log_content="\n".join(lines),
        detected_source_type=detected_source_type,
        parsed_event_count=len(lines),
        skipped_line_count=skipped,
        preview_events=preview_events,
        encoding_fallback_used=encoding_fallback_used,
    )
