"""Attachment file-type detection using magic bytes."""

from __future__ import annotations

from pathlib import Path

import magic


EXTENSION_TYPES = {
    ".pdf": {"pdf"},
    ".png": {"png"},
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".gif": {"gif"},
    ".txt": {"text"},
    ".csv": {"text"},
    ".html": {"html"},
    ".htm": {"html"},
    ".zip": {"zip"},
    ".doc": {"msword", "ole"},
    ".xls": {"ms-excel", "ole"},
    ".ppt": {"ms-powerpoint", "ole"},
    ".docx": {"zip", "office"},
    ".xlsx": {"zip", "office"},
    ".pptx": {"zip", "office"},
    ".docm": {"zip", "office", "macro"},
    ".xlsm": {"zip", "office", "macro"},
    ".pptm": {"zip", "office", "macro"},
    ".exe": {"pe", "executable"},
    ".dll": {"pe", "executable"},
    ".msi": {"ole", "msi"},
    ".rar": {"rar"},
    ".7z": {"7-zip"},
    ".tar": {"tar"},
    ".gz": {"gzip"},
    ".iso": {"iso"},
}


def detect_file_type(file_bytes: bytes) -> dict:
    """Detect the actual file type from its content."""
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")

    if not file_bytes:
        return {
            "mime_type": "application/x-empty",
            "description": "empty",
            "type": "empty",
        }

    try:
        mime_type = magic.from_buffer(file_bytes, mime=True)
        description = magic.from_buffer(file_bytes)
    except Exception as exc:
        return {
            "mime_type": "application/octet-stream",
            "description": "unknown",
            "type": "unknown",
            "error": str(exc),
        }

    detected_type = _classify_type(mime_type, description, file_bytes)

    return {
        "mime_type": mime_type,
        "description": description,
        "type": detected_type,
    }


def _classify_type(
    mime_type: str,
    description: str,
    file_bytes: bytes,
) -> str:
    """Map libmagic output to a simple security-oriented type."""
    mime = mime_type.lower()
    desc = description.lower()

    if "pdf" in mime or "pdf" in desc:
        return "pdf"

    if "zip" in mime or "zip archive" in desc:
        if _looks_like_office_zip(file_bytes):
            return "office"
        return "zip"

    if "rar" in mime or "rar archive" in desc:
        return "rar"

    if "7-zip" in mime or "7-zip" in desc:
        return "7-zip"

    if "gzip" in mime or "gzip compressed" in desc:
        return "gzip"

    if "tar archive" in desc:
        return "tar"

    if "png" in mime or "png image" in desc:
        return "png"

    if "jpeg" in mime or "jpeg image" in desc:
        return "jpeg"

    if "gif" in mime or "gif image" in desc:
        return "gif"

    if (
        "msword" in mime
        or "ms-excel" in mime
        or "ms-powerpoint" in mime
        or "microsoft office" in desc
        or "compound document" in desc
    ):
        return "ole"

    if (
        "pe32" in desc
        or "portable executable" in desc
        or mime in {
            "application/x-dosexec",
            "application/vnd.microsoft.portable-executable",
        }
    ):
        return "executable"

    if mime.startswith("text/"):
        return "text"

    if "html" in mime:
        return "html"

    return "unknown"


def _looks_like_office_zip(file_bytes: bytes) -> bool:
    """Identify OOXML Office files by their ZIP entries."""
    markers = (
        b"[Content_Types].xml",
        b"word/",
        b"xl/",
        b"ppt/",
    )

    return b"[Content_Types].xml" in file_bytes and any(
        marker in file_bytes for marker in markers
    )


def check_extension_mismatch(
    filename: str,
    detected_type: dict,
) -> dict:
    """Check whether the filename extension conflicts with magic bytes."""
    extension = Path(filename or "").suffix.lower()
    actual_type = str(detected_type.get("type", "unknown")).lower()

    expected_types = EXTENSION_TYPES.get(extension)

    if expected_types is None:
        return {
            "filename": filename,
            "extension": extension,
            "actual_type": actual_type,
            "expected_types": [],
            "mismatch": False,
            "reason": "Extension is not in the known mapping.",
        }

    mismatch = actual_type not in expected_types

    return {
        "filename": filename,
        "extension": extension,
        "actual_type": actual_type,
        "expected_types": sorted(expected_types),
        "mismatch": mismatch,
        "reason": (
            f"Extension {extension} does not match detected type {actual_type}."
            if mismatch
            else "Extension matches detected type."
        ),
    }
