"""Safe inspection of common archive formats."""

from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

import py7zr
import rarfile


DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi",
    ".hta", ".lnk", ".iso", ".img",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz",
}

MAX_FILES = 1000
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024


def inspect_archive(
    filename: str,
    file_bytes: bytes,
) -> dict:
    """Inspect a supported archive without extracting files to disk."""
    extension = PurePosixPath(filename or "").suffix.lower()

    result = {
        "filename": filename,
        "archive_type": extension.lstrip(".") or "unknown",
        "is_archive": extension in ARCHIVE_EXTENSIONS,
        "file_count": 0,
        "total_uncompressed_size": 0,
        "dangerous_files": [],
        "nested_archives": [],
        "encrypted_files": [],
        "suspicious": False,
        "zip_bomb_risk": False,
        "error": None,
    }

    if extension not in ARCHIVE_EXTENSIONS:
        return result

    try:
        if extension == ".zip":
            entries = _inspect_zip(file_bytes)
        elif extension == ".rar":
            entries = _inspect_rar(file_bytes)
        elif extension == ".7z":
            entries = _inspect_7z(file_bytes)
        else:
            # TAR/GZ inspection is deliberately conservative for now.
            result["error"] = (
                "TAR/GZ archive inspection is not enabled yet."
            )
            return result

        result["file_count"] = len(entries)

        for entry in entries:
            name = entry["name"]
            size = entry["size"]

            result["total_uncompressed_size"] += size

            suffix = PurePosixPath(name).suffix.lower()

            if suffix in DANGEROUS_EXTENSIONS:
                result["dangerous_files"].append(name)

            if suffix in ARCHIVE_EXTENSIONS:
                result["nested_archives"].append(name)

            if entry.get("encrypted"):
                result["encrypted_files"].append(name)

        result["zip_bomb_risk"] = (
            result["file_count"] > MAX_FILES
            or result["total_uncompressed_size"] > MAX_TOTAL_UNCOMPRESSED
        )

        result["suspicious"] = bool(
            result["dangerous_files"]
            or result["nested_archives"]
            or result["encrypted_files"]
            or result["zip_bomb_risk"]
        )

        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result


def _inspect_zip(file_bytes: bytes) -> list[dict]:
    entries = []

    with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
        for info in archive.infolist():
            entries.append(
                {
                    "name": info.filename,
                    "size": int(info.file_size),
                    "compressed_size": int(info.compress_size),
                    "encrypted": bool(info.flag_bits & 0x1),
                }
            )

    return entries


def _inspect_rar(file_bytes: bytes) -> list[dict]:
    entries = []

    with rarfile.RarFile(io.BytesIO(file_bytes)) as archive:
        for info in archive.infolist():
            entries.append(
                {
                    "name": info.filename,
                    "size": int(info.file_size),
                    "compressed_size": int(info.compress_size),
                    "encrypted": bool(info.needs_password()),
                }
            )

    return entries


def _inspect_7z(file_bytes: bytes) -> list[dict]:
    entries = []

    with py7zr.SevenZipFile(io.BytesIO(file_bytes), mode="r") as archive:
        for info in archive.list():
            entries.append(
                {
                    "name": info.filename,
                    "size": int(info.uncompressed),
                    "compressed_size": int(info.compressed),
                    "encrypted": False,
                }
            )

    return entries
