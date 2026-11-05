"""Unified attachment security analysis service."""

from __future__ import annotations

from pathlib import Path

from app.services.attachment_analysis.archive_inspector import (
    inspect_archive,
)
from app.services.attachment_analysis.file_type import (
    check_extension_mismatch,
    detect_file_type,
)
from app.services.attachment_analysis.hash_checker import (
    check_hash_reputation,
)
from app.services.attachment_analysis.macro_detector import (
    detect_macros,
)


def _add_finding(
    findings: list[dict],
    finding_id: str,
    severity: str,
    description: str,
    evidence: dict,
) -> None:
    findings.append(
        {
            "finding_id": finding_id,
            "severity": severity,
            "description": description,
            "evidence": evidence,
        }
    )


def _log_malware_if_detected(
    filename: str,
    sha256: str,
    detection_source: str,
    threat_names: list[str] | None = None,
) -> None:
    """Log malware detection event (fire and forget)."""
    try:
        from app.logging import log_malware_detected
        log_malware_detected(
            filename=filename,
            sha256=sha256,
            detection_source=detection_source,
            threat_names=threat_names or [],
        )
    except Exception:
        # Logging must never break analysis
        pass


async def analyze_attachment(
    filename: str,
    file_bytes: bytes,
) -> dict:
    """Perform unified security analysis of an attachment."""
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename is required")

    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")

    filename = Path(filename).name

    result = {
        "filename": filename,
        "size": len(file_bytes),
        "hashes": {},
        "file_type": {},
        "extension_check": {},
        "reputation": {},
        "archive": {},
        "macros": {},
        "risk_score": 0,
        "status": "clean",
        "findings": [],
        "errors": [],
    }

    findings = result["findings"]

    # 1. Hash + VirusTotal reputation.
    try:
        hash_result = await check_hash_reputation(file_bytes)

        result["hashes"] = hash_result.get("hashes", {})
        result["reputation"] = hash_result.get("reputation", {})

        reputation = result["reputation"]
        verdict = reputation.get("verdict", "unknown")

        if verdict == "malicious":
            result["risk_score"] = max(result["risk_score"], 100)

            _add_finding(
                findings,
                "ATTACH-HASH-001",
                "critical",
                "VirusTotal identified the attachment hash as malicious.",
                {
                    "hash": reputation.get("hash"),
                    "malicious_count": reputation.get(
                        "malicious_count", 0
                    ),
                    "suspicious_count": reputation.get(
                        "suspicious_count", 0
                    ),
                    "total_engines": reputation.get(
                        "total_engines", 0
                    ),
                    "threat_names": reputation.get(
                        "threat_names", []
                    ),
                },
            )

            # Step 10: Log malware detection
            _log_malware_if_detected(
                filename=filename,
                sha256=result["hashes"].get("sha256", reputation.get("hash", "")),
                detection_source="virustotal",
                threat_names=reputation.get("threat_names", []),
            )

        elif verdict == "suspicious":
            result["risk_score"] = max(result["risk_score"], 70)

            _add_finding(
                findings,
                "ATTACH-HASH-001",
                "high",
                "VirusTotal reported suspicious detections for the attachment hash.",
                {
                    "hash": reputation.get("hash"),
                    "malicious_count": reputation.get(
                        "malicious_count", 0
                    ),
                    "suspicious_count": reputation.get(
                        "suspicious_count", 0
                    ),
                    "total_engines": reputation.get(
                        "total_engines", 0
                    ),
                    "threat_names": reputation.get(
                        "threat_names", []
                    ),
                },
            )

        if reputation.get("error"):
            result["errors"].append(
                f"Hash reputation: {reputation['error']}"
            )

    except Exception as exc:
        result["errors"].append(f"Hash analysis: {exc}")

    # 2. Magic-byte file type detection.
    try:
        file_type = detect_file_type(file_bytes)
        result["file_type"] = file_type

        extension_check = check_extension_mismatch(
            filename,
            file_type,
        )
        result["extension_check"] = extension_check

        if extension_check.get("mismatch"):
            result["risk_score"] = max(result["risk_score"], 80)

            _add_finding(
                findings,
                "ATTACH-TYPE-001",
                "high",
                "The attachment filename extension does not match its detected file type.",
                extension_check,
            )

    except Exception as exc:
        result["errors"].append(f"File type analysis: {exc}")

    # 3. Archive inspection.
    try:
        archive = inspect_archive(filename, file_bytes)
        result["archive"] = archive

        if archive.get("dangerous_files"):
            result["risk_score"] = max(result["risk_score"], 90)

            _add_finding(
                findings,
                "ATTACH-ARCHIVE-001",
                "high",
                "The archive contains potentially dangerous executable or script files.",
                {
                    "dangerous_files": archive.get(
                        "dangerous_files", []
                    ),
                },
            )

        if archive.get("nested_archives"):
            result["risk_score"] = max(result["risk_score"], 60)

            _add_finding(
                findings,
                "ATTACH-ARCHIVE-002",
                "medium",
                "The archive contains nested archive files.",
                {
                    "nested_archives": archive.get(
                        "nested_archives", []
                    ),
                },
            )

        if archive.get("encrypted_files"):
            result["risk_score"] = max(result["risk_score"], 60)

            _add_finding(
                findings,
                "ATTACH-ARCHIVE-002",
                "medium",
                "The archive contains encrypted files that cannot be inspected normally.",
                {
                    "encrypted_files": archive.get(
                        "encrypted_files", []
                    ),
                },
            )

        if archive.get("zip_bomb_risk"):
            result["risk_score"] = max(result["risk_score"], 90)

            _add_finding(
                findings,
                "ATTACH-ARCHIVE-001",
                "high",
                "The archive exceeds configured safety limits and may represent archive-bomb behavior.",
                {
                    "file_count": archive.get("file_count", 0),
                    "total_uncompressed_size": archive.get(
                        "total_uncompressed_size", 0
                    ),
                },
            )

        if archive.get("error"):
            result["errors"].append(
                f"Archive analysis: {archive['error']}"
            )

    except Exception as exc:
        result["errors"].append(f"Archive analysis: {exc}")

    # 4. Office VBA macro analysis.
    try:
        macros = detect_macros(filename, file_bytes)
        result["macros"] = macros

        if macros.get("suspicious") or macros.get("auto_exec"):
            result["risk_score"] = max(result["risk_score"], 85)

            _add_finding(
                findings,
                "ATTACH-MACRO-001",
                "high",
                "The Office document contains VBA macro behavior requiring security review.",
                {
                    "macro_count": macros.get("macro_count", 0),
                    "auto_exec": macros.get("auto_exec", []),
                    "suspicious": macros.get("suspicious", []),
                    "ioc": macros.get("ioc", []),
                },
            )

        elif macros.get("has_vba"):
            result["risk_score"] = max(result["risk_score"], 60)

            _add_finding(
                findings,
                "ATTACH-MACRO-002",
                "medium",
                "The Office document contains VBA macros.",
                {
                    "macro_count": macros.get("macro_count", 0),
                },
            )

        if macros.get("error"):
            result["errors"].append(
                f"Macro analysis: {macros['error']}"
            )

    except Exception as exc:
        result["errors"].append(f"Macro analysis: {exc}")

    # 5. Final status.
    result["risk_score"] = min(
        100,
        max(0, int(result["risk_score"])),
    )

    if result["risk_score"] >= 80:
        result["status"] = "malicious"
    elif result["risk_score"] >= 40:
        result["status"] = "suspicious"
    elif result["errors"]:
        result["status"] = "unknown"
    else:
        result["status"] = "clean"

    return result


async def analyze_attachments(
    attachments: list[dict],
) -> list[dict]:
    """Analyze multiple attachments with available content."""
    results = []

    for attachment in attachments:
        filename = attachment.get("filename") or attachment.get("name")
        content = attachment.get("content")

        if not filename:
            results.append(
                {
                    "filename": "",
                    "status": "unknown",
                    "risk_score": 0,
                    "findings": [],
                    "errors": ["Attachment filename is missing."],
                }
            )
            continue

        if not isinstance(content, bytes):
            results.append(
                {
                    "filename": filename,
                    "status": "unknown",
                    "risk_score": 0,
                    "findings": [],
                    "errors": [
                        "Attachment content is unavailable; "
                        "metadata-only analysis is required."
                    ],
                }
            )
            continue

        results.append(
            await analyze_attachment(filename, content)
        )

    return results
