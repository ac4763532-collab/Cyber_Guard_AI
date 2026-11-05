"""Office VBA macro detection using oletools."""

from __future__ import annotations

import io
from pathlib import Path

from oletools.olevba import VBA_Parser


MACRO_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppsm",
    ".ppam",
}


def detect_macros(
    filename: str,
    file_bytes: bytes,
) -> dict:
    """Detect and analyze VBA macros in an Office document."""
    extension = Path(filename or "").suffix.lower()

    result = {
        "filename": filename,
        "is_macro_document": extension in MACRO_EXTENSIONS,
        "has_vba": False,
        "macro_count": 0,
        "auto_exec": [],
        "suspicious": [],
        "ioc": [],
        "risk": "none",
        "error": None,
    }

    if not file_bytes:
        return result

    # Only Office macro-capable extensions should be analyzed by oletools.
    # This prevents false positives on unrelated formats such as PDF.
    if extension not in MACRO_EXTENSIONS:
        return result

    parser = None

    try:
        parser = VBA_Parser(
            filename=filename or "attachment",
            data=file_bytes,
        )

        if not parser.detect_vba_macros():
            return result

        result["has_vba"] = True

        macros = []

        for macro in parser.extract_macros():
            if len(macro) >= 4:
                _, stream_path, vba_filename, code = macro[:4]

                macros.append(
                    {
                        "stream": stream_path,
                        "filename": vba_filename,
                        "code": code,
                    }
                )

        result["macro_count"] = len(macros)

        try:
            result["auto_exec"] = list(
                parser.analyze_macros(show_decoded_strings=False).get(
                    "AutoExec", []
                )
            )
        except Exception:
            result["auto_exec"] = []

        try:
            analysis = parser.analyze_macros(
                show_decoded_strings=False
            )

            suspicious_items = analysis.get("Suspicious", [])
            ioc_items = analysis.get("IOC", [])

            result["suspicious"] = [
                item if isinstance(item, dict) else str(item)
                for item in suspicious_items
            ]

            result["ioc"] = [
                item if isinstance(item, dict) else str(item)
                for item in ioc_items
            ]

        except Exception:
            result["suspicious"] = []
            result["ioc"] = []

        if result["suspicious"] or result["auto_exec"] or result["ioc"]:
            result["risk"] = "high"
        elif result["has_vba"]:
            result["risk"] = "medium"

        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result

    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass
