"""
CyberGuard AI — Windows Collector Credential Store
============================================================================

Encrypts and stores the collector's long-lived credential at rest using
Windows DPAPI (Data Protection API).

Why DPAPI
---------
The credential authenticates every event POST to the backend. If an
attacker gains read access to the file (e.g. backup exfiltration, or a
malicious process running as the user), a plaintext credential in
``config.json`` would be an immediate compromise.

DPAPI solves this by encrypting the credential with keys derived from
the current Windows user's login credentials. The ciphertext:

    - Can only be decrypted by the same Windows user on the same machine
    - Is useless if the file is copied to another machine
    - Is useless if the file is copied to another user's session
    - Requires no separate key management — DPAPI handles it

This is the same mechanism Chrome, Edge, and other Windows applications
use for stored passwords.

Scope
-----
``CryptProtectData`` is called with ``CRYPTPROTECT_LOCAL_MACHINE = 0``
(the default), which ties the ciphertext to the *current user's* login
session. This is correct for the collector:

    - When installed as a SYSTEM service, the service account is the
      "current user" — the credential is tied to SYSTEM on that machine.
    - When run manually by an admin for testing, the credential is tied
      to that admin's session.

The trade-off: an admin who manually enrolls, then installs the
service, must re-enroll (the SYSTEM session can't decrypt the admin-
encrypted blob). ``install_service.ps1`` handles this by installing the
service first and enrolling from the service context.

Fallback (dev/test only)
------------------------
On non-Windows (Linux, WSL, macOS), DPAPI is not available. This module
falls back to storing the credential as a base64 blob with a loud
warning log. **This is NOT secure** — it exists only so developers can
test the collector's logic on a non-Windows machine.

Production deployments must be on Windows.

Threat model
------------
Protected against:
    - File theft (backup exfiltration)
    - Casual inspection (config.json is not readable as plaintext)
    - Transfer to another machine (DPAPI ciphertext is machine-bound)

NOT protected against:
    - Malware running as the same Windows user (can call DPAPI to
      decrypt the same way the collector does)
    - Physical access to an unlocked, logged-in session

If the collector's credential is compromised despite DPAPI, the backend
provides the real defense: every credential is unique per device, can be
revoked individually, and can be rotated by an admin.

API
---
    encrypt_credential(plaintext: str) -> str       # base64 DPAPI blob
    decrypt_credential(ciphertext: str) -> str      # plaintext credential
    store_credential(config, plaintext) -> None     # convenience: encrypt + save
    load_credential(config) -> str | None           # convenience: load + decrypt

Usage
-----
    from config import CollectorConfig
    from credential_store import store_credential, load_credential

    # After successful enrollment:
    store_credential(config, plaintext_credential)
    config.save()   # persists config.json with encrypted credential

    # On subsequent startup:
    plaintext = load_credential(config)
    if plaintext is None:
        # Not enrolled, or decrypt failed → re-enroll
        ...
"""

from __future__ import annotations

import base64
import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config import CollectorConfig


logger = logging.getLogger(__name__)


# ============================================================================
# PLATFORM DETECTION
# ============================================================================

_IS_WINDOWS = sys.platform == "win32"

#: Length of the marker prepended to non-DPAPI blobs so we can detect
#: them and refuse to trust them on Windows.
_INSECURE_MARKER = "INSECURE_BASE64:"


# ============================================================================
# WINDOWS DPAPI
# ============================================================================

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """
    Encrypt bytes using Windows DPAPI (user-scoped).

    Raises ``RuntimeError`` if pywin32 is not installed (indicates a
    broken collector install — the installer should have installed it).
    """
    try:
        import win32crypt
    except ImportError as exc:
        raise RuntimeError(
            "pywin32 is required for Windows credential encryption. "
            "The collector installer should have installed it. "
            "Run: pip install pywin32"
        ) from exc

    try:
        # CRYPTPROTECT_UI_FORBIDDEN = 0x1 — don't show a UI prompt if
        # something goes wrong (the collector runs headless)
        blob = win32crypt.CryptProtectData(
            plaintext,
            "CyberGuard Collector Credential",
            None,       # optional entropy — not used
            None,       # reserved
            None,       # prompt struct — unused when UI forbidden
            0x1,        # CRYPTPROTECT_UI_FORBIDDEN
        )
        return blob
    except Exception as exc:
        raise RuntimeError(
            f"DPAPI encryption failed: {exc}"
        ) from exc


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """
    Decrypt bytes using Windows DPAPI.

    Raises ``RuntimeError`` on failure (wrong user, wrong machine,
    corrupted blob).
    """
    try:
        import win32crypt
    except ImportError as exc:
        raise RuntimeError(
            "pywin32 is required for Windows credential decryption."
        ) from exc

    try:
        # CryptUnprotectData returns (description, decrypted_bytes)
        _description, decrypted = win32crypt.CryptUnprotectData(
            ciphertext,
            None,       # optional entropy
            None,       # reserved
            None,       # prompt struct
            0x1,        # CRYPTPROTECT_UI_FORBIDDEN
        )
        return decrypted
    except Exception as exc:
        raise RuntimeError(
            f"DPAPI decryption failed — the credential may have been "
            f"encrypted under a different Windows user or machine, or "
            f"the file is corrupt. Original error: {exc}"
        ) from exc


# ============================================================================
# PUBLIC API
# ============================================================================

def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt a plaintext credential for storage in config.json.

    Returns a base64-encoded string. On Windows, this is a DPAPI blob
    (secure). On non-Windows, this is a base64 blob with the
    ``INSECURE_BASE64:`` prefix marker so we can detect and warn about
    it later.

    Parameters
    ----------
    plaintext : str
        The credential to protect (typically ``cgc_...`` from enrollment).

    Returns
    -------
    str
        Encrypted blob as a base64 string, safe to store in JSON.

    Raises
    ------
    RuntimeError
        On Windows if pywin32 is missing or DPAPI fails.
        On non-Windows, this method succeeds but logs a WARNING.
    """
    if not plaintext:
        raise ValueError("Cannot encrypt an empty credential")

    plaintext_bytes = plaintext.encode("utf-8")

    if _IS_WINDOWS:
        encrypted = _dpapi_encrypt(plaintext_bytes)
        return base64.b64encode(encrypted).decode("ascii")
    else:
        # Non-Windows — NOT SECURE, dev/test only
        logger.warning(
            "credential_store: DPAPI is not available on this platform "
            "(%s). Storing credential with base64 encoding only — "
            "NOT SECURE for production. This is intended for local "
            "development and testing only.",
            sys.platform,
        )
        encoded = base64.b64encode(plaintext_bytes).decode("ascii")
        return _INSECURE_MARKER + encoded


def decrypt_credential(ciphertext: str) -> str:
    """
    Decrypt a stored credential blob.

    Parameters
    ----------
    ciphertext : str
        The base64 blob (possibly prefixed with ``INSECURE_BASE64:``).

    Returns
    -------
    str
        The plaintext credential.

    Raises
    ------
    RuntimeError
        On Windows if pywin32 is missing, DPAPI fails, or the blob was
        created on a different machine/user.
    ValueError
        If the input is empty or not valid base64.
    """
    if not ciphertext:
        raise ValueError("Cannot decrypt an empty credential blob")

    # Detect insecure (dev-only) blob
    if ciphertext.startswith(_INSECURE_MARKER):
        if _IS_WINDOWS:
            # A dev-test blob is on a Windows machine — probably moved
            # from a dev laptop. Refuse for safety.
            logger.warning(
                "credential_store: found INSECURE_BASE64 credential on "
                "Windows — this credential was created on a non-Windows "
                "machine. It cannot be decrypted securely. Re-enroll."
            )
            raise RuntimeError(
                "Insecure credential blob cannot be used on Windows. "
                "Delete config.json and re-enroll the collector."
            )
        encoded = ciphertext[len(_INSECURE_MARKER):]
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except Exception as exc:
            raise RuntimeError(
                f"Failed to decode insecure credential blob: {exc}"
            ) from exc

    # Standard path — base64 blob (Windows DPAPI)
    try:
        raw_blob = base64.b64decode(ciphertext)
    except Exception as exc:
        raise ValueError(
            f"Credential is not valid base64: {exc}"
        ) from exc

    if not _IS_WINDOWS:
        logger.warning(
            "credential_store: attempting to decrypt a DPAPI blob on "
            "non-Windows (%s). This will fail. DPAPI blobs are "
            "machine-bound.",
            sys.platform,
        )
        raise RuntimeError(
            "DPAPI blobs cannot be decrypted on non-Windows platforms. "
            "The credential was created on a Windows machine and can "
            "only be decrypted there."
        )

    decrypted = _dpapi_decrypt(raw_blob)
    return decrypted.decode("utf-8")


# ============================================================================
# CONVENIENCE HELPERS
# ============================================================================

def store_credential(config: "CollectorConfig", plaintext: str) -> None:
    """
    Encrypt the credential and store it on the config object.

    Does NOT save the config to disk — the caller must call
    ``config.save()`` after this. That separation lets the caller
    batch multiple config updates into one disk write.

    Parameters
    ----------
    config : CollectorConfig
        The config instance to update (mutated in place).
    plaintext : str
        The plaintext credential (``cgc_...``).

    Raises
    ------
    RuntimeError
        If encryption fails.
    """
    encrypted = encrypt_credential(plaintext)
    config.credential = encrypted
    config.is_enrolled = True


def load_credential(config: "CollectorConfig") -> str | None:
    """
    Load and decrypt the stored credential.

    Returns None if:
        - The config has no credential (not enrolled)
        - The stored blob cannot be decrypted (wrong machine/user,
          corrupt, or a dev-only blob on Windows)

    Never raises — callers treat None as "need to re-enroll".

    Parameters
    ----------
    config : CollectorConfig

    Returns
    -------
    str | None
        The plaintext credential, or None if unavailable.
    """
    if not config.credential:
        return None

    try:
        plaintext = decrypt_credential(config.credential)
    except Exception as exc:
        logger.warning(
            "credential_store: failed to decrypt stored credential — "
            "collector will need to re-enroll. Error: %s",
            str(exc)[:300],
        )
        return None

    return plaintext


def clear_credential(config: "CollectorConfig") -> None:
    """
    Remove the credential from the config (does not save to disk).

    Use cases:
        - After a revocation notice from the backend
        - Before re-enrollment (to ensure a clean state)
        - On explicit user logout

    Call ``config.save()`` afterward to persist the removal.
    """
    config.credential = None
    config.is_enrolled = False


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "encrypt_credential",
    "decrypt_credential",
    "store_credential",
    "load_credential",
    "clear_credential",
]