"""
CyberGuard AI — Linux Collector Credential Store
============================================================================

Encrypts and stores the collector's long-lived credential at rest using
Fernet (AES-128-CBC + HMAC-SHA256) from the ``cryptography`` package.

Why Fernet (and not DPAPI)
--------------------------
Windows has DPAPI — the OS provides user/machine-bound encryption for
free. Linux has no equivalent single API. The available options:

    systemd-creds         systemd-only, requires per-install setup
    Kernel keyring        session-scoped (lost on reboot)
    TPM                   requires hardware + tpm2-tss tooling
    Plain 0600 file       trivial to defeat by backup exfiltration

The middle ground: a **symmetric key file** stored separately from the
encrypted credential, both with mode 0600 and root ownership. An
attacker with both files can decrypt — but so can an attacker with
DPAPI access on Windows. The threat model is the same: protect against
casual disk theft, not against root-level compromise.

Layered defense
---------------
    /var/lib/cyberguard/collector/fernet.key        — mode 0600 root
    /var/lib/cyberguard/collector/credential.enc    — mode 0600 root
    /var/lib/cyberguard/collector/                  — mode 0750 root

Two independent files must be stolen, from a root-only directory. The
collector service runs as root (via systemd) — regular users cannot
read either file. This is the correct threat model for a device agent.

Threat model
------------
Protected against:
    - Backup exfiltration (both files needed, neither readable by non-root)
    - Casual inspection of config.json (credential not in config.json)
    - Transfer to another machine (key + ciphertext must both move)

NOT protected against:
    - Root access (can read both files — root can do anything)
    - Malware running as root

If the credential is compromised despite Fernet, the backend provides
the real defense: per-device credentials can be revoked individually
and rotated by an admin.

API
---
    ensure_key_exists()                     — generate key if missing
    encrypt_credential(plaintext) -> str    — encrypt and return base64
    decrypt_credential(ciphertext) -> str   — decrypt, raise on tamper
    store_credential(config, plaintext)     — encrypt + assign to config
    load_credential(config) -> str | None   — decrypt, return None on failure
    clear_credential(config)                — remove from config

Usage
-----
    from config import CollectorConfig
    from credential_store import store_credential, load_credential

    config = CollectorConfig.load()
    store_credential(config, plaintext_credential)
    config.save()

    # Later:
    plaintext = load_credential(config)
    if plaintext is None:
        # Need re-enrollment
        ...
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from config import CREDENTIAL_FILE, FERNET_KEY_FILE

if TYPE_CHECKING:
    from config import CollectorConfig


logger = logging.getLogger(__name__)


# ============================================================================
# PLATFORM HELPER
# ============================================================================

def _is_root() -> bool:
    """Return True if running as UID 0."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _chmod(path: Path, mode: int) -> None:
    """chmod, ignoring errors (WSL/macOS edge cases)."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


# ============================================================================
# KEY MANAGEMENT
# ============================================================================

def _import_fernet():
    """
    Import Fernet, raising a clear error if ``cryptography`` is missing.

    ``cryptography`` is a hard dependency of the Linux collector —
    the install_service.sh script installs it. If it's missing at
    runtime, the collector cannot encrypt credentials, so we fail
    loudly here rather than produce unreadable bytes.
    """
    try:
        from cryptography.fernet import Fernet
        return Fernet
    except ImportError as exc:
        raise RuntimeError(
            "The 'cryptography' package is required for Linux credential "
            "encryption. Install it with:\n"
            "    pip install cryptography\n"
            "Or run the installer:\n"
            "    sudo ./install_service.sh install"
        ) from exc


def ensure_key_exists() -> None:
    """
    Generate the Fernet key file if it doesn't exist.

    Idempotent. Called from:
        - install_service.sh (during install, to pre-create the key)
        - encrypt_credential() on first enrollment
        - main.py startup (defensive — ensures key is present before
          any operation needs it)

    The key file is written with mode 0600. On production systems it
    ends up root:root; the collector service runs as root via systemd
    so it can read it.

    If the key file already exists, this is a no-op — the existing
    key is preserved. Never regenerate a key that already exists —
    that would make all existing ciphertexts unreadable.
    """
    if FERNET_KEY_FILE.exists():
        return

    Fernet = _import_fernet()

    FERNET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    FERNET_KEY_FILE.write_bytes(key)
    _chmod(FERNET_KEY_FILE, 0o600)

    logger.info(
        "Generated Fernet encryption key",
        extra={"path": str(FERNET_KEY_FILE)},
    )


def _read_key() -> bytes:
    """
    Read the Fernet key from disk. Generates it if missing.

    Raises RuntimeError if the file is unreadable or malformed.
    """
    ensure_key_exists()

    try:
        key = FERNET_KEY_FILE.read_bytes().strip()
    except OSError as exc:
        raise RuntimeError(
            f"Cannot read credential key file at {FERNET_KEY_FILE}: {exc}"
        ) from exc

    if not key:
        raise RuntimeError(
            f"Credential key file at {FERNET_KEY_FILE} is empty. "
            "Delete it to regenerate (existing credentials will become "
            "unreadable and re-enrollment is required)."
        )

    return key


# ============================================================================
# ENCRYPT / DECRYPT
# ============================================================================

def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt a plaintext credential for storage.

    Returns the ciphertext as a URL-safe base64 ASCII string (Fernet's
    native format), safe to embed in ``config.json`` or write to
    ``credential.enc``.

    Parameters
    ----------
    plaintext : str
        The credential to protect (``cgc_...`` from enrollment).

    Returns
    -------
    str
        Fernet ciphertext (base64 ASCII).

    Raises
    ------
    ValueError
        If ``plaintext`` is empty.
    RuntimeError
        If ``cryptography`` is missing or the key file is unavailable.
    """
    if not plaintext:
        raise ValueError("Cannot encrypt an empty credential")

    Fernet = _import_fernet()
    key = _read_key()

    try:
        cipher = Fernet(key)
        ciphertext_bytes = cipher.encrypt(plaintext.encode("utf-8"))
        return ciphertext_bytes.decode("ascii")
    except Exception as exc:
        raise RuntimeError(
            f"Credential encryption failed: {exc}"
        ) from exc


def decrypt_credential(ciphertext: str) -> str:
    """
    Decrypt a stored credential blob.

    Parameters
    ----------
    ciphertext : str
        The Fernet ciphertext (base64 ASCII) previously produced by
        ``encrypt_credential``.

    Returns
    -------
    str
        The plaintext credential.

    Raises
    ------
    ValueError
        If ``ciphertext`` is empty or not valid base64.
    RuntimeError
        If the key file is missing/wrong, or the ciphertext has been
        tampered with (HMAC verification fails).
    """
    if not ciphertext:
        raise ValueError("Cannot decrypt an empty credential blob")

    Fernet = _import_fernet()

    try:
        from cryptography.fernet import InvalidToken
    except ImportError:  # pragma: no cover — different cryptography versions
        InvalidToken = Exception  # type: ignore[assignment]

    key = _read_key()

    try:
        cipher = Fernet(key)
        plaintext_bytes = cipher.decrypt(ciphertext.encode("ascii"))
        return plaintext_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Credential decryption failed — the key does not match the "
            "ciphertext, or the ciphertext was tampered with. This usually "
            "means:\n"
            "  - The key file (.fernet.key) was deleted or replaced\n"
            "  - The credential was encrypted on a different machine\n"
            "  - The credential file was corrupted\n"
            "Fix: run 'python main.py clear-credential' then re-enroll."
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Credential decryption failed: {exc}"
        ) from exc


# ============================================================================
# FILE-LEVEL PERSISTENCE (optional — config.json has the blob too)
# ============================================================================
# The credential also lives in config.json as an encrypted blob. This
# file-level credential file is an additional, redundant storage for
# deployments that prefer to keep the config JSON free of secrets
# (e.g. config.json readable by an auditor). The collector reads from
# config.credential first, then falls back to credential.enc.

def _write_credential_file(ciphertext: str) -> None:
    """
    Write the encrypted credential to ``credential.enc``.

    Mode 0600. Called by ``store_credential`` — kept separate from
    ``config.save()`` so the encrypted blob has its own file with
    its own permissions.
    """
    ensure_key_exists()
    CREDENTIAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIAL_FILE.write_text(ciphertext, encoding="ascii")
    _chmod(CREDENTIAL_FILE, 0o600)


def _read_credential_file() -> str | None:
    """Read the encrypted credential from ``credential.enc`` (if present)."""
    if not CREDENTIAL_FILE.exists():
        return None
    try:
        return CREDENTIAL_FILE.read_text(encoding="ascii").strip()
    except OSError as exc:
        logger.warning(
            "Failed to read credential file",
            extra={
                "path": str(CREDENTIAL_FILE),
                "error": str(exc)[:200],
            },
        )
        return None


def _delete_credential_file() -> None:
    """Delete the credential file (used by ``clear_credential``)."""
    if CREDENTIAL_FILE.exists():
        try:
            CREDENTIAL_FILE.unlink()
        except OSError as exc:
            logger.warning(
                "Failed to delete credential file",
                extra={
                    "path": str(CREDENTIAL_FILE),
                    "error": str(exc)[:200],
                },
            )


# ============================================================================
# CONVENIENCE HELPERS
# ============================================================================

def store_credential(config: "CollectorConfig", plaintext: str) -> None:
    """
    Encrypt the credential, store it on the config, and write the
    ``credential.enc`` file.

    Does NOT call ``config.save()`` — the caller batches that with
    other config changes (e.g. heartbeat interval from the enroll
    response).

    Parameters
    ----------
    config : CollectorConfig
        Mutated in place — ``credential`` set to the encrypted blob,
        ``is_enrolled`` set to True.
    plaintext : str
        Plaintext credential from enrollment.

    Raises
    ------
    RuntimeError
        If encryption or file write fails.
    """
    encrypted = encrypt_credential(plaintext)
    config.credential = encrypted
    config.is_enrolled = True
    _write_credential_file(encrypted)


def load_credential(config: "CollectorConfig") -> str | None:
    """
    Load and decrypt the stored credential.

    Tries sources in order:
        1. ``config.credential`` (the blob stored in config.json)
        2. ``credential.enc`` file (if config.json was cleared or
           the deployment uses file-only storage)

    Returns None if:
        - No credential stored (not enrolled)
        - Decryption fails (key mismatch, corrupt ciphertext)

    Never raises — callers treat None as "need to re-enroll".
    """
    # Try config.credential first
    blob: str | None = config.credential

    # Fall back to file if config is empty
    if not blob:
        blob = _read_credential_file()

    if not blob:
        return None

    try:
        return decrypt_credential(blob)
    except Exception as exc:
        logger.warning(
            "Failed to decrypt stored credential — re-enrollment required",
            extra={"error": str(exc)[:300]},
        )
        return None


def clear_credential(config: "CollectorConfig") -> None:
    """
    Remove the credential from the config AND delete the credential
    file (if present).

    Does NOT call ``config.save()`` — the caller persists the removal
    with ``config.save()``.

    Also does NOT delete the Fernet key file. The key is reused across
    re-enrollments; deleting it is only necessary if you want to
    invalidate ALL past ciphertexts (e.g. forensics on a compromised
    host — but at that point you should be re-imaging the machine).

    Use cases:
        - ``main.py clear-credential`` command
        - After a revocation notice from the backend
        - Before re-enrollment (clean state)
    """
    config.credential = None
    config.is_enrolled = False
    _delete_credential_file()
    logger.info("Credential cleared from config and file")


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "ensure_key_exists",
    "encrypt_credential",
    "decrypt_credential",
    "store_credential",
    "load_credential",
    "clear_credential",
]