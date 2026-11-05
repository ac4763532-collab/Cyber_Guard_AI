"""
CyberGuard AI - Token Encryption Service

Secure encryption/decryption for OAuth tokens using Fernet (AES-128-CBC with HMAC).
Never stores or logs plaintext tokens.
"""

from __future__ import annotations

import structlog
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


logger = structlog.get_logger(__name__)


class TokenEncryptionService:
    """
    Encrypts and decrypts OAuth tokens using Fernet symmetric encryption.

    Security:
    - Uses Fernet (AES-128-CBC + HMAC-SHA256)
    - Key loaded from environment variable
    - Tokens encrypted at rest
    - Decryption only when needed for API calls
    - Never logs token values
    """

    def __init__(self):
        self._settings = get_settings()
        self._fernet: Fernet | None = None
        self._initialized = False

    def _get_fernet(self) -> Fernet:
        """Get Fernet instance, initializing if needed."""
        if self._fernet is None:
            key = self._settings.token_encryption_key
            if not key:
                raise ValueError(
                    "TOKEN_ENCRYPTION_KEY not configured. "
                    "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
                )
            try:
                self._fernet = Fernet(key.encode())
                self._initialized = True
            except Exception as e:
                logger.error("Invalid encryption key format")
                raise ValueError("Invalid TOKEN_ENCRYPTION_KEY format") from e

        return self._fernet

    @property
    def is_configured(self) -> bool:
        """Check if encryption is properly configured."""
        return bool(self._settings.token_encryption_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a token value.

        Args:
            plaintext: The token to encrypt (access_token or refresh_token)

        Returns:
            Base64-encoded encrypted string safe for database storage
        """
        if not plaintext:
            return ""

        fernet = self._get_fernet()
        encrypted = fernet.encrypt(plaintext.encode())
        return encrypted.decode()  # Return as string for DB storage

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a token value.

        Args:
            ciphertext: The encrypted token from database

        Returns:
            Decrypted plaintext token

        Raises:
            ValueError: If decryption fails (invalid key or corrupted data)
        """
        if not ciphertext:
            return ""

        fernet = self._get_fernet()
        try:
            decrypted = fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except InvalidToken:
            logger.error("Token decryption failed - invalid key or corrupted data")
            raise ValueError("Failed to decrypt token - key may have changed")


# Singleton
_encryption_service: TokenEncryptionService | None = None


def get_token_encryption_service() -> TokenEncryptionService:
    """Get the token encryption service."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = TokenEncryptionService()
    return _encryption_service
