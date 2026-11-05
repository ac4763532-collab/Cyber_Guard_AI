"""
CyberGuard AI - Ingestion API Key Management (STEP 8.4)

Machine-to-machine credentials for automated log ingestion.

These credentials are:
- Source-scoped: bound to a specific LogSource
- Tenant-scoped: bound to the source's organization_id
- Revocable: can be disabled without deleting
- Rotatable: new keys can be created, old ones revoked
- Secure: stored as hashed values, never logged

Security:
- Raw API key is shown ONCE at creation time
- Only a hash/fingerprint is stored
- Keys are never logged or exposed in API responses
- Keys can be revoked immediately
"""

import hashlib
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, SecretStr
import structlog


logger = structlog.get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

# API key prefix for identification
API_KEY_PREFIX = "cg_"

# Length of the random part of the key
API_KEY_LENGTH = 32

# Hash algorithm for key storage
HASH_ALGORITHM = "sha256"


# =============================================================================
# Models
# =============================================================================


class IngestionKeyStatus(str, Enum):
    """Status of an ingestion API key."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class IngestionApiKey(BaseModel):
    """
    Ingestion API key for machine-to-machine authentication.

    The actual key value is NOT stored - only a hash for verification.
    """

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique key ID",
    )

    # Binding
    source_id: str = Field(
        ...,
        description="LogSource this key authenticates for",
    )
    organization_id: str = Field(
        ...,
        description="Organization/tenant this key belongs to",
    )

    # Key identification (NOT the actual key)
    key_prefix: str = Field(
        ...,
        description="First 8 chars of the key for identification",
    )
    key_hash: str = Field(
        ...,
        description="SHA-256 hash of the full key",
    )

    # Metadata
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable name for this key",
    )
    description: str | None = Field(
        None,
        max_length=1000,
        description="Description of key purpose",
    )

    # Status
    status: IngestionKeyStatus = Field(
        default=IngestionKeyStatus.ACTIVE,
        description="Current key status",
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    expires_at: datetime | None = Field(
        None,
        description="Optional expiration time",
    )
    last_used_at: datetime | None = Field(
        None,
        description="Last successful authentication",
    )
    revoked_at: datetime | None = Field(
        None,
        description="When the key was revoked",
    )

    # Usage stats
    use_count: int = Field(
        default=0,
        description="Number of successful authentications",
    )

    # Creator
    created_by: str | None = Field(
        None,
        description="User who created this key",
    )

    def is_valid(self) -> bool:
        """Check if key is currently valid."""
        if self.status != IngestionKeyStatus.ACTIVE:
            return False

        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes key_hash for security)."""
        return {
            "id": self.id,
            "source_id": self.source_id,
            "organization_id": self.organization_id,
            "key_prefix": self.key_prefix,
            # key_hash intentionally excluded
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "use_count": self.use_count,
            "created_by": self.created_by,
        }


class IngestionKeyCreate(BaseModel):
    """Request to create a new ingestion API key."""

    source_id: str = Field(
        ...,
        description="LogSource this key will authenticate for",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable name",
    )
    description: str | None = Field(
        None,
        max_length=1000,
    )
    expires_in_days: int | None = Field(
        None,
        ge=1,
        le=365,
        description="Days until expiration (None = no expiration)",
    )


class IngestionKeyCreated(BaseModel):
    """
    Response when a new key is created.

    IMPORTANT: The raw_key is shown ONLY ONCE at creation time.
    Store it securely - it cannot be retrieved again.
    """

    id: str
    source_id: str
    organization_id: str
    name: str
    key_prefix: str
    raw_key: str = Field(
        ...,
        description="The actual API key - SHOWN ONLY ONCE",
    )
    created_at: datetime
    expires_at: datetime | None


# =============================================================================
# Key Generation and Verification
# =============================================================================


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        (full_key, key_prefix, key_hash)
    """
    # Generate random bytes
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)

    # Create full key with prefix
    full_key = f"{API_KEY_PREFIX}{random_part}"

    # Extract prefix for identification (first 8 chars after cg_)
    key_prefix = full_key[:len(API_KEY_PREFIX) + 8]

    # Hash for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()

    return full_key, key_prefix, key_hash


def hash_api_key(key: str) -> str:
    """Hash an API key for verification."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key: str, stored_hash: str) -> bool:
    """
    Verify an API key against stored hash.

    Uses constant-time comparison to prevent timing attacks.
    """
    computed_hash = hash_api_key(key)
    return secrets.compare_digest(computed_hash, stored_hash)


def verify_source_tenant_match(source: Any, key: IngestionApiKey) -> None:
    """
    Verify an IngestionApiKey is authorized to write to a given LogSource.

    STEP 4 (Secure Ingestion + Tenant Isolation): shared helper extracted
    from the ownership check already enforced in
    app.api.v1.web_ingest.ingest_log (the original, proven pattern) so
    app.api.v1.logs's /ingest and /ingest/raw enforce the exact same rule
    instead of duplicating it.

    `source` is typed as Any to avoid a reverse import onto
    app.logs.models.LogSource from this lower-level auth module; callers
    pass the real LogSource and only its `.id` / `.organization_id`
    attributes are read.

    Raises:
        PermissionError: if the key is not authorized for this source,
            i.e. the source does not exist (source is None) or the
            source's organization_id does not match the key's
            organization_id. Callers map this to HTTP 403 without
            revealing *why* (don't distinguish "no such source" from
            "wrong tenant" in the HTTP response - see Part 12).
    """
    if source is None:
        raise PermissionError("LogSource not found or not authorized for this API key")

    if getattr(source, "organization_id", None) != key.organization_id:
        logger.warning(
            "Ingestion key tenant mismatch",
            key_id=key.id,
            key_organization_id=key.organization_id,
            source_id=getattr(source, "id", None),
            source_organization_id=getattr(source, "organization_id", None),
        )
        raise PermissionError("LogSource not authorized for this API key")


# =============================================================================
# Repository
# =============================================================================


class IngestionKeyRepository:
    """
    Repository for ingestion API keys.

    Uses PostgreSQL for persistent storage.
    """

    _instance: "IngestionKeyRepository | None" = None

    def __init__(self):
        self._keys: dict[str, IngestionApiKey] = {}  # In-memory cache

    @classmethod
    def get_instance(cls) -> "IngestionKeyRepository":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def create(
        self,
        create_request: IngestionKeyCreate,
        organization_id: str,
        created_by: str | None = None,
    ) -> tuple[IngestionApiKey, str]:
        """
        Create a new ingestion API key.

        Returns:
            (key_record, raw_key) - raw_key is returned only at creation
        """
        from datetime import timedelta

        # Generate key
        raw_key, key_prefix, key_hash = generate_api_key()

        # Calculate expiration
        expires_at = None
        if create_request.expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=create_request.expires_in_days
            )

        # Create record
        key_record = IngestionApiKey(
            source_id=create_request.source_id,
            organization_id=organization_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=create_request.name,
            description=create_request.description,
            expires_at=expires_at,
            created_by=created_by,
        )

        # Persist to database
        await self._save_to_db(key_record)

        # Cache
        self._keys[key_record.id] = key_record

        logger.info(
            "Created ingestion API key",
            key_id=key_record.id,
            source_id=key_record.source_id,
            organization_id=key_record.organization_id,
            # Never log the raw key
        )

        return key_record, raw_key

    async def get(self, key_id: str) -> IngestionApiKey | None:
        """Get a key by ID."""
        # Check cache
        if key_id in self._keys:
            return self._keys[key_id]

        # Load from database
        key = await self._load_from_db(key_id)
        if key:
            self._keys[key_id] = key

        return key

    async def get_by_hash(self, key_hash: str) -> IngestionApiKey | None:
        """Get a key by its hash (for authentication)."""
        # Check cache first
        for key in self._keys.values():
            if key.key_hash == key_hash:
                return key

        # Load from database
        return await self._load_by_hash_from_db(key_hash)

    async def authenticate(self, raw_key: str) -> IngestionApiKey | None:
        """
        Authenticate using a raw API key.

        Returns the key record if valid, None otherwise.
        """
        # Hash the provided key
        key_hash = hash_api_key(raw_key)

        # Look up by hash
        key = await self.get_by_hash(key_hash)

        if not key:
            logger.warning(
                "Ingestion authentication failed: key not found",
                key_prefix=raw_key[:len(API_KEY_PREFIX) + 8] if len(raw_key) > 10 else "invalid",
            )
            return None

        # Check validity
        if not key.is_valid():
            logger.warning(
                "Ingestion authentication failed: key invalid",
                key_id=key.id,
                status=key.status.value,
            )
            return None

        # Update last used
        key.last_used_at = datetime.now(timezone.utc)
        key.use_count += 1
        await self._update_usage(key)

        return key

    async def list_by_source(self, source_id: str) -> list[IngestionApiKey]:
        """List all keys for a source."""
        return await self._list_by_source_from_db(source_id)

    async def list_by_organization(self, organization_id: str) -> list[IngestionApiKey]:
        """List all keys for an organization."""
        return await self._list_by_org_from_db(organization_id)

    async def revoke(self, key_id: str) -> bool:
        """Revoke a key."""
        key = await self.get(key_id)
        if not key:
            return False

        key.status = IngestionKeyStatus.REVOKED
        key.revoked_at = datetime.now(timezone.utc)

        await self._update_status(key)

        logger.info(
            "Revoked ingestion API key",
            key_id=key_id,
            source_id=key.source_id,
        )

        return True

    async def delete(self, key_id: str) -> bool:
        """Delete a key permanently."""
        key = await self.get(key_id)
        if not key:
            return False

        await self._delete_from_db(key_id)
        self._keys.pop(key_id, None)

        logger.info(
            "Deleted ingestion API key",
            key_id=key_id,
        )

        return True

    # -------------------------------------------------------------------------
    # Database operations
    # -------------------------------------------------------------------------

    async def _save_to_db(self, key: IngestionApiKey) -> None:
        """Save key to database."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO ingestion_api_keys (
                    id, source_id, organization_id, key_prefix, key_hash,
                    name, description, status, created_at, expires_at,
                    last_used_at, revoked_at, use_count, created_by
                ) VALUES (
                    %(id)s, %(source_id)s, %(organization_id)s, %(key_prefix)s,
                    %(key_hash)s, %(name)s, %(description)s, %(status)s,
                    %(created_at)s, %(expires_at)s, %(last_used_at)s,
                    %(revoked_at)s, %(use_count)s, %(created_by)s
                )
                """,
                {
                    "id": key.id,
                    "source_id": key.source_id,
                    "organization_id": key.organization_id,
                    "key_prefix": key.key_prefix,
                    "key_hash": key.key_hash,
                    "name": key.name,
                    "description": key.description,
                    "status": key.status.value,
                    "created_at": key.created_at,
                    "expires_at": key.expires_at,
                    "last_used_at": key.last_used_at,
                    "revoked_at": key.revoked_at,
                    "use_count": key.use_count,
                    "created_by": key.created_by,
                },
            )

    async def _load_from_db(self, key_id: str) -> IngestionApiKey | None:
        """Load key from database by ID."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM ingestion_api_keys WHERE id = %s",
                    (key_id,),
                )
                row = await cur.fetchone()
                if row:
                    return self._row_to_key(row, cur.description)
        return None

    async def _load_by_hash_from_db(self, key_hash: str) -> IngestionApiKey | None:
        """Load key from database by hash."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM ingestion_api_keys WHERE key_hash = %s",
                    (key_hash,),
                )
                row = await cur.fetchone()
                if row:
                    key = self._row_to_key(row, cur.description)
                    self._keys[key.id] = key  # Cache
                    return key
        return None

    async def _list_by_source_from_db(self, source_id: str) -> list[IngestionApiKey]:
        """List keys by source from database."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM ingestion_api_keys WHERE source_id = %s ORDER BY created_at DESC",
                    (source_id,),
                )
                rows = await cur.fetchall()
                return [self._row_to_key(row, cur.description) for row in rows]

    async def _list_by_org_from_db(self, organization_id: str) -> list[IngestionApiKey]:
        """List keys by organization from database."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT * FROM ingestion_api_keys WHERE organization_id = %s ORDER BY created_at DESC",
                    (organization_id,),
                )
                rows = await cur.fetchall()
                return [self._row_to_key(row, cur.description) for row in rows]

    async def _update_usage(self, key: IngestionApiKey) -> None:
        """Update usage statistics."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                UPDATE ingestion_api_keys
                SET last_used_at = %(last_used_at)s, use_count = %(use_count)s
                WHERE id = %(id)s
                """,
                {
                    "id": key.id,
                    "last_used_at": key.last_used_at,
                    "use_count": key.use_count,
                },
            )

    async def _update_status(self, key: IngestionApiKey) -> None:
        """Update key status."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                UPDATE ingestion_api_keys
                SET status = %(status)s, revoked_at = %(revoked_at)s
                WHERE id = %(id)s
                """,
                {
                    "id": key.id,
                    "status": key.status.value,
                    "revoked_at": key.revoked_at,
                },
            )

        # Update cache
        self._keys[key.id] = key

    async def _delete_from_db(self, key_id: str) -> None:
        """Delete key from database."""
        from app.database.connection import get_pool

        pool = await get_pool()
        async with pool.connection() as conn:
            await conn.execute(
                "DELETE FROM ingestion_api_keys WHERE id = %s",
                (key_id,),
            )

    def _row_to_key(self, row: tuple, description: Any) -> IngestionApiKey:
        """Convert database row to IngestionApiKey."""
        columns = [col[0] for col in description]
        data = dict(zip(columns, row))

        return IngestionApiKey(
            id=data["id"],
            source_id=data["source_id"],
            organization_id=data["organization_id"],
            key_prefix=data["key_prefix"],
            key_hash=data["key_hash"],
            name=data["name"],
            description=data.get("description"),
            status=IngestionKeyStatus(data["status"]),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            last_used_at=data.get("last_used_at"),
            revoked_at=data.get("revoked_at"),
            use_count=data.get("use_count", 0),
            created_by=data.get("created_by"),
        )


def get_ingestion_key_repository() -> IngestionKeyRepository:
    """Get the ingestion key repository singleton."""
    return IngestionKeyRepository.get_instance()
