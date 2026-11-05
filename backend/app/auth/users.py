"""
CyberGuard AI - User Management

User storage and authentication logic.
Supports both in-memory (development) and database (production) storage.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import hashlib
import secrets

import structlog

from app.auth.models import User, UserRole, UserCreate
from app.config import get_settings


logger = structlog.get_logger(__name__)


class UserManager:
    """
    User management service.

    Handles user CRUD and authentication.
    Uses database when DB_ENABLED=true, otherwise uses in-memory storage.
    """

    def __init__(self):
        self._settings = get_settings()
        self._db_enabled = self._settings.db_enabled

        # In-memory user storage (fallback when DB disabled)
        self._users: dict[str, dict[str, Any]] = {}
        self._by_username: dict[str, str] = {}  # username -> user_id

        # Only create default users if database is disabled
        if not self._db_enabled:
            self._create_default_users()
        else:
            logger.info("Database enabled - users will be stored in PostgreSQL")

    def _get_db_repo(self):
        """Get database repository (lazy import to avoid circular deps)."""
        from app.database.repositories.users import get_user_repository
        return get_user_repository()

    def _create_default_users(self) -> None:
        """Create default users for development."""
        # Admin user
        admin = self.create_user(UserCreate(
            username="admin",
            password="admin123!",  # Change in production!
            email="admin@cyberguard.example.com",
            full_name="System Administrator",
            role=UserRole.ADMIN,
        ))
        if admin:
            logger.info("Default admin user created", username="admin")

        # Demo analyst user
        analyst = self.create_user(UserCreate(
            username="analyst",
            password="analyst123!",
            email="analyst@cyberguard.example.com",
            full_name="Security Analyst",
            role=UserRole.ANALYST,
        ))
        if analyst:
            logger.info("Default analyst user created", username="analyst")

    def _hash_password(self, password: str, salt: str | None = None) -> tuple[str, str]:
        """Hash a password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)

        # Use PBKDF2-like hashing (simplified for demo)
        salted = f"{salt}:{password}"
        hashed = hashlib.sha256(salted.encode()).hexdigest()

        return hashed, salt

    def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify a password against its hash."""
        check_hash, _ = self._hash_password(password, salt)
        return secrets.compare_digest(check_hash, hashed)

    def create_user(self, user_data: UserCreate) -> User | None:
        """Create a new user (sync, in-memory only)."""
        # Check if username exists
        if user_data.username.lower() in self._by_username:
            logger.warning("Username already exists", username=user_data.username)
            return None

        user_id = str(uuid4())
        password_hash, salt = self._hash_password(user_data.password)

        # Set permissions based on role
        permissions = self._get_role_permissions(user_data.role)

        user_dict = {
            "id": user_id,
            "username": user_data.username,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "role": user_data.role.value,
            "is_active": True,
            "password_hash": password_hash,
            "password_salt": salt,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": None,
            "organization_id": user_data.organization_id,
            **permissions,
        }

        self._users[user_id] = user_dict
        self._by_username[user_data.username.lower()] = user_id

        return self._dict_to_user(user_dict)

    async def create_user_async(self, user_data: UserCreate) -> User | None:
        """Create a new user (async, uses database when DB_ENABLED)."""
        if not self._db_enabled:
            return self.create_user(user_data)

        repo = self._get_db_repo()

        # Check if user already exists
        existing = await repo.get_by_username(user_data.username)
        if existing:
            logger.warning("Username already exists", username=user_data.username)
            return existing

        password_hash, salt = self._hash_password(user_data.password)

        return await repo.create(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            role=user_data.role,
            password_hash=password_hash,
            password_salt=salt,
            organization_id=user_data.organization_id,
        )

    def authenticate(self, username: str, password: str) -> User | None:
        """
        Authenticate a user by username and password.
        Note: For database mode, use authenticate_async() instead.
        """
        user_id = self._by_username.get(username.lower())
        if not user_id:
            return None

        user_dict = self._users.get(user_id)
        if not user_dict:
            return None

        if not user_dict.get("is_active", False):
            return None

        # Firebase users cannot authenticate with password
        if user_dict.get("password_hash") == "FIREBASE_AUTH":
            return None

        if not self._verify_password(
            password,
            user_dict["password_hash"],
            user_dict["password_salt"],
        ):
            return None

        # Update last login
        user_dict["last_login"] = datetime.now(timezone.utc).isoformat()

        return self._dict_to_user(user_dict)

    async def authenticate_async(self, username: str, password: str) -> User | None:
        """Authenticate a user (async version for database mode)."""
        if not self._db_enabled:
            return self.authenticate(username, password)

        repo = self._get_db_repo()
        user_data = await repo.get_with_password(username)

        if not user_data:
            return None

        if not user_data.get("is_active", False):
            return None

        # Firebase users cannot authenticate with password
        if user_data.get("password_hash") == "FIREBASE_AUTH":
            return None

        if not self._verify_password(
            password,
            user_data["password_hash"],
            user_data["password_salt"],
        ):
            return None

        # Update last login
        await repo.update_last_login(str(user_data["id"]))

        return repo._row_to_user(user_data)

    def get_user(self, user_id: str) -> User | None:
        """Get a user by ID."""
        user_dict = self._users.get(user_id)
        if user_dict:
            return self._dict_to_user(user_dict)
        return None

    async def get_user_async(self, user_id: str) -> User | None:
        """Get a user by ID (async version for database)."""
        if not self._db_enabled:
            return self.get_user(user_id)
        repo = self._get_db_repo()
        return await repo.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        """Get a user by username (sync version for in-memory)."""
        user_id = self._by_username.get(username.lower())
        if user_id:
            return self.get_user(user_id)
        return None

    async def get_user_by_username_async(self, username: str) -> User | None:
        """Get a user by username (async version for database)."""
        if not self._db_enabled:
            return self.get_user_by_username(username)
        repo = self._get_db_repo()
        return await repo.get_by_username(username)

    def get_user_by_email(self, email: str) -> User | None:
        """Get a user by email address (sync version)."""
        for user_dict in self._users.values():
            if user_dict.get("email", "").lower() == email.lower():
                return self._dict_to_user(user_dict)
        return None

    async def get_user_by_email_async(self, email: str) -> User | None:
        """Get a user by email address (async version)."""
        if not self._db_enabled:
            return self.get_user_by_email(email)
        repo = self._get_db_repo()
        return await repo.get_by_email(email)

    async def get_user_by_firebase_uid(self, firebase_uid: str) -> User | None:
        """Get a user by Firebase UID."""
        if not self._db_enabled:
            username = f"firebase:{firebase_uid}"
            return self.get_user_by_username(username)
        repo = self._get_db_repo()
        return await repo.get_by_firebase_uid(firebase_uid)
        return None

    def create_firebase_user(
        self,
        firebase_uid: str,
        email: str | None,
        full_name: str | None,
        role: UserRole,
        provider: str,
        organization_id: str | None = None,
    ) -> User | None:
        """
        Create a new user from Firebase authentication.

        Firebase users use 'firebase:{uid}' as their username
        and don't have a password (they authenticate via Firebase).
        """
        # Use Firebase UID as the unique identifier in username
        username = f"firebase:{firebase_uid}"

        # Check if already exists
        if username.lower() in self._by_username:
            logger.warning("Firebase user already exists", firebase_uid=firebase_uid)
            return self.get_user_by_username(username)

        user_id = str(uuid4())

        # Firebase users don't have passwords - use a placeholder
        # They can only authenticate via Firebase tokens
        password_hash = "FIREBASE_AUTH"
        salt = "FIREBASE_AUTH"

        # Set permissions based on role
        permissions = self._get_role_permissions(role)

        user_dict = {
            "id": user_id,
            "username": username,
            "email": email,
            "full_name": full_name,
            "role": role.value,
            "is_active": True,
            "password_hash": password_hash,
            "password_salt": salt,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": datetime.now(timezone.utc).isoformat(),
            "firebase_uid": firebase_uid,
            "auth_provider": provider,
            "organization_id": organization_id,
            **permissions,
        }

        self._users[user_id] = user_dict
        self._by_username[username.lower()] = user_id

        logger.info(
            "Firebase user created",
            user_id=user_id,
            firebase_uid=firebase_uid,
            email=email,
            role=role.value,
        )

        return self._dict_to_user(user_dict)

    async def create_firebase_user_async(
        self,
        firebase_uid: str,
        email: str | None,
        full_name: str | None,
        role: UserRole,
        provider: str,
        organization_id: str | None = None,
    ) -> User | None:
        """Create a Firebase user (async version for database)."""
        if not self._db_enabled:
            return self.create_firebase_user(firebase_uid, email, full_name, role, provider, organization_id)

        repo = self._get_db_repo()

        # Check if user already exists by Firebase UID
        existing = await repo.get_by_firebase_uid(firebase_uid)
        if existing:
            logger.warning("Firebase user already exists", firebase_uid=firebase_uid)
            return existing

        username = f"firebase:{firebase_uid}"

        return await repo.create(
            username=username,
            email=email,
            full_name=full_name,
            role=role,
            password_hash="FIREBASE_AUTH",
            password_salt="FIREBASE_AUTH",
            firebase_uid=firebase_uid,
            auth_provider=provider,
            organization_id=organization_id,
        )

    def list_users(self) -> list[User]:
        """List all users (sync version)."""
        return [self._dict_to_user(u) for u in self._users.values()]

    async def list_users_async(self) -> list[User]:
        """List all users (async version for database)."""
        if not self._db_enabled:
            return self.list_users()
        repo = self._get_db_repo()
        return await repo.list()

    def update_user(
        self,
        user_id: str,
        updates: dict[str, Any],
    ) -> User | None:
        """Update a user."""
        user_dict = self._users.get(user_id)
        if not user_dict:
            return None

        # Update allowed fields
        allowed = ["email", "full_name", "is_active", "role"]
        for key in allowed:
            if key in updates:
                user_dict[key] = updates[key]

        # Handle password change
        if "password" in updates:
            password_hash, salt = self._hash_password(updates["password"])
            user_dict["password_hash"] = password_hash
            user_dict["password_salt"] = salt

        return self._dict_to_user(user_dict)

    def delete_user(self, user_id: str) -> bool:
        """Delete a user (soft delete)."""
        user_dict = self._users.get(user_id)
        if user_dict:
            user_dict["is_active"] = False
            return True
        return False

    def _get_role_permissions(self, role: UserRole) -> dict[str, bool]:
        """Get default permissions for a role."""
        if role == UserRole.ADMIN:
            return {
                "can_create_alerts": True,
                "can_run_analysis": True,
                "can_manage_users": True,
            }
        elif role == UserRole.ANALYST:
            return {
                "can_create_alerts": True,
                "can_run_analysis": True,
                "can_manage_users": False,
            }
        elif role == UserRole.VIEWER:
            return {
                "can_create_alerts": False,
                "can_run_analysis": False,
                "can_manage_users": False,
            }
        else:
            return {
                "can_create_alerts": False,
                "can_run_analysis": True,
                "can_manage_users": False,
            }

    def _dict_to_user(self, user_dict: dict[str, Any]) -> User:
        """Convert user dictionary to User model."""
        return User(
            id=user_dict["id"],
            username=user_dict["username"],
            email=user_dict.get("email"),
            full_name=user_dict.get("full_name"),
            role=UserRole(user_dict["role"]),
            is_active=user_dict.get("is_active", True),
            created_at=datetime.fromisoformat(user_dict["created_at"]) if isinstance(user_dict["created_at"], str) else user_dict["created_at"],
            last_login=datetime.fromisoformat(user_dict["last_login"]) if user_dict.get("last_login") else None,
            can_create_alerts=user_dict.get("can_create_alerts", False),
            can_run_analysis=user_dict.get("can_run_analysis", False),
            can_manage_users=user_dict.get("can_manage_users", False),
            organization_id=user_dict.get("organization_id"),
        )


# Singleton
_user_manager: UserManager | None = None


def get_user_manager() -> UserManager:
    """Get the global user manager."""
    global _user_manager
    if _user_manager is None:
        _user_manager = UserManager()
    return _user_manager
