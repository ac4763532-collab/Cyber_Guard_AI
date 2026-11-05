"""
CyberGuard AI - User Repository

Database operations for User entities.
Handles persistent storage of users when database is enabled.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import structlog

from app.database.connection import get_database
from app.auth.models import User, UserRole


logger = structlog.get_logger(__name__)


class UserRepository:
    """Repository for User database operations."""

    def __init__(self):
        self.db = get_database()

    async def create(
        self,
        username: str,
        email: str | None,
        full_name: str | None,
        role: UserRole,
        password_hash: str | None = None,
        password_salt: str | None = None,
        firebase_uid: str | None = None,
        auth_provider: str = "local",
        organization_id: str | None = None,
    ) -> User | None:
        """Create a new user."""
        user_id = str(uuid4())
        now = datetime.now(timezone.utc)

        # Set permissions based on role
        permissions = self._get_role_permissions(role)

        query = """
            INSERT INTO users (
                id, username, email, full_name, role, is_active,
                password_hash, password_salt, firebase_uid, auth_provider,
                organization_id,
                can_create_alerts, can_manage_incidents, can_run_analysis, can_manage_users,
                created_at, updated_at
            )
            VALUES (
                %(id)s, %(username)s, %(email)s, %(full_name)s, %(role)s, true,
                %(password_hash)s, %(password_salt)s, %(firebase_uid)s, %(auth_provider)s,
                %(organization_id)s,
                %(can_create_alerts)s, %(can_manage_incidents)s, %(can_run_analysis)s, %(can_manage_users)s,
                %(created_at)s, %(updated_at)s
            )
            ON CONFLICT (username) DO NOTHING
            RETURNING *
        """

        try:
            result = await self.db.execute_one(query, {
                "id": user_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role.value,
                "password_hash": password_hash,
                "password_salt": password_salt,
                "firebase_uid": firebase_uid,
                "auth_provider": auth_provider,
                "organization_id": organization_id,
                "created_at": now,
                "updated_at": now,
                **permissions,
            })

            if result:
                logger.info("User created in database", user_id=user_id, username=username)
                return self._row_to_user(result)
            return None

        except Exception as e:
            logger.error("Failed to create user", error=str(e), username=username)
            return None

    async def get(self, user_id: str) -> User | None:
        """Get a user by ID."""
        query = "SELECT * FROM users WHERE id = %(id)s"
        result = await self.db.execute_one(query, {"id": user_id})
        return self._row_to_user(result) if result else None

    async def get_by_username(self, username: str) -> User | None:
        """Get a user by username (case-insensitive)."""
        query = "SELECT * FROM users WHERE LOWER(username) = LOWER(%(username)s)"
        result = await self.db.execute_one(query, {"username": username})
        return self._row_to_user(result) if result else None

    async def get_by_email(self, email: str) -> User | None:
        """Get a user by email (case-insensitive)."""
        query = "SELECT * FROM users WHERE LOWER(email) = LOWER(%(email)s)"
        result = await self.db.execute_one(query, {"email": email})
        return self._row_to_user(result) if result else None

    async def get_by_firebase_uid(self, firebase_uid: str) -> User | None:
        """Get a user by Firebase UID."""
        query = "SELECT * FROM users WHERE firebase_uid = %(firebase_uid)s"
        result = await self.db.execute_one(query, {"firebase_uid": firebase_uid})
        return self._row_to_user(result) if result else None

    async def get_with_password(self, username: str) -> dict[str, Any] | None:
        """
        Get a user with password hash for authentication.

        Bug fix: this previously omitted organization_id from the SELECT
        list, so every successful DB-mode login
        (UserManager.authenticate_async -> this method ->
        _row_to_user(user_data)) silently baked organization_id=None into
        the returned User/JWT regardless of what was actually stored on
        the row. For any non-admin, that organization_id is then the sole
        tenant scope get_authorized_tenant_ids() (app/api/v1/logs.py) uses
        - so a correctly-provisioned analyst/viewer with a real
        organization_id would still get 400 "no organization assigned" on
        every tenant-scoped endpoint (GET /events, /logs/*, etc.) after
        logging in. Admins were unaffected (they bypass tenant scoping
        entirely). Found while verifying the Events page pagination fix
        with a fresh DB-backed test user.
        """
        query = """
            SELECT id, username, email, full_name, role, is_active,
                   password_hash, password_salt, firebase_uid, auth_provider,
                   can_create_alerts, can_manage_incidents, can_run_analysis, can_manage_users,
                   organization_id, created_at, updated_at, last_login
            FROM users
            WHERE LOWER(username) = LOWER(%(username)s)
        """
        return await self.db.execute_one(query, {"username": username})

    async def list(self, limit: int = 50, offset: int = 0) -> list[User]:
        """List all users."""
        query = """
            SELECT * FROM users
            WHERE is_active = true
            ORDER BY created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        results = await self.db.execute(query, {"limit": limit, "offset": offset})
        return [self._row_to_user(row) for row in results]

    async def update(self, user_id: str, updates: dict[str, Any]) -> User | None:
        """Update a user."""
        allowed_fields = ["email", "full_name", "is_active", "role", "last_login", "organization_id"]
        set_clauses = []
        params: dict[str, Any] = {"id": user_id}

        for field in allowed_fields:
            if field in updates:
                set_clauses.append(f"{field} = %({field})s")
                params[field] = updates[field]
                if field == "role" and isinstance(updates[field], UserRole):
                    params[field] = updates[field].value

        if not set_clauses:
            return await self.get(user_id)

        query = f"""
            UPDATE users
            SET {", ".join(set_clauses)}
            WHERE id = %(id)s
            RETURNING *
        """

        result = await self.db.execute_one(query, params)
        return self._row_to_user(result) if result else None

    async def update_password(
        self,
        user_id: str,
        password_hash: str,
        password_salt: str,
    ) -> bool:
        """Update a user's password."""
        query = """
            UPDATE users
            SET password_hash = %(password_hash)s, password_salt = %(password_salt)s
            WHERE id = %(id)s
        """
        try:
            await self.db.execute(query, {
                "id": user_id,
                "password_hash": password_hash,
                "password_salt": password_salt,
            })
            return True
        except Exception as e:
            logger.error("Failed to update password", error=str(e), user_id=user_id)
            return False

    async def update_last_login(self, user_id: str) -> None:
        """Update the last login timestamp."""
        query = "UPDATE users SET last_login = %(last_login)s WHERE id = %(id)s"
        await self.db.execute(query, {
            "id": user_id,
            "last_login": datetime.now(timezone.utc),
        })

    async def deactivate(self, user_id: str) -> bool:
        """Soft delete a user (set is_active = false)."""
        query = "UPDATE users SET is_active = false WHERE id = %(id)s"
        try:
            await self.db.execute(query, {"id": user_id})
            return True
        except Exception as e:
            logger.error("Failed to deactivate user", error=str(e), user_id=user_id)
            return False

    async def count(self) -> int:
        """Count total users."""
        query = "SELECT COUNT(*) as count FROM users WHERE is_active = true"
        result = await self.db.execute_one(query, {})
        return result["count"] if result else 0

    def _get_role_permissions(self, role: UserRole) -> dict[str, bool]:
        """Get default permissions for a role."""
        if role == UserRole.ADMIN:
            return {
                "can_create_alerts": True,
                "can_manage_incidents": True,
                "can_run_analysis": True,
                "can_manage_users": True,
            }
        elif role == UserRole.ANALYST:
            return {
                "can_create_alerts": True,
                "can_manage_incidents": True,
                "can_run_analysis": True,
                "can_manage_users": False,
            }
        elif role == UserRole.VIEWER:
            return {
                "can_create_alerts": False,
                "can_manage_incidents": False,
                "can_run_analysis": False,
                "can_manage_users": False,
            }
        else:  # API
            return {
                "can_create_alerts": False,
                "can_manage_incidents": False,
                "can_run_analysis": True,
                "can_manage_users": False,
            }

    def _row_to_user(self, row: dict[str, Any]) -> User:
        """Convert database row to User model."""
        return User(
            id=str(row["id"]),
            username=row["username"],
            email=row.get("email"),
            full_name=row.get("full_name"),
            role=UserRole(row["role"]),
            is_active=row.get("is_active", True),
            created_at=row["created_at"],
            last_login=row.get("last_login"),
            can_create_alerts=row.get("can_create_alerts", False),
            can_manage_incidents=row.get("can_manage_incidents", False),
            can_run_analysis=row.get("can_run_analysis", False),
            can_manage_users=row.get("can_manage_users", False),
            organization_id=row.get("organization_id"),
        )


# Singleton
_user_repo: UserRepository | None = None


def get_user_repository() -> UserRepository:
    """Get the user repository."""
    global _user_repo
    if _user_repo is None:
        _user_repo = UserRepository()
    return _user_repo
