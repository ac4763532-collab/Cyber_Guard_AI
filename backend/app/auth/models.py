"""
CyberGuard AI - Authentication Models

User and token models for authentication.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, EmailStr


class UserRole(str, Enum):
    """User roles for authorization."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API = "api"


class User(BaseModel):
    """User model."""

    id: str
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    role: UserRole = UserRole.VIEWER
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None

    # Tenant/organization membership. NULL for ADMIN is fine (admin sees
    # all tenants regardless - see get_authorized_tenant_ids). For any
    # other role this is the single tenant the user is scoped to; it is
    # the server-side source of truth for tenant-scoped queries (e.g.
    # GET /logs/sources) and is never trusted from client input.
    organization_id: str | None = None

    # Permissions
    can_create_alerts: bool = False
    can_run_analysis: bool = False
    can_manage_users: bool = False

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        if self.role == UserRole.ADMIN:
            return True

        permission_map = {
            "create_alerts": self.can_create_alerts,
            "run_analysis": self.can_run_analysis,
            "manage_users": self.can_manage_users,
        }

        return permission_map.get(permission, False)


class UserCreate(BaseModel):
    """Schema for creating a user."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: EmailStr | None = None
    full_name: str | None = None
    role: UserRole = UserRole.VIEWER
    organization_id: str | None = Field(
        None,
        description="Tenant/organization to assign this user to. Admins may omit this.",
    )


class UserLogin(BaseModel):
    """Schema for user login."""

    username: str
    password: str


class Token(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Data extracted from JWT token."""

    user_id: str
    username: str
    role: UserRole
    exp: datetime
    organization_id: str | None = None
