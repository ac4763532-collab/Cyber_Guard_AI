"""
CyberGuard AI - JWT Authentication

JWT token creation and verification.
"""

from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import structlog

from app.config import get_settings
from app.auth.models import TokenData, User, UserRole


logger = structlog.get_logger(__name__)

security = HTTPBearer(auto_error=False)


def create_access_token(
    user_id: str,
    username: str,
    role: UserRole,
    organization_id: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        user_id: User ID
        username: Username
        role: User role
        organization_id: Tenant/organization the user belongs to (None for
            admin or users with no single-tenant restriction)
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token
    """
    settings = get_settings()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    payload = {
        "sub": user_id,
        "username": username,
        "role": role.value,
        "organization_id": organization_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm,
    )

    return token


def verify_token(token: str) -> TokenData | None:
    """
    Verify and decode a JWT token.

    Args:
        token: The JWT token to verify

    Returns:
        TokenData if valid, None otherwise
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
        )

        return TokenData(
            user_id=payload["sub"],
            username=payload["username"],
            role=UserRole(payload["role"]),
            organization_id=payload.get("organization_id"),
            exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid token", error=str(e))
        return None


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> User | None:
    """
    Get the current user from the JWT token.

    This is a soft dependency - returns None if no token provided.
    Use get_current_active_user for required authentication.
    """
    if not credentials:
        return None

    token_data = verify_token(credentials.credentials)
    if not token_data:
        return None

    # Import here to avoid circular imports
    from app.auth.users import get_user_manager

    user_manager = get_user_manager()
    user = user_manager.get_user(token_data.user_id)

    return user


async def get_current_active_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> User:
    """
    Get the current active user (required authentication).

    Raises HTTPException if not authenticated.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.auth.users import get_user_manager

    user_manager = get_user_manager()

    # Try async DB lookup first if DB enabled
    user = await user_manager.get_user_async(token_data.user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )

    return user


def require_role(allowed_roles: list[UserRole]):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role([UserRole.ADMIN]))])
    """
    async def role_checker(
        user: Annotated[User, Depends(get_current_active_user)],
    ) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_checker
