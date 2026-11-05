"""
CyberGuard AI - Authentication API Endpoints

User authentication and management endpoints.
Supports both local (username/password) and Firebase authentication.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth.jwt import create_access_token, get_current_active_user, require_role
from app.auth.models import User, UserRole, UserCreate, UserLogin, Token
from app.auth.users import get_user_manager
from app.auth.firebase_verify import (
    verify_firebase_token,
    is_firebase_enabled,
    FirebaseVerificationError,
    FirebaseUser,
)
from app.config import get_settings


router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginResponse(BaseModel):
    """Login response with token and user info."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]


class UserResponse(BaseModel):
    """User response (without sensitive data)."""

    id: str
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: str
    last_login: str | None = None
    organization_id: str | None = None


def _user_to_response(user: User) -> UserResponse:
    """Convert User to response model."""
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        last_login=user.last_login.isoformat() if user.last_login else None,
        organization_id=user.organization_id,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login",
    description="Authenticate and receive JWT token.",
)
async def login(credentials: UserLogin) -> LoginResponse:
    """Authenticate user and return JWT token."""
    user_manager = get_user_manager()
    settings = get_settings()

    # Use async authentication when database is enabled
    user = await user_manager.authenticate_async(credentials.username, credentials.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        organization_id=user.organization_id,
    )

    return LoginResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "full_name": user.full_name,
            "organization_id": user.organization_id,
        },
    )


class FirebaseLoginRequest(BaseModel):
    """Request to login with Firebase ID token."""

    id_token: str = Field(..., description="Firebase ID token from frontend")


class FirebaseLoginResponse(BaseModel):
    """Response after Firebase login."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]
    firebase_uid: str
    is_new_user: bool = False


@router.post(
    "/firebase-login",
    response_model=FirebaseLoginResponse,
    summary="Firebase Login",
    description="Authenticate with Firebase ID token and receive backend JWT.",
)
async def firebase_login(request: FirebaseLoginRequest) -> FirebaseLoginResponse:
    """
    Authenticate using Firebase ID token.

    This endpoint:
    1. Verifies the Firebase ID token
    2. Creates/updates the local user record
    3. Returns a backend JWT for API access

    The backend JWT should be used for all subsequent API calls.
    """
    settings = get_settings()

    if not is_firebase_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase authentication is not configured",
        )

    try:
        # Verify Firebase token
        firebase_user: FirebaseUser = await verify_firebase_token(request.id_token)
    except FirebaseVerificationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Find or create local user
    user_manager = get_user_manager()
    is_new_user = False

    # Try to find existing user by Firebase UID
    user = await user_manager.get_user_by_firebase_uid(firebase_user.uid)

    if not user:
        # Check if user exists by email
        if firebase_user.email:
            user = await user_manager.get_user_by_email_async(firebase_user.email)

    if not user:
        # Create new user from Firebase data
        is_new_user = True

        # Map Firebase role claim to local role
        role = UserRole.VIEWER  # Default role
        if firebase_user.role == "admin":
            role = UserRole.ADMIN
        elif firebase_user.role == "analyst":
            role = UserRole.ANALYST

        # Firebase custom claims carry no org/tenant field today (see
        # app/auth/firebase_verify.py::FirebaseUser) - fall back to the
        # same default tenant assigned to other non-admin accounts.
        # Admins have no single-tenant restriction (organization_id=None).
        organization_id = None if role == UserRole.ADMIN else settings.default_organization_id

        # Create user with Firebase UID as username
        user = await user_manager.create_firebase_user_async(
            firebase_uid=firebase_user.uid,
            email=firebase_user.email,
            full_name=firebase_user.name,
            role=role,
            provider=firebase_user.provider,
            organization_id=organization_id,
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user account",
            )

    # Create backend JWT
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        organization_id=user.organization_id,
    )

    return FirebaseLoginResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "full_name": user.full_name,
            "organization_id": user.organization_id,
        },
        firebase_uid=firebase_user.uid,
        is_new_user=is_new_user,
    )


@router.get(
    "/firebase-status",
    summary="Firebase Status",
    description="Check if Firebase authentication is enabled.",
)
async def firebase_status() -> dict[str, Any]:
    """Check Firebase authentication status."""
    settings = get_settings()
    return {
        "enabled": is_firebase_enabled(),
        "project_id": settings.firebase_project_id or None,
    }


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User",
    description="Get the currently authenticated user's profile.",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> UserResponse:
    """Get current user profile."""
    return _user_to_response(current_user)


@router.post(
    "/register",
    response_model=UserResponse,
    summary="Register User",
    description="Register a new user (admin only in production).",
)
async def register(user_data: UserCreate) -> UserResponse:
    """Register a new user."""
    user_manager = get_user_manager()
    settings = get_settings()

    # In production, this should require admin privileges
    # For demo, allow open registration

    # Default non-admin registrations to the shared default tenant when
    # the caller didn't specify one, so they aren't left with no
    # organization_id (which would 400 on tenant-scoped queries like
    # GET /logs/sources - see get_authorized_tenant_ids).
    if user_data.organization_id is None and user_data.role != UserRole.ADMIN:
        user_data.organization_id = settings.default_organization_id

    user = user_manager.create_user(user_data)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    return _user_to_response(user)


@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List Users",
    description="List all users (admin only).",
    dependencies=[Depends(require_role([UserRole.ADMIN]))],
)
async def list_users() -> list[UserResponse]:
    """List all users (admin only)."""
    user_manager = get_user_manager()
    users = await user_manager.list_users_async()
    return [_user_to_response(u) for u in users]


@router.get(
    "/verify",
    summary="Verify Token",
    description="Verify if the current token is valid.",
)
async def verify_token(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> dict[str, Any]:
    """Verify token validity."""
    return {
        "valid": True,
        "user_id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.value,
    }
