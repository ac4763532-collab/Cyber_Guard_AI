"""
CyberGuard AI - Firebase Token Verification

Verifies Firebase ID tokens and bridges Firebase users to the application.
"""

from typing import Any
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)

# Firebase Admin SDK - initialized lazily
_firebase_app = None
_firebase_initialized = False


def _init_firebase() -> bool:
    """
    Initialize Firebase Admin SDK.

    Uses Application Default Credentials or service account.
    Returns True if initialization succeeded.
    """
    global _firebase_app, _firebase_initialized

    if _firebase_initialized:
        return _firebase_app is not None

    _firebase_initialized = True
    settings = get_settings()

    # Check if Firebase is configured
    if not settings.firebase_project_id:
        logger.info("Firebase not configured - token verification disabled")
        return False

    try:
        import firebase_admin
        from firebase_admin import credentials

        # Try service account file first
        if settings.firebase_service_account_path:
            cred = credentials.Certificate(settings.firebase_service_account_path)
            _firebase_app = firebase_admin.initialize_app(cred)
            logger.info(
                "Firebase initialized with service account",
                project_id=settings.firebase_project_id
            )
        else:
            # Use project ID only (for environments with ADC)
            _firebase_app = firebase_admin.initialize_app(
                options={"projectId": settings.firebase_project_id}
            )
            logger.info(
                "Firebase initialized with project ID",
                project_id=settings.firebase_project_id
            )

        return True

    except ImportError:
        logger.warning("firebase-admin package not installed")
        return False
    except Exception as e:
        logger.error("Firebase initialization failed", error=str(e))
        return False


def is_firebase_enabled() -> bool:
    """Check if Firebase is available for token verification."""
    return _init_firebase()


class FirebaseUser:
    """Represents a verified Firebase user."""

    def __init__(
        self,
        uid: str,
        email: str | None,
        email_verified: bool,
        name: str | None,
        picture: str | None,
        provider: str,
        claims: dict[str, Any],
    ):
        self.uid = uid
        self.email = email
        self.email_verified = email_verified
        self.name = name
        self.picture = picture
        self.provider = provider
        self.claims = claims

        # Extract custom claims
        self.role = claims.get("role", "viewer")
        self.permissions = claims.get("permissions", [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "email": self.email,
            "email_verified": self.email_verified,
            "name": self.name,
            "picture": self.picture,
            "provider": self.provider,
            "role": self.role,
            "permissions": self.permissions,
        }


class FirebaseVerificationError(Exception):
    """Raised when Firebase token verification fails."""

    def __init__(self, message: str, code: str = "invalid_token"):
        self.message = message
        self.code = code
        super().__init__(message)


async def verify_firebase_token(id_token: str) -> FirebaseUser:
    """
    Verify a Firebase ID token and return user information.

    Args:
        id_token: The Firebase ID token from the frontend

    Returns:
        FirebaseUser with verified user information

    Raises:
        FirebaseVerificationError: If verification fails
    """
    if not _init_firebase():
        raise FirebaseVerificationError(
            "Firebase is not configured",
            code="firebase_not_configured"
        )

    try:
        from firebase_admin import auth

        # Verify the token
        decoded_token = auth.verify_id_token(id_token)

        # Extract user information
        uid = decoded_token["uid"]
        email = decoded_token.get("email")
        email_verified = decoded_token.get("email_verified", False)
        name = decoded_token.get("name")
        picture = decoded_token.get("picture")

        # Determine auth provider
        provider = "email"
        sign_in_provider = decoded_token.get("firebase", {}).get("sign_in_provider", "")
        if "google" in sign_in_provider:
            provider = "google"
        elif "phone" in sign_in_provider:
            provider = "phone"

        # Get custom claims (excluding standard fields)
        standard_claims = {
            "iss", "aud", "auth_time", "user_id", "sub", "iat", "exp",
            "email", "email_verified", "firebase", "uid", "name", "picture"
        }
        custom_claims = {
            k: v for k, v in decoded_token.items()
            if k not in standard_claims
        }

        logger.info(
            "Firebase token verified",
            uid=uid,
            email=email,
            provider=provider,
            has_custom_claims=bool(custom_claims)
        )

        return FirebaseUser(
            uid=uid,
            email=email,
            email_verified=email_verified,
            name=name,
            picture=picture,
            provider=provider,
            claims=custom_claims,
        )

    except ImportError:
        raise FirebaseVerificationError(
            "firebase-admin package not installed",
            code="package_not_installed"
        )
    except auth.ExpiredIdTokenError:
        raise FirebaseVerificationError(
            "Token has expired",
            code="token_expired"
        )
    except auth.RevokedIdTokenError:
        raise FirebaseVerificationError(
            "Token has been revoked",
            code="token_revoked"
        )
    except auth.InvalidIdTokenError as e:
        raise FirebaseVerificationError(
            f"Invalid token: {str(e)}",
            code="invalid_token"
        )
    except Exception as e:
        logger.error("Token verification failed", error=str(e))
        raise FirebaseVerificationError(
            f"Verification failed: {str(e)}",
            code="verification_failed"
        )


async def set_user_claims(uid: str, claims: dict[str, Any]) -> None:
    """
    Set custom claims on a Firebase user.

    Use this to set roles and permissions that will be included
    in future ID tokens.

    Args:
        uid: Firebase user ID
        claims: Custom claims to set (e.g., {"role": "admin"})
    """
    if not _init_firebase():
        raise FirebaseVerificationError(
            "Firebase is not configured",
            code="firebase_not_configured"
        )

    try:
        from firebase_admin import auth

        auth.set_custom_user_claims(uid, claims)
        logger.info("Custom claims set", uid=uid, claims=list(claims.keys()))

    except Exception as e:
        logger.error("Failed to set custom claims", uid=uid, error=str(e))
        raise FirebaseVerificationError(
            f"Failed to set claims: {str(e)}",
            code="claims_failed"
        )


async def get_firebase_user(uid: str) -> dict[str, Any] | None:
    """
    Get a Firebase user by UID.

    Args:
        uid: Firebase user ID

    Returns:
        User record as dictionary, or None if not found
    """
    if not _init_firebase():
        return None

    try:
        from firebase_admin import auth

        user = auth.get_user(uid)
        return {
            "uid": user.uid,
            "email": user.email,
            "email_verified": user.email_verified,
            "display_name": user.display_name,
            "photo_url": user.photo_url,
            "disabled": user.disabled,
            "custom_claims": user.custom_claims or {},
        }

    except auth.UserNotFoundError:
        return None
    except Exception as e:
        logger.error("Failed to get Firebase user", uid=uid, error=str(e))
        return None
