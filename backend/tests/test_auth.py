"""
CyberGuard AI — Authentication & Slug Generation Regression Tests
============================================================================
Verifies:
1. Individual registration automatically derives public slug '<name>-user-<6digits>'.
2. Analyst registration automatically derives public slug '<name>-analyst-<6digits>'.
3. Slug collisions generate distinct random suffix pins.
"""
import re
import pytest
from app.services import user_service
from app.models.enums import UserStatus
from app.models.user import User


def test_user_registration_generates_public_slug(db_session):
    user = user_service.create_user(
        db_session,
        email="sarah.connor@example.com",
        password="Password123!@#",
        full_name="Sarah Connor",
        role="individual",
        status=UserStatus.PENDING_VERIFICATION,
    )
    db_session.commit()

    assert user.email == "sarah.connor@example.com"
    assert user.role == "individual"
    assert user.public_user_id is not None
    assert re.match(r"^sarah-connor-user-\d{6}$", user.public_user_id), f"Invalid slug pattern: {user.public_user_id}"


def test_analyst_registration_slug(db_session):
    analyst = user_service.create_user(
        db_session,
        email="marcus.vance@example.com",
        password="Password123!@#",
        full_name="Marcus Vance",
        role="analyst",
        status=UserStatus.PENDING_VERIFICATION,
    )
    db_session.commit()

    assert analyst.role == "analyst"
    assert analyst.public_user_id is not None
    assert re.match(r"^marcus-vance-analyst-\d{6}$", analyst.public_user_id), f"Invalid analyst slug pattern: {analyst.public_user_id}"


def test_slug_uniqueness_on_name_collision(db_session):
    user1 = user_service.create_user(
        db_session,
        email="john.doe.1@example.com",
        password="Password123!@#",
        full_name="John Doe",
        role="individual",
    )
    user2 = user_service.create_user(
        db_session,
        email="john.doe.2@example.com",
        password="Password123!@#",
        full_name="John Doe",
        role="individual",
    )
    db_session.commit()

    assert user1.public_user_id != user2.public_user_id
    assert user1.public_user_id.startswith("john-doe-user-")
    assert user2.public_user_id.startswith("john-doe-user-")
