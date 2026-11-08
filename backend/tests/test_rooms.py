"""
CyberGuard AI — Room Creation & Direct Join Regression Tests
============================================================================
Verifies:
1. Room creation generates public code with prefix 'ROOM-'.
2. Direct join with invalid password raises InvalidCredentialsError.
3. Direct join with correct password successfully joins and records member role.
4. Redundant direct join is idempotent (already_member=True).
5. Room list returns newly joined rooms for user.
"""
import pytest
from app.services import room_service, user_service
from app.schemas.room import RoomCreate
from app.core.exceptions import InvalidCredentialsError, PermissionDeniedError
from app.models.enums import UserStatus


def test_room_lifecycle_and_direct_join(db_session):
    # 1. Create room owner
    owner = user_service.create_user(
        db_session,
        email="owner_test@corp.com",
        password="ValidPassword123!",
        full_name="War Room Lead",
        role="organizer",
        status=UserStatus.ACTIVE,
    )
    # 2. Create another user to join
    member_user = user_service.create_user(
        db_session,
        email="member_test@corp.com",
        password="ValidPassword123!",
        full_name="Alice Member",
        role="individual",
        status=UserStatus.ACTIVE,
    )
    db_session.commit()

    # 3. Owner creates a password-protected room
    room = room_service.create_room(
        db_session,
        creator=owner,
        data=RoomCreate(
            name="Containment Alpha",
            description="Urgent incident war room",
            password="WarRoomPassword123!",
            join_policy="direct",
        ),
    )
    db_session.commit()

    assert room.public_room_id.startswith("ROOM-")
    assert room.created_by == owner.id

    # 4. Member attempts join with WRONG password -> raises InvalidCredentialsError
    with pytest.raises(InvalidCredentialsError):
        room_service.direct_join_room(
            db_session,
            user=member_user,
            room_code=room.public_room_id,
            password="IncorrectPassword!",
        )

    # 5. Member joins with CORRECT password -> succeeds
    joined_room, membership, already_member = room_service.direct_join_room(
        db_session,
        user=member_user,
        room_code=room.public_room_id,
        password="WarRoomPassword123!",
    )
    db_session.commit()

    assert joined_room.id == room.id
    assert membership.user_id == member_user.id
    assert membership.role == "member"
    assert already_member is False

    # 6. Re-joining same room is idempotent
    re_room, re_member, re_already = room_service.direct_join_room(
        db_session,
        user=member_user,
        room_code=room.public_room_id,
        password="WarRoomPassword123!",
    )
    assert re_already is True
    assert re_member.id == membership.id

    # 7. Member lists their joined rooms
    my_rooms = room_service.list_user_rooms(db_session, user_id=member_user.id)
    assert any(r.id == room.id for r in my_rooms)
