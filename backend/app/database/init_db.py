"""
CyberGuard AI - Database Initialization Script

Run this script to initialize the PostgreSQL database schema.
Usage: python -m app.database.init_db
"""

import asyncio
import sys

import structlog

# psycopg's async connection pool requires a SelectorEventLoop; asyncio's
# default on Windows is ProactorEventLoop. Same fix as run_windows.py /
# app/windows_loop.py (uvicorn's own loop_factory) and
# scripts/live_e2e_verification.py (this exact pattern) - this script runs
# standalone via asyncio.run(), so the policy (not a uvicorn loop_factory)
# is what actually takes effect here.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app.config import get_settings
from app.database.connection import get_database, init_database, close_database
from app.database.schema import create_schema, SCHEMA_SQL


logger = structlog.get_logger(__name__)


async def init_db(create_default_users: bool = True) -> bool:
    """
    Initialize the database schema and optionally create default users.

    Returns True if successful.
    """
    settings = get_settings()

    if not settings.db_enabled:
        print("ERROR: Database is disabled (DB_ENABLED=false)")
        print("Set DB_ENABLED=true in .env to enable database")
        return False

    print(f"Connecting to PostgreSQL at {settings.db_host}:{settings.db_port}/{settings.db_name}...")

    try:
        # Initialize connection
        await init_database()
        db = get_database()

        print("Creating schema...")
        await create_schema(db)

        print("Schema created successfully!")

        # Create default admin user if requested
        if create_default_users:
            print("Creating default users...")
            await _create_default_users(db)

        # Verify tables
        result = await db.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)

        print("\nTables created:")
        for row in result:
            print(f"  - {row['table_name']}")

        return True

    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        print(f"ERROR: {e}")
        return False

    finally:
        await close_database()


async def _create_default_users(db) -> None:
    """Create default admin and analyst users."""
    import hashlib
    import secrets
    from uuid import uuid4
    from datetime import datetime, timezone

    def hash_password(password: str) -> tuple[str, str]:
        salt = secrets.token_hex(16)
        salted = f"{salt}:{password}"
        hashed = hashlib.sha256(salted.encode()).hexdigest()
        return hashed, salt

    # Check if admin exists
    existing = await db.execute_one(
        "SELECT id FROM users WHERE username = 'admin'"
    )

    if existing:
        print("  - Default users already exist, skipping")
        return

    # Create admin
    admin_hash, admin_salt = hash_password("admin123!")
    await db.execute("""
        INSERT INTO users (
            id, username, email, full_name, role, is_active,
            password_hash, password_salt, auth_provider,
            can_create_alerts, can_run_analysis, can_manage_users
        ) VALUES (
            %(id)s, 'admin', 'admin@cyberguard.example.com', 'System Administrator', 'admin', true,
            %(password_hash)s, %(password_salt)s, 'local',
            true, true, true
        )
    """, {
        "id": str(uuid4()),
        "password_hash": admin_hash,
        "password_salt": admin_salt,
    })
    print("  - Created admin user (admin / admin123!)")

    # Create analyst
    analyst_hash, analyst_salt = hash_password("analyst123!")
    await db.execute("""
        INSERT INTO users (
            id, username, email, full_name, role, is_active,
            password_hash, password_salt, auth_provider,
            can_create_alerts, can_run_analysis, can_manage_users
        ) VALUES (
            %(id)s, 'analyst', 'analyst@cyberguard.example.com', 'Security Analyst', 'analyst', true,
            %(password_hash)s, %(password_salt)s, 'local',
            true, true, false
        )
    """, {
        "id": str(uuid4()),
        "password_hash": analyst_hash,
        "password_salt": analyst_salt,
    })
    print("  - Created analyst user (analyst / analyst123!)")


async def check_db_connection() -> bool:
    """Check if database connection works."""
    settings = get_settings()

    if not settings.db_enabled:
        print("Database is disabled")
        return False

    try:
        await init_database()
        db = get_database()
        health = await db.health_check()

        if health["status"] == "healthy":
            print(f"Database connection OK: {settings.db_host}:{settings.db_port}/{settings.db_name}")
            return True
        else:
            print(f"Database unhealthy: {health.get('error', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"Connection failed: {e}")
        return False

    finally:
        await close_database()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="CyberGuard AI Database Initialization")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check database connection",
    )
    parser.add_argument(
        "--no-users",
        action="store_true",
        help="Skip creating default users",
    )

    args = parser.parse_args()

    if args.check:
        success = asyncio.run(check_db_connection())
    else:
        success = asyncio.run(init_db(create_default_users=not args.no_users))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
