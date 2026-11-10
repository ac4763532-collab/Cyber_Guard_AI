"""
Seed script to create ready-to-use demo accounts for CyberGuard AI.
Roles: Analyst (SOC), Individual User, Organizer / SecOps Admin.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

backend_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_root))
load_dotenv(backend_root / ".env")

from app.db.session import session_scope
from app.models.enums import UserStatus
from app.services import user_service, workspace_service

DEMO_USERS = [
    {
        "email": "analyst@cyberguard.ai",
        "password": "CyberGuard2026!",
        "full_name": "Sarah Connor (SOC Analyst)",
        "role": "analyst",
    },
    {
        "email": "user@cyberguard.ai",
        "password": "CyberGuard2026!",
        "full_name": "Alex Morgan (Security Pro)",
        "role": "individual",
    },
    {
        "email": "admin@cyberguard.ai",
        "password": "CyberGuard2026!",
        "full_name": "DevSecOps Lead (Admin)",
        "role": "organizer",
    },
]

def seed() -> None:
    with session_scope() as db:
        for u in DEMO_USERS:
            existing = user_service.get_by_email_optional(db, email=u["email"])
            if existing:
                print(f"User {u['email']} already exists.")
                workspace_service.create_personal_workspace(db, existing)
                continue
            user = user_service.create_user(
                db,
                email=u["email"],
                password=u["password"],
                full_name=u["full_name"],
                role=u["role"],
                status=UserStatus.ACTIVE,
            )
            user.email_verified_at = datetime.now(timezone.utc)
            db.flush()
            workspace_service.create_personal_workspace(db, user)
            print(f"Created demo user: {u['email']} ({u['role']})")
        db.commit()
    print("Demo user seeding completed successfully!")

if __name__ == "__main__":
    seed()
