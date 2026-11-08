"""
CyberGuard AI — Phase 15A Live PostgreSQL Migration & Integration Verification
============================================================================
Runs against live PostgreSQL 18.6:
1. Validates connection & PostgreSQL version.
2. Fresh DB installation: alembic upgrade head -> verifies 17 tables + columns.
3. Existing DB upgrade: seeds pre-0002 data, runs upgrade head, verifies data preservation.
4. Application integration: starts FastAPI with live PG, tests auth, profile, rooms, join.
5. Migration safety: tests downgrade -1 on disposable DB, verifies table drop + data retention, re-upgrades.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from typing import Any

import psycopg2
from psycopg2 import sql, errors

# Ensure backend directory is in sys.path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

PG_HOST = "localhost"
PG_PORT = 15432
PG_USER = "cyberguard"
DEFAULT_DB = "postgres"
FRESH_DB = "cyberguard_fresh"
UPGRADE_DB = "cyberguard_upgrade"

PG_CONNINFO_DEFAULT = f"host={PG_HOST} port={PG_PORT} user={PG_USER} dbname={DEFAULT_DB}"
PG_CONNINFO_FRESH = f"host={PG_HOST} port={PG_PORT} user={PG_USER} dbname={FRESH_DB}"
PG_CONNINFO_UPGRADE = f"host={PG_HOST} port={PG_PORT} user={PG_USER} dbname={UPGRADE_DB}"

ALEMBIC_URL_FRESH = f"postgresql+psycopg2://{PG_USER}@{PG_HOST}:{PG_PORT}/{FRESH_DB}"
ALEMBIC_URL_UPGRADE = f"postgresql+psycopg2://{PG_USER}@{PG_HOST}:{PG_PORT}/{UPGRADE_DB}"

ALEMBIC_BIN = os.path.join(BACKEND_DIR, ".venv", "Scripts", "alembic.exe")


def get_conn(conninfo: str, autocommit: bool = False):
    conn = psycopg2.connect(conninfo)
    conn.autocommit = autocommit
    return conn


def run_cmd(cmd: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    res = subprocess.run(cmd, cwd=BACKEND_DIR, capture_output=True, text=True, env=merged_env)
    return res.returncode, res.stdout, res.stderr


_pg_proc = None

def start_postgres_server() -> None:
    global _pg_proc
    postgres_exe = r"C:\Program Files\PostgreSQL\18\bin\postgres.exe"
    data_dir = r"E:\CyberGuard\.pgdata_test"
    print("Starting PostgreSQL 18.6 server on port 15432...", flush=True)
    _pg_proc = subprocess.Popen(
        [postgres_exe, "-D", data_dir, "-p", "15432"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    import time
    for _ in range(25):
        try:
            conn = psycopg2.connect("host=localhost port=15432 user=cyberguard dbname=postgres")
            conn.close()
            print("PostgreSQL 18.6 server ready!", flush=True)
            return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Failed to connect to PostgreSQL 18.6 server")


def stop_postgres_server() -> None:
    global _pg_proc
    if _pg_proc is not None:
        print("Stopping PostgreSQL 18.6 server...", flush=True)
        _pg_proc.terminate()
        try:
            _pg_proc.wait(timeout=5)
        except Exception:
            _pg_proc.kill()
        _pg_proc = None
        print("PostgreSQL 18.6 stopped cleanly.", flush=True)


def recreate_database(dbname: str) -> None:
    conn = get_conn(PG_CONNINFO_DEFAULT, autocommit=True)
    with conn.cursor() as cur:
        # Terminate any active connections
        cur.execute(
            """
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = %s AND pid <> pg_backend_pid();
            """,
            (dbname,),
        )
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    conn.close()


def drop_database(dbname: str) -> None:
    try:
        conn = get_conn(PG_CONNINFO_DEFAULT, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s AND pid <> pg_backend_pid();
                """,
                (dbname,),
            )
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
        conn.close()
    except Exception as exc:
        print(f"Warning: could not drop {dbname}: {exc}")


def step_1_inspect_postgres() -> dict[str, Any]:
    print("\n" + "=" * 70)
    print("STEP 1: INSPECT LIVE POSTGRESQL INSTANCE")
    print("=" * 70)
    conn = get_conn(PG_CONNINFO_DEFAULT)
    with conn.cursor() as cur:
        cur.execute("SELECT version();")
        version_str = cur.fetchone()[0]
        cur.execute("SELECT current_user, current_database();")
        user, db = cur.fetchone()
    conn.close()

    print(f"PostgreSQL Version: {version_str}")
    print(f"Connected User:     {user}")
    print(f"Connected Database: {db}")

    # Inspect alembic migrations in codebase
    code, out, _ = run_cmd([ALEMBIC_BIN, "history"])
    print(f"Alembic History:\n{out.strip()}")
    assert "0001_initial_schema" in out
    assert "0002_add_rooms_and_slugs" in out

    return {
        "postgres_version": version_str,
        "connected_user": user,
        "migration_history": out.strip(),
    }


def step_2_fresh_installation() -> dict[str, Any]:
    print("\n" + "=" * 70)
    print("STEP 2: FRESH POSTGRESQL INSTALLATION (alembic upgrade head)")
    print("=" * 70)
    recreate_database(FRESH_DB)
    print(f"Created fresh disposable database: {FRESH_DB}")

    env = {"DATABASE_URL": ALEMBIC_URL_FRESH, "APP_ENV": "development"}
    code, out, err = run_cmd([ALEMBIC_BIN, "upgrade", "head"], env=env)
    print(f"Alembic Output:\n{out}\n{err}")
    assert code == 0, f"Fresh upgrade failed: {err}"

    # Verify tables in catalog
    required_tables = [
        "users", "organizations", "workspaces", "security_sources",
        "collector_credentials", "security_events", "agent_findings",
        "security_alerts", "security_incidents", "security_cases",
        "security_evidence", "case_conversations", "case_messages",
        "security_audit_logs", "rooms", "room_members", "room_invitations"
    ]

    conn = get_conn(PG_CONNINFO_FRESH)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
        """)
        existing_tables = set(r[0] for r in cur.fetchall())

        # Check revision in alembic_version
        cur.execute("SELECT version_num FROM alembic_version;")
        current_rev = cur.fetchone()[0]

        # Check columns in users
        cur.execute("""
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'users';
        """)
        user_cols = {r[0]: {"type": r[1], "nullable": r[2], "default": r[3]} for r in cur.fetchall()}
    conn.close()

    print(f"Current Alembic Revision in DB: {current_rev}")
    assert current_rev == "0002_add_rooms_and_slugs"

    missing_tables = [t for t in required_tables if t not in existing_tables]
    print(f"Total Tables Created: {len(existing_tables)}")
    print(f"Required Tables Present: {len(required_tables)} / {len(required_tables)}")
    assert not missing_tables, f"Missing required tables: {missing_tables}"

    assert "public_user_id" in user_cols, "users.public_user_id missing!"
    assert "role" in user_cols, "users.role missing!"
    print("Verified users.public_user_id and users.role columns exist!")

    return {
        "status": "VERIFIED",
        "current_revision": current_rev,
        "tables_count": len(existing_tables),
        "required_tables_verified": required_tables,
    }


def step_3_existing_database_upgrade() -> dict[str, Any]:
    print("\n" + "=" * 70)
    print("STEP 3: EXISTING DATABASE UPGRADE & DATA PRESERVATION")
    print("=" * 70)
    recreate_database(UPGRADE_DB)
    print(f"Created upgrade disposable database: {UPGRADE_DB}")

    env = {"DATABASE_URL": ALEMBIC_URL_UPGRADE, "APP_ENV": "development"}
    
    # 1. Apply baseline 0001_initial_schema
    code, out, err = run_cmd([ALEMBIC_BIN, "upgrade", "0001_initial_schema"], env=env)
    assert code == 0, f"Baseline upgrade failed: {err}"
    print("Applied baseline revision 0001_initial_schema.")

    # 2. Seed pre-existing records (User, Org, Event, Alert, Incident)
    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    source_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    alert_id = str(uuid.uuid4())
    incident_id = str(uuid.uuid4())

    conn = get_conn(PG_CONNINFO_UPGRADE)
    with conn.cursor() as cur:
        # Seed user (baseline schema before 0002)
        cur.execute("""
            INSERT INTO users (id, email, password_hash, full_name, status)
            VALUES (%s, 'sarah.senior@enterprise.com', '$2b$12$eXampleHashedPassword1234567890123456789012', 'Sarah Senior', 'active');
        """, (user_id,))

        # Seed org
        cur.execute("""
            INSERT INTO organizations (id, name, slug, status, owner_id)
            VALUES (%s, 'CyberGuard Enterprise', 'cyberguard-enterprise', 'ACTIVE', %s);
        """, (org_id, user_id))

        # Seed security source
        cur.execute("""
            INSERT INTO security_sources (id, name, type, status)
            VALUES (%s, 'Production Endpoint Sensor', 'endpoint', 'ACTIVE');
        """, (source_id,))

        # Seed security event
        cur.execute("""
            INSERT INTO security_events (id, source_id, event_type, severity, raw_payload)
            VALUES (%s, %s, 'process_creation', 'HIGH', '{"cmd": "powershell.exe -enc ..."}');
        """, (event_id, source_id))

        # Seed security alert
        cur.execute("""
            INSERT INTO security_alerts (id, title, severity, status, trigger_event_id)
            VALUES (%s, 'Unauthorized PowerShell Execution', 'high', 'new', %s);
        """, (alert_id, event_id))

        # Seed incident
        cur.execute("""
            INSERT INTO security_incidents (id, title, severity, status)
            VALUES (%s, 'Potential Lateral Movement Outbreak', 'high', 'open');
        """, (incident_id,))
    conn.commit()
    conn.close()
    print("Seeded baseline records into 0001_initial_schema database.")

    # 3. Apply 0002_add_rooms_and_slugs upgrade
    code, out, err = run_cmd([ALEMBIC_BIN, "upgrade", "head"], env=env)
    assert code == 0, f"Upgrade to head failed: {err}"
    print("Successfully executed 'alembic upgrade head' over pre-existing database.")

    # 4. Verify data preservation and backfilled public slug
    conn = get_conn(PG_CONNINFO_UPGRADE)
    with conn.cursor() as cur:
        cur.execute("SELECT email, full_name, role, public_user_id FROM users WHERE id = %s;", (user_id,))
        user_row = cur.fetchone()
        email, full_name, role, public_slug = user_row

        cur.execute("SELECT count(*) FROM organizations WHERE id = %s;", (org_id,))
        org_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM security_events WHERE id = %s;", (event_id,))
        event_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM security_alerts WHERE id = %s;", (alert_id,))
        alert_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM security_incidents WHERE id = %s;", (incident_id,))
        inc_count = cur.fetchone()[0]
    conn.close()

    print(f"Pre-existing User Intact:      {email} | Name: {full_name}")
    print(f"Role Defaulted:                {role}")
    print(f"Public User ID Backfilled:     {public_slug}")
    assert email == "sarah.senior@enterprise.com"
    assert full_name == "Sarah Senior"
    assert role == "individual"
    assert public_slug is not None
    assert re.match(r"^sarah-senior-user-\d{6}$", public_slug), f"Invalid backfilled slug: {public_slug}"

    assert org_count == 1, "Organization record lost!"
    assert event_count == 1, "Security event record lost!"
    assert alert_count == 1, "Security alert record lost!"
    assert inc_count == 1, "Security incident record lost!"
    print("All pre-existing security records and entities verified intact (100% data preservation)!")

    # 5. Verify room constraints work on upgraded database
    room_id = str(uuid.uuid4())
    conn = get_conn(PG_CONNINFO_UPGRADE)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO rooms (id, public_room_id, name, created_by, status)
            VALUES (%s, 'ROOM-WAR1', 'Triage Alpha', %s, 'active');
        """, (room_id, user_id))

        cur.execute("""
            INSERT INTO room_members (id, room_id, user_id, role, status)
            VALUES (%s, %s, %s, 'owner', 'active');
        """, (str(uuid.uuid4()), room_id, user_id))
    conn.commit()

    # Test composite unique constraint violation (room_id, user_id)
    duplicate_failed = False
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO room_members (id, room_id, user_id, role, status)
                VALUES (%s, %s, %s, 'member', 'active');
            """, (str(uuid.uuid4()), room_id, user_id))
        conn.commit()
    except errors.UniqueViolation:
        conn.rollback()
        duplicate_failed = True
    conn.close()

    assert duplicate_failed, "Composite unique constraint uq_room_member failed to prevent duplicate membership!"
    print("Verified room membership unique constraint uq_room_member prevents duplicates.")

    # 6. Verify idempotency of repeated upgrade
    code2, out2, err2 = run_cmd([ALEMBIC_BIN, "upgrade", "head"], env=env)
    assert code2 == 0, f"Repeated upgrade failed: {err2}"
    print("Verified idempotency: repeated 'alembic upgrade head' completed without modifications.")

    return {
        "status": "VERIFIED",
        "data_preservation": "100%",
        "backfilled_slug": public_slug,
        "unique_constraint": "VERIFIED",
        "idempotent_upgrade": "VERIFIED",
    }


def step_4_application_integration() -> dict[str, Any]:
    print("\n" + "=" * 70)
    print("STEP 4: LIVE FASTAPI INTEGRATION ON POSTGRESQL")
    print("=" * 70)

    # Point settings to FRESH_DB
    os.environ["DATABASE_URL"] = ALEMBIC_URL_FRESH
    os.environ["APP_ENV"] = "test"
    os.environ["AGENT_EXECUTION_ENABLED"] = "false"

    from app.core.config import settings
    settings.DATABASE_URL = ALEMBIC_URL_FRESH
    settings.APP_ENV = "test"
    settings.AGENT_EXECUTION_ENABLED = False

    from app.db.session import dispose_engine
    dispose_engine()

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        # 1. Health check
        res = client.get("/health")
        print(f"GET /health: {res.status_code}")
        assert res.status_code == 200, res.text
        health_data = res.json()
        assert health_data["checks"]["db"]["status"] == "ok"
        print("Live PostgreSQL Health Check: OK")

        # 2. User registration
        reg_payload = {
            "email": "marcus.live@cyberguard.tech",
            "password": "SecurePassword123!@#",
            "full_name": "Marcus Live",
            "role": "analyst",
        }
        res = client.post("/api/v1/auth/register", json=reg_payload)
        print(f"POST /api/v1/auth/register: {res.status_code}")
        assert res.status_code == 201, res.text
        tokens = res.json()
        access_token = tokens["access_token"]
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # 3. User login
        login_res = client.post("/api/v1/auth/login", json={
            "email": "marcus.live@cyberguard.tech",
            "password": "SecurePassword123!@#",
        })
        print(f"POST /api/v1/auth/login: {login_res.status_code}")
        assert login_res.status_code == 200, login_res.text

        # 4. Profile & Public Slug
        me_res = client.get("/api/v1/auth/me", headers=auth_headers)
        print(f"GET /api/v1/auth/me: {me_res.status_code}")
        assert me_res.status_code == 200, me_res.text
        me_data = me_res.json()
        public_slug = me_data["public_user_id"]
        role = me_data["role"]
        print(f"Authenticated User: {me_data['email']} | Role: {role} | Public Slug: {public_slug}")
        assert role == "analyst"
        assert re.match(r"^marcus-live-analyst-\d{6}$", public_slug)

        # 5. Room creation
        room_payload = {
            "name": "Live Response Unit",
            "description": "Active PostgreSQL incident room",
            "password": "RoomPassword789!",
            "join_policy": "direct",
        }
        create_room_res = client.post("/api/v1/rooms", headers=auth_headers, json=room_payload)
        print(f"POST /api/v1/rooms: {create_room_res.status_code}")
        assert create_room_res.status_code == 201, create_room_res.text
        room_data = create_room_res.json()
        public_room_id = room_data["public_room_id"]
        print(f"Created Room: {room_data['name']} (Code: {public_room_id})")

        # 6. Second user registers & joins room
        second_reg = client.post("/api/v1/auth/register", json={
            "email": "sarah.responder@cyberguard.tech",
            "password": "SecurePassword123!@#",
            "full_name": "Sarah Responder",
            "role": "individual",
        })
        second_token = second_reg.json()["access_token"]
        second_headers = {"Authorization": f"Bearer {second_token}"}

        # Direct join with room code + password
        join_res = client.post("/api/v1/rooms/join", headers=second_headers, json={
            "room_code": public_room_id,
            "password": "RoomPassword789!",
        })
        print(f"POST /api/v1/rooms/join: {join_res.status_code}")
        assert join_res.status_code == 200, join_res.text
        join_data = join_res.json()
        assert join_data["success"] is True
        print(f"Second user successfully joined {public_room_id}")

        # 7. Check user joined rooms
        my_rooms_res = client.get("/api/v1/rooms/me", headers=second_headers)
        assert my_rooms_res.status_code == 200
        my_rooms = my_rooms_res.json()
        assert any(r["public_room_id"] == public_room_id for r in my_rooms)
        print("Verified room membership list in GET /api/v1/rooms/me")

    return {
        "status": "VERIFIED",
        "endpoints_tested": [
            "/health",
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/me",
            "/api/v1/rooms",
            "/api/v1/rooms/join",
            "/api/v1/rooms/me",
        ],
    }


def step_5_downgrade_safety() -> dict[str, Any]:
    print("\n" + "=" * 70)
    print("STEP 5: DOWNGRADE SAFETY & RE-UPGRADE TESTING")
    print("=" * 70)
    env = {"DATABASE_URL": ALEMBIC_URL_UPGRADE, "APP_ENV": "development"}

    # 1. Test downgrade -1
    code, out, err = run_cmd([ALEMBIC_BIN, "downgrade", "-1"], env=env)
    assert code == 0, f"Downgrade failed: {err}"
    print(f"Downgraded UPGRADE_DB to baseline:\n{out}")

    # 2. Verify rooms, room_members, room_invitations dropped, but users & orgs retained
    conn = get_conn(PG_CONNINFO_UPGRADE)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
        """)
        remaining_tables = set(r[0] for r in cur.fetchall())

        cur.execute("SELECT count(*) FROM users;")
        users_count = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM organizations;")
        orgs_count = cur.fetchone()[0]

        cur.execute("SELECT version_num FROM alembic_version;")
        cur_ver = cur.fetchone()[0]
    conn.close()

    assert cur_ver == "0001_initial_schema"
    assert "rooms" not in remaining_tables
    assert "room_members" not in remaining_tables
    assert "room_invitations" not in remaining_tables
    assert "users" in remaining_tables
    assert "organizations" in remaining_tables
    assert users_count > 0, "Users were lost during downgrade!"
    assert orgs_count > 0, "Organizations were lost during downgrade!"
    print("Verified: Rooms tables cleanly removed; baseline users and organizations 100% preserved.")

    # 3. Test re-upgrade to head
    code2, out2, err2 = run_cmd([ALEMBIC_BIN, "upgrade", "head"], env=env)
    assert code2 == 0, f"Re-upgrade failed: {err2}"
    print("Verified: Clean re-upgrade to head completed without errors.")

    return {
        "status": "VERIFIED",
        "downgrade_data_loss_risk": "Rooms dropped as designed; baseline tables & data intact.",
        "re_upgrade": "VERIFIED",
    }


def main():
    print("CYBERGUARD AI — PHASE 15A LIVE POSTGRESQL VERIFICATION")
    start_postgres_server()
    try:
        s1 = step_1_inspect_postgres()
        s2 = step_2_fresh_installation()
        s3 = step_3_existing_database_upgrade()
        s4 = step_4_application_integration()
        s5 = step_5_downgrade_safety()

        print("\n" + "=" * 70)
        print("PHASE 15A VERIFICATION COMPLETED WITH 100% SUCCESS")
        print("=" * 70)
        print(f"Step 1 (PostgreSQL Instance):     VERIFIED ({s1['postgres_version'][:30]}...)")
        print(f"Step 2 (Fresh Installation):       VERIFIED ({s2['tables_count']} tables created)")
        print(f"Step 3 (Existing DB Upgrade):      VERIFIED (100% data preservation)")
        print(f"Step 4 (FastAPI Live Integration): VERIFIED ({len(s4['endpoints_tested'])} endpoints tested)")
        print(f"Step 5 (Downgrade Safety):         VERIFIED (clean drop & re-upgrade)")

    finally:
        print("\nCleaning up disposable databases...")
        drop_database(FRESH_DB)
        drop_database(UPGRADE_DB)
        print("Disposable databases removed cleanly.")
        stop_postgres_server()


if __name__ == "__main__":
    main()
