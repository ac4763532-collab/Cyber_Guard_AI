# CyberGuard AI — Database Migrations Guide

This guide explains the Alembic migration architecture, baseline schema, upgrade/downgrade procedures, and schema verification against PostgreSQL.

---

## 1. Migration Architecture

CyberGuard AI manages database schema revisions using **Alembic** (`backend/alembic`).
- Migration scripts live in `backend/alembic/versions/`.
- Configuration is declared in `backend/alembic.ini`.
- Dynamic model registration is centralized in `backend/alembic/env.py`, importing `Base.metadata` from `app.db.base`.

---

## 2. Migration Lineage

```
<base>
  │
  ▼
0001_initial_schema (Initial CyberGuard AI Schema)
  │
  ▼
0002_add_rooms_and_slugs (Add Rooms, Room Members, Room Invitations, and User Public Slugs) [HEAD]
```

### Revision Details

#### `0001_initial_schema.py`
- **Revision ID:** `0001_initial_schema`
- **Revises:** `<base>`
- **Scope:** Creates foundational tables:
  - IAM: `users`, `organizations`, `workspaces`
  - Telemetry: `security_sources`, `collector_credentials`, `security_events`
  - Detection: `agent_findings`, `security_alerts`, `security_incidents`
  - Cases & Evidence: `security_cases`, `security_evidence`, `case_conversations`, `case_messages`
  - Compliance: `security_audit_logs`

#### `0002_add_rooms_and_slugs.py`
- **Revision ID:** `0002_add_rooms_and_slugs`
- **Revises:** `0001_initial_schema`
- **Scope:**
  - Adds `users.public_user_id` (VARCHAR(64), unique, indexed)
  - Adds `users.role` (VARCHAR(32), default `'individual'`)
  - Creates `rooms` table with `public_room_id`, `password_hash`, `join_policy`, `created_by` FK
  - Creates `room_members` table with unique `(room_id, user_id)` constraint
  - Creates `room_invitations` table with verification token and expiry
- **Downgrade:** Completely reversible — drops `room_invitations`, `room_members`, `rooms`, and removes columns from `users`.

---

## 3. Standard Migration Commands

All commands should be executed from `backend/` using the active virtual environment:

```powershell
# 1. View migration history
& ".venv\Scripts\alembic.exe" history

# 2. View current database revision
& ".venv\Scripts\alembic.exe" current

# 3. Upgrade database to latest revision
& ".venv\Scripts\alembic.exe" upgrade head

# 4. Generate SQL script without running (offline validation)
& ".venv\Scripts\alembic.exe" upgrade head --sql

# 5. Rollback to baseline (1 step)
& ".venv\Scripts\alembic.exe" downgrade -1
```

---

## 4. Verification & Testing

Both migrations have been verified through:
1. **Offline SQL DDL Generation:** Synthesizes transactional PostgreSQL DDL without errors.
2. **Schema Introspection:** Confirmed unique constraints (`uq_rooms_public_room_id`, `uq_room_members_room_user`), foreign keys (`ON DELETE CASCADE`), and indexes.
3. **Automated Regression Suite:** Tested against in-memory models and migration graphs with 100% pass rate.
