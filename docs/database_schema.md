# CyberGuard AI — Database Schema Reference

This document provides the authoritative schema reference for the CyberGuard AI cybersecurity platform, detailing all core entities, tables, relationships, constraints, and data integrity guarantees.

---

## 1. Schema Overview

The database is built on **PostgreSQL 16+** using **SQLAlchemy 2.0** declarative ORM mappings and versioned through **Alembic** migrations.

The schema is partitioned into functional security domains:
1. **Identity & Access Management (IAM):** `users`, `organizations`, `workspaces`
2. **Collaborative Triage & Spaces:** `rooms`, `room_members`, `room_invitations`
3. **Telemetry & Collection:** `security_sources`, `collector_credentials`, `security_events`
4. **Agent Detection Engine:** `agent_findings`, `security_alerts`, `security_incidents`
5. **Investigation & Case Management:** `security_cases`, `security_evidence`, `case_conversations`, `case_messages`
6. **Audit & Compliance:** `security_audit_logs`

---

## 2. Collaborative Spaces (Rooms & Slugs)

### `rooms`
Dedicated incident response rooms, war rooms, and organization team workspaces.

| Column | Type | Nullable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `UUID` | No | `gen_random_uuid()` | Primary Key |
| `public_room_id` | `VARCHAR(32)` | No | — | Unique public identifier (e.g. `ROOM-7K9P`) |
| `organization_id` | `UUID` | Yes | `NULL` | Foreign key to `organizations.id` (ON DELETE SET NULL) |
| `name` | `VARCHAR(128)` | No | — | Display name of the room |
| `description` | `VARCHAR(500)` | Yes | `NULL` | Mission or description |
| `password_hash` | `VARCHAR(255)` | Yes | `NULL` | Bcrypt hashed room entry password |
| `join_policy` | `VARCHAR(32)` | No | `'direct'` | Policy: `'direct'`, `'invite_only'`, `'approval'` |
| `status` | `VARCHAR(32)` | No | `'active'` | Status: `'active'`, `'archived'`, `'closed'` |
| `created_by` | `UUID` | No | — | Foreign key to `users.id` (creator) |
| `created_at` | `TIMESTAMPTZ` | No | `now()` | Timestamp created |
| `updated_at` | `TIMESTAMPTZ` | No | `now()` | Timestamp updated |

**Indexes & Constraints:**
- `pk_rooms PRIMARY KEY (id)`
- `uq_rooms_public_room_id UNIQUE (public_room_id)`
- `fk_rooms_organization_id FOREIGN KEY (organization_id) REFERENCES organizations(id)`
- `fk_rooms_created_by FOREIGN KEY (created_by) REFERENCES users(id)`
- `ix_rooms_public_room_id INDEX (public_room_id)`
- `ix_rooms_organization_id INDEX (organization_id)`

---

### `room_members`
Association table tracking membership, role, and authorization inside rooms.

| Column | Type | Nullable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `UUID` | No | `gen_random_uuid()` | Primary Key |
| `room_id` | `UUID` | No | — | Foreign key to `rooms.id` (ON DELETE CASCADE) |
| `user_id` | `UUID` | No | — | Foreign key to `users.id` (ON DELETE CASCADE) |
| `role` | `VARCHAR(32)` | No | `'member'` | Role in room: `'owner'`, `'moderator'`, `'member'`, `'observer'` |
| `status` | `VARCHAR(32)` | No | `'active'` | Status: `'active'`, `'muted'`, `'revoked'` |
| `joined_at` | `TIMESTAMPTZ` | No | `now()` | Membership timestamp |

**Indexes & Constraints:**
- `pk_room_members PRIMARY KEY (id)`
- `uq_room_members_room_user UNIQUE (room_id, user_id)`
- `fk_room_members_room_id FOREIGN KEY (room_id) REFERENCES rooms(id)`
- `fk_room_members_user_id FOREIGN KEY (user_id) REFERENCES users(id)`
- `ix_room_members_room_id INDEX (room_id)`
- `ix_room_members_user_id INDEX (user_id)`

---

### `room_invitations`
Tracks invitations sent by organizers to analysts or team members.

| Column | Type | Nullable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `UUID` | No | `gen_random_uuid()` | Primary Key |
| `room_id` | `UUID` | No | — | Foreign key to `rooms.id` (ON DELETE CASCADE) |
| `inviter_id` | `UUID` | No | — | Foreign key to `users.id` |
| `invitee_id` | `UUID` | Yes | `NULL` | Target registered user |
| `invitee_email` | `VARCHAR(320)` | No | — | Target email address |
| `token` | `VARCHAR(128)` | No | — | Secure random invitation verification token |
| `role` | `VARCHAR(32)` | No | `'member'` | Assigned role upon acceptance |
| `status` | `VARCHAR(32)` | No | `'pending'` | Status: `'pending'`, `'accepted'`, `'declined'`, `'expired'` |
| `expires_at` | `TIMESTAMPTZ` | No | — | Expiration timestamp (default 7 days) |
| `created_at` | `TIMESTAMPTZ` | No | `now()` | Timestamp created |

---

## 3. User Identity & Public Slugs

### `users` (Selected Columns)
| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | No | Internal UUID Primary Key |
| `public_user_id` | `VARCHAR(64)` | No | Format: `<name-slug>-<role>-<6digits>` (e.g. `marcus-vance-analyst-582914`) |
| `role` | `VARCHAR(32)` | No | Role intent: `'individual'`, `'analyst'`, `'organizer'`, `'admin'` |
| `email` | `VARCHAR(320)` | No | Unique normalized email address |
| `password_hash` | `VARCHAR(255)` | No | Bcrypt hashed password (min 8, max 72 bytes) |
| `status` | `VARCHAR(32)` | No | `'pending_verification'`, `'active'`, `'suspended'`, `'deleted'` |

**Integrity Rule:** `public_user_id` is public and safe to share in invitations, rooms, and analyst listings. Internal `id` (UUID) is never exposed directly in URLs.

---

## 4. Migration History & Lineage

The Alembic migration chain is tracked in `backend/alembic/versions/`:
- `0001_initial_schema`: Baseline tables (users, organizations, workspaces, events, findings, alerts, incidents, cases, audit logs).
- `0002_add_rooms_and_slugs`: Adds `public_user_id` and `role` to `users`, and creates `rooms`, `room_members`, and `room_invitations`.
