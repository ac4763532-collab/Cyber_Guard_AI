# Database Setup Guide

## Overview

CyberGuard AI uses PostgreSQL for persistent storage. When `DB_ENABLED=true`, all data (users, events, alerts, incidents) is stored in the database. When `DB_ENABLED=false` (default), data is stored in-memory and lost on restart.

## Prerequisites

- PostgreSQL 14+ installed and running
- Database created for CyberGuard AI

## Quick Start

### 1. Install PostgreSQL

**Windows:**
Download from https://www.postgresql.org/download/windows/

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**macOS:**
```bash
brew install postgresql@14
brew services start postgresql@14
```

### 2. Create Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE DATABASE cyberguard;
CREATE USER cyberguard_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE cyberguard TO cyberguard_user;

# Exit
\q
```

### 3. Configure Backend

Update `backend/.env`:

```env
# Enable database
DB_ENABLED=true

# Connection settings
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyberguard
DB_USER=cyberguard_user
DB_PASSWORD=your_secure_password
```

### 4. Initialize Schema

```bash
cd backend

# Check connection
python -m app.database.init_db --check

# Create tables and default users
python -m app.database.init_db
```

Expected output:
```
Connecting to PostgreSQL at localhost:5432/cyberguard...
Creating schema...
Schema created successfully!
Creating default users...
  - Created admin user (admin / admin123!)
  - Created analyst user (analyst / analyst123!)

Tables created:
  - alerts
  - audit_log
  - detection_stats
  - events
  - findings
  - incidents
  - iocs
  - users
```

### 5. Start Backend

```bash
uvicorn app.main:app --reload
```

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts (local and Firebase) |
| `events` | Ingested security events |
| `findings` | Detection findings from analysis |
| `alerts` | Security alerts for analyst review |
| `incidents` | Security incidents grouping alerts |
| `iocs` | Indicators of Compromise |
| `detection_stats` | Hourly detection statistics |
| `audit_log` | User action audit trail |

### Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'viewer',  -- admin, analyst, viewer, api
    is_active BOOLEAN DEFAULT true,

    -- Authentication
    password_hash VARCHAR(255),
    password_salt VARCHAR(255),
    firebase_uid VARCHAR(255) UNIQUE,
    auth_provider VARCHAR(50) DEFAULT 'local',  -- local, google, phone

    -- Permissions
    can_create_alerts BOOLEAN DEFAULT false,
    can_manage_incidents BOOLEAN DEFAULT false,
    can_run_analysis BOOLEAN DEFAULT false,
    can_manage_users BOOLEAN DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);
```

## Connection Pooling

The database manager uses connection pooling:
- **Min connections:** 2
- **Max connections:** 10

Configure in `app/database/connection.py` if needed.

## Migrations

For schema changes in production, use Alembic:

```bash
# Initialize Alembic (first time)
cd backend
alembic init alembic

# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head
```

## Troubleshooting

### Connection Refused

```
error while attempting to bind on address: [Errno 10061] connection refused
```

**Solution:** Ensure PostgreSQL is running:
```bash
# Windows
net start postgresql-x64-14

# Linux
sudo systemctl start postgresql

# macOS
brew services start postgresql@14
```

### Authentication Failed

```
password authentication failed for user "postgres"
```

**Solution:** Check credentials in `.env` match your PostgreSQL setup.

### Database Does Not Exist

```
database "cyberguard" does not exist
```

**Solution:** Create the database:
```sql
CREATE DATABASE cyberguard;
```

### Permission Denied

```
permission denied for table users
```

**Solution:** Grant permissions:
```sql
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cyberguard_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cyberguard_user;
```

## Development vs Production

### Development (DB_ENABLED=false)

- Data stored in-memory
- Default users created on startup
- Fast iteration, no PostgreSQL needed
- Data lost on restart

### Production (DB_ENABLED=true)

- Persistent PostgreSQL storage
- Run `init_db.py` once to create schema
- Data survives restarts
- Connection pooling for performance
- Proper indexes for queries

## Security Notes

1. **Change default passwords** in production
2. **Use environment variables** for credentials, not hardcoded values
3. **Restrict database access** to application server only
4. **Enable SSL** for database connections in production
5. **Regular backups** - implement backup strategy
