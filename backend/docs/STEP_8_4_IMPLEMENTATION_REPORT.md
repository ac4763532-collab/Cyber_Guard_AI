# STEP 8.4 Implementation Report

## Web Application Real-Time Log Collector

**Status:** ✅ COMPLETE  
**Date:** 2026-09-18  
**Tests:** 648 passed, 31 skipped (51 new web ingestion tests)

---

## Summary

STEP 8.4 implements an authenticated HTTP ingestion endpoint for receiving structured logs from web applications. The system provides:

- Machine-to-machine API key authentication
- Tenant isolation (keys bound to organization)
- Source authorization (keys bound to LogSource)
- Rate limiting (1000 req/min per key)
- Request size limits (1MB, 1000 entries)
- Stable source_event_id generation for idempotency
- Centralized redaction for sensitive data
- PostgreSQL storage with idempotent upserts
- Redpanda event bus publishing

---

## 1. Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `app/auth/ingestion_keys.py` | API key management (models, generation, repository) | ~620 |
| `app/api/v1/web_ingest.py` | Authenticated web log ingestion endpoint | ~530 |
| `migrations/versions/add_ingestion_api_keys.py` | Database migration for keys table | ~70 |
| `tests/test_step8_4_web_ingest.py` | Comprehensive tests (51 tests) | ~880 |

---

## 2. Files Modified

| File | Changes |
|------|---------|
| `app/api/v1/router.py` | Added web_ingest router |

---

## 3. Architecture

```
Web Application
      │
      │ POST /api/v1/logs/web/ingest
      │ Header: X-Ingestion-Key: cg_xxxxxxxxxx
      ▼
┌─────────────────────────────────────────┐
│       API Key Authentication            │
│  - Lookup by hash (constant-time)       │
│  - Verify status (active, not expired)  │
│  - Update usage stats                   │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       Tenant/Source Authorization       │
│  - Verify key.source_id exists          │
│  - Verify key.organization_id matches   │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       Request Validation                │
│  - Max 1MB body size                    │
│  - Max 1000 entries per request         │
│  - Validate log levels, fields          │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       Rate Limiting (slowapi)           │
│  - 1000 requests/minute per key         │
│  - Redis-backed state                   │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       Centralized Redaction             │
│  - app/logs/redaction.py                │
│  - Passwords, tokens, keys, secrets     │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       source_event_id Generation        │
│  - Client-provided: web-cli-{src}-{id}  │
│  - Server-generated: web-{hash}-{idx}   │
│  - Deterministic & idempotent           │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       PostgreSQL (Idempotent)           │
│  - ON CONFLICT (source_event_id)        │
│  - Deduplicates retries                 │
└─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│       Redpanda (security-events)        │
│  - Existing event bus integration       │
│  - Flows to Dispatcher → LogAgent       │
└─────────────────────────────────────────┘
```

---

## 4. API Endpoints

### POST /api/v1/logs/web/ingest

Authenticated endpoint for web application log ingestion.

**Headers:**
```
X-Ingestion-Key: cg_xxxxxxxxxxxxxxxxxx
Content-Type: application/json
```

**Request Body:**
```json
{
  "entries": [
    {
      "timestamp": "2026-09-18T10:30:00Z",
      "level": "ERROR",
      "message": "Database connection failed",
      "logger_name": "db.connector",
      "request_id": "req-abc-123",
      "user_id": "user-456",
      "ip_address": "192.168.1.1",
      "url": "/api/users",
      "method": "GET",
      "status_code": 500,
      "duration_ms": 1234.5,
      "error_type": "ConnectionError",
      "stack_trace": "Traceback...",
      "extra": {"custom_field": "value"},
      "client_event_id": "my-unique-id"
    }
  ],
  "hostname": "web-server-01",
  "application": "myapp",
  "environment": "production"
}
```

**Response:**
```json
{
  "accepted": 1,
  "stored": 1,
  "published": 1,
  "source_id": "src-456",
  "organization_id": "org-789",
  "request_id": "req-20260918103000-1234"
}
```

**Error Codes:**
- 401: Missing or invalid API key
- 403: Source not authorized for this key
- 413: Request body too large
- 422: Validation error
- 429: Rate limit exceeded

### POST /api/v1/logs/web/keys

Create a new ingestion API key.

**Request:**
```json
{
  "source_id": "src-123",
  "name": "Production Web Server",
  "description": "Key for prod web server logs",
  "expires_in_days": 90
}
```

**Response (key shown ONLY ONCE):**
```json
{
  "id": "key-abc-123",
  "source_id": "src-123",
  "organization_id": "org-456",
  "name": "Production Web Server",
  "key_prefix": "cg_abcd1234",
  "raw_key": "cg_abcd1234xxxxxxxxxxxxxxxxx",
  "created_at": "2026-09-18T10:30:00Z",
  "expires_at": "2026-12-17T10:30:00Z"
}
```

### GET /api/v1/logs/web/keys?source_id=xxx

List API keys for a source (without revealing keys).

### DELETE /api/v1/logs/web/keys/{key_id}

Revoke an API key immediately.

---

## 5. API Key Security

### Key Format
```
cg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
│   └── 32+ URL-safe random characters
└── Prefix for identification
```

### Storage
- Raw key: **NEVER stored** (shown once at creation)
- Key hash: SHA-256 of full key (stored in DB)
- Key prefix: First 11 chars (safe for logging)

### Verification
```python
# Constant-time comparison prevents timing attacks
secrets.compare_digest(computed_hash, stored_hash)
```

### Lifecycle
1. **Create**: Generate key, hash it, store hash, return raw key once
2. **Authenticate**: Hash provided key, lookup by hash, verify status
3. **Revoke**: Set status to REVOKED, key stops working immediately
4. **Expire**: Automatic invalidation when expires_at passes

---

## 6. Source Event ID Algorithm

### Client-Provided ID
```python
# If client sends client_event_id
source_event_id = f"web-cli-{source_id[:8]}-{client_event_id}"
```

### Server-Generated ID
```python
# Deterministic from content
content = f"{source_id}|{timestamp}|{message}|{index}"
if request_id:
    content += f"|req:{request_id}"
hash_digest = sha256(content).hexdigest()[:16]
source_event_id = f"web-{hash_digest}-{index}"
```

### Properties
- **Deterministic**: Same entry → same ID (idempotent retries)
- **Unique per batch**: Index differentiates identical entries
- **Client-controllable**: client_event_id overrides server generation

---

## 7. Tenant Isolation

| Component | Binding |
|-----------|---------|
| API Key | Bound to organization_id + source_id |
| LogSource | Has organization_id |
| LogEvent | Inherits organization_id via source |

### Authorization Check
```python
# Key must match source's organization
if source.organization_id != key.organization_id:
    raise HTTPException(403, "LogSource not authorized for this API key")
```

---

## 8. Rate Limiting

| Limit | Value |
|-------|-------|
| Requests per minute | 1000 |
| Max request body | 1 MB |
| Max entries per request | 1000 |

Uses existing Redis-backed slowapi infrastructure.

---

## 9. Database Schema

```sql
CREATE TABLE ingestion_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    source_id VARCHAR(36) NOT NULL,
    organization_id VARCHAR(36) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    use_count INTEGER NOT NULL DEFAULT 0,
    created_by VARCHAR(36)
);

-- Indexes for fast lookup
CREATE UNIQUE INDEX ix_ingestion_api_keys_key_hash ON ingestion_api_keys(key_hash);
CREATE INDEX ix_ingestion_api_keys_source_id ON ingestion_api_keys(source_id);
CREATE INDEX ix_ingestion_api_keys_organization_id ON ingestion_api_keys(organization_id);
CREATE INDEX ix_ingestion_api_keys_status ON ingestion_api_keys(status);
```

---

## 10. Test Coverage

### Test Categories (51 tests)

| Category | Tests | Coverage |
|----------|-------|----------|
| API Key Generation | 7 | Format, uniqueness, entropy, hashing |
| IngestionApiKey Model | 5 | Validity, expiration, to_dict security |
| IngestionKeyRepository | 6 | Create, authenticate, revoke |
| WebLogEntry Validation | 8 | Levels, required fields, normalization |
| Source Event ID | 5 | Client ID, deterministic, uniqueness |
| Web Ingestion Endpoint | 3 | Auth errors, valid key |
| Tenant Isolation | 2 | Organization binding |
| Security | 4 | No raw key storage, hash exclusion |
| Rate Limiting | 3 | Configuration checks |
| WebLogBatch Validation | 3 | Limits, empty rejection |
| Integration | 1 | Full key lifecycle |
| Edge Cases | 4 | Unicode, long traces, IPv6 |

---

## 11. Example Client Integration

### Python
```python
import requests

API_KEY = "cg_your_api_key_here"
ENDPOINT = "https://cyberguard.example.com/api/v1/logs/web/ingest"

def send_logs(logs):
    response = requests.post(
        ENDPOINT,
        headers={"X-Ingestion-Key": API_KEY},
        json={
            "entries": logs,
            "hostname": "web-01",
            "application": "myapp",
            "environment": "production",
        },
    )
    response.raise_for_status()
    return response.json()

# Usage
send_logs([
    {"level": "ERROR", "message": "Connection timeout", "request_id": "req-123"},
    {"level": "INFO", "message": "Request completed", "duration_ms": 45.2},
])
```

### JavaScript/Node.js
```javascript
const API_KEY = "cg_your_api_key_here";
const ENDPOINT = "https://cyberguard.example.com/api/v1/logs/web/ingest";

async function sendLogs(logs) {
  const response = await fetch(ENDPOINT, {
    method: "POST",
    headers: {
      "X-Ingestion-Key": API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      entries: logs,
      hostname: "web-01",
      application: "myapp",
    }),
  });
  return response.json();
}
```

---

## 12. Security Considerations

| Risk | Mitigation |
|------|------------|
| API key exposure | Show raw key only once, store only hash |
| Timing attacks | Use secrets.compare_digest |
| Key compromise | Keys are revocable instantly |
| Cross-tenant access | Keys bound to organization_id |
| Replay attacks | Idempotent source_event_ids |
| Data leakage | Centralized redaction |
| DoS attacks | Rate limiting + size limits |
| Log injection | Input validation, field limits |

---

## 13. Test Results

```
========== 648 passed, 31 skipped, 117 warnings in 147.40s ==========
```

### New Tests (51)
- test_step8_4_web_ingest.py: 51 tests covering all components

### Full Regression
- ✅ All existing functionality preserved
- ✅ STEP 8.1 Windows Event Log collection
- ✅ STEP 8.2 Windows detection rules
- ✅ STEP 8.3 Linux/SSH collection
- ✅ All other milestones

---

## 14. Migration Steps

1. Run database migration:
   ```bash
   alembic upgrade head
   ```

2. Create API key for each web application:
   ```bash
   curl -X POST https://api/v1/logs/web/keys \
     -H "Content-Type: application/json" \
     -d '{"source_id": "src-xxx", "name": "Web App Key"}'
   ```

3. Store returned raw_key securely (shown only once)

4. Configure web application to send logs to `/api/v1/logs/web/ingest`

---

## 15. Final Classification

### ✅ COMPLETE

**Rationale:**
- All code implemented and tested
- 51 unit/integration tests pass
- 648 total tests pass (full regression)
- Authentication, authorization, rate limiting implemented
- Tenant isolation enforced
- Idempotency via stable source_event_ids
- Integrates with existing canonical log architecture
- Ready for production deployment after migration
