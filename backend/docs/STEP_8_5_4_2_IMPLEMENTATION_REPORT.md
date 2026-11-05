# STEP 8.5.4.2 - Alert Migration Safety + Production Persistence Verification

**Date:** 2026-09-18  
**Status:** ✅ COMPLETE

## Summary

This step hardened the alert migration and persistence path to ensure production-grade safety:
- SHA-256 fingerprints (NOT MD5)
- Separate UUID `id` and `fingerprint` columns
- `UNIQUE(tenant_id, fingerprint)` constraint for atomic deduplication
- Verified cross-tenant isolation
- PostgreSQL restart persistence verified

---

## 1. Schema Changes

### Migration File
`migrations/versions/step8_5_4_2_alert_schema.py`

### New Columns
| Column | Type | Constraints |
|--------|------|-------------|
| `fingerprint` | VARCHAR(64) | NOT NULL |
| `tenant_id` | VARCHAR(255) | NOT NULL |

### Constraints & Indexes
- `UNIQUE(tenant_id, fingerprint)` — `uq_alerts_tenant_fingerprint`
- `ix_alerts_fingerprint` — Individual fingerprint lookup
- `ix_alerts_tenant_id` — Tenant filtering
- `ix_alerts_correlation_id` — Correlation queries

---

## 2. Fingerprint Generation

### Algorithm: SHA-256 (NOT MD5)
```python
# In windows_integration.py
canonical = f"alert:{tenant_id}:{finding_fingerprint}"
alert_fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:32]
```

### Migration Backfill (PostgreSQL native)
```sql
fingerprint = SUBSTRING(
    encode(digest('legacy-alert:' || id::text, 'sha256'), 'hex'),
    1, 32
)
```

---

## 3. Atomic Deduplication

### ON CONFLICT Pattern
```sql
INSERT INTO alerts (id, fingerprint, tenant_id, ...)
VALUES (gen_random_uuid(), %(fingerprint)s, %(tenant_id)s, ...)
ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
    updated_at = EXCLUDED.updated_at
RETURNING id, (xmax = 0) AS inserted
```

**Key Features:**
- Separate UUID `id` — stable primary key
- `fingerprint` — deduplication key only
- `(xmax = 0)` — detects insert vs update atomically
- Race-condition safe via constraint

---

## 4. Verification Results

### 4.1 PostgreSQL Restart Persistence
```
✅ PASS - All 6 alerts survived restart (cleaned to 4 test alerts)
```

### 4.2 Cross-Tenant Isolation
```
✅ PASS - Same fingerprint allowed across different tenants
✅ PASS - Duplicate fingerprint within same tenant rejected
   ERROR: duplicate key value violates unique constraint "uq_alerts_tenant_fingerprint"
```

### 4.3 Test Suite
```
✅ 870 passed, 31 skipped in 137.22s
```

### 4.4 Infrastructure Health
| Service | Status |
|---------|--------|
| PostgreSQL | ✅ healthy |
| Redis | ✅ healthy (39 keys) |
| Redpanda | ✅ healthy (security-events topic) |

---

## 5. Historical Tenant Ownership

### Analysis
The 4 existing alerts were verified as test data:
- Titles: "Test Persistence Alert", "STEP3 Test Alert"
- No `event_id` associations
- No `correlation_id` associations

### Decision
Assigned to `'default'` tenant — safe for test data with no authoritative ownership.

---

## 6. Code Changes

### Modified Files
| File | Change |
|------|--------|
| `app/detection/windows_integration.py` | Separate UUID + fingerprint, SHA-256 |
| `app/database/models/base.py` | Added `fingerprint`, `tenant_id` fields |
| `app/database/repositories/alerts.py` | Updated `_row_to_alert()` |
| `migrations/versions/step8_5_4_2_alert_schema.py` | New staged migration |

### Removed Files
| File | Reason |
|------|--------|
| `migrations/versions/step8_5_4_1_alerts_fingerprint.py` | Used MD5 |

---

## 7. Security Audit Checklist

- [x] **SHA-256** — No weak hashing (MD5 removed)
- [x] **Tenant isolation** — `UNIQUE(tenant_id, fingerprint)` enforced
- [x] **No tenant bypass** — `tenant_id` from trusted source only
- [x] **Atomic deduplication** — ON CONFLICT handles race conditions
- [x] **Persistence verified** — Restart test passed
- [x] **No data loss** — Historical alerts preserved with deterministic fingerprints

---

## 8. Final Database State

```sql
SELECT COUNT(*) as total, COUNT(DISTINCT tenant_id) as tenants, 
       COUNT(DISTINCT fingerprint) as fingerprints FROM alerts;

 total | tenants | fingerprints 
-------+---------+--------------
     4 |       1 |            4
```

All alerts have valid SHA-256 fingerprints and tenant assignments.

---

## Status: ✅ COMPLETE

All STEP 8.5.4.2 requirements verified:
1. ✅ SHA-256 fingerprints (not MD5)
2. ✅ Separate UUID id and fingerprint columns
3. ✅ UNIQUE(tenant_id, fingerprint) constraint
4. ✅ Atomic concurrent deduplication via ON CONFLICT
5. ✅ Tenant-safe alert creation
6. ✅ PostgreSQL restart persistence verified
7. ✅ Cross-tenant isolation verified
8. ✅ All 870 tests passing
