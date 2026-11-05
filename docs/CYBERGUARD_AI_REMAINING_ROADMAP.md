# CyberGuard AI — Remaining Roadmap

**Generated:** 2026-09-18  
**Based on:** Master Project Audit (same date)  
**Ordering principle:** Dependencies first. A later item never requires knowledge of an earlier unfinished item to be safe to ship.

---

## How to read this document

- **P0** = Production blocker. System cannot be safely deployed without this fix.
- **P1** = Feature broken or incorrect for production use. Fix before enabling the affected feature.
- **P2** = Functional gap that produces misleading or fabricated data. Fix before GA.
- **P3** = Hardening, operations, and reliability. Fix before sustained production operation.

Each item states: what to do, which file(s) to change, and why it is ordered where it is.

---

## Phase 0 — Unblock the live pipeline (do these first, in order)

These items fix the already-live detection pipeline. They are ordered by dependency: item 0.1 must be done before 0.2 because the schema change is a prerequisite for testing correlation.

### 0.1 — Create the `correlated_activities` PostgreSQL table

**Priority:** P0  
**Blocker for:** 0.2, all correlation persistence  
**Evidence:** `backend/app/database/schema.py` — no `CREATE TABLE correlated_activities`; `STEP_8_5_6` report line 28

**What to do:**

Add a `CREATE TABLE IF NOT EXISTS correlated_activities` statement to `backend/app/database/schema.py` matching the INSERT columns referenced in `backend/app/database/repositories/correlated_activities.py`. Apply the SQL to the live database.

Minimum required columns (derive exact column list from the repository INSERT statement):
- `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
- `tenant_id VARCHAR NOT NULL`
- `finding_ids UUID[] DEFAULT '{}'`
- `correlation_key VARCHAR NOT NULL`
- `entity_type VARCHAR`
- `entity_value VARCHAR`
- `created_at TIMESTAMPTZ DEFAULT NOW()`

Then establish Alembic tracking so this table and all future changes are version-controlled:

```bash
cd backend
alembic revision --autogenerate -m "add_correlated_activities"
alembic upgrade head
```

**Why first:** Every finding creation in the already-live pipeline calls `trigger_realtime_correlation()`, which calls `CorrelatedActivityRepository`. Without this table, every finding in production causes a PostgreSQL `UndefinedTable` error.

---

### 0.2 — Resolve the incident query type mismatch

**Priority:** P1  
**Depends on:** 0.1 (stable schema)  
**Evidence:** `STEP_8_5_6` report line 29 — "INCIDENT: ⚠️ NOT VERIFIED — Query type mismatch (minor)"

**What to do:**

Read `backend/app/incidents/manager.py` and `backend/app/database/repositories/incidents.py`. Identify the column or parameter where a Python type (e.g., `str` UUID vs `uuid.UUID`) does not match the PostgreSQL column type. Add an explicit cast or use the correct type. Run a live query against the incidents table to confirm no error.

**Why here:** The reports endpoint calls `list_incidents_async()` on every report request. A type error here means all report generation may fail or produce partial data.

---

### 0.3 — Fix the reports time-window filter

**Priority:** P1  
**Depends on:** 0.2 (incidents query working)  
**Evidence:** `backend/app/api/v1/reports.py:75–84`

**What to do:**

Pass `period_start` to all three repository calls in `get_summary_report()`:

```python
# Current (broken):
events = await event_repo.list(limit=1000)
alerts = await alert_repo.list(limit=1000)
incidents = await incident_mgr.list_incidents_async(limit=1000)

# Required (add after= / since= parameter to each repository list() method):
events = await event_repo.list(limit=1000, created_after=period_start)
alerts = await alert_repo.list(limit=1000, created_after=period_start)
incidents = await incident_mgr.list_incidents_async(limit=1000, created_after=period_start)
```

Add the `created_after` parameter to:
- `backend/app/database/repositories/events.py` — `list()` method
- `backend/app/database/repositories/alerts.py` — `list()` method
- `backend/app/incidents/manager.py` — `list_incidents_async()` method

Each should add a `WHERE created_at >= $N` clause to the SQL query when the parameter is provided.

Apply the same fix to `get_threat_landscape()` (lines 233–274) where `event_repo.list()` and `alert_repo.list()` also lack time filters.

**Why here:** Time-window reporting is a core feature. After the pipeline bugs are fixed, this is the next highest-impact data correctness fix.

---

## Phase 1 — Security fixes (P0 items, ordered by risk)

### 1.1 — Replace the insecure SECRET_KEY default

**Priority:** P0  
**Depends on:** Nothing  
**Evidence:** `.env:10` — `SECRET_KEY=dev-secret-change-in-production`

**What to do:**

1. Generate a cryptographically random key:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. Replace the value in `.env` with the generated key.
3. Confirm `.env` is in `.gitignore` and has never been committed to git history. If it has been committed, rotate the key and treat all previously issued JWTs as compromised.
4. Document the key rotation procedure for production deployments.

**Why here:** A known `SECRET_KEY` allows anyone to forge JWTs for any tenant. This is a complete authentication bypass.

---

### 1.2 — Remove DEMO-AUTH-TOKEN-2024 from NetworkAnalysisPage

**Priority:** P0  
**Depends on:** 1.3 (the real fix; this removes the symptom)  
**Evidence:** `frontend/src/pages/NetworkAnalysisPage.tsx` lines 71, 100, 110

**What to do:**

Replace the hardcoded default token with an empty string at all three locations:
- Line 71: state initialization
- Line 100: `handleReset()` 
- Line 110: `loadSampleTarget()`

The form should start empty and require the user to explicitly enter a value.

---

### 1.3 — Implement real authorization_token validation server-side

**Priority:** P0  
**Depends on:** 1.2  
**Evidence:** `backend/app/agents/network_agent.py` `validate()` — checks `authorized: bool` only; `backend/app/schemas/analysis.py:123`

**What to do:**

Decide on one of two valid approaches:

**Option A (remove the token field entirely):** The `authorized: bool` boolean is the correct model — the user affirmatively confirms authorization. Remove `authorization_token` from `NetworkAnalysisRequest` and from the frontend form. Update `frontend/src/services/api.ts:134` to remove the field. This is the simpler path.

**Option B (validate the token):** If the intent is that the token is a real credential (e.g., a pre-shared key proving the user owns the target range), add server-side validation: check the token against a user record or a network authorization table in PostgreSQL. The frontend must be updated to make clear what a valid token looks like.

**Do not** leave the current state where the field exists, is sent by the frontend, but is silently ignored by the backend.

---

### 1.4 — Disable or clearly gate the network scan simulation

**Priority:** P0  
**Depends on:** Nothing  
**Evidence:** `backend/app/agents/network_agent.py:332–355` — `_simulate_scan()` hardcodes service versions

**What to do:**

When nmap is not installed or fails, the agent must NOT return fabricated scan results as real data. Two acceptable approaches:

**Option A (fail loudly):** When `_run_nmap_scan()` encounters an error or nmap is absent, raise an exception or return an explicit error response: `{"status": "error", "message": "nmap not installed or scan failed. Real scan results unavailable."}`. The frontend should surface this as an error state, not as analysis data.

**Option B (label clearly and gate):** If simulation is intentionally kept for development/demo purposes, gate it behind an explicit config flag (`SIMULATION_MODE=true` in `.env`) that is `false` by default. The response schema must include `"simulated": true` at the top level, and the frontend must render a prominent warning: "SIMULATED DATA — NOT REAL SCAN RESULTS".

Do not remove the `_simulate_scan()` function until the nmap path is live-verified.

---

## Phase 2 — Data integrity fixes

### 2.1 — Verify and fix alerts repository tenant isolation

**Priority:** P0/P1 (determine severity by reading the full list() method)  
**Depends on:** Phase 0 complete  
**Evidence:** `backend/app/database/repositories/alerts.py` `list()` — no `tenant_id` WHERE clause confirmed in reviewed excerpt

**What to do:**

Read the complete `list()` method in `backend/app/database/repositories/alerts.py`. If `tenant_id` is not present as a WHERE clause filter, add it:

```python
# Add to list() signature:
async def list(self, ..., tenant_id: str | None = None) -> list[Alert]:
    ...
    # Add to WHERE clause:
    WHERE ... AND ($N IS NULL OR tenant_id = $N)
```

Confirm the same isolation exists in `events`, `findings`, `incidents`, and `log_events` repositories. Any repository that returns data without scoping to `tenant_id` is a data leakage risk.

---

### 2.2 — Remove hardcoded stats from AgentsPage

**Priority:** P2  
**Depends on:** Nothing (independent frontend fix)  
**Evidence:** `frontend/src/pages/AgentsPage.tsx:219–233`

**What to do:**

Remove the hardcoded strings: "Phishing Rules: 3", "IOC Types: 4", "Accuracy: 98%", "Log Types: 6", "Patterns: 15", "Anomaly ML: Active", "Scan Types: 4", "Port Checks: 1000+".

Replace with one of:
- Real data fetched from the corresponding API (`detectionApi.getRules()` returns the actual rule list; count them)
- Empty/loading state while data is unavailable
- Omit the stat entirely if there is no real data source for it

"Accuracy: 98%" must be removed. There is no data source for this claim.

---

### 2.3 — Unify risk scoring across agents

**Priority:** P2  
**Depends on:** Nothing (independent backend fix)  
**Evidence:** `backend/app/agents/email_agent.py`, `log_agent.py`, `network_agent.py` — each has `_calculate_risk()`; `backend/app/detection/scoring.py` — `RiskScoringEngine`

**What to do:**

Replace the agent-local `_calculate_risk()` implementations with calls to `get_scoring_engine()` from `backend/app/detection/scoring.py`. Each agent should construct the appropriate input dict (rule_match score, ioc_match score, anomaly score, correlation score) and call `scoring_engine.calculate_risk(...)`.

This ensures risk scores from agent-based analysis (email, log, network) are on the same scale and use the same thresholds as the detection pipeline.

---

## Phase 3 — Activate non-functional features

### 3.1 — Configure ANTHROPIC_API_KEY

**Priority:** P1  
**Depends on:** Nothing  
**Evidence:** `.env:13` — `ANTHROPIC_API_KEY=` (empty)

**What to do:**

Add a valid Anthropic API key to `.env`. Verify with a live call to `GET /api/v1/llm/status`. Confirm `POST /llm/analyze-threat`, `POST /llm/remediation`, `POST /llm/enrich-ioc`, `POST /llm/map-mitre` all return valid responses.

Add the key to deployment secrets management (not hardcoded in any file).

---

### 3.2 — Live-verify WIN-002 and WIN-003 detection rules

**Priority:** P2  
**Depends on:** 0.1, live detection pipeline  
**Evidence:** `STEP_8_5_6` report — WIN-001 verified, WIN-002/WIN-003 unverified

**What to do:**

Using `scripts/live_e2e_verification.py` as a template, write a verification script that:

1. Injects 3 Event ID 4625 failures followed by 1 Event ID 4624 success from the same source IP → verifies WIN-002 triggers
2. Injects 1 Event ID 4672 → verifies WIN-003 triggers

Run against the live pipeline. Confirm findings appear in PostgreSQL with correct rule_id values.

---

### 3.3 — Live-verify web log ingestion end-to-end

**Priority:** P2  
**Depends on:** 0.1  
**Evidence:** `POST /api/v1/logs/web/ingest` — endpoint exists, no E2E report

**What to do:**

POST structured log entries to `/api/v1/logs/ingest`. Confirm:
1. Entries are stored in `log_events` table
2. If `publish_to_bus=true`, events appear in Redpanda
3. Detection rules evaluate the events
4. Findings/alerts created for matching patterns

---

### 3.4 — Live-verify Gmail OAuth integration

**Priority:** P2  
**Depends on:** 3.1 (LLM active for email analysis)  
**Evidence:** `STEP_8_5_8` report claims "ALREADY COMPLETE" but no runtime OAuth flow verification documented

**What to do:**

Perform an actual OAuth connect flow:
1. Call `GET /api/v1/gmail/oauth/connect`
2. Complete Google OAuth in browser
3. Confirm callback stores refresh token
4. Call `GET /api/v1/gmail/messages` — confirm real messages returned
5. Call `POST /api/v1/gmail/analyze/{messageId}` — confirm real analysis result

---

## Phase 4 — Operations and hardening

### 4.1 — Initialize Alembic and create baseline migration

**Priority:** P1  
**Depends on:** 0.1 (correlated_activities table exists before baseline is stamped)  
**Evidence:** `STEP_8_5_6` report: "Alembic is NOT INITIALIZED for this project"

```bash
cd backend
alembic init alembic
# Edit alembic.ini to point to DATABASE_URL
alembic revision --autogenerate -m "baseline_schema_2026_09_18"
alembic stamp head
```

All future schema changes must go through Alembic revisions.

---

### 4.2 — Add rate limiting

**Priority:** P3  
**Depends on:** Nothing  

Add `slowapi` or equivalent middleware to FastAPI. Apply per-IP limits to analysis endpoints (`/analysis/email`, `/analysis/logs`, `/analysis/network`) and per-tenant limits to ingestion endpoints.

---

### 4.3 — Implement data retention

**Priority:** P3  
**Depends on:** 4.1 (Alembic in place before adding new schema objects)  

Add a Celery periodic task that:
- Purges `log_events` older than a configurable retention window (default 90 days)
- Purges `events` older than a configurable window (default 365 days)
- Removes `iocs` where `expires_at < NOW()`

Add a `retention_days` configuration key to `.env`.

---

### 4.4 — Create backup and recovery procedures

**Priority:** P3  
**Depends on:** Nothing  

Add `scripts/backup.sh` that runs `pg_dump` with connection parameters from environment variables and stores the output to a dated file. Document restore procedure. Compliance check in `reports.py:292` currently returns `"backup_configured": False` — update to `True` once a real backup job is configured.

---

### 4.5 — Add HTTPS, CORS, and CSP hardening

**Priority:** P3  
**Depends on:** Nothing  

In `backend/app/main.py`:
- Configure `CORSMiddleware` with an explicit `allow_origins` list (not `["*"]`)
- Add security headers middleware (X-Content-Type-Options, X-Frame-Options, Content-Security-Policy)

Add TLS configuration to the Redpanda and PostgreSQL connection strings for production deployments.

---

### 4.6 — Create production deployment manifests

**Priority:** P3  
**Depends on:** All P0 and P1 items resolved  

Create either:
- `docker-compose.yml` covering FastAPI, PostgreSQL, Redis, Redpanda, and the frontend
- Or Kubernetes manifests with secrets management (not `.env` files)

Ensure `SECRET_KEY`, `ANTHROPIC_API_KEY`, and `DB_PASSWORD` are injected via environment secrets, not file-based configuration.

---

## NEXT IMPLEMENTATION STEP

**Create the `correlated_activities` table in `backend/app/database/schema.py` and apply it to the PostgreSQL database.**

This is the single most important action because:

1. The detection pipeline is already live and writing findings to PostgreSQL.
2. Every finding creation calls `trigger_realtime_correlation()`, which calls `CorrelatedActivityRepository`.
3. That repository references a table that does not exist.
4. This causes a PostgreSQL `UndefinedTable` error on every finding in the running system right now.
5. All other roadmap items depend on a stable, error-free pipeline.

**Exact steps:**

1. Read `backend/app/database/repositories/correlated_activities.py` to confirm the exact column names in the INSERT statement.
2. Add the `CREATE TABLE IF NOT EXISTS correlated_activities (...)` block to `backend/app/database/schema.py`.
3. Apply the SQL to the live PostgreSQL database.
4. Restart the FastAPI service.
5. Run `scripts/live_e2e_verification.py` and confirm: findings created, no `UndefinedTable` errors in logs, `correlated_activities` rows present after the run.

---

```
TERMINAL SUMMARY
================

Audit date:    2026-09-18
Repository:    E:\CyberGuard_AI

LIVE VERIFIED (production-quality evidence):
  - Redpanda consumer group cyberguard-security-processor: Stable, LAG=0, offset 111
  - WIN-001 detection rule: triggered and verified in PostgreSQL
  - Findings + Alerts: persisted to PostgreSQL with tenant isolation and dedup
  - Frontend API client: real backend data, no mock values in production paths

PRODUCTION BLOCKERS (P0) — 5 items:
  1. SECRET_KEY=dev-secret-change-in-production (.env:10) — JWT forgery possible
  2. correlated_activities table MISSING from schema.py — runtime error on every finding
  3. DEMO-AUTH-TOKEN-2024 hardcoded in NetworkAnalysisPage.tsx (lines 71, 100, 110)
  4. authorization_token never validated server-side (network_agent.py validate())
  5. _simulate_scan() returns fabricated service versions as real scan data

BROKEN FEATURES (P1):
  - Reports time-window: period_start computed but never passed to DB queries (reports.py:75-84)
  - Incident query type mismatch: unresolved from STEP_8_5_6
  - LLM features: ANTHROPIC_API_KEY empty (.env:13)
  - Alerts tenant isolation: tenant_id filter unconfirmed in alerts repository list()

FABRICATED DATA IN UI (P2):
  - AgentsPage.tsx:219-233: "Accuracy: 98%", "Phishing Rules: 3", "Port Checks: 1000+"
    are hardcoded string literals with no data source

NEXT IMPLEMENTATION STEP:
  Add CREATE TABLE correlated_activities to backend/app/database/schema.py
  and apply to live database. This unblocks the already-live detection pipeline.

Documents produced:
  docs/CYBERGUARD_AI_MASTER_PROJECT_AUDIT.md   — 44-section evidence-backed audit
  docs/CYBERGUARD_AI_REMAINING_ROADMAP.md      — dependency-ordered P0→P3 roadmap
```
