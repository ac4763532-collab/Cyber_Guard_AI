"""
CyberGuard AI - Database Schema

SQL schema for PostgreSQL tables.
Run this to initialize the database structure.
"""

SCHEMA_SQL = """
-- ============================================================
-- Users Table
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT true,

    -- Password (null for Firebase users)
    password_hash VARCHAR(255),
    password_salt VARCHAR(255),

    -- Firebase integration
    firebase_uid VARCHAR(255) UNIQUE,
    auth_provider VARCHAR(50) DEFAULT 'local',

    -- Permissions
    can_create_alerts BOOLEAN DEFAULT false,
    can_run_analysis BOOLEAN DEFAULT false,
    can_manage_users BOOLEAN DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(LOWER(username));
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_firebase ON users(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- STEP 4 follow-up: real tenant/organization membership for human
-- analysts. Added via idempotent ALTER TABLE (not just inside CREATE
-- TABLE IF NOT EXISTS above) so this applies to databases where users
-- already exists from a prior schema version - never drops or rewrites
-- existing rows. Nullable: NULL means "no single-tenant restriction"
-- (today only meaningful for ADMIN, who already sees all tenants
-- regardless - see get_authorized_tenant_ids in app/api/v1/logs.py).
-- This closes the previously-documented gap where GET /logs/sources
-- (and other tenant-scoped query endpoints) hard-required a client
-- -supplied tenant_id query param with no server-side source of truth
-- for non-admin users to supply one from.
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);

-- ============================================================
-- Events Table
-- ============================================================
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    source VARCHAR(255) NOT NULL,
    raw_data JSONB NOT NULL,

    status VARCHAR(20) DEFAULT 'pending',
    processed_at TIMESTAMPTZ,

    risk_score INTEGER DEFAULT 0,
    severity VARCHAR(20) DEFAULT 'info',
    findings_count INTEGER DEFAULT 0,

    correlation_id UUID,
    related_events UUID[] DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation_id);

-- Phase 1 (Log Collection -> Automatic Detection): tenant ownership and
-- idempotency columns, added via idempotent ALTER TABLE (not just inside
-- CREATE TABLE IF NOT EXISTS above) so this applies to databases where
-- events already exists from a prior schema version. Mirrors the exact
-- pattern already used for log_events.tenant_id/source_event_id below.
--
-- tenant_id: nullable at the DB level. Historical rows created before
-- this column existed cannot be safely attributed to a tenant after the
-- fact (there is no reliable signal in raw_data to derive one from), so
-- they are deliberately left NULL rather than fabricated into a
-- "default"/"unknown" tenant - doing otherwise would misrepresent
-- ownership of real security events. New rows going forward always have
-- tenant_id populated at write time by the service layer (never trusted
-- from client input - see app/api/v1/events.py's use of
-- get_authorized_tenant_ids), the same convention as log_events.tenant_id.
--
-- source_event_id: lets a log-sourced SecurityEvent's log_events.id be
-- recorded as this row's external identifier, so EventRepository can
-- create one minimal events row per log event idempotently (ON CONFLICT
-- DO NOTHING) instead of either (a) inserting a fresh events row on
-- every Kafka redelivery of the same message, which would multiply rows
-- and break findings_count/statistics, or (b) relaxing findings.event_id
-- to no longer have a real foreign key. The partial unique index below
-- enforces this per (source, source_event_id) pair, matching the
-- log_events(source_id, source_event_id) unique index's shape.
ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE events ADD COLUMN IF NOT EXISTS source_event_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_event_unique
    ON events(source, source_event_id)
    WHERE source_event_id IS NOT NULL;

-- ============================================================
-- Findings Table
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID REFERENCES events(id) ON DELETE CASCADE,
    detection_id UUID NOT NULL,

    finding_type VARCHAR(50) NOT NULL,
    rule_id VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT DEFAULT 0.0,

    title VARCHAR(500) NOT NULL,
    description TEXT,
    evidence JSONB DEFAULT '{}',

    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',

    status VARCHAR(20) NOT NULL DEFAULT 'new',

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_event ON findings(event_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);

-- Phase 1: tenant ownership column, same rationale and nullability as
-- events.tenant_id above - a finding's tenant_id is always set at write
-- time by FindingRepository.create() from its parent event's resolved
-- tenant_id (see app/database/repositories/findings.py), never DB-enforced
-- against events.tenant_id via a trigger/constraint, consistent with how
-- the rest of this codebase treats cross-table tenant consistency
-- (e.g. correlation_id references) as an application-level invariant.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings(tenant_id);

-- Phase 1: lifecycle status column. Declared inside CREATE TABLE IF NOT
-- EXISTS above too, but that declaration alone is NOT idempotent against
-- a findings table that already existed before this column was added -
-- CREATE TABLE IF NOT EXISTS is a full no-op (including its column list)
-- once the table exists, exactly like tenant_id above. Mirrors
-- FindingStatus in app/database/models/base.py; 'new' matches
-- FindingStatus.NEW, the model's default.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'new';
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Phase 1: dedup key for idempotent finding persistence. A finding is
-- considered a duplicate if the same rule matched the same event again
-- (e.g. the underlying SecurityEvent was redelivered after a consumer
-- restart - see app/event_bus/consumer.py's manual-commit fix). Partial
-- (rule_id IS NOT NULL) because anomaly/IOC findings without a rule_id
-- are not deduped by this index; FindingRepository.find_duplicate()
-- handles that case with an explicit query instead.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_event_rule_unique
    ON findings(event_id, rule_id)
    WHERE rule_id IS NOT NULL;

-- ============================================================
-- Alerts Table
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    event_id UUID REFERENCES events(id) ON DELETE SET NULL,
    finding_ids UUID[] DEFAULT '{}',
    correlation_id UUID,

    -- Tenant isolation and deduplication
    tenant_id VARCHAR(255),
    fingerprint VARCHAR(64),

    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    risk_score INTEGER DEFAULT 0,

    status VARCHAR(30) DEFAULT 'new',
    assigned_to VARCHAR(255),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,

    source_ips INET[] DEFAULT '{}',
    destination_ips INET[] DEFAULT '{}',
    affected_assets TEXT[] DEFAULT '{}',

    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',

    notes JSONB DEFAULT '[]',
    actions_taken JSONB DEFAULT '[]',

    -- Deduplication: same correlation fingerprint within a tenant produces one alert
    UNIQUE(tenant_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_assigned ON alerts(assigned_to);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);

-- Automatic detection pipeline: distinguishes an individually-detected
-- alert (email_security / log_security / network_security) from a
-- cross-agent correlated_threat alert, independent of correlation_id
-- being set (an individual alert never has one; a correlated alert
-- always does, but the category is the stable, display-ready label).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS category VARCHAR(30);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

-- Additive incident lifecycle schema. Incidents are tenant-owned and
-- deduplicated by a deterministic fingerprint; evidence IDs remain linked
-- to their source records without copying or deleting those records.
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    finding_ids UUID[] NOT NULL DEFAULT '{}',
    alert_ids UUID[] NOT NULL DEFAULT '{}',
    event_ids UUID[] NOT NULL DEFAULT '{}',
    correlation_ids UUID[] NOT NULL DEFAULT '{}',
    recommendations JSONB NOT NULL DEFAULT '[]',
    actions_taken JSONB NOT NULL DEFAULT '[]',
    history JSONB NOT NULL DEFAULT '[]',
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_incidents_tenant_fingerprint UNIQUE (tenant_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);

-- ============================================================
-- IOCs Table
-- ============================================================
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type VARCHAR(50) NOT NULL,
    value VARCHAR(1000) NOT NULL,
    threat_level VARCHAR(20) NOT NULL,

    description TEXT,
    source VARCHAR(255) DEFAULT 'manual',
    tags TEXT[] DEFAULT '{}',

    active BOOLEAN DEFAULT true,
    verified BOOLEAN DEFAULT false,

    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    hit_count INTEGER DEFAULT 0,

    UNIQUE(ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_threat ON iocs(threat_level);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);

-- ============================================================
-- Detection Statistics Table
-- ============================================================
CREATE TABLE IF NOT EXISTS detection_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    date DATE NOT NULL,
    hour INTEGER,

    events_processed INTEGER DEFAULT 0,
    findings_total INTEGER DEFAULT 0,

    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,

    rule_matches INTEGER DEFAULT 0,
    ioc_matches INTEGER DEFAULT 0,
    anomalies_detected INTEGER DEFAULT 0,

    avg_risk_score FLOAT DEFAULT 0.0,
    avg_processing_time_ms FLOAT DEFAULT 0.0,

    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(date, hour)
);

CREATE INDEX IF NOT EXISTS idx_stats_date ON detection_stats(date DESC);

-- ============================================================
-- Audit Log Table
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID,

    user_id VARCHAR(255),
    ip_address INET,

    old_value JSONB,
    new_value JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- ============================================================
-- Notifications Table
--
-- Per-recipient delivery records for alerts. Distinct from `alerts`
-- (a tenant-wide detection record) - a single alert can fan out into
-- zero or more notification rows, one per (recipient, channel) pair,
-- each tracking its own real delivery outcome. Never marked
-- "delivered" except by the sending service after a confirmed
-- provider response.
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- What this notification is about
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,

    -- Tenant isolation and recipient
    tenant_id VARCHAR(255),
    recipient_user_id VARCHAR(255) NOT NULL,
    recipient_address VARCHAR(500),  -- email address / webhook URL actually used

    channel VARCHAR(20) NOT NULL,  -- 'in_app' | 'email' | 'webhook'
    severity VARCHAR(20) NOT NULL,

    title VARCHAR(500) NOT NULL,
    summary TEXT NOT NULL,  -- short evidence summary, never raw logs/credentials/full email bodies

    -- Deduplication: same (recipient, channel, fingerprint) is sent once
    fingerprint VARCHAR(64) NOT NULL,

    -- Delivery lifecycle - set only by the sending service, never by a client
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending | sent | failed | read
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW(),   -- when the underlying detection occurred
    queued_at TIMESTAMPTZ DEFAULT NOW(),    -- when this notification was created
    sent_at TIMESTAMPTZ,                    -- when delivery was confirmed by the provider
    read_at TIMESTAMPTZ,                    -- when the recipient acknowledged it in-app

    UNIQUE(recipient_user_id, channel, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);
CREATE INDEX IF NOT EXISTS idx_notifications_alert ON notifications(alert_id);

-- ============================================================
-- Analysis History Table (Step 12)
-- ============================================================
CREATE TABLE IF NOT EXISTS analysis_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Analysis results
    classification VARCHAR(32) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    findings JSONB DEFAULT '[]',

    -- Email metadata (NO body content - privacy)
    email_sender VARCHAR(255),
    email_subject VARCHAR(500),
    email_body_hash VARCHAR(64),  -- SHA-256 hash only

    -- Timing
    analyzed_at TIMESTAMPTZ DEFAULT NOW(),
    processing_time_ms FLOAT,

    -- Context
    analyzed_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_analysis_history_classification ON analysis_history(classification);
CREATE INDEX IF NOT EXISTS idx_analysis_history_analyzed_at ON analysis_history(analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_history_body_hash ON analysis_history(email_body_hash);
CREATE INDEX IF NOT EXISTS idx_analysis_history_analyzed_by ON analysis_history(analyzed_by);

-- ============================================================
-- Email Feedback Table (Step 12)
-- ============================================================
-- Postgres has no `CREATE TYPE IF NOT EXISTS`. Without this guard, re-running
-- this script against a database that already has these types (e.g. to pick
-- up a later ALTER TABLE/CREATE TABLE added below) fails outright with
-- "type already exists" and aborts the whole script before any later
-- statement runs - which is what silently prevented the notifications table
-- and findings.status/tenant_id columns further down from ever being applied
-- to this project's dev database. Wrapping in DO/EXCEPTION makes creation
-- idempotent like every other DDL statement in this file.
DO $$ BEGIN
    CREATE TYPE feedback_type AS ENUM ('false_positive', 'false_negative', 'wrong_category');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE feedback_status AS ENUM ('pending', 'approved', 'rejected', 'duplicate');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS email_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Link to original analysis
    analysis_id VARCHAR(64) NOT NULL,

    -- Original analysis results (server-populated)
    original_classification VARCHAR(32) NOT NULL,
    original_risk_score INTEGER NOT NULL CHECK (original_risk_score >= 0 AND original_risk_score <= 100),
    original_findings JSONB DEFAULT '[]',

    -- Feedback details
    feedback_type feedback_type NOT NULL,
    correct_classification VARCHAR(32),
    user_comment VARCHAR(1000),

    -- Email metadata (NO body content - privacy)
    email_sender VARCHAR(255),
    email_subject VARCHAR(500),
    email_body_hash VARCHAR(64),  -- SHA-256 hash only

    -- Submission metadata
    submitted_by VARCHAR(255),
    submitted_at TIMESTAMPTZ DEFAULT NOW(),

    -- Review workflow
    status feedback_status DEFAULT 'pending',
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMPTZ,
    review_notes VARCHAR(1000),

    -- Training integration
    included_in_training BOOLEAN DEFAULT false,
    training_batch_id VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_email_feedback_analysis_id ON email_feedback(analysis_id);
CREATE INDEX IF NOT EXISTS idx_email_feedback_status ON email_feedback(status);
CREATE INDEX IF NOT EXISTS idx_email_feedback_feedback_type ON email_feedback(feedback_type);
CREATE INDEX IF NOT EXISTS idx_email_feedback_submitted_at ON email_feedback(submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_feedback_submitted_by ON email_feedback(submitted_by);
CREATE INDEX IF NOT EXISTS idx_email_feedback_training ON email_feedback(included_in_training) WHERE status = 'approved';

-- ============================================================
-- Analysis History / Feedback generalization (Log Feedback feature)
-- ============================================================
-- Generalizes analysis_history/email_feedback (previously email-only,
-- see their Step 12 comments above) to also cover log analysis results,
-- so LogAgent's Module Performance can show a real, feedback-derived
-- accuracy figure instead of a fabricated one. analysis_type
-- distinguishes rows; context carries type-specific metadata that
-- doesn't fit the email_sender/subject/body_hash columns (e.g. log
-- source/source_host/processed_event_count instead). DEFAULT 'email'
-- backfills every pre-existing row correctly with no data migration -
-- this table was email-only until now.
ALTER TABLE analysis_history ADD COLUMN IF NOT EXISTS analysis_type VARCHAR(16) NOT NULL DEFAULT 'email';
ALTER TABLE analysis_history ADD COLUMN IF NOT EXISTS context JSONB DEFAULT '{}';

ALTER TABLE email_feedback ADD COLUMN IF NOT EXISTS analysis_type VARCHAR(16) NOT NULL DEFAULT 'email';

CREATE INDEX IF NOT EXISTS idx_analysis_history_type ON analysis_history(analysis_type);
CREATE INDEX IF NOT EXISTS idx_email_feedback_type_discriminator ON email_feedback(analysis_type);

-- "confirmed" (true positive) feedback type, needed so log feedback can
-- express a positive confirmation, not just the three mistake-only
-- types email feedback historically needed (false_positive/
-- false_negative/wrong_category) - without a positive signal there's no
-- way to compute "N of M findings confirmed correct" for Module
-- Performance. ADD VALUE IF NOT EXISTS is idempotent (PG12+). Safe here
-- because nothing in this same script inserts a row using the new
-- value - only later application code does, in a separate transaction.
ALTER TYPE feedback_type ADD VALUE IF NOT EXISTS 'confirmed';

-- ============================================================
-- OAuth Tokens Table (Step 5)
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- User association
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Provider info
    provider VARCHAR(50) NOT NULL DEFAULT 'google',
    provider_account_id VARCHAR(255),  -- Google user email

    -- Encrypted tokens (Fernet encrypted, base64 encoded)
    encrypted_access_token TEXT NOT NULL,
    encrypted_refresh_token TEXT,

    -- Token metadata (not sensitive)
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMPTZ,
    scopes TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One token per user per provider
    UNIQUE(user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_provider ON oauth_tokens(provider);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_provider_account ON oauth_tokens(provider_account_id);

-- ============================================================
-- Gmail Sync State Table
-- Automatic detection pipeline: persists each connected account's Gmail
-- history.list() cursor so the poller (app/services/gmail/poller.py)
-- only fetches new/changed messages each cycle instead of re-listing the
-- whole mailbox. One row per user (a user has at most one Gmail account
-- connected at a time, matching oauth_tokens' UNIQUE(user_id, provider)).
-- Deleted automatically when the user disconnects Gmail (ON DELETE
-- CASCADE from users), so a stale cursor is never left behind for an
-- account that no longer has valid tokens.
-- ============================================================
CREATE TABLE IF NOT EXISTS gmail_sync_state (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    -- Gmail's own incrementing history cursor. NULL until the first
    -- successful poll has established a baseline.
    history_id VARCHAR(255),

    -- Poll health, surfaced to the frontend "automatic monitoring" status
    -- indicator (EmailAnalysisPage) so a failing poll is visible instead
    -- of silently never updating.
    last_polled_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gmail_sync_state_user ON gmail_sync_state(user_id);

-- ============================================================
-- Log Sources Table (Step 8)
-- ============================================================
CREATE TABLE IF NOT EXISTS log_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,

    -- Type
    source_type VARCHAR(50) NOT NULL,
    collector_type VARCHAR(50) NOT NULL DEFAULT 'manual_upload',

    -- Status
    status VARCHAR(30) DEFAULT 'pending',
    last_event_at TIMESTAMPTZ,
    event_count BIGINT DEFAULT 0,
    error_message TEXT,

    -- Configuration (non-sensitive only - no passwords/tokens)
    configuration JSONB DEFAULT '{}',
    encrypted_config TEXT,  -- Fernet-encrypted credentials
    parser_config JSONB DEFAULT '{}',

    -- Filtering
    include_patterns TEXT[] DEFAULT '{}',
    exclude_patterns TEXT[] DEFAULT '{}',

    -- Ownership
    created_by VARCHAR(255),
    organization_id VARCHAR(255),

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_sources_name ON log_sources(name);
CREATE INDEX IF NOT EXISTS idx_log_sources_type ON log_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_log_sources_status ON log_sources(status);
CREATE INDEX IF NOT EXISTS idx_log_sources_created_by ON log_sources(created_by);

-- ============================================================
-- Log Events Table (Step 8)
-- ============================================================
CREATE TABLE IF NOT EXISTS log_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Source-specific event identifier for idempotency (STEP 8.0.1)
    source_event_id VARCHAR(255),

    -- Source identification
    source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    source_type VARCHAR(50) NOT NULL,
    hostname VARCHAR(255),
    program VARCHAR(255),
    pid INTEGER,

    -- Timestamps
    timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),

    -- Log content (secrets must be scrubbed before storage)
    level VARCHAR(20) NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    raw_content TEXT,

    -- Extracted fields
    extracted_fields JSONB DEFAULT '{}',

    -- Security analysis
    analyzed BOOLEAN DEFAULT false,
    analysis_result_id VARCHAR(64),
    risk_indicators TEXT[] DEFAULT '{}',

    -- Categorization
    tags TEXT[] DEFAULT '{}',
    category VARCHAR(100),

    -- Correlation
    correlation_id UUID,
    session_id VARCHAR(255)
);

-- STEP 4 (Log Agent Secure Ingestion): tenant/organization ownership column.
-- Added via idempotent ALTER TABLE (not just inside CREATE TABLE IF NOT
-- EXISTS above) so this applies to databases where log_events already
-- exists from a prior schema version. Never drops or rewrites existing
-- data. Nullable at the DB level for backward compatibility with any
-- pre-existing rows; application code (LogEventRepository.create/
-- create_batch) always populates it going forward from the trusted
-- LogSource.organization_id, never from client-supplied input. Named
-- "tenant_id" (not "organization_id") to match the vocabulary already
-- used by the correlation/alerting subsystem (see alerts.tenant_id,
-- correlated_activities.tenant_id below).
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

-- Retention (app/retention/cleanup.py): explicit preservation flag that
-- automatic cleanup must always skip, independent of age or whether a
-- Finding references the row. Defaults to false so existing rows are
-- not retroactively treated as held. Nullable-safe: cleanup's WHERE
-- clause checks `legal_hold IS NOT TRUE` so a NULL (pre-migration row
-- read before the DEFAULT applies, if any) is treated as "not held",
-- not as blocking deletion forever.
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT false;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_log_events_source ON log_events(source_id);
CREATE INDEX IF NOT EXISTS idx_log_events_source_type ON log_events(source_type);
CREATE INDEX IF NOT EXISTS idx_log_events_hostname ON log_events(hostname);
CREATE INDEX IF NOT EXISTS idx_log_events_timestamp ON log_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_log_events_level ON log_events(level);
CREATE INDEX IF NOT EXISTS idx_log_events_category ON log_events(category);
CREATE INDEX IF NOT EXISTS idx_log_events_analyzed ON log_events(analyzed);
CREATE INDEX IF NOT EXISTS idx_log_events_correlation ON log_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_log_events_tenant ON log_events(tenant_id);

-- Retention cleanup (app/retention/cleanup.py) scans for delete-eligible
-- rows via `tenant_id = X AND timestamp < cutoff AND legal_hold IS NOT
-- TRUE`, ordered for a bounded batch - this composite index lets that
-- scan use an index instead of a sequential scan on a table that can
-- grow very large. Partial on legal_hold = false since held rows are
-- never scanned for deletion and excluding them keeps the index smaller.
CREATE INDEX IF NOT EXISTS idx_log_events_retention_scan
    ON log_events(tenant_id, timestamp)
    WHERE legal_hold = false;

-- Full-text search on message (optional, for search feature)
CREATE INDEX IF NOT EXISTS idx_log_events_message_search ON log_events USING gin(to_tsvector('english', message));

-- STEP 8.0.1: Unique constraint for idempotency (source_id + source_event_id)
-- Allows duplicate detection on collector restart/retry
CREATE UNIQUE INDEX IF NOT EXISTS idx_log_events_source_event_unique
    ON log_events(source_id, source_event_id)
    WHERE source_id IS NOT NULL AND source_event_id IS NOT NULL;

-- ============================================================
-- Log Checkpoints Table (Step 8.0.1)
-- ============================================================
CREATE TABLE IF NOT EXISTS log_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- One checkpoint per source
    source_id UUID NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE UNIQUE,

    -- Checkpoint type determines value structure
    checkpoint_type VARCHAR(50) NOT NULL,

    -- Checkpoint data (JSON structure depends on type)
    -- WINDOWS_RECORD_ID: {"record_id": 12345, "channel": "Security", "computer": "DC01"}
    -- LINUX_FILE_OFFSET: {"inode": 123456, "offset": 78901, "path": "/var/log/auth.log"}
    -- WEB_EVENT_ID: {"event_id": "abc123", "timestamp": "2026-09-17T10:00:00Z"}
    checkpoint_value JSONB NOT NULL,

    -- When last updated
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_checkpoints_source ON log_checkpoints(source_id);
CREATE INDEX IF NOT EXISTS idx_log_checkpoints_updated ON log_checkpoints(updated_at DESC);

-- ============================================================
-- Correlated Activities Table (Step 8.5.3)
-- ============================================================
CREATE TABLE IF NOT EXISTS correlated_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Correlation identity
    correlation_id UUID NOT NULL UNIQUE,
    fingerprint VARCHAR(64) NOT NULL,

    -- Tenant isolation (mandatory)
    tenant_id VARCHAR(255) NOT NULL,

    -- Correlated items
    finding_ids UUID[] NOT NULL DEFAULT '{}',
    event_ids TEXT[] NOT NULL DEFAULT '{}',
    source_types TEXT[] NOT NULL DEFAULT '{}',

    -- Correlation metadata
    correlation_type VARCHAR(50) NOT NULL,
    correlation_strength FLOAT NOT NULL DEFAULT 0.0,
    shared_entities JSONB DEFAULT '{}',

    -- Risk assessment
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),

    -- Timestamps
    timestamp TIMESTAMPTZ NOT NULL,
    correlation_bucket VARCHAR(30) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Deduplication: unique fingerprint per tenant
    UNIQUE(tenant_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_correlated_activities_tenant ON correlated_activities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_correlated_activities_correlation_id ON correlated_activities(correlation_id);
CREATE INDEX IF NOT EXISTS idx_correlated_activities_fingerprint ON correlated_activities(fingerprint);
CREATE INDEX IF NOT EXISTS idx_correlated_activities_timestamp ON correlated_activities(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_correlated_activities_type ON correlated_activities(correlation_type);
CREATE INDEX IF NOT EXISTS idx_correlated_activities_bucket ON correlated_activities(correlation_bucket);

-- ============================================================
-- Reports Table (Step: Reporting Agent Persistence)
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    generated_by VARCHAR(255) NOT NULL,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    filters JSONB DEFAULT '{}',
    data JSONB NOT NULL DEFAULT '{}',
    narrative TEXT,
    file_path VARCHAR(1000),
    file_format VARCHAR(20),
    file_size_bytes INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_reports_tenant_type_period UNIQUE (tenant_id, report_type, period_start, period_end, generated_by)
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_generated_by ON reports(generated_by);

-- ============================================================
-- Trigger for updated_at
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS events_updated ON events;
CREATE TRIGGER events_updated
    BEFORE UPDATE ON events
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS alerts_updated ON alerts;
CREATE TRIGGER alerts_updated
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS incidents_updated ON incidents;
CREATE TRIGGER incidents_updated
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS users_updated ON users;
CREATE TRIGGER users_updated
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS oauth_tokens_updated ON oauth_tokens;
CREATE TRIGGER oauth_tokens_updated
    BEFORE UPDATE ON oauth_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS log_sources_updated ON log_sources;
CREATE TRIGGER log_sources_updated
    BEFORE UPDATE ON log_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
"""


async def create_schema(db) -> None:
    """Create database schema."""
    async with db.connection() as conn:
        await conn.execute(SCHEMA_SQL)
        await conn.commit()


async def drop_schema(db) -> None:
    """Drop all tables (use with caution!)."""
    drop_sql = """
    DROP TABLE IF EXISTS log_events CASCADE;
    DROP TABLE IF EXISTS log_sources CASCADE;
    DROP TABLE IF EXISTS email_feedback CASCADE;
    DROP TABLE IF EXISTS analysis_history CASCADE;
    DROP TABLE IF EXISTS audit_log CASCADE;
    DROP TABLE IF EXISTS detection_stats CASCADE;
    DROP TABLE IF EXISTS iocs CASCADE;
    DROP TABLE IF EXISTS alerts CASCADE;
    DROP TABLE IF EXISTS findings CASCADE;
    DROP TABLE IF EXISTS events CASCADE;
    DROP TABLE IF EXISTS users CASCADE;
    DROP TYPE IF EXISTS feedback_type CASCADE;
    DROP TYPE IF EXISTS feedback_status CASCADE;
    DROP FUNCTION IF EXISTS update_updated_at CASCADE;
    """
    async with db.connection() as conn:
        await conn.execute(drop_sql)
        await conn.commit()
