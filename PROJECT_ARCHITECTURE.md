# CyberGuard AI - Complete Project Architecture

## 📋 Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Frontend Architecture](#frontend-architecture)
4. [Backend Architecture](#backend-architecture)
5. [Database Schema](#database-schema)
6. [ML Pipeline](#ml-pipeline)
7. [External Services](#external-services)
8. [API Endpoints](#api-endpoints)
9. [Data Flow Diagrams](#data-flow-diagrams)
10. [Deployment Architecture](#deployment-architecture)

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CYBERGUARD AI PLATFORM                                │
│                     AI-Powered Security Operations Center                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Core Capabilities:                                                             │
│  • Email Phishing Detection (ML + Rules + Threat Intel)                        │
│  • Log Security Analysis                                                        │
│  • Network Vulnerability Scanning                                               │
│  • Real-time Threat Monitoring                                                  │
│  • Incident Management                                                          │
│  • SOC Investigation Reports                                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Tech Stack Summary

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | React 18 + Vite + TypeScript | Modern SPA with type safety |
| Styling | Tailwind CSS | Utility-first CSS framework |
| State | React Query + Context | Server state + Auth state |
| Backend | FastAPI (Python 3.11+) | High-performance async API |
| Database | PostgreSQL | Primary data store |
| Cache | Redis | Rate limiting, caching, sessions |
| ML | scikit-learn (TF-IDF + LogReg) | Email classification |
| Auth | Firebase + JWT | Multi-provider authentication |
| Task Queue | Celery | Background job processing |

---

## 2. Architecture Diagram

```
                                    ┌──────────────────┐
                                    │   User Browser   │
                                    └────────┬─────────┘
                                             │
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (React + Vite)                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  Pages                                                                    │  │
│  │  ├── LoginPage          ├── DashboardPage      ├── EmailAnalysisPage    │  │
│  │  ├── SignupPage         ├── AlertsPage         ├── LogAnalysisPage      │  │
│  │  ├── SettingsPage       ├── IncidentsPage      ├── NetworkAnalysisPage  │  │
│  │  └── ReportsPage        └── EventsPage         └── AgentsPage           │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  Components: Sidebar | Header | Toast | Skeletons | Investigation Report │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │  Services: api.ts (axios) | AuthContext | React Query                    │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             │ HTTP/WebSocket
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                           BACKEND (FastAPI Python)                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  Middleware Layer                                                        │   │
│  │  • Rate Limiting (Redis)    • Request ID Tracking                       │   │
│  │  • Concurrency Control      • Logging & Security Events                 │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  API v1 Routers                                                          │   │
│  │  ├── /health       ├── /analysis      ├── /detection    ├── /auth      │   │
│  │  ├── /alerts       ├── /events        ├── /incidents    ├── /reports   │   │
│  │  ├── /gmail        ├── /llm           ├── /knowledge    ├── /metrics   │   │
│  │  ├── /correlation  ├── /feedback      ├── /training     └── /ws        │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │  Core Services                                                           │   │
│  │  ├── Email Analysis Agent (1100+ lines)                                 │   │
│  │  ├── Log Analysis Agent                                                  │   │
│  │  ├── Network Analysis Agent                                              │   │
│  │  ├── Detection Engine (Rules + IOC + Anomaly)                           │   │
│  │  ├── Correlation Engine                                                  │   │
│  │  └── Incident Manager                                                    │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────┘
           │              │              │               │              │
           ▼              ▼              ▼               ▼              ▼
    ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
    │PostgreSQL │  │   Redis   │  │  ML Model │  │ Firebase  │  │ External  │
    │  Database │  │   Cache   │  │ Classifier│  │   Auth    │  │   APIs    │
    └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘
```

---

## 3. Frontend Architecture

### 3.1 Directory Structure
```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx        # Navigation with real-time badges
│   │   │   └── Header.tsx         # Search, notifications, user menu
│   │   ├── ui/
│   │   │   ├── Toast.tsx          # Notification system
│   │   │   ├── KeyboardShortcuts.tsx  # Power user shortcuts
│   │   │   ├── Skeleton.tsx       # Loading states
│   │   │   └── EmptyState.tsx     # Empty data guidance
│   │   ├── auth/
│   │   │   ├── AuthLayout.tsx     # Auth page wrapper
│   │   │   ├── GoogleButton.tsx   # OAuth button
│   │   │   └── OTPInput.tsx       # Phone verification
│   │   └── EmailInvestigationReport.tsx  # SOC-style report (914 lines)
│   │
│   ├── pages/
│   │   ├── DashboardPage.tsx      # Real-time metrics & status
│   │   ├── EmailAnalysisPage.tsx  # Manual + Gmail analysis (869 lines)
│   │   ├── LogAnalysisPage.tsx    # Security log analysis
│   │   ├── NetworkAnalysisPage.tsx # Vulnerability scanning
│   │   ├── AlertsPage.tsx         # Security alerts
│   │   ├── IncidentsPage.tsx      # Incident management
│   │   ├── EventsPage.tsx         # Security events
│   │   ├── ReportsPage.tsx        # Generated reports
│   │   ├── AgentsPage.tsx         # AI agent status
│   │   ├── SettingsPage.tsx       # User preferences
│   │   └── Auth pages (Login, Signup, ForgotPassword, PhoneLogin, VerifyEmail)
│   │
│   ├── contexts/
│   │   └── AuthContext.tsx        # Authentication state management
│   │
│   ├── services/
│   │   └── api.ts                 # Axios API client
│   │
│   ├── lib/
│   │   └── firebase.ts            # Firebase configuration
│   │
│   ├── types/
│   │   └── index.ts               # TypeScript interfaces
│   │
│   ├── App.tsx                    # Routing configuration
│   └── main.tsx                   # App entry point
│
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

### 3.2 Data Flow (Frontend)
```
User Action
    │
    ▼
┌─────────────────┐
│  React Component │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  React Query    │────▶│    api.ts       │
│  (Caching)      │     │  (Axios Client) │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │ Backend API     │
                        │ /api/v1/*       │
                        └─────────────────┘
```

### 3.3 Authentication Flow
```
┌──────────────────────────────────────────────────────────────────────────┐
│                        AUTHENTICATION FLOW                               │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Option 1: Email/Password (Firebase)                                     │
│  ┌────────┐    ┌──────────┐    ┌─────────┐    ┌────────┐    ┌────────┐ │
│  │ User   │───▶│ Firebase │───▶│ID Token │───▶│Backend │───▶│  JWT   │ │
│  │ Login  │    │  Auth    │    │         │    │Verify  │    │ Token  │ │
│  └────────┘    └──────────┘    └─────────┘    └────────┘    └────────┘ │
│                                                                          │
│  Option 2: Google OAuth (Firebase)                                       │
│  ┌────────┐    ┌──────────┐    ┌─────────┐    ┌────────┐    ┌────────┐ │
│  │ User   │───▶│ Google   │───▶│Firebase │───▶│Backend │───▶│  JWT   │ │
│  │ Click  │    │  OAuth   │    │ID Token │    │Verify  │    │ Token  │ │
│  └────────┘    └──────────┘    └─────────┘    └────────┘    └────────┘ │
│                                                                          │
│  Option 3: Demo Mode (No Firebase)                                       │
│  ┌────────┐    ┌──────────┐    ┌────────┐                               │
│  │ User   │───▶│ Backend  │───▶│  JWT   │                               │
│  │ Login  │    │/auth/login│   │ Token  │                               │
│  └────────┘    └──────────┘    └────────┘                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Backend Architecture

### 4.1 Directory Structure
```
backend/
├── app/
│   ├── api/v1/
│   │   ├── router.py           # Main API router aggregator
│   │   ├── health.py           # Health check endpoints
│   │   ├── analysis.py         # Email/Log/Network analysis
│   │   ├── detection.py        # Threat detection
│   │   ├── correlation.py      # Event correlation
│   │   ├── incidents.py        # Incident management
│   │   ├── alerts.py           # Alert management
│   │   ├── events.py           # Security events
│   │   ├── auth.py             # Authentication
│   │   ├── reports.py          # Report generation
│   │   ├── gmail.py            # Gmail integration
│   │   ├── llm.py              # LLM endpoints
│   │   ├── knowledge.py        # RAG/Knowledge base
│   │   ├── metrics.py          # System metrics
│   │   ├── feedback.py         # User feedback
│   │   ├── training.py         # Model retraining
│   │   └── ws.py               # WebSocket endpoints
│   │
│   ├── agents/
│   │   ├── base.py             # Base agent class
│   │   ├── email_agent.py      # Email analysis (1106 lines)
│   │   ├── log_agent.py        # Log analysis
│   │   ├── network_agent.py    # Network scanning
│   │   └── dispatcher.py       # Agent orchestration
│   │
│   ├── services/
│   │   ├── email_auth/         # SPF/DKIM/DMARC verification
│   │   │   ├── spf_verifier.py
│   │   │   ├── dkim_verifier.py
│   │   │   ├── dmarc_checker.py
│   │   │   └── service.py
│   │   ├── url_analysis/       # URL security analysis
│   │   │   ├── patterns.py     # Suspicious URL patterns
│   │   │   ├── expander.py     # URL shortener expansion
│   │   │   ├── reputation.py   # Domain reputation
│   │   │   ├── safe_browsing.py # Google Safe Browsing
│   │   │   └── service.py
│   │   ├── attachment_analysis/  # File analysis
│   │   │   ├── hash_checker.py   # VirusTotal hash lookup
│   │   │   ├── file_type.py      # MIME type detection
│   │   │   ├── archive_inspector.py  # ZIP/RAR inspection
│   │   │   ├── macro_detector.py # Office macro detection
│   │   │   └── service.py
│   │   ├── threat_intel/       # External threat intelligence
│   │   │   └── service.py      # VirusTotal, AbuseIPDB
│   │   ├── gmail/              # Gmail API integration
│   │   │   ├── oauth.py
│   │   │   ├── client.py
│   │   │   └── parser.py
│   │   ├── rate_limiting/      # Redis rate limiter
│   │   ├── circuit_breaker/    # External API resilience
│   │   └── email_report_builder.py  # SOC report generation
│   │
│   ├── ml/
│   │   ├── classifier.py       # TF-IDF + Logistic Regression
│   │   ├── ensemble.py         # Multi-model ensemble
│   │   ├── url_analyzer.py     # URL-specific ML
│   │   ├── threshold_tuner.py  # Dynamic threshold tuning
│   │   ├── models/             # Trained model files
│   │   │   ├── tfidf_vectorizer.joblib
│   │   │   └── logistic_classifier.joblib
│   │   └── training/
│   │       ├── trainer.py
│   │       ├── pipeline.py
│   │       ├── model_manager.py
│   │       ├── data_combiner.py
│   │       └── feedback_exporter.py
│   │
│   ├── detection/
│   │   ├── engine.py           # Main detection orchestrator
│   │   ├── rules/              # Rule-based detection
│   │   │   ├── base.py
│   │   │   └── registry.py
│   │   ├── ioc.py              # IOC detection
│   │   ├── anomaly.py          # Anomaly detection
│   │   └── scoring.py          # Risk scoring
│   │
│   ├── correlation/
│   │   └── engine.py           # Event correlation
│   │
│   ├── incidents/
│   │   └── manager.py          # Incident lifecycle
│   │
│   ├── database/
│   │   ├── connection.py       # PostgreSQL connection pool
│   │   ├── init_db.py          # Schema initialization
│   │   └── repositories/
│   │       └── users.py        # User data access
│   │
│   ├── cache/
│   │   └── redis_client.py     # Redis client wrapper
│   │
│   ├── auth/
│   │   ├── models.py           # Auth data models
│   │   └── firebase_verify.py  # Firebase token verification
│   │
│   ├── llm/
│   │   ├── client.py           # Anthropic Claude client
│   │   ├── enhanced_client.py  # Advanced LLM features
│   │   └── prompts.py          # Prompt templates
│   │
│   ├── rag/
│   │   ├── knowledge.py        # Knowledge base
│   │   └── retriever.py        # Document retrieval
│   │
│   ├── websocket/
│   │   ├── manager.py          # WebSocket connection manager
│   │   └── events.py           # Real-time event broadcasting
│   │
│   ├── middleware/
│   │   ├── rate_limit.py       # Rate limiting middleware
│   │   ├── concurrency.py      # Concurrent request limiting
│   │   ├── request_id.py       # Request tracking
│   │   └── logging.py          # Request/response logging
│   │
│   ├── metrics/
│   │   └── collector.py        # Prometheus metrics
│   │
│   ├── logging/
│   │   └── security_events.py  # Security event logging
│   │
│   ├── tasks/
│   │   ├── celery_app.py       # Celery configuration
│   │   ├── analysis.py         # Background analysis tasks
│   │   └── notifications.py    # Notification tasks
│   │
│   ├── schemas/
│   │   └── email_report.py     # Pydantic schemas
│   │
│   ├── core/
│   │   ├── email_enums.py      # Email-related enums
│   │   └── domain_utils.py     # Domain utilities
│   │
│   └── config.py               # Settings management
│
├── tests/                       # 277 automated tests
├── data/
│   └── phishing_email.csv      # Training data (18,650 samples)
├── main.py                     # Application entry point
├── requirements.txt
└── .env.example
```

### 4.2 Email Analysis Pipeline (Core Feature)
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         EMAIL ANALYSIS PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  INPUT                                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Email Data: Subject, Body, Sender, Headers, URLs, Attachments         │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 1: ML CLASSIFICATION                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  TF-IDF Vectorizer → Logistic Regression → Phishing/Legitimate Score   │    │
│  │  Model: 99.70% accuracy on test set                                    │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 2: RULE-BASED DETECTION                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  • Urgency patterns (URGENT, IMMEDIATE ACTION)                         │    │
│  │  • Suspicious sender domains                                           │    │
│  │  • Credential request patterns                                         │    │
│  │  • Typosquatting detection                                             │    │
│  │  • Header anomalies                                                    │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 3: EMAIL AUTHENTICATION                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  SPF Verification  →  DKIM Verification  →  DMARC Check                │    │
│  │  (DNS lookups)        (Crypto validation)    (Policy check)            │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 4: URL ANALYSIS                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  • Pattern matching (IP URLs, long params, suspicious TLDs)            │    │
│  │  • URL expansion (bit.ly, tinyurl)                                     │    │
│  │  • Domain reputation (creation date, registrar)                        │    │
│  │  • Google Safe Browsing API check                                      │    │
│  │  • VirusTotal URL reputation                                           │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 5: ATTACHMENT ANALYSIS                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  • File type detection (magic bytes, extension)                        │    │
│  │  • Hash lookup (VirusTotal)                                            │    │
│  │  • Macro detection (Office documents)                                  │    │
│  │  • Archive inspection (nested files, password protection)              │    │
│  │  • Executable detection                                                │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 6: THREAT INTELLIGENCE                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  • VirusTotal: Domain/IP/URL reputation                                │    │
│  │  • AbuseIPDB: IP abuse reports                                         │    │
│  │  • Cached results (1hr malicious, 24hr clean)                          │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  STAGE 7: RISK SCORING                                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Weighted aggregation of all signals → Risk Score (0-100)              │    │
│  │  • ML confidence: 40%                                                  │    │
│  │  • Rule matches: 25%                                                   │    │
│  │  • Auth failures: 15%                                                  │    │
│  │  • URL/Attachment: 15%                                                 │    │
│  │  • Threat Intel: 5%                                                    │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  OUTPUT                                                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  • Classification: phishing | suspicious | legitimate                  │    │
│  │  • Risk Score: 0-100                                                   │    │
│  │  • Severity: critical | high | medium | low | info                     │    │
│  │  • Findings: List of detected issues with evidence                     │    │
│  │  • Indicators: IOCs (malicious URLs, IPs, hashes)                      │    │
│  │  • Authentication: SPF/DKIM/DMARC results                              │    │
│  │  • Recommendations: Actionable security advice                         │    │
│  │  • MITRE ATT&CK: Mapped techniques                                     │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Database Schema

### 5.1 PostgreSQL Tables
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    firebase_uid VARCHAR(255) UNIQUE,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'analyst',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Security Events
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source VARCHAR(255),
    data JSONB,
    timestamp TIMESTAMP DEFAULT NOW(),
    processed BOOLEAN DEFAULT false
);

-- Alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    source VARCHAR(255),
    event_ids UUID[],
    assigned_to UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

-- Incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    alert_ids UUID[],
    assigned_to UUID REFERENCES users(id),
    timeline JSONB,
    root_cause TEXT,
    remediation TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

-- Analysis Results (for auditing)
CREATE TABLE analysis_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_type VARCHAR(50) NOT NULL,
    input_hash VARCHAR(64),
    result JSONB NOT NULL,
    risk_score INTEGER,
    classification VARCHAR(50),
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- User Feedback (for model retraining)
CREATE TABLE feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES analysis_results(id),
    user_id UUID REFERENCES users(id),
    original_classification VARCHAR(50),
    corrected_classification VARCHAR(50),
    comment TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Gmail OAuth Tokens
CREATE TABLE gmail_tokens (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    email VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    scopes TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### 5.2 Redis Data Structures
```
# Rate Limiting
rate_limit:{user_id}:{endpoint} → Counter with TTL

# Threat Intel Cache
threat_intel:vt:{ioc_hash} → JSON result with TTL
threat_intel:abuseipdb:{ip} → JSON result with TTL

# Circuit Breaker State
circuit:{service_name} → {failures: N, state: open|closed, last_failure: timestamp}

# Session Cache
session:{token} → User JSON with TTL

# Analysis Queue
analysis:queue → List of pending analysis jobs
```

---

## 6. ML Pipeline

### 6.1 Model Architecture
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           ML CLASSIFICATION PIPELINE                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  TRAINING DATA                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  phishing_email.csv: 18,650 samples                                    │    │
│  │  • Phishing: 9,116 samples (48.9%)                                     │    │
│  │  • Legitimate: 9,534 samples (51.1%)                                   │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  PREPROCESSING                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  1. MIME header decoding                                               │    │
│  │  2. HTML stripping (preserve URLs)                                     │    │
│  │  3. Text normalization                                                 │    │
│  │  4. Subject + Body concatenation                                       │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  FEATURE EXTRACTION                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  TF-IDF Vectorizer                                                     │    │
│  │  • max_features: 10,000                                                │    │
│  │  • ngram_range: (1, 2)                                                 │    │
│  │  • sublinear_tf: True                                                  │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  CLASSIFIER                                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Logistic Regression                                                   │    │
│  │  • C: 1.0 (regularization)                                             │    │
│  │  • class_weight: balanced                                              │    │
│  │  • max_iter: 1000                                                      │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                    │                                            │
│                                    ▼                                            │
│  MODEL PERFORMANCE                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Accuracy:  99.70%                                                     │    │
│  │  Precision: 99.63% (phishing)                                          │    │
│  │  Recall:    99.78% (phishing)                                          │    │
│  │  F1-Score:  99.70%                                                     │    │
│  │                                                                        │    │
│  │  Confusion Matrix:                                                     │    │
│  │  ┌─────────────────────────────────┐                                   │    │
│  │  │              Predicted          │                                   │    │
│  │  │           Legit    Phish        │                                   │    │
│  │  │  Actual ┌───────┬───────┐       │                                   │    │
│  │  │  Legit │ 1900  │    7  │        │                                   │    │
│  │  │  Phish │    4  │ 1819  │        │                                   │    │
│  │  │        └───────┴───────┘       │                                   │    │
│  │  └─────────────────────────────────┘                                   │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Continuous Learning Pipeline
```
┌────────────────────────────────────────────────────────────────────────────────┐
│                         CONTINUOUS LEARNING FLOW                               │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐             │
│  │  User    │────▶│ Analysis │────▶│ Feedback │────▶│ Feedback │             │
│  │ Submits  │     │ Result   │     │ "Wrong!" │     │   DB     │             │
│  │  Email   │     │          │     │          │     │          │             │
│  └──────────┘     └──────────┘     └──────────┘     └──────────┘             │
│                                                           │                   │
│                                                           ▼                   │
│                                    ┌──────────────────────────────────────┐   │
│                                    │  Feedback Exporter (Weekly/Manual)   │   │
│                                    │  Exports corrected samples to CSV    │   │
│                                    └──────────────────────────────────────┘   │
│                                                           │                   │
│                                                           ▼                   │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Data Combiner                                                        │    │
│  │  • Original training data (18,650)                                    │    │
│  │  • + User feedback samples                                            │    │
│  │  • Deduplication                                                      │    │
│  │  • Balance check                                                      │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                          │                                    │
│                                          ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Trainer                                                              │    │
│  │  • Retrain TF-IDF + Logistic Regression                              │    │
│  │  • Cross-validation                                                   │    │
│  │  • Performance comparison                                             │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                          │                                    │
│                                          ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Model Manager                                                        │    │
│  │  • Version control (model_v1, model_v2, ...)                          │    │
│  │  • A/B testing support                                                │    │
│  │  • Rollback capability                                                │    │
│  │  • Hot-swap in production                                             │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. External Services Integration

### 7.1 Service Map
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL SERVICE INTEGRATIONS                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  AUTHENTICATION                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Firebase Authentication                                                │    │
│  │  • Google OAuth 2.0                                                    │    │
│  │  • Email/Password                                                      │    │
│  │  • Phone (SMS OTP)                                                     │    │
│  │  • ID Token verification                                               │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  THREAT INTELLIGENCE                                                            │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  VirusTotal API                                                        │    │
│  │  • URL reputation (malicious/clean/suspicious)                         │    │
│  │  • Domain reputation                                                   │    │
│  │  • IP address analysis                                                 │    │
│  │  • File hash lookup                                                    │    │
│  │  Rate Limit: 4 requests/minute (free tier)                            │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  AbuseIPDB                                                             │    │
│  │  • IP abuse reports                                                    │    │
│  │  • Abuse confidence score                                              │    │
│  │  • ISP/Country information                                             │    │
│  │  Rate Limit: 1000 requests/day (free tier)                            │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Google Safe Browsing API                                              │    │
│  │  • URL threat detection                                                │    │
│  │  • Malware, phishing, unwanted software                               │    │
│  │  Rate Limit: 10,000 requests/day                                      │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  EMAIL INTEGRATION                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Gmail API (OAuth 2.0)                                                 │    │
│  │  • Read user emails                                                    │    │
│  │  • Fetch email content, headers, attachments                          │    │
│  │  • List/search messages                                                │    │
│  │  Scopes: gmail.readonly, userinfo.email                               │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  LLM (Optional Enhancement)                                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Anthropic Claude API                                                  │    │
│  │  • Natural language analysis                                           │    │
│  │  • Report generation                                                   │    │
│  │  • Contextual recommendations                                          │    │
│  │  Model: claude-sonnet-4-20250514                                       │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Rate Limiting & Circuit Breaker
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     RESILIENCE PATTERNS FOR EXTERNAL APIS                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  RATE LIMITING (Redis-backed)                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Service          │ Limit          │ Window                            │    │
│  │  ─────────────────┼────────────────┼─────────────────────────────────  │    │
│  │  VirusTotal       │ 4 requests     │ per minute                        │    │
│  │  AbuseIPDB        │ 60 requests    │ per minute                        │    │
│  │  Safe Browsing    │ 8000 requests  │ per day                           │    │
│  │  Email Analysis   │ 30 requests    │ per minute (per user)             │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  CIRCUIT BREAKER                                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │                                                                        │    │
│  │  CLOSED ──(failures > 5)──▶ OPEN ──(60s timeout)──▶ HALF-OPEN         │    │
│  │     ▲                          │                         │             │    │
│  │     │                          │                         │             │    │
│  │     └──────────────────────────┴──(success)──────────────┘             │    │
│  │                                                                        │    │
│  │  States:                                                               │    │
│  │  • CLOSED: Normal operation, requests pass through                    │    │
│  │  • OPEN: All requests fail-fast, return cached/default                │    │
│  │  • HALF-OPEN: Test single request, decide next state                  │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
│  CACHING STRATEGY                                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │  Result Type      │ Cache TTL                                          │    │
│  │  ─────────────────┼─────────────────────────────────────────────────── │    │
│  │  Malicious        │ 1 hour (refresh frequently)                       │    │
│  │  Clean            │ 24 hours (stable)                                  │    │
│  │  Error/Unknown    │ 5 minutes (retry soon)                             │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. API Endpoints

### 8.1 Complete API Reference
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              API v1 ENDPOINTS                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  HEALTH                                                                         │
│  GET  /api/v1/health              Simple health check                          │
│  GET  /api/v1/health/detailed     Detailed component status                    │
│                                                                                 │
│  AUTHENTICATION                                                                 │
│  POST /api/v1/auth/login          Username/password login                      │
│  POST /api/v1/auth/firebase-login Firebase ID token exchange                   │
│  GET  /api/v1/auth/firebase-status Check Firebase availability                 │
│  GET  /api/v1/auth/me             Get current user                             │
│  GET  /api/v1/auth/verify         Verify token validity                        │
│                                                                                 │
│  ANALYSIS                                                                       │
│  POST /api/v1/analysis/email      Analyze email for phishing                   │
│  POST /api/v1/analysis/logs       Analyze security logs                        │
│  POST /api/v1/analysis/network    Network vulnerability scan                   │
│                                                                                 │
│  GMAIL INTEGRATION                                                              │
│  GET  /api/v1/gmail/status        Check Gmail connection                       │
│  GET  /api/v1/gmail/connect       Initiate OAuth flow                          │
│  GET  /api/v1/gmail/oauth/callback OAuth callback handler                      │
│  POST /api/v1/gmail/disconnect    Revoke Gmail access                          │
│  GET  /api/v1/gmail/messages      List Gmail messages                          │
│  GET  /api/v1/gmail/messages/{id} Get message details                          │
│  POST /api/v1/gmail/analyze/{id}  Analyze specific message                     │
│  POST /api/v1/gmail/investigate/{id} Full SOC investigation                    │
│  POST /api/v1/gmail/batch         Batch analyze messages                       │
│                                                                                 │
│  DETECTION                                                                      │
│  POST /api/v1/detection/analyze   Run detection engine                         │
│  GET  /api/v1/detection/rules     List detection rules                         │
│                                                                                 │
│  CORRELATION                                                                    │
│  POST /api/v1/correlation/analyze Correlate events                             │
│                                                                                 │
│  INCIDENTS                                                                      │
│  GET  /api/v1/incidents           List incidents                               │
│  POST /api/v1/incidents           Create incident                              │
│  GET  /api/v1/incidents/{id}      Get incident details                         │
│  PUT  /api/v1/incidents/{id}      Update incident                              │
│  GET  /api/v1/incidents/statistics Incident statistics                         │
│                                                                                 │
│  ALERTS                                                                         │
│  GET  /api/v1/alerts              List alerts                                  │
│  POST /api/v1/alerts              Create alert                                 │
│  GET  /api/v1/alerts/{id}         Get alert details                            │
│  PUT  /api/v1/alerts/{id}         Update alert                                 │
│  GET  /api/v1/alerts/statistics   Alert statistics                             │
│                                                                                 │
│  EVENTS                                                                         │
│  GET  /api/v1/events              List security events                         │
│  POST /api/v1/events              Create event                                 │
│  GET  /api/v1/events/{id}         Get event details                            │
│  GET  /api/v1/events/statistics   Event statistics                             │
│                                                                                 │
│  REPORTS                                                                        │
│  GET  /api/v1/reports             List generated reports                       │
│  POST /api/v1/reports             Generate new report                          │
│  GET  /api/v1/reports/{id}        Get report details                           │
│                                                                                 │
│  FEEDBACK (Model Improvement)                                                   │
│  POST /api/v1/feedback            Submit analysis feedback                     │
│  GET  /api/v1/feedback            List feedback entries                        │
│                                                                                 │
│  TRAINING (Admin)                                                               │
│  POST /api/v1/training/retrain    Trigger model retraining                     │
│  GET  /api/v1/training/status     Get training status                          │
│  GET  /api/v1/training/models     List model versions                          │
│                                                                                 │
│  LLM                                                                            │
│  POST /api/v1/llm/analyze         LLM-powered analysis                         │
│  POST /api/v1/llm/explain         Explain detection results                    │
│                                                                                 │
│  KNOWLEDGE (RAG)                                                                │
│  POST /api/v1/knowledge/query     Query knowledge base                         │
│  POST /api/v1/knowledge/ingest    Add to knowledge base                        │
│                                                                                 │
│  METRICS                                                                        │
│  GET  /api/v1/metrics             Prometheus metrics                           │
│  GET  /api/v1/metrics/dashboard   Dashboard metrics                            │
│                                                                                 │
│  WEBSOCKET                                                                      │
│  WS   /api/v1/ws                  Real-time event stream                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Data Flow Diagrams

### 9.1 User Email Analysis Flow
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      MANUAL EMAIL ANALYSIS FLOW                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  User                   Frontend                    Backend                     │
│   │                        │                           │                        │
│   │ 1. Paste email         │                           │                        │
│   │───────────────────────▶│                           │                        │
│   │                        │                           │                        │
│   │                        │ 2. POST /analysis/email   │                        │
│   │                        │──────────────────────────▶│                        │
│   │                        │                           │                        │
│   │                        │                           │ 3. Email Agent         │
│   │                        │                           │    ┌─────────────────┐ │
│   │                        │                           │    │ ML Classifier   │ │
│   │                        │                           │    │ Rule Engine     │ │
│   │                        │                           │    │ Auth Verify     │ │
│   │                        │                           │    │ URL Analysis    │ │
│   │                        │                           │    │ Threat Intel    │ │
│   │                        │                           │    └─────────────────┘ │
│   │                        │                           │                        │
│   │                        │ 4. Analysis Result        │                        │
│   │                        │◀──────────────────────────│                        │
│   │                        │                           │                        │
│   │ 5. Display Report      │                           │                        │
│   │◀───────────────────────│                           │                        │
│   │                        │                           │                        │
│   │ 6. Submit Feedback     │                           │                        │
│   │───────────────────────▶│ POST /feedback            │                        │
│   │                        │──────────────────────────▶│                        │
│   │                        │                           │ 7. Store for           │
│   │                        │                           │    retraining          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Gmail Integration Flow
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         GMAIL INTEGRATION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  User        Frontend           Backend            Google              Gmail    │
│   │             │                  │                 │                   │      │
│   │ 1. Click    │                  │                 │                   │      │
│   │  "Connect"  │                  │                 │                   │      │
│   │────────────▶│                  │                 │                   │      │
│   │             │ GET /gmail/connect                 │                   │      │
│   │             │─────────────────▶│                 │                   │      │
│   │             │                  │                 │                   │      │
│   │             │◀─ auth_url ──────│                 │                   │      │
│   │             │                  │                 │                   │      │
│   │◀── Redirect to Google ────────│                 │                   │      │
│   │                                                  │                   │      │
│   │ 2. Grant permission ────────────────────────────▶│                   │      │
│   │                                                  │                   │      │
│   │◀── Redirect with code ──────────────────────────│                   │      │
│   │             │                  │                 │                   │      │
│   │             │ GET /oauth/callback?code=...      │                   │      │
│   │             │─────────────────▶│                 │                   │      │
│   │             │                  │ Exchange code   │                   │      │
│   │             │                  │────────────────▶│                   │      │
│   │             │                  │◀── tokens ──────│                   │      │
│   │             │                  │                 │                   │      │
│   │             │                  │ Store tokens    │                   │      │
│   │             │◀─ Connected ─────│                 │                   │      │
│   │             │                  │                 │                   │      │
│   │ 3. List     │                  │                 │                   │      │
│   │  emails     │ GET /gmail/messages               │                   │      │
│   │────────────▶│─────────────────▶│                 │                   │      │
│   │             │                  │─────────────────────────────────────▶│      │
│   │             │                  │◀──────────── messages ──────────────│      │
│   │             │◀─ email list ────│                 │                   │      │
│   │             │                  │                 │                   │      │
│   │ 4. Analyze  │ POST /gmail/analyze/{id}          │                   │      │
│   │────────────▶│─────────────────▶│                 │                   │      │
│   │             │                  │─────────────────────────────────────▶│      │
│   │             │                  │◀──────────── full email ────────────│      │
│   │             │                  │                 │                   │      │
│   │             │                  │ Run analysis    │                   │      │
│   │             │                  │ pipeline        │                   │      │
│   │             │◀─ result ────────│                 │                   │      │
│   │◀─ report ───│                  │                 │                   │      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Real-time Monitoring Flow
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        REAL-TIME MONITORING FLOW                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Dashboard         WebSocket Manager          Detection Engine       Database   │
│      │                   │                          │                   │       │
│      │ 1. Connect WS     │                          │                   │       │
│      │──────────────────▶│                          │                   │       │
│      │                   │                          │                   │       │
│      │◀── Connected ─────│                          │                   │       │
│      │                   │                          │                   │       │
│      │                   │                          │ 2. New Event      │       │
│      │                   │                          │◀──────────────────│       │
│      │                   │                          │                   │       │
│      │                   │                          │ 3. Process        │       │
│      │                   │                          │    • Rules        │       │
│      │                   │                          │    • IOC check    │       │
│      │                   │                          │    • Scoring      │       │
│      │                   │                          │                   │       │
│      │                   │                          │ 4. Generate Alert │       │
│      │                   │                          │──────────────────▶│       │
│      │                   │                          │                   │       │
│      │                   │◀── Alert Event ──────────│                   │       │
│      │                   │                          │                   │       │
│      │◀── Push Alert ────│                          │                   │       │
│      │                   │                          │                   │       │
│      │ 5. Update UI      │                          │                   │       │
│      │   (badge, toast)  │                          │                   │       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Deployment Architecture

### 10.1 Development Setup
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DEVELOPMENT ENVIRONMENT                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐ │
│  │  Local Machine                                                             │ │
│  │                                                                            │ │
│  │  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │ │
│  │  │  Frontend   │     │   Backend   │     │  PostgreSQL │                  │ │
│  │  │  Vite Dev   │────▶│   Uvicorn   │────▶│  (Docker)   │                  │ │
│  │  │  :5173      │     │   :8000     │     │  :5432      │                  │ │
│  │  └─────────────┘     └─────────────┘     └─────────────┘                  │ │
│  │                             │                                              │ │
│  │                             ▼                                              │ │
│  │                      ┌─────────────┐                                       │ │
│  │                      │    Redis    │                                       │ │
│  │                      │  (Docker)   │                                       │ │
│  │                      │   :6379     │                                       │ │
│  │                      └─────────────┘                                       │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  Commands:                                                                      │
│  # Frontend                                                                     │
│  cd frontend && npm run dev                                                    │
│                                                                                 │
│  # Backend                                                                      │
│  cd backend && uvicorn main:app --reload                                       │
│                                                                                 │
│  # Docker services                                                              │
│  docker-compose up -d postgres redis                                           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Production Architecture
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PRODUCTION DEPLOYMENT                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                              ┌────────────────┐                                 │
│                              │   CloudFlare   │                                 │
│                              │   (CDN/WAF)    │                                 │
│                              └───────┬────────┘                                 │
│                                      │                                          │
│                              ┌───────▼────────┐                                 │
│                              │  Load Balancer │                                 │
│                              │   (Nginx/ALB)  │                                 │
│                              └───────┬────────┘                                 │
│                                      │                                          │
│                    ┌─────────────────┼─────────────────┐                       │
│                    │                 │                 │                        │
│            ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐              │
│            │   Frontend    │ │   Backend     │ │   Backend     │              │
│            │   (Static)    │ │   Instance 1  │ │   Instance 2  │              │
│            │   S3/Nginx    │ │   (Docker)    │ │   (Docker)    │              │
│            └───────────────┘ └───────┬───────┘ └───────┬───────┘              │
│                                      │                 │                        │
│                    ┌─────────────────┴─────────────────┘                       │
│                    │                                                            │
│         ┌─────────┴─────────┬─────────────────┬─────────────────┐             │
│         │                   │                 │                 │              │
│  ┌──────▼──────┐    ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐    │
│  │ PostgreSQL  │    │     Redis     │ │    Celery     │ │   ML Model    │    │
│  │   (RDS)     │    │  (ElastiCache)│ │   Workers     │ │   Service     │    │
│  │   Primary   │    │    Cluster    │ │   (2-4x)      │ │               │    │
│  │  + Replica  │    │               │ │               │ │               │    │
│  └─────────────┘    └───────────────┘ └───────────────┘ └───────────────┘    │
│                                                                                 │
│  Infrastructure:                                                                │
│  • Container: Docker + Kubernetes (EKS/GKE)                                    │
│  • Database: AWS RDS / Google Cloud SQL                                        │
│  • Cache: AWS ElastiCache / GCP Memorystore                                    │
│  • Storage: S3 for static assets, model files                                  │
│  • Secrets: AWS Secrets Manager / GCP Secret Manager                           │
│  • Monitoring: Prometheus + Grafana, CloudWatch/Stackdriver                    │
│  • Logging: ELK Stack / CloudWatch Logs                                        │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Environment Variables

```bash
# =============================================================================
# REQUIRED CONFIGURATION (.env)
# =============================================================================

# Application
APP_NAME=CyberGuard AI
ENVIRONMENT=development  # development | staging | production
DEBUG=true

# Database (PostgreSQL)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyberguard
DB_USER=postgres
DB_PASSWORD=your_secure_password
DB_ENABLED=true

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=generate-with-openssl-rand-hex-32

# Firebase Authentication
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_SERVICE_ACCOUNT_PATH=/path/to/service-account.json

# Google OAuth (Gmail API)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/gmail/oauth/callback

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your-vt-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
GOOGLE_SAFE_BROWSING_API_KEY=your-safe-browsing-key

# LLM (Optional)
ANTHROPIC_API_KEY=your-anthropic-key

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_EMAIL_ANALYSIS=30/minute
```

---

## 12. Quick Start Commands

```bash
# Clone repository
git clone https://github.com/your-org/cyberguard-ai.git
cd cyberguard-ai

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
uvicorn main:app --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev

# Access
# Frontend: http://localhost:5173
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

---

## 13. Feature Checklist

| Feature | Status | Backend | Frontend |
|---------|--------|---------|----------|
| Email Phishing Detection (ML) | ✅ | `ml/classifier.py` | `EmailAnalysisPage` |
| Rule-based Detection | ✅ | `agents/email_agent.py` | - |
| SPF/DKIM/DMARC Verification | ✅ | `services/email_auth/` | Results displayed |
| URL Analysis | ✅ | `services/url_analysis/` | - |
| Attachment Analysis | ✅ | `services/attachment_analysis/` | - |
| Threat Intelligence | ✅ | `services/threat_intel/` | IOC display |
| Gmail Integration | ✅ | `services/gmail/` | Gmail tab |
| SOC Investigation Report | ✅ | `services/email_report_builder.py` | `EmailInvestigationReport` |
| Log Analysis | ✅ | `agents/log_agent.py` | `LogAnalysisPage` |
| Network Scanning | ✅ | `agents/network_agent.py` | `NetworkAnalysisPage` |
| Firebase Authentication | ✅ | `auth/firebase_verify.py` | Auth pages |
| Real-time Dashboard | ✅ | Health/Stats APIs | `DashboardPage` |
| Alert Management | ✅ | `api/v1/alerts.py` | `AlertsPage` |
| Incident Management | ✅ | `incidents/manager.py` | `IncidentsPage` |
| User Feedback Loop | ✅ | `api/v1/feedback.py` | Feedback buttons |
| Model Retraining | ✅ | `ml/training/` | Admin only |
| WebSocket Events | ✅ | `websocket/manager.py` | Sidebar badges |
| Rate Limiting | ✅ | `middleware/rate_limit.py` | - |
| Circuit Breaker | ✅ | `services/circuit_breaker/` | - |

---

*Last Updated: September 2026*
*Version: 1.0*
