"""Generate CyberGuard AI project survey PDF report."""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import date

OUTPUT = "E:/CyberGuard_AI/docs/CyberGuard_AI_Project_Report.pdf"

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=letter,
    leftMargin=0.85*inch,
    rightMargin=0.85*inch,
    topMargin=0.9*inch,
    bottomMargin=0.9*inch,
)

styles = getSampleStyleSheet()

CYAN   = colors.HexColor("#06b6d4")
DARK   = colors.HexColor("#0f172a")
GRAY   = colors.HexColor("#64748b")
LIGHT  = colors.HexColor("#f1f5f9")
RED    = colors.HexColor("#ef4444")
GREEN  = colors.HexColor("#22c55e")
AMBER  = colors.HexColor("#f59e0b")

title_style = ParagraphStyle("Title", parent=styles["Title"],
    fontSize=24, textColor=DARK, spaceAfter=6, alignment=TA_CENTER)
subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"],
    fontSize=11, textColor=GRAY, spaceAfter=4, alignment=TA_CENTER)
h1_style = ParagraphStyle("H1", parent=styles["Heading1"],
    fontSize=14, textColor=CYAN, spaceBefore=16, spaceAfter=6,
    borderPad=0)
h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
    fontSize=11, textColor=DARK, spaceBefore=10, spaceAfter=4)
body_style = ParagraphStyle("Body", parent=styles["Normal"],
    fontSize=9.5, textColor=DARK, spaceAfter=4, leading=14)
small_style = ParagraphStyle("Small", parent=styles["Normal"],
    fontSize=8.5, textColor=GRAY, spaceAfter=3, leading=12)
warn_style = ParagraphStyle("Warn", parent=styles["Normal"],
    fontSize=9, textColor=colors.HexColor("#92400e"),
    backColor=colors.HexColor("#fef3c7"),
    borderPad=6, spaceAfter=6, leading=13)

def hr():
    return HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=8)

def section(title):
    return [Paragraph(title, h1_style), hr()]

def tbl(data, col_widths, header=True):
    t = Table(data, colWidths=col_widths)
    ts = [
        ("BACKGROUND", (0, 0), (-1, 0 if header else -1), CYAN if header else LIGHT),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white if header else DARK),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
    ]
    if header:
        ts.append(("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"))
    t.setStyle(TableStyle(ts))
    return t

story = []

# ── Cover ────────────────────────────────────────────────────────────────────
story += [
    Spacer(1, 0.5*inch),
    Paragraph("CyberGuard AI", title_style),
    Paragraph("Project Survey Report", subtitle_style),
    Paragraph(f"Generated: {date.today().strftime('%B %d, %Y')}", small_style),
    Spacer(1, 0.3*inch),
    hr(),
    Spacer(1, 0.1*inch),
]

# ── 1. Overview ───────────────────────────────────────────────────────────────
story += section("1. Project Overview")
story += [
    Paragraph(
        "CyberGuard AI is a full-stack Security Operations Centre (SOC) platform "
        "with an AI-driven threat analysis backend and a React dashboard frontend. "
        "The project was built incrementally across multiple milestones (Steps 2–8.5.x), "
        "each adding a new detection or integration capability.",
        body_style,
    ),
    Spacer(1, 6),
    tbl(
        [["Area", "Technology"],
         ["Backend framework", "FastAPI 0.115+ / Python 3.14 / Uvicorn"],
         ["Database", "PostgreSQL 16 via psycopg3 + SQLAlchemy 2.0 + Alembic"],
         ["Cache / state", "Redis 7"],
         ["Event bus", "Apache Redpanda (Kafka-compatible)"],
         ["Frontend", "React 18 + TypeScript, Vite 5, TanStack Query v5, Tailwind CSS"],
         ["Auth", "Firebase (Google OAuth / email / phone) + backend JWT"],
         ["ML", "scikit-learn TF-IDF + Logistic Regression (phishing classifier)"],
         ["Threat intel", "Google Safe Browsing API + VirusTotal + local IOC rules"],
         ["Infra", "Docker Compose (backend, PostgreSQL, Redis, Redpanda)"]],
        [2.2*inch, 4.0*inch],
    ),
    Spacer(1, 8),
]

# ── 2. Repository Layout ──────────────────────────────────────────────────────
story += section("2. Repository Layout")
story += [
    tbl(
        [["Directory", "Contents"],
         ["backend/app/", "FastAPI application — agents, API routes, services, ML, DB, auth"],
         ["backend/tests/", "~27 pytest test modules"],
         ["backend/ml_models/", "Trained model artefacts (phishing_model.pkl, vectorizer)"],
         ["frontend/src/", "React pages, components, contexts, services"],
         ["docs/", "Step implementation reports (STEP_*.md, GMAIL_AUTH_401_FIX_REPORT.md)"],
         ["email_analysis_ml_data/", "Offline ML data pipeline scripts"],
         ["docker-compose.yml", "Multi-service orchestration"]],
        [2.0*inch, 4.2*inch],
    ),
    Spacer(1, 8),
]

# ── 3. Backend Modules ─────────────────────────────────────────────────────────
story += section("3. Backend Modules")
story += [Paragraph("3.1 Agents", h2_style)]
story += [
    tbl(
        [["Agent", "Status", "Description"],
         ["EmailAgent", "Implemented", "SPF/DKIM/DMARC, URL analysis, attachment scan, ML classify, brand impersonation"],
         ["LogAgent", "Implemented", "Windows Event Log + Linux syslog / journald collector"],
         ["NetworkAgent", "Stub", "Placeholder — registered but returns pending"],
         ["TaskDispatcher", "Implemented", "Routes analysis requests; falls back to PlaceholderAgent on import failure"]],
        [1.6*inch, 1.2*inch, 3.4*inch],
    ),
    Spacer(1, 8),
    Paragraph("3.2 API Routes (v1)", h2_style),
    tbl(
        [["Route prefix", "Feature"],
         ["/auth", "Login, Firebase exchange, JWT verify, user management"],
         ["/gmail", "OAuth connect/disconnect, list/get/analyze/investigate messages"],
         ["/analysis", "Manual email / log / network analysis submission"],
         ["/detection", "Rule engine, IOC matching, anomaly, scoring"],
         ["/alerts", "CRUD, status, statistics"],
         ["/events", "Ingest, reanalyze, statistics"],
         ["/incidents", "Create (manual + from correlation), timeline, statistics"],
         ["/correlation", "Cross-event correlation engine"],
         ["/logs", "Log source management, event ingestion, raw ingest"],
         ["/reports", "Summary, executive, threat-landscape, compliance"],
         ["/llm", "Threat analysis, IOC enrichment, MITRE mapping, remediation"],
         ["/knowledge", "RAG search, MITRE technique/CVE lookup"],
         ["/ws", "WebSocket realtime channel manager"],
         ["/metrics", "Prometheus-style metrics collector"],
         ["/training", "Feedback export, model retrain, threshold tuning"]],
        [1.6*inch, 4.6*inch],
    ),
    Spacer(1, 8),
    Paragraph("3.3 Services", h2_style),
    tbl(
        [["Service", "Description"],
         ["url_analysis/service.py", "URL expansion, pattern scoring, Safe Browsing, VirusTotal"],
         ["email_report_builder.py", "Assembles SOC-style EmailInvestigationReport from agent output"],
         ["gmail/ (OAuth + parser)", "Gmail OAuth2 flow, GmailParser (MIME, auth headers, URLs, attachments)"],
         ["threat_intel/", "IOC batch lookup, TTL-cached results"],
         ["attachment_analysis/", "Macro detection, archive inspection, file hash"],
         ["oauth_state_store.py", "Redis-backed CSRF-safe OAuth state"],
         ["token_encryption.py", "AES-GCM encryption for stored OAuth tokens"],
         ["circuit_breaker.py", "Per-service failure isolation"]],
        [2.2*inch, 4.0*inch],
    ),
    Spacer(1, 8),
]

# ── 4. Frontend ────────────────────────────────────────────────────────────────
story += section("4. Frontend")
story += [
    tbl(
        [["Page", "Feature"],
         ["Dashboard", "KPI tiles, alert feed, realtime WebSocket updates"],
         ["EmailAnalysis", "Manual paste analysis + Gmail OAuth integration tab"],
         ["Alerts / Incidents / Events", "List, filter, detail view, status update"],
         ["LogAnalysis", "Source management, event browser, raw ingest"],
         ["NetworkAnalysis", "Stub — minimal UI"],
         ["Reports", "Summary, executive, compliance, threat landscape"],
         ["Settings", "User profile, API key management"],
         ["Auth pages", "Login, Signup, ForgotPassword, VerifyEmail, PhoneLogin"]],
        [1.8*inch, 4.4*inch],
    ),
    Spacer(1, 6),
    Paragraph(
        "The frontend uses a single authenticated Axios instance with a request interceptor "
        "that attaches the backend JWT from localStorage. A response interceptor clears the "
        "session on 401 only when the request carried a token (fixed 2026-09-18 to prevent "
        "race-condition session wipes during Firebase auth initialization).",
        body_style,
    ),
    Spacer(1, 8),
]

# ── 5. ML Pipeline ─────────────────────────────────────────────────────────────
story += section("5. Machine Learning Pipeline")
story += [
    tbl(
        [["Component", "Detail"],
         ["Classifier", "TF-IDF vectorizer + Logistic Regression (scikit-learn)"],
         ["Training data", "Offline pipeline in email_analysis_ml_data/"],
         ["Inference", "app/ml/classifier.py — ml_predict() in EmailAgent"],
         ["Continuous learning", "FeedbackExporter → ModelTrainer → ThresholdTuner"],
         ["Model artefacts", "backend/ml_models/phishing_model.pkl + vectorizer.pkl"],
         ["Ensemble", "app/ml/ensemble.py — multiple model voting (if configured)"]],
        [2.0*inch, 4.2*inch],
    ),
    Spacer(1, 8),
]

# ── 6. Test Coverage ───────────────────────────────────────────────────────────
story += section("6. Test Coverage")
story += [
    Paragraph("Backend has ~27 pytest test modules. Last full run: 781 passed / 1 pre-existing Redis e2e failure / 26 skipped.", body_style),
    Spacer(1, 4),
    tbl(
        [["Test file", "Covers"],
         ["test_email_regression.py", "Email agent end-to-end scenarios"],
         ["test_url_analyzer.py", "URL pattern + Safe Browsing + VirusTotal"],
         ["test_step6_oauth_state.py", "Gmail OAuth state (29 tests)"],
         ["test_step8_*.py (6 files)", "Correlation engine, Redis state, log ingestion, web ingest, e2e"],
         ["test_step7*.py (3 files)", "Event bus, Redpanda live integration"],
         ["test_step5_*.py", "Windows/Linux log collector"],
         ["test_feedback_*.py", "Continuous learning feedback loop"],
         ["test_detection_*.py", "Rule engine, IOC, anomaly, scoring"],
         ["Frontend tests", "None — no test framework configured"]],
        [2.4*inch, 3.8*inch],
    ),
    Spacer(1, 8),
]

# ── 7. Known Issues ────────────────────────────────────────────────────────────
story += section("7. Known Issues & Incomplete Areas")
story += [
    tbl(
        [["Severity", "Issue", "Location"],
         ["HIGH", "serviceAccountKey.json committed to repo (Firebase credentials)", "backend/"],
         ["HIGH", "Malformed pip artefacts: =0.10.0 and =3.4.0 directories", "backend/"],
         ["MEDIUM", "RAG knowledge base has no vector DB dependency — may be non-functional", "app/rag/"],
         ["MEDIUM", "LLM client requires external API key with no SDK pinned in requirements", "app/llm/"],
         ["MEDIUM", "NetworkAgent is a stub — returns pending for all requests", "app/agents/"],
         ["LOW", "Dead backup files: email_agent_v1_backup.py, email_agent_v2_backup_step7.py", "app/agents/"],
         ["LOW", "No frontend test framework", "frontend/"],
         ["LOW", "Live Redpanda tests require separately running instance", "tests/"],
         ["LOW", "NetworkAnalysis and Reports pages are thin on the frontend", "frontend/src/pages/"]],
        [0.8*inch, 3.2*inch, 2.2*inch],
    ),
    Spacer(1, 6),
    Paragraph(
        "<b>Action required:</b> The Firebase service account key file should be removed from "
        "version control immediately and added to .gitignore. Rotate the key if the repository "
        "has ever been pushed to a remote.",
        warn_style,
    ),
    Spacer(1, 8),
]

# ── 8. Recent Fixes ────────────────────────────────────────────────────────────
story += section("8. Recent Fixes (Sept 2026)")
story += [
    tbl(
        [["Date", "Fix", "Files changed"],
         ["2026-09-18", "Email pipeline: dispatcher imported non-existent email_agent_v2 → always PENDING", "dispatcher.py"],
         ["2026-09-18", "URL intelligence: url_analysis service never called in investigate endpoint", "gmail.py"],
         ["2026-09-18", "Report builder: NOT_DETECTED used when no analysis ran (should be UNKNOWN)", "email_report_builder.py"],
         ["2026-09-18", "Frontend: PENDING/error shown as 0-risk; confidence falsy-zero bug", "EmailAnalysisPage.tsx"],
         ["2026-09-18", "Gmail 401: status query fired before auth initialized, wiped session", "api.ts, EmailAnalysisPage.tsx"]],
        [1.0*inch, 3.5*inch, 1.7*inch],
    ),
    Spacer(1, 8),
]

# ── Footer note ───────────────────────────────────────────────────────────────
story += [
    hr(),
    Paragraph(
        "This report was auto-generated from a live codebase survey. "
        "Architecture details reflect the state of the repository as of the generation date.",
        small_style,
    ),
]

doc.build(story)
print(f"PDF written to {OUTPUT}")
