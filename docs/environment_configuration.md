# CyberGuard AI — Environment Configuration & Secrets Management

This guide documents the configuration model, secret validation invariants, and the boundary between standalone local development and production external integrations.

---

## 1. Zero-Credential Standalone Operation

CyberGuard AI is architected to operate out-of-the-box in local development and testing environments without requiring external third-party API credentials.

### Service Boundary Matrix

| Capability | Standalone Mode (Default / Dev) | External Provider (Optional Production) | Required Key |
| :--- | :--- | :--- | :--- |
| **Authentication & Tokens** | Local cryptographic HS256 JWT | Local cryptographic HS256 JWT | `JWT_SECRET_KEY` |
| **Persistence** | PostgreSQL (Docker or local) | Managed Cloud SQL / Aurora PostgreSQL | `DATABASE_URL` |
| **Cache & Real-time State** | Redis (Docker or in-memory) | Managed Redis / Memorystore | `REDIS_URL` |
| **AI Security Assistant** | Ollama (`http://localhost:11434`) | Anthropic Claude / Google Gemini | `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` |
| **Threat Intelligence** | Local IOC cache & heuristic rules | VirusTotal API, AbuseIPDB API | `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` |
| **Email Ingestion** | IMAP / Direct upload / Synthetic | Google Workspace Gmail OAuth2 | Gmail OAuth Client ID / Secret |

> **Crucial Rule:** In local development, the platform must never crash or block core operations because external threat intelligence or cloud LLM keys are absent. All analysis falls back cleanly to local heuristic detection and rule correlation.

---

## 2. Environment Invariants & Enforcement

CyberGuard AI uses Pydantic Settings (`app.core.config.Settings`) with strict startup invariants:

### Production Rules (`APP_ENV=production`)
1. **`JWT_SECRET_KEY` is Mandatory:**
   - Must be explicitly set via environment variable.
   - Must be at least 32 characters long.
   - Must **not** contain `CHANGE_ME` or start with `dev_`.
   - Missing or weak keys immediately abort startup (`ConfigurationError`).
2. **Database Security:**
   - Rejects the default development password (`cyberguard_dev`).
3. **CORS Invariants:**
   - Wildcards (`*`) are rejected when `APP_ENV=production`. Origins must be explicitly listed.

### Development Mode (`APP_ENV=development`)
1. **Fallback Secret:**
   - If `JWT_SECRET_KEY` is not provided in `.env`, an ephemeral local secret is securely generated at startup so development proceeds smoothly.
   - Logs a warning reminding the developer to set an explicit secret before production deployment.

---

## 3. Secret Hygiene Rules

1. **Git Exclusion:** Root `.gitignore` strictly ignores `.env`, `*.env`, `.env.*`, and certificate stores (`*.pem`, `*.key`).
2. **Docker Compose:** `docker-compose.yml` uses dynamic environment interpolation (`${JWT_SECRET_KEY:-}`, `${APP_ENV:-development}`) instead of hardcoded plaintext secrets.
3. **Logs Masking:** Secrets wrapped in `SecretStr` are automatically masked as `**********` across all structured JSON log emitters.
