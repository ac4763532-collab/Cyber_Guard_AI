# CyberGuard AI — Frontend ↔ Backend Integration Map

Maps every frontend page to the backend endpoints it actually calls, its
integration status, and what was verified live versus what remains
unverified. Companion to `BACKEND_CAPABILITY_AUDIT.md` (endpoint-level
detail) and `FRONTEND_IMPLEMENTATION_REPORT.md` (what was built/fixed and
when).

Status legend: **Full** = wired to real backend data, verified live in
browser this session or a prior session in this project's history. **New**
= built and verified in this session specifically. **Missing** = backend
capability exists with no frontend surface at all.

## Pages with full backend integration (pre-existing, confirmed still intact)

| Page | Route | Backend modules used | Verified |
|---|---|---|---|
| Dashboard | `/` | health, events, alerts, incidents, reports | Prior sessions + spot-checked this session |
| Alerts | `/alerts` | alerts.py | Prior sessions |
| Events | `/events` | events.py | Prior sessions |
| Incidents | `/incidents` | incidents.py | Prior sessions |
| Reports | `/reports` | reports.py | Prior sessions |
| Settings | `/settings` | auth.py (profile), health.py, detection.py (rules/IOCs) | This session — fixed `rule.id`/`rule.name` → `rule_id`/`rule_name` field mismatch; re-verified live after fix |
| Login / Signup | `/login`, `/signup` | auth.py, Firebase | Prior sessions |
| Email Analysis (+ Gmail) | `/analysis/email` | analysis.py, gmail.py | Prior sessions |
| Log Analysis | `/analysis/logs` | logs.py | Prior sessions |
| Network Analysis | `/analysis/network` | analysis.py | Prior sessions |
| Agents | `/agents` | analysis.py (agent status), llm.py (status) | Prior sessions |

## Pages built and verified this session (new frontend surface for existing backend capability)

| Page | Route | Backend modules used | What was verified live |
|---|---|---|---|
| Correlation | `/correlation` | `correlation.py` (`POST /correlation/analyze`, `GET /correlation/statistics`) | Statistics card renders flat real values (`correlation_window_hours`, `min_correlation_score`, `attack_chains_loaded`); submit-events-for-correlation form present; empty states confirmed against fresh DB |
| Knowledge Base | `/knowledge` | `knowledge.py` (search, technique/CVE lookup, tactics, statistics) | Search, technique lookup (T-codes), CVE lookup, tactics browser, and statistics all rendering real data (30 entries: 12 tactics, 14 techniques, 4 CVEs); fixed a nested-object rendering bug in statistics (`by_type` was printing `[object Object]`) |
| Feedback | `/feedback` | `feedback.py` (submit, pending queue, review, statistics) | Submit form (any authenticated user) and admin review queue both rendered; stats grid showed real `0` counts against the fresh DB; empty state ("No pending feedback") confirmed; admin-only queue section confirmed visible only for the admin test user |
| Training / ML Ops | `/training` | `training.py` (models, retrain/deploy/rollback, threshold tuning, feedback export) | Admin-only route guard confirmed (non-admin sees "Admin access required", makes zero API calls); model list empty state confirmed (no trained versions in fresh DB); threshold tuning controls and feedback export section rendered |

All four pages are routed in `App.tsx` and present in `Sidebar.tsx` under a
new "Intelligence" section (Correlation, Knowledge Base) and the existing
"System" section (Feedback, Training — Training's nav link itself is
admin-gated in the sidebar, matching the page's own guard).

## Backend capability still with no frontend surface

| Capability | Backend module | Why not built | 
|---|---|---|
| Metrics dashboard | `metrics.py` (`GET /metrics`, `GET /metrics/summary`) | Plan decision: fold into an existing page (Agents or Reports) rather than add a 15th nav item. **Not yet actually added** — remains open, see `FRONTEND_IMPLEMENTATION_REPORT.md` Remaining Work. |
| WebSocket live updates | `ws.py` (`/api/v1/ws`) | Polling already covers every existing page; real-time push assessed as a nice-to-have, not a coverage gap. `wsApi.connect`'s URL-derivation bug was fixed this session (hardcoded `ws://127.0.0.1:8000` → derived from `window.location`), but no component subscribes to it yet. |
| Ingestion API-key management UI | `web_ingest.py` (`POST/GET /logs/web/keys`, `DELETE /logs/web/keys/{id}`) | Explicitly withheld: `POST /logs/web/keys` has zero caller authentication (confirmed TODO in source — see capability audit). Building a UI for an unauthenticated privileged action was judged worse than leaving the gap visible. Flagged for the user's decision if they want the backend auth gap fixed first. |
| LLM chat / streaming UI | `llm.py` (`POST /llm/chat`, `POST /llm/stream`) | API client methods added this session (`llmApi.chat`, `llmApi.stream` as an async generator over SSE), but no dedicated chat page was built — out of this plan's explicit scope (new pages list did not include a chat UI). |

## API client (`frontend/src/services/api.ts`) changes this session

- Added `feedbackApi` (submit, getPending, review, getStatistics, get-by-id).
- Added `trainingApi` (full surface: models, retrain, deploy, rollback,
  compare, history, feedback export/batches, data info/combine, threshold
  get/tune/set/reset/analyze, status).
- Extended `llmApi` with `chat` and `stream` (SSE via `fetch` +
  `ReadableStream`, not `EventSource`, since the backend endpoint is a
  POST with a JSON body, which `EventSource` cannot send).
- `knowledgeApi` already existed; no changes needed beyond what the new
  `KnowledgeBasePage.tsx` already consumed.
- `correlationApi` already existed; reused as-is by `CorrelationPage.tsx`.
- Fixed `wsApi.connect`: was hardcoded to `ws://127.0.0.1:8000`; now derives
  protocol (`ws`/`wss`) and host from `window.location`, so it works behind
  nginx/prod reverse proxies, not just local dev.
- `VITE_API_URL` was defined in `.env.local` but dead/unused in `api.ts`;
  wired it in as the base URL fallback, consistent with how
  `docker-compose.yml`'s frontend service already sets `VITE_API_URL=/api/v1`
  for the nginx-proxied production build.

## `frontend/src/types/index.ts` changes this session

Added response/request interfaces for the modules this plan touched:
Correlation, Feedback, Training, and the LLM chat/stream additions. Existing
types for already-integrated modules (alerts, events, incidents, etc.) were
left as-is — this was not a blanket retype pass.

## Known integration-level issues (not fixed, documented)

- `/health/detailed`'s Redis component is hardcoded "pending" regardless of
  actual state (see capability audit). The Sidebar's system-status indicator
  reads the top-level `status` field from the same payload, which is
  computed from component statuses — worth checking in a future pass
  whether the hardcoded Redis "pending" value is dragging the overall
  reported status down even when Redis is actually healthy. Not resolved
  this session (backend logic, out of scope).
- The Dockerized frontend's own Docker healthcheck reports "unhealthy" even
  though the container correctly serves the app and proxies real backend
  requests (confirmed via its own nginx access log showing 200s for
  `/api/v1/health/detailed`, `/api/v1/events`, `/api/v1/alerts`, etc., and
  for `/auth/firebase-login`). This looks like a healthcheck configuration
  issue (wrong path or expectation inside the Dockerfile/compose
  healthcheck directive for the frontend service), not an actual outage.
  Not fixed — outside this session's scope (frontend container healthcheck
  wasn't part of the plan), flagged for a future pass.
- nginx's `location /ws/` proxy block in `frontend/nginx.conf`-equivalent
  config forwards to `http://backend:8000/ws/`, but the backend's actual
  WebSocket route is mounted at `/api/v1/ws` (no separate `/ws` prefix).
  Traffic to the frontend's `/api/v1/ws` path would correctly go through
  the `/api/` block instead, so this doesn't block anything today, but the
  dedicated `/ws/` block is effectively dead configuration. Not fixed —
  pre-existing, zero current impact, noted for cleanup.
