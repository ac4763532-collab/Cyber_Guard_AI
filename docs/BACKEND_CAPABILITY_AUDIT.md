# CyberGuard AI — Backend Capability Audit

**Scope:** Every route registered under `/api/v1` as mounted in
`backend/app/main.py` (`app.include_router(api_router, prefix="/api/v1")`)
and aggregated in `backend/app/api/v1/router.py`. Verified by reading
source directly (route decorators, `Depends()` auth, Pydantic schemas) and,
where noted, by live `curl`/browser requests against the running backend
during this session. Nothing below is inferred from comments, READMEs, or
file names alone — every "implemented" claim traces to an actual route
handler or a live, observed response.

Last verified: 2026-10-09/10, against `backend/app` as checked out at that
time, backend running natively (port 8000) and also validated through the
Dockerized backend after the Compose database fix (see
`FRONTEND_BACKEND_INTEGRATION_MAP.md` and `FRONTEND_IMPLEMENTATION_REPORT.md`
for that work).

## Router mounting

- `backend/app/main.py`: `app.include_router(api_router, prefix=settings.api_v1_prefix)`, `api_v1_prefix = "/api/v1"`.
- `backend/app/api/v1/router.py`: aggregates 17 sub-routers with no additional prefix (`ws.py` has none of its own either, so its routes sit directly under `/api/v1`).
- Each other file declares its own `APIRouter(prefix="/...")`.

| File | Router prefix | Full base path |
|---|---|---|
| alerts.py | `/alerts` | `/api/v1/alerts` |
| analysis.py | `/analysis` | `/api/v1/analysis` |
| auth.py | `/auth` | `/api/v1/auth` |
| correlation.py | `/correlation` | `/api/v1/correlation` |
| detection.py | `/detection` | `/api/v1/detection` |
| events.py | `/events` | `/api/v1/events` |
| feedback.py | `/feedback` | `/api/v1/feedback` |
| gmail.py | `/gmail` | `/api/v1/gmail` |
| health.py | `/health` | `/api/v1/health` |
| incidents.py | `/incidents` | `/api/v1/incidents` |
| knowledge.py | `/knowledge` | `/api/v1/knowledge` |
| llm.py | `/llm` | `/api/v1/llm` |
| logs.py | `/logs` | `/api/v1/logs` |
| metrics.py | `/metrics` | `/api/v1/metrics` |
| reports.py | `/reports` | `/api/v1/reports` |
| training.py | `/training` | `/api/v1/training` |
| web_ingest.py | `/logs/web` | `/api/v1/logs/web` |
| ws.py | (none) | `/api/v1` |

## Endpoint inventory

### alerts.py — `/api/v1/alerts`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/alerts` | **none** | `AlertCreateRequest` | `AlertResponse` | |
| GET | `/alerts` | **none** | query params | `list[AlertResponse]` | |
| GET | `/alerts/statistics` | **none** | — | dict | Verified live this session (frontend sidebar badges) |
| GET | `/alerts/{alert_id}` | **none** | — | `AlertResponse` | |
| PATCH | `/alerts/{alert_id}` | **none** | `AlertUpdateRequest` | `AlertResponse` | |
| DELETE | `/alerts/{alert_id}` | **none** | — | dict | |

### analysis.py — `/api/v1/analysis`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/analysis/email` | **none** | `EmailAnalysisRequest` | `AnalysisResponse` | Rate-limited (30/min), not auth |
| POST | `/analysis/logs` | **none** | `LogAnalysisRequest` | `AnalysisResponse` | |
| POST | `/analysis/network` | **none** | `NetworkAnalysisRequest` | `AnalysisResponse` | |
| GET | `/analysis/agents` | **none** | — | dict | |

### auth.py — `/api/v1/auth`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/auth/login` | none (is the login route) | `UserLogin` | `LoginResponse` | Verified live repeatedly this session |
| POST | `/auth/firebase-login` | none (is the login route) | `FirebaseLoginRequest` | `FirebaseLoginResponse` | |
| GET | `/auth/firebase-status` | **none** | — | dict | |
| GET | `/auth/me` | `Depends(get_current_active_user)` | — | `UserResponse` | |
| POST | `/auth/register` | **none** — flagged gap | `UserCreate` | `UserResponse` | Code comment: *"In production, this should require admin privileges / For demo, allow open registration"* |
| GET | `/auth/users` | `Depends(require_role([ADMIN]))` | — | `list[UserResponse]` | Admin only |
| GET | `/auth/verify` | `Depends(get_current_active_user)` | — | dict | |

### correlation.py — `/api/v1/correlation`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/correlation/analyze` | **none** | `CorrelateRequest` | `CorrelationResponse` | Frontend surface built this session: `CorrelationPage.tsx` |
| GET | `/correlation/statistics` | **none** | — | dict (flat: `correlation_window_hours`, `min_correlation_score`, `attack_chains_loaded`) | Verified live via curl this session |

### detection.py — `/api/v1/detection`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/detection/analyze` | **none** | `DetectionRequest` | `DetectionResponse` | |
| GET | `/detection/statistics` | **none** | — | dict | |
| GET | `/detection/rules` | **none** | — | dict (`rules: [{rule_id, rule_name, description, severity, category, enabled, confidence, mitre_techniques}]`) | Field is `rule_id`/`rule_name`, not `id`/`name` — see Known Issues |
| GET | `/detection/iocs` | **none** | — | dict | |

### events.py — `/api/v1/events`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/events` | **none** | `EventCreateRequest` | `EventResponse` | |
| GET | `/events` | **none** | query params | `list[EventResponse]` | |
| GET | `/events/statistics` | **none** | — | dict | |
| GET | `/events/{event_id}` | **none** | — | dict | |
| POST | `/events/{event_id}/reanalyze` | **none** | — | `EventResponse` | |

### feedback.py — `/api/v1/feedback`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/feedback` | `Depends(get_current_active_user)` | `FeedbackSubmit` | `FeedbackResponse` | Any authenticated user |
| GET | `/feedback/pending` | user + `Depends(require_role([ADMIN]))` | — | `FeedbackListResponse` | Admin only |
| POST | `/feedback/{feedback_id}/review` | user + admin dep | `FeedbackReview` | `FeedbackDetail` | Admin only |
| GET | `/feedback/statistics` | user + admin dep | — | `FeedbackStatistics` | Admin only |
| GET | `/feedback/{feedback_id}` | user + admin dep | — | `FeedbackDetail` | Admin only |

Module docstring documents this exact auth model and the code matches it.
Fully verified live this session: `FeedbackPage.tsx` submit form (any user)
and admin review queue, both rendering real data, correct empty states.

### gmail.py — `/api/v1/gmail`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/gmail/oauth/connect` | `Depends(get_current_active_user)` | — | `GmailConnectResponse` | |
| GET | `/gmail/oauth/callback` | none by design — OAuth `state` token validated manually | — | redirect | Protected by state param, not JWT |
| GET | `/gmail/status` | `Depends(get_current_active_user)` | — | `GmailStatusResponse` | |
| POST | `/gmail/disconnect` | `Depends(get_current_active_user)` | — | dict | |
| GET | `/gmail/messages` | `Depends(get_current_active_user)` | query params | `GmailMessageListResponse` | Rate-limited |
| GET | `/gmail/messages/{message_id}` | `Depends(get_current_active_user)` | — | `GmailMessageResponse` | Rate-limited |
| POST | `/gmail/analyze/{message_id}` | `Depends(get_current_active_user)` | `GmailAnalyzeRequest` | `GmailAnalyzeResponse` | Rate-limited |
| POST | `/gmail/investigate/{message_id}` | `Depends(get_current_active_user)` | — | dict (no `response_model`) | Rate-limited |
| POST | `/gmail/analyze-batch` | `Depends(get_current_active_user)` | `list[str]` | dict | Rate-limited |

### health.py — `/api/v1/health`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/health` | none (expected) | — | `SimpleHealthResponse` | |
| GET | `/health/detailed` | none (expected) | — | `HealthResponse` | **Redis component hardcoded to `status="pending"`, `"Not configured"` (health.py:129-134) regardless of actual Redis state** — confirmed by reading code and by live curl: Redis container was running and healthy (`PONG` via `redis-cli ping`) while this endpoint still reported "pending". Pre-existing bug, not touched. |
| GET | `/health/ready` | none (expected) | — | `ReadinessResponse` | This endpoint *does* have real Redis connectivity logic (`get_redis_client().health_check()`), separate code path from `/health/detailed` |
| GET | `/health/live` | none (expected) | — | `LivenessResponse` | |

No-auth is normal/acceptable for all four — standard health/readiness/liveness probe practice.

### incidents.py — `/api/v1/incidents`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/incidents` | **none** | `IncidentCreateRequest` | `IncidentResponse` | |
| POST | `/incidents/from-correlation` | **none** | `CreateFromCorrelationRequest` | `IncidentResponse` | |
| GET | `/incidents` | **none** | query params | `list[IncidentResponse]` | |
| GET | `/incidents/statistics` | **none** | — | dict | Verified live via Dockerized backend this session (200, real DB data) |
| GET | `/incidents/{incident_id}` | **none** | — | `IncidentResponse` | |
| GET | `/incidents/{incident_id}/timeline` | **none** | — | dict | |
| PATCH | `/incidents/{incident_id}` | **none** | `IncidentUpdateRequest` | `IncidentResponse` | Hardcodes `user="api_user"` for the audit trail — no real identity available since there's no auth dependency |
| POST | `/incidents/{incident_id}/alerts/{alert_id}` | **none** | — | `IncidentResponse` | |

### knowledge.py — `/api/v1/knowledge`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/knowledge/statistics` | **none** | — | dict `{total_entries, by_type: {mitre_tactic, mitre_technique, cve}}` | Nested shape — see Known Issues (fixed in frontend this session) |
| POST | `/knowledge/search` | **none** | `SearchRequest` | dict | |
| POST | `/knowledge/techniques` | **none** | `TechniqueRequest` | dict | |
| GET | `/knowledge/technique/{technique_id}` | **none** | — | dict | |
| GET | `/knowledge/cve/{cve_id}` | **none** | — | dict | |
| POST | `/knowledge/enrich` | **none** | `EnrichRequest` | dict | |
| GET | `/knowledge/tactics` | **none** | — | dict | |

Fully verified live this session: `KnowledgeBasePage.tsx` — search, technique
lookup, CVE lookup, tactics browser, statistics (30 entries: 12 tactics, 14
techniques, 4 CVEs).

### llm.py — `/api/v1/llm`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/llm/status` | **none** | — | `LLMStatusResponse` | Live: reports "degraded"/mock mode, no Anthropic API key configured in dev `.env` — expected, not a bug |
| POST | `/llm/analyze-threat` | **none** | `ThreatAnalysisRequest` | `LLMAnalysisResponse` | |
| POST | `/llm/remediation` | **none** | `RemediationRequest` | `LLMAnalysisResponse` | |
| POST | `/llm/enrich-ioc` | **none** | `IOCEnrichRequest` | `LLMAnalysisResponse` | |
| POST | `/llm/map-mitre` | **none** | `MITREMapRequest` | `LLMAnalysisResponse` | |
| POST | `/llm/chat` | **none** | `ChatRequest` | `LLMAnalysisResponse` | Frontend client added this session (`llmApi.chat`); not yet wired to a dedicated chat UI page |
| POST | `/llm/stream` | **none** | `StreamRequest` | `StreamingResponse` (SSE, no `response_model`) | Frontend client added this session (`llmApi.stream`, async generator over fetch + `ReadableStream`); not yet wired to a dedicated UI |

### logs.py — `/api/v1/logs`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/logs/sources` | `Depends(get_current_active_user)` | `LogSourceCreate` | dict | Any authenticated user, no role restriction |
| GET | `/logs/sources` | `Depends(get_authorized_tenant_ids)` (JWT, tenant-scoped) | query params | dict | |
| GET | `/logs/sources/{source_id}` | tenant-scoped | — | dict | Cross-tenant access returns 404 |
| PATCH | `/logs/sources/{source_id}` | `Depends(get_current_active_user)` | `LogSourceUpdate` | dict | No tenant check on this one |
| DELETE | `/logs/sources/{source_id}` | `Depends(get_current_active_user)` | — | dict | No tenant check on this one |
| GET | `/logs/events` | tenant-scoped | query params | dict | |
| GET | `/logs/events/{event_id}` | tenant-scoped | — | dict | |
| GET | `/logs/events/statistics` | tenant-scoped | — | dict | |
| POST | `/logs/ingest` | **API key** (`X-Ingestion-Key`), checked manually in-body via `get_authenticated_key(...)`, not a `Depends()` | `list[ParsedLogEntry]` | dict | Real enforcement, just not visible to OpenAPI/signature-based scans |
| POST | `/logs/ingest/raw` | same manual API-key pattern | query params | dict | |

Module docstring explicitly documents a real, self-flagged limitation:
tenant authorization for non-admin users relies on a client-supplied
`tenant_id` query parameter checked against known tenant IDs, because `User`
has no `organization_id` field — "any analyst who knows a valid tenant_id
string can query that tenant's data." This is documented by the original
authors, not hidden, but remains a genuine weakness worth carrying forward
in this audit.

### metrics.py — `/api/v1/metrics`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/metrics` | **none** | — | `MetricsResponse` | No dedicated frontend page (by plan decision — folded into existing pages rather than a 15th nav item; not yet actually added to Agents/Reports page this session — see Pending below) |
| GET | `/metrics/summary` | **none** | — | `MetricsSummaryResponse` | |

### reports.py — `/api/v1/reports`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| GET | `/reports/summary` | **none** | query: `hours` | `ReportSummary` | **`top_iocs` field is hardcoded to `[]` always** (reports.py:61 default, :168 explicit) — confirmed in code, not populated from real IOC data despite the field existing in the schema |
| GET | `/reports/executive` | **none** | query: `hours` | dict | Verified live this session (200, real data) |
| GET | `/reports/threat-landscape` | **none** | — | dict | |
| GET | `/reports/compliance` | **none** | — | dict | Partially hardcoded per earlier session audit — not re-verified line-by-line this pass |

### training.py — `/api/v1/training`

All 17 routes require `Depends(require_admin)` (`require_role([ADMIN])`) —
consistently applied, no gaps.

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/training/models` | — | dict |
| GET | `/training/models/{version}` | — | dict |
| POST | `/training/retrain` | `RunPipelineRequest` | dict |
| POST | `/training/deploy` | `DeployModelRequest` | `DeploymentResponse` |
| POST | `/training/rollback` | — | `DeploymentResponse` |
| POST | `/training/compare` | `CompareModelsRequest` | dict |
| GET | `/training/history` | query: `limit` | dict |
| GET | `/training/feedback/export-batches` | — | dict |
| POST | `/training/feedback/export` | query: `limit`, `mark_as_exported` | dict |
| GET | `/training/data/info` | — | dict |
| POST | `/training/data/combine` | — | dict |
| GET | `/training/threshold` | — | dict |
| POST | `/training/threshold/tune` | `TuneThresholdRequest` | dict |
| POST | `/training/threshold/set` | `SetThresholdRequest` | dict |
| POST | `/training/threshold/reset` | query: `domain` | dict |
| GET | `/training/threshold/analyze` | — | dict |
| GET | `/training/status` | — | dict |

Fully verified live this session via `TrainingPage.tsx`: model versions
(empty state — no trained versions in this fresh database), threshold
tuning stats, feedback export, all admin-gated correctly (non-admin sees
"Admin access required" and the page makes no API calls).

### web_ingest.py — `/api/v1/logs/web`

| Method | Path | Auth | Request | Response | Notes |
|---|---|---|---|---|---|
| POST | `/logs/web/ingest` | `Depends(get_authenticated_key)` (API key, `X-Ingestion-Key`) | `WebLogBatch` | `WebIngestResponse` | Properly authenticated |
| POST | `/logs/web/keys` | **none — confirmed gap** | `IngestionKeyCreate` | `IngestionKeyCreated` | Source code contains `# TODO: Verify user has access to this source's organization` and `created_by=None,  # TODO: from JWT`. Can mint a valid ingestion key for any `source_id` with zero caller authentication. |
| GET | `/logs/web/keys` | **none** | query: `source_id` | `list[dict]` | Lists key metadata for an arbitrary source_id, no auth |
| DELETE | `/logs/web/keys/{key_id}` | **none** | — | 204 | Anyone can revoke any key by ID, no ownership check |
| GET | `/logs/web/health` | **none** | — | dict | Acceptable — non-sensitive health check |

No frontend UI was built for key creation/management this session or
previously, specifically because of this unresolved auth gap — matches the
original plan's explicit decision to not ship a UI for an unauthenticated
privileged action.

### ws.py — mounted at `/api/v1` directly (no own prefix)

| Method | Path | Auth | Notes |
|---|---|---|---|
| WS | `/ws` | **none** | Any client can subscribe to `alerts`, `incidents`, `events`, `agents`, `system` channels and receive live broadcasts. Not consumed by any frontend page yet — `wsApi.connect` exists in `api.ts` (URL hardcoding fixed this session) but no component calls it. |
| GET | `/ws/stats` | **none** | |

## Security summary — authentication coverage

Out of 18 route files and roughly 100 routes:

**Entirely unauthenticated** (every route): alerts.py, analysis.py,
correlation.py, detection.py, events.py, incidents.py, knowledge.py, llm.py,
metrics.py, reports.py, ws.py. health.py is also entirely unauthenticated,
which is normal and expected for health probes.

**Entirely authenticated/gated**: training.py (100% admin), feedback.py
(100% — mix of any-authenticated-user and admin-only, matches its own
documented design).

**Mixed**: auth.py (login routes correctly open; `/register` is an
unflagged-to-users but code-commented-as-known gap: open self-registration
with no admin check), gmail.py (only the OAuth callback is unauthenticated,
by design), logs.py (tenant-scoped JWT on reads; two source-mutation routes
have JWT but no tenant check; ingestion routes use API-key auth checked
manually in the function body, not as a `Depends()` — real enforcement,
just not visible to naive route-signature audits), web_ingest.py (the
actual log-ingest route is properly API-key gated; all three key-management
routes are not, with explicit TODOs admitting it).

**This remains the single largest real security gap in the backend**: the
entire core security-operations surface — alerts, events, incidents,
correlation, detection, knowledge base, LLM analysis, metrics, reports — has
no authentication at all. This was true before this session's frontend
work and remains true now. No backend auth was added in this session, per
explicit scope boundaries agreed with the user (frontend completion and a
Docker Compose database fix only). It is called out here, in full, rather
than hidden or minimized, per the user's standing instruction not to hide
unsupported/missing features.

## Known pre-existing backend data/response-shape issues

1. **`/health/detailed` Redis component is hardcoded** (`health.py:129-134`)
   to `pending`/`"Not configured"` regardless of actual Redis state. Confirmed
   by code reading and by live test (Redis was running and responding to
   `PING` while this endpoint still reported "pending"). The *separate*
   `/health/ready` endpoint does have real Redis connectivity logic — the
   two code paths are inconsistent.
2. **`/reports/summary`'s `top_iocs` field is always `[]`** (`reports.py:61,168`)
   — never populated from real IOC data, confirmed in code.
3. **`/detection/rules` returns `rule_id`/`rule_name` fields**, not `id`/`name`.
   The frontend's `SettingsPage.tsx` was using the wrong field names
   (`rule.id`, `rule.name`) causing a React duplicate/missing-key console
   warning and blank rule names in the UI — fixed this session (see
   `FRONTEND_IMPLEMENTATION_REPORT.md`).
4. **`/knowledge/statistics` returns a nested shape** (`{total_entries,
   by_type: {...}}`), not a flat object — a frontend rendering bug assumed
   flatness and printed `[object Object]`; fixed this session.
   `/correlation/statistics` was checked against the same assumption and
   confirmed to genuinely be flat, so it needed no fix.
5. **`incidents.py` hardcodes `user="api_user"`** for incident update audit
   trails rather than using a real identity — consistent with there being no
   auth dependency on that route at all.

## Not independently re-verified this session (carried from prior audit)

- `/reports/compliance`'s exact degree of hardcoding (prior session's audit
  flagged this as "partly hardcoded"; not re-read line-by-line this pass).
- Full correctness of the detection/correlation/ML pipelines themselves
  (prior sessions' deep audits cover this; this pass focused on frontend
  integration + the route/auth inventory + the Compose database fix).
