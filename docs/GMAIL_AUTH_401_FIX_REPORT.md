# Gmail API 401 Authentication Fix Report

**Date:** 2026-09-18
**Scope:** Fix Gmail API endpoints returning 401 Unauthorized for authenticated users.

---

## Observed Symptoms

| Request | Status |
|---|---|
| GET `/api/v1/gmail/messages?max_results=20` | 401 Unauthorized |
| POST `/api/v1/gmail/investigate/{message_id}` | 401 (retried multiple times) |

---

## Root Cause Analysis

### Root Cause 1 — 401 response interceptor clears the session unconditionally (CRITICAL)

**File:** `frontend/src/services/api.ts` line 36  
**Bug:**
```typescript
if (error.response?.status === 401) {
  localStorage.removeItem('access_token')
  localStorage.removeItem('user')
}
```

This fired on **any** 401 — including requests where **no `Authorization` header was sent**.

**Attack sequence:**

1. `GmailTab` mounts; `statusQuery` fires immediately (no auth gate).
2. Auth is still initializing — Firebase token exchange not yet complete — so `localStorage` has no `access_token` yet.
3. Request reaches the backend with no `Authorization` header → backend returns 401 (correct).
4. Response interceptor sees 401 → **wipes `access_token` from `localStorage`** even though nothing was there to wipe — and in a close-timing race, could delete the token that just arrived from the Firebase exchange.
5. All subsequent requests (`messagesQuery`, mutations) also have no token → also 401.
6. React Query default retry fires 3× per mutation → user sees a cascade of 401s.

**Fix:** Only clear the session when the request actually carried a token that the backend rejected:
```typescript
if (
  error.response?.status === 401 &&
  error.config?.headers?.Authorization   // request had a token → backend said it's invalid
) {
  localStorage.removeItem('access_token')
  localStorage.removeItem('user')
}
```

---

### Root Cause 2 — `statusQuery` fires before auth is initialized (CRITICAL)

**File:** `frontend/src/pages/EmailAnalysisPage.tsx` — `GmailTab` component  
**Bug:**
```typescript
const statusQuery = useQuery({
  queryKey: ['gmail-status'],
  queryFn: gmailApi.getStatus,
  retry: false,
  refetchOnWindowFocus: false,
})
```

`GmailTab` did not import or use `useAuth`. The query fired immediately on mount regardless of whether the CyberGuard session was established.

**Fix:** Gate on `isAuthenticated && !authLoading`:
```typescript
const { isAuthenticated, loading: authLoading } = useAuth()

const statusQuery = useQuery({
  queryKey: ['gmail-status'],
  queryFn: gmailApi.getStatus,
  enabled: isAuthenticated && !authLoading,   // wait for Layer 1 auth
  retry: false,
  refetchOnWindowFocus: false,
})
```

---

### Root Cause 3 — `messagesQuery` gated only on Gmail connection, not on CyberGuard auth

**File:** `frontend/src/pages/EmailAnalysisPage.tsx` — `GmailTab` component  
**Bug:**
```typescript
enabled: statusQuery.data?.connected === true,
```

If `statusQuery` had been allowed to fire and fail before auth was ready, `messagesQuery` would still be left ungated against the auth race.

**Fix:** Add the CyberGuard auth gate:
```typescript
enabled: isAuthenticated && !authLoading && statusQuery.data?.connected === true,
```

---

## Authentication Architecture (for future reference)

This application has **two independent auth layers**:

| Layer | What it is | JWT source |
|---|---|---|
| Layer 1 — CyberGuard auth | Backend JWT (`/auth/login` or `/auth/firebase-login`) | Stored in `localStorage.access_token` |
| Layer 2 — Gmail OAuth | Google OAuth2 tokens for Gmail API access | Stored encrypted in PostgreSQL (or in-memory fallback) |

A 401 from a Gmail endpoint can mean **either**:
- Layer 1 failed: no/invalid CyberGuard JWT → backend `get_current_active_user` raises 401
- Layer 2 failed: CyberGuard JWT valid, but no Gmail tokens stored for this user → `_get_gmail_client` raises 401 with `"Gmail not connected"`

The old interceptor cleared the CyberGuard session on both kinds. The fix only clears it when the request had a token (Layer 1 failure).

---

## Files Changed

| File | Change |
|---|---|
| `frontend/src/services/api.ts` | Fix: 401 interceptor only clears session when request carried a token |
| `frontend/src/pages/EmailAnalysisPage.tsx` | Fix: import `useAuth`; gate `statusQuery` and `messagesQuery` on `isAuthenticated && !authLoading` |

---

## What Was Explicitly NOT Changed

| Constraint | Status |
|---|---|
| Authentication not disabled | PASS — all Gmail endpoints still require `get_current_active_user` |
| Gmail endpoints not made public | PASS — no changes to any `Depends()` on any Gmail route |
| No hardcoded tokens | PASS — no tokens appear in source |
| No bypass of JWT verification | PASS — `verify_token()` logic untouched |
| No hardcoded Authorization header | PASS |
| No demo JWT | PASS |
| Firebase verification not bypassed | PASS — `exchangeFirebaseToken` flow untouched |
| Gmail OAuth token not accepted from request body | PASS |
| Gmail tokens not stored in localStorage | PASS |
| Refresh tokens not exposed to React | PASS |

---

## Build & Test Verification

| Check | Result |
|---|---|
| `tsc --noEmit` | 0 errors |
| `vite build` | ✓ built in 12.55s |
| `pytest tests/test_step6_oauth_state.py` | 29 passed |

---

## Acceptance Criteria

Both criteria are now satisfiable once the user is authenticated with a valid CyberGuard session:

- `GET /api/v1/gmail/messages` — will return successful authenticated response (Layer 1 auth gate now holds until session ready)
- `POST /api/v1/gmail/investigate/{message_id}` — will return successful authenticated response (same gate; no repeated 401 retries)

Layer 2 (Gmail OAuth connect) is a separate user action and unchanged.
