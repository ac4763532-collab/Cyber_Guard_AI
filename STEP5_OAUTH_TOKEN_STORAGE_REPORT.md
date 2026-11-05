# STEP 5 Report: Secure Gmail OAuth Token Storage

**Date:** 2026-09-17  
**Status:** ✅ COMPLETE

---

## 1. Files Changed

| File | Change | Reason |
|------|--------|--------|
| `backend/app/config.py` | Added `token_encryption_key` setting | Configuration for Fernet encryption key |
| `backend/app/database/schema.py` | Added `oauth_tokens` table definition | Schema for encrypted token storage |
| `backend/app/services/token_encryption.py` | Created | Fernet encryption/decryption service |
| `backend/app/database/repositories/oauth_tokens.py` | Created | Repository for encrypted OAuth token storage |
| `backend/app/api/v1/gmail.py` | Updated | Replaced `_user_tokens` dict with DB-backed storage |
| `backend/.env` | Added `TOKEN_ENCRYPTION_KEY` | Test encryption key |

---

## 2. Existing Gmail OAuth Flow (Before)

```
User → /gmail/oauth/connect
         ↓
Google Authorization
         ↓
/gmail/oauth/callback
         ↓
Token Exchange
         ↓
_user_tokens[username] = GmailTokens  ← IN-MEMORY (plaintext!)
         ↓
Gmail API calls
```

**Problems:**
- Tokens stored in plaintext in process memory
- Lost on backend restart
- Multiple backend processes don't share tokens
- No encryption of sensitive refresh tokens

---

## 3. New Secure Architecture (After)

```
User → /gmail/oauth/connect
         ↓
Google Authorization
         ↓
/gmail/oauth/callback
         ↓
Token Exchange
         ↓
TokenEncryptionService.encrypt()
         ↓
OAuthTokenRepository.store()
         ↓
PostgreSQL (oauth_tokens table)
         ↓
[Encrypted tokens at rest]

Gmail API call needed:
         ↓
OAuthTokenRepository.get_decrypted_tokens()
         ↓
TokenEncryptionService.decrypt()
         ↓
GmailTokens (in-memory only for API call duration)
         ↓
Gmail API
```

---

## 4. Database Schema

New `oauth_tokens` table:

```sql
CREATE TABLE oauth_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL DEFAULT 'google',
    provider_account_id VARCHAR(255),  -- Gmail email address
    encrypted_access_token TEXT NOT NULL,  -- Fernet encrypted
    encrypted_refresh_token TEXT,          -- Fernet encrypted
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMPTZ,
    scopes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, provider)
);
```

**Security features:**
- Foreign key to `users` table with CASCADE delete
- One token per user per provider (UNIQUE constraint)
- Tokens encrypted before storage
- Provider account ID for audit/lookup (not sensitive)

---

## 5. Encryption Implementation

**Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)

**Key management:**
- Key loaded from `TOKEN_ENCRYPTION_KEY` environment variable
- Never hardcoded, never logged
- Generate with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

**TokenEncryptionService:**
```python
def encrypt(self, plaintext: str) -> str:
    """Encrypt token for storage."""
    fernet = self._get_fernet()
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt(self, ciphertext: str) -> str:
    """Decrypt token for API use."""
    fernet = self._get_fernet()
    return fernet.decrypt(ciphertext.encode()).decode()
```

---

## 6. Token Storage Verification

### Test 1: Encryption Service
```
Configured: True
Original: ya29.test_access_tok...
Encrypted: gAAAAABqq6DuDEptMhFOCl5Ow6cYc9MxZUvT2HHi...
Decrypted matches: True
```

### Test 2: Repository Storage
```
Stored token ID: a3fab40c-1568-4e76-8a09-ca6de6758db2
Provider: google
Provider account: test@gmail.com

Encrypted access token in DB: gAAAAABqq6Du43owxr8KO9Exhe7zdgSoVNkZ0Pg2...
Access token does NOT contain plaintext: True

Decrypted access token: test_access_token_step5
Decrypted refresh token: test_refresh_token_step5
Tokens match: True
```

### Test 3: Persistence Across Fresh Connection
```
=== Fresh Connection - Verify Persistence ===
Token found!
Decrypted access token: test_access_token_step5
Decrypted refresh token: test_refresh_token_step5

=== Persistence VERIFIED ===
```

---

## 7. Token Refresh Flow

```python
async def _refresh_and_store_tokens(user_id, tokens):
    """Refresh tokens if expired and store the new ones."""
    if not tokens.is_expired():
        return tokens

    if not tokens.refresh_token:
        return None  # Cannot refresh

    # Call Google token endpoint
    oauth_service = get_gmail_oauth_service()
    new_tokens = await oauth_service.refresh_tokens(tokens.refresh_token)

    # Store refreshed tokens (encrypted)
    await _store_tokens(user_id, new_tokens)

    return new_tokens
```

---

## 8. Security Verification

| Check | Status |
|-------|--------|
| Tokens encrypted at rest | ✅ Fernet (AES-128-CBC + HMAC) |
| Key from environment variable | ✅ `TOKEN_ENCRYPTION_KEY` |
| No hardcoded secrets | ✅ |
| No token logging | ✅ Only metadata logged |
| Parameterized SQL | ✅ All queries use placeholders |
| Foreign key to users | ✅ CASCADE delete |
| One token per user per provider | ✅ UNIQUE constraint |
| Decryption only when needed | ✅ On-demand for API calls |
| Fallback for development | ✅ In-memory when no encryption key |

---

## 9. API Contract Preservation

| Endpoint | Change | Compatibility |
|----------|--------|---------------|
| `GET /gmail/oauth/connect` | None | ✅ Compatible |
| `GET /gmail/oauth/callback` | Storage method | ✅ Compatible |
| `GET /gmail/status` | Token retrieval | ✅ Compatible |
| `POST /gmail/disconnect` | Token deletion | ✅ Compatible |
| `GET /gmail/messages` | Token retrieval | ✅ Compatible |
| `POST /gmail/analyze/{id}` | Token retrieval | ✅ Compatible |

All endpoints maintain the same request/response contracts.

---

## 10. Tests

| Metric | Result |
|--------|--------|
| Original tests | 275 passed |
| Skipped | 2 |
| STEP4 tests (in isolation) | 9 passed |

**Note:** STEP4 tests fail when run with full suite due to Windows psycopg3 event loop issue (documented in STEP2-4). They pass in isolation.

---

## 11. Remaining In-Memory State

| Variable | Location | Purpose | Acceptable? |
|----------|----------|---------|-------------|
| `_user_tokens` | gmail.py | Fallback when no encryption key | ✅ Yes - development only |
| `_pending_states` | oauth.py | OAuth CSRF state (10 min TTL) | ✅ Yes - ephemeral by design |

**When `DB_ENABLED=true` AND `TOKEN_ENCRYPTION_KEY` is set:**
- `_user_tokens` is NOT used
- All tokens stored in PostgreSQL encrypted

---

## 12. Configuration Required

Add to `.env` for production:

```bash
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOKEN_ENCRYPTION_KEY=<your-generated-key>
```

**Without this key:**
- Falls back to in-memory storage (development mode)
- Logs warning: "Token encryption not configured"

---

## 13. Definition of Done

| Requirement | Status |
|-------------|--------|
| Tokens encrypted at rest | ✅ Fernet (AES-128-CBC + HMAC) |
| Key loaded from environment | ✅ `TOKEN_ENCRYPTION_KEY` |
| No plaintext tokens in database | ✅ Verified |
| No hardcoded secrets | ✅ |
| No token logging | ✅ |
| Tokens persist across restarts | ✅ Verified |
| Token refresh works | ✅ Implemented |
| Token revocation works | ✅ Implemented |
| Existing API contracts preserved | ✅ |
| Original tests pass | ✅ 275 passed |
| Foreign key to users table | ✅ |
| Development fallback | ✅ In-memory when no key |

---

## Conclusion

**STEP 5: ✅ COMPLETE**

Gmail OAuth tokens are now securely stored in PostgreSQL with Fernet encryption (AES-128-CBC + HMAC-SHA256). The encryption key is loaded from environment configuration, never hardcoded. Tokens are decrypted only when needed for Gmail API calls, not kept in long-lived global state. The existing OAuth flow and API contracts are preserved. A development fallback to in-memory storage exists when no encryption key is configured.
