# CyberGuard AI — Security Configuration & Invariants

This document details the core security controls, authentication safeguards, access control patterns, and cryptographic standards enforced across CyberGuard AI.

---

## 1. Authentication & JWT Tokens

### Token Architecture
- **Algorithm:** HS256 (HMAC with SHA-256)
- **Token Types:**
  - `access`: Short-lived (default 60 minutes) for authorized API calls.
  - `refresh`: Long-lived (default 30 days) stored securely to renew sessions.
- **Type Segregation Claim:** Every token includes `"type": "access"` or `"type": "refresh"`. Calling an API with a refresh token or attempting refresh with an access token is rejected immediately (`JWT_WRONG_TYPE`).
- **Cryptographic Subject:** `sub` claim holds the user UUID.
- **Public Metadata:** Access tokens embed `role` and `public_user_id` for client routing without sensitive identity leaks.

### Password Security
- **Hashing:** Bcrypt with dynamic salting.
- **Byte Bounds:** Enforces strict bounds of 8 to 72 bytes (reflecting Bcrypt's UTF-8 byte truncation boundary) to prevent password collision vulnerabilities.
- **Complexity:** Requires minimum one letter and one number at schema validation time.

---

## 2. Collaborative Room Security

Rooms represent private triage channels and incident war rooms.

### Access Control Rules
1. **Direct Join with Password:**
   - Password protection is optional per room.
   - If `password_hash` is present, joining requires verifying the plaintext password against the room hash.
   - Incorrect password raises `InvalidCredentialsError` (HTTP 401).
2. **Invite Only:**
   - Rooms configured with `join_policy="invite_only"` reject direct join attempts (`ROOM_INVITE_ONLY` / HTTP 403).
   - Only users possessing an unexpired, pending `RoomInvitation` token can join.
3. **Revocation:**
   - Members with `status="revoked"` in `room_members` are blocked from viewing or contributing (`ROOM_ACCESS_REVOKED` / HTTP 403).
4. **Idempotency:**
   - Users already active in a room receive `already_member=True` without duplicate database entries.

---

## 3. Public Slugs & Identifiers

To prevent enumeration attacks and exposure of internal database auto-increment or UUID identifiers:
- **Format:** `<full-name-slug>-<role>-<6digits>` (e.g. `sarah-connor-user-491823`, `marcus-vance-analyst-840192`)
- **Uniqueness:** Generated automatically on account registration. In the event of collisions, up to 10 unique candidate suffixes are generated.
- **Visibility:** Public slugs are displayed in UI cards, invite links, room rosters, and analyst marketplace listings.
