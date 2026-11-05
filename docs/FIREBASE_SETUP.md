# Firebase Authentication Setup

## Overview

CyberGuard AI uses Firebase Authentication for user sign-in (Google, Email, Phone) 
and a bridge to the FastAPI backend for API authorization.

## Authentication Flow

```
┌──────────┐    Firebase Auth    ┌──────────┐
│ Frontend │ ─────────────────►  │ Firebase │
│ (React)  │ ◄───── ID Token ─── │          │
└────┬─────┘                     └──────────┘
     │
     │ POST /auth/firebase-login
     │ { id_token: "..." }
     ▼
┌──────────┐    Verify Token     ┌──────────┐
│ Backend  │ ─────────────────►  │ Firebase │
│ (FastAPI)│ ◄── User Claims ─── │  Admin   │
└────┬─────┘                     └──────────┘
     │
     │ Returns: { access_token, user }
     ▼
┌──────────┐
│ Backend  │  ◄── All API calls use backend JWT
│   JWT    │
└──────────┘
```

## Setup Instructions

### 1. Firebase Console Setup (Already Done)

Project: `cyberguard-ai-825d4`

- Enable Authentication providers (Google, Email/Password, Phone)
- Frontend config is in `frontend/.env.local`

### 2. Service Account for Backend

To verify Firebase ID tokens, the backend needs a service account:

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select project `cyberguard-ai-825d4`
3. Go to **Project Settings** → **Service Accounts**
4. Click **Generate new private key**
5. Download the JSON file
6. Save it securely (DO NOT commit to git!)

### 3. Configure Backend

**Option A: Service Account File (Recommended)**

```bash
# backend/.env
FIREBASE_PROJECT_ID=cyberguard-ai-825d4
FIREBASE_SERVICE_ACCOUNT_PATH=/path/to/serviceAccountKey.json
```

**Option B: Environment Variable**

```bash
# Set the GOOGLE_APPLICATION_CREDENTIALS env var
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/serviceAccountKey.json"

# backend/.env
FIREBASE_PROJECT_ID=cyberguard-ai-825d4
```

**Option C: GCP Environment (Cloud Run, etc.)**

If running on Google Cloud, Application Default Credentials work automatically.
Just set the project ID:

```bash
FIREBASE_PROJECT_ID=cyberguard-ai-825d4
```

### 4. Verify Setup

```bash
# Start backend
cd backend
uvicorn app.main:app --reload

# Check Firebase status
curl http://localhost:8000/api/v1/auth/firebase-status
# Should return: {"enabled": true, "project_id": "cyberguard-ai-825d4"}
```

## API Endpoints

### `GET /api/v1/auth/firebase-status`
Check if Firebase authentication is enabled.

**Response:**
```json
{
  "enabled": true,
  "project_id": "cyberguard-ai-825d4"
}
```

### `POST /api/v1/auth/firebase-login`
Exchange Firebase ID token for backend JWT.

**Request:**
```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "uuid",
    "username": "firebase:abc123",
    "email": "user@example.com",
    "role": "viewer",
    "full_name": "John Doe"
  },
  "firebase_uid": "abc123",
  "is_new_user": false
}
```

### `POST /api/v1/auth/login`
Traditional username/password login (fallback when Firebase unavailable).

## Role Management

Roles can be set via Firebase Custom Claims:

```python
# Backend: Set user role
from app.auth.firebase_verify import set_user_claims

await set_user_claims(firebase_uid, {"role": "analyst"})
```

Available roles:
- `admin` - Full access
- `analyst` - Create alerts, manage incidents, run analysis
- `viewer` - Read-only access

## Security Notes

1. **Never commit service account keys to git**
2. **The backend JWT is separate from Firebase tokens** - use it for API calls
3. **Firebase tokens expire in 1 hour** - the frontend handles refresh automatically
4. **Backend JWTs expire in 30 minutes** (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)

## Troubleshooting

### "Firebase is not configured"
- Check `FIREBASE_PROJECT_ID` is set in `backend/.env`
- Ensure `firebase-admin` is installed: `pip install firebase-admin`

### "Your default credentials were not found"
- Download service account JSON from Firebase Console
- Set `FIREBASE_SERVICE_ACCOUNT_PATH` in `.env`

### "Invalid token"
- Token may have expired (>1 hour old)
- Token may be from a different Firebase project
- Ensure frontend and backend use the same project ID
