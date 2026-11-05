# CyberGuard AI - Authentication System

## Overview

CyberGuard AI implements a professional, production-ready authentication system with support for multiple authentication methods:

- **Email/Password** - Traditional authentication
- **Google Sign-In** - OAuth 2.0 via Firebase
- **Phone/SMS OTP** - Firebase Phone Authentication
- **Demo Mode** - Fallback when Firebase is not configured

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FRONTEND (React + TypeScript)                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Firebase Auth SDK                        │  │
│  │  • Google OAuth    • Email/Password    • Phone SMS OTP    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                    Firebase ID Token                             │
└──────────────────────────────┼───────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    BACKEND (FastAPI + Python)                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Firebase Admin SDK (Token Verification) OR JWT Fallback   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                    Authenticated User                            │
└──────────────────────────────┼───────────────────────────────────┘
                               │
                               ▼
                      CyberGuard AI APIs
```

## Firebase Configuration

### Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Create a project"**
3. Enter project name: `cyberguard-ai`
4. Enable/disable Google Analytics (optional)
5. Click **"Create project"**

### Step 2: Add Web Application

1. In Firebase Console, click the gear icon → **Project Settings**
2. Scroll to "Your apps" section
3. Click the **Web** icon (`</>`)
4. Register app:
   - App nickname: `CyberGuard AI Web`
   - ✓ Also set up Firebase Hosting (optional)
5. Click **"Register app"**
6. Copy the configuration values:

```javascript
const firebaseConfig = {
  apiKey: "AIza...",
  authDomain: "cyberguard-ai.firebaseapp.com",
  projectId: "cyberguard-ai",
  storageBucket: "cyberguard-ai.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abc123"
};
```

### Step 3: Enable Authentication Methods

1. Go to **Build** → **Authentication** → **Sign-in method**
2. Enable the following providers:

#### Email/Password
- Click **Email/Password**
- Toggle **Enable**
- Click **Save**

#### Google
- Click **Google**
- Toggle **Enable**
- Set **Project public-facing name**: `CyberGuard AI`
- Set **Project support email**: your email
- Click **Save**

#### Phone
- Click **Phone**
- Toggle **Enable**
- Click **Save**

### Step 4: Configure Authorized Domains

1. Go to **Authentication** → **Settings** → **Authorized domains**
2. Add your domains:
   - `localhost` (for development)
   - Your production domain (e.g., `cyberguard.yourdomain.com`)

### Step 5: Configure SMS Region Policy (Optional)

1. Go to **Authentication** → **Settings** → **SMS region policy**
2. Configure allowed regions for phone authentication

### Step 6: Add Environment Variables

Create `frontend/.env.local`:

```env
VITE_FIREBASE_API_KEY=AIza...
VITE_FIREBASE_AUTH_DOMAIN=cyberguard-ai.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=cyberguard-ai
VITE_FIREBASE_STORAGE_BUCKET=cyberguard-ai.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=123456789
VITE_FIREBASE_APP_ID=1:123456789:web:abc123
```

**Important:** Never commit `.env.local` to version control.

## Authentication Flows

### Email/Password Login

```
User enters email + password
        ↓
Frontend validates input
        ↓
Firebase signInWithEmailAndPassword()
        ↓
Success → ID Token received
        ↓
Navigate to Dashboard
```

### Google Sign-In

```
User clicks "Continue with Google"
        ↓
Firebase signInWithPopup(GoogleAuthProvider)
        ↓
Google OAuth popup opens
        ↓
User selects Google account
        ↓
Success → ID Token received
        ↓
Navigate to Dashboard
```

### Phone OTP

```
User enters phone number
        ↓
reCAPTCHA verification (invisible)
        ↓
Firebase signInWithPhoneNumber()
        ↓
SMS sent with 6-digit OTP
        ↓
User enters OTP
        ↓
confirmationResult.confirm(otp)
        ↓
Success → ID Token received
        ↓
Navigate to Dashboard
```

### Email Verification

```
User signs up with email/password
        ↓
Account created
        ↓
Verification email sent automatically
        ↓
User clicks verification link
        ↓
Email marked as verified
        ↓
Full access granted
```

## Demo Mode

When Firebase is not configured, the system falls back to demo mode:

- Uses backend JWT authentication
- Pre-configured demo accounts:
  - **Admin**: `admin` / `admin123!`
  - **Analyst**: `analyst` / `analyst123!`
- Demo mode is indicated in the UI

## Protected Routes

The following routes require authentication:

| Route | Description |
|-------|-------------|
| `/` | Dashboard |
| `/alerts` | Security Alerts |
| `/events` | Security Events |
| `/incidents` | Incident Management |
| `/reports` | Reports |
| `/settings` | User Settings |
| `/analysis/email` | Email Analysis |
| `/analysis/logs` | Log Analysis |
| `/analysis/network` | Network Analysis |
| `/agents` | Agent Management |

## Security Considerations

### Frontend

- Never store passwords in localStorage
- Firebase tokens are stored securely by Firebase SDK
- All API calls include Authorization header
- Session persistence handled by Firebase

### Backend

- Always verify Firebase ID tokens server-side
- Never trust client-provided user data
- Implement rate limiting on auth endpoints
- Use HTTPS in production

### Firebase Security Rules

Configure Firestore/Realtime Database rules if using Firebase databases:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```

## Error Handling

Common Firebase auth errors are mapped to user-friendly messages:

| Error Code | User Message |
|------------|--------------|
| `auth/invalid-credential` | Invalid email or password. |
| `auth/user-not-found` | No account found with this email. |
| `auth/wrong-password` | Incorrect password. |
| `auth/email-already-in-use` | An account with this email already exists. |
| `auth/weak-password` | Password must be at least 6 characters. |
| `auth/popup-closed-by-user` | Sign-in was cancelled. |
| `auth/popup-blocked` | Sign-in popup was blocked. Please allow popups. |
| `auth/too-many-requests` | Too many attempts. Please wait and try again. |
| `auth/invalid-verification-code` | Invalid verification code. |
| `auth/code-expired` | Verification code has expired. |

## Testing

### Development Testing

1. Start the backend:
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload
   ```

2. Start the frontend:
   ```bash
   cd frontend
   npm run dev
   ```

3. Test authentication flows:
   - Email/password login
   - Google sign-in (requires Firebase config)
   - Phone OTP (requires Firebase config)
   - Logout
   - Protected route access

### Firebase Test Phone Numbers

For testing phone auth without SMS costs:

1. Go to Firebase Console → Authentication → Sign-in method → Phone
2. Add test phone numbers with verification codes
3. Example: `+1 650-555-1234` with code `123456`

## Troubleshooting

### "Firebase is not configured"

Ensure all environment variables are set in `.env.local`:
- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`

### Google Sign-In Popup Blocked

- Enable popups for the site
- Use `signInWithRedirect` as fallback

### Phone Auth Not Working

- Verify phone provider is enabled
- Check authorized domains
- Verify reCAPTCHA is configured
- Check SMS region policy

### CORS Errors

- Add domain to Firebase authorized domains
- Configure backend CORS settings

## File Structure

```
frontend/src/
├── lib/
│   └── firebase.ts           # Firebase initialization
├── contexts/
│   └── AuthContext.tsx       # Auth state management
├── components/auth/
│   ├── AuthLayout.tsx        # Split-screen layout
│   ├── GoogleButton.tsx      # Google sign-in button
│   └── OTPInput.tsx          # 6-digit OTP input
├── pages/
│   ├── LoginPage.tsx         # Main login page
│   ├── SignupPage.tsx        # Registration page
│   ├── ForgotPasswordPage.tsx
│   ├── VerifyEmailPage.tsx
│   └── PhoneLoginPage.tsx
└── App.tsx                   # Protected routes
```

## Future Enhancements

- [ ] Multi-factor authentication (MFA)
- [ ] Social providers (GitHub, Microsoft)
- [ ] Session management UI
- [ ] Account linking
- [ ] Backend Firebase Admin SDK integration
- [ ] Role-based access control with Firebase claims
