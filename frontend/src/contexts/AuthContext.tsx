/**
 * CyberGuard AI - Authentication Context
 *
 * Provides authentication state and methods throughout the app.
 * Supports both Firebase and demo/fallback mode.
 *
 * Authentication Flow:
 * 1. User authenticates with Firebase (Google, Email, Phone)
 * 2. Frontend receives Firebase ID token
 * 3. Frontend sends token to /auth/firebase-login
 * 4. Backend verifies token and returns backend JWT
 * 5. Backend JWT is used for all API calls
 */

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  ReactNode,
} from 'react'
import {
  isFirebaseConfigured,
  onAuthChange,
  signInWithGoogle,
  signInWithEmail,
  createAccountWithEmail,
  sendVerificationEmail,
  sendPasswordReset,
  firebaseSignOut,
  getAuthErrorMessage,
  User as FirebaseUser,
} from '@/lib/firebase'
import { authApi } from '@/services/api'
import axios from 'axios'

// Auth provider types
export type AuthProvider = 'email' | 'google' | 'phone' | 'demo'

// User interface
export interface AuthUser {
  id: string
  email: string | null
  displayName: string | null
  photoURL: string | null
  emailVerified: boolean
  phoneNumber: string | null
  provider: AuthProvider
  role?: string
}

// Auth context interface
interface AuthContextType {
  user: AuthUser | null
  loading: boolean
  isAuthenticated: boolean
  isFirebaseEnabled: boolean
  error: string | null

  // Email/Password
  signInWithEmailPassword: (email: string, password: string) => Promise<void>
  signUpWithEmailPassword: (email: string, password: string) => Promise<void>
  resendVerificationEmail: () => Promise<void>
  resetPassword: (email: string) => Promise<void>

  // Google
  signInWithGoogleProvider: () => Promise<void>

  // Demo mode (fallback)
  signInDemo: (username: string, password: string) => Promise<void>

  // Logout
  logout: () => Promise<void>

  // Utilities
  clearError: () => void
  getToken: () => Promise<string | null>
}

const AuthContext = createContext<AuthContextType | null>(null)

// Convert Firebase user to AuthUser
const firebaseUserToAuthUser = (
  fbUser: FirebaseUser,
  provider: AuthProvider
): AuthUser => ({
  id: fbUser.uid,
  email: fbUser.email,
  displayName: fbUser.displayName,
  photoURL: fbUser.photoURL,
  emailVerified: fbUser.emailVerified,
  phoneNumber: fbUser.phoneNumber,
  provider,
})

// Demo user for fallback mode
const createDemoUser = (username: string, role: string): AuthUser => ({
  id: `demo-${username}`,
  email: `${username}@cyberguard.example.com`,
  displayName: username === 'admin' ? 'System Administrator' : 'Security Analyst',
  photoURL: null,
  emailVerified: true,
  phoneNumber: null,
  provider: 'demo',
  role,
})

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const isFirebaseEnabled = isFirebaseConfigured()

  // Initialize auth state
  useEffect(() => {
    // Check localStorage first for existing backend session
    const storedUser = localStorage.getItem('user')
    const token = localStorage.getItem('access_token')

    if (storedUser && token) {
      try {
        const parsed = JSON.parse(storedUser)
        // Restore user from stored session (works for both Firebase and demo users)
        setUser({
          id: parsed.id || `demo-${parsed.username}`,
          email: parsed.email || `${parsed.username}@cyberguard.example.com`,
          displayName: parsed.full_name || parsed.username,
          photoURL: null,
          emailVerified: true,
          phoneNumber: null,
          provider: parsed.username?.startsWith('firebase:') ? 'google' : 'demo',
          role: parsed.role,
        })
        setLoading(false)
        return
      } catch {
        localStorage.removeItem('user')
        localStorage.removeItem('access_token')
      }
    }

    if (isFirebaseEnabled) {
      // Listen to Firebase auth state
      const unsubscribe = onAuthChange(async (fbUser) => {
        if (fbUser) {
          // Firebase user exists - exchange for backend token
          try {
            await exchangeFirebaseToken(fbUser)
          } catch {
            // If exchange fails, still set basic user info
            const providerId = fbUser.providerData[0]?.providerId
            let provider: AuthProvider = 'email'
            if (providerId === 'google.com') provider = 'google'
            else if (providerId === 'phone') provider = 'phone'

            setUser(firebaseUserToAuthUser(fbUser, provider))
          }
        } else {
          setUser(null)
        }
        setLoading(false)
      })

      return () => unsubscribe()
    } else {
      setLoading(false)
    }
  }, [isFirebaseEnabled])

  // Clear error
  const clearError = useCallback(() => setError(null), [])

  // Get auth token for API calls - always returns backend JWT
  const getToken = useCallback(async (): Promise<string | null> => {
    // Backend JWT is stored in localStorage after successful login
    return localStorage.getItem('access_token')
  }, [])

  /**
   * Exchange Firebase ID token for backend JWT.
   * This bridges Firebase auth with our backend's authorization system.
   */
  const exchangeFirebaseToken = async (firebaseUser: FirebaseUser): Promise<void> => {
    try {
      // Get Firebase ID token
      const idToken = await firebaseUser.getIdToken()

      // Exchange for backend JWT
      const response = await axios.post('/api/v1/auth/firebase-login', {
        id_token: idToken,
      })

      const { access_token, user: backendUser } = response.data

      // Store backend JWT and user info
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('user', JSON.stringify(backendUser))

      // Update user state with role from backend
      const providerId = firebaseUser.providerData[0]?.providerId
      let provider: AuthProvider = 'email'
      if (providerId === 'google.com') provider = 'google'
      else if (providerId === 'phone') provider = 'phone'

      setUser({
        id: backendUser.id,
        email: firebaseUser.email,
        displayName: firebaseUser.displayName || backendUser.full_name,
        photoURL: firebaseUser.photoURL,
        emailVerified: firebaseUser.emailVerified,
        phoneNumber: firebaseUser.phoneNumber,
        provider,
        role: backendUser.role,
      })
    } catch (err) {
      console.error('Failed to exchange Firebase token:', err)
      // If backend is unavailable, still allow Firebase-only auth
      // but API calls will fail
    }
  }

  // Email/Password sign in
  const signInWithEmailPassword = useCallback(
    async (email: string, password: string) => {
      setError(null)
      setLoading(true)

      try {
        if (isFirebaseEnabled) {
          const result = await signInWithEmail(email, password)
          // Exchange Firebase token for backend JWT
          await exchangeFirebaseToken(result.user)
        } else {
          // Fallback to demo backend
          await authApi.login(email.split('@')[0], password)
          const storedUser = authApi.getUser()
          if (storedUser) {
            setUser(createDemoUser(storedUser.username, storedUser.role))
          }
        }
      } catch (err: unknown) {
        const firebaseError = err as { code?: string; message?: string }
        const code = firebaseError.code || ''
        setError(getAuthErrorMessage(code) || firebaseError.message || 'Sign in failed')
        throw err
      } finally {
        setLoading(false)
      }
    },
    [isFirebaseEnabled]
  )

  // Email/Password sign up
  const signUpWithEmailPassword = useCallback(
    async (email: string, password: string) => {
      setError(null)
      setLoading(true)

      try {
        if (!isFirebaseEnabled) {
          throw new Error('Sign up requires Firebase configuration')
        }

        const result = await createAccountWithEmail(email, password)
        await sendVerificationEmail(result.user)
        // Exchange Firebase token for backend JWT
        await exchangeFirebaseToken(result.user)
      } catch (err: unknown) {
        const firebaseError = err as { code?: string; message?: string }
        const code = firebaseError.code || ''
        setError(getAuthErrorMessage(code) || firebaseError.message || 'Sign up failed')
        throw err
      } finally {
        setLoading(false)
      }
    },
    [isFirebaseEnabled]
  )

  // Resend verification email
  const resendVerificationEmail = useCallback(async () => {
    if (!isFirebaseEnabled) return

    try {
      const auth = await import('@/lib/firebase').then((m) => m.getFirebaseAuth())
      const currentUser = auth?.currentUser
      if (currentUser) {
        await sendVerificationEmail(currentUser)
      }
    } catch (err: unknown) {
      const firebaseError = err as { code?: string }
      const code = firebaseError.code || ''
      setError(getAuthErrorMessage(code) || 'Failed to send verification email')
      throw err
    }
  }, [isFirebaseEnabled])

  // Password reset
  const resetPassword = useCallback(
    async (email: string) => {
      setError(null)

      try {
        if (!isFirebaseEnabled) {
          throw new Error('Password reset requires Firebase configuration')
        }

        await sendPasswordReset(email)
      } catch (err: unknown) {
        const firebaseError = err as { code?: string }
        const code = firebaseError.code || ''
        setError(getAuthErrorMessage(code) || 'Failed to send reset email')
        throw err
      }
    },
    [isFirebaseEnabled]
  )

  // Google sign in
  const signInWithGoogleProvider = useCallback(async () => {
    setError(null)
    setLoading(true)

    try {
      if (!isFirebaseEnabled) {
        throw new Error('Google sign-in requires Firebase configuration')
      }

      const result = await signInWithGoogle()
      // Exchange Firebase token for backend JWT
      await exchangeFirebaseToken(result.user)
    } catch (err: unknown) {
      const firebaseError = err as { code?: string; message?: string }
      const code = firebaseError.code || ''
      setError(getAuthErrorMessage(code) || firebaseError.message || 'Google sign in failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [isFirebaseEnabled])

  // Demo mode sign in
  const signInDemo = useCallback(async (username: string, password: string) => {
    setError(null)
    setLoading(true)

    try {
      const result = await authApi.login(username, password)
      if (result.user) {
        setUser(createDemoUser(result.user.username, result.user.role))
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { detail?: string } } }
      setError(axiosError.response?.data?.detail || 'Invalid credentials')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  // Logout
  const logout = useCallback(async () => {
    setLoading(true)

    try {
      if (isFirebaseEnabled) {
        await firebaseSignOut()
      }
      // Always clear local storage
      authApi.logout()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [isFirebaseEnabled])

  const value: AuthContextType = {
    user,
    loading,
    isAuthenticated: !!user,
    isFirebaseEnabled,
    error,
    signInWithEmailPassword,
    signUpWithEmailPassword,
    resendVerificationEmail,
    resetPassword,
    signInWithGoogleProvider,
    signInDemo,
    logout,
    clearError,
    getToken,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// Hook to use auth context
export function useAuth(): AuthContextType {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
