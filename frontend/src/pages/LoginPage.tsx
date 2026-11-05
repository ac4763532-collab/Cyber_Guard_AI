/**
 * CyberGuard AI - Login Page
 *
 * Professional cybersecurity-themed authentication screen.
 * Supports: Email/Password, Google Sign-In, Phone
 */

import { useState, FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle, LogIn, Smartphone, ArrowRight, Info } from 'lucide-react'
import { clsx } from 'clsx'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { GoogleButton } from '@/components/auth/GoogleButton'
import { useAuth } from '@/contexts/AuthContext'

export function LoginPage() {
  const {
    signInWithEmailPassword,
    signInWithGoogleProvider,
    isFirebaseEnabled,
    loading,
    error,
    clearError,
  } = useAuth()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [localError, setLocalError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [showFirebaseNotice, setShowFirebaseNotice] = useState(false)

  // Validation
  const validateEmail = (email: string): boolean => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
  }

  // Handle email/password submit
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError('')
    clearError()

    // Validate
    if (!validateEmail(email)) {
      setLocalError('Please enter a valid email address.')
      return
    }

    if (!password) {
      setLocalError('Password is required.')
      return
    }

    setIsSubmitting(true)

    try {
      await signInWithEmailPassword(email, password)
      // Navigation handled by PublicRoute when isAuthenticated becomes true
    } catch {
      // Error handled by context
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle Google sign-in
  const handleGoogleSignIn = async () => {
    if (!isFirebaseEnabled) {
      setShowFirebaseNotice(true)
      return
    }

    clearError()
    setLocalError('')

    try {
      await signInWithGoogleProvider()
      // Navigation handled by PublicRoute when isAuthenticated becomes true
    } catch {
      // Error handled by context
    }
  }

  // Handle phone login click
  const handlePhoneClick = (e: React.MouseEvent) => {
    if (!isFirebaseEnabled) {
      e.preventDefault()
      setShowFirebaseNotice(true)
    }
  }

  const displayError = localError || error

  return (
    <AuthLayout title="Welcome back" subtitle="Sign in to CyberGuard AI">
      {/* Google Sign-In */}
      <GoogleButton
        onClick={handleGoogleSignIn}
        disabled={loading || isSubmitting}
      />

      {/* Divider */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-slate-700" />
        </div>
        <div className="relative flex justify-center">
          <span className="px-4 text-sm text-slate-500 bg-[#05070B]">or</span>
        </div>
      </div>

      {/* Firebase notice */}
      {showFirebaseNotice && (
        <div className="flex items-start gap-3 p-4 mb-6 bg-amber-500/10 border border-amber-500/30 rounded-lg">
          <Info className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-amber-400 font-medium">Firebase Required</p>
            <p className="text-xs text-amber-400/70 mt-1">
              Google Sign-In and Phone authentication require Firebase configuration.
              Use the demo credentials below or configure Firebase in .env.local
            </p>
          </div>
          <button
            onClick={() => setShowFirebaseNotice(false)}
            className="text-amber-400 hover:text-amber-300 p-1"
          >
            ×
          </button>
        </div>
      )}

      {/* Error message */}
      {displayError && (
        <div className="flex items-start gap-3 p-4 mb-6 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{displayError}</p>
        </div>
      )}

      {/* Login form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Email / Username */}
        <div>
          <label
            htmlFor="email"
            className="block text-sm font-medium text-slate-300 mb-2"
          >
            {isFirebaseEnabled ? 'Email address' : 'Username'}
          </label>
          <input
            id="email"
            type={isFirebaseEnabled ? 'email' : 'text'}
            value={email}
            onChange={(e) => {
              setEmail(e.target.value)
              setLocalError('')
            }}
            required
            autoComplete={isFirebaseEnabled ? 'email' : 'username'}
            autoFocus
            placeholder={isFirebaseEnabled ? 'you@example.com' : 'Enter username'}
            className={clsx(
              'w-full px-4 py-3 bg-slate-800/50 border rounded-lg text-white placeholder-slate-500',
              'focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent',
              'transition-all duration-200',
              displayError ? 'border-red-500/50' : 'border-slate-700'
            )}
          />
        </div>

        {/* Password */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label
              htmlFor="password"
              className="block text-sm font-medium text-slate-300"
            >
              Password
            </label>
            <Link
              to={isFirebaseEnabled ? '/forgot-password' : '#'}
              onClick={(e) => {
                if (!isFirebaseEnabled) {
                  e.preventDefault()
                  setShowFirebaseNotice(true)
                }
              }}
              className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              Forgot password?
            </Link>
          </div>
          <div className="relative">
            <input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value)
                setLocalError('')
              }}
              required
              autoComplete="current-password"
              placeholder="••••••••"
              className={clsx(
                'w-full px-4 py-3 pr-12 bg-slate-800/50 border rounded-lg text-white placeholder-slate-500',
                'focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent',
                'transition-all duration-200',
                displayError ? 'border-red-500/50' : 'border-slate-700'
              )}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 transition-colors"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Submit button */}
        <button
          type="submit"
          disabled={loading || isSubmitting}
          className={clsx(
            'w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200',
            loading || isSubmitting
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30'
          )}
        >
          {loading || isSubmitting ? (
            <>
              <div className="w-5 h-5 border-2 border-slate-500 border-t-transparent rounded-full animate-spin" />
              <span>Signing in...</span>
            </>
          ) : (
            <>
              <LogIn className="w-5 h-5" />
              <span>Sign In</span>
            </>
          )}
        </button>
      </form>

      {/* Phone login option */}
      <Link
        to={isFirebaseEnabled ? '/login/phone' : '#'}
        onClick={handlePhoneClick}
        className="flex items-center justify-center gap-2 mt-4 py-3 text-slate-400 hover:text-white transition-colors group"
      >
        <Smartphone className="w-4 h-4" />
        <span>Continue with phone</span>
        <ArrowRight className="w-4 h-4 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
      </Link>

      {/* Sign up link */}
      <p className="mt-6 text-center text-slate-400">
        Don't have an account?{' '}
        <Link
          to={isFirebaseEnabled ? '/signup' : '#'}
          onClick={(e) => {
            if (!isFirebaseEnabled) {
              e.preventDefault()
              setShowFirebaseNotice(true)
            }
          }}
          className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
        >
          Create account
        </Link>
      </p>

      {/* Security footer */}
      <div className="mt-8 flex items-center justify-center gap-2 text-xs text-slate-600">
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
          />
        </svg>
        <span>Secure authentication protected by industry-standard encryption</span>
      </div>
    </AuthLayout>
  )
}
