/**
 * CyberGuard AI - Sign Up Page
 *
 * User registration with email/password.
 */

import { useState, FormEvent } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  Eye,
  EyeOff,
  AlertCircle,
  UserPlus,
  Check,
  X,
} from 'lucide-react'
import { clsx } from 'clsx'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { GoogleButton } from '@/components/auth/GoogleButton'
import { useAuth } from '@/contexts/AuthContext'

// Password strength calculation
function getPasswordStrength(password: string): {
  score: number
  label: string
  color: string
} {
  let score = 0

  if (password.length >= 6) score++
  if (password.length >= 8) score++
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++
  if (/\d/.test(password)) score++
  if (/[^a-zA-Z0-9]/.test(password)) score++

  if (score <= 1) return { score, label: 'Weak', color: 'bg-red-500' }
  if (score === 2) return { score, label: 'Fair', color: 'bg-orange-500' }
  if (score === 3) return { score, label: 'Good', color: 'bg-yellow-500' }
  return { score, label: 'Strong', color: 'bg-emerald-500' }
}

// Password requirement check
function PasswordRequirement({
  met,
  text,
}: {
  met: boolean
  text: string
}) {
  return (
    <div className="flex items-center gap-2 text-xs">
      {met ? (
        <Check className="w-3.5 h-3.5 text-emerald-400" />
      ) : (
        <X className="w-3.5 h-3.5 text-slate-500" />
      )}
      <span className={met ? 'text-slate-300' : 'text-slate-500'}>{text}</span>
    </div>
  )
}

export function SignupPage() {
  const navigate = useNavigate()
  const {
    signUpWithEmailPassword,
    signInWithGoogleProvider,
    isFirebaseEnabled,
    loading,
    error,
    clearError,
  } = useAuth()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [localError, setLocalError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [agreedToTerms, setAgreedToTerms] = useState(false)

  // Validation
  const validateEmail = (email: string): boolean => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
  }

  const passwordStrength = getPasswordStrength(password)

  // Password requirements
  const requirements = {
    length: password.length >= 8,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /\d/.test(password),
  }

  // Handle form submit
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError('')
    clearError()

    // Validate email
    if (!validateEmail(email)) {
      setLocalError('Please enter a valid email address.')
      return
    }

    // Validate password
    if (password.length < 6) {
      setLocalError('Password must be at least 6 characters.')
      return
    }

    // Validate password match
    if (password !== confirmPassword) {
      setLocalError('Passwords do not match.')
      return
    }

    // Check terms
    if (!agreedToTerms) {
      setLocalError('Please agree to the terms to continue.')
      return
    }

    setIsSubmitting(true)

    try {
      await signUpWithEmailPassword(email, password)
      navigate('/verify-email')
    } catch {
      // Error handled by context
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle Google sign-in
  const handleGoogleSignIn = async () => {
    clearError()
    setLocalError('')

    try {
      await signInWithGoogleProvider()
      navigate('/')
    } catch {
      // Error handled by context
    }
  }

  const displayError = localError || error

  // If Firebase not configured, redirect
  if (!isFirebaseEnabled) {
    return (
      <AuthLayout title="Sign Up" subtitle="Create your account">
        <div className="text-center py-8">
          <AlertCircle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            Registration Unavailable
          </h3>
          <p className="text-slate-400 mb-6">
            Firebase is not configured. Sign up is not available in demo mode.
          </p>
          <Link
            to="/login"
            className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
          >
            Back to Login
          </Link>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title="Create account" subtitle="Get started with CyberGuard AI">
      {/* Google Sign-In */}
      <GoogleButton
        onClick={handleGoogleSignIn}
        disabled={loading || isSubmitting}
        label="Sign up with Google"
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

      {/* Error message */}
      {displayError && (
        <div className="flex items-start gap-3 p-4 mb-6 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{displayError}</p>
        </div>
      )}

      {/* Signup form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Email */}
        <div>
          <label
            htmlFor="email"
            className="block text-sm font-medium text-slate-300 mb-2"
          >
            Email address
          </label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value)
              setLocalError('')
            }}
            required
            autoComplete="email"
            autoFocus
            placeholder="you@example.com"
            className="w-full px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-200"
          />
        </div>

        {/* Password */}
        <div>
          <label
            htmlFor="password"
            className="block text-sm font-medium text-slate-300 mb-2"
          >
            Password
          </label>
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
              autoComplete="new-password"
              placeholder="••••••••"
              className="w-full px-4 py-3 pr-12 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-200"
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

          {/* Password strength */}
          {password && (
            <div className="mt-3 space-y-2">
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={clsx('h-full transition-all duration-300', passwordStrength.color)}
                    style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                  />
                </div>
                <span className={clsx('text-xs font-medium', {
                  'text-red-400': passwordStrength.score <= 1,
                  'text-orange-400': passwordStrength.score === 2,
                  'text-yellow-400': passwordStrength.score === 3,
                  'text-emerald-400': passwordStrength.score >= 4,
                })}>
                  {passwordStrength.label}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-1">
                <PasswordRequirement met={requirements.length} text="8+ characters" />
                <PasswordRequirement met={requirements.lowercase} text="Lowercase letter" />
                <PasswordRequirement met={requirements.uppercase} text="Uppercase letter" />
                <PasswordRequirement met={requirements.number} text="Number" />
              </div>
            </div>
          )}
        </div>

        {/* Confirm Password */}
        <div>
          <label
            htmlFor="confirmPassword"
            className="block text-sm font-medium text-slate-300 mb-2"
          >
            Confirm password
          </label>
          <div className="relative">
            <input
              id="confirmPassword"
              type={showConfirmPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value)
                setLocalError('')
              }}
              required
              autoComplete="new-password"
              placeholder="••••••••"
              className={clsx(
                'w-full px-4 py-3 pr-12 bg-slate-800/50 border rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-200',
                confirmPassword && password !== confirmPassword
                  ? 'border-red-500/50'
                  : 'border-slate-700'
              )}
            />
            <button
              type="button"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 transition-colors"
              aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
            >
              {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
          {confirmPassword && password !== confirmPassword && (
            <p className="mt-1 text-xs text-red-400">Passwords do not match</p>
          )}
        </div>

        {/* Terms checkbox */}
        <div className="flex items-start gap-3">
          <input
            type="checkbox"
            id="terms"
            checked={agreedToTerms}
            onChange={(e) => setAgreedToTerms(e.target.checked)}
            className="mt-1 w-4 h-4 rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-0"
          />
          <label htmlFor="terms" className="text-sm text-slate-400">
            I agree to the{' '}
            <a href="#" className="text-cyan-400 hover:text-cyan-300">
              Terms of Service
            </a>{' '}
            and{' '}
            <a href="#" className="text-cyan-400 hover:text-cyan-300">
              Privacy Policy
            </a>
          </label>
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
              <span>Creating account...</span>
            </>
          ) : (
            <>
              <UserPlus className="w-5 h-5" />
              <span>Create Account</span>
            </>
          )}
        </button>
      </form>

      {/* Sign in link */}
      <p className="mt-8 text-center text-slate-400">
        Already have an account?{' '}
        <Link
          to="/login"
          className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
        >
          Sign in
        </Link>
      </p>
    </AuthLayout>
  )
}
