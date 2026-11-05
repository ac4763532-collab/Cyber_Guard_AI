/**
 * CyberGuard AI - Forgot Password Page
 *
 * Password reset request flow.
 */

import { useState, FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { AlertCircle, Mail, ArrowLeft, CheckCircle } from 'lucide-react'
import { clsx } from 'clsx'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { useAuth } from '@/contexts/AuthContext'

export function ForgotPasswordPage() {
  const { resetPassword, isFirebaseEnabled, error, clearError } = useAuth()

  const [email, setEmail] = useState('')
  const [localError, setLocalError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [emailSent, setEmailSent] = useState(false)

  // Validation
  const validateEmail = (email: string): boolean => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
  }

  // Handle submit
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLocalError('')
    clearError()

    if (!validateEmail(email)) {
      setLocalError('Please enter a valid email address.')
      return
    }

    setIsSubmitting(true)

    try {
      await resetPassword(email)
      setEmailSent(true)
    } catch {
      // Even on error, show success message for security (don't reveal if email exists)
      setEmailSent(true)
    } finally {
      setIsSubmitting(false)
    }
  }

  const displayError = localError || error

  // If Firebase not configured
  if (!isFirebaseEnabled) {
    return (
      <AuthLayout title="Reset Password" subtitle="Recover your account access">
        <div className="text-center py-8">
          <AlertCircle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            Feature Unavailable
          </h3>
          <p className="text-slate-400 mb-6">
            Password reset requires Firebase configuration.
          </p>
          <Link
            to="/login"
            className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Login
          </Link>
        </div>
      </AuthLayout>
    )
  }

  // Success state
  if (emailSent) {
    return (
      <AuthLayout title="Check your email" subtitle="Password reset instructions sent">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-emerald-500/20 rounded-full mb-6">
            <CheckCircle className="w-8 h-8 text-emerald-400" />
          </div>

          <p className="text-slate-400 mb-2">
            If an account exists for
          </p>
          <p className="text-white font-medium mb-6">{email}</p>
          <p className="text-slate-400 mb-8">
            you will receive password reset instructions shortly.
          </p>

          <div className="space-y-3">
            <Link
              to="/login"
              className="block w-full px-4 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-cyan-500/20"
            >
              Return to Sign In
            </Link>

            <button
              onClick={() => setEmailSent(false)}
              className="block w-full px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium rounded-lg transition-colors"
            >
              Try a different email
            </button>
          </div>
        </div>

        <p className="mt-8 text-center text-xs text-slate-500">
          Didn't receive the email? Check your spam folder or try again.
        </p>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout
      title="Forgot your password?"
      subtitle="Enter your email to receive reset instructions"
    >
      {/* Back to login */}
      <Link
        to="/login"
        className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors mb-6"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Back to login</span>
      </Link>

      {/* Error message */}
      {displayError && (
        <div className="flex items-start gap-3 p-4 mb-6 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{displayError}</p>
        </div>
      )}

      {/* Reset form */}
      <form onSubmit={handleSubmit} className="space-y-5">
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
            className={clsx(
              'w-full px-4 py-3 bg-slate-800/50 border rounded-lg text-white placeholder-slate-500',
              'focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent',
              'transition-all duration-200',
              displayError ? 'border-red-500/50' : 'border-slate-700'
            )}
          />
        </div>

        <button
          type="submit"
          disabled={isSubmitting}
          className={clsx(
            'w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200',
            isSubmitting
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30'
          )}
        >
          {isSubmitting ? (
            <>
              <div className="w-5 h-5 border-2 border-slate-500 border-t-transparent rounded-full animate-spin" />
              <span>Sending...</span>
            </>
          ) : (
            <>
              <Mail className="w-5 h-5" />
              <span>Send Reset Link</span>
            </>
          )}
        </button>
      </form>

      {/* Security note */}
      <p className="mt-8 text-center text-xs text-slate-500">
        For security, we don't confirm whether an email is registered.
      </p>
    </AuthLayout>
  )
}
