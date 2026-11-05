/**
 * CyberGuard AI - Email Verification Page
 *
 * Shows after signup, prompting user to verify their email.
 */

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Mail, RefreshCw, CheckCircle, AlertCircle } from 'lucide-react'
import { clsx } from 'clsx'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { useAuth } from '@/contexts/AuthContext'

export function VerifyEmailPage() {
  const navigate = useNavigate()
  const { user, resendVerificationEmail, logout, isFirebaseEnabled } = useAuth()

  const [resending, setResending] = useState(false)
  const [resent, setResent] = useState(false)
  const [error, setError] = useState('')

  // Mask email for privacy
  const maskEmail = (email: string): string => {
    const [local, domain] = email.split('@')
    if (local.length <= 2) return email
    return `${local[0]}${'*'.repeat(Math.min(local.length - 2, 5))}${local.slice(-1)}@${domain}`
  }

  // Handle resend
  const handleResend = async () => {
    setError('')
    setResending(true)

    try {
      await resendVerificationEmail()
      setResent(true)
      setTimeout(() => setResent(false), 5000)
    } catch {
      setError('Failed to send verification email. Please try again.')
    } finally {
      setResending(false)
    }
  }

  // Handle "I've verified"
  const handleVerified = () => {
    // Reload to check verification status
    window.location.reload()
  }

  // Handle sign out
  const handleSignOut = async () => {
    await logout()
    navigate('/login')
  }

  // If not Firebase or no user
  if (!isFirebaseEnabled || !user) {
    return (
      <AuthLayout title="Verify Email" subtitle="Confirm your email address">
        <div className="text-center py-8">
          <AlertCircle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            No Verification Needed
          </h3>
          <p className="text-slate-400 mb-6">
            {!isFirebaseEnabled
              ? 'Email verification is not available in demo mode.'
              : 'Please sign in first.'}
          </p>
          <Link
            to="/login"
            className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
          >
            Go to Login
          </Link>
        </div>
      </AuthLayout>
    )
  }

  // If already verified
  if (user.emailVerified) {
    return (
      <AuthLayout title="Email Verified" subtitle="Your account is ready">
        <div className="text-center py-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-emerald-500/20 rounded-full mb-6">
            <CheckCircle className="w-8 h-8 text-emerald-400" />
          </div>

          <h3 className="text-lg font-medium text-white mb-2">
            You're all set!
          </h3>
          <p className="text-slate-400 mb-8">
            Your email has been verified. You can now access the full platform.
          </p>

          <Link
            to="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-cyan-500/20"
          >
            Go to Dashboard
          </Link>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title="Verify your email" subtitle="One last step to secure your account">
      <div className="text-center">
        {/* Icon */}
        <div className="inline-flex items-center justify-center w-16 h-16 bg-cyan-500/20 rounded-full mb-6">
          <Mail className="w-8 h-8 text-cyan-400" />
        </div>

        {/* Message */}
        <p className="text-slate-400 mb-2">We sent a verification link to:</p>
        <p className="text-white font-medium text-lg mb-6">
          {user.email ? maskEmail(user.email) : 'your email'}
        </p>

        <p className="text-slate-400 text-sm mb-8">
          Click the link in the email to verify your account. If you don't see it, check your spam folder.
        </p>

        {/* Error */}
        {error && (
          <div className="flex items-center justify-center gap-2 p-3 mb-6 bg-red-500/10 border border-red-500/30 rounded-lg">
            <AlertCircle className="w-4 h-4 text-red-400" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Success message */}
        {resent && (
          <div className="flex items-center justify-center gap-2 p-3 mb-6 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <p className="text-sm text-emerald-400">Verification email sent!</p>
          </div>
        )}

        {/* Actions */}
        <div className="space-y-3">
          <button
            onClick={handleVerified}
            className="w-full px-4 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium rounded-lg transition-all duration-200 shadow-lg shadow-cyan-500/20"
          >
            I've Verified My Email
          </button>

          <button
            onClick={handleResend}
            disabled={resending}
            className={clsx(
              'w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-colors',
              resending
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
            )}
          >
            {resending ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Sending...</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4" />
                <span>Resend Verification Email</span>
              </>
            )}
          </button>
        </div>

        {/* Sign out option */}
        <p className="mt-8 text-sm text-slate-500">
          Wrong email?{' '}
          <button
            onClick={handleSignOut}
            className="text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            Sign out and try again
          </button>
        </p>
      </div>
    </AuthLayout>
  )
}
