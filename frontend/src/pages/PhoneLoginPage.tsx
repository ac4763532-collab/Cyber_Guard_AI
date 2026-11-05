/**
 * CyberGuard AI - Phone Login Page
 *
 * Phone number authentication with SMS OTP.
 */

import { useState, useEffect, useRef, FormEvent } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { AlertCircle, ArrowLeft, Phone, RefreshCw } from 'lucide-react'
import { clsx } from 'clsx'
import { RecaptchaVerifier, ConfirmationResult } from 'firebase/auth'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { OTPInput } from '@/components/auth/OTPInput'
import { useAuth } from '@/contexts/AuthContext'
import {
  isFirebaseConfigured,
  setupRecaptcha,
  signInWithPhone,
  getAuthErrorMessage,
} from '@/lib/firebase'

type Step = 'phone' | 'otp'

// Common country codes
const countryCodes = [
  { code: '+1', country: 'US/CA', flag: '🇺🇸' },
  { code: '+91', country: 'India', flag: '🇮🇳' },
  { code: '+44', country: 'UK', flag: '🇬🇧' },
  { code: '+61', country: 'Australia', flag: '🇦🇺' },
  { code: '+49', country: 'Germany', flag: '🇩🇪' },
  { code: '+33', country: 'France', flag: '🇫🇷' },
  { code: '+81', country: 'Japan', flag: '🇯🇵' },
  { code: '+86', country: 'China', flag: '🇨🇳' },
]

export function PhoneLoginPage() {
  const navigate = useNavigate()
  const { isFirebaseEnabled } = useAuth()

  const [step, setStep] = useState<Step>('phone')
  const [countryCode, setCountryCode] = useState('+91')
  const [phoneNumber, setPhoneNumber] = useState('')
  const [otp, setOtp] = useState('')
  const [error, setError] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [confirmationResult, setConfirmationResult] = useState<ConfirmationResult | null>(null)
  const [resendTimer, setResendTimer] = useState(0)

  const recaptchaRef = useRef<RecaptchaVerifier | null>(null)
  const recaptchaContainerRef = useRef<HTMLDivElement>(null)

  // Initialize reCAPTCHA
  useEffect(() => {
    if (isFirebaseConfigured() && recaptchaContainerRef.current && !recaptchaRef.current) {
      recaptchaRef.current = setupRecaptcha('recaptcha-container')
    }

    return () => {
      if (recaptchaRef.current) {
        recaptchaRef.current = null
      }
    }
  }, [])

  // Resend timer countdown
  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer((t) => t - 1), 1000)
      return () => clearTimeout(timer)
    }
  }, [resendTimer])

  // Format phone number for display
  const formatPhone = (phone: string): string => {
    const cleaned = phone.replace(/\D/g, '')
    if (cleaned.length <= 5) return cleaned
    return `${cleaned.slice(0, 5)} ${cleaned.slice(5)}`
  }

  // Validate phone number
  const isValidPhone = (phone: string): boolean => {
    const cleaned = phone.replace(/\D/g, '')
    return cleaned.length >= 10 && cleaned.length <= 15
  }

  // Handle send OTP
  const handleSendOTP = async (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (!isValidPhone(phoneNumber)) {
      setError('Please enter a valid phone number.')
      return
    }

    if (!recaptchaRef.current) {
      setError('reCAPTCHA not initialized. Please refresh the page.')
      return
    }

    setIsSubmitting(true)

    try {
      const fullNumber = `${countryCode}${phoneNumber.replace(/\D/g, '')}`
      const result = await signInWithPhone(fullNumber, recaptchaRef.current)
      setConfirmationResult(result)
      setStep('otp')
      setResendTimer(30)
    } catch (err: any) {
      const code = err.code || ''
      setError(getAuthErrorMessage(code) || 'Failed to send verification code.')

      // Reset reCAPTCHA on error
      if (recaptchaRef.current) {
        recaptchaRef.current = setupRecaptcha('recaptcha-container')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle verify OTP
  const handleVerifyOTP = async (code?: string) => {
    const verifyCode = code || otp

    if (verifyCode.length !== 6) {
      setError('Please enter the complete 6-digit code.')
      return
    }

    if (!confirmationResult) {
      setError('Session expired. Please request a new code.')
      return
    }

    setIsSubmitting(true)
    setError('')

    try {
      await confirmationResult.confirm(verifyCode)
      navigate('/')
    } catch (err: any) {
      const errorCode = err.code || ''
      setError(getAuthErrorMessage(errorCode) || 'Invalid verification code.')
    } finally {
      setIsSubmitting(false)
    }
  }

  // Handle resend OTP
  const handleResendOTP = async () => {
    if (resendTimer > 0) return

    setError('')
    setOtp('')

    // Reset reCAPTCHA
    if (recaptchaRef.current) {
      recaptchaRef.current = setupRecaptcha('recaptcha-container')
    }

    setIsSubmitting(true)

    try {
      const fullNumber = `${countryCode}${phoneNumber.replace(/\D/g, '')}`
      const result = await signInWithPhone(fullNumber, recaptchaRef.current!)
      setConfirmationResult(result)
      setResendTimer(30)
    } catch (err: any) {
      const code = err.code || ''
      setError(getAuthErrorMessage(code) || 'Failed to resend code.')
    } finally {
      setIsSubmitting(false)
    }
  }

  // If Firebase not configured
  if (!isFirebaseEnabled) {
    return (
      <AuthLayout title="Phone Login" subtitle="Sign in with your phone number">
        <div className="text-center py-8">
          <AlertCircle className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">
            Feature Unavailable
          </h3>
          <p className="text-slate-400 mb-6">
            Phone authentication requires Firebase configuration.
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

  return (
    <AuthLayout
      title={step === 'phone' ? 'Sign in with phone' : 'Verify your phone'}
      subtitle={
        step === 'phone'
          ? 'Enter your phone number to receive a verification code'
          : `Enter the 6-digit code sent to ${countryCode} ${formatPhone(phoneNumber)}`
      }
    >
      {/* Back link */}
      <Link
        to="/login"
        className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors mb-6"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>{step === 'phone' ? 'Back to login' : 'Change phone number'}</span>
      </Link>

      {/* Error message */}
      {error && (
        <div className="flex items-start gap-3 p-4 mb-6 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {step === 'phone' ? (
        // Phone number step
        <form onSubmit={handleSendOTP} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Phone number
            </label>
            <div className="flex gap-2">
              {/* Country code */}
              <select
                value={countryCode}
                onChange={(e) => setCountryCode(e.target.value)}
                className="w-24 px-2 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                {countryCodes.map((c) => (
                  <option key={c.code} value={c.code}>
                    {c.flag} {c.code}
                  </option>
                ))}
              </select>

              {/* Phone input */}
              <input
                type="tel"
                value={phoneNumber}
                onChange={(e) => {
                  setPhoneNumber(e.target.value.replace(/[^\d]/g, '').slice(0, 15))
                  setError('')
                }}
                required
                autoFocus
                placeholder="9876543210"
                className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-200"
              />
            </div>
          </div>

          {/* reCAPTCHA container */}
          <div id="recaptcha-container" ref={recaptchaContainerRef} />

          <button
            type="submit"
            disabled={isSubmitting || !isValidPhone(phoneNumber)}
            className={clsx(
              'w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200',
              isSubmitting || !isValidPhone(phoneNumber)
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30'
            )}
          >
            {isSubmitting ? (
              <>
                <div className="w-5 h-5 border-2 border-slate-500 border-t-transparent rounded-full animate-spin" />
                <span>Sending code...</span>
              </>
            ) : (
              <>
                <Phone className="w-5 h-5" />
                <span>Send Verification Code</span>
              </>
            )}
          </button>
        </form>
      ) : (
        // OTP verification step
        <div className="space-y-6">
          <OTPInput
            value={otp}
            onChange={setOtp}
            onComplete={handleVerifyOTP}
            disabled={isSubmitting}
            error={!!error}
          />

          <button
            onClick={() => handleVerifyOTP()}
            disabled={isSubmitting || otp.length !== 6}
            className={clsx(
              'w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-all duration-200',
              isSubmitting || otp.length !== 6
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30'
            )}
          >
            {isSubmitting ? (
              <>
                <div className="w-5 h-5 border-2 border-slate-500 border-t-transparent rounded-full animate-spin" />
                <span>Verifying...</span>
              </>
            ) : (
              <span>Verify Code</span>
            )}
          </button>

          {/* Resend option */}
          <div className="text-center">
            <p className="text-sm text-slate-400 mb-2">Didn't receive the code?</p>
            {resendTimer > 0 ? (
              <p className="text-sm text-slate-500">
                Resend in {resendTimer}s
              </p>
            ) : (
              <button
                onClick={handleResendOTP}
                disabled={isSubmitting}
                className="inline-flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Resend code</span>
              </button>
            )}
          </div>

          {/* Hidden reCAPTCHA for resend */}
          <div id="recaptcha-container" ref={recaptchaContainerRef} className="hidden" />
        </div>
      )}
    </AuthLayout>
  )
}
