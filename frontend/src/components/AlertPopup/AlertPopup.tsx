/**
 * CyberGuard AI - Real-time alert popup
 *
 * Non-blocking, accessible popup shown for every new eligible persisted
 * alert (spec #3/#4/#11). Mounted once near the app root (see main.tsx),
 * driven entirely by AlertNotificationContext's queue - this component
 * has no knowledge of WebSockets, sound synthesis, or dedup; it only
 * renders whatever `currentAlert` is and calls the actions it's given.
 *
 * Accessibility / non-blocking requirements (spec #11):
 * - role="alertdialog" + aria-live="assertive" so screen readers announce
 *   it immediately without the page needing focus to move there.
 * - aria-modal="false" and no focus trap / backdrop click-capture: the
 *   rest of the UI stays fully usable while this is showing, and Escape
 *   or clicking elsewhere never gets blocked by this popup.
 * - All actions are real buttons, reachable by Tab, with visible focus
 *   rings (inherited from the existing design system's own button
 *   classes used elsewhere in this codebase, e.g. AlertsPage.tsx).
 */

import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Bell, Check, ExternalLink, VolumeX, X } from 'lucide-react'
import { clsx } from 'clsx'
import { useAlertNotifications } from '@/contexts/AlertNotificationContext'
import { getSeverityBadgeClasses } from '@/components/ui'
import { normalizeSeverity } from '@/lib/severity'
import { alertsApi } from '@/services/api'

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
}

export function AlertPopup() {
  const { currentAlert, queueLength, dismissCurrent, retrySound } = useAlertNotifications()
  const navigate = useNavigate()

  if (!currentAlert) return null

  const severity = normalizeSeverity(currentAlert.severity)
  const { bg, text } = getSeverityBadgeClasses(severity)
  const timestamp = currentAlert.createdAt ? new Date(currentAlert.createdAt) : null

  const handleOpen = () => {
    navigate('/alerts', { state: { openAlertId: currentAlert.alertId } })
    dismissCurrent()
  }

  const handleAcknowledge = async () => {
    // Acknowledge is the one action here that actually mutates the real
    // alert - distinct from "dismiss", which only clears this popup (see
    // AlertNotificationContext's docstring / spec #9).
    try {
      await alertsApi.update(currentAlert.alertId, { status: 'acknowledged' })
    } catch {
      // Best-effort: even if the PATCH fails (e.g. transient network
      // issue), the popup still dismisses - the user explicitly asked
      // to close it, and they can re-acknowledge from the Alerts page
      // if the status didn't actually change.
    }
    dismissCurrent()
  }

  return (
    <div
      role="alertdialog"
      aria-live="assertive"
      aria-modal="false"
      aria-labelledby="alert-popup-title"
      className="fixed top-4 right-4 z-[100] w-full max-w-sm pointer-events-none"
    >
      <div
        className={clsx(
          'pointer-events-auto rounded-xl border shadow-2xl bg-slate-900 overflow-hidden',
          'animate-in slide-in-from-top-2 fade-in duration-200',
          severity === 'critical' ? 'border-red-500/50' : 'border-slate-700'
        )}
      >
        <div className={clsx('flex items-start gap-3 px-4 py-3 border-b border-slate-800', bg)}>
          <AlertTriangle className={clsx('w-5 h-5 mt-0.5 shrink-0', text)} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={clsx('px-2 py-0.5 text-xs font-semibold rounded', bg, text)}>
                {SEVERITY_LABELS[severity] || currentAlert.severity}
              </span>
              {currentAlert.category && (
                <span className="text-xs text-slate-400">{currentAlert.category.replace('_', ' ')}</span>
              )}
            </div>
          </div>
          <button
            onClick={dismissCurrent}
            aria-label="Dismiss notification"
            className="text-slate-400 hover:text-white shrink-0 focus:outline-none focus:ring-2 focus:ring-cyan-500 rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-4 py-3 space-y-2">
          <h2 id="alert-popup-title" className="text-sm font-semibold text-white leading-snug">
            {currentAlert.title || 'New alert'}
          </h2>
          {currentAlert.summary && (
            <p className="text-xs text-slate-400 line-clamp-3">{currentAlert.summary}</p>
          )}
          {timestamp && (
            <p className="text-xs text-slate-500">{timestamp.toLocaleString()}</p>
          )}
          {currentAlert.soundBlockedByAutoplay && (
            <button
              onClick={retrySound}
              className="flex items-center gap-1.5 text-xs text-amber-400 hover:text-amber-300 focus:outline-none focus:ring-2 focus:ring-amber-500 rounded"
            >
              <VolumeX className="w-3.5 h-3.5" />
              Sound blocked by browser - click to enable
            </button>
          )}
          {queueLength > 1 && (
            <p className="text-xs text-slate-500 flex items-center gap-1">
              <Bell className="w-3 h-3" />
              {queueLength - 1} more waiting
            </p>
          )}
        </div>

        <div className="px-4 py-3 border-t border-slate-800 flex items-center gap-2">
          <button
            onClick={handleOpen}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-400"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            Open Alert
          </button>
          <button
            onClick={handleAcknowledge}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <Check className="w-3.5 h-3.5" />
            Acknowledge
          </button>
          <button
            onClick={dismissCurrent}
            className="ml-auto px-3 py-1.5 text-slate-400 hover:text-slate-200 text-xs font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  )
}
