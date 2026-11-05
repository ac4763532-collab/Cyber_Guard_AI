/**
 * CyberGuard AI - Real-time alert notification context
 *
 * Wires together:
 * - useAlertSocket: authenticated, tenant-scoped delivery of persisted
 *   alerts, with reconnect + missed-alert recovery + dedup by
 *   stable alert id (never a frontend-generated id).
 * - useNotificationPreferences: per-severity sound on/off, volume, mute.
 * - lib/alertSound: Web Audio synthesis, autoplay-restriction-aware.
 *
 * and exposes a small popup queue so AlertPopup can render one alert at
 * a time (acknowledge/dismiss on the current one before the next shows),
 * without ever blocking the rest of the UI - this provider renders no
 * blocking overlay itself, only state; AlertPopup (mounted once near the
 * root, like ToastProvider's own toasts) does the actual rendering.
 *
 * Scope note: dismissing a popup here only removes it from this queue.
 * It is explicitly NOT a call to PATCH /alerts/{id} - acknowledging an
 * alert (which the popup also offers as a distinct action) is the only
 * thing that updates the alert's real status. See the spec's requirement
 * #9: "a popup dismissal must NOT delete the alert or suppress future
 * distinct alerts."
 */

import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  ReactNode,
} from 'react'
import { useAlertSocket, type RealtimeAlert } from '@/hooks/useAlertSocket'
import {
  useNotificationPreferences,
  type NotificationPreferences,
} from '@/hooks/useNotificationPreferences'
import { getAlertSoundEngine, type AlertSoundSeverity } from '@/lib/alertSound'
import { normalizeSeverity } from '@/lib/severity'

export interface QueuedAlert extends RealtimeAlert {
  /** True once ensureRunning() reported the browser is blocking audio
   * for this alert - AlertPopup shows a "click to enable sound"
   * indicator when this is set, rather than silently staying silent. */
  soundBlockedByAutoplay: boolean
}

interface AlertNotificationContextType {
  /** The alert currently shown in the popup, or null if the queue is
   * empty. Only one popup is ever shown at a time. */
  currentAlert: QueuedAlert | null
  queueLength: number
  dismissCurrent: () => void
  preferences: NotificationPreferences
  updatePreferences: (partial: Partial<NotificationPreferences>) => void
  updateSeveritySound: (severity: 'critical' | 'high' | 'medium', enabled: boolean) => void
  /** Replays the current popup's sound - used by the "enable sound"
   * affordance after a real user click/keypress, which is the only thing
   * that can actually unblock the AudioContext. */
  retrySound: () => void
  testSound: (severity: AlertSoundSeverity) => void
}

const AlertNotificationContext = createContext<AlertNotificationContextType | null>(null)

export function useAlertNotifications(): AlertNotificationContextType {
  const context = useContext(AlertNotificationContext)
  if (!context) {
    throw new Error('useAlertNotifications must be used within AlertNotificationProvider')
  }
  return context
}

const SOUND_SEVERITIES = new Set(['critical', 'high', 'medium'])

export function AlertNotificationProvider({ children }: { children: ReactNode }) {
  const { preferences, update, updateSeveritySound, shouldPlaySound } = useNotificationPreferences()
  const [queue, setQueue] = useState<QueuedAlert[]>([])
  const preferencesRef = useRef(preferences)
  preferencesRef.current = preferences

  const playSoundFor = useCallback(
    async (severity: string): Promise<boolean> => {
      const normalized = normalizeSeverity(severity)
      if (!SOUND_SEVERITIES.has(normalized)) {
        // low / info - silent by default, not a sound engine call at all.
        return false
      }
      if (!shouldPlaySound(normalized)) {
        return false
      }
      const result = await getAlertSoundEngine().play(
        normalized as AlertSoundSeverity,
        preferencesRef.current.volume
      )
      return result.blockedByAutoplay
    },
    [shouldPlaySound]
  )

  const handleIncomingAlert = useCallback(
    (alert: RealtimeAlert) => {
      // Fire-and-track: we don't want to delay enqueuing the popup on
      // the sound attempt resolving, since the popup itself must show
      // "for every new eligible alert by default" (spec #4) regardless
      // of whether sound is blocked.
      void playSoundFor(alert.severity).then((blocked) => {
        if (blocked) {
          setQueue((prev) =>
            prev.map((a) => (a.alertId === alert.alertId ? { ...a, soundBlockedByAutoplay: true } : a))
          )
        }
      })

      setQueue((prev) => [...prev, { ...alert, soundBlockedByAutoplay: false }])
    },
    [playSoundFor]
  )

  useAlertSocket(handleIncomingAlert)

  const currentAlert = queue[0] ?? null

  const dismissCurrent = useCallback(() => {
    // Stop any repeating critical siren tied to the alert being
    // dismissed - dismissing the popup must silence it (the user has
    // acknowledged seeing it, even if they didn't click "Acknowledge");
    // it must NOT touch the alert's persisted status (requirement #9).
    getAlertSoundEngine().stopSiren()
    setQueue((prev) => prev.slice(1))
  }, [])

  const retrySound = useCallback(() => {
    if (!currentAlert) return
    void playSoundFor(currentAlert.severity).then((blocked) => {
      setQueue((prev) =>
        prev.map((a) =>
          a.alertId === currentAlert.alertId ? { ...a, soundBlockedByAutoplay: blocked } : a
        )
      )
    })
  }, [currentAlert, playSoundFor])

  const testSound = useCallback((severity: AlertSoundSeverity) => {
    void getAlertSoundEngine().test(severity, preferencesRef.current.volume)
  }, [])

  const value: AlertNotificationContextType = {
    currentAlert,
    queueLength: queue.length,
    dismissCurrent,
    preferences,
    updatePreferences: update,
    updateSeveritySound,
    retrySound,
    testSound,
  }

  return (
    <AlertNotificationContext.Provider value={value}>
      {children}
    </AlertNotificationContext.Provider>
  )
}
