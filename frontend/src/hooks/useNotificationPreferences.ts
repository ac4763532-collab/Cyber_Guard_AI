/**
 * CyberGuard AI - Notification preferences
 *
 * User-configurable popup/sound behavior for real-time alerts (spec
 * requirement #5: per-severity sound enable/disable, volume, mute).
 * Stored in localStorage - deliberately NOT sessionStorage, since these
 * are preferences ("how loud do I want sirens") that should persist
 * across browser restarts, unlike useAlertSocket's seen-alert dedup
 * (which is intentionally per-session).
 */

import { useCallback, useEffect, useState } from 'react'

export interface NotificationPreferences {
  /** Master switch - when false, no sound plays for any severity
   * regardless of the per-severity toggles below (popups still show). */
  soundEnabled: boolean
  /** 0-1 */
  volume: number
  /** Per-severity sound toggle. Defaults match the spec: critical/high
   * on, medium off (optional per spec), low/info have no entry here at
   * all - they are silent by policy, not by a disable-able preference. */
  severitySoundEnabled: {
    critical: boolean
    high: boolean
    medium: boolean
  }
  /** Global mute - distinct from soundEnabled so the UI can offer both
   * a persistent "I don't want sound at all" setting and a quick mute
   * toggle without losing the user's severity-level configuration. */
  muted: boolean
}

export const DEFAULT_PREFERENCES: NotificationPreferences = {
  soundEnabled: true,
  volume: 0.6,
  severitySoundEnabled: {
    critical: true,
    high: true,
    medium: false,
  },
  muted: false,
}

const STORAGE_KEY = 'cyberguard.notificationPreferences'

function loadPreferences(): NotificationPreferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_PREFERENCES
    const parsed = JSON.parse(raw)
    // Shallow-merge over defaults so a preferences shape added in a later
    // release (a new key) doesn't crash on an older stored value, and an
    // old stored value missing a newer key still gets a sane default.
    return {
      ...DEFAULT_PREFERENCES,
      ...parsed,
      severitySoundEnabled: {
        ...DEFAULT_PREFERENCES.severitySoundEnabled,
        ...(parsed?.severitySoundEnabled || {}),
      },
    }
  } catch {
    return DEFAULT_PREFERENCES
  }
}

function savePreferences(prefs: NotificationPreferences): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // Private-mode/storage-full edge case - preferences just won't
    // persist across reloads; the in-memory state for this tab is
    // unaffected.
  }
}

export function useNotificationPreferences() {
  const [preferences, setPreferences] = useState<NotificationPreferences>(loadPreferences)

  useEffect(() => {
    savePreferences(preferences)
  }, [preferences])

  const update = useCallback((partial: Partial<NotificationPreferences>) => {
    setPreferences((prev) => ({ ...prev, ...partial }))
  }, [])

  const updateSeveritySound = useCallback(
    (severity: 'critical' | 'high' | 'medium', enabled: boolean) => {
      setPreferences((prev) => ({
        ...prev,
        severitySoundEnabled: { ...prev.severitySoundEnabled, [severity]: enabled },
      }))
    },
    []
  )

  /** Resolves whether a sound should actually play for a given severity,
   * folding in the master switch and mute - the single source of truth
   * AlertNotificationContext should consult rather than re-deriving this
   * logic itself. */
  const shouldPlaySound = useCallback(
    (severity: string): boolean => {
      if (preferences.muted || !preferences.soundEnabled) return false
      if (severity === 'critical') return preferences.severitySoundEnabled.critical
      if (severity === 'high') return preferences.severitySoundEnabled.high
      if (severity === 'medium') return preferences.severitySoundEnabled.medium
      // low / info - silent by default, not configurable (per spec #5).
      return false
    },
    [preferences]
  )

  return { preferences, update, updateSeveritySound, shouldPlaySound }
}
