/**
 * CyberGuard AI - Notification settings panel
 *
 * Spec requirement #5: sound enable/disable, volume, test-sound, and
 * mute controls, with per-severity sound toggles. Mounted as a tab in
 * SettingsPage - reads/writes through AlertNotificationContext so this
 * panel and the live popup always agree on the current preferences
 * (no separate copy of preference state).
 */

import { Volume2, VolumeX } from 'lucide-react'
import { clsx } from 'clsx'
import { useAlertNotifications } from '@/contexts/AlertNotificationContext'
import type { AlertSoundSeverity } from '@/lib/alertSound'

const SEVERITY_ROWS: { key: AlertSoundSeverity; label: string; description: string }[] = [
  {
    key: 'critical',
    label: 'Critical',
    description: 'Repeating siren until acknowledged or dismissed.',
  },
  {
    key: 'high',
    label: 'High',
    description: 'A short alert tone.',
  },
  {
    key: 'medium',
    label: 'Medium',
    description: 'Optional short tone (off by default).',
  },
]

export function NotificationSettings() {
  const { preferences, updatePreferences, updateSeveritySound, testSound } = useAlertNotifications()

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-6 py-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white">Alert Notifications</h2>
          <p className="text-sm text-slate-500 mt-1">
            Popups show for every new alert. Sound behavior is configurable per severity.
          </p>
        </div>

        <div className="p-6 space-y-6">
          {/* Master mute + enable */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {preferences.muted || !preferences.soundEnabled ? (
                <VolumeX className="w-5 h-5 text-slate-500" />
              ) : (
                <Volume2 className="w-5 h-5 text-cyan-400" />
              )}
              <div>
                <p className="text-white font-medium">Sound notifications</p>
                <p className="text-sm text-slate-500">Master switch for all alert sounds</p>
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={preferences.soundEnabled}
                onChange={(e) => updatePreferences({ soundEnabled: e.target.checked })}
                className="sr-only peer"
                aria-label="Enable sound notifications"
              />
              <div className="w-11 h-6 bg-slate-700 peer-checked:bg-cyan-600 rounded-full transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-cyan-400" />
              <div className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
            </label>
          </div>

          {/* Mute */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Mute</p>
              <p className="text-sm text-slate-500">Quickly silence all sounds without changing your settings</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={preferences.muted}
                onChange={(e) => updatePreferences({ muted: e.target.checked })}
                className="sr-only peer"
                aria-label="Mute all alert sounds"
              />
              <div className="w-11 h-6 bg-slate-700 peer-checked:bg-cyan-600 rounded-full transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-cyan-400" />
              <div className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
            </label>
          </div>

          {/* Volume */}
          <div>
            <label htmlFor="alert-volume" className="block text-white font-medium mb-2">
              Volume
            </label>
            <input
              id="alert-volume"
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={preferences.volume}
              onChange={(e) => updatePreferences({ volume: Number(e.target.value) })}
              className="w-full accent-cyan-500"
            />
          </div>

          {/* Per-severity controls */}
          <div className="border-t border-slate-800 pt-4 space-y-4">
            <h3 className="text-sm font-medium text-slate-300">Per-severity sound</h3>
            {SEVERITY_ROWS.map(({ key, label, description }) => (
              <div key={key} className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-white text-sm font-medium">{label}</p>
                  <p className="text-xs text-slate-500">{description}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <button
                    onClick={() => testSound(key)}
                    className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    Test
                  </button>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={preferences.severitySoundEnabled[key]}
                      onChange={(e) => updateSeveritySound(key, e.target.checked)}
                      className="sr-only peer"
                      aria-label={`Enable sound for ${label} severity alerts`}
                    />
                    <div
                      className={clsx(
                        'w-11 h-6 bg-slate-700 peer-checked:bg-cyan-600 rounded-full transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-cyan-400'
                      )}
                    />
                    <div className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-5" />
                  </label>
                </div>
              </div>
            ))}
            <p className="text-xs text-slate-500">
              Low / Informational alerts are always silent and are not configurable here - they still
              show a popup.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
