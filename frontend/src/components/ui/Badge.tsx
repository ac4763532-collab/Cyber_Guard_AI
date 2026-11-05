/**
 * Shared severity/status badge components for CyberGuard AI.
 *
 * Moved out of LogAnalysisPage.tsx so SeverityBadge, StatusDot, and the
 * severity color map all come from one place - previously
 * SourceHealthOverview's chart kept its own separate SEVERITY_COLORS map,
 * which could silently drift from this badge's colors. Both now read the
 * same SEVERITY_COLORS table below.
 */

import { clsx } from 'clsx'

// Canonical severity -> color mapping. Hex values here are used directly
// by chart code (e.g. recharts <Cell fill=.../>, which needs a real color
// value, not a Tailwind class name). Tailwind class names for the badge
// pill are derived from the same key set in SEVERITY_BADGE_CLASSES below -
// keep both tables in sync when adding a new severity level.
export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  error: '#fb923c',
  medium: '#facc15',
  warning: '#facc15',
  low: '#38bdf8',
  notice: '#38bdf8',
  info: '#64748b',
  debug: '#475569',
}

const SEVERITY_BADGE_CLASSES: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  error: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  warning: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  notice: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  info: { bg: 'bg-slate-500/20', text: 'text-slate-400' },
  debug: { bg: 'bg-slate-500/20', text: 'text-slate-400' },
}

/** Exposed so other severity-colored UI (e.g. AlertPopup) can reuse the
 * exact same bg/text pair as this badge instead of re-deriving its own
 * map - see this file's top-of-file note on why both tables must stay
 * in sync; a second copy of this one would reintroduce that problem. */
export function getSeverityBadgeClasses(severity: string): { bg: string; text: string } {
  const key = severity?.toLowerCase() || 'info'
  return SEVERITY_BADGE_CLASSES[key] || SEVERITY_BADGE_CLASSES.info
}

export function SeverityBadge({ severity }: { severity: string }) {
  const { bg, text } = getSeverityBadgeClasses(severity)
  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded-md', bg, text)}>
      {severity.toUpperCase()}
    </span>
  )
}

// Real backend LogSourceStatus values (app/logs/models.py) - active, paused,
// error, disabled, pending. "connected"/"disconnected"/"inactive" are kept
// here only because older rows or other callers may still produce them;
// callers that build a status <select> should only offer the real enum
// values.
const STATUS_DOT_CLASSES: Record<string, { color: string; label: string }> = {
  active: { color: 'bg-emerald-400', label: 'Active' },
  connected: { color: 'bg-emerald-400', label: 'Connected' },
  paused: { color: 'bg-yellow-400', label: 'Paused' },
  pending: { color: 'bg-yellow-400', label: 'Pending' },
  error: { color: 'bg-red-400', label: 'Error' },
  disconnected: { color: 'bg-red-400', label: 'Disconnected' },
  disabled: { color: 'bg-slate-500', label: 'Disabled' },
  inactive: { color: 'bg-slate-500', label: 'Inactive' },
  // Live CollectorSupervisorStatus.state values (SourceCard in
  // LogAnalysisPage.tsx maps these in ahead of the DB-persisted status
  // when a live supervisor is running) - reconnecting is deliberately its
  // own amber state, distinct from the red "error" dot, since a collector
  // actively retrying its connection isn't the same as one that's failed.
  starting: { color: 'bg-yellow-400', label: 'Starting' },
  reconnecting: { color: 'bg-amber-400', label: 'Reconnecting' },
  stopping: { color: 'bg-slate-500', label: 'Stopping' },
  stopped: { color: 'bg-slate-500', label: 'Stopped' },
}

export function StatusDot({ status }: { status: string }) {
  const { color, label } = STATUS_DOT_CLASSES[status?.toLowerCase()] || {
    color: 'bg-slate-500',
    label: status || 'Unknown',
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={clsx('w-2 h-2 rounded-full', color)} />
      <span className="text-slate-300">{label}</span>
    </span>
  )
}
