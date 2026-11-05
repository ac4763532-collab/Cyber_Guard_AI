/**
 * Shared badge/chip components and the collapsible panel wrapper used
 * throughout the Email Investigation Report.
 */
import { useState } from 'react'
import { clsx } from 'clsx'
import { ChevronDown, ChevronRight } from 'lucide-react'

export function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
    high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
    medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
    info: { bg: 'bg-slate-500/20', text: 'text-slate-400' },
  }
  const { bg, text } = config[severity?.toLowerCase()] || config.info
  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded uppercase', bg, text)}>
      {severity}
    </span>
  )
}

/**
 * Status vocabulary mapping. Each entry is a DISTINCT, honest label -
 * UNKNOWN is never used as a stand-in for FAIL, and a configured
 * integration that simply found nothing (no_iocs) gets its own label
 * instead of falling through to a generic bucket.
 *
 * Covers: DetectionStatus (detected/not_detected/unknown/not_available/
 * not_applicable), AuthStatus (pass/fail/softfail/neutral/none/
 * temperror/permerror/unknown/not_available), ThreatIntelSection.status
 * (not_configured/configured/no_iocs), and per-IOC lookup statuses
 * (clean/suspicious/malicious/unknown/error).
 */
const STATUS_CONFIG: Record<string, { bg: string; text: string; label: string }> = {
  pass: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'PASS' },
  detected: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'DETECTED' },
  fail: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'FAIL' },
  softfail: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'SOFTFAIL' },
  neutral: { bg: 'bg-slate-500/20', text: 'text-slate-400', label: 'UNKNOWN' },
  none: { bg: 'bg-slate-500/20', text: 'text-slate-400', label: 'NOT EVALUATED' },
  not_detected: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'NOT DETECTED' },
  not_applicable: { bg: 'bg-slate-600/20', text: 'text-slate-500', label: 'N/A' },
  not_available: { bg: 'bg-slate-600/20', text: 'text-slate-500', label: 'NOT AVAILABLE' },
  unknown: { bg: 'bg-slate-600/20', text: 'text-slate-500', label: 'UNKNOWN' },
  configured: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'CONFIGURED' },
  not_configured: { bg: 'bg-slate-600/20', text: 'text-slate-500', label: 'NOT CONFIGURED' },
  no_iocs: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'NO IOCS' },
  temperror: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'ERROR' },
  permerror: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'ERROR' },
  error: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'ERROR' },
  clean: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'CLEAN' },
  suspicious: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'SUSPICIOUS' },
  malicious: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'MALICIOUS' },
}

export function StatusBadge({ status }: { status: string }) {
  const statusLower = (status || 'unknown').toLowerCase()
  const { bg, text, label } = STATUS_CONFIG[statusLower] || STATUS_CONFIG.unknown

  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', bg, text)}>
      {label}
    </span>
  )
}

export function CollapsibleSection({
  title,
  icon: Icon,
  defaultOpen = false,
  status,
  children,
}: {
  title: string
  icon: any
  defaultOpen?: boolean
  status?: string
  children: React.ReactNode
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors"
        aria-expanded={isOpen}
      >
        <div className="flex items-center gap-3">
          <Icon className="w-5 h-5 text-cyan-400" />
          <span className="font-medium text-white">{title}</span>
        </div>
        <div className="flex items-center gap-3">
          {status && <StatusBadge status={status} />}
          {isOpen ? (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
        </div>
      </button>
      {isOpen && <div className="p-4 bg-slate-900/50">{children}</div>}
    </div>
  )
}
