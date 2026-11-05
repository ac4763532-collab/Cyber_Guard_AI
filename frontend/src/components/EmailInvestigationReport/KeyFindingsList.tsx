/**
 * Key findings list - top 3 remaining findings (skipping index 0, since
 * PrimaryFindingCard already shows that one in full), with a "View all"
 * expand control for the rest. Avoids duplicating the same finding
 * across the primary card and this list.
 *
 * Evidence/technical detail for each finding is hidden by default and
 * only shown once a user expands that specific row - the row itself
 * always shows severity, title, one-line description, and risk
 * contribution.
 */
import { useState } from 'react'
import { clsx } from 'clsx'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { FindingDetail, InvestigationReport } from './types'
import { SeverityBadge } from './shared/badges'

const SEVERITY_BORDER_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
}

function FindingRow({ finding }: { finding: FindingDetail }) {
  const [expanded, setExpanded] = useState(false)
  const hasEvidence = finding.evidence?.length > 0

  return (
    <div
      className="p-2.5 bg-slate-800 rounded-lg border-l-4"
      style={{ borderLeftColor: SEVERITY_BORDER_COLOR[finding.severity?.toLowerCase()] || '#64748b' }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <SeverityBadge severity={finding.severity} />
            <span className="text-white font-medium text-sm">{finding.title}</span>
          </div>
          <p className="text-xs text-slate-400">{finding.description}</p>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {finding.risk_contribution > 0 && (
            <span className="text-xs text-slate-500 whitespace-nowrap">+{finding.risk_contribution}</span>
          )}
          {hasEvidence && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-1 text-slate-500 hover:text-white"
              aria-label={expanded ? 'Collapse evidence' : 'Expand evidence'}
              aria-expanded={expanded}
            >
              {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {expanded && hasEvidence && (
        <div className="mt-2 space-y-1">
          {finding.evidence.map((ev, i) => (
            <p key={i} className="text-xs text-slate-500 font-mono bg-slate-900 px-2 py-1 rounded break-all">
              {ev}
            </p>
          ))}
        </div>
      )}
    </div>
  )
}

export function KeyFindingsList({ report }: { report: InvestigationReport }) {
  const [expanded, setExpanded] = useState(false)

  const all = report.all_findings?.length ? report.all_findings : report.key_findings || []
  // Skip index 0 - already shown in full by PrimaryFindingCard.
  const rest = all.slice(1)
  if (rest.length === 0) return null

  const visible = expanded ? rest : rest.slice(0, 3)

  return (
    <div>
      <h3 className="text-sm font-medium text-slate-400 mb-2">
        {expanded ? `All Findings (${all.length})` : 'Key Findings'}
      </h3>
      <div className="space-y-1.5">
        {visible.map((finding) => (
          <FindingRow key={finding.finding_id} finding={finding} />
        ))}
      </div>

      {rest.length > 3 && (
        <button
          onClick={() => setExpanded(!expanded)}
          className={clsx('mt-2 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors')}
        >
          {expanded ? 'Show fewer findings' : `View all ${all.length} findings`}
        </button>
      )}
    </div>
  )
}
