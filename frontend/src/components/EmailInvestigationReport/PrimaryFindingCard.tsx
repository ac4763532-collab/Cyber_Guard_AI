/**
 * Primary finding card - the single most severe finding, shown in full
 * detail up front instead of buried in a list.
 *
 * all_findings is already severity-sorted server-side (critical=0 ...
 * info=4), so all_findings[0] is the primary finding. Falls back to
 * key_findings[0] if all_findings is empty, and renders nothing if both
 * are empty (never fabricates a "finding" to fill the slot).
 *
 * Severity, title, one-line description, risk contribution, why-it-
 * matters, and the signal-not-proof caveat are always visible (this is
 * the short explanation the compact spec asks for). Raw evidence is
 * collapsed behind a toggle.
 */
import { useState } from 'react'
import { AlertCircle, ChevronDown, ChevronRight } from 'lucide-react'
import type { FindingDetail, InvestigationReport } from './types'
import { SeverityBadge } from './shared/badges'

/**
 * Findings that are signals, not proof, get an explicit caveat line so
 * the UI never implies a heuristic match is confirmed malicious intent.
 */
function getCaveat(finding: FindingDetail): string | null {
  const title = finding.title?.toLowerCase() || ''
  if (title.includes('return-path') || title.includes('reply-to')) {
    return 'This is a signal, not proof of phishing - legitimate bulk-mail and marketing platforms also commonly use a different Return-Path or Reply-To domain than the From address.'
  }
  if (title.includes('lookalike') || title.includes('suspicious tld')) {
    return 'Domain-pattern signals can also appear on legitimate smaller or newer domains - treat as one input among several, not a standalone verdict.'
  }
  if (title.includes('shortener')) {
    return 'URL shorteners are also used for entirely legitimate purposes (marketing, social media) - presence alone does not confirm malicious intent.'
  }
  return null
}

export function PrimaryFindingCard({ report }: { report: InvestigationReport }) {
  const [expanded, setExpanded] = useState(false)
  const finding = report.all_findings?.[0] || report.key_findings?.[0]
  if (!finding) return null

  const caveat = getCaveat(finding)
  const hasEvidence = finding.evidence?.length > 0

  return (
    <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
      <div className="flex items-center gap-2 mb-1.5">
        <AlertCircle className="w-4 h-4 text-cyan-400" />
        <span className="text-sm font-medium text-slate-300">Primary Finding</span>
      </div>

      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 mb-1">
          <SeverityBadge severity={finding.severity} />
          <span className="text-white font-medium">{finding.title}</span>
        </div>
        {finding.risk_contribution > 0 && (
          <span className="text-xs text-slate-500 whitespace-nowrap">
            +{finding.risk_contribution} to risk score
          </span>
        )}
      </div>

      <p className="text-sm text-slate-400 mt-1">{finding.description}</p>

      {finding.why_it_matters && (
        <p className="text-xs text-slate-400 mt-1.5">
          <span className="text-slate-500">Why it matters: </span>
          {finding.why_it_matters}
        </p>
      )}

      {caveat && <p className="text-xs text-slate-500 mt-1.5 italic">{caveat}</p>}

      {hasEvidence && (
        <div className="mt-2 pt-2 border-t border-slate-700">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
            aria-expanded={expanded}
          >
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            {expanded ? 'Hide evidence' : 'Show evidence'}
          </button>

          {expanded && (
            <div className="mt-2 space-y-1">
              {finding.evidence.map((ev, i) => (
                <p key={i} className="text-xs text-slate-300 font-mono bg-slate-900 px-2 py-1 rounded break-all">
                  {ev}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
