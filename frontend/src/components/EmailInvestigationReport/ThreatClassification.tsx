/**
 * Threat classification panel.
 *
 * There is no sub-category taxonomy anywhere in the backend - only a
 * flat 5-value Verdict enum. So this panel does NOT invent ML-supported
 * categories. It shows the overall verdict label (reusing the header's
 * mapping) plus a small fixed table of named threat patterns, each
 * marked evaluated-true only when real matching evidence exists in
 * THIS report. Everything else is explicitly "NOT EVALUATED - no
 * detector configured for this category," never silently omitted or
 * mislabeled as ruled-out.
 *
 * Collapsed by default to keep the report compact.
 */
import { useState } from 'react'
import { ChevronDown, ChevronRight, Tags } from 'lucide-react'
import { clsx } from 'clsx'
import type { FindingDetail, InvestigationReport } from './types'
import { getVerdictLabel } from './shared/riskHelpers'

interface CategoryCheck {
  group: string
  name: string
  evaluated: boolean
  evidence?: string
}

function evaluateCategories(report: InvestigationReport): CategoryCheck[] {
  const findings: FindingDetail[] = report.all_findings || []
  const titles = findings.map((f) => f.title?.toLowerCase() || '')

  const credentialPhishing =
    report.content?.credential_request_detected ||
    titles.some((t) => t.includes('credential'))
  const becSignals =
    report.sender?.reply_to_mismatch ||
    report.sender?.return_path_mismatch ||
    titles.some((t) => t.includes('reply-to') || t.includes('return-path') || t.includes('impersonat'))
  const maliciousAttachment =
    report.attachments?.dangerous_attachments > 0 ||
    titles.some((t) => t.includes('macro') || t.includes('dangerous extension'))
  const maliciousUrl =
    report.urls?.suspicious_urls > 0 || titles.some((t) => t.includes('url') || t.includes('shortener'))

  return [
    {
      group: 'Identity Deception & Fraud',
      name: 'Business Email Compromise (BEC) signals',
      evaluated: becSignals,
      evidence: becSignals ? 'Reply-To/Return-Path mismatch or impersonation finding present' : undefined,
    },
    {
      group: 'Information & Credential Theft',
      name: 'Credential phishing',
      evaluated: credentialPhishing,
      evidence: credentialPhishing ? 'Credential-request language or finding detected in body' : undefined,
    },
    {
      group: 'Technical Delivery',
      name: 'Malicious or suspicious URL delivery',
      evaluated: maliciousUrl,
      evidence: maliciousUrl ? `${report.urls?.suspicious_urls || 0} suspicious URL(s) flagged` : undefined,
    },
    {
      group: 'Technical Delivery',
      name: 'Malicious attachment delivery',
      evaluated: maliciousAttachment,
      evidence: maliciousAttachment ? 'Dangerous extension, macro, or double-extension finding present' : undefined,
    },
  ]
}

export function ThreatClassification({ report }: { report: InvestigationReport }) {
  const [isOpen, setIsOpen] = useState(false)
  const categories = evaluateCategories(report)
  const verdictLabel = getVerdictLabel(report.verdict.classification)

  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-800/50 hover:bg-slate-800 transition-colors"
        aria-expanded={isOpen}
      >
        <div className="flex items-center gap-3">
          <Tags className="w-5 h-5 text-cyan-400" />
          <span className="font-medium text-white">Threat Classification</span>
          <span className="text-xs text-slate-400">({verdictLabel})</span>
        </div>
        {isOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
      </button>

      {isOpen && (
        <div className="p-4 bg-slate-900/50">
          <p className="text-xs text-slate-500 mb-3">
            There is no machine-learning sub-category classifier in this system. The rows below reflect whether
            specific rule-based signals were found in THIS email - rows without matching evidence are marked NOT
            EVALUATED, not ruled out.
          </p>
          <div className="space-y-2">
            {categories.map((cat) => (
              <div
                key={cat.name}
                className={clsx(
                  'flex items-center justify-between p-2.5 rounded-lg',
                  cat.evaluated ? 'bg-orange-500/10 border border-orange-500/20' : 'bg-slate-800'
                )}
              >
                <div>
                  <p className="text-xs text-slate-500">{cat.group}</p>
                  <p className="text-sm text-white">{cat.name}</p>
                  {cat.evidence && <p className="text-xs text-slate-400 mt-0.5">{cat.evidence}</p>}
                </div>
                <span
                  className={clsx(
                    'text-xs font-medium px-2 py-0.5 rounded whitespace-nowrap',
                    cat.evaluated ? 'bg-orange-500/20 text-orange-400' : 'bg-slate-700 text-slate-500'
                  )}
                >
                  {cat.evaluated ? 'EVIDENCE FOUND' : 'NOT EVALUATED'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
