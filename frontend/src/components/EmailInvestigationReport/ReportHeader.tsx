/**
 * Compact report header: verdict badge, risk chip, report ID + copy,
 * export - all on one row, with a smaller line below for timestamp and
 * a gated primary threat category. Replaces the old large centered
 * title block that duplicated the page's own header and pushed content
 * below the fold.
 */
import { clsx } from 'clsx'
import type { InvestigationReport } from './types'
import { getVerdictLabel, getClassificationIcon, getClassificationBgClass } from './shared/riskHelpers'
import { CopyButton } from './FeedbackExportBar'
import { ExportReportButton } from './FeedbackExportBar'

/**
 * Primary category is only shown when the classification itself is
 * malicious/phishing AND there's a real matching finding backing it -
 * never invents a category the backend's own heuristic didn't commit to.
 */
function getPrimaryCategory(report: InvestigationReport): string | null {
  const classification = (report.verdict.classification || '').toLowerCase()
  if (classification !== 'phishing' && classification !== 'malicious') return null

  const findings = report.all_findings || []
  const hasCredentialSignal =
    report.content?.credential_request_detected ||
    findings.some((f) => /credential/i.test(f.title))
  const hasImpersonationSignal =
    report.content?.brand_impersonation_detected ||
    findings.some((f) => /impersonat|lookalike|spoof/i.test(f.title))

  if (hasCredentialSignal) return 'Credential Phishing'
  if (hasImpersonationSignal) return 'Brand Impersonation'
  return null
}

export function ReportHeader({ report }: { report: InvestigationReport }) {
  const { verdict } = report
  const verdictLabel = getVerdictLabel(verdict.classification)
  const primaryCategory = getPrimaryCategory(report)
  const timestamp = report.investigation_timestamp
    ? new Date(report.investigation_timestamp).toLocaleString()
    : 'Unknown time'

  return (
    <div
      className={clsx(
        'p-3 rounded-xl border bg-gradient-to-r',
        getClassificationBgClass(verdict.classification)
      )}
    >
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          {getClassificationIcon(verdict.classification)}
          <span className="text-lg font-bold text-white uppercase tracking-wide">
            {verdictLabel}
          </span>
          {primaryCategory && (
            <span className="px-2 py-0.5 bg-white/10 rounded text-xs text-slate-300">
              {primaryCategory}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>ID: {report.report_id}</span>
            <CopyButton text={report.report_id} />
          </div>
          <ExportReportButton report={report} />
        </div>
      </div>

      <p className="text-xs text-slate-400 mt-1">{timestamp}</p>
    </div>
  )
}
