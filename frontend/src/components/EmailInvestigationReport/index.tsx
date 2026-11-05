/**
 * CyberGuard AI - Email Investigation Report
 *
 * Professional SOC-style email security investigation report, built
 * entirely from real backend fields. Compact top summary (verdict,
 * risk/confidence, primary finding, identity, export/feedback) followed
 * by a single "Investigation Details" block holding every detailed
 * section in a fixed order, so Key Findings and URL Analysis are easy
 * to locate instead of buried among unrelated panels:
 *
 *  1. Key Findings        5. Sender Intelligence   9. Header Forensics
 *  2. URL Analysis        6. Email Authentication  10. Threat Intelligence
 *  3. Recommended Actions 7. Content Analysis      11. IOC Inventory
 *  4. Security Checks     8. Attachment Analysis   12. Risk Score Breakdown
 *                                                   13. Raw Evidence/Technical Details
 *
 * ThreatClassification is intentionally not rendered here - it's a
 * heuristic category table built client-side from finding titles, not
 * backend-sourced data, and isn't one of the required sections.
 */
import { ReportHeader } from './ReportHeader'
import { RiskConfidenceCards } from './RiskConfidenceCards'
import { PrimaryFindingCard } from './PrimaryFindingCard'
import { IdentitySummary } from './IdentitySummary'
import { KeyFindingsList } from './KeyFindingsList'
import { UrlAnalysisSection } from './UrlAnalysisSection'
import { RecommendedActions } from './RecommendedActions'
import { SecurityChecksGrid } from './SecurityChecksGrid'
import { FeedbackExportBar } from './FeedbackExportBar'
import { EvidencePanels } from './EvidencePanels'
import type { InvestigationReport } from './types'

export type { InvestigationReport } from './types'

interface EmailInvestigationReportProps {
  report: InvestigationReport
}

export function EmailInvestigationReport({ report }: EmailInvestigationReportProps) {
  if (!report) return null

  return (
    <div className="space-y-3">
      {/* Top summary: verdict, risk/confidence, primary finding, identity */}
      <ReportHeader report={report} />
      <RiskConfidenceCards report={report} />
      <PrimaryFindingCard report={report} />
      <IdentitySummary report={report} />
      <FeedbackExportBar report={report} />

      {/* Investigation Details: fixed order, 1-13 */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-2 pt-1 border-t border-slate-700">
          Investigation Details
        </h2>
        <div className="space-y-3">
          <KeyFindingsList report={report} />
          <UrlAnalysisSection report={report} />
          <RecommendedActions report={report} />
          <SecurityChecksGrid report={report} />
          <EvidencePanels report={report} />
        </div>
      </div>
    </div>
  )
}

export default EmailInvestigationReport
