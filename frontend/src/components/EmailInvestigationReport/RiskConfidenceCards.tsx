/**
 * Risk Score and Verdict Confidence cards.
 *
 * These are deliberately kept as two SEPARATE metrics with separate
 * captions - risk score, confidence, and model accuracy are different
 * things and this UI never collapses one into another:
 *
 * - Risk score (0-100): a weighted sum of finding severities minus a
 *   trust-signal discount (_calculate_verdict in email_agent_v2.py).
 *   It measures how risky the email looks, not how sure we are.
 * - Confidence: a hand-tuned RULE-BASED heuristic, not a calibrated ML
 *   probability. Backend sends a bare 0-1 float with no documented
 *   calibration semantics, so this card labels it honestly as a
 *   heuristic and shows confidence_reasons as the "why" instead of
 *   dressing it up as a statistical probability.
 */
import { AlertTriangle, Gauge } from 'lucide-react'
import { clsx } from 'clsx'
import type { InvestigationReport } from './types'
import { getRiskColorClass, getRiskBandLabel } from './shared/riskHelpers'

const RISK_BAND_BAR_COLOR: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-emerald-500',
}

function RiskScoreCard({ report }: { report: InvestigationReport }) {
  const { verdict } = report
  const band = getRiskBandLabel(verdict.risk_level, verdict.risk_score)
  const barColor = RISK_BAND_BAR_COLOR[band] || 'bg-slate-500'

  return (
    <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-1.5">
          <Gauge className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-medium text-slate-300">Risk Score</span>
        </div>
        <span
          className={clsx('text-xs font-semibold px-2 py-0.5 rounded uppercase', getRiskColorClass(verdict.risk_score))}
        >
          {band}
        </span>
      </div>

      <div className={clsx('text-3xl font-bold', getRiskColorClass(verdict.risk_score))}>
        {verdict.risk_score}
        <span className="text-base text-slate-500 font-normal">/100</span>
      </div>

      <div className="mt-1.5 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full', barColor)}
          style={{ width: `${Math.min(100, Math.max(0, verdict.risk_score))}%` }}
        />
      </div>

      <p
        className="text-xs text-slate-500 mt-1.5"
        title="Risk score reflects how dangerous this email's observed signals look. It is not a measure of how certain the analysis is, and not a prediction of real-world outcome certainty."
      >
        How risky the signals look - not a measure of certainty.
      </p>
    </div>
  )
}

function ConfidenceCard({ report }: { report: InvestigationReport }) {
  const { verdict } = report
  const hasConfidence = typeof verdict.confidence === 'number' && !Number.isNaN(verdict.confidence)

  // If any confidence_reasons mention the ML model, surface that as a
  // cross-reference rather than implying confidence IS the ML score.
  const mlReason = verdict.confidence_reasons?.find((r) => /ml[-\s]?001|model/i.test(r))

  return (
    <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
      <div className="flex items-center gap-1.5 mb-1.5">
        <AlertTriangle className="w-4 h-4 text-cyan-400" />
        <span className="text-sm font-medium text-slate-300">Verdict Confidence</span>
      </div>

      {hasConfidence ? (
        <>
          <div className="text-3xl font-bold text-white">
            {(verdict.confidence * 100).toFixed(0)}
            <span className="text-base text-slate-500 font-normal">%</span>
          </div>
          <p
            className="text-xs text-slate-500 mt-1"
            title="This is a rule-based heuristic confidence score, derived from how many independent signals agree. It is not a calibrated statistical probability and is not the same as model accuracy."
          >
            Rule-based heuristic confidence, not a calibrated probability.
          </p>

          {verdict.confidence_reasons?.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {verdict.confidence_reasons.map((reason, idx) => (
                <span key={idx} className="px-2 py-0.5 bg-white/10 rounded text-xs text-slate-300">
                  {reason}
                </span>
              ))}
            </div>
          )}

          {mlReason && (
            <p className="text-xs text-slate-500 mt-1.5 border-t border-slate-700 pt-1.5">
              Cross-referenced against ML model output: {mlReason}
            </p>
          )}
        </>
      ) : (
        <p className="text-sm text-slate-500">Confidence score not available for this analysis.</p>
      )}
    </div>
  )
}

export function RiskConfidenceCards({ report }: { report: InvestigationReport }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <RiskScoreCard report={report} />
      <ConfidenceCard report={report} />
    </div>
  )
}
