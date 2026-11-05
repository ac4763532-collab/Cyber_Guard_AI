/**
 * Recommended actions - tight list instead of tall bordered cards.
 * Already phrased by the backend as suggestions ("Based on: ..."), not
 * completed-action claims - this stays a list of recommendations, never
 * relabeled as actions that were actually executed.
 */
import { AlertTriangle, CheckCircle2 } from 'lucide-react'
import { clsx } from 'clsx'
import type { InvestigationReport, RecommendationItem } from './types'

/**
 * Collapses recommendations that convey the same advice (same action
 * text, case-insensitive) so the list doesn't repeat itself, while
 * keeping the first occurrence's priority/based_on.
 */
function dedupeRecommendations(items: RecommendationItem[]): RecommendationItem[] {
  const seen = new Set<string>()
  const result: RecommendationItem[] = []
  for (const item of items) {
    const key = item.action?.trim().toLowerCase()
    if (key && !seen.has(key)) {
      seen.add(key)
      result.push(item)
    }
  }
  return result
}

export function RecommendedActions({ report }: { report: InvestigationReport }) {
  const recommendations = dedupeRecommendations(report.recommendations || [])
  if (recommendations.length === 0) return null

  return (
    <div>
      <h3 className="text-sm font-medium text-slate-400 mb-2">Recommended Actions</h3>
      <div className="space-y-1">
        {recommendations.map((rec, idx) => {
          const isImmediate = rec.priority === 'immediate'
          const isHigh = rec.priority === 'high'
          const Icon = isImmediate || isHigh ? AlertTriangle : CheckCircle2

          return (
            <div key={idx} className="flex items-start gap-2 py-1 px-1.5">
              <Icon
                className={clsx(
                  'w-3.5 h-3.5 mt-0.5 flex-shrink-0',
                  isImmediate ? 'text-red-400' : isHigh ? 'text-orange-400' : 'text-emerald-400'
                )}
              />
              <div className="min-w-0">
                <span className="text-sm text-white">{rec.action}</span>
                {rec.based_on && <span className="text-xs text-slate-500 ml-1.5">— {rec.based_on}</span>}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
