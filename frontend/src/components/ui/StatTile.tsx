/**
 * Shared small stat tile (icon + label + value + optional sublabel).
 *
 * Extracted from LogAnalysisPage.tsx for reuse across analysis pages.
 */
import type { ReactNode } from 'react'

export function StatTile({
  icon,
  label,
  value,
  sublabel,
}: {
  icon: ReactNode
  label: string
  value: ReactNode
  sublabel?: string
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
      <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center flex-shrink-0">
        {icon}
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <p className="text-xl font-bold text-white leading-tight">{value}</p>
        {sublabel && <p className="text-[11px] text-slate-500">{sublabel}</p>}
      </div>
    </div>
  )
}
