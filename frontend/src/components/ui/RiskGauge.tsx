/**
 * Shared risk gauge + risk color/label helpers.
 *
 * Extracted from LogAnalysisPage.tsx so NetworkAnalysisPage.tsx (and any
 * future analysis page) can reuse the same visual, instead of each page
 * growing its own slightly-different copy.
 */

const RISK_RING_CIRCUMFERENCE = 2 * Math.PI * 36 // r=36

export function riskColor(score: number): string {
  if (score >= 75) return '#f87171' // red-400
  if (score >= 50) return '#fb923c' // orange-400
  if (score >= 25) return '#facc15' // yellow-400
  return '#34d399' // emerald-400
}

export function riskLabel(score: number): string {
  if (score >= 75) return 'HIGH RISK'
  if (score >= 50) return 'ELEVATED RISK'
  if (score >= 25) return 'MODERATE RISK'
  return 'LOW RISK'
}

export function RiskGauge({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score))
  const color = riskColor(clamped)
  const offset = RISK_RING_CIRCUMFERENCE * (1 - clamped / 100)
  return (
    <div className="relative w-20 h-20 flex items-center justify-center">
      <svg viewBox="0 0 80 80" className="w-20 h-20 -rotate-90">
        <circle cx="40" cy="40" r="36" fill="none" stroke="#1e293b" strokeWidth="7" />
        <circle
          cx="40"
          cy="40"
          r="36"
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={RISK_RING_CIRCUMFERENCE}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold text-white">{clamped}</span>
        <span className="text-[10px] text-slate-500">/100</span>
      </div>
    </div>
  )
}
