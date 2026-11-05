/**
 * CyberGuard AI - Reports Page
 *
 * Security reports and compliance dashboard.
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  RefreshCw,
  TrendingUp,
  Shield,
  AlertTriangle,
  CheckCircle2,
  BarChart3,
  Download,
} from 'lucide-react'
import { clsx } from 'clsx'
import { reportsApi } from '@/services/api'

function downloadExecutiveCsv(report: Record<string, any>) {
  const rows: Array<[string, unknown]> = [
    ['report_id', report.report_id],
    ['generated_at', report.generated_at],
    ['period_hours', report.period_hours],
    ['security_score', report.security_score],
    ['status', report.status],
    ...Object.entries(report.highlights || {}).map(([key, value]) => [`highlights.${key}`, value]),
    ['data_complete', report.data_complete],
    ...((report.limitations || []) as string[]).map((value, index) => [`limitation.${index + 1}`, value]),
    ...((report.recommendations || []) as string[]).map((value, index) => [`recommendation.${index + 1}`, value]),
  ]
  const escape = (value: unknown) => {
    let text = value == null ? '' : String(value)
    if (/^\s*[=+\-@]/.test(text)) text = `'${text}`
    return `"${text.replace(/"/g, '""')}"`
  }
  const csv = ['metric,value', ...rows.map(([key, value]) => `${escape(key)},${escape(value)}`)].join('\r\n')
  const blob = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `cyberguard-executive-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

// Security score gauge
function SecurityScoreGauge({ score, status, statusColor }: { score: number; status: string; statusColor: string }) {
  const getColor = (c: string) => {
    const colors: Record<string, string> = {
      green: 'text-emerald-500',
      yellow: 'text-yellow-500',
      orange: 'text-orange-500',
      red: 'text-red-500',
    }
    return colors[c] || 'text-slate-500'
  }

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-32 h-32">
        <svg className="w-32 h-32 transform -rotate-90">
          <circle
            cx="64"
            cy="64"
            r="56"
            stroke="currentColor"
            strokeWidth="12"
            fill="none"
            className="text-slate-700"
          />
          <circle
            cx="64"
            cy="64"
            r="56"
            stroke="currentColor"
            strokeWidth="12"
            fill="none"
            strokeDasharray={351.86}
            strokeDashoffset={351.86 - (351.86 * score) / 100}
            className={getColor(statusColor)}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={clsx('text-3xl font-bold', getColor(statusColor))}>{score}</span>
        </div>
      </div>
      <div>
        <p className={clsx('text-2xl font-semibold', getColor(statusColor))}>{status}</p>
        <p className="text-slate-400">Security Score</p>
      </div>
    </div>
  )
}

// Compliance check item
function ComplianceCheck({ name, passed }: { name: string; passed: boolean }) {
  return (
    <div className="flex items-center justify-between py-2">
      <span className="text-sm text-slate-300">{name.replace(/_/g, ' ')}</span>
      {passed ? (
        <CheckCircle2 className="w-5 h-5 text-emerald-500" />
      ) : (
        <AlertTriangle className="w-5 h-5 text-yellow-500" />
      )}
    </div>
  )
}

export function ReportsPage() {
  const [activeTab, setActiveTab] = useState<'executive' | 'threats' | 'compliance'>('executive')

  // Fetch executive summary
  const { data: executive, isLoading: execLoading, isError: execError, refetch: refetchExec } = useQuery({
    queryKey: ['reports', 'executive'],
    queryFn: () => reportsApi.getExecutive(24),
  })

  // Fetch threat landscape
  const { data: threats, isLoading: threatsLoading, isError: threatsError } = useQuery({
    queryKey: ['reports', 'threat-landscape'],
    queryFn: reportsApi.getThreatLandscape,
    enabled: activeTab === 'threats',
  })

  // Fetch compliance
  const { data: compliance, isLoading: complianceLoading, isError: complianceError } = useQuery({
    queryKey: ['reports', 'compliance'],
    queryFn: reportsApi.getCompliance,
    enabled: activeTab === 'compliance',
  })

  const isLoading = execLoading || (activeTab === 'threats' && threatsLoading) || (activeTab === 'compliance' && complianceLoading)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Reports</h1>
          <p className="text-slate-400 mt-1">Security posture and compliance reports</p>
        </div>
        <div className="flex gap-2">
          {executive && (
            <button
              onClick={() => downloadExecutiveCsv(executive)}
              title="Download the displayed executive report as CSV"
              className="flex items-center gap-2 border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
            >
              <Download className="h-4 w-4" />
              CSV
            </button>
          )}
          <button
            onClick={() => refetchExec()}
            disabled={isLoading}
            className="flex items-center gap-2 bg-slate-800 px-4 py-2 text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-slate-800">
        {[
          { id: 'executive', label: 'Executive Summary', icon: BarChart3 },
          { id: 'threats', label: 'Threat Landscape', icon: TrendingUp },
          { id: 'compliance', label: 'Compliance', icon: Shield },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id as any)}
            className={clsx(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
              activeTab === id
                ? 'text-cyan-400 border-cyan-400'
                : 'text-slate-400 border-transparent hover:text-slate-300'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {((activeTab === 'executive' && execError) || (activeTab === 'threats' && threatsError) || (activeTab === 'compliance' && complianceError)) && (
        <p role="alert" className="border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          This report could not be loaded. Check your access and backend connection, then refresh.
        </p>
      )}

      {/* Executive Summary Tab */}
      {activeTab === 'executive' && executive && (
        <div className="space-y-6">
          {/* Score card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <SecurityScoreGauge
                score={executive.security_score}
                status={executive.status}
                statusColor={executive.status_color}
              />
              <div className="text-right">
                <p className="text-sm text-slate-400">Report Period</p>
                <p className="text-white font-medium">Last {executive.period_hours} hours</p>
                <p className="text-xs text-slate-500 mt-1">
                  Generated: {new Date(executive.generated_at).toLocaleString()}
                </p>
              </div>
            </div>
          </div>

          {!executive.data_complete && executive.limitations?.length > 0 && (
            <p className="border border-amber-800 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
              Partial data: {executive.limitations.join(' ')}
            </p>
          )}

          {/* Highlights */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-white">{executive.highlights?.total_events || 0}</p>
              <p className="text-sm text-slate-400">Total Events</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-orange-400">{executive.highlights?.open_alerts || 0}</p>
              <p className="text-sm text-slate-400">Open Alerts</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-red-400">{executive.highlights?.critical_findings || 0}</p>
              <p className="text-sm text-slate-400">Critical Findings</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-orange-400">{executive.highlights?.high_findings || 0}</p>
              <p className="text-sm text-slate-400">High Findings</p>
            </div>
          </div>

          {/* Recommendations */}
          {executive.recommendations && executive.recommendations.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-semibold text-white">Recommendations</h2>
              </div>
              <div className="p-4 space-y-3">
                {executive.recommendations.map((rec: string, idx: number) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg">
                    <div className={clsx(
                      'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold',
                      idx === 0 ? 'bg-red-500/20 text-red-400' : 'bg-slate-700 text-slate-400'
                    )}>
                      {idx + 1}
                    </div>
                    <p className="text-sm text-slate-300">{rec}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Threat Landscape Tab */}
      {activeTab === 'threats' && threats && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attack Vectors */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-semibold text-white">Attack Vectors</h2>
              </div>
              <div className="p-6">
                {Object.keys(threats.attack_vectors || {}).length > 0 ? (
                  <div className="space-y-4">
                    {Object.entries(threats.attack_vectors).map(([vector, count]) => {
                      const total = Object.values(threats.attack_vectors as Record<string, number>).reduce((a, b) => a + b, 0)
                      const pct = Math.round(((count as number) / total) * 100)
                      return (
                        <div key={vector}>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-slate-400 capitalize">{vector}</span>
                            <span className="text-white font-medium">{count as number}</span>
                          </div>
                          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-cyan-500 rounded-full"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <p className="text-slate-500 text-center">No attack vector data</p>
                )}
              </div>
            </div>

            {/* Severity Distribution */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-semibold text-white">Severity Distribution</h2>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                    const count = threats.severity_distribution?.[severity] || 0
                    const total = Object.values(threats.severity_distribution || {}).reduce((a: number, b: unknown) => a + (b as number), 0) || 1
                    const pct = Math.round((count / total) * 100)
                    const colors: Record<string, string> = {
                      critical: 'bg-red-500',
                      high: 'bg-orange-500',
                      medium: 'bg-yellow-500',
                      low: 'bg-blue-500',
                      info: 'bg-slate-500',
                    }
                    return (
                      <div key={severity}>
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="text-slate-400 capitalize">{severity}</span>
                          <span className="text-white font-medium">{count}</span>
                        </div>
                        <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className={clsx('h-full rounded-full', colors[severity])}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* MITRE Techniques */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">Top MITRE ATT&CK Techniques</h2>
            </div>
            <div className="p-6">
              {Object.keys(threats.mitre_techniques || {}).length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(threats.mitre_techniques).map(([tech, count]) => (
                    <span
                      key={tech}
                      className="px-3 py-1.5 bg-purple-500/20 text-purple-400 text-sm rounded-lg font-mono"
                    >
                      {tech} ({count as number})
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 text-center">No MITRE technique data</p>
              )}
            </div>
          </div>

          {!threats.data_complete && threats.limitations?.length > 0 && (
            <p className="border border-amber-800 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
              Partial data: {threats.limitations.join(' ')}
            </p>
          )}
          <p className="text-sm text-slate-500">Trend comparison is not available because this report does not calculate a prior-period baseline.</p>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && compliance && (
        <div className="space-y-6">
          {/* Compliance Score */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              {compliance.compliance_score == null ? (
                <div>
                  <p className="text-xl font-semibold text-white">Compliance not assessed</p>
                  <p className="text-sm text-slate-400">Control evidence is not collected by this application.</p>
                </div>
              ) : (
              <div className="flex items-center gap-6">
                <div className="relative w-24 h-24">
                  <svg className="w-24 h-24 transform -rotate-90">
                    <circle
                      cx="48"
                      cy="48"
                      r="40"
                      stroke="currentColor"
                      strokeWidth="8"
                      fill="none"
                      className="text-slate-700"
                    />
                    <circle
                      cx="48"
                      cy="48"
                      r="40"
                      stroke="currentColor"
                      strokeWidth="8"
                      fill="none"
                      strokeDasharray={251.2}
                      strokeDashoffset={251.2 - (251.2 * compliance.compliance_score) / 100}
                      className={compliance.compliance_score >= 80 ? 'text-emerald-500' : compliance.compliance_score >= 60 ? 'text-yellow-500' : 'text-red-500'}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-xl font-bold text-white">{compliance.compliance_score}%</span>
                  </div>
                </div>
                <div>
                  <p className="text-xl font-semibold text-white">Compliance Score</p>
                  <p className="text-slate-400">{compliance.checks_passed} of {compliance.checks_total} checks passed</p>
                </div>
              </div>
              )}
              <div className="text-right text-sm text-slate-400">
                Generated: {new Date(compliance.generated_at).toLocaleString()}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Security Checks */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-semibold text-white">Security Controls</h2>
              </div>
              <div className="p-6 divide-y divide-slate-800">
                {Object.entries(compliance.checks || {}).map(([check, passed]) => (
                  <ComplianceCheck key={check} name={check} passed={passed as boolean} />
                ))}
              </div>
            </div>

            {/* Framework Status */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-semibold text-white">Framework Compliance</h2>
              </div>
              <div className="p-6 space-y-4">
                {Object.entries(compliance.frameworks || {}).map(([framework, status]) => {
                  const colors: Record<string, { bg: string; text: string }> = {
                    'Compliant': { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
                    'Partial': { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
                    'In Progress': { bg: 'bg-blue-500/20', text: 'text-blue-400' },
                    'Non-Compliant': { bg: 'bg-red-500/20', text: 'text-red-400' },
                  }
                  const { bg, text } = colors[status as string] || colors['Partial']
                  return (
                    <div key={framework} className="flex items-center justify-between">
                      <span className="text-slate-300">{framework.replace(/_/g, ' ')}</span>
                      <span className={clsx('px-3 py-1 text-sm rounded-lg', bg, text)}>
                        {status as string}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-8 h-8 text-slate-500 animate-spin" />
        </div>
      )}
    </div>
  )
}
