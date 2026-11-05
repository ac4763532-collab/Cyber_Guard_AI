/**
 * CyberGuard AI - Detection Report Panel
 *
 * "View Detection Report" for automatic monitoring (Log Sources + Local
 * Network Monitor, which is a log source with source_type =
 * 'local_network_monitor' - see SourceCard in LogAnalysisPage.tsx, shared
 * by both pages). Fetches GET /logs/sources/{id}/report, which computes
 * the report on demand from persisted events/findings/alerts - there is
 * no separate "report"/"run" row, so this component never has fabricated
 * data to fall back on: it only ever renders what the backend actually
 * found, or an honest empty/error state.
 *
 * Deliberately a new, independent component rather than a retrofit of
 * LogAnalysisPage.tsx's local AnalysisReport - that component is tightly
 * shaped around a single manual-analysis result (risk gauge, affected
 * systems/accounts, module performance, feedback tied to one result_id)
 * and isn't a safe or honest fit for a time-ranged, status-driven
 * monitoring report. This reuses the same shared building blocks
 * (StatTile, SeverityBadge, exportReport) instead of literally sharing
 * that function, so both reports look consistent without coupling them.
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  Clock,
  Download,
  FileText,
  Loader2,
  Radar,
  RefreshCw,
  Server,
  Shield,
  X,
} from 'lucide-react'
import { clsx } from 'clsx'
import { logsApi } from '@/services/api'
import type { DetectionReportResponse, DetectionReportStatus } from '@/types'
import { SeverityBadge } from './Badge'
import { StatTile } from './StatTile'
import { exportReport } from './exportReport'

const STATUS_LABELS: Record<DetectionReportStatus, string> = {
  monitoring: 'Monitoring',
  detection_in_progress: 'Detection in Progress',
  detection_completed: 'Detection Completed',
  completed_with_findings: 'Completed with Findings',
  completed_no_threats: 'Completed — No Threats Detected',
  partially_completed: 'Partially Completed',
  failed: 'Failed',
}

const STATUS_STYLES: Record<DetectionReportStatus, { bg: string; text: string; border: string }> = {
  monitoring: { bg: 'bg-slate-500/10', text: 'text-slate-300', border: 'border-slate-500/30' },
  detection_in_progress: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  detection_completed: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  completed_with_findings: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  completed_no_threats: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  partially_completed: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  failed: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
}

function StatusBadge({ status }: { status: DetectionReportStatus }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.monitoring
  return (
    <span
      className={clsx(
        'px-2.5 py-1 text-xs font-semibold rounded-lg border',
        style.bg, style.text, style.border
      )}
    >
      {STATUS_LABELS[status] || status}
    </span>
  )
}

/**
 * Button + slide-over panel. Kept as one component so SourceCard only
 * needs to render a single element - the open/close state lives here,
 * not in the parent.
 */
export function DetectionReportButton({ sourceId, sourceName }: { sourceId: string; sourceName: string }) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 rounded-lg transition-colors"
      >
        <FileText className="w-4 h-4" />
        View Detection Report
      </button>
      {open && (
        <DetectionReportModal sourceId={sourceId} sourceName={sourceName} onClose={() => setOpen(false)} />
      )}
    </>
  )
}

function DetectionReportModal({
  sourceId,
  sourceName,
  onClose,
}: {
  sourceId: string
  sourceName: string
  onClose: () => void
}) {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['detection-report', sourceId],
    queryFn: () => logsApi.getSourceReport(sourceId),
  })

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center p-4 bg-black/60" role="dialog" aria-modal="true" aria-label={`Detection report for ${sourceName}`}>
      <div className="bg-slate-950 border border-slate-800 rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-slate-950 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Detection Report
            </h2>
            <p className="text-sm text-slate-400 mt-0.5">{sourceName}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors disabled:opacity-50"
              aria-label="Refresh report"
            >
              <RefreshCw className={clsx('w-4 h-4', isFetching && 'animate-spin')} />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              aria-label="Close detection report"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-16 text-slate-500">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              Loading report…
            </div>
          ) : isError ? (
            <div className="flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-red-400">Could not load the detection report</p>
                <p className="text-xs text-red-300/80 mt-1">
                  {(error as any)?.response?.data?.detail || 'The report request failed. Try refreshing.'}
                </p>
                <button
                  onClick={() => refetch()}
                  className="mt-2 flex items-center gap-1.5 text-xs text-red-300 hover:text-white"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Try again
                </button>
              </div>
            </div>
          ) : data ? (
            <DetectionReportContent report={data} />
          ) : null}
        </div>
      </div>
    </div>
  )
}

function DetectionReportContent({ report }: { report: DetectionReportResponse }) {
  // Empty state: nothing has finished processing yet and nothing failed -
  // a genuinely brand-new or still-warming-up source, not an error.
  const hasAnyActivity = report.events_processed > 0 || report.events_pending > 0
  if (!hasAnyActivity) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <Radar className="w-10 h-10 text-slate-600 mb-3" />
        <p className="text-slate-300 font-medium">No completed detection report yet</p>
        <p className="text-sm text-slate-500 mt-1 max-w-sm">
          This source is being monitored, but no events have been collected and processed
          in the selected time range yet. Check back once activity comes in.
        </p>
        <div className="mt-3">
          <StatusBadge status={report.status} />
        </div>
      </div>
    )
  }

  const severityEntries = Object.entries(report.severity_breakdown || {})

  return (
    <div className="space-y-5">
      {/* Header: status + time range + source/host */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <StatusBadge status={report.status} />
            {report.collector_status && (
              <span className="text-xs text-slate-500">
                Collector: <span className="text-slate-300">{report.collector_status}</span>
              </span>
            )}
          </div>
          <button
            onClick={() => exportReport(report)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>

        <div className="flex items-center gap-x-5 gap-y-1 flex-wrap mt-4 text-xs text-slate-400">
          <span className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            {new Date(report.time_range_start).toLocaleString()} – {new Date(report.time_range_end).toLocaleString()}
          </span>
          {report.hostname && (
            <span className="flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5" />
              Host: {report.hostname}
            </span>
          )}
          <span className="flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5" />
            Report generated: {new Date(report.generated_at).toLocaleString()}
          </span>
        </div>
      </div>

      {/* Real errors, if any - never fabricated, only what the live
          collector supervisor actually reported. */}
      {report.errors.length > 0 && (
        <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="min-w-0">
            {report.errors.map((e, i) => (
              <p key={i} className="text-xs text-red-300 break-words">{e}</p>
            ))}
          </div>
        </div>
      )}

      {/* Stat tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile
          icon={<Server className="w-5 h-5 text-cyan-400" />}
          label="Events Processed"
          value={report.events_processed.toLocaleString()}
          sublabel={report.events_pending > 0 ? `${report.events_pending} still pending` : undefined}
        />
        <StatTile
          icon={<AlertTriangle className="w-5 h-5 text-orange-400" />}
          label="Findings"
          value={report.findings_count.toLocaleString()}
        />
        <StatTile
          icon={<Shield className="w-5 h-5 text-red-400" />}
          label="Failed Events"
          value={report.events_failed.toLocaleString()}
        />
        <StatTile
          icon={<Radar className="w-5 h-5 text-purple-400" />}
          label="Linked Alerts"
          value={report.alert_ids.length.toLocaleString()}
        />
      </div>

      {/* Severity breakdown */}
      {severityEntries.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 mb-2">Severity breakdown</p>
          <div className="flex items-center gap-2 flex-wrap">
            {severityEntries.map(([severity, count]) => (
              <span key={severity} className="flex items-center gap-1.5">
                <SeverityBadge severity={severity} />
                <span className="text-xs text-slate-400">× {count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Findings table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-5 py-3 border-b border-slate-800">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
            Findings in this window
          </h3>
        </div>
        {report.findings.length === 0 ? (
          <div className="p-5 text-center text-slate-500 text-sm">
            No findings detected in this time range.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-2 font-medium">#</th>
                  <th className="px-4 py-2 font-medium">Finding</th>
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">Description</th>
                  <th className="px-4 py-2 font-medium">Rule ID</th>
                  <th className="px-4 py-2 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {report.findings.map((f, i) => (
                  <tr key={f.finding_id || i} className="border-b border-slate-800/60 last:border-0">
                    <td className="px-4 py-3 text-slate-500">{i + 1}</td>
                    <td className="px-4 py-3 text-white font-medium whitespace-nowrap">{f.name}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs">{f.description}</td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap font-mono text-xs">{f.rule_id || '—'}</td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                      {f.timestamp ? new Date(f.timestamp).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
