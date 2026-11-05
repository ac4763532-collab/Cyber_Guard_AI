/**
 * Feedback (False Positive / Missed Threat) and export controls.
 *
 * Feedback is wired to the real backend endpoint (POST /feedback) - this
 * is not a placeholder. Export stays entirely client-side since no
 * per-investigation export endpoint exists on the backend: a readable
 * text summary is the primary option, raw JSON is a secondary one. No
 * action here is ever claimed to be more than it is.
 */
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { CheckCircle2, Copy, ThumbsUp, ThumbsDown, Download, FileText } from 'lucide-react'
import { feedbackApi } from '@/services/api'
import { useToast } from '@/components/ui'
import type { InvestigationReport } from './types'
import { getVerdictLabel, getRiskBandLabel } from './shared/riskHelpers'

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:bg-slate-700 rounded transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
      ) : (
        <Copy className="w-3 h-3 text-slate-400" />
      )}
    </button>
  )
}

/**
 * Builds a plain-text, human-readable export of the report. Pure
 * function (no DOM access) so it's independently unit-testable.
 */
export function buildReadableExport(report: InvestigationReport): string {
  const lines: string[] = []
  const v = report.verdict

  lines.push('CYBERGUARD AI - EMAIL SECURITY INVESTIGATION REPORT')
  lines.push('='.repeat(55))
  lines.push(`Report ID: ${report.report_id}`)
  lines.push(`Timestamp: ${report.investigation_timestamp || 'unknown'}`)
  lines.push('')
  lines.push(`Verdict: ${getVerdictLabel(v.classification)}`)
  lines.push(`Risk Score: ${v.risk_score}/100 (${getRiskBandLabel(v.risk_level, v.risk_score)})`)
  lines.push(
    `Confidence: ${typeof v.confidence === 'number' ? `${(v.confidence * 100).toFixed(0)}% (rule-based heuristic, not a calibrated probability)` : 'not available'}`
  )
  lines.push('')

  if (report.executive_summary) {
    lines.push('EXECUTIVE SUMMARY')
    lines.push('-'.repeat(20))
    lines.push(report.executive_summary)
    lines.push('')
  }

  const findings = report.all_findings?.length ? report.all_findings : report.key_findings || []
  if (findings.length > 0) {
    lines.push(`FINDINGS (${findings.length})`)
    lines.push('-'.repeat(20))
    findings.forEach((f, i) => {
      lines.push(`${i + 1}. [${f.severity?.toUpperCase()}] ${f.title}`)
      lines.push(`   ${f.description}`)
      if (f.evidence?.length) {
        f.evidence.forEach((e) => lines.push(`   Evidence: ${e}`))
      }
    })
    lines.push('')
  }

  lines.push('SENDER')
  lines.push('-'.repeat(20))
  lines.push(`From: ${report.sender?.from_address || '-'} (${report.sender?.from_domain || '-'})`)
  lines.push(`Reply-To: ${report.sender?.reply_to || '-'}`)
  lines.push(`Return-Path: ${report.sender?.return_path || '-'}`)
  lines.push('')

  if (report.recommendations?.length) {
    lines.push('RECOMMENDED ACTIONS')
    lines.push('-'.repeat(20))
    report.recommendations.forEach((r) => lines.push(`- [${r.priority?.toUpperCase()}] ${r.action}`))
    lines.push('')
  }

  return lines.join('\n')
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function ExportReportButton({ report }: { report: InvestigationReport }) {
  const handleExportText = () => {
    downloadBlob(
      buildReadableExport(report),
      `email-investigation-${report.report_id || 'report'}.txt`,
      'text/plain'
    )
  }

  const handleExportJson = () => {
    // Client-side only: no per-investigation export endpoint exists on
    // the backend, so this downloads the already-fetched report data as
    // JSON rather than fabricating a format the backend doesn't produce.
    downloadBlob(
      JSON.stringify(report, null, 2),
      `email-investigation-${report.report_id || 'report'}.json`,
      'application/json'
    )
  }

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={handleExportText}
        className="flex items-center gap-1.5 px-3 py-1.5 bg-white/10 hover:bg-white/20 text-slate-200 text-xs font-medium rounded-lg transition-colors"
        title="Download a readable summary of this report"
      >
        <FileText className="w-3.5 h-3.5" />
        Export Report
      </button>
      <button
        onClick={handleExportJson}
        className="flex items-center gap-1 px-2 py-1.5 bg-white/5 hover:bg-white/10 text-slate-400 text-xs rounded-lg transition-colors"
        title="Download raw report data as JSON"
      >
        <Download className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

export function FeedbackActions({ reportId }: { reportId: string }) {
  const toast = useToast()
  const [submittedType, setSubmittedType] = useState<'false_positive' | 'false_negative' | null>(null)

  const mutation = useMutation({
    mutationFn: (feedback_type: 'false_positive' | 'false_negative') =>
      feedbackApi.submit({ analysis_id: reportId, feedback_type }),
    onSuccess: (_data, feedback_type) => {
      setSubmittedType(feedback_type)
      toast.success('Feedback submitted', 'Thanks - this helps improve detection accuracy.')
    },
    onError: (error: any) => {
      const status = error?.response?.status
      const detail = error?.response?.data?.detail || error?.response?.data?.message
      if (status === 400 && detail?.toLowerCase().includes('duplicate')) {
        toast.warning('Already submitted', 'You already reported this result.')
      } else {
        toast.error('Feedback failed', detail || 'Could not submit feedback. Please try again.')
      }
    },
  })

  if (submittedType) {
    return (
      <div className="flex items-center gap-2 text-sm text-emerald-400">
        <CheckCircle2 className="w-4 h-4" />
        {submittedType === 'false_positive' ? 'Reported as false positive' : 'Reported as missed threat'}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-slate-500 mr-1">Was this verdict correct?</span>
      <button
        onClick={() => mutation.mutate('false_positive')}
        disabled={mutation.isPending}
        title="This was flagged but is actually safe"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsDown className="w-3.5 h-3.5" />
        False Positive
      </button>
      <button
        onClick={() => mutation.mutate('false_negative')}
        disabled={mutation.isPending}
        title="This is actually malicious but was missed or under-scored"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsUp className="w-3.5 h-3.5" />
        Missed Threat
      </button>
    </div>
  )
}

export function FeedbackExportBar({ report }: { report: InvestigationReport }) {
  return (
    <div className="flex items-center justify-between flex-wrap gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700">
      <FeedbackActions reportId={report.report_id} />
    </div>
  )
}
