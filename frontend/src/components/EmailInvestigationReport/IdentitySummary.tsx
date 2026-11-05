/**
 * Email identity summary - compact two-column list of sender identity
 * fields. Uses the already-clean sender.*_domain fields (now correctly
 * stripped server-side in email_agent_v2.py), plus a defensive
 * stripTrailingBracket() client-side guard as belt-and-suspenders.
 */
import { User } from 'lucide-react'
import type { InvestigationReport } from './types'
import { stripTrailingBracket } from './shared/riskHelpers'
import { CopyButton } from './FeedbackExportBar'

function Field({ label, value, copyable }: { label: string; value: string; copyable?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-slate-500">{label}</p>
      <div className="flex items-center gap-1 min-w-0">
        <p className="text-sm text-white font-mono truncate" title={value || '-'}>
          {value || '-'}
        </p>
        {copyable && value && <CopyButton text={value} />}
      </div>
    </div>
  )
}

export function IdentitySummary({ report }: { report: InvestigationReport }) {
  const sender = report.sender

  return (
    <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
      <div className="flex items-center gap-1.5 mb-2">
        <User className="w-4 h-4 text-cyan-400" />
        <span className="text-sm font-medium text-slate-300">Email Identity</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <Field label="From" value={stripTrailingBracket(sender?.from_address)} copyable />
        <Field label="From Domain" value={stripTrailingBracket(sender?.from_domain)} copyable />
        <Field label="Reply-To" value={stripTrailingBracket(sender?.reply_to)} copyable />
        <Field label="Return-Path" value={stripTrailingBracket(sender?.return_path)} copyable />
        <Field label="URL Count" value={String(report.urls?.total_urls ?? 0)} />
        <Field label="Attachment Count" value={String(report.attachments?.total_attachments ?? 0)} />
      </div>

      {(sender?.is_free_email_provider ||
        sender?.is_suspicious_tld ||
        sender?.is_lookalike_domain ||
        sender?.reply_to_mismatch ||
        sender?.return_path_mismatch) && (
        <div className="flex flex-wrap gap-1.5 mt-2 pt-2 border-t border-slate-700">
          {sender?.is_free_email_provider && (
            <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">Free Email Provider</span>
          )}
          {sender?.is_suspicious_tld && (
            <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded">Suspicious TLD</span>
          )}
          {sender?.is_lookalike_domain && (
            <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">Lookalike Domain</span>
          )}
          {sender?.reply_to_mismatch && (
            <span className="px-2 py-1 bg-orange-500/20 text-orange-400 text-xs rounded">Reply-To Mismatch</span>
          )}
          {sender?.return_path_mismatch && (
            <span className="px-2 py-1 bg-orange-500/20 text-orange-400 text-xs rounded">Return-Path Mismatch</span>
          )}
        </div>
      )}
    </div>
  )
}
