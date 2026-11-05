/**
 * URL Analysis - promoted out of EvidencePanels into its own top-level
 * section (required position #2 in Investigation Details) so it's easy
 * to locate instead of buried inside a generic evidence panel.
 *
 * Status badge logic deliberately distinguishes three different things:
 *  - a real threat-intel lookup result (url.threat_intel_status) - an
 *    actual reputation verdict from a configured provider
 *  - pattern flags (shortener/IP-based/suspicious TLD/@ deception) -
 *    DETECTED means "a suspicious pattern was found", not "confirmed
 *    malicious"
 *  - no threat-intel result AND no pattern flags - NOT DETECTED, never
 *    upgraded to a "safe"/"clean" claim the data can't back
 *
 * Technical flags stay behind a per-row expand toggle, same convention
 * as KeyFindingsList.
 */
import { useState } from 'react'
import { ChevronDown, ChevronRight, Link as LinkIcon } from 'lucide-react'
import { clsx } from 'clsx'
import type { ExtractedURL, InvestigationReport } from './types'
import { SeverityBadge, StatusBadge } from './shared/badges'
import { CopyButton } from './FeedbackExportBar'

function hasPatternFlags(url: ExtractedURL): boolean {
  return Boolean(url.is_shortener || url.is_ip_based || url.is_suspicious_tld || url.has_at_symbol)
}

function UrlRow({ url }: { url: ExtractedURL }) {
  const [expanded, setExpanded] = useState(false)
  const flagged = hasPatternFlags(url)
  const mismatched = Boolean(url.display_text && url.display_text !== url.url)
  const hasTechnicalDetail = flagged || mismatched

  return (
    <div className="p-2.5 bg-slate-800 rounded-lg">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <p className="text-sm text-white font-mono truncate" title={url.url}>
              {url.url}
            </p>
            <CopyButton text={url.url} />
          </div>
          <p className="text-xs text-slate-500 mt-0.5 truncate">{url.domain || '-'}</p>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {url.threat_intel_status ? (
            <StatusBadge status={url.threat_intel_status} />
          ) : (
            <StatusBadge status={flagged ? 'detected' : 'not_detected'} />
          )}
          {url.severity && url.severity !== 'info' && <SeverityBadge severity={url.severity} />}
          {hasTechnicalDetail && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-1 text-slate-500 hover:text-white"
              aria-label={expanded ? 'Collapse URL technical details' : 'Expand URL technical details'}
              aria-expanded={expanded}
            >
              {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {expanded && hasTechnicalDetail && (
        <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t border-slate-700">
          {url.threat_intel_result && (
            <span className="text-xs text-slate-400 mr-1">{url.threat_intel_result}</span>
          )}
          {mismatched && (
            <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">
              Display text "{url.display_text}" mismatch
            </span>
          )}
          {url.is_shortener && (
            <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">Shortener</span>
          )}
          {url.is_ip_based && (
            <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">IP-based</span>
          )}
          {url.is_suspicious_tld && (
            <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">Suspicious TLD</span>
          )}
          {url.has_at_symbol && (
            <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">@ Deception</span>
          )}
        </div>
      )}
    </div>
  )
}

export function UrlAnalysisSection({ report }: { report: InvestigationReport }) {
  const urls = report.urls?.urls || []

  return (
    <div>
      <h3 className="text-sm font-medium text-slate-400 mb-2 flex items-center gap-1.5">
        <LinkIcon className="w-3.5 h-3.5" />
        URL Analysis {urls.length > 0 && <span className="text-slate-500">({urls.length})</span>}
      </h3>
      {urls.length > 0 ? (
        <div className={clsx('space-y-1.5')}>
          {urls.map((url, idx) => (
            <UrlRow key={idx} url={url} />
          ))}
        </div>
      ) : (
        <p className="text-slate-500 text-sm">No URLs found in this email.</p>
      )}
    </div>
  )
}
