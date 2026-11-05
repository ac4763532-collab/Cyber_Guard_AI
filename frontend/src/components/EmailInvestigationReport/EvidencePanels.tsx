/**
 * Expandable evidence panels - the detailed, lower-priority view that
 * sits inside Investigation Details. Carries forward the original
 * panels (sender, auth, content, attachment, header, threat intel, IOC
 * inventory) plus ML output/model metadata, risk-score contributing
 * factors, and raw evidence/technical detail.
 *
 * URL Intelligence has moved out to its own top-level UrlAnalysisSection
 * component (required position #2) and is no longer rendered here.
 *
 * Panel ids match the SecurityChecksGrid tile targets so clicking a
 * tile scrolls straight to the matching panel.
 */
import {
  User,
  Shield,
  FileText,
  Paperclip,
  Server,
  Globe,
  Hash,
  Info,
  CheckCircle2,
  AlertCircle,
  Cpu,
  FileCode,
} from 'lucide-react'
import { clsx } from 'clsx'
import type { InvestigationReport } from './types'
import { CollapsibleSection, SeverityBadge, StatusBadge } from './shared/badges'
import { getRiskColorClass, stripTrailingBracket } from './shared/riskHelpers'
import { CopyButton } from './FeedbackExportBar'

export function EvidencePanels({ report }: { report: InvestigationReport }) {
  return (
    <div className="space-y-2">
      {/* Sender Intelligence */}
      <div id="panel-sender">
        <CollapsibleSection
          title="Sender Intelligence"
          icon={User}
          defaultOpen={report.sender?.findings?.length > 0}
          status={report.sender?.findings?.length > 0 ? 'detected' : 'not_detected'}
        >
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-xs text-slate-500">From Address</p>
              <p className="text-sm text-white font-mono break-all">
                {stripTrailingBracket(report.sender?.from_address) || '-'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500">From Domain</p>
              <p className="text-sm text-white font-mono break-all">
                {stripTrailingBracket(report.sender?.from_domain) || '-'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Reply-To</p>
              <p className="text-sm text-white font-mono break-all">
                {stripTrailingBracket(report.sender?.reply_to) || '-'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Return-Path</p>
              <p className="text-sm text-white font-mono break-all">
                {stripTrailingBracket(report.sender?.return_path) || '-'}
              </p>
            </div>
          </div>
        </CollapsibleSection>
      </div>

      {/* Email Authentication */}
      <div id="panel-auth">
        <CollapsibleSection title="Email Authentication" icon={Shield} defaultOpen>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {(['spf', 'dkim', 'dmarc'] as const).map((authType) => {
              const auth = report.authentication?.[authType]
              const status = auth?.status || 'unknown'

              return (
                <div key={authType} className="p-2.5 bg-slate-800 rounded-lg">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-medium text-white uppercase">{authType}</span>
                    <StatusBadge status={status} />
                  </div>
                  {auth?.evidence && <p className="text-xs text-slate-500">{auth.evidence}</p>}
                  {auth?.domain && <p className="text-xs text-slate-400 mt-1">Domain: {auth.domain}</p>}
                  {auth?.reason && status === 'unknown' && (
                    <p className="text-xs text-slate-500 mt-1 italic">{auth.reason}</p>
                  )}
                </div>
              )
            })}
          </div>
        </CollapsibleSection>
      </div>

      {/* Content Analysis */}
      <div id="panel-content">
        <CollapsibleSection
          title="Content Analysis"
          icon={FileText}
          defaultOpen={report.content?.urgency_detected || report.content?.credential_request_detected}
          status={report.content?.urgency_detected || report.content?.credential_request_detected ? 'detected' : 'not_detected'}
        >
          <div className="space-y-2">
            <div className="flex items-center justify-between p-2.5 bg-slate-800 rounded-lg">
              <span className="text-sm text-slate-400">Social Engineering Score</span>
              <span
                className={clsx(
                  'text-lg font-bold',
                  report.content?.social_engineering_score >= 70
                    ? 'text-red-400'
                    : report.content?.social_engineering_score >= 40
                    ? 'text-yellow-400'
                    : 'text-emerald-400'
                )}
              >
                {report.content?.social_engineering_score || 0}/100
              </span>
            </div>

            <div className="p-2.5 bg-slate-800 rounded-lg">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm text-white">Urgency Language</span>
                <StatusBadge status={report.content?.urgency_detected ? 'detected' : 'not_detected'} />
              </div>
              {report.content?.urgency_matches?.length > 0 && (
                <div className="space-y-1">
                  {report.content.urgency_matches.map((match, i) => (
                    <p key={i} className="text-xs text-slate-400 font-mono bg-slate-900 px-2 py-1 rounded">
                      "{match}"
                    </p>
                  ))}
                </div>
              )}
            </div>

            <div className="p-2.5 bg-slate-800 rounded-lg">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm text-white">Credential Request</span>
                <StatusBadge status={report.content?.credential_request_detected ? 'detected' : 'not_detected'} />
              </div>
              {report.content?.credential_matches?.length > 0 && (
                <div className="space-y-1">
                  {report.content.credential_matches.map((match, i) => (
                    <p key={i} className="text-xs text-slate-400 font-mono bg-slate-900 px-2 py-1 rounded">
                      "{match}"
                    </p>
                  ))}
                </div>
              )}
            </div>

            <div className="p-2.5 bg-slate-800 rounded-lg">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm text-white">Brand Impersonation</span>
                <StatusBadge status={report.content?.brand_impersonation_detected ? 'detected' : 'not_detected'} />
              </div>
              {report.content?.impersonated_brands?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {report.content.impersonated_brands.map((brand, i) => (
                    <span key={i} className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">
                      {brand}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </CollapsibleSection>
      </div>

      {/* Attachments */}
      <div id="panel-attachments">
        <CollapsibleSection
          title={`Attachment Analysis (${report.attachments?.total_attachments || 0})`}
          icon={Paperclip}
          defaultOpen={report.attachments?.dangerous_attachments > 0}
          status={report.attachments?.status}
        >
          {report.attachments?.attachments?.length > 0 ? (
            <div className="space-y-1.5">
              {report.attachments.attachments.map((att, idx) => (
                <div key={idx} className="p-2.5 bg-slate-800 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-sm text-white font-mono">{att.filename}</p>
                      <p className="text-xs text-slate-500">
                        {att.mime_type} | {(att.size / 1024).toFixed(1)} KB
                      </p>
                      {att.sha256 && (
                        <div className="flex items-center gap-1 mt-1">
                          <p className="text-xs text-slate-500 font-mono truncate max-w-xs">
                            SHA256: {att.sha256.substring(0, 16)}...
                          </p>
                          <CopyButton text={att.sha256} />
                        </div>
                      )}
                    </div>
                    {att.severity !== 'info' && <SeverityBadge severity={att.severity} />}
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {att.is_dangerous_extension && (
                      <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">Dangerous Extension</span>
                    )}
                    {att.is_double_extension && (
                      <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">Double Extension</span>
                    )}
                    {att.is_macro_enabled && (
                      <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-400 text-xs rounded">Macro Enabled</span>
                    )}
                    {att.has_mime_mismatch && (
                      <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">MIME Mismatch</span>
                    )}
                    {att.is_archive && (
                      <span className="px-1.5 py-0.5 bg-slate-600/20 text-slate-400 text-xs rounded">Archive</span>
                    )}
                    {att.is_disk_image && (
                      <span className="px-1.5 py-0.5 bg-slate-600/20 text-slate-400 text-xs rounded">Disk Image</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No attachments in this email.</p>
          )}
        </CollapsibleSection>
      </div>

      {/* Header Forensics */}
      <div id="panel-headers">
        <CollapsibleSection title="Header Forensics" icon={Server} status={report.headers?.status}>
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 bg-slate-800 rounded-lg">
                <p className="text-xs text-slate-500">Message-ID</p>
                <p className="text-sm text-white font-mono truncate">
                  {report.headers?.message_id || (report.headers?.message_id_present ? '-' : 'MISSING')}
                </p>
              </div>
              <div className="p-2.5 bg-slate-800 rounded-lg">
                <p className="text-xs text-slate-500">Mail Hops</p>
                <p className="text-sm text-white">
                  {report.headers?.received_hops || 0}
                  {report.headers?.excessive_hops && (
                    <span className="ml-2 px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">
                      EXCESSIVE
                    </span>
                  )}
                </p>
              </div>
            </div>

            {report.headers?.findings?.length > 0 && (
              <div className="space-y-1.5">
                {report.headers.findings.map((finding: any, idx: number) => (
                  <div key={idx} className="p-2 bg-slate-800 rounded border-l-2 border-yellow-500">
                    <p className="text-sm text-white">{finding.name}</p>
                    <p className="text-xs text-slate-400">{finding.evidence?.join(', ')}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CollapsibleSection>
      </div>

      {/* Threat Intelligence */}
      <div id="panel-threat-intel">
        <CollapsibleSection title="Threat Intelligence" icon={Globe} status={report.threat_intel?.status}>
          {report.threat_intel?.status === 'configured' && report.threat_intel?.results?.length > 0 ? (
            <div className="space-y-1.5">
              {report.threat_intel.results.map((result: any, idx: number) => (
                <div key={idx} className="p-2.5 bg-slate-800 rounded-lg flex items-center justify-between">
                  <div>
                    <p className="text-sm text-white font-mono">{result.ioc}</p>
                    <p className="text-xs text-slate-500">
                      {result.ioc_type} | {result.provider}
                    </p>
                  </div>
                  <StatusBadge status={result.status} />
                </div>
              ))}
            </div>
          ) : report.threat_intel?.status === 'not_configured' ? (
            <div className="text-center py-3">
              <Info className="w-6 h-6 text-slate-500 mx-auto mb-1.5" />
              <p className="text-slate-400 text-sm">Threat intelligence not configured</p>
              <p className="text-slate-500 text-xs mt-1">
                Configure VirusTotal or AbuseIPDB API keys to enable IOC lookups
              </p>
            </div>
          ) : report.threat_intel?.status === 'no_iocs' ||
            (report.threat_intel?.status === 'configured' &&
              (!report.threat_intel?.results || report.threat_intel?.results?.length === 0)) ? (
            <div className="text-center py-3">
              <CheckCircle2 className="w-6 h-6 text-green-500 mx-auto mb-1.5" />
              <p className="text-slate-300 text-sm">No suspicious indicators found</p>
              <p className="text-slate-500 text-xs mt-1">
                Email is from a trusted domain with no suspicious URLs, IPs, or file hashes to check
              </p>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No threat intelligence results available.</p>
          )}
        </CollapsibleSection>
      </div>

      {/* IOC Inventory */}
      <CollapsibleSection title={`IOC Inventory (${report.iocs?.total_iocs || 0})`} icon={Hash}>
        <div className="space-y-2">
          {report.iocs?.domains?.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Domains ({report.iocs.domains.length})</p>
              <div className="flex flex-wrap gap-1">
                {report.iocs.domains.map((domain, i) => (
                  <span key={i} className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded font-mono">
                    {domain}
                  </span>
                ))}
              </div>
            </div>
          )}
          {report.iocs?.ips?.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">IP Addresses ({report.iocs.ips.length})</p>
              <div className="flex flex-wrap gap-1">
                {report.iocs.ips.map((ip, i) => (
                  <span key={i} className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded font-mono">
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          )}
          {report.iocs?.urls?.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">URLs ({report.iocs.urls.length})</p>
              <div className="space-y-1">
                {report.iocs.urls.slice(0, 5).map((url, i) => (
                  <p key={i} className="text-xs text-slate-300 font-mono bg-slate-800 px-2 py-1 rounded truncate">
                    {url}
                  </p>
                ))}
              </div>
            </div>
          )}
          {report.iocs?.emails?.length ? (
            <div>
              <p className="text-xs text-slate-500 mb-1">Email Addresses ({report.iocs.emails.length})</p>
              <div className="flex flex-wrap gap-1">
                {report.iocs.emails.map((email, i) => (
                  <span key={i} className="px-2 py-1 bg-slate-800 text-slate-300 text-xs rounded font-mono">
                    {email}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
          {report.iocs?.hashes?.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">File Hashes ({report.iocs.hashes.length})</p>
              <div className="space-y-1">
                {report.iocs.hashes.map((hash, i) => (
                  <div key={i} className="flex items-center gap-1">
                    <p className="text-xs text-slate-300 font-mono bg-slate-800 px-2 py-1 rounded truncate">{hash}</p>
                    <CopyButton text={hash} />
                  </div>
                ))}
              </div>
            </div>
          )}
          {!report.iocs?.total_iocs && <p className="text-slate-500 text-sm">No IOCs extracted from this email.</p>}
        </div>
      </CollapsibleSection>

      {/* Risk Score Breakdown - the 7 component scores are a separate
          heuristic approximation and do not necessarily sum to
          total_score, so this stays phrased as "what contributed," not
          a strict decomposition. */}
      <CollapsibleSection title="Risk Score Breakdown" icon={AlertCircle}>
        <div className="space-y-2">
          <div className="flex items-center justify-between p-2.5 bg-slate-800 rounded-lg">
            <span className="text-white font-medium text-sm">Total Risk Score</span>
            <span className={clsx('text-xl font-bold', getRiskColorClass(report.risk_breakdown?.total_score || 0))}>
              {report.risk_breakdown?.total_score || 0}/100
            </span>
          </div>

          <div className="grid grid-cols-5 gap-1.5">
            {[
              { label: 'Critical', count: report.risk_breakdown?.critical_findings || 0, color: 'text-red-400' },
              { label: 'High', count: report.risk_breakdown?.high_findings || 0, color: 'text-orange-400' },
              { label: 'Medium', count: report.risk_breakdown?.medium_findings || 0, color: 'text-yellow-400' },
              { label: 'Low', count: report.risk_breakdown?.low_findings || 0, color: 'text-blue-400' },
              { label: 'Info', count: report.risk_breakdown?.info_findings || 0, color: 'text-slate-400' },
            ].map((item) => (
              <div key={item.label} className="p-1.5 bg-slate-800 rounded text-center">
                <div className={clsx('text-lg font-bold', item.color)}>{item.count}</div>
                <div className="text-xs text-slate-500">{item.label}</div>
              </div>
            ))}
          </div>

          <p className="text-xs text-slate-500 italic">
            Contributing factors, not a strict decomposition - these do not necessarily sum to the total.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
            {[
              { label: 'Sender', value: report.risk_breakdown?.sender_score },
              { label: 'Auth', value: report.risk_breakdown?.auth_score },
              { label: 'URL', value: report.risk_breakdown?.url_score },
              { label: 'Content', value: report.risk_breakdown?.content_score },
              { label: 'Attachment', value: report.risk_breakdown?.attachment_score },
              { label: 'Header', value: report.risk_breakdown?.header_score },
              { label: 'Threat Intel', value: report.risk_breakdown?.threat_intel_score },
            ]
              .filter((item) => typeof item.value === 'number')
              .map((item) => (
                <div key={item.label} className="p-1.5 bg-slate-800 rounded text-center">
                  <div className="text-sm font-semibold text-slate-300">{item.value}</div>
                  <div className="text-xs text-slate-500">{item.label}</div>
                </div>
              ))}
          </div>
        </div>
      </CollapsibleSection>

      {/* ML Output / Model Metadata - only rendered when the backend
          actually sent ML-related confidence_reasons. */}
      {report.verdict?.confidence_reasons?.some((r) => /ml[-\s]?001|model/i.test(r)) && (
        <CollapsibleSection title="ML Output / Model Metadata" icon={Cpu}>
          <div className="space-y-1.5">
            <p className="text-xs text-slate-500">
              Signals below reference the ML model's output as cross-referenced by the rule-based confidence
              heuristic. The model's score is one input among several, not an independent final verdict.
            </p>
            {report.verdict.confidence_reasons
              .filter((r) => /ml[-\s]?001|model/i.test(r))
              .map((reason, idx) => (
                <p key={idx} className="text-sm text-slate-300 bg-slate-800 p-2 rounded">
                  {reason}
                </p>
              ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Raw Evidence / Technical Detail */}
      <CollapsibleSection title="Raw Evidence / Technical Details" icon={FileCode}>
        <div className="space-y-1.5">
          {(report.all_findings?.length ? report.all_findings : report.key_findings || []).map((finding) => (
            <div key={finding.finding_id} className="p-2 bg-slate-800 rounded">
              <p className="text-xs text-slate-500">
                {finding.finding_id} {finding.rule_id ? `(${finding.rule_id})` : ''} — source: {finding.source}
              </p>
              {finding.evidence?.map((ev, i) => (
                <p key={i} className="text-xs text-slate-400 font-mono mt-1 break-all">
                  {ev}
                </p>
              ))}
            </div>
          ))}
          {!(report.all_findings?.length || report.key_findings?.length) && (
            <p className="text-slate-500 text-sm">No findings recorded for this analysis.</p>
          )}
        </div>
      </CollapsibleSection>
    </div>
  )
}
