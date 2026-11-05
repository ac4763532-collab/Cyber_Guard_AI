/**
 * CyberGuard AI - Threat Intelligence Page
 *
 * Standalone IOC lookup against the Threat Intelligence Agent (VirusTotal +
 * AbuseIPDB via the existing ThreatIntelService). Shows the final
 * reputation classification plus every provider's individual outcome, so a
 * failed/timed-out provider is always visible and never silently collapsed
 * into "clean".
 */

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Fingerprint, Search, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX, Loader2 } from 'lucide-react'
import { clsx } from 'clsx'
import { threatIntelApi } from '@/services/api'
import type { ReputationStatus, ThreatIntelLookupResponse } from '@/types'

const IOC_TYPES: { value: string; label: string }[] = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash_md5', label: 'File Hash (MD5)' },
  { value: 'hash_sha1', label: 'File Hash (SHA-1)' },
  { value: 'hash_sha256', label: 'File Hash (SHA-256)' },
]

const REPUTATION_CONFIG: Record<
  ReputationStatus,
  { label: string; bg: string; text: string; icon: typeof ShieldAlert }
> = {
  malicious: { label: 'MALICIOUS', bg: 'bg-red-500/20', text: 'text-red-400', icon: ShieldX },
  suspicious: { label: 'SUSPICIOUS', bg: 'bg-orange-500/20', text: 'text-orange-400', icon: ShieldAlert },
  clean: { label: 'CLEAN', bg: 'bg-emerald-500/20', text: 'text-emerald-400', icon: ShieldCheck },
  unknown: { label: 'UNKNOWN', bg: 'bg-slate-500/20', text: 'text-slate-400', icon: ShieldQuestion },
  // Deliberately distinct styling from CLEAN - a failed lookup must never
  // read as a confirmed-safe result.
  lookup_failed: { label: 'LOOKUP FAILED', bg: 'bg-yellow-500/20', text: 'text-yellow-400', icon: ShieldQuestion },
}

function ReputationBadge({ status }: { status: ReputationStatus }) {
  const config = REPUTATION_CONFIG[status] || REPUTATION_CONFIG.unknown
  const Icon = config.icon
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-3 py-1 text-sm font-semibold rounded-lg', config.bg, config.text)}>
      <Icon className="w-4 h-4" />
      {config.label}
    </span>
  )
}

function ProviderStatusPill({ status }: { status: string }) {
  const isSuccess = status === 'success'
  const isNotConfigured = status === 'not_configured'
  return (
    <span
      className={clsx(
        'px-2 py-0.5 text-xs font-medium rounded',
        isSuccess && 'bg-emerald-500/20 text-emerald-400',
        !isSuccess && !isNotConfigured && 'bg-yellow-500/20 text-yellow-400',
        isNotConfigured && 'bg-slate-700 text-slate-400'
      )}
    >
      {status.replace(/_/g, ' ').toUpperCase()}
    </span>
  )
}

export function ThreatIntelPage() {
  const [iocType, setIocType] = useState('ip')
  const [iocValue, setIocValue] = useState('')

  const { data: status } = useQuery({
    queryKey: ['threat-intel', 'status'],
    queryFn: threatIntelApi.getStatus,
  })

  const lookupMutation = useMutation({
    mutationFn: () => threatIntelApi.lookup(iocType, iocValue.trim()),
  })

  const canSubmit = iocValue.trim().length > 0 && !lookupMutation.isPending

  const runLookup = () => {
    if (!canSubmit) return
    lookupMutation.mutate()
  }

  const result: ThreatIntelLookupResponse | undefined = lookupMutation.data

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Fingerprint className="w-6 h-6 text-cyan-400" />
            Threat Intelligence
          </h1>
          <p className="text-slate-400 mt-1">
            Look up an indicator of compromise against VirusTotal and AbuseIPDB
          </p>
        </div>
        {status && (
          <div className="flex items-center gap-2 text-sm">
            <span className={clsx('px-2 py-1 rounded', status.virustotal_configured ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-500')}>
              VirusTotal {status.virustotal_configured ? 'configured' : 'not configured'}
            </span>
            <span className={clsx('px-2 py-1 rounded', status.abuseipdb_configured ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-500')}>
              AbuseIPDB {status.abuseipdb_configured ? 'configured' : 'not configured'}
            </span>
          </div>
        )}
      </div>

      {/* Lookup form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-end gap-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Indicator type</label>
            <select
              value={iocType}
              onChange={(e) => setIocType(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              {IOC_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs text-slate-500 mb-1">Indicator value</label>
            <input
              type="text"
              value={iocValue}
              onChange={(e) => setIocValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runLookup()}
              placeholder={iocType === 'ip' ? '8.8.8.8' : iocType === 'domain' ? 'example.com' : 'Value to look up'}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <button
            onClick={runLookup}
            disabled={!canSubmit}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {lookupMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {lookupMutation.isPending ? 'Looking up...' : 'Look Up'}
          </button>
        </div>

        {lookupMutation.isError && (
          <p className="text-sm text-red-400">
            {(lookupMutation.error as any)?.response?.data?.detail || (lookupMutation.error as Error).message || 'Lookup failed'}
          </p>
        )}
      </div>

      {/* Result */}
      {result && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-500">{result.ioc_type.toUpperCase()}</p>
              <p className="text-lg font-mono text-white">{result.ioc_value}</p>
            </div>
            <ReputationBadge status={result.reputation_status} />
          </div>

          <div className="p-6 space-y-4">
            <p className="text-slate-300">{result.classification_reason}</p>

            {result.risk_score !== null && (
              <div>
                <p className="text-xs text-slate-500 mb-1">Risk score</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={clsx(
                        'h-full rounded-full',
                        result.risk_score >= 70 ? 'bg-red-500' : result.risk_score >= 40 ? 'bg-orange-500' : 'bg-emerald-500'
                      )}
                      style={{ width: `${result.risk_score}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono text-white">{result.risk_score}/100</span>
                </div>
              </div>
            )}

            {result.provider_outcomes.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Provider results</p>
                <div className="space-y-2">
                  {result.provider_outcomes.map((outcome) => (
                    <div key={outcome.name} className="flex items-center justify-between bg-slate-800/50 rounded-lg px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="font-medium text-white">{outcome.name}</span>
                        <ProviderStatusPill status={outcome.status} />
                      </div>
                      <div className="flex items-center gap-4 text-xs text-slate-400">
                        {outcome.detections !== null && <span>{outcome.detections} detections</span>}
                        {outcome.confidence_score !== null && <span>confidence {outcome.confidence_score}</span>}
                        {outcome.last_analysis_at && <span>as of {new Date(outcome.last_analysis_at).toLocaleString()}</span>}
                        {outcome.detail && <span className="text-slate-500">{outcome.detail}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.recommendations.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Recommendations</p>
                <ul className="space-y-1">
                  {result.recommendations.map((rec, i) => (
                    <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                      <span className="text-cyan-400 mt-1">&bull;</span>
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
