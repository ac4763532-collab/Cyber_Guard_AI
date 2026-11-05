/**
 * CyberGuard AI - Network Analysis Page
 *
 * Tabs:
 * - Analyze: passive OSINT lookup (DNS/geolocation/RDAP/threat-intel) for
 *   an IP or domain. No scan of the target's live systems.
 * - Local Network Monitor: connect THIS computer (real, backed by an
 *   embedded psutil-based collector) and an honest "not available"
 *   message for a router/office network (no ingestion exists for that).
 * - Network Scan: authorized active port scan (nmap-backed, with honest
 *   simulated-data fallback when nmap is unavailable).
 * - Findings: findings from persisted network scan history.
 * - History: paginated network analysis history.
 *
 * Honesty principle throughout: every panel either shows real data or
 * explicitly says why it can't (not configured / lookup failed / not
 * implemented) - never a fabricated or defaulted "looks fine" state.
 */

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  Network,
  Search,
  Send,
  AlertTriangle,
  CheckCircle2,
  Shield,
  RefreshCw,
  XCircle,
  Globe,
  Lock,
  ThumbsUp,
  ThumbsDown,
  FlaskConical,
  Activity,
  Info,
  MapPin,
  Server,
  ScrollText,
  ExternalLink,
  History as HistoryIcon,
  ListChecks,
  Radar,
} from 'lucide-react'
import { clsx } from 'clsx'
import { analysisApi, feedbackApi, logsApi } from '@/services/api'
import { useToast, SeverityBadge, RiskGauge, EmptyState } from '@/components/ui'
import { SourceCard } from '@/pages/LogAnalysisPage'

// =============================================================================
// Shared feedback actions (used by the Network Scan tab's result panel)
// =============================================================================

function NetworkFeedbackActions({ analysisId }: { analysisId: string }) {
  const toast = useToast()
  const [submittedType, setSubmittedType] = useState<'confirmed' | 'false_positive' | null>(null)

  const mutation = useMutation({
    mutationFn: (feedback_type: 'confirmed' | 'false_positive') =>
      feedbackApi.submit({ analysis_id: analysisId, feedback_type }),
    onSuccess: (_data, feedback_type) => {
      setSubmittedType(feedback_type)
      toast.success('Feedback submitted', 'Thanks - this helps track NetworkAgent accuracy.')
    },
    onError: (error: any) => {
      const status = error?.response?.status
      const detail = error?.response?.data?.detail || error?.response?.data?.message
      if (status === 400 && detail?.toLowerCase().includes('duplicate')) {
        toast.warning('Already submitted', 'You already reported this result.')
      } else if (status === 401) {
        toast.error('Sign in required', 'Log in to submit feedback on this analysis.')
      } else {
        toast.error('Feedback failed', detail || 'Could not submit feedback. Please try again.')
      }
    },
  })

  if (submittedType) {
    return (
      <div className="flex items-center gap-2 text-sm text-emerald-400">
        <CheckCircle2 className="w-4 h-4" />
        {submittedType === 'confirmed' ? 'Marked as confirmed' : 'Reported as false positive'}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-slate-500 mr-1">Were these findings correct?</span>
      <button
        onClick={() => mutation.mutate('confirmed')}
        disabled={mutation.isPending}
        title="These findings are correct"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsUp className="w-3.5 h-3.5" />
        Confirm
      </button>
      <button
        onClick={() => mutation.mutate('false_positive')}
        disabled={mutation.isPending}
        title="These findings were flagged but are actually benign"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
      >
        <ThumbsDown className="w-3.5 h-3.5" />
        False Positive
      </button>
    </div>
  )
}

// A small labeled info row used across the Analyze tab's panels.
function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1.5 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 text-right">{value ?? '—'}</span>
    </div>
  )
}

function PanelError({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 text-sm text-slate-400 py-2">
      <AlertTriangle className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  )
}

// =============================================================================
// Threat-intel reputation + per-provider status (Analyze tab)
//
// Mirrors the backend's five-way classification exactly - this component
// never computes its own malicious/clean verdict, it only renders the
// `reputation_status` the backend already decided. See
// `backend/app/services/threat_intel/service.py`'s ReputationStatus
// docstring for the classification policy.
// =============================================================================

type ReputationStatusValue = 'malicious' | 'clean' | 'suspicious' | 'unknown' | 'lookup_failed'

interface ProviderOutcome {
  name: string
  status: 'success' | 'timeout' | 'auth_error' | 'rate_limited' | 'unavailable' | 'not_configured'
  detections?: number | null
  confidence_score?: number | null
  last_analysis_at?: string | null
  detail?: string | null
}

interface ThreatIntelField {
  configured: boolean
  reputation_status?: ReputationStatusValue
  classification_reason?: string
  sources?: string[]
  provider_outcomes?: ProviderOutcome[]
  risk_score?: number | null
  error?: string | null
}

const REPUTATION_DISPLAY: Record<
  ReputationStatusValue,
  { label: string; className: string; icon: typeof CheckCircle2 }
> = {
  malicious: { label: 'MALICIOUS', className: 'bg-red-500/10 border-red-500/30 text-red-400', icon: XCircle },
  suspicious: { label: 'SUSPICIOUS', className: 'bg-amber-500/10 border-amber-500/30 text-amber-400', icon: AlertTriangle },
  clean: { label: 'CLEAN', className: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400', icon: CheckCircle2 },
  lookup_failed: { label: 'LOOKUP FAILED', className: 'bg-slate-700/40 border-slate-600 text-slate-300', icon: XCircle },
  unknown: { label: 'UNKNOWN', className: 'bg-slate-700/40 border-slate-600 text-slate-300', icon: Info },
}

const PROVIDER_STATUS_LABEL: Record<ProviderOutcome['status'], string> = {
  success: 'Checked',
  timeout: 'Timed out',
  auth_error: 'Authentication failed',
  rate_limited: 'Rate limited',
  unavailable: 'Unavailable',
  not_configured: 'Not configured',
}

function ReputationSummary({ threatIntel }: { threatIntel: ThreatIntelField | undefined }) {
  if (!threatIntel?.configured) {
    return (
      <div className="flex items-start gap-3 p-3 bg-slate-800/50 border border-slate-700 rounded-lg">
        <Info className="w-4 h-4 text-slate-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-slate-300 text-sm font-medium">Not configured</p>
          <p className="text-slate-500 text-xs mt-0.5">
            No VirusTotal or AbuseIPDB API key is set on this server, so reputation data cannot be
            retrieved for this target.
          </p>
        </div>
      </div>
    )
  }

  const status = threatIntel.reputation_status ?? 'unknown'
  const display = REPUTATION_DISPLAY[status]
  const Icon = display.icon

  return (
    <div className="space-y-2">
      <div className={clsx('flex items-center gap-2 p-3 rounded-lg border', display.className)}>
        <Icon className="w-4 h-4 flex-shrink-0" />
        <span className="text-sm font-medium">Reputation Status: {display.label}</span>
        {typeof threatIntel.risk_score === 'number' && (
          <span className="text-xs text-slate-400 ml-auto">Risk score: {threatIntel.risk_score}/100</span>
        )}
      </div>
      {threatIntel.classification_reason && (
        <p className="text-xs text-slate-400">{threatIntel.classification_reason}</p>
      )}
      <p className="text-xs text-slate-500">
        Sources checked: {threatIntel.sources && threatIntel.sources.length > 0 ? threatIntel.sources.join(', ') : 'none'}
      </p>
    </div>
  )
}

function ProviderOutcomeRow({ outcome }: { outcome: ProviderOutcome }) {
  const ok = outcome.status === 'success'
  return (
    <div className="flex items-start gap-3 p-3 bg-slate-800/40 border border-slate-700 rounded-lg">
      {ok ? (
        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
      ) : (
        <XCircle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-slate-200">{outcome.name}</span>
          <span className={clsx('text-xs font-medium', ok ? 'text-emerald-400' : 'text-amber-400')}>
            {PROVIDER_STATUS_LABEL[outcome.status]}
          </span>
        </div>
        {ok ? (
          <div className="mt-1 text-xs text-slate-400 space-x-3">
            {typeof outcome.detections === 'number' && <span>Detections: {outcome.detections}</span>}
            {typeof outcome.confidence_score === 'number' && <span>Confidence/score: {outcome.confidence_score}/100</span>}
            {outcome.last_analysis_at && <span>Last analysis: {outcome.last_analysis_at}</span>}
          </div>
        ) : (
          <p className="mt-1 text-xs text-slate-500">{outcome.detail || 'This provider could not be checked.'}</p>
        )}
      </div>
    </div>
  )
}

// =============================================================================
// Analyze tab
// =============================================================================

function AnalyzeTab() {
  const [target, setTarget] = useState('')
  const [lastTarget, setLastTarget] = useState('')

  const lookupMutation = useMutation({
    mutationFn: (t: string) => analysisApi.lookupNetwork(t),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    setLastTarget(target.trim())
    lookupMutation.mutate(target.trim())
  }

  const result = lookupMutation.data

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex gap-3">
        <div className="relative flex-1">
          <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            required
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="IP address or domain (e.g. 8.8.8.8 or example.com)"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-3 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        <button
          type="submit"
          disabled={lookupMutation.isPending}
          className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          {lookupMutation.isPending ? (
            <RefreshCw className="w-4 h-4 animate-spin" />
          ) : (
            <Search className="w-4 h-4" />
          )}
          Lookup
        </button>
      </form>

      {lookupMutation.error && (
        <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-5 h-5 text-red-400" />
          <p className="text-red-400">Lookup failed for "{lastTarget}". Please check the target and try again.</p>
        </div>
      )}

      {!result && !lookupMutation.isPending && !lookupMutation.error && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <EmptyState
            icon={Search}
            title="No lookup yet"
            description="Enter an IP address or domain above to see DNS, geolocation, registration, and threat-intelligence information."
          />
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Threat Intel Summary - the critical honesty gate */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <Shield className="w-4 h-4 text-cyan-400" />
              Threat Intelligence Summary
            </h3>
            <ReputationSummary threatIntel={result.threat_intel} />
          </div>

          {/* Per-provider status - never silently drops a failed provider */}
          {result.threat_intel?.configured && result.threat_intel.provider_outcomes?.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <Server className="w-4 h-4 text-cyan-400" />
                Threat Intelligence Providers
              </h3>
              <div className="space-y-2">
                {result.threat_intel.provider_outcomes.map((outcome: ProviderOutcome, idx: number) => (
                  <ProviderOutcomeRow key={idx} outcome={outcome} />
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Geographic Location */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <MapPin className="w-4 h-4 text-cyan-400" />
                Geographic Location
              </h3>
              {result.geoip?.available ? (
                <div>
                  <InfoRow label="Country" value={result.geoip.country} />
                  <InfoRow label="Region" value={result.geoip.region} />
                  <InfoRow label="City" value={result.geoip.city} />
                  <InfoRow label="ISP" value={result.geoip.isp} />
                  <InfoRow label="Organization" value={result.geoip.org} />
                  <InfoRow label="ASN" value={result.geoip.asn} />
                  {result.geoip.lat != null && result.geoip.lon != null && (
                    <a
                      href={`https://www.openstreetmap.org/?mlat=${result.geoip.lat}&mlon=${result.geoip.lon}#map=10/${result.geoip.lat}/${result.geoip.lon}`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 mt-2 text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      View on map <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              ) : (
                <PanelError message={result.geoip?.error || 'Geolocation unavailable for this target.'} />
              )}
            </div>

            {/* DNS Information */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <Globe className="w-4 h-4 text-cyan-400" />
                DNS Information
              </h3>
              {!result.dns?.error ? (
                <div>
                  <InfoRow label="Query type" value={result.dns?.query_type === 'reverse' ? 'Reverse (PTR)' : 'Forward (A)'} />
                  <InfoRow label="Hostname" value={result.dns?.hostname} />
                  <InfoRow
                    label="Resolved IPs"
                    value={result.dns?.resolved_ips?.length > 0 ? result.dns.resolved_ips.join(', ') : '—'}
                  />
                  {result.dns?.aliases?.length > 0 && (
                    <InfoRow label="Aliases" value={result.dns.aliases.join(', ')} />
                  )}
                </div>
              ) : (
                <PanelError message={result.dns.error} />
              )}
            </div>

            {/* RDAP / Registration Info */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <ScrollText className="w-4 h-4 text-cyan-400" />
                Registration Info (RDAP)
              </h3>
              {result.rdap?.available ? (
                <div>
                  <InfoRow label="Registrar" value={result.rdap.registrar} />
                  <InfoRow label="Created" value={result.rdap.created_date} />
                  <InfoRow label="Updated" value={result.rdap.updated_date} />
                  <InfoRow
                    label="Nameservers"
                    value={result.rdap.nameservers?.length > 0 ? result.rdap.nameservers.join(', ') : '—'}
                  />
                  {result.rdap.status?.length > 0 && (
                    <InfoRow label="Status" value={result.rdap.status.join(', ')} />
                  )}
                </div>
              ) : (
                <PanelError message={result.rdap?.error || 'No RDAP record found.'} />
              )}
            </div>

            {/* Recent Network Activity - honest "not tracked" note */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-cyan-400" />
                Recent Network Activity
              </h3>
              <div className="flex items-start gap-2 text-sm text-slate-400">
                <Info className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
                <p>
                  Recent activity for this target isn't tracked - Analyze performs a one-time lookup, not
                  continuous monitoring. See the Network Scan tab for authorized active scanning.
                </p>
              </div>
            </div>
          </div>

          {/* Recommended Actions - built only from real signals present */}
          <RecommendedActions result={result} />
        </div>
      )}
    </div>
  )
}

interface NetworkIntelResultShape {
  target_classification?: string
  threat_intel?: ThreatIntelField
  dns?: { error?: string | null }
  geoip?: { available?: boolean; error?: string | null }
}

function RecommendedActions({ result }: { result: NetworkIntelResultShape }) {
  const recs: string[] = []
  const status = result.threat_intel?.reputation_status

  if (status === 'malicious') {
    recs.push('Threat intelligence flagged this target as malicious - investigate before allowing traffic to or from it.')
  } else if (status === 'suspicious') {
    recs.push('Threat intelligence found some suspicious signal but not enough to call this malicious - treat with caution and corroborate with other evidence before acting.')
  } else if (status === 'lookup_failed') {
    recs.push('One or more threat-intelligence providers could not be checked. This is NOT a confirmed clean result - retry the lookup or check server logs before trusting this target.')
  } else if (!result.threat_intel?.configured) {
    recs.push('No threat intelligence configured - add a VirusTotal and/or AbuseIPDB API key on the server to enable reputation checks.')
  }

  const isNonPublicTarget = Boolean(result.target_classification) && result.target_classification !== 'public'

  if (result.target_classification === 'malformed') {
    recs.push("This target is not a valid IP address - it was rejected before any lookup was attempted. Double-check the address and try again.")
  } else if (isNonPublicTarget) {
    recs.push(`This target is a ${result.target_classification} - public reputation, geolocation, and registration data don't apply to it, and it was not sent to any external provider.`)
  }
  // Only show a DNS-specific recommendation when DNS was actually attempted
  // (a public target) - a malformed/private target's `dns.error` reflects
  // the same validation rejection already explained above, not a genuine
  // DNS failure, and repeating it here would be misleading.
  if (!isNonPublicTarget && result.dns?.error) {
    recs.push('DNS lookup failed for this target - verify the target is spelled correctly and is publicly resolvable.')
  }
  if (recs.length === 0) {
    recs.push('No specific concerns identified from the data available above. Review each panel for full context.')
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
        <ListChecks className="w-4 h-4 text-cyan-400" />
        Recommended Actions
      </h3>
      <ul className="space-y-1.5">
        {recs.map((rec, idx) => (
          <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
            {rec}
          </li>
        ))}
      </ul>
    </div>
  )
}

// =============================================================================
// Local Network Monitor tab - connect THIS computer (Option A, real) and an
// honest "not available" message for a router/office network (Option B).
//
// Option A reuses the exact same LogSource / embedded-collector machinery
// as the Log Analysis page (SourceCard, logsApi) - this is not a parallel
// monitoring system, just a new source_type on the existing one. The
// source observes connections/interfaces on the machine running this
// backend process - never a remote router, Wi-Fi AP, or other device.
// =============================================================================

const LOCAL_MONITOR_SOURCE_TYPE = 'local_network_monitor'

function LocalConnectionEventsTable({ sourceId }: { sourceId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['local-network-events', sourceId],
    queryFn: () => logsApi.listEvents({ source_id: sourceId, limit: 20 }),
    refetchInterval: 15_000,
  })

  if (isLoading) {
    return <div className="text-sm text-slate-500 py-4">Loading observed connections…</div>
  }
  if (error) {
    return <PanelError message="Could not load events for this source." />
  }

  const events = data?.events || data || []

  if (!Array.isArray(events) || events.length === 0) {
    return (
      <div className="flex items-start gap-2 text-sm text-slate-400 py-3">
        <Info className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
        <p>
          No connections observed yet. New entries appear here as this collector polls the backend
          host's real connection table (every ~15s once running) - nothing is shown until a genuine
          poll produces data.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/50 text-slate-400 text-xs uppercase">
          <tr>
            <th className="px-3 py-2 text-left">Local</th>
            <th className="px-3 py-2 text-left">Remote</th>
            <th className="px-3 py-2 text-left">Protocol</th>
            <th className="px-3 py-2 text-left">Status</th>
            <th className="px-3 py-2 text-left">Process</th>
            <th className="px-3 py-2 text-left">Observed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {events.map((event: any) => {
            const f = event.extracted_fields || {}
            return (
              <tr key={event.id || event.event_id}>
                <td className="px-3 py-2 font-mono text-xs text-slate-300">
                  {f.local_addr ? `${f.local_addr}:${f.local_port ?? '-'}` : '—'}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-300">
                  {f.remote_addr ? `${f.remote_addr}:${f.remote_port ?? '-'}` : '— (listening)'}
                </td>
                <td className="px-3 py-2 text-slate-400 text-xs uppercase">{f.protocol || '—'}</td>
                <td className="px-3 py-2 text-slate-400 text-xs">{f.status || '—'}</td>
                <td className="px-3 py-2 text-slate-300 text-xs">{f.process_name || '—'}</td>
                <td className="px-3 py-2 text-slate-500 text-xs">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '—'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ConnectThisComputerPanel() {
  const toast = useToast()
  const queryClient = useQueryClient()

  const { data, isLoading, error } = useQuery({
    queryKey: ['log-sources', LOCAL_MONITOR_SOURCE_TYPE],
    queryFn: () => logsApi.listSources({ source_type: LOCAL_MONITOR_SOURCE_TYPE }),
  })

  const createMutation = useMutation({
    mutationFn: () =>
      logsApi.createSource({
        name: 'This Computer (Local Monitor)',
        description: 'Active TCP/UDP connections and interfaces on this backend host.',
        source_type: LOCAL_MONITOR_SOURCE_TYPE,
      }),
    onSuccess: () => {
      toast.success('Connecting…', 'Starting the local network collector on this backend host.')
      queryClient.invalidateQueries({ queryKey: ['log-sources', LOCAL_MONITOR_SOURCE_TYPE] })
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || err?.response?.data?.message
      toast.error('Could not connect', detail || 'Failed to create the local network monitor source.')
    },
  })

  if (isLoading) {
    return <div className="text-sm text-slate-500 py-6 text-center">Checking for an existing connection…</div>
  }
  if (error) {
    return (
      <div className="p-6">
        <PanelError message="Could not check for an existing local network monitor source." />
      </div>
    )
  }

  const source = data?.sources?.[0]

  if (!source) {
    return (
      <div className="p-8 text-center">
        <Radar className="w-12 h-12 text-slate-700 mx-auto mb-4" />
        <h3 className="text-white font-medium mb-2">This Computer</h3>
        <p className="text-slate-500 text-sm max-w-md mx-auto mb-5">
          Observe active TCP/UDP connections and network interfaces on the computer running this
          backend. This reads the same connection table a local <code>netstat</code> would show - no
          packet capture, no traffic content, nothing from any other device.
        </p>
        <button
          onClick={() => createMutation.mutate()}
          disabled={createMutation.isPending}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          {createMutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
          Connect this computer
        </button>
      </div>
    )
  }

  return (
    <div className="p-5 space-y-5">
      <SourceCard source={source} onDelete={() => queryClient.invalidateQueries({ queryKey: ['log-sources', LOCAL_MONITOR_SOURCE_TYPE] })} />
      <div>
        <h4 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          Recent Observed Connections
        </h4>
        <div className="bg-slate-800/30 border border-slate-800 rounded-lg">
          <LocalConnectionEventsTable sourceId={source.id} />
        </div>
      </div>
    </div>
  )
}

function OfficeNetworkNotAvailablePanel() {
  return (
    <div className="p-6 flex items-start gap-3 bg-slate-800/30 border border-slate-800 rounded-lg">
      <Info className="w-5 h-5 text-slate-500 flex-shrink-0 mt-0.5" />
      <div>
        <p className="text-slate-300 text-sm font-medium">Wi-Fi / office network: integration not available</p>
        <p className="text-slate-500 text-xs mt-1 max-w-xl">
          Monitoring a router, firewall, or office Wi-Fi network requires that device to actually send
          its traffic data here (e.g. via syslog or a flow export) - a Wi-Fi password alone cannot do
          this. No such receiver is configured on this server today, so this capability is honestly
          unavailable rather than simulated.
        </p>
      </div>
    </div>
  )
}

function LocalNetworkMonitorTab() {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
      <ConnectThisComputerPanel />
      <OfficeNetworkNotAvailablePanel />
    </div>
  )
}

// =============================================================================
// Network Scan tab - the existing authorized active-scan form, with the
// request contract fixed to match the real backend schema.
// =============================================================================

function NetworkScanTab() {
  const [formData, setFormData] = useState<{ target: string; scanType: 'basic' | 'service' | 'full'; authorized: boolean }>({
    target: '',
    scanType: 'basic',
    authorized: false,
  })
  const [result, setResult] = useState<any>(null)

  const { data: moduleAccuracy } = useQuery({
    queryKey: ['networkModuleAccuracy'],
    queryFn: () => feedbackApi.getNetworkModuleAccuracy(),
    staleTime: 30_000,
  })

  const analyzeMutation = useMutation({
    mutationFn: () =>
      analysisApi.analyzeNetwork({
        target: formData.target,
        scan_type: formData.scanType,
        authorized: formData.authorized,
      }),
    onSuccess: (data) => setResult(data),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setResult(null)
    analyzeMutation.mutate()
  }

  const handleReset = () => {
    setFormData({ target: '', scanType: 'basic', authorized: false })
    setResult(null)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Input Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-6 py-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Scan Configuration
          </h2>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="flex items-start gap-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
            <p className="text-yellow-400/80 text-xs">
              Only scan networks and systems you are authorized to test. Unauthorized scanning may be illegal.
            </p>
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-1">Target *</label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                required
                value={formData.target}
                onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                placeholder="IP address or CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-1">Scan Type</label>
            <select
              value={formData.scanType}
              onChange={(e) => setFormData({ ...formData, scanType: e.target.value as 'basic' | 'service' | 'full' })}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="basic">Basic (host discovery + common ports)</option>
              <option value="service">Service (service &amp; version detection)</option>
              <option value="full">Full (comprehensive scan)</option>
            </select>
          </div>

          <label className="flex items-start gap-2.5 p-3 bg-slate-800/50 border border-slate-700 rounded-lg cursor-pointer">
            <input
              type="checkbox"
              checked={formData.authorized}
              onChange={(e) => setFormData({ ...formData, authorized: e.target.checked })}
              className="mt-0.5 w-4 h-4 accent-cyan-500"
            />
            <span className="text-sm text-slate-300 flex items-start gap-1.5">
              <Lock className="w-3.5 h-3.5 mt-0.5 flex-shrink-0 text-slate-500" />
              I confirm I am authorized to scan this target
            </span>
          </label>

          <div className="flex gap-3 pt-2">
            <button
              type="submit"
              disabled={analyzeMutation.isPending || !formData.authorized}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              {analyzeMutation.isPending ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  Start Scan
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleReset}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
            >
              Reset
            </button>
          </div>
        </form>
      </div>

      {/* Results */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-6 py-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Scan Results
          </h2>
        </div>
        <div className="p-6">
          {analyzeMutation.error && (
            <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-lg mb-4">
              <XCircle className="w-5 h-5 text-red-400" />
              <p className="text-red-400">
                Scan failed. {(analyzeMutation.error as any)?.response?.data?.detail || 'Please check the target and try again.'}
              </p>
            </div>
          )}

          {!result ? (
            <div className="text-center py-12">
              <Network className="w-16 h-16 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-500">Configure and start a scan to see results</p>
            </div>
          ) : (
            <div className="space-y-6">
              {result.data_source === 'simulated' && (
                <div className="flex items-start gap-3 p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                  <FlaskConical className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-orange-400 font-medium">Simulated data — not a real scan</p>
                    <p className="text-orange-400/70 text-sm">
                      {result.scan_warnings?.[0] || 'nmap is not available on this server, so the results below are simulated for demonstration purposes.'}
                    </p>
                  </div>
                </div>
              )}
              {result.data_source !== 'simulated' && result.scan_warnings?.length > 0 && (
                <div className="flex items-start gap-3 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <p className="text-yellow-400/80 text-sm">{result.scan_warnings[0]}</p>
                </div>
              )}

              <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg">
                <div>
                  <p className="text-white font-medium">Target: {result.target}</p>
                  <p className="text-sm text-slate-400">
                    {result.findings?.length || 0} findings
                    {result.data_source && <> · source: {result.data_source === 'simulated' ? 'simulated' : 'nmap'}</>}
                  </p>
                </div>
                <RiskGauge score={result.risk_score || 0} />
              </div>

              {result.findings?.length > 0 && result.result_id && (
                <div className="p-3 bg-slate-800/30 border border-slate-800 rounded-lg">
                  <NetworkFeedbackActions analysisId={result.result_id} />
                </div>
              )}

              <div className="flex items-center gap-3">
                <span className="text-slate-400">Severity:</span>
                <SeverityBadge severity={result.severity || 'info'} />
              </div>

              {result.findings?.length > 0 && (
                <div>
                  <p className="text-sm text-slate-400 mb-2">Security Findings</p>
                  <div className="space-y-2">
                    {result.findings.map((finding: any, idx: number) => (
                      <div key={finding.finding_id || idx} className="p-3 bg-slate-800 rounded-lg">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-2">
                            <AlertTriangle
                              className={clsx(
                                'w-4 h-4 mt-0.5 flex-shrink-0',
                                finding.severity === 'critical' || finding.severity === 'high' ? 'text-red-400' :
                                finding.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                              )}
                            />
                            <div>
                              <p className="text-sm font-medium text-white">{finding.name}</p>
                              <p className="text-xs text-slate-400 mt-0.5">{finding.description}</p>
                              {finding.evidence?.length > 0 && (
                                <p className="text-xs text-slate-500 mt-1 font-mono">{finding.evidence.join(' · ')}</p>
                              )}
                            </div>
                          </div>
                          <SeverityBadge severity={finding.severity} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.recommendations?.length > 0 && (
                <div>
                  <p className="text-sm text-slate-400 mb-2">Recommendations</p>
                  <ul className="space-y-1">
                    {result.recommendations.map((rec: string, idx: number) => (
                      <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="border-t border-slate-800 pt-4">
                <h4 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Module Performance
                </h4>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center gap-2 text-sm">
                    <Shield className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="text-white">NetworkAgent (Rule Engine)</span>
                  </div>
                  <span className="text-xs text-slate-400">
                    {!moduleAccuracy || moduleAccuracy.confirmed_count + moduleAccuracy.false_positive_count === 0 ? (
                      <>No feedback yet — {moduleAccuracy?.total_analyses ?? 0} analyses run, 0 reviewed</>
                    ) : (
                      <>
                        {moduleAccuracy.confirmed_count} of {moduleAccuracy.confirmed_count + moduleAccuracy.false_positive_count} reviewed
                        findings confirmed ({moduleAccuracy.accuracy_percent}%)
                      </>
                    )}
                  </span>
                </div>
                <div className="mt-2 p-3 bg-slate-800/50 border border-slate-700 rounded-lg flex items-start gap-2">
                  <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-slate-400">
                    About Module Accuracy: this is a real, feedback-derived signal, not a supervised benchmark. It
                    reflects the ratio of "Confirm" to "False Positive" feedback submitted by analysts above, so it
                    starts sparse and grows more reliable as more analyses are reviewed. It does not evaluate
                    whether a scan used real nmap data or simulated data — see the notice above the risk score
                    for that.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// =============================================================================
// Findings tab - real findings flattened from persisted network scan
// history (not a session-only cache, not fabricated).
// =============================================================================

function FindingsTab() {
  const { data: history, isLoading, error } = useQuery({
    queryKey: ['networkHistory', 'findings'],
    queryFn: () => analysisApi.getHistory({ analysis_type: 'network', limit: 20 }),
  })

  if (isLoading) {
    return <div className="text-center py-12 text-slate-500">Loading findings…</div>
  }

  if (error) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <PanelError message="Could not load findings history." />
      </div>
    )
  }

  const rows: Array<{ entryId: string; analyzedAt: string; target: string; finding: any }> = []
  for (const entry of history || []) {
    for (const finding of entry.findings || []) {
      rows.push({
        entryId: entry.id,
        analyzedAt: entry.analyzed_at,
        target: entry.context?.target || 'unknown',
        finding,
      })
    }
  }

  if (rows.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <EmptyState
          icon={Server}
          title="No findings yet"
          description="Findings from past network scans will appear here. Run a scan in the Network Scan tab to get started."
        />
      </div>
    )
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/50 text-slate-400 text-xs uppercase">
          <tr>
            <th className="px-4 py-3 text-left">Finding</th>
            <th className="px-4 py-3 text-left">Severity</th>
            <th className="px-4 py-3 text-left">Target</th>
            <th className="px-4 py-3 text-left">Scanned</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {rows.map((row, idx) => (
            <tr key={`${row.entryId}-${idx}`}>
              <td className="px-4 py-3">
                <p className="text-white font-medium">{row.finding.name}</p>
                <p className="text-xs text-slate-500">{row.finding.description}</p>
              </td>
              <td className="px-4 py-3"><SeverityBadge severity={row.finding.severity} /></td>
              <td className="px-4 py-3 text-slate-300 font-mono text-xs">{row.target}</td>
              <td className="px-4 py-3 text-slate-400 text-xs">{new Date(row.analyzedAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// =============================================================================
// History tab - paginated real network analysis history.
// =============================================================================

const HISTORY_PAGE_SIZE = 25

function HistoryTab() {
  const [offset, setOffset] = useState(0)

  const { data: history, isLoading, error } = useQuery({
    queryKey: ['networkHistory', 'history', offset],
    queryFn: () => analysisApi.getHistory({ analysis_type: 'network', limit: HISTORY_PAGE_SIZE, offset }),
  })

  if (isLoading) {
    return <div className="text-center py-12 text-slate-500">Loading history…</div>
  }

  if (error) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
        <PanelError message="Could not load analysis history." />
      </div>
    )
  }

  if (!history || history.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <EmptyState
          icon={HistoryIcon}
          title="No history yet"
          description="Network analyses you run will be recorded here (requires the server's database to be configured)."
        />
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-800/50 text-slate-400 text-xs uppercase">
            <tr>
              <th className="px-4 py-3 text-left">Analyzed</th>
              <th className="px-4 py-3 text-left">Target</th>
              <th className="px-4 py-3 text-left">Scan Type</th>
              <th className="px-4 py-3 text-left">Classification</th>
              <th className="px-4 py-3 text-left">Severity</th>
              <th className="px-4 py-3 text-left">Risk</th>
              <th className="px-4 py-3 text-left">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {history.map((entry: any) => (
              <tr key={entry.id}>
                <td className="px-4 py-3 text-slate-400 text-xs">{new Date(entry.analyzed_at).toLocaleString()}</td>
                <td className="px-4 py-3 text-slate-200 font-mono text-xs">{entry.context?.target || '—'}</td>
                <td className="px-4 py-3 text-slate-300 text-xs">{entry.context?.scan_type || '—'}</td>
                <td className="px-4 py-3 text-slate-300">{entry.classification}</td>
                <td className="px-4 py-3"><SeverityBadge severity={entry.severity} /></td>
                <td className="px-4 py-3 text-slate-300">{entry.risk_score}</td>
                <td className="px-4 py-3 text-slate-400 text-xs">
                  {entry.processing_time_ms != null ? `${Math.round(entry.processing_time_ms)}ms` : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between">
        <button
          onClick={() => setOffset(Math.max(0, offset - HISTORY_PAGE_SIZE))}
          disabled={offset === 0}
          className="px-3 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg disabled:opacity-40"
        >
          Previous
        </button>
        <button
          onClick={() => setOffset(offset + HISTORY_PAGE_SIZE)}
          disabled={history.length < HISTORY_PAGE_SIZE}
          className="px-3 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}

// =============================================================================
// Main Page
// =============================================================================

type TabId = 'analyze' | 'monitor' | 'scan' | 'findings' | 'history'
const TAB_IDS: TabId[] = ['analyze', 'monitor', 'scan', 'findings', 'history']

export function NetworkAnalysisPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const rawTab = searchParams.get('tab')
  const activeTab: TabId = TAB_IDS.includes(rawTab as TabId) ? (rawTab as TabId) : 'analyze'
  const setActiveTab = (id: TabId) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('tab', id)
      return next
    })
  }

  const tabs: { id: TabId; label: string; icon: typeof Network }[] = [
    { id: 'analyze', label: 'Analyze', icon: Search },
    { id: 'monitor', label: 'Local Network Monitor', icon: Radar },
    { id: 'scan', label: 'Network Scan', icon: Network },
    { id: 'findings', label: 'Findings', icon: ListChecks },
    { id: 'history', label: 'History', icon: HistoryIcon },
  ]

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Network Analysis</h1>
        <p className="text-slate-400 mt-1">Look up, scan, and review network targets for security risk</p>
      </div>

      <div className="flex gap-1 border-b border-slate-800 overflow-x-auto">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap',
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

      {activeTab === 'analyze' && <AnalyzeTab />}
      {activeTab === 'monitor' && <LocalNetworkMonitorTab />}
      {activeTab === 'scan' && <NetworkScanTab />}
      {activeTab === 'findings' && <FindingsTab />}
      {activeTab === 'history' && <HistoryTab />}
    </div>
  )
}
