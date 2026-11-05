/**
 * CyberGuard AI - Correlation Page
 *
 * Review persisted correlations and re-run analysis over persisted findings.
 */

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  GitMerge,
  Plus,
  Trash2,
  Play,
  RefreshCw,
  AlertTriangle,
  Users,
  Shield,
  Database,
  Link2,
} from 'lucide-react'
import { clsx } from 'clsx'
import { correlationApi } from '@/services/api'

interface EventDraft {
  event_id: string
  domain: string
  timestamp: string
  ips: string
  users: string
  risk_score: string
  severity: string
}

function emptyEvent(): EventDraft {
  return {
    event_id: '',
    domain: 'email',
    timestamp: new Date().toISOString().slice(0, 16),
    ips: '',
    users: '',
    risk_score: '50',
    severity: 'medium',
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
    high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
    medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
    info: { bg: 'bg-slate-500/20', text: 'text-slate-400' },
  }
  const { bg, text } = config[severity] || config.info
  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', bg, text)}>
      {severity.toUpperCase()}
    </span>
  )
}

export function CorrelationPage() {
  const [activeTab] = useState<'analyze' | 'persisted'>('persisted')
  const [events, setEvents] = useState<EventDraft[]>([emptyEvent(), emptyEvent()])
  const [timeWindowHours, setTimeWindowHours] = useState(24)
  const [recorrelateIds, setRecorrelateIds] = useState('')

  const {
    data: activities,
    refetch: refetchActivities,
    isFetching: isFetchingActivities,
  } = useQuery({
    queryKey: ['correlation', 'activities'],
    queryFn: () => correlationApi.getActivities(),
    enabled: activeTab === 'persisted',
  })

  const correlateMutation = useMutation({
    mutationFn: (payload: {
      events: Array<{
        event_id: string
        domain: string
        timestamp: string
        ips?: string[]
        users?: string[]
        risk_score?: number
        severity?: string
      }>
      time_window_hours: number
    }) => correlationApi.analyze(payload),
    onSuccess: () => refetchStats(),
  })

  const recorrelateMutation = useMutation({
    mutationFn: (findingIds: string[]) => correlationApi.recorrelate(findingIds),
    onSuccess: () => refetchActivities(),
  })

  const updateEvent = (idx: number, patch: Partial<EventDraft>) => {
    setEvents((prev) => prev.map((e, i) => (i === idx ? { ...e, ...patch } : e)))
  }

  const addEvent = () => setEvents((prev) => [...prev, emptyEvent()])
  const removeEvent = (idx: number) =>
    setEvents((prev) => (prev.length > 1 ? prev.filter((_, i) => i !== idx) : prev))

  const canSubmit = events.every((e) => e.event_id.trim() && e.timestamp)

  const runCorrelation = () => {
    if (!canSubmit) return
    correlateMutation.mutate({
      events: events.map((e) => ({
        event_id: e.event_id.trim(),
        domain: e.domain,
        timestamp: new Date(e.timestamp).toISOString(),
        ips: e.ips.split(',').map((s) => s.trim()).filter(Boolean),
        users: e.users.split(',').map((s) => s.trim()).filter(Boolean),
        risk_score: Number(e.risk_score) || 0,
        severity: e.severity,
      })),
      time_window_hours: timeWindowHours,
    })
  }

  const result = correlateMutation.data

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <GitMerge className="w-6 h-6 text-cyan-400" />
            Event Correlation
          </h1>
          <p className="text-slate-400 mt-1">
            Inspect relationships derived from persisted, tenant-authorized findings.
          </p>
        </div>
        <button
          onClick={() => refetchActivities()}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {activeTab === 'persisted' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Link2 className="w-5 h-5 text-cyan-400" />
                Re-correlate Findings
              </h2>
            </div>
            <p className="text-sm text-slate-400">
              Enter 2 or more existing finding IDs (comma-separated) to re-run the IOC
              Correlation Agent on demand. Running this again on the same findings is
              idempotent - it won't create duplicate records.
            </p>
            <div className="flex items-center gap-3">
              <input
                type="text"
                placeholder="finding-id-1, finding-id-2, ..."
                value={recorrelateIds}
                onChange={(e) => setRecorrelateIds(e.target.value)}
                className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              <button
                onClick={() => {
                  const ids = recorrelateIds.split(',').map((s) => s.trim()).filter(Boolean)
                  if (ids.length >= 2) recorrelateMutation.mutate(ids)
                }}
                disabled={
                  recorrelateMutation.isPending ||
                  recorrelateIds.split(',').map((s) => s.trim()).filter(Boolean).length < 2
                }
                className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                <GitMerge className={clsx('w-4 h-4', recorrelateMutation.isPending && 'animate-pulse')} />
                {recorrelateMutation.isPending ? 'Re-correlating...' : 'Re-correlate'}
              </button>
            </div>
            {recorrelateMutation.isError && (
              <p className="text-sm text-red-400">
                {(recorrelateMutation.error as any)?.response?.data?.detail?.message ||
                  (recorrelateMutation.error as Error).message ||
                  'Re-correlation request failed'}
              </p>
            )}
            {recorrelateMutation.isSuccess && (
              <p className="text-sm text-emerald-400">
                {recorrelateMutation.data.summary}
              </p>
            )}
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Persisted Correlated Activities</h2>
              <button
                onClick={() => refetchActivities()}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
              >
                <RefreshCw className={clsx('w-4 h-4', isFetchingActivities && 'animate-spin')} />
                Refresh
              </button>
            </div>
            {!activities || activities.length === 0 ? (
              <div className="p-12 text-center">
                <Database className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                <p className="text-slate-500">No persisted correlated activities yet</p>
                <p className="text-sm text-slate-600 mt-1">
                  Activities appear here once the automatic pipeline or a re-correlation run persists a group
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800">
                {activities.map((activity: any) => (
                  <div key={activity.correlation_id} className="p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-slate-400">{activity.correlation_id}</span>
                        <span className="px-2 py-0.5 text-xs font-medium rounded bg-slate-800 text-slate-300 uppercase">
                          {activity.correlation_type.replace(/_/g, ' ')}
                        </span>
                        <span
                          className={clsx(
                            'px-2 py-0.5 text-xs font-medium rounded',
                            activity.correlation_bucket === 'on_demand'
                              ? 'bg-cyan-500/20 text-cyan-400'
                              : 'bg-purple-500/20 text-purple-400'
                          )}
                        >
                          {activity.correlation_bucket === 'on_demand' ? 'ON-DEMAND' : 'AUTOMATIC'}
                        </span>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-slate-500">Risk Score</p>
                        <p className="text-lg font-bold text-white">{activity.risk_score}</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <Shield className="w-3 h-3" /> {activity.finding_ids.length} findings
                      </span>
                      <span>Sources: {activity.source_types.join(', ') || 'n/a'}</span>
                      <span>Strength: {(activity.correlation_strength * 100).toFixed(0)}%</span>
                      <span>{new Date(activity.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Event input form */}
      {activeTab === 'analyze' && (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Events to Correlate</h2>
          <div className="flex items-center gap-3">
            <label className="text-sm text-slate-400">Time window (hours)</label>
            <input
              type="number"
              min={1}
              max={168}
              value={timeWindowHours}
              onChange={(e) => setTimeWindowHours(Number(e.target.value))}
              className="w-20 bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        <div className="space-y-3">
          {events.map((event, idx) => (
            <div key={idx} className="grid grid-cols-12 gap-2 items-center bg-slate-800/50 rounded-lg p-3">
              <input
                type="text"
                placeholder="Event ID"
                value={event.event_id}
                onChange={(e) => updateEvent(idx, { event_id: e.target.value })}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <select
                value={event.domain}
                onChange={(e) => updateEvent(idx, { domain: e.target.value })}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="email">Email</option>
                <option value="log">Log</option>
                <option value="network">Network</option>
              </select>
              <input
                type="datetime-local"
                value={event.timestamp}
                onChange={(e) => updateEvent(idx, { timestamp: e.target.value })}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <input
                type="text"
                placeholder="IPs (comma-sep)"
                value={event.ips}
                onChange={(e) => updateEvent(idx, { ips: e.target.value })}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <input
                type="text"
                placeholder="Users (comma-sep)"
                value={event.users}
                onChange={(e) => updateEvent(idx, { users: e.target.value })}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <select
                value={event.severity}
                onChange={(e) => updateEvent(idx, { severity: e.target.value })}
                className="col-span-1 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <button
                onClick={() => removeEvent(idx)}
                disabled={events.length <= 1}
                className="col-span-1 flex items-center justify-center text-slate-500 hover:text-red-400 disabled:opacity-30 disabled:hover:text-slate-500"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between pt-2">
          <button
            onClick={addEvent}
            className="flex items-center gap-2 px-3 py-2 text-sm text-cyan-400 hover:text-cyan-300"
          >
            <Plus className="w-4 h-4" />
            Add Event
          </button>
          <button
            onClick={runCorrelation}
            disabled={!canSubmit || correlateMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <Play className={clsx('w-4 h-4', correlateMutation.isPending && 'animate-pulse')} />
            {correlateMutation.isPending ? 'Correlating...' : 'Run Correlation'}
          </button>
        </div>

        {correlateMutation.isError && (
          <p className="text-sm text-red-400">
            {(correlateMutation.error as any)?.response?.data?.detail?.message ||
              (correlateMutation.error as Error).message ||
              'Correlation request failed'}
          </p>
        )}
      </div>
      )}

      {/* Results */}
      {activeTab === 'analyze' && result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-white">{result.summary.event_count}</p>
              <p className="text-sm text-slate-400">Events Analyzed</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-cyan-400">{result.summary.groups_found}</p>
              <p className="text-sm text-slate-400">Groups Found</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-purple-400">{result.summary.cross_domain_groups}</p>
              <p className="text-sm text-slate-400">Cross-Domain Groups</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-red-400">{result.summary.potential_incidents}</p>
              <p className="text-sm text-slate-400">Potential Incidents</p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <p className="text-2xl font-bold text-white">{result.summary.processing_time_ms.toFixed(1)}ms</p>
              <p className="text-sm text-slate-400">Processing Time</p>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800">
              <h2 className="text-lg font-semibold text-white">Correlation Groups</h2>
            </div>
            {result.groups.length === 0 ? (
              <div className="p-12 text-center">
                <GitMerge className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                <p className="text-slate-500">No correlation groups found</p>
                <p className="text-sm text-slate-600 mt-1">
                  Events didn't share enough indicators within the time window
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800">
                {result.groups.map((group: any) => (
                  <div key={group.group_id} className="p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-slate-400">{group.group_id}</span>
                        <SeverityBadge severity={group.severity} />
                        {group.domains?.length > 1 && (
                          <span className="px-2 py-0.5 text-xs font-medium rounded bg-purple-500/20 text-purple-400">
                            CROSS-DOMAIN
                          </span>
                        )}
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-slate-500">Risk Score</p>
                        <p className="text-lg font-bold text-white">{group.risk_score}</p>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <Shield className="w-3 h-3" /> {group.event_ids?.length || 0} events
                      </span>
                      <span>Domains: {group.domains?.join(', ') || 'n/a'}</span>
                      <span>{group.correlation_count} correlations</span>
                    </div>

                    {group.shared_users?.length > 0 && (
                      <div className="flex items-center gap-2 text-xs">
                        <Users className="w-3 h-3 text-slate-500" />
                        <span className="text-slate-400">Shared users:</span>
                        {group.shared_users.map((u: string) => (
                          <span key={u} className="px-2 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">
                            {u}
                          </span>
                        ))}
                      </div>
                    )}

                    {group.shared_iocs?.length > 0 && (
                      <div className="flex items-start gap-2 text-xs">
                        <AlertTriangle className="w-3 h-3 text-slate-500 mt-0.5" />
                        <span className="text-slate-400">Shared IOCs:</span>
                        <div className="flex flex-wrap gap-1">
                          {group.shared_iocs.map((ioc: any, i: number) => (
                            <span key={i} className="px-2 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">
                              {ioc.type}:{ioc.value}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {group.attack_techniques?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {group.attack_techniques.map((tech: string) => (
                          <span key={tech} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded font-mono">
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
