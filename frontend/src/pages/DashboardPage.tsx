/**
 * CyberGuard AI - Dashboard Page
 *
 * Main dashboard showing system status, recent events, and key metrics.
 * All data comes from actual backend APIs - no fake/hardcoded values.
 */

import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  Activity,
  Shield,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu,
  Mail,
  FileText,
  Network,
  RefreshCw,
  ShieldAlert,
  Eye,
} from 'lucide-react'
import { clsx } from 'clsx'
import { healthApi, alertsApi, eventsApi, reportsApi } from '@/services/api'
import type { ComponentStatus } from '@/types'

// Status badge component
function StatusBadge({ status }: { status: ComponentStatus['status'] }) {
  const config = {
    online: { color: 'bg-emerald-500', text: 'Online', icon: CheckCircle2 },
    offline: { color: 'bg-red-500', text: 'Offline', icon: XCircle },
    degraded: { color: 'bg-yellow-500', text: 'Degraded', icon: AlertTriangle },
    pending: { color: 'bg-slate-500', text: 'Pending', icon: Clock },
  }[status]

  const Icon = config.icon

  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full text-white',
      config.color
    )}>
      <Icon className="w-3 h-3" />
      {config.text}
    </span>
  )
}

// Severity badge
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

// Stat card component
function StatCard({
  title,
  value,
  icon: Icon,
  color,
  subtitle,
  loading,
}: {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  color: string
  subtitle?: string
  loading?: boolean
}) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 card-hover">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-slate-400">{title}</p>
          {loading ? (
            <div className="h-9 w-16 bg-slate-700 animate-pulse rounded mt-1" />
          ) : (
            <p className={clsx('text-3xl font-bold mt-1', color)}>{value}</p>
          )}
          {subtitle && (
            <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg', color.replace('text-', 'bg-') + '/20')}>
          <Icon className={clsx('w-6 h-6', color)} />
        </div>
      </div>
    </div>
  )
}

// Agent status card
function AgentCard({
  name,
  icon: Icon,
  status,
  message
}: {
  name: string
  icon: React.ComponentType<{ className?: string }>
  status: ComponentStatus['status']
  message: string | null
}) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-slate-700 rounded-lg">
          <Icon className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-medium text-white truncate">{name}</h4>
          <p className="text-xs text-slate-500 truncate">{message || 'Ready'}</p>
        </div>
        <StatusBadge status={status} />
      </div>
    </div>
  )
}

// Security score gauge
function SecurityScoreGauge({ score, status }: { score: number; status: string }) {
  const getColor = (s: number) => {
    if (s >= 80) return 'text-emerald-500'
    if (s >= 60) return 'text-yellow-500'
    if (s >= 40) return 'text-orange-500'
    return 'text-red-500'
  }

  return (
    <div className="flex items-center gap-4">
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
            strokeDashoffset={251.2 - (251.2 * score) / 100}
            className={getColor(score)}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={clsx('text-2xl font-bold', getColor(score))}>{score}</span>
        </div>
      </div>
      <div>
        <p className={clsx('text-lg font-semibold', getColor(score))}>{status}</p>
        <p className="text-sm text-slate-400">Security Score</p>
      </div>
    </div>
  )
}

export function DashboardPage() {
  // Fetch detailed health status from backend
  const { data: health, isLoading: healthLoading, error: healthError, refetch: refetchHealth } = useQuery({
    queryKey: ['health', 'detailed'],
    queryFn: healthApi.detailed,
    refetchInterval: 30000,
  })

  // Fetch alert statistics
  const { data: alertStats, isLoading: alertsLoading } = useQuery({
    queryKey: ['alerts', 'statistics'],
    queryFn: alertsApi.getStatistics,
    refetchInterval: 30000,
  })

  // Fetch event statistics
  const { data: eventStats, isLoading: eventsLoading } = useQuery({
    queryKey: ['events', 'statistics'],
    queryFn: eventsApi.getStatistics,
    refetchInterval: 30000,
  })

  // Fetch executive summary
  const { data: executive } = useQuery({
    queryKey: ['reports', 'executive'],
    queryFn: () => reportsApi.getExecutive(24),
    refetchInterval: 60000,
  })

  // Fetch recent events
  const { data: recentEvents } = useQuery({
    queryKey: ['events', 'recent'],
    queryFn: () => eventsApi.list({ limit: 5 }),
    refetchInterval: 15000,
  })

  // Fetch recent alerts
  const { data: recentAlerts } = useQuery({
    queryKey: ['alerts', 'recent'],
    queryFn: () => alertsApi.list({ limit: 5 }),
    refetchInterval: 15000,
  })

  const isLoading = healthLoading || alertsLoading || eventsLoading

  // Format timestamp
  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString()
  }

  const formatDateTime = (timestamp: string) => {
    const d = new Date(timestamp)
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  // Refresh all data
  const refreshAll = () => {
    refetchHealth()
  }

  return (
    <div className="p-6 space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 mt-1">
            AI-Powered Security Operations Center
          </p>
        </div>
        <button
          onClick={refreshAll}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Error state */}
      {healthError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-3">
          <XCircle className="w-5 h-5 text-red-500" />
          <div>
            <p className="text-red-400 font-medium">Backend Connection Error</p>
            <p className="text-red-400/70 text-sm">Unable to connect to CyberGuard AI backend</p>
          </div>
        </div>
      )}

      {/* Executive Summary Banner */}
      {executive && (
        <div className={clsx(
          'rounded-xl p-6 flex items-center justify-between',
          executive.status_color === 'green' && 'bg-emerald-500/10 border border-emerald-500/30',
          executive.status_color === 'yellow' && 'bg-yellow-500/10 border border-yellow-500/30',
          executive.status_color === 'orange' && 'bg-orange-500/10 border border-orange-500/30',
          executive.status_color === 'red' && 'bg-red-500/10 border border-red-500/30',
        )}>
          <div className="flex items-center gap-6">
            <SecurityScoreGauge score={executive.security_score} status={executive.status} />
            <div className="border-l border-slate-700 pl-6">
              <p className="text-sm text-slate-400 mb-2">24-Hour Summary</p>
              <div className="flex gap-6">
                <div>
                  <p className="text-2xl font-bold text-white">{executive.highlights?.total_events || 0}</p>
                  <p className="text-xs text-slate-500">Events</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-orange-400">{executive.highlights?.open_alerts || 0}</p>
                  <p className="text-xs text-slate-500">Open Alerts</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-red-400">{executive.highlights?.critical_findings || 0}</p>
                  <p className="text-xs text-slate-500">Critical</p>
                </div>
              </div>
            </div>
          </div>
          {executive.recommendations && executive.recommendations.length > 0 && (
            <div className="max-w-md">
              <p className="text-sm font-medium text-slate-300 mb-1">Top Recommendation</p>
              <p className="text-sm text-slate-400">{executive.recommendations[0]}</p>
            </div>
          )}
        </div>
      )}

      {/* System status banner (fallback if no executive data) */}
      {!executive && health && (
        <div className={clsx(
          'rounded-xl p-4 flex items-center justify-between',
          health.status === 'healthy' && 'bg-emerald-500/10 border border-emerald-500/30',
          health.status === 'degraded' && 'bg-yellow-500/10 border border-yellow-500/30',
          health.status === 'unhealthy' && 'bg-red-500/10 border border-red-500/30',
        )}>
          <div className="flex items-center gap-3">
            <Shield className={clsx(
              'w-6 h-6',
              health.status === 'healthy' && 'text-emerald-500',
              health.status === 'degraded' && 'text-yellow-500',
              health.status === 'unhealthy' && 'text-red-500',
            )} />
            <div>
              <p className={clsx(
                'font-medium',
                health.status === 'healthy' && 'text-emerald-400',
                health.status === 'degraded' && 'text-yellow-400',
                health.status === 'unhealthy' && 'text-red-400',
              )}>
                System Status: {health.status.charAt(0).toUpperCase() + health.status.slice(1)}
              </p>
              <p className="text-sm text-slate-400">
                Version {health.version} • {health.environment} • Last checked: {formatTime(health.timestamp)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard
          title="Active Alerts"
          value={alertStats?.open || 0}
          icon={ShieldAlert}
          color="text-orange-500"
          subtitle={`${alertStats?.total || 0} total alerts`}
          loading={alertsLoading}
        />
        <StatCard
          title="Security Events"
          value={eventStats?.total || 0}
          icon={Activity}
          color="text-cyan-500"
          subtitle={`${eventStats?.by_severity?.high || 0} high severity`}
          loading={eventsLoading}
        />
        <StatCard
          title="Active Agents"
          value={health?.components ? Object.values(health.components).filter(c => c.status === 'online').length : 0}
          icon={Cpu}
          color="text-emerald-500"
          subtitle={`of ${health?.components ? Object.keys(health.components).length : 0} total`}
          loading={healthLoading}
        />
      </div>

      {/* Three column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Agent Status</h2>
            <p className="text-sm text-slate-500">Multi-agent security analysis</p>
          </div>
          <div className="p-4 space-y-3">
            {healthLoading ? (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="w-6 h-6 text-slate-500 animate-spin" />
              </div>
            ) : health?.components ? (
              <>
                <AgentCard
                  name="Email Security Agent"
                  icon={Mail}
                  status={health.components.email_agent?.status || 'pending'}
                  message={health.components.email_agent?.message || null}
                />
                <AgentCard
                  name="Log Analyzer Agent"
                  icon={FileText}
                  status={health.components.log_agent?.status || 'pending'}
                  message={health.components.log_agent?.message || null}
                />
                <AgentCard
                  name="Network Analysis Agent"
                  icon={Network}
                  status={health.components.network_agent?.status || 'pending'}
                  message={health.components.network_agent?.message || null}
                />
                <AgentCard
                  name="AI Analyst (LLM)"
                  icon={Cpu}
                  status={health.components.ai?.status || 'pending'}
                  message={health.components.ai?.message || null}
                />
              </>
            ) : (
              <p className="text-slate-500 text-center py-4">No agent data available</p>
            )}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
              <p className="text-sm text-slate-500">Latest security alerts</p>
            </div>
            <a href="/alerts" className="text-sm text-cyan-400 hover:text-cyan-300">View all →</a>
          </div>
          <div className="divide-y divide-slate-800">
            {recentAlerts?.alerts && recentAlerts.alerts.length > 0 ? (
              recentAlerts.alerts.slice(0, 5).map((alert: any) => (
                <div key={alert.id} className="px-4 py-3 hover:bg-slate-800/50 transition-colors">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">{alert.title}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{formatDateTime(alert.created_at)}</p>
                    </div>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                </div>
              ))
            ) : (
              <div className="p-8 text-center">
                <ShieldAlert className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                <p className="text-slate-500 text-sm">No alerts yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Recent Events */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Recent Events</h2>
              <p className="text-sm text-slate-500">Latest security events</p>
            </div>
            <a href="/events" className="text-sm text-cyan-400 hover:text-cyan-300">View all →</a>
          </div>
          <div className="divide-y divide-slate-800">
            {recentEvents?.events && recentEvents.events.length > 0 ? (
              recentEvents.events.slice(0, 5).map((event: any) => (
                <div key={event.id} className="px-4 py-3 hover:bg-slate-800/50 transition-colors">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs px-1.5 py-0.5 bg-slate-700 text-slate-300 rounded">
                          {event.event_type}
                        </span>
                        <span className="text-xs text-slate-500">{event.source}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{formatDateTime(event.created_at)}</p>
                    </div>
                    <SeverityBadge severity={event.severity} />
                  </div>
                </div>
              ))
            ) : (
              <div className="p-8 text-center">
                <Activity className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                <p className="text-slate-500 text-sm">No events yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Alert Distribution</h2>
            <p className="text-sm text-slate-500">By severity level</p>
          </div>
          <div className="p-6">
            {alertStats?.by_severity ? (
              <div className="space-y-4">
                {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                  const count = alertStats.by_severity[severity] || 0
                  const total = alertStats.total || 1
                  const pct = Math.round((count / total) * 100) || 0
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
                          className={clsx('h-full rounded-full transition-all', colors[severity])}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-slate-500 text-center">No data available</p>
            )}
          </div>
        </div>

        {/* Event Types */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-white">Event Types</h2>
            <p className="text-sm text-slate-500">By category</p>
          </div>
          <div className="p-6">
            {eventStats?.by_type && Object.keys(eventStats.by_type).length > 0 ? (
              <div className="space-y-4">
                {Object.entries(eventStats.by_type).map(([type, count]) => {
                  const total = eventStats.total || 1
                  const pct = Math.round(((count as number) / total) * 100) || 0
                  const icons: Record<string, typeof Mail> = {
                    email: Mail,
                    log: FileText,
                    network: Network,
                  }
                  const Icon = icons[type] || Activity
                  return (
                    <div key={type} className="flex items-center gap-3">
                      <div className="p-2 bg-slate-800 rounded-lg">
                        <Icon className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between text-sm mb-1">
                          <span className="text-slate-400 capitalize">{type}</span>
                          <span className="text-white font-medium">{count as number}</span>
                        </div>
                        <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-cyan-500 rounded-full transition-all"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-slate-500 text-center">No data available</p>
            )}
          </div>
        </div>
      </div>

      {/* Infrastructure Health */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="px-6 py-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white">Infrastructure Health</h2>
          <p className="text-sm text-slate-500">Core system components</p>
        </div>
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {healthLoading ? (
            <div className="col-span-full flex items-center justify-center py-8">
              <RefreshCw className="w-6 h-6 text-slate-500 animate-spin" />
            </div>
          ) : health?.components ? (
            <>
              <AgentCard
                name="Detection Engine"
                icon={Eye}
                status={health.components.detection?.status || 'pending'}
                message={health.components.detection?.message || null}
              />
              <AgentCard
                name="PostgreSQL Database"
                icon={Activity}
                status={health.components.database?.status || 'pending'}
                message={health.components.database?.message || null}
              />
              <AgentCard
                name="Redis Cache"
                icon={Activity}
                status={health.components.redis?.status || 'pending'}
                message={health.components.redis?.message || null}
              />
            </>
          ) : (
            <p className="col-span-full text-slate-500 text-center py-4">No component data available</p>
          )}
        </div>
      </div>
    </div>
  )
}
