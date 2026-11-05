/**
 * CyberGuard AI - Agent Management Page
 *
 * View and manage security analysis agents.
 */

import { useQuery } from '@tanstack/react-query'
import {
  Cpu,
  Mail,
  FileText,
  Network,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Activity,
  Brain,
  Database,
  Zap,
  Fingerprint,
  GitMerge,
  ShieldAlert,
  FileBarChart,
} from 'lucide-react'
import { clsx } from 'clsx'
import { healthApi, detectionApi } from '@/services/api'

// Status badge
function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; text: string; icon: typeof CheckCircle2 }> = {
    online: { color: 'bg-emerald-500', text: 'Online', icon: CheckCircle2 },
    offline: { color: 'bg-red-500', text: 'Offline', icon: XCircle },
    degraded: { color: 'bg-yellow-500', text: 'Degraded', icon: AlertTriangle },
    pending: { color: 'bg-slate-500', text: 'Pending', icon: Clock },
  }
  const { color, text, icon: Icon } = config[status] || config.pending

  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full text-white',
      color
    )}>
      <Icon className="w-3 h-3" />
      {text}
    </span>
  )
}

// Agent card component
function AgentCard({
  name,
  description,
  icon: Icon,
  status,
  message,
  stats,
}: {
  name: string
  description: string
  icon: typeof Mail
  status: string
  message: string | null
  stats?: { label: string; value: string | number }[]
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className={clsx(
              'w-14 h-14 rounded-xl flex items-center justify-center',
              status === 'online' ? 'bg-cyan-500/20' : 'bg-slate-800'
            )}>
              <Icon className={clsx(
                'w-7 h-7',
                status === 'online' ? 'text-cyan-400' : 'text-slate-500'
              )} />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">{name}</h3>
              <p className="text-sm text-slate-400">{description}</p>
            </div>
          </div>
          <StatusBadge status={status} />
        </div>

        {message && (
          <p className="mt-4 text-sm text-slate-500 bg-slate-800/50 rounded-lg px-3 py-2">
            {message}
          </p>
        )}

        {stats && stats.length > 0 && (
          <div className="mt-4 grid grid-cols-3 gap-3">
            {stats.map((stat, idx) => (
              <div key={idx} className="bg-slate-800/50 rounded-lg p-3 text-center">
                <p className="text-xl font-bold text-white">{stat.value}</p>
                <p className="text-xs text-slate-500">{stat.label}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="px-6 py-3 bg-slate-800/30 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {status === 'online' ? 'Running normally' : 'Not available'}
        </span>
        <div className={clsx(
          'w-2 h-2 rounded-full',
          status === 'online' && 'bg-emerald-500 animate-pulse'
        )} />
      </div>
    </div>
  )
}

export function AgentsPage() {
  // Fetch health status
  const { data: health, isLoading, refetch } = useQuery({
    queryKey: ['health', 'detailed'],
    queryFn: healthApi.detailed,
    refetchInterval: 30000,
  })

  // Fetch detection stats
  const { data: detectionStats } = useQuery({
    queryKey: ['detection', 'statistics'],
    queryFn: detectionApi.getStatistics,
  })

  const components = health?.components || {}

  const agentKeys = [
    'email_agent', 'log_agent', 'network_agent', 'threat_intel_agent',
    'ioc_correlation_agent', 'incident_response_agent', 'reporting_agent',
  ]
  const onlineCount = agentKeys.filter((key) => components[key]?.status === 'online').length
  const totalCount = agentKeys.length

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Agent Management</h1>
          <p className="text-slate-400 mt-1">Monitor and manage security analysis agents</p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', isLoading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/20 rounded-lg">
              <Zap className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{onlineCount}/{totalCount}</p>
              <p className="text-sm text-slate-400">Agents Online</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{detectionStats?.rules?.total_rules || 0}</p>
              <p className="text-sm text-slate-400">Detection Rules</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Database className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{detectionStats?.iocs?.total || 0}</p>
              <p className="text-sm text-slate-400">IOC Signatures</p>
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Agents */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Analysis Agents</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          <AgentCard
            name="Email Security Agent"
            description="Analyzes emails for phishing, malware, and social engineering"
            icon={Mail}
            status={components.email_agent?.status || 'pending'}
            message={components.email_agent?.message || null}
            stats={[
              { label: 'Detection Rules', value: detectionStats?.rules?.total_rules ?? 'N/A' },
              { label: 'IOC Signatures', value: detectionStats?.iocs?.total ?? 'N/A' },
            ]}
          />
          <AgentCard
            name="Log Analyzer Agent"
            description="Detects anomalies and threats in system and security logs"
            icon={FileText}
            status={components.log_agent?.status || 'pending'}
            message={components.log_agent?.message || null}
            stats={[
              { label: 'Detection Rules', value: detectionStats?.rules?.enabled ?? 'N/A' },
              { label: 'Anomaly Detection', value: detectionStats?.anomaly?.enabled ? 'Active' : 'Inactive' },
            ]}
          />
          <AgentCard
            name="Network Analysis Agent"
            description="Scans networks for vulnerabilities and suspicious activity"
            icon={Network}
            status={components.network_agent?.status || 'pending'}
            message={components.network_agent?.message || null}
          />
          <AgentCard
            name="Threat Intelligence Agent"
            description="Enriches supported indicators using configured external providers"
            icon={Fingerprint}
            status={components.threat_intel_agent?.status || 'pending'}
            message={components.threat_intel_agent?.message || null}
            stats={[
              { label: 'Last Run', value: components.threat_intel_agent?.last_run ? new Date(components.threat_intel_agent.last_run).toLocaleString() : 'Never' },
              { label: 'Successful', value: components.threat_intel_agent?.last_successful_run ? new Date(components.threat_intel_agent.last_successful_run).toLocaleString() : 'Never' },
              { label: 'Errors', value: components.threat_intel_agent?.error_count ?? 0 },
            ]}
          />
          <AgentCard
            name="IOC Correlation Agent"
            description="Reuses the shared correlation engine over tenant-authorized persisted findings"
            icon={GitMerge}
            status={components.ioc_correlation_agent?.status || 'pending'}
            message={components.ioc_correlation_agent?.message || null}
            stats={[
              { label: 'Last Run', value: components.ioc_correlation_agent?.last_run ? new Date(components.ioc_correlation_agent.last_run).toLocaleString() : 'Never' },
              { label: 'Successful', value: components.ioc_correlation_agent?.last_successful_run ? new Date(components.ioc_correlation_agent.last_successful_run).toLocaleString() : 'Never' },
              { label: 'Errors', value: components.ioc_correlation_agent?.error_count ?? 0 },
            ]}
          />
          <AgentCard
            name="Incident Response Agent"
            description="Creates evidence-linked investigations from qualifying findings; response actions remain manual"
            icon={ShieldAlert}
            status={components.incident_response_agent?.status || 'pending'}
            message={components.incident_response_agent?.message || null}
            stats={[
              { label: 'Last Run', value: components.incident_response_agent?.last_run ? new Date(components.incident_response_agent.last_run).toLocaleString() : 'Never' },
              { label: 'Successful', value: components.incident_response_agent?.last_successful_run ? new Date(components.incident_response_agent.last_successful_run).toLocaleString() : 'Never' },
              { label: 'Errors', value: components.incident_response_agent?.error_count ?? 0 },
            ]}
          />
          <AgentCard
            name="Reporting Agent"
            description="Builds summaries from persisted, authorized events and alerts"
            icon={FileBarChart}
            status={components.reporting_agent?.status || 'pending'}
            message={components.reporting_agent?.message || null}
            stats={[
              { label: 'Last Run', value: components.reporting_agent?.last_run ? new Date(components.reporting_agent.last_run).toLocaleString() : 'Never' },
              { label: 'Successful', value: components.reporting_agent?.last_successful_run ? new Date(components.reporting_agent.last_successful_run).toLocaleString() : 'Never' },
              { label: 'Errors', value: components.reporting_agent?.error_count ?? 0 },
            ]}
          />
        </div>
      </div>

      {/* Core Services */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Core Services</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          <AgentCard
            name="AI Analyst (LLM)"
            description="Provides contextual threat analysis and recommendations"
            icon={Brain}
            status={components.ai?.status || 'pending'}
            message={components.ai?.message || null}
          />
          <AgentCard
            name="Detection Engine"
            description="Rule-based and ML-powered threat detection"
            icon={Cpu}
            status={components.detection?.status || 'pending'}
            message={components.detection?.message || null}
            stats={[
              { label: 'Rules', value: detectionStats?.rules?.enabled || 0 },
              { label: 'IOCs', value: detectionStats?.iocs?.total || 0 },
              { label: 'Anomaly', value: detectionStats?.anomaly?.enabled ? 'On' : 'Off' },
            ]}
          />
        </div>
      </div>

      {/* Infrastructure */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Infrastructure</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center">
                  <Database className="w-6 h-6 text-slate-400" />
                </div>
                <div>
                  <h3 className="text-white font-medium">PostgreSQL Database</h3>
                  <p className="text-sm text-slate-500">{components.database?.message || 'Data persistence layer'}</p>
                </div>
              </div>
              <StatusBadge status={components.database?.status || 'pending'} />
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-slate-800 rounded-lg flex items-center justify-center">
                  <Zap className="w-6 h-6 text-slate-400" />
                </div>
                <div>
                  <h3 className="text-white font-medium">Redis Cache</h3>
                  <p className="text-sm text-slate-500">{components.redis?.message || 'In-memory caching'}</p>
                </div>
              </div>
              <StatusBadge status={components.redis?.status || 'pending'} />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
