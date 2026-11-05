/**
 * CyberGuard AI - Alerts Page
 *
 * View and manage security alerts.
 */

import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldAlert,
  RefreshCw,
  Search,
  Clock,
  CheckCircle2,
  XCircle,
  Eye,
} from 'lucide-react'
import { clsx } from 'clsx'
import { alertsApi } from '@/services/api'
import { SeverityBadge } from '@/components/ui'

// Category badge - reflects alerts.category as set by
// _alert_category_for_source() in app/correlation/finding_lifecycle.py:
// email_security / log_security / network_security for a single-source
// finding's individual alert, or correlated_threat when the alert came
// from RealtimeCorrelationService linking 2+ findings across sources.
function CategoryBadge({ category }: { category?: string }) {
  if (!category) return <span className="text-xs text-slate-500">-</span>

  const config: Record<string, { bg: string; text: string; label: string }> = {
    email_security: { bg: 'bg-purple-500/20', text: 'text-purple-400', label: 'Email' },
    log_security: { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'Log' },
    network_security: { bg: 'bg-teal-500/20', text: 'text-teal-400', label: 'Network' },
    correlated_threat: { bg: 'bg-pink-500/20', text: 'text-pink-400', label: 'Correlated' },
  }
  const { bg, text, label } = config[category] || {
    bg: 'bg-slate-500/20',
    text: 'text-slate-400',
    label: category.replace('_', ' '),
  }

  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded', bg, text)}>
      {label}
    </span>
  )
}

// Status badge
function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string; icon: typeof Clock }> = {
    new: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', icon: Clock },
    acknowledged: { bg: 'bg-blue-500/20', text: 'text-blue-400', icon: Eye },
    investigating: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', icon: Search },
    resolved: { bg: 'bg-emerald-500/20', text: 'text-emerald-400', icon: CheckCircle2 },
    false_positive: { bg: 'bg-slate-500/20', text: 'text-slate-400', icon: XCircle },
  }
  const { bg, text, icon: Icon } = config[status] || config.new

  return (
    <span className={clsx('inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded', bg, text)}>
      <Icon className="w-3 h-3" />
      {status.replace('_', ' ')}
    </span>
  )
}

// Alert detail modal
function AlertDetailModal({
  alert,
  onClose,
  onUpdate,
}: {
  alert: any
  onClose: () => void
  onUpdate: (id: string, data: any) => void
}) {
  const [status, setStatus] = useState(alert.status)
  const [note, setNote] = useState('')

  const handleUpdate = () => {
    onUpdate(alert.id, { status, note: note || undefined })
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Alert Details</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <h3 className="text-xl font-semibold text-white">{alert.title}</h3>
            <p className="text-slate-400 mt-1">{alert.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-slate-500">Severity</p>
              <SeverityBadge severity={alert.severity} />
            </div>
            <div>
              <p className="text-sm text-slate-500">Risk Score</p>
              <p className="text-white font-medium">{alert.risk_score || 'N/A'}</p>
            </div>
            <div>
              <p className="text-sm text-slate-500">Source</p>
              <p className="text-white">{alert.source || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-sm text-slate-500">Created</p>
              <p className="text-white">{new Date(alert.created_at).toLocaleString()}</p>
            </div>
          </div>

          {alert.mitre_techniques && alert.mitre_techniques.length > 0 && (
            <div>
              <p className="text-sm text-slate-500 mb-2">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-2">
                {alert.mitre_techniques.map((tech: string) => (
                  <span key={tech} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="border-t border-slate-700 pt-4">
            <label className="block text-sm text-slate-500 mb-2">Update Status</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="new">New</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          <div>
            <label className="block text-sm text-slate-500 mb-2">Add Note</label>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add a note about this alert..."
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 h-24 resize-none"
            />
          </div>
        </div>

        <div className="px-6 py-4 border-t border-slate-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleUpdate}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
          >
            Update Alert
          </button>
        </div>
      </div>
    </div>
  )
}

export function AlertsPage() {
  const queryClient = useQueryClient()
  const location = useLocation()
  const navigate = useNavigate()
  const [selectedAlert, setSelectedAlert] = useState<any>(null)
  const [filters, setFilters] = useState({
    status: '',
    severity: '',
    category: '',
    search: '',
  })

  // Fetch alerts
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => alertsApi.list({
      status: filters.status || undefined,
      severity: filters.severity || undefined,
      category: filters.category || undefined,
      limit: 50,
    }),
    refetchInterval: 30000,
  })

  // "Open Alert" from the real-time popup navigates here with
  // { state: { openAlertId } } (see components/AlertPopup). Fetch that
  // one alert directly by id instead of depending on it already being in
  // the (filtered, paginated) list query above, then clear the state so
  // a later refresh/back-navigation doesn't reopen it.
  const openAlertId = (location.state as { openAlertId?: string } | null)?.openAlertId
  useEffect(() => {
    if (!openAlertId) return
    let cancelled = false
    alertsApi.get(openAlertId).then((alert) => {
      if (!cancelled) setSelectedAlert(alert)
    }).catch(() => {
      // Alert may have been deleted, or the id was stale - fail silently,
      // same as any other not-found navigation target.
    })
    navigate(location.pathname, { replace: true, state: null })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openAlertId])

  // Fetch statistics
  const { data: stats } = useQuery({
    queryKey: ['alerts', 'statistics'],
    queryFn: alertsApi.getStatistics,
  })

  // Update alert mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => alertsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const handleUpdate = (id: string, updateData: any) => {
    updateMutation.mutate({ id, data: updateData })
  }

  const alerts = data?.alerts || []
  const filteredAlerts = alerts.filter((alert: any) => {
    if (filters.search) {
      const search = filters.search.toLowerCase()
      return (
        alert.title.toLowerCase().includes(search) ||
        alert.description?.toLowerCase().includes(search)
      )
    }
    return true
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
          <p className="text-slate-400 mt-1">Monitor and manage security alerts</p>
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

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{stats.total}</p>
            <p className="text-sm text-slate-400">Total Alerts</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-cyan-400">{stats.open}</p>
            <p className="text-sm text-slate-400">Open</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-red-400">{stats.by_severity?.critical || 0}</p>
            <p className="text-sm text-slate-400">Critical</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-orange-400">{stats.by_severity?.high || 0}</p>
            <p className="text-sm text-slate-400">High</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-emerald-400">{stats.by_status?.resolved || 0}</p>
            <p className="text-sm text-slate-400">Resolved</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={filters.search}
            onChange={(e) => setFilters({ ...filters, search: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        <select
          value={filters.severity}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={filters.status}
          onChange={(e) => setFilters({ ...filters, status: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select
          value={filters.category}
          onChange={(e) => setFilters({ ...filters, category: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="">All Categories</option>
          <option value="email_security">Email</option>
          <option value="log_security">Log</option>
          <option value="network_security">Network</option>
          <option value="correlated_threat">Correlated</option>
        </select>
      </div>

      {/* Alerts table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Alert</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Category</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Created</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center">
                    <RefreshCw className="w-6 h-6 text-slate-500 animate-spin mx-auto" />
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center">
                    <ShieldAlert className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                    <p className="text-slate-500">No alerts found</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert: any) => (
                  <tr key={alert.id} className="hover:bg-slate-800/50 transition-colors">
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-sm font-medium text-white">{alert.title}</p>
                        <p className="text-xs text-slate-500 truncate max-w-xs">{alert.description}</p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <CategoryBadge category={alert.category} />
                    </td>
                    <td className="px-6 py-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400">{alert.source || '-'}</td>
                    <td className="px-6 py-4 text-sm text-slate-400">
                      {new Date(alert.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="text-cyan-400 hover:text-cyan-300 text-sm"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert detail modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdate={handleUpdate}
        />
      )}
    </div>
  )
}
