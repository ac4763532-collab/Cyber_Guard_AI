/**
 * CyberGuard AI - Events Page
 *
 * View and manage security events.
 */

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  RefreshCw,
  Search,
  Mail,
  FileText,
  Network,
  Clock,
  Eye,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
} from 'lucide-react'
import { clsx } from 'clsx'
import { eventsApi } from '@/services/api'

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

// Event type icon
function EventTypeIcon({ type }: { type: string }) {
  const icons: Record<string, typeof Mail> = {
    email: Mail,
    log: FileText,
    network: Network,
  }
  const Icon = icons[type] || Activity

  return (
    <div className="p-2 bg-slate-700 rounded-lg">
      <Icon className="w-4 h-4 text-cyan-400" />
    </div>
  )
}

// Event detail panel
function EventDetail({ event, onClose }: { event: any; onClose: () => void }) {
  const [showRawData, setShowRawData] = useState(false)

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Event Details</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">×</button>
        </div>

        <div className="p-6 space-y-6">
          {/* Header */}
          <div className="flex items-start gap-4">
            <EventTypeIcon type={event.event_type} />
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-lg font-medium text-white capitalize">{event.event_type} Event</span>
                <SeverityBadge severity={event.severity} />
              </div>
              <p className="text-sm text-slate-400 mt-1">Source: {event.source}</p>
            </div>
            <div className="text-right">
              <p className="text-sm text-slate-400">Risk Score</p>
              <p className={clsx(
                'text-2xl font-bold',
                event.risk_score >= 75 ? 'text-red-400' :
                event.risk_score >= 50 ? 'text-orange-400' :
                event.risk_score >= 25 ? 'text-yellow-400' : 'text-emerald-400'
              )}>
                {event.risk_score || 0}
              </p>
            </div>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 bg-slate-800/50 rounded-lg p-4">
            <div>
              <p className="text-xs text-slate-500">Event ID</p>
              <p className="text-sm text-white font-mono">{event.id}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Status</p>
              <p className="text-sm text-white capitalize">{event.status}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Created At</p>
              <p className="text-sm text-white">{new Date(event.created_at).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Findings</p>
              <p className="text-sm text-white">{event.findings_count || 0} findings</p>
            </div>
          </div>

          {/* MITRE Techniques */}
          {event.mitre_techniques && event.mitre_techniques.length > 0 && (
            <div>
              <p className="text-sm font-medium text-slate-300 mb-2">MITRE ATT&CK Techniques</p>
              <div className="flex flex-wrap gap-2">
                {event.mitre_techniques.map((tech: string) => (
                  <span key={tech} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded font-mono">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {event.findings && event.findings.length > 0 && (
            <div>
              <p className="text-sm font-medium text-slate-300 mb-2">Analysis Findings</p>
              <div className="space-y-2">
                {event.findings.map((finding: any, idx: number) => (
                  <div key={idx} className="bg-slate-800 rounded-lg p-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-sm font-medium text-white">{finding.type}</p>
                        <p className="text-xs text-slate-400 mt-0.5">{finding.description}</p>
                      </div>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw Data */}
          <div>
            <button
              onClick={() => setShowRawData(!showRawData)}
              className="flex items-center gap-2 text-sm text-slate-400 hover:text-white"
            >
              {showRawData ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              Raw Event Data
            </button>
            {showRawData && (
              <pre className="mt-2 bg-slate-800 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
                {JSON.stringify(event.raw_data, null, 2)}
              </pre>
            )}
          </div>
        </div>

        <div className="px-6 py-4 border-t border-slate-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

// Display page size for the Events page. This bounds how many of the
// latest matching events are fetched/rendered per page - it does NOT
// bound how many events exist in the database, how many are processed
// by detection, or how long they're retained (see
// app/retention/cleanup.py on the backend for the real retention
// policy). Raised from the previous hardcoded 50 to the backend's new
// max of 1000 so a single page can show the full "latest 1000" view;
// pagination (via offset) still works for paging into older events
// beyond that.
const EVENTS_PAGE_SIZE = 1000

export function EventsPage() {
  const [selectedEvent, setSelectedEvent] = useState<any>(null)
  const [offset, setOffset] = useState(0)
  const [filters, setFilters] = useState({
    event_type: '',
    severity: '',
    search: '',
  })
  // Debounced separately from the raw input so every keystroke doesn't
  // refire the query - mirrors the pattern already used by LogAnalysisPage's
  // LogEventsTab search box.
  const [debouncedSearch, setDebouncedSearch] = useState('')

  useEffect(() => {
    const handle = setTimeout(() => setDebouncedSearch(filters.search.trim()), 400)
    return () => clearTimeout(handle)
  }, [filters.search])

  // Changing a filter should always reset back to the first page -
  // otherwise a stale offset from a previous, larger result set can
  // land past the end of a newly-filtered, smaller one.
  useEffect(() => {
    setOffset(0)
  }, [filters.event_type, filters.severity, debouncedSearch])

  // Fetch events
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['events', filters.event_type, filters.severity, debouncedSearch, offset],
    queryFn: () => eventsApi.list({
      event_type: filters.event_type || undefined,
      severity: filters.severity || undefined,
      search: debouncedSearch.length >= 2 ? debouncedSearch : undefined,
      limit: EVENTS_PAGE_SIZE,
      offset,
    }),
    refetchInterval: 30000,
  })

  // Fetch statistics
  const { data: stats } = useQuery({
    queryKey: ['events', 'statistics'],
    queryFn: eventsApi.getStatistics,
  })

  const events = data?.events || []
  const total = data?.total ?? events.length
  const hasNextPage = offset + EVENTS_PAGE_SIZE < total
  const hasPrevPage = offset > 0
  const rangeStart = total === 0 ? 0 : offset + 1
  const rangeEnd = Math.min(offset + EVENTS_PAGE_SIZE, total)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Events</h1>
          <p className="text-slate-400 mt-1">View and analyze security events</p>
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
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{stats.total}</p>
            <p className="text-sm text-slate-400">Total Events</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-cyan-400">{stats.by_type?.email || 0}</p>
            <p className="text-sm text-slate-400">Email Events</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-emerald-400">{stats.by_type?.log || 0}</p>
            <p className="text-sm text-slate-400">Log Events</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-purple-400">{stats.by_type?.network || 0}</p>
            <p className="text-sm text-slate-400">Network Events</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search events..."
            value={filters.search}
            onChange={(e) => setFilters({ ...filters, search: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        <select
          value={filters.event_type}
          onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="">All Types</option>
          <option value="email">Email</option>
          <option value="log">Log</option>
          <option value="network">Network</option>
        </select>
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
      </div>

      {/* Events list */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center">
            <RefreshCw className="w-6 h-6 text-slate-500 animate-spin mx-auto" />
          </div>
        ) : events.length === 0 ? (
          <div className="p-12 text-center">
            <Activity className="w-12 h-12 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-500">No events found</p>
            <p className="text-sm text-slate-600 mt-1">Events will appear here when data is ingested</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {events.map((event: any) => (
              <div
                key={event.id}
                onClick={() => setSelectedEvent(event)}
                className="p-4 hover:bg-slate-800/50 transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-4">
                  <EventTypeIcon type={event.event_type} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white capitalize">{event.event_type}</span>
                      <span className="text-xs text-slate-500">from {event.source}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                      <Clock className="w-3 h-3" />
                      {new Date(event.created_at).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Risk</p>
                      <p className={clsx(
                        'text-lg font-bold',
                        event.risk_score >= 75 ? 'text-red-400' :
                        event.risk_score >= 50 ? 'text-orange-400' :
                        event.risk_score >= 25 ? 'text-yellow-400' : 'text-emerald-400'
                      )}>
                        {event.risk_score || 0}
                      </p>
                    </div>
                    <SeverityBadge severity={event.severity} />
                    <Eye className="w-4 h-4 text-slate-500" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between text-sm text-slate-400">
          <p>
            Showing {rangeStart}-{rangeEnd} of {total} events
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - EVENTS_PAGE_SIZE))}
              disabled={!hasPrevPage || isLoading}
              className="flex items-center gap-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => setOffset(offset + EVENTS_PAGE_SIZE)}
              disabled={!hasNextPage || isLoading}
              className="flex items-center gap-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Event detail modal */}
      {selectedEvent && (
        <EventDetail
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  )
}
