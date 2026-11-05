import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Clock3, LoaderCircle, ShieldAlert } from 'lucide-react'
import { incidentsApi } from '@/services/api'
import { useAuth } from '@/contexts/AuthContext'

type IncidentRecord = {
  id: string
  title: string
  description: string
  severity: string
  status: string
  finding_ids: string[]
  event_ids: string[]
  alert_ids: string[]
  correlation_ids: string[]
  recommendations: string[]
  actions_taken: Record<string, unknown>[]
  history: Record<string, unknown>[]
  created_at: string
  updated_at: string
}

const transitions: Record<string, string[]> = {
  open: ['investigating'],
  investigating: ['containment_in_progress', 'resolved'],
  containment_in_progress: ['investigating', 'resolved'],
  resolved: ['investigating', 'closed'],
  closed: [],
}

const badge: Record<string, string> = {
  critical: 'border-red-800 bg-red-950/50 text-red-300',
  high: 'border-orange-800 bg-orange-950/50 text-orange-300',
  medium: 'border-yellow-800 bg-yellow-950/50 text-yellow-300',
}

export function IncidentsPage() {
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [findingId, setFindingId] = useState('')
  const [reason, setReason] = useState('')
  const [message, setMessage] = useState('')
  const canManage = user?.role === 'admin' || user?.role === 'analyst'

  const incidentsQuery = useQuery({
    queryKey: ['incidents'],
    queryFn: () => incidentsApi.list(),
  })
  const detailQuery = useQuery({
    queryKey: ['incidents', selectedId],
    queryFn: () => incidentsApi.get(selectedId!),
    enabled: Boolean(selectedId),
  })

  const qualifyMutation = useMutation({
    mutationFn: () => incidentsApi.qualifyFinding(findingId.trim()),
    onSuccess: async (result) => {
      setMessage(result.summary)
      setFindingId('')
      await queryClient.invalidateQueries({ queryKey: ['incidents'] })
    },
    onError: (error: Error) => setMessage(error.message),
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      incidentsApi.updateStatus(id, status, reason.trim()),
    onSuccess: async (updated) => {
      setMessage(`Incident status updated to ${updated.status}.`)
      setReason('')
      await queryClient.invalidateQueries({ queryKey: ['incidents'] })
      if (selectedId) await queryClient.invalidateQueries({ queryKey: ['incidents', selectedId] })
    },
    onError: (error: Error) => setMessage(error.message),
  })

  const incidents = (incidentsQuery.data || []) as IncidentRecord[]
  const selected = detailQuery.data as IncidentRecord | undefined

  return (
    <div className="space-y-6 p-6">
      <header className="flex items-start gap-3 border-b border-slate-800 pb-5">
        <ShieldAlert className="mt-1 h-6 w-6 text-orange-300" />
        <div>
          <h1 className="text-2xl font-semibold text-white">Incidents</h1>
          <p className="mt-1 text-sm text-slate-400">Persisted investigations, supporting evidence, and lifecycle history.</p>
        </div>
      </header>

      {canManage && (
        <form
          className="flex flex-col gap-3 border-b border-slate-800 pb-5 sm:flex-row"
          onSubmit={(event) => { event.preventDefault(); setMessage(''); qualifyMutation.mutate() }}
        >
          <label className="flex-1">
            <span className="mb-1 block text-sm text-slate-300">Qualify a persisted finding</span>
            <input
              value={findingId}
              onChange={(event) => setFindingId(event.target.value)}
              placeholder="Finding identifier"
              className="w-full border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
            />
          </label>
          <button
            type="submit"
            disabled={!findingId.trim() || qualifyMutation.isPending}
            className="mt-auto inline-flex items-center justify-center gap-2 bg-orange-700 px-4 py-2 text-sm font-medium text-white hover:bg-orange-600 disabled:opacity-50"
          >
            {qualifyMutation.isPending ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <AlertTriangle className="h-4 w-4" />}
            Qualify finding
          </button>
        </form>
      )}

      {message && <p role="status" className="border border-slate-700 px-4 py-3 text-sm text-slate-200">{message}</p>}
      {incidentsQuery.isError && <p role="alert" className="text-sm text-red-300">Incidents could not be loaded. Check access and backend availability.</p>}
      {incidentsQuery.isLoading && <p className="text-sm text-slate-400">Loading incidents…</p>}
      {!incidentsQuery.isLoading && !incidentsQuery.isError && incidents.length === 0 && (
        <p className="py-8 text-center text-sm text-slate-400">No incidents are recorded for this tenant.</p>
      )}

      {incidents.length > 0 && (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <section aria-label="Incident list" className="divide-y divide-slate-800 border-y border-slate-800">
            {incidents.map((incident) => (
              <button
                key={incident.id}
                type="button"
                onClick={() => setSelectedId(incident.id)}
                className={`block w-full px-4 py-4 text-left hover:bg-slate-900 ${selectedId === incident.id ? 'bg-slate-900' : ''}`}
              >
                <span className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-white">{incident.title}</span>
                  <span className={`border px-2 py-1 text-xs uppercase ${badge[incident.severity] || 'border-slate-700 text-slate-300'}`}>{incident.severity}</span>
                </span>
                <span className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                  <Clock3 className="h-3.5 w-3.5" />
                  {incident.status.replace(/_/g, ' ')} · Updated {new Date(incident.updated_at).toLocaleString()}
                </span>
              </button>
            ))}
          </section>

          <section aria-label="Incident detail" className="min-w-0">
            {!selectedId && <p className="py-6 text-sm text-slate-500">Select an incident to inspect its evidence and history.</p>}
            {detailQuery.isLoading && <p className="py-6 text-sm text-slate-400">Loading incident details…</p>}
            {detailQuery.isError && <p role="alert" className="py-6 text-sm text-red-300">Incident details could not be loaded.</p>}
            {selected && (
              <div className="space-y-5">
                <div className="border-b border-slate-800 pb-4">
                  <h2 className="text-lg font-semibold text-white">{selected.title}</h2>
                  <p className="mt-2 whitespace-pre-wrap text-sm text-slate-300">{selected.description}</p>
                  <p className="mt-2 break-all font-mono text-xs text-slate-500">{selected.id}</p>
                  <p className="mt-1 text-xs text-slate-500">Created {new Date(selected.created_at).toLocaleString()}</p>
                </div>

                <EvidenceList title="Findings" ids={selected.finding_ids} />
                <EvidenceList title="Events" ids={selected.event_ids} />
                <EvidenceList title="Alerts" ids={selected.alert_ids} />
                <EvidenceList title="Correlations" ids={selected.correlation_ids} />

                <div>
                  <h3 className="text-sm font-semibold text-white">Recommendations</h3>
                  <p className="mb-2 mt-1 text-xs text-slate-500">Recommendations only. No containment or remediation action was executed.</p>
                  {selected.recommendations.length ? selected.recommendations.map((item, index) => (
                    <p key={`${item}-${index}`} className="border-l-2 border-orange-700 py-1 pl-3 text-sm text-slate-300">{item}</p>
                  )) : <p className="text-sm text-slate-500">No recommendations recorded.</p>}
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-white">Response actions</h3>
                  <p className="mt-1 text-sm text-slate-500">{selected.actions_taken.length ? 'Recorded actions are listed in the incident history.' : 'No response actions recorded.'}</p>
                </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold text-white">Investigation history</h3>
                  <div className="space-y-2 border-l border-slate-700 pl-3">
                    {selected.history.map((entry, index) => (
                      <p key={index} className="text-xs text-slate-400">
                        <span className="text-slate-200">{String(entry.action || 'update').replace(/_/g, ' ')}</span>
                        {entry.timestamp ? ` · ${new Date(String(entry.timestamp)).toLocaleString()}` : ''}
                        {entry.reason ? ` · ${String(entry.reason)}` : ''}
                      </p>
                    ))}
                  </div>
                </div>

                {canManage && transitions[selected.status]?.length > 0 && (
                  <div className="space-y-3 border-t border-slate-800 pt-4">
                    <label className="block text-sm text-slate-300">
                      Audit reason
                      <input
                        value={reason}
                        onChange={(event) => setReason(event.target.value)}
                        className="mt-1 w-full border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                        placeholder="Why is this transition being made?"
                      />
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {transitions[selected.status].map((nextStatus) => (
                        <button
                          key={nextStatus}
                          type="button"
                          disabled={reason.trim().length < 3 || statusMutation.isPending}
                          onClick={() => statusMutation.mutate({ id: selected.id, status: nextStatus })}
                          className="inline-flex items-center gap-2 border border-slate-700 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-50"
                        >
                          <Check className="h-3.5 w-3.5" />
                          {nextStatus.replace(/_/g, ' ')}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  )
}

function EvidenceList({ title, ids }: { title: string; ids: string[] }) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-white">{title} <span className="text-slate-500">({ids.length})</span></h3>
      {ids.length ? (
        <ul className="mt-2 space-y-1">
          {ids.map((id) => <li key={id} className="break-all font-mono text-xs text-slate-400">{id}</li>)}
        </ul>
      ) : <p className="mt-1 text-sm text-slate-500">No linked {title.toLowerCase()}.</p>}
    </div>
  )
}
