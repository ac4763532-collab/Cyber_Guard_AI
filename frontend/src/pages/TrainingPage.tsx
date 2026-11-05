/**
 * CyberGuard AI - Training / ML Ops Page
 *
 * Admin-only page for model version management, retraining pipeline,
 * deployment/rollback, and threshold tuning.
 */

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Cpu,
  RefreshCw,
  Rocket,
  RotateCcw,
  PlayCircle,
  Download,
  Sliders,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '@/contexts/AuthContext'
import { trainingApi } from '@/services/api'

function ConfirmButton({
  label,
  confirmLabel,
  onConfirm,
  icon: Icon,
  className,
  disabled,
}: {
  label: string
  confirmLabel: string
  onConfirm: () => void
  icon: typeof Rocket
  className?: string
  disabled?: boolean
}) {
  const [confirming, setConfirming] = useState(false)

  if (confirming) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-sm text-slate-400">{confirmLabel}</span>
        <button
          onClick={() => {
            setConfirming(false)
            onConfirm()
          }}
          className="px-3 py-1.5 text-sm bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors"
        >
          Confirm
        </button>
        <button
          onClick={() => setConfirming(false)}
          className="px-3 py-1.5 text-sm bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
        >
          Cancel
        </button>
      </div>
    )
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      disabled={disabled}
      className={clsx(
        'flex items-center gap-2 px-4 py-2 text-sm rounded-lg transition-colors disabled:opacity-50',
        className
      )}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  )
}

function ModelsSection() {
  const queryClient = useQueryClient()

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['training', 'status'],
    queryFn: trainingApi.getStatus,
  })

  const { data: models, isLoading } = useQuery({
    queryKey: ['training', 'models'],
    queryFn: trainingApi.listModels,
  })

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ['training'] })
  }

  const retrainMutation = useMutation({
    mutationFn: () => trainingApi.retrain({ auto_deploy: false, export_feedback: true }),
    onSuccess: invalidateAll,
  })

  const deployMutation = useMutation({
    mutationFn: (version: string) => trainingApi.deploy(version),
    onSuccess: invalidateAll,
  })

  const rollbackMutation = useMutation({
    mutationFn: () => trainingApi.rollback(),
    onSuccess: invalidateAll,
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          Model Versions
        </h2>
        <button
          onClick={() => {
            refetchStatus()
            invalidateAll()
          }}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {status && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-lg font-bold text-white font-mono truncate">
              {status.current_model.version || 'none'}
            </p>
            <p className="text-sm text-slate-400">Current Version</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-cyan-400">{status.available_versions}</p>
            <p className="text-sm text-slate-400">Available Versions</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{status.threshold.current.toFixed(2)}</p>
            <p className="text-sm text-slate-400">Current Threshold</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{status.feedback_batches}</p>
            <p className="text-sm text-slate-400">Feedback Batches</p>
          </div>
        </div>
      )}

      <div className="flex items-center gap-3">
        <button
          onClick={() => retrainMutation.mutate()}
          disabled={retrainMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          <PlayCircle className={clsx('w-4 h-4', retrainMutation.isPending && 'animate-pulse')} />
          {retrainMutation.isPending ? 'Running Pipeline...' : 'Trigger Retraining'}
        </button>
        <ConfirmButton
          label="Rollback to Previous"
          confirmLabel="Rollback production model?"
          onConfirm={() => rollbackMutation.mutate()}
          icon={RotateCcw}
          disabled={!status?.current_model.rollback_available || rollbackMutation.isPending}
          className="bg-orange-600/20 hover:bg-orange-600/30 text-orange-400"
        />
      </div>

      {retrainMutation.isError && (
        <p className="text-sm text-red-400 flex items-center gap-2">
          <XCircle className="w-4 h-4" />
          Retraining failed: {(retrainMutation.error as any)?.response?.data?.detail?.message || 'Unknown error'}
        </p>
      )}
      {retrainMutation.isSuccess && (
        <div className="bg-slate-800/50 rounded-lg p-4 text-sm text-slate-300 space-y-1">
          <p className="flex items-center gap-2 text-emerald-400">
            <CheckCircle2 className="w-4 h-4" /> {retrainMutation.data.message || 'Pipeline finished'}
          </p>
          {retrainMutation.data.warnings?.length > 0 && (
            <ul className="list-disc list-inside text-yellow-400">
              {retrainMutation.data.warnings.map((w: string, i: number) => <li key={i}>{w}</li>)}
            </ul>
          )}
        </div>
      )}
      {rollbackMutation.isError && (
        <p className="text-sm text-red-400">Rollback failed: {(rollbackMutation.error as any)?.response?.data?.detail || 'Unknown error'}</p>
      )}
      {rollbackMutation.isSuccess && (
        <p className="text-sm text-emerald-400">{rollbackMutation.data.message}</p>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center">
            <RefreshCw className="w-6 h-6 text-slate-500 animate-spin mx-auto" />
          </div>
        ) : !models || models.versions.length === 0 ? (
          <div className="p-12 text-center">
            <Cpu className="w-12 h-12 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-500">No trained model versions yet</p>
            <p className="text-sm text-slate-600 mt-1">Trigger a retraining run to create the first version</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {models.versions.map((v) => (
              <div key={v.version} className="p-4 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm text-white">{v.version}</span>
                    {v.is_current && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-emerald-500/20 text-emerald-400">
                        CURRENT
                      </span>
                    )}
                    <span className="text-xs text-slate-500 capitalize">{v.status}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {v.train_samples} samples
                    {v.trained_at && ` · trained ${new Date(v.trained_at).toLocaleString()}`}
                  </p>
                  {v.metrics && (
                    <p className="text-xs text-slate-400 mt-1">
                      {Object.entries(v.metrics).map(([k, val]) => `${k}: ${Number(val).toFixed(3)}`).join(' · ')}
                    </p>
                  )}
                </div>
                {!v.is_current && (
                  <ConfirmButton
                    label="Deploy"
                    confirmLabel={`Deploy ${v.version} to production?`}
                    onConfirm={() => deployMutation.mutate(v.version)}
                    icon={Rocket}
                    disabled={deployMutation.isPending}
                    className="bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400"
                  />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function ThresholdSection() {
  const queryClient = useQueryClient()
  const [targetFp, setTargetFp] = useState(0.05)
  const [targetFn, setTargetFn] = useState(0.02)

  const { data: config, refetch } = useQuery({
    queryKey: ['training', 'threshold'],
    queryFn: trainingApi.getThreshold,
  })

  const { data: analysis } = useQuery({
    queryKey: ['training', 'threshold', 'analyze'],
    queryFn: trainingApi.analyzeThresholdErrors,
  })

  const tuneMutation = useMutation({
    mutationFn: (dryRun: boolean) =>
      trainingApi.tuneThreshold({ target_fp_rate: targetFp, target_fn_rate: targetFn, dry_run: dryRun }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['training', 'threshold'] })
      refetch()
    },
  })

  const resetMutation = useMutation({
    mutationFn: () => trainingApi.resetThreshold(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['training', 'threshold'] })
      refetch()
    },
  })

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <Sliders className="w-5 h-5 text-cyan-400" />
        Threshold Tuning
      </h2>

      {analysis && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{analysis.total_feedback_samples}</p>
            <p className="text-sm text-slate-400">Feedback Samples</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-orange-400">{(analysis.fp_rate * 100).toFixed(1)}%</p>
            <p className="text-sm text-slate-400">False Positive Rate</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-red-400">{(analysis.fn_rate * 100).toFixed(1)}%</p>
            <p className="text-sm text-slate-400">False Negative Rate</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-cyan-400">{analysis.current_threshold.toFixed(2)}</p>
            <p className="text-sm text-slate-400">Current Threshold</p>
          </div>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-6">
          <div>
            <label className="block text-sm text-slate-400 mb-1">Target FP Rate</label>
            <input
              type="number"
              step={0.01}
              min={0}
              max={0.5}
              value={targetFp}
              onChange={(e) => setTargetFp(Number(e.target.value))}
              className="w-24 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">Target FN Rate</label>
            <input
              type="number"
              step={0.01}
              min={0}
              max={0.5}
              value={targetFn}
              onChange={(e) => setTargetFn(Number(e.target.value))}
              className="w-24 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => tuneMutation.mutate(true)}
            disabled={tuneMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
          >
            Preview (Dry Run)
          </button>
          <ConfirmButton
            label="Apply Tuning"
            confirmLabel="Apply new threshold to production?"
            onConfirm={() => tuneMutation.mutate(false)}
            icon={Sliders}
            disabled={tuneMutation.isPending}
            className="bg-cyan-600 hover:bg-cyan-500 text-white"
          />
          <ConfirmButton
            label="Reset to Default"
            confirmLabel="Reset threshold to default?"
            onConfirm={() => resetMutation.mutate()}
            icon={RotateCcw}
            disabled={resetMutation.isPending}
            className="bg-slate-800 hover:bg-slate-700 text-slate-300"
          />
        </div>

        {tuneMutation.data && (
          <pre className="bg-slate-800/50 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
            {JSON.stringify(tuneMutation.data, null, 2)}
          </pre>
        )}
        {tuneMutation.isError && (
          <p className="text-sm text-red-400">Tuning failed. Check that enough feedback data exists.</p>
        )}

        {config && (
          <p className="text-xs text-slate-500">
            Global threshold: {config.global_threshold.toFixed(3)} · last updated{' '}
            {config.last_updated ? new Date(config.last_updated).toLocaleString() : 'never'} ·{' '}
            {config.feedback_samples_used} feedback samples used
          </p>
        )}
      </div>
    </div>
  )
}

function FeedbackExportSection() {
  const exportMutation = useMutation({
    mutationFn: () => trainingApi.exportFeedback(),
  })

  const { data: batches, refetch } = useQuery({
    queryKey: ['training', 'feedback', 'export-batches'],
    queryFn: trainingApi.listFeedbackExportBatches,
  })

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <Download className="w-5 h-5 text-cyan-400" />
        Feedback Export
      </h2>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <p className="text-sm text-slate-400 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
          Approved feedback currently stores only a hash of the original email body, not the
          text itself, so exported batches are metadata-only and cannot be used directly to
          retrain the text classifier. This is a known backend limitation, not a UI bug.
        </p>
        <button
          onClick={() => {
            exportMutation.mutate()
            refetch()
          }}
          disabled={exportMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
        >
          <Download className="w-4 h-4" />
          {exportMutation.isPending ? 'Exporting...' : 'Export Approved Feedback'}
        </button>

        {exportMutation.data && (
          <pre className="bg-slate-800/50 rounded-lg p-4 text-xs text-slate-300 overflow-x-auto">
            {JSON.stringify(exportMutation.data, null, 2)}
          </pre>
        )}

        {batches && (
          <p className="text-xs text-slate-500">{batches.total} export batch(es) on disk</p>
        )}
      </div>
    </div>
  )
}

export function TrainingPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  if (!isAdmin) {
    return (
      <div className="p-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <ShieldAlert className="w-12 h-12 text-slate-700 mx-auto mb-3" />
          <p className="text-slate-400">Admin access required</p>
          <p className="text-sm text-slate-600 mt-1">
            Model training and threshold tuning are restricted to administrators
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Training &amp; ML Ops</h1>
        <p className="text-slate-400 mt-1">
          Manage model versions, retraining pipeline, and classification thresholds
        </p>
      </div>

      <ModelsSection />
      <ThresholdSection />
      <FeedbackExportSection />
    </div>
  )
}
