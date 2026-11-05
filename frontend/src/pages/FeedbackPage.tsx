/**
 * CyberGuard AI - Feedback Page
 *
 * Analysts submit feedback on analysis results (false positive / false
 * negative / wrong category). Admins additionally see a review queue to
 * approve, reject, or mark feedback as duplicate.
 */

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  MessageSquareWarning,
  Send,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Copy,
  Clock,
  ShieldAlert,
} from 'lucide-react'
import { clsx } from 'clsx'
import { useAuth } from '@/contexts/AuthContext'
import { feedbackApi } from '@/services/api'
import type { FeedbackDetail } from '@/types'

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    pending: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    approved: { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
    rejected: { bg: 'bg-red-500/20', text: 'text-red-400' },
    duplicate: { bg: 'bg-slate-500/20', text: 'text-slate-400' },
  }
  const { bg, text } = config[status] || config.pending
  return (
    <span className={clsx('px-2 py-0.5 text-xs font-medium rounded capitalize', bg, text)}>
      {status}
    </span>
  )
}

function SubmitFeedbackForm() {
  const [analysisId, setAnalysisId] = useState('')
  const [feedbackType, setFeedbackType] = useState<'false_positive' | 'false_negative' | 'wrong_category'>('false_positive')
  const [correctClassification, setCorrectClassification] = useState('')
  const [comment, setComment] = useState('')

  const submitMutation = useMutation({
    mutationFn: () =>
      feedbackApi.submit({
        analysis_id: analysisId.trim(),
        feedback_type: feedbackType,
        correct_classification: feedbackType === 'wrong_category' ? correctClassification || undefined : undefined,
        comment: comment.trim() || undefined,
      }),
    onSuccess: () => {
      setAnalysisId('')
      setComment('')
      setCorrectClassification('')
    },
  })

  const canSubmit = analysisId.trim().length > 0 && (feedbackType !== 'wrong_category' || correctClassification.trim())

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <MessageSquareWarning className="w-5 h-5 text-cyan-400" />
        Report an Analysis Result
      </h2>
      <p className="text-sm text-slate-400">
        Flag an incorrect classification to help improve detection. The analysis ID can be found
        in the detail view of any email, log, or network analysis result.
      </p>

      <div className="space-y-3">
        <div>
          <label className="block text-sm text-slate-400 mb-1">Analysis ID</label>
          <input
            type="text"
            placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000"
            value={analysisId}
            onChange={(e) => setAnalysisId(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Feedback Type</label>
          <select
            value={feedbackType}
            onChange={(e) => setFeedbackType(e.target.value as typeof feedbackType)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="false_positive">False Positive — flagged but actually safe</option>
            <option value="false_negative">False Negative — missed a real threat</option>
            <option value="wrong_category">Wrong Category — classification was incorrect</option>
          </select>
        </div>

        {feedbackType === 'wrong_category' && (
          <div>
            <label className="block text-sm text-slate-400 mb-1">Correct Classification</label>
            <select
              value={correctClassification}
              onChange={(e) => setCorrectClassification(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">Select correct classification...</option>
              <option value="benign">Benign</option>
              <option value="suspicious">Suspicious</option>
              <option value="phishing">Phishing</option>
              <option value="malicious">Malicious</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
        )}

        <div>
          <label className="block text-sm text-slate-400 mb-1">Comment (optional)</label>
          <textarea
            placeholder="Explain why this result was incorrect..."
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            maxLength={1000}
            rows={3}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
          />
        </div>
      </div>

      <button
        onClick={() => submitMutation.mutate()}
        disabled={!canSubmit || submitMutation.isPending}
        className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
      >
        <Send className="w-4 h-4" />
        {submitMutation.isPending ? 'Submitting...' : 'Submit Feedback'}
      </button>

      {submitMutation.isSuccess && (
        <p className="text-sm text-emerald-400 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          {submitMutation.data.message}
        </p>
      )}
      {submitMutation.isError && (
        <p className="text-sm text-red-400">
          {(submitMutation.error as any)?.response?.data?.detail?.message ||
            (submitMutation.error as any)?.response?.data?.message ||
            'Failed to submit feedback. Check the analysis ID and try again.'}
        </p>
      )}
    </div>
  )
}

function AdminReviewQueue() {
  const queryClient = useQueryClient()
  const [reviewingId, setReviewingId] = useState<string | null>(null)

  const { data: stats, refetch: refetchStats } = useQuery({
    queryKey: ['feedback', 'statistics'],
    queryFn: feedbackApi.getStatistics,
  })

  const { data: pending, isLoading, refetch } = useQuery({
    queryKey: ['feedback', 'pending'],
    queryFn: () => feedbackApi.getPending({ limit: 50 }),
    refetchInterval: 30000,
  })

  const reviewMutation = useMutation({
    mutationFn: ({ id, status, notes }: { id: string; status: 'approved' | 'rejected' | 'duplicate'; notes?: string }) =>
      feedbackApi.review(id, { status, notes }),
    onSuccess: () => {
      setReviewingId(null)
      queryClient.invalidateQueries({ queryKey: ['feedback'] })
    },
  })

  const items: FeedbackDetail[] = pending?.items || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-orange-400" />
          Review Queue (Admin)
        </h2>
        <button
          onClick={() => {
            refetch()
            refetchStats()
          }}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-white">{stats.total_feedback}</p>
            <p className="text-sm text-slate-400">Total</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-yellow-400">{stats.pending_count}</p>
            <p className="text-sm text-slate-400">Pending</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-emerald-400">{stats.approved_count}</p>
            <p className="text-sm text-slate-400">Approved</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-red-400">{stats.rejected_count}</p>
            <p className="text-sm text-slate-400">Rejected</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <p className="text-2xl font-bold text-cyan-400">{stats.included_in_training_count}</p>
            <p className="text-sm text-slate-400">Used in Training</p>
          </div>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center">
            <RefreshCw className="w-6 h-6 text-slate-500 animate-spin mx-auto" />
          </div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center">
            <MessageSquareWarning className="w-12 h-12 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-500">No pending feedback</p>
            <p className="text-sm text-slate-600 mt-1">Submitted feedback awaiting review will appear here</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {items.map((item) => (
              <div key={item.feedback_id} className="p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white capitalize">
                        {item.feedback_type.replace(/_/g, ' ')}
                      </span>
                      <StatusBadge status={item.status} />
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 flex items-center gap-2">
                      <Clock className="w-3 h-3" />
                      {new Date(item.submitted_at).toLocaleString()}
                      {item.submitted_by && <span>· by {item.submitted_by}</span>}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-slate-500">{item.feedback_id.slice(0, 8)}</span>
                </div>

                <div className="grid grid-cols-2 gap-3 bg-slate-800/50 rounded-lg p-3 text-sm">
                  <div>
                    <p className="text-xs text-slate-500">Original Classification</p>
                    <p className="text-white capitalize">{item.original_classification}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500">Original Risk Score</p>
                    <p className="text-white">{item.original_risk_score}</p>
                  </div>
                  {item.correct_classification && (
                    <div>
                      <p className="text-xs text-slate-500">Suggested Correction</p>
                      <p className="text-cyan-400 capitalize">{item.correct_classification}</p>
                    </div>
                  )}
                  {item.email_sender && (
                    <div>
                      <p className="text-xs text-slate-500">Sender</p>
                      <p className="text-white truncate">{item.email_sender}</p>
                    </div>
                  )}
                </div>

                {item.user_comment && (
                  <p className="text-sm text-slate-300 bg-slate-800/30 rounded-lg p-3 italic">
                    "{item.user_comment}"
                  </p>
                )}

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => reviewMutation.mutate({ id: item.feedback_id, status: 'approved' })}
                    disabled={reviewMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded-lg transition-colors disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Approve
                  </button>
                  <button
                    onClick={() => reviewMutation.mutate({ id: item.feedback_id, status: 'rejected' })}
                    disabled={reviewMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg transition-colors disabled:opacity-50"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    Reject
                  </button>
                  <button
                    onClick={() => reviewMutation.mutate({ id: item.feedback_id, status: 'duplicate' })}
                    disabled={reviewMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors disabled:opacity-50"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    Duplicate
                  </button>
                </div>

                {reviewMutation.isError && reviewingId === item.feedback_id && (
                  <p className="text-sm text-red-400">Failed to update feedback status.</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export function FeedbackPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Feedback</h1>
        <p className="text-slate-400 mt-1">
          {isAdmin
            ? 'Submit feedback on results and review the pending queue'
            : 'Report incorrect analysis results to help improve detection'}
        </p>
      </div>

      <SubmitFeedbackForm />

      {isAdmin && <AdminReviewQueue />}
    </div>
  )
}
