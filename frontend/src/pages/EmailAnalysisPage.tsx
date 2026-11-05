/**
 * CyberGuard AI - Email Analysis Page
 *
 * Submit emails for phishing and threat analysis.
 * Supports both manual paste and Gmail integration.
 */

import { useState, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useAuth } from '@/contexts/AuthContext'
import {
  Mail,
  Shield,
  RefreshCw,
  XCircle,
  Inbox,
  Paperclip,
  User,
  Search,
  ChevronRight,
  Lock,
  Unlock,
  LogOut,
  FileSearch,
  UploadCloud,
  History,
  X,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react'
import { clsx } from 'clsx'
import { analysisApi, gmailApi } from '@/services/api'
import { EmailInvestigationReport } from '@/components/EmailInvestigationReport'
import { EmailDropzone } from '@/components/EmailDropzone'
import { EmptyState } from '@/components/ui/EmptyState'

// =============================================================================
// Automatic Monitoring Status
// =============================================================================

/**
 * Honest automatic-monitoring indicator for a connected Gmail account.
 *
 * Reflects the real backend state (GmailStatusResponse.auto_poll_enabled /
 * last_polled_at / last_poll_error from app/api/v1/gmail.py, backed by
 * app/services/gmail/poller.py + the gmail_sync_state table) - never shows
 * "monitoring" when the poller is disabled server-side, and surfaces a
 * poll failure instead of silently hiding it.
 */
function AutoMonitoringStatus({ status }: { status: any }) {
  if (!status?.auto_poll_enabled) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg">
        <AlertTriangle className="w-4 h-4 text-slate-500 flex-shrink-0" />
        <span className="text-xs text-slate-400">
          Automatic monitoring is disabled on this server. New mail must be analyzed manually.
        </span>
      </div>
    )
  }

  if (status.last_poll_error) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg">
        <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
        <span className="text-xs text-red-300">
          Automatic monitoring is failing: {status.last_poll_error}
          {status.last_poll_error_at && (
            <> (since {new Date(status.last_poll_error_at).toLocaleString()})</>
          )}
        </span>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 px-3 py-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
      <span className="text-xs text-emerald-300">
        Automatically monitoring for new mail
        {status.last_polled_at && (
          <> &middot; last checked {new Date(status.last_polled_at).toLocaleString()}</>
        )}
        {!status.last_polled_at && <> &middot; first check pending</>}
      </span>
    </div>
  )
}

// =============================================================================
// Manual Input Tab
// =============================================================================

function ManualInputTab({ onInvestigationComplete }: { onInvestigationComplete: (report: any) => void }) {
  const [formData, setFormData] = useState({
    subject: '',
    body: '',
    sender: '',
    urls: '',
  })

  const investigateMutation = useMutation({
    mutationFn: () => {
      const urls = formData.urls.split('\n').filter(u => u.trim())
      return analysisApi.investigateEmail({
        subject: formData.subject,
        body: formData.body,
        sender: formData.sender,
        urls: urls.length > 0 ? urls : undefined,
      })
    },
    onSuccess: (data) => {
      onInvestigationComplete(data)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    investigateMutation.mutate()
  }

  const handleReset = () => {
    setFormData({ subject: '', body: '', sender: '', urls: '' })
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-slate-400 mb-1">Sender Email *</label>
          <input
            type="text"
            required
            value={formData.sender}
            onChange={(e) => setFormData({ ...formData, sender: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="sender@example.com"
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Subject *</label>
          <input
            type="text"
            required
            value={formData.subject}
            onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="Email subject line"
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">Body *</label>
          <textarea
            required
            value={formData.body}
            onChange={(e) => setFormData({ ...formData, body: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 h-40 resize-none font-mono text-sm"
            placeholder="Paste email body content here..."
          />
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">URLs (one per line)</label>
          <textarea
            value={formData.urls}
            onChange={(e) => setFormData({ ...formData, urls: e.target.value })}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 h-16 resize-none font-mono text-sm"
            placeholder="http://example.com/suspicious-link"
          />
        </div>

        <div className="flex gap-3 pt-2">
          <button
            type="submit"
            disabled={investigateMutation.isPending}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {investigateMutation.isPending ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Investigating...
              </>
            ) : (
              <>
                <FileSearch className="w-4 h-4" />
                Full Investigation
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

        {investigateMutation.error && (
          <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
            <XCircle className="w-5 h-5 text-red-400" />
            <p className="text-red-400 text-sm">
              {(investigateMutation.error as any)?.response?.data?.detail
                || (investigateMutation.error as any)?.response?.data?.message
                || 'Investigation failed. Please try again.'}
            </p>
          </div>
        )}
      </form>
    </div>
  )
}

// =============================================================================
// Gmail Tab
// =============================================================================

function GmailTab({
  onInvestigationComplete,
}: {
  onInvestigationComplete: (report: any) => void
}) {
  const { isAuthenticated, loading: authLoading } = useAuth()
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedMessage, setSelectedMessage] = useState<string | null>(null)

  // Check Gmail connection status — only after the CyberGuard session is ready
  const statusQuery = useQuery({
    queryKey: ['gmail-status'],
    queryFn: gmailApi.getStatus,
    enabled: isAuthenticated && !authLoading,
    retry: false,
    refetchOnWindowFocus: false,
  })

  // List messages — only when both CyberGuard auth and Gmail auth are confirmed
  const messagesQuery = useQuery({
    queryKey: ['gmail-messages', searchQuery],
    queryFn: () => gmailApi.listMessages({ query: searchQuery || undefined, max_results: 20 }),
    enabled: isAuthenticated && !authLoading && statusQuery.data?.connected === true,
    retry: false,
  })

  // Full investigation (SOC-style report)
  const investigateMutation = useMutation({
    mutationFn: (messageId: string) => gmailApi.investigateMessage(messageId),
    onSuccess: (data) => {
      onInvestigationComplete(data)
    },
  })

  // Connect Gmail
  const connectMutation = useMutation({
    mutationFn: () => gmailApi.connect(window.location.pathname),
    onSuccess: (data) => {
      // Redirect to Google OAuth
      window.location.href = data.auth_url
    },
    onError: (error: any) => {
      console.error('Gmail connect error:', error?.response?.data || error.message)
    }
  })

  // Disconnect Gmail
  const disconnectMutation = useMutation({
    mutationFn: gmailApi.disconnect,
    onSuccess: () => {
      statusQuery.refetch()
    },
  })

  const handleInvestigate = () => {
    if (selectedMessage) {
      investigateMutation.mutate(selectedMessage)
    }
  }

  const toggleMessageSelection = (id: string) => {
    setSelectedMessage(id)
  }

  // Not connected state
  if (!statusQuery.data?.connected) {
    return (
      <div className="text-center py-12">
        <div className="w-16 h-16 mx-auto mb-4 bg-slate-800 rounded-full flex items-center justify-center">
          <Lock className="w-8 h-8 text-slate-500" />
        </div>
        <h3 className="text-lg font-medium text-white mb-2">Connect Your Gmail</h3>
        <p className="text-slate-400 mb-6 max-w-md mx-auto">
          Connect your Gmail account to analyze emails directly. We only request read-only access for security analysis.
        </p>
        <button
          onClick={() => connectMutation.mutate()}
          disabled={connectMutation.isPending}
          className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          {connectMutation.isPending ? (
            <RefreshCw className="w-5 h-5 animate-spin" />
          ) : (
            <Mail className="w-5 h-5" />
          )}
          Connect Gmail
        </button>
        {connectMutation.error && (
          <p className="mt-4 text-red-400 text-sm">
            {(connectMutation.error as any)?.response?.status === 401
              ? 'Please log in to connect Gmail.'
              : (connectMutation.error as any)?.response?.data?.detail || 'Failed to connect. Please try again.'}
          </p>
        )}
        {statusQuery.error && (
          <p className="mt-4 text-yellow-400 text-sm">
            {(statusQuery.error as any)?.response?.status === 401
              ? 'You must be logged in to use Gmail integration.'
              : ''}
          </p>
        )}
        <p className="mt-4 text-xs text-slate-500">
          Only gmail.readonly permission requested • Your data stays secure
        </p>
      </div>
    )
  }

  // Connected state
  return (
    <div className="space-y-4">
      {/* Header with status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Unlock className="w-4 h-4 text-emerald-400" />
          <span className="text-sm text-slate-400">Connected:</span>
          <span className="text-sm text-white">{statusQuery.data.email}</span>
        </div>
        <button
          onClick={() => disconnectMutation.mutate()}
          className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-red-400 transition-colors"
        >
          <LogOut className="w-3 h-3" />
          Disconnect
        </button>
      </div>

      {/* Automatic monitoring status - reflects the real gmail_poll_enabled
          setting and this account's last poll cycle, never a fabricated
          "monitoring" badge when the poller is off or failing. */}
      <AutoMonitoringStatus status={statusQuery.data} />

      {/* Search and mode toggle */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search emails (e.g., from:suspicious@domain.com)"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
      </div>

      {/* Message list */}
      <div className="border border-slate-700 rounded-lg overflow-hidden">
        <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex items-center justify-between">
          <span className="text-sm text-slate-400">
            {messagesQuery.data?.total_estimate || 0} emails
          </span>
        </div>

        <div className="max-h-72 overflow-y-auto">
          {messagesQuery.isLoading ? (
            <div className="p-8 text-center">
              <RefreshCw className="w-6 h-6 animate-spin text-slate-500 mx-auto" />
            </div>
          ) : messagesQuery.data?.messages?.length === 0 ? (
            <div className="p-8 text-center text-slate-500">No emails found</div>
          ) : (
            messagesQuery.data?.messages?.map((msg: any) => (
              <div
                key={msg.id}
                onClick={() => toggleMessageSelection(msg.id)}
                className={clsx(
                  'px-4 py-3 border-b border-slate-800 cursor-pointer transition-colors',
                  selectedMessage === msg.id
                    ? 'bg-cyan-900/30 border-l-2 border-l-cyan-400'
                    : 'hover:bg-slate-800/50'
                )}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      {msg.is_unread && (
                        <span className="w-2 h-2 rounded-full bg-cyan-400" />
                      )}
                      <p className="text-sm font-medium text-white truncate">{msg.subject}</p>
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3" />
                        {msg.sender?.split('<')[0]?.trim() || msg.sender}
                      </span>
                      {msg.has_attachments && (
                        <span className="flex items-center gap-1">
                          <Paperclip className="w-3 h-3" />
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">
                      {msg.date ? new Date(msg.date).toLocaleDateString() : ''}
                    </span>
                    <ChevronRight className="w-4 h-4 text-slate-600" />
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Investigate button */}
      <div className="flex gap-2">
        <button
          onClick={handleInvestigate}
          disabled={!selectedMessage || investigateMutation.isPending}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          title="Full SOC-style investigation report"
        >
          {investigateMutation.isPending ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              Investigating...
            </>
          ) : (
            <>
              <FileSearch className="w-4 h-4" />
              Full Investigation
            </>
          )}
        </button>
      </div>

      {investigateMutation.error && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-5 h-5 text-red-400" />
          <p className="text-red-400 text-sm">
            {(investigateMutation.error as any)?.response?.data?.detail ||
              (investigateMutation.error as any)?.response?.data?.message ||
              'Investigation failed. Please try again.'}
          </p>
        </div>
      )}
    </div>
  )
}

// =============================================================================
// Upload Tab
// =============================================================================

function UploadTab({ onInvestigationComplete }: { onInvestigationComplete: (report: any) => void }) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)

  const uploadMutation = useMutation({
    mutationFn: (file: File) => analysisApi.uploadEmail(file),
    onSuccess: (data) => {
      onInvestigationComplete(data)
    },
  })

  const handleFileSelected = (file: File) => {
    setFileError(null)
    setSelectedFile(file)
    uploadMutation.reset()
  }

  const handleClear = () => {
    setSelectedFile(null)
    setFileError(null)
    uploadMutation.reset()
  }

  const handleAnalyze = () => {
    if (selectedFile && !uploadMutation.isPending) {
      uploadMutation.mutate(selectedFile)
    }
  }

  const getErrorMessage = (error: any): string => {
    if (error?.code === 'ECONNABORTED' || error?.message?.includes('timeout')) {
      return 'The request timed out. Please try again.'
    }
    const status = error?.response?.status
    if (status === 401) {
      return 'Authentication failed. Please log in again.'
    }
    if (status === 413) {
      return error?.response?.data?.detail || 'File is too large.'
    }
    if (status === 400) {
      return error?.response?.data?.detail || 'This file could not be analyzed.'
    }
    if (status >= 500) {
      return error?.response?.data?.detail || 'A server error occurred. Please try again later.'
    }
    return error?.response?.data?.detail || error?.response?.data?.message || 'Upload failed. Please try again.'
  }

  return (
    <div className="space-y-4">
      <EmailDropzone
        selectedFile={selectedFile}
        error={fileError}
        disabled={uploadMutation.isPending}
        onFileSelected={handleFileSelected}
        onError={setFileError}
        onClear={handleClear}
      />

      <button
        type="button"
        onClick={handleAnalyze}
        disabled={!selectedFile || uploadMutation.isPending}
        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {uploadMutation.isPending ? (
          <>
            <RefreshCw className="w-4 h-4 animate-spin" />
            Analyzing...
          </>
        ) : (
          <>
            <FileSearch className="w-4 h-4" />
            Analyze Email
          </>
        )}
      </button>

      {uploadMutation.isError && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{getErrorMessage(uploadMutation.error)}</p>
        </div>
      )}
    </div>
  )
}

// =============================================================================
// Analysis History Slide-over
// =============================================================================

function AnalysisHistoryPanel({ onClose }: { onClose: () => void }) {
  const historyQuery = useQuery({
    queryKey: ['analysis-history'],
    queryFn: () => analysisApi.getHistory({ limit: 50 }),
    retry: false,
  })

  const entries = Array.isArray(historyQuery.data) ? historyQuery.data : []

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-label="Analysis History">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Panel */}
      <div className="relative w-full max-w-md h-full bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" />
            Analysis History
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="px-6 py-3 text-xs text-slate-500 border-b border-slate-800">
          Shows past analysis summaries only. Full investigation reports are not retained — reopen is not available.
        </p>

        <div className="flex-1 overflow-y-auto">
          {historyQuery.isLoading ? (
            <div className="p-8 text-center">
              <RefreshCw className="w-6 h-6 animate-spin text-slate-500 mx-auto" />
            </div>
          ) : historyQuery.isError ? (
            <div className="p-6 text-center text-slate-500 text-sm">
              Could not load analysis history.
            </div>
          ) : entries.length === 0 ? (
            <div className="p-6 text-center text-slate-500 text-sm">
              No analysis history yet.
            </div>
          ) : (
            <div className="divide-y divide-slate-800">
              {entries.map((entry: any) => (
                <div key={entry.id} className="px-6 py-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {entry.email_subject || '(no subject)'}
                      </p>
                      <p className="text-xs text-slate-400 truncate mt-0.5">
                        {entry.email_sender || 'Unknown sender'}
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        {entry.analyzed_at ? new Date(entry.analyzed_at).toLocaleString() : ''}
                      </p>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      <span className="inline-block px-2 py-0.5 text-xs font-medium rounded bg-slate-800 text-slate-300">
                        {entry.classification?.toUpperCase() || 'UNKNOWN'}
                      </span>
                      <p className="text-xs text-slate-500 mt-1">Risk: {entry.risk_score ?? '—'}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// =============================================================================
// Main Page Component
// =============================================================================

export function EmailAnalysisPage() {
  const [activeTab, setActiveTab] = useState<'upload' | 'manual' | 'gmail'>('upload')
  const [showHistory, setShowHistory] = useState(false)
  const [investigationReport, setInvestigationReport] = useState<any>(null)

  // Check URL params for Gmail OAuth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.get('gmail_connected') === 'true') {
      setActiveTab('gmail')
      // Clear URL params
      window.history.replaceState({}, '', window.location.pathname)
    }
    if (params.get('gmail_error')) {
      // Handle error
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [])

  const handleInvestigationComplete = (report: any) => {
    setInvestigationReport(report)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Email Analysis</h1>
          <p className="text-slate-400 mt-1">Analyze emails for phishing and threats</p>
        </div>
        <button
          onClick={() => setShowHistory(true)}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg transition-colors text-sm"
        >
          <History className="w-4 h-4" />
          View History
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          {/* Tabs */}
          <div className="flex border-b border-slate-800">
            <button
              onClick={() => setActiveTab('upload')}
              className={clsx(
                'flex-1 px-4 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                activeTab === 'upload'
                  ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/30'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              <UploadCloud className="w-4 h-4" />
              Upload
            </button>
            <button
              onClick={() => setActiveTab('manual')}
              className={clsx(
                'flex-1 px-4 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                activeTab === 'manual'
                  ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/30'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              <Mail className="w-4 h-4" />
              Manual Input
            </button>
            <button
              onClick={() => setActiveTab('gmail')}
              className={clsx(
                'flex-1 px-4 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                activeTab === 'gmail'
                  ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/30'
                  : 'text-slate-400 hover:text-white'
              )}
            >
              <Inbox className="w-4 h-4" />
              Gmail
            </button>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {activeTab === 'upload' ? (
              <UploadTab onInvestigationComplete={handleInvestigationComplete} />
            ) : activeTab === 'manual' ? (
              <ManualInputTab onInvestigationComplete={handleInvestigationComplete} />
            ) : (
              <GmailTab onInvestigationComplete={handleInvestigationComplete} />
            )}
          </div>
        </div>

        {/* Results Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              Analysis Results
            </h2>
          </div>
          <div className="p-6">
            {investigationReport ? (
              <EmailInvestigationReport report={investigationReport} />
            ) : (
              <EmptyState
                icon={Mail}
                title="No analysis yet"
                description="Upload a .eml file, paste email details, or select a Gmail message to see analysis results here."
              />
            )}
          </div>
        </div>
      </div>

      {showHistory && <AnalysisHistoryPanel onClose={() => setShowHistory(false)} />}
    </div>
  )
}
