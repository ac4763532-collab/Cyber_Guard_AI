/**
 * CyberGuard AI - API Service
 *
 * Centralized API client for backend communication.
 */

import axios from 'axios'
import type {
  ApiInfo,
  HealthResponse,
  SimpleHealthResponse,
  FeedbackResponse,
  FeedbackDetail,
  FeedbackListResponse,
  FeedbackStatistics,
  ModuleAccuracyResponse,
  TrainingStatus,
  ModelVersionsResponse,
  DeploymentResponse,
  ThresholdConfig,
  ThresholdAnalysis,
  LLMAnalysisResponse,
  LLMStatusResponse,
  NotificationItem,
  UnreadCountResponse,
  LogSourceListResponse,
  LogSourceResponse,
  ConnectionCheckResult,
  DetectionReportResponse,
  ThreatIntelLookupResponse,
  ThreatIntelStatusResponse,
} from '@/types'

// Base URL for the backend API. VITE_API_URL is expected to be a path like
// "/api/v1" (proxied by nginx/vite in dev and prod) rather than a full origin,
// so this still works unchanged behind any host/port.
export const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

// Create axios instance with base configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Only clear the session when the request carried a token AND the backend
    // actually rejected that JWT. A 401 on a request that had no Authorization
    // header means auth wasn't initialized yet — don't wipe a valid session
    // that is still in the Firebase token-exchange race.
    //
    // Some endpoints (e.g. Gmail investigate/list) also return plain 401s for
    // reasons that have nothing to do with the login JWT - e.g. "Gmail not
    // connected" or "Gmail session expired" from a stale Google OAuth token
    // (see backend app/api/v1/gmail.py::_get_gmail_client). Those are not
    // login-session failures and must not log the user out. FastAPI's JWT
    // dependency (get_current_active_user) is the only thing that sets the
    // WWW-Authenticate header on its 401s, so use that to tell the two apart
    // instead of treating every 401 as "the JWT is bad".
    const isJwtRejection = Boolean(error.response?.headers?.['www-authenticate'])
    if (
      error.response?.status === 401 &&
      error.config?.headers?.Authorization &&
      isJwtRejection
    ) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
    }
    return Promise.reject(error)
  }
)

/**
 * Health check endpoints
 */
export const healthApi = {
  check: async (): Promise<SimpleHealthResponse> => {
    const { data } = await api.get<SimpleHealthResponse>('/health')
    return data
  },
  detailed: async (): Promise<HealthResponse> => {
    const { data } = await api.get<HealthResponse>('/health/detailed')
    return data
  },
}

/**
 * Authentication endpoints
 */
export const authApi = {
  login: async (username: string, password: string) => {
    const { data } = await api.post('/auth/login', { username, password })
    if (data.access_token) {
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('user', JSON.stringify(data.user))
    }
    return data
  },
  /**
   * Firebase login - exchange Firebase ID token for backend JWT
   */
  firebaseLogin: async (idToken: string) => {
    const { data } = await api.post('/auth/firebase-login', { id_token: idToken })
    if (data.access_token) {
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('user', JSON.stringify(data.user))
    }
    return data
  },
  /**
   * Check if Firebase auth is enabled on backend
   */
  getFirebaseStatus: async () => {
    const { data } = await api.get('/auth/firebase-status')
    return data
  },
  logout: () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
  },
  getMe: async () => {
    const { data } = await api.get('/auth/me')
    return data
  },
  verify: async () => {
    const { data } = await api.get('/auth/verify')
    return data
  },
  isAuthenticated: () => {
    return !!localStorage.getItem('access_token')
  },
  getUser: () => {
    const user = localStorage.getItem('user')
    return user ? JSON.parse(user) : null
  },
}

/**
 * Analysis endpoints
 */
export const analysisApi = {
  analyzeEmail: async (emailData: {
    subject: string
    body: string
    sender?: string
    headers?: Record<string, string>
    urls?: string[]
    attachments?: Array<{ filename: string; content_type: string }>
  }) => {
    const { data } = await api.post('/analysis/email', emailData)
    return data
  },
  investigateEmail: async (emailData: {
    subject: string
    body: string
    sender: string
    headers?: Record<string, string>
    urls?: string[]
    attachments?: Array<{ filename: string; content_type: string }>
  }) => {
    // Full investigation enriches every URL/domain via external threat-intel
    // (VirusTotal), which has its own server-side rate-limit wait of up to
    // 30s per lookup. That can push total request time past the global 30s
    // default and get killed client-side right as the backend is about to
    // succeed, so this call gets a longer budget than the global default.
    const { data } = await api.post('/analysis/email/investigate', emailData, {
      timeout: 60000,
    })
    return data
  },
  /**
   * Upload a raw .eml file for the same full investigation report as
   * investigateEmail, with real header-derived data (SPF/DKIM/DMARC, etc.)
   * when present in the file.
   */
  uploadEmail: async (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    // Same threat-intel enrichment path as investigateEmail - see the
    // timeout comment there.
    const { data } = await api.post('/analysis/email/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 60000,
    })
    return data
  },
  /**
   * List recent analysis history summaries (not full reports).
   */
  getHistory: async (params?: {
    limit?: number
    offset?: number
    classification?: string
    analysis_type?: string
  }) => {
    const { data } = await api.get('/analysis/history', { params })
    return data
  },
  analyzeLogs: async (logData: {
    log_content: string
    log_type?: string
    source?: string
  }) => {
    const { data } = await api.post('/analysis/logs', logData)
    return data
  },
  /**
   * Upload a raw log file (.log/.txt/.csv/.json/.jsonl) for parsing and,
   * unless previewOnly, the same deterministic LogAgent analysis as
   * analyzeLogs - see POST /analysis/logs/upload
   * (backend/app/api/v1/analysis.py::upload_log_file). Requires auth
   * (unlike uploadEmail/analyzeLogs, which have no auth dependency today).
   */
  uploadLogFile: async (
    file: File,
    sourceTypeHint: 'windows' | 'linux_ssh' | 'android' | 'auto' = 'auto',
    options?: { onProgress?: (percent: number) => void; previewOnly?: boolean }
  ) => {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('source_type_hint', sourceTypeHint)
    formData.append('preview_only', String(options?.previewOnly ?? false))

    const { data } = await api.post('/analysis/logs/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 60000,
      onUploadProgress: options?.onProgress
        ? (progressEvent) => {
            if (!progressEvent.total) return
            options.onProgress!(Math.round((progressEvent.loaded / progressEvent.total) * 100))
          }
        : undefined,
    })
    return data
  },
  /**
   * Run an authorized port scan against a target. Matches the backend's
   * NetworkAnalysisRequest exactly: target, scan_type (basic/service/full),
   * and the required authorized confirmation. No ports/authorization_token
   * fields exist server-side.
   */
  analyzeNetwork: async (networkData: {
    target: string
    scan_type?: 'basic' | 'service' | 'full'
    authorized: boolean
  }) => {
    const { data } = await api.post('/analysis/network', networkData)
    return data
  },
  /**
   * Lightweight passive OSINT lookup for an IP or domain: DNS, geolocation,
   * RDAP, and threat-intel reputation (when VirusTotal/AbuseIPDB keys are
   * configured). No scan of the target's live systems, so no authorization
   * confirmation is required.
   */
  lookupNetwork: async (target: string) => {
    const { data } = await api.post('/analysis/network/lookup', { target })
    return data
  },
}

/**
 * Detection endpoints
 */
export const detectionApi = {
  analyze: async (requestData: {
    data: Record<string, unknown>
    skip_rules?: boolean
    skip_ioc?: boolean
    skip_anomaly?: boolean
  }) => {
    const { data } = await api.post('/detection/analyze', requestData)
    return data
  },
  getStatistics: async () => {
    const { data } = await api.get('/detection/statistics')
    return data
  },
  getRules: async () => {
    const { data } = await api.get('/detection/rules')
    return data
  },
  getIOCs: async () => {
    const { data } = await api.get('/detection/iocs')
    return data
  },
}

/**
 * Alerts endpoints
 */
export const alertsApi = {
  list: async (params?: {
    status?: string
    severity?: string
    category?: string
    limit?: number
    offset?: number
  }) => {
    const { data } = await api.get('/alerts', { params })
    // Backend returns list[AlertResponse] (plain array); wrap for consistent shape
    const arr = Array.isArray(data) ? data : []
    return { alerts: arr, total: arr.length }
  },
  get: async (id: string) => {
    const { data } = await api.get(`/alerts/${id}`)
    return data
  },
  create: async (alertData: {
    title: string
    description: string
    severity: string
    risk_score?: number
    source?: string
    mitre_techniques?: string[]
  }) => {
    const { data } = await api.post('/alerts', alertData)
    return data
  },
  update: async (id: string, updateData: {
    status?: string
    assigned_to?: string
    note?: string
  }) => {
    const { data } = await api.patch(`/alerts/${id}`, updateData)
    return data
  },
  getStatistics: async () => {
    const { data } = await api.get('/alerts/statistics')
    return data
  },
  /**
   * Recover alerts missed while disconnected from the real-time feed
   * (GET /alerts/recent, tenant-scoped server-side). `since` should be
   * the created_at of the last alert the caller successfully processed.
   */
  getRecent: async (params?: { since?: string; limit?: number }) => {
    const { data } = await api.get('/alerts/recent', { params })
    return Array.isArray(data) ? data : []
  },
}

/**
 * Notifications endpoints (Phase 10 - real delivery, in-app inbox)
 *
 * Scoped server-side to the authenticated caller - there is no user_id
 * param here because the backend ignores any client-supplied identity
 * for these routes and always uses the JWT's own user.
 */
export const notificationsApi = {
  list: async (params?: { unread_only?: boolean; limit?: number; offset?: number }): Promise<NotificationItem[]> => {
    const { data } = await api.get('/notifications', { params })
    return Array.isArray(data) ? data : []
  },
  getUnreadCount: async (): Promise<UnreadCountResponse> => {
    const { data } = await api.get('/notifications/unread-count')
    return data
  },
  markRead: async (id: string): Promise<NotificationItem> => {
    const { data } = await api.post(`/notifications/${id}/read`)
    return data
  },
}

/**
 * Events endpoints
 */
export const eventsApi = {
  list: async (params?: {
    event_type?: string
    status?: string
    severity?: string
    search?: string
    limit?: number
    offset?: number
  }) => {
    // Backend now returns a real { events, total, limit, offset } shape
    // (see GET /events in app/api/v1/events.py) - total reflects the full
    // matching row count server-side, not just this page's length, so
    // the frontend can show "showing X of Y" / enable "load more"
    // correctly instead of a fake total that always equals the page size.
    const { data } = await api.get('/events', { params })
    const events = Array.isArray(data?.events) ? data.events : []
    return {
      events,
      total: typeof data?.total === 'number' ? data.total : events.length,
      limit: data?.limit ?? params?.limit ?? 1000,
      offset: data?.offset ?? params?.offset ?? 0,
    }
  },
  get: async (id: string) => {
    const { data } = await api.get(`/events/${id}`)
    return data
  },
  ingest: async (eventData: {
    event_type: string
    source: string
    raw_data: Record<string, unknown>
    auto_analyze?: boolean
  }) => {
    const { data } = await api.post('/events', eventData)
    return data
  },
  reanalyze: async (id: string) => {
    const { data } = await api.post(`/events/${id}/reanalyze`)
    return data
  },
  getStatistics: async () => {
    const { data } = await api.get('/events/statistics')
    return data
  },
}

/**
 * Correlation endpoints
 */
export const correlationApi = {
  analyze: async (requestData: {
    events: Array<{
      event_id: string
      domain: string
      timestamp: string
      ips?: string[]
      domains?: string[]
      users?: string[]
      risk_score?: number
      severity?: string
      mitre_techniques?: string[]
    }>
    time_window_hours?: number
  }) => {
    const { data } = await api.post('/correlation/analyze', requestData)
    return data
  },
  getStatistics: async () => {
    const { data } = await api.get('/correlation/statistics')
    return data
  },
  recorrelate: async (findingIds: string[]) => {
    const { data } = await api.post('/correlation/recorrelate', { finding_ids: findingIds })
    return data
  },
  getActivities: async (limit = 100, offset = 0) => {
    const { data } = await api.get('/correlation/activities', { params: { limit, offset } })
    return data
  },
}

/**
 * Threat Intelligence endpoints
 */
export const threatIntelApi = {
  lookup: async (iocType: string, iocValue: string): Promise<ThreatIntelLookupResponse> => {
    const { data } = await api.post('/threat-intel/lookup', { ioc_type: iocType, ioc_value: iocValue })
    return data
  },
  lookupBatch: async (
    iocs: Array<{ ioc_type: string; ioc_value: string }>
  ): Promise<ThreatIntelLookupResponse[]> => {
    const { data } = await api.post('/threat-intel/lookup/batch', { iocs })
    return data
  },
  getStatus: async (): Promise<ThreatIntelStatusResponse> => {
    const { data } = await api.get('/threat-intel/status')
    return data
  },
}

/**
 * LLM endpoints
 */
export const llmApi = {
  getStatus: async (): Promise<LLMStatusResponse> => {
    const { data } = await api.get('/llm/status')
    return data
  },
  analyzeThreat: async (
    findings: Array<Record<string, unknown>>,
    context?: Record<string, unknown>,
    structuredOutput?: boolean
  ): Promise<LLMAnalysisResponse> => {
    const { data } = await api.post('/llm/analyze-threat', {
      findings,
      context,
      structured_output: structuredOutput ?? false,
    })
    return data
  },
  getRemediation: async (incidentData: Record<string, unknown>): Promise<LLMAnalysisResponse> => {
    const { data } = await api.post('/llm/remediation', { incident_data: incidentData })
    return data
  },
  enrichIOC: async (iocType: string, iocValue: string): Promise<LLMAnalysisResponse> => {
    const { data } = await api.post('/llm/enrich-ioc', { ioc_type: iocType, ioc_value: iocValue })
    return data
  },
  mapToMITRE: async (
    description: string,
    findings?: Array<Record<string, unknown>>
  ): Promise<LLMAnalysisResponse> => {
    const { data } = await api.post('/llm/map-mitre', { description, findings })
    return data
  },
  /**
   * Chat with the cybersecurity AI assistant (non-streaming).
   */
  chat: async (
    message: string,
    conversationHistory?: Array<{ role: string; content: string }>
  ): Promise<LLMAnalysisResponse> => {
    const { data } = await api.post('/llm/chat', {
      message,
      conversation_history: conversationHistory,
    })
    return data
  },
  /**
   * Stream an analysis response using the Fetch API (axios doesn't support
   * streaming response bodies in the browser). Yields text chunks as they
   * arrive. `signal` can be used to abort the stream.
   */
  stream: async function* (
    prompt: string,
    systemPrompt?: string,
    signal?: AbortSignal
  ): AsyncGenerator<string, void, unknown> {
    const token = localStorage.getItem('access_token')
    const response = await fetch(`${API_BASE_URL}/llm/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ prompt, system_prompt: systemPrompt }),
      signal,
    })

    if (!response.ok || !response.body) {
      const text = await response.text().catch(() => '')
      throw new Error(text || `Stream request failed: ${response.status}`)
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        yield decoder.decode(value, { stream: true })
      }
    } finally {
      reader.releaseLock()
    }
  },
}

/**
 * Reports endpoints
 */
export const incidentsApi = {
  list: async (status?: string) => {
    const { data } = await api.get('/incidents', { params: status ? { status } : {} })
    return data
  },
  get: async (incidentId: string) => {
    const { data } = await api.get(`/incidents/${encodeURIComponent(incidentId)}`)
    return data
  },
  qualifyFinding: async (findingId: string) => {
    const { data } = await api.post('/incidents/qualify', { finding_id: findingId })
    return data
  },
  updateStatus: async (incidentId: string, status: string, reason: string) => {
    const { data } = await api.patch(`/incidents/${encodeURIComponent(incidentId)}/status`, { status, reason })
    return data
  },
}

export const reportsApi = {
  getSummary: async (hours?: number, includeNarrative?: boolean) => {
    const { data } = await api.get('/reports/summary', { params: { hours: hours || 24, include_narrative: includeNarrative } })
    return data
  },
  getExecutive: async (hours?: number, includeNarrative?: boolean) => {
    const { data } = await api.get('/reports/executive', { params: { hours: hours || 24, include_narrative: includeNarrative } })
    return data
  },
  getThreatLandscape: async (includeNarrative?: boolean) => {
    const { data } = await api.get('/reports/threat-landscape', { params: { include_narrative: includeNarrative } })
    return data
  },
  getIncidentInvestigation: async (incidentId: string, includeNarrative?: boolean) => {
    const { data } = await api.get('/reports/incident-investigation', { params: { incident_id: incidentId, include_narrative: includeNarrative } })
    return data
  },
  getCorrelation: async (correlationIds: string[], includeNarrative?: boolean) => {
    const { data } = await api.get('/reports/correlation', { params: { correlation_ids: correlationIds.join(','), include_narrative: includeNarrative } })
    return data
  },
  getCompliance: async () => {
    const { data } = await api.get('/reports/compliance')
    return data
  },
  list: async (params?: { limit?: number; offset?: number; report_type?: string; status?: string }) => {
    const { data } = await api.get('/reports', { params })
    return data
  },
  get: async (reportId: string) => {
    const { data } = await api.get(`/reports/${encodeURIComponent(reportId)}`)
    return data
  },
  export: async (reportId: string, format: 'json' | 'pdf' | 'csv' = 'json') => {
    const { data } = await api.get(`/reports/${encodeURIComponent(reportId)}/export`, { 
      params: { format },
      responseType: format === 'json' ? 'json' : 'blob'
    })
    return data
  },
}

/**
 * Gmail integration endpoints
 */
export const gmailApi = {
  /**
   * Get Gmail connection status
   */
  getStatus: async () => {
    const { data } = await api.get('/gmail/status')
    return data
  },
  /**
   * Initiate Gmail OAuth flow
   */
  connect: async (redirectAfter?: string) => {
    const params = redirectAfter ? { redirect_after: redirectAfter } : {}
    const { data } = await api.get('/gmail/oauth/connect', { params })
    return data
  },
  /**
   * Disconnect Gmail account
   */
  disconnect: async () => {
    const { data } = await api.post('/gmail/disconnect')
    return data
  },
  /**
   * List Gmail messages
   */
  listMessages: async (params?: {
    query?: string
    max_results?: number
    page_token?: string
    label?: string
  }) => {
    const { data } = await api.get('/gmail/messages', { params })
    return data
  },
  /**
   * Get a specific Gmail message
   */
  getMessage: async (messageId: string) => {
    const { data } = await api.get(`/gmail/messages/${messageId}`)
    return data
  },
  /**
   * Analyze a Gmail message for threats
   */
  analyzeMessage: async (messageId: string, includeRaw: boolean = true) => {
    const { data } = await api.post(`/gmail/analyze/${messageId}`, { include_raw: includeRaw })
    return data
  },
  /**
   * Full investigation report for a Gmail message (enhanced SOC-style report)
   */
  investigateMessage: async (messageId: string) => {
    const { data } = await api.post(`/gmail/investigate/${messageId}`)
    return data
  },
  /**
   * Analyze multiple Gmail messages (batch/campaign detection)
   */
  analyzeBatch: async (messageIds: string[]) => {
    const { data } = await api.post('/gmail/analyze-batch', messageIds)
    return data
  },
}

/**
 * Log Analysis endpoints (Step 8)
 */
export const logsApi = {
  // Log Sources
  listSources: async (params?: {
    status?: string
    source_type?: string
    limit?: number
    offset?: number
  }): Promise<LogSourceListResponse> => {
    const { data } = await api.get('/logs/sources', { params })
    return data
  },
  getSource: async (sourceId: string): Promise<LogSourceResponse> => {
    const { data } = await api.get(`/logs/sources/${sourceId}`)
    return data
  },
  createSource: async (sourceData: {
    name: string
    description?: string
    source_type: string
    collector_type?: string
    configuration?: Record<string, unknown>
    parser_config?: Record<string, unknown>
    include_patterns?: string[]
    exclude_patterns?: string[]
  }) => {
    const { data } = await api.post('/logs/sources', sourceData)
    return data
  },
  updateSource: async (sourceId: string, updateData: {
    name?: string
    description?: string
    status?: string
    configuration?: Record<string, unknown>
    parser_config?: Record<string, unknown>
    include_patterns?: string[]
    exclude_patterns?: string[]
  }) => {
    const { data } = await api.patch(`/logs/sources/${sourceId}`, updateData)
    return data
  },
  deleteSource: async (sourceId: string) => {
    const { data } = await api.delete(`/logs/sources/${sourceId}`)
    return data
  },
  restartSource: async (sourceId: string) => {
    const { data } = await api.post(`/logs/sources/${sourceId}/restart`)
    return data
  },
  stopSource: async (sourceId: string) => {
    const { data } = await api.post(`/logs/sources/${sourceId}/stop`)
    return data
  },
  // Detection report for automatic monitoring (View Detection Report).
  // Computed server-side on demand from persisted events/findings/alerts -
  // see backend app/api/v1/logs.py's get_log_source_report(). since/until
  // default server-side to the source's creation time / now when omitted.
  getSourceReport: async (
    sourceId: string,
    params?: { since?: string; until?: string }
  ): Promise<DetectionReportResponse> => {
    const { data } = await api.get(`/logs/sources/${sourceId}/report`, { params })
    return data
  },
  // Permission/connectivity pre-flight check against an existing source's
  // real target. Admin-only; never fabricates ok:true.
  checkConnection: async (sourceId: string): Promise<ConnectionCheckResult> => {
    const { data } = await api.post(`/logs/sources/${sourceId}/check-connection`)
    return data
  },
  // Same check, but before any source exists yet - used by the Add Source
  // modal's "Test connection" button. Persists nothing.
  checkConnectionPreview: async (payload: {
    source_type: string
    configuration?: Record<string, unknown>
    credentials?: Record<string, unknown>
  }): Promise<ConnectionCheckResult> => {
    const { data } = await api.post('/logs/sources/check-connection/preview', payload)
    return data
  },

  // Log Events
  listEvents: async (params?: {
    source_id?: string
    source_type?: string
    hostname?: string
    level?: string
    category?: string
    analyzed?: boolean
    search?: string
    start_time?: string
    end_time?: string
    limit?: number
    offset?: number
  }) => {
    const { data } = await api.get('/logs/events', { params })
    return data
  },
  getEvent: async (eventId: string) => {
    const { data } = await api.get(`/logs/events/${eventId}`)
    return data
  },
  getStatistics: async (params?: {
    source_id?: string
    hours?: number
  }) => {
    const { data } = await api.get('/logs/events/statistics', { params })
    return data
  },

  // Log Ingestion
  ingest: async (entries: Array<{
    timestamp: string
    hostname?: string
    program?: string
    level?: string
    message: string
    raw_line?: string
    extracted_fields?: Record<string, unknown>
    tags?: string[]
  }>, sourceId?: string, publishToBus: boolean = true) => {
    const { data } = await api.post('/logs/ingest', entries, {
      params: { source_id: sourceId, publish_to_bus: publishToBus }
    })
    return data
  },
  ingestRaw: async (params: {
    log_content: string
    source_id?: string
    source_type?: string
    hostname?: string
    analyze?: boolean
  }) => {
    const { data } = await api.post('/logs/ingest/raw', null, { params })
    return data
  },
}

/**
 * Feedback endpoints (Step 12)
 */
export const feedbackApi = {
  /**
   * Submit feedback on an analysis result. Requires authentication.
   */
  submit: async (feedbackData: {
    analysis_id: string
    feedback_type: 'false_positive' | 'false_negative' | 'wrong_category' | 'confirmed'
    correct_classification?: string
    comment?: string
  }): Promise<FeedbackResponse> => {
    const { data } = await api.post('/feedback', feedbackData)
    return data
  },
  /**
   * Get pending feedback awaiting review. Admin only.
   */
  getPending: async (params?: { limit?: number; offset?: number }): Promise<FeedbackListResponse> => {
    const { data } = await api.get('/feedback/pending', { params })
    return data
  },
  /**
   * Get a specific feedback item's detail. Admin only.
   */
  get: async (feedbackId: string): Promise<FeedbackDetail> => {
    const { data } = await api.get(`/feedback/${feedbackId}`)
    return data
  },
  /**
   * Approve, reject, or mark a feedback item as duplicate. Admin only.
   */
  review: async (
    feedbackId: string,
    reviewData: { status: 'approved' | 'rejected' | 'duplicate'; notes?: string }
  ): Promise<FeedbackDetail> => {
    const { data } = await api.post(`/feedback/${feedbackId}/review`, reviewData)
    return data
  },
  /**
   * Get aggregate feedback statistics. Admin only.
   */
  getStatistics: async (): Promise<FeedbackStatistics> => {
    const { data } = await api.get('/feedback/statistics')
    return data
  },
  /**
   * Get real, feedback-derived accuracy stats for LogAgent (the rule-based
   * log analysis engine). accuracy_percent is null until reviewed feedback
   * exists - never a fabricated or default percentage.
   */
  getLogModuleAccuracy: async (): Promise<ModuleAccuracyResponse> => {
    const { data } = await api.get('/feedback/module-accuracy/log')
    return data
  },
  /**
   * Get real, feedback-derived accuracy stats for NetworkAgent (the
   * rule-based scanning/vulnerability engine). accuracy_percent is null
   * until reviewed feedback exists - never a fabricated or default
   * percentage.
   */
  getNetworkModuleAccuracy: async (): Promise<ModuleAccuracyResponse> => {
    const { data } = await api.get('/feedback/module-accuracy/network')
    return data
  },
}

/**
 * Training / ML Ops endpoints (Step 13). All admin-only on the backend.
 */
export const trainingApi = {
  listModels: async (): Promise<ModelVersionsResponse> => {
    const { data } = await api.get('/training/models')
    return data
  },
  getModel: async (version: string) => {
    const { data } = await api.get(`/training/models/${version}`)
    return data
  },
  retrain: async (requestData?: {
    auto_deploy?: boolean
    min_samples?: number
    min_f1_improvement?: number
    export_feedback?: boolean
  }) => {
    const { data } = await api.post('/training/retrain', requestData || {})
    return data
  },
  deploy: async (version: string, force: boolean = false): Promise<DeploymentResponse> => {
    const { data } = await api.post('/training/deploy', { version, force })
    return data
  },
  rollback: async (): Promise<DeploymentResponse> => {
    const { data } = await api.post('/training/rollback')
    return data
  },
  compare: async (versionA: string, versionB: string) => {
    const { data } = await api.post('/training/compare', { version_a: versionA, version_b: versionB })
    return data
  },
  getDeploymentHistory: async (limit: number = 20) => {
    const { data } = await api.get('/training/history', { params: { limit } })
    return data
  },
  listFeedbackExportBatches: async () => {
    const { data } = await api.get('/training/feedback/export-batches')
    return data
  },
  exportFeedback: async (limit: number = 1000, markAsExported: boolean = true) => {
    const { data } = await api.post('/training/feedback/export', null, {
      params: { limit, mark_as_exported: markAsExported },
    })
    return data
  },
  getTrainingDataInfo: async () => {
    const { data } = await api.get('/training/data/info')
    return data
  },
  combineTrainingData: async () => {
    const { data } = await api.post('/training/data/combine')
    return data
  },
  getThreshold: async (): Promise<ThresholdConfig> => {
    const { data } = await api.get('/training/threshold')
    return data
  },
  tuneThreshold: async (requestData?: {
    target_fp_rate?: number
    target_fn_rate?: number
    dry_run?: boolean
  }) => {
    const { data } = await api.post('/training/threshold/tune', requestData || {})
    return data
  },
  setThreshold: async (threshold: number, domain?: string, reason?: string) => {
    const { data } = await api.post('/training/threshold/set', { threshold, domain, reason })
    return data
  },
  resetThreshold: async (domain?: string) => {
    const { data } = await api.post('/training/threshold/reset', null, { params: { domain } })
    return data
  },
  analyzeThresholdErrors: async (): Promise<ThresholdAnalysis> => {
    const { data } = await api.get('/training/threshold/analyze')
    return data
  },
  getStatus: async (): Promise<TrainingStatus> => {
    const { data } = await api.get('/training/status')
    return data
  },
}

/**
 * WebSocket connection
 */
export const wsApi = {
  getStats: async () => {
    const { data } = await api.get('/ws/stats')
    return data
  },
  connect: (channels: string[] = ['system', 'alerts'], token?: string) => {
    // Derive scheme/host from the current page so this works through any
    // reverse proxy (nginx in Docker, Vite dev server, prod) instead of
    // only against a hardcoded localhost backend.
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const params = new URLSearchParams({ channels: channels.join(',') })
    // Browsers cannot set a custom Authorization header on a WebSocket
    // upgrade request, so the backend (app/websocket/auth.py) accepts the
    // same JWT as a query param instead. Omitted entirely when no token
    // is passed, so callers that don't need auth (none exist today, but
    // kept backward compatible) still work unchanged.
    if (token) params.set('token', token)
    const wsUrl = `${wsProtocol}//${window.location.host}/api/v1/ws?${params.toString()}`
    return new WebSocket(wsUrl)
  },
}

/**
 * Root API info
 */
export const getApiInfo = async (): Promise<ApiInfo> => {
  const { data } = await axios.get<ApiInfo>('/')
  return data
}

export default api
