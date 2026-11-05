/**
 * CyberGuard AI - Type Definitions
 */

// Health check types
export interface ComponentStatus {
  name: string
  status: 'online' | 'offline' | 'degraded' | 'pending'
  message: string | null
  latency_ms: number | null
  last_run?: string | null
  last_successful_run?: string | null
  total_analyzed?: number | null
  error_count?: number | null
}

export interface HealthResponse {
  status: 'healthy' | 'unhealthy' | 'degraded'
  timestamp: string
  version: string
  environment?: string
  components?: Record<string, ComponentStatus>
}

export interface SimpleHealthResponse {
  status: string
  timestamp: string
  version: string
}

// API info types
export interface ApiInfo {
  name: string
  version: string
  description: string
  documentation: {
    swagger: string
    redoc: string
    openapi: string
  }
  health: string
}

// Severity levels
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// Agent types
export type AgentType = 'email' | 'log' | 'network'

export interface AgentStatus {
  name: string
  type: AgentType
  status: 'online' | 'offline' | 'pending' | 'error'
  lastRun: string | null
  totalAnalyzed: number
  errorCount: number
}

// Dashboard statistics (will be populated from real data later)
export interface DashboardStats {
  critical: number
  high: number
  medium: number
  low: number
  totalEvents: number
  resolvedToday: number
}

// =============================================================================
// Feedback types (Step 12)
// =============================================================================

export type FeedbackType = 'false_positive' | 'false_negative' | 'wrong_category' | 'confirmed'
export type FeedbackStatus = 'pending' | 'approved' | 'rejected' | 'duplicate'

// =============================================================================
// Notification types (Phase 10 - real delivery, in-app inbox)
// =============================================================================

export type NotificationStatus = 'pending' | 'sent' | 'failed' | 'read'

export interface NotificationItem {
  id: string
  alert_id: string | null
  severity: string
  title: string
  summary: string
  status: NotificationStatus
  created_at: string
  read_at: string | null
}

export interface UnreadCountResponse {
  unread_count: number
}

// =============================================================================
// Log source / collector health types
//
// `collector_status` reflects real, in-memory CollectorManager telemetry
// (see backend/app/logs/collector_manager.py::CollectorSupervisorStatus).
// It is `null` whenever no live supervisor exists for a source - e.g. a
// PENDING/DISABLED source, an HTTP_RECEIVER source (no embedded collector),
// or any source the backend hasn't re-started since its last restart. This
// is an honest absence signal, never a fabricated "stopped"/"idle" object.
// =============================================================================

export type SupervisorState =
  | 'starting'
  | 'running'
  | 'reconnecting'
  | 'stopping'
  | 'stopped'
  | 'failed'

export interface CollectorStatus {
  state: SupervisorState
  started_at: string | null
  last_successful_collection_at: string | null
  reconnect_count: number
  error_count: number
  last_error: string | null
  last_error_at: string | null
}

// Result of a one-off connection/permission pre-flight check against a
// collector's real target (Windows event log, SSH host, adb device). Never
// a simulation - `ok: true` only when the backend's own connect()/
// disconnect() (or device-state probe) actually succeeded just now.
export interface ConnectionCheckResult {
  ok: boolean
  source_type: string
  message: string
  detail: string | null
}

export interface LogSourceResponse {
  id: string
  name: string
  description: string | null
  source_type: string
  collector_type: string
  status: string
  last_event_at: string | null
  event_count: number
  error_message: string | null
  configuration: Record<string, unknown>
  created_by: string
  organization_id: string
  created_at: string
  updated_at: string
  collector_status: CollectorStatus | null
}

export interface LogSourceListResponse {
  sources: LogSourceResponse[]
  total: number
  limit: number
  offset: number
}

// Detection report for automatic monitoring (View Detection Report).
// Mirrors backend app/schemas/analysis.py's DetectionReportResponse -
// computed on demand from persisted events/findings/alerts, never a
// separate fabricated "run" concept.
export interface DetectionReportFinding {
  finding_id: string
  rule_id: string | null
  name: string
  description: string
  severity: string
  confidence: number
  evidence: string[]
  mitre_techniques: string[]
  recommendations: string[]
  metadata: Record<string, unknown> | null
  source_ip: string | null
  host: string | null
  timestamp: string | null
}

export type DetectionReportStatus =
  | 'monitoring'
  | 'detection_in_progress'
  | 'detection_completed'
  | 'completed_with_findings'
  | 'completed_no_threats'
  | 'partially_completed'
  | 'failed'

export interface DetectionReportResponse {
  source_id: string
  source_name: string
  source_type: string
  hostname: string | null
  time_range_start: string
  time_range_end: string
  generated_at: string
  status: DetectionReportStatus
  collector_status: string | null
  events_processed: number
  events_pending: number
  events_failed: number
  findings_count: number
  severity_breakdown: Record<string, number>
  errors: string[]
  findings: DetectionReportFinding[]
  alert_ids: string[]
}

export interface FeedbackResponse {
  feedback_id: string
  analysis_id: string
  feedback_type: string
  status: string
  submitted_at: string
  message: string
}

export interface FeedbackFinding {
  rule_id?: string | null
  name?: string | null
  severity?: string | null
}

export interface FeedbackDetail {
  feedback_id: string
  analysis_id: string
  original_classification: string
  original_risk_score: number
  original_findings: FeedbackFinding[]
  feedback_type: string
  correct_classification: string | null
  user_comment: string | null
  email_sender: string | null
  email_subject: string | null
  submitted_by: string | null
  submitted_at: string
  status: string
  reviewed_by: string | null
  reviewed_at: string | null
  review_notes: string | null
  included_in_training: boolean
}

export interface FeedbackListResponse {
  items: FeedbackDetail[]
  total: number
  page: number
  page_size: number
}

export interface FeedbackStatistics {
  total_feedback: number
  pending_count: number
  approved_count: number
  rejected_count: number
  duplicate_count: number
  false_positive_count: number
  false_negative_count: number
  wrong_category_count: number
  included_in_training_count: number
}

/**
 * Real, feedback-derived accuracy signal for a rule-based analysis module
 * (currently: LogAgent). accuracy_percent is null until at least one
 * confirmed/false_positive feedback submission exists - never a fabricated
 * or default percentage.
 */
export interface ModuleAccuracyResponse {
  total_analyses: number
  total_feedback_count: number
  confirmed_count: number
  false_positive_count: number
  accuracy_percent: number | null
}

// =============================================================================
// Training / ML Ops types (Step 13)
// =============================================================================

export interface ModelVersionInfo {
  version: string
  trained_at: string | null
  deployed_at: string | null
  is_current: boolean
  train_samples: number
  metrics: Record<string, number> | null
  status: string
}

export interface ModelVersionsResponse {
  current_version: string | null
  previous_version: string | null
  versions: ModelVersionInfo[]
  total_versions: number
}

export interface DeploymentResponse {
  success: boolean
  version: string
  previous_version: string | null
  message: string
  deployed_at: string | null
  rollback_available: boolean
}

export interface ThresholdConfig {
  global_threshold: number
  domain_thresholds: Record<string, number>
  last_updated: string | null
  feedback_samples_used: number
  false_positive_rate: number | null
  false_negative_rate: number | null
  adjustment_history: Array<Record<string, unknown>>
}

export interface ThresholdAnalysis {
  total_feedback_samples: number
  false_positives: number
  false_negatives: number
  wrong_category: number
  fp_rate: number
  fn_rate: number
  by_sender_domain: Record<string, unknown>
  current_threshold: number
}

export interface TrainingStatus {
  current_model: {
    version: string | null
    rollback_available: boolean
  }
  threshold: {
    current: number
    last_tuned: string | null
    feedback_samples: number
    fp_rate: number | null
    fn_rate: number | null
  }
  available_versions: number
  original_data: Record<string, unknown>
  feedback_batches: number
  system_ready: boolean
  feedback_improves_detection: string
}

// =============================================================================
// LLM types
// =============================================================================

export interface LLMAnalysisResponse {
  response_id: string
  content: string
  structured_data: Record<string, unknown> | null
  model: string
  tokens_used: number
  input_tokens: number
  output_tokens: number
  processing_time_ms: number
  success: boolean
  error: string | null
}

export interface LLMStatusResponse {
  available: boolean
  model: string | null
  templates: string[]
  usage: {
    total_requests: number
    total_input_tokens: number
    total_output_tokens: number
    total_cost_usd: number
    errors: number
  } | null
}

// =============================================================================
// Threat Intelligence types
// =============================================================================

/** Final reputation classification. Kept distinct from each provider's own
 * execution status (ProviderOutcome.status) - a failed/timed-out lookup is
 * never represented as "clean". */
export type ReputationStatus = 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'lookup_failed'

/** A single provider's execution outcome, always present for every provider
 * that was attempted, whether it succeeded or failed. */
export interface ProviderOutcome {
  name: string
  status: 'success' | 'timeout' | 'auth_error' | 'rate_limited' | 'unavailable' | 'not_configured'
  detections: number | null
  confidence_score: number | null
  last_analysis_at: string | null
  detail: string | null
}

export interface ThreatIntelLookupResponse {
  ioc_type: string
  ioc_value: string
  reputation_status: ReputationStatus
  classification_reason: string
  risk_score: number | null
  sources: string[]
  provider_outcomes: ProviderOutcome[]
  recommendations: string[]
  success: boolean
  error: string | null
}

export interface ThreatIntelStatusResponse {
  virustotal_configured: boolean
  abuseipdb_configured: boolean
  any_configured: boolean
}
