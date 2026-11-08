/**
 * CyberGuard AI — Core TypeScript Definitions
 * ============================================================================
 * 
 * These interfaces mirror the Pydantic schemas from the backend (Files 39-68).
 * Every API request/response shape is defined here.
 * 
 * By strictly typing the frontend to match the backend, TypeScript will
 * throw a compile-time error if the backend changes a field name (e.g.,
 * `rule_id` to `rule`), preventing runtime `undefined` crashes in the UI.
 */

// ============================================================================
// ENUMS (Mirroring app/models/enums.py)
// ============================================================================

export type UserStatus = "active" | "pending_verification" | "suspended" | "inactive";

export type EventSeverity = "info" | "low" | "medium" | "high" | "critical";
export type IncidentSeverity = "low" | "medium" | "high" | "critical";

export type EventCategory = 
  | "authentication" | "authorization" | "network" | "file" 
  | "process" | "system" | "email" | "database" | "other";

export type FindingCategory = 
  | "phishing" | "malware" | "brute_force" | "port_scan" 
  | "privilege_escalation" | "suspicious_login" | "data_exfiltration" 
  | "correlated_activity" | "threat_intel_hit" | "policy_violation" | "other";

export type FindingStatus = "new" | "acknowledged" | "investigating" | "resolved" | "dismissed" | "false_positive";
export type AlertStatus = "new" | "acknowledged" | "investigating" | "resolved" | "dismissed";
export type IncidentStatus = "open" | "investigating" | "containment" | "eradication" | "recovery" | "resolved" | "closed";
export type CaseStatus = "open" | "assigned" | "investigating" | "pending_client" | "pending_info" | "resolved" | "closed" | "cancelled";
export type CasePriority = "low" | "medium" | "high" | "urgent";


// ============================================================================
// AUTH & USERS
// ============================================================================

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface User {
  id: string; // UUID
  public_user_id: string;
  role: "individual" | "analyst" | "organizer" | "admin" | string;
  email: string;
  full_name: string | null;
  status: UserStatus;
  email_verified_at: string | null;
  last_login_at: string | null;
  mfa_enabled: boolean;
  preferred_language: string;
  timezone: string;
  locked_until: string | null;
  is_active: boolean;
  is_locked: boolean;
  has_password: boolean;
  created_at: string;
  updated_at: string | null;
}


// ============================================================================
// TENANCY (Orgs & Workspaces)
// ============================================================================

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  status: string;
  owner_id: string;
  subscription_plan: string;
  created_at: string;
}

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  workspace_type: "personal" | "organization" | "shared";
  owner_id: string;
  organization_id: string | null;
  color: string | null;
  icon: string | null;
  is_active: boolean;
  created_at: string;
}


// ============================================================================
// SECURITY EVENTS (Raw Telemetry)
// ============================================================================

export interface SecurityEvent {
  id: string;
  workspace_id: string;
  source_id: string | null;
  event_time: string;
  received_at: string;
  severity: EventSeverity;
  category: EventCategory;
  event_type: string;
  action: string | null;
  outcome: string | null;
  username: string | null;
  hostname: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  process_name: string | null;
  file_path: string | null;
  url: string | null;
  domain: string | null;
  email_address: string | null;
  hash_md5: string | null;
  hash_sha256: string | null;
  raw_payload: Record<string, any>;
  normalized_payload: Record<string, any>;
  tags: string[];
  findings_count: number;
}


// ============================================================================
// AGENT FINDINGS (Detection Engine Output)
// ============================================================================

export interface AgentFinding {
  id: string;
  workspace_id: string;
  source_id: string | null;
  agent_name: string;
  rule_id: string;
  title: string;
  description: string | null;
  severity: EventSeverity;
  category: FindingCategory;
  confidence: number;
  status: FindingStatus;
  primary_event_id: string | null;
  event_ids: string[];
  evidence: Record<string, any>;
  mitre_techniques: string[];
  tags: string[];
  alert_id: string | null;
  incident_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  created_at: string;
  updated_at: string | null;
}


// ============================================================================
// ALERTS (User-Facing Notifications)
// ============================================================================

export interface SecurityAlert {
  id: string;
  workspace_id: string;
  source_id: string | null;
  incident_id: string | null;
  assigned_to_id: string | null;
  alert_type: string;
  severity: EventSeverity;
  category: FindingCategory;
  status: AlertStatus;
  title: string;
  description: string | null;
  finding_ids: string[];
  context: Record<string, any>;
  recommended_actions: Record<string, any>[];
  mitre_techniques: string[];
  seen_at: string | null;
  acknowledged_at: string | null;
  resolved_at: string | null;
  dismissed_at: string | null;
  resolution_notes: string | null;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  created_at: string;
}


// ============================================================================
// INCIDENTS (Managed Investigations)
// ============================================================================

export interface SecurityIncident {
  id: string;
  workspace_id: string;
  primary_source_id: string | null;
  previous_incident_id: string | null;
  assigned_to_id: string | null;
  assigned_by_id: string | null;
  title: string;
  description: string | null;
  severity: IncidentSeverity;
  category: FindingCategory;
  status: IncidentStatus;
  alert_ids: string[];
  finding_ids: string[];
  affected_devices: string[];
  affected_users: string[];
  affected_ips: string[];
  mitre_techniques: string[];
  tags: string[];
  context: Record<string, any>;
  
  // NIST lifecycle timestamps
  opened_at: string;
  acknowledged_at: string | null;
  containment_at: string | null;
  eradication_at: string | null;
  recovery_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  
  // Resolution
  root_cause: string | null;
  resolution_summary: string | null;
  lessons_learned: string | null;
  
  // SLA
  sla_acknowledge_hours: number | null;
  sla_resolve_hours: number | null;
  expires_at: string | null;
  
  occurrence_count: number;
  created_at: string;
  updated_at: string | null;
}


// ============================================================================
// CASES (Analyst Work Items)
// ============================================================================

export interface SecurityCase {
  id: string;
  workspace_id: string;
  incident_id: string | null;
  case_number: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  priority: CasePriority;
  severity: EventSeverity;
  category: FindingCategory;
  assigned_to_id: string | null;
  assigned_by_id: string | null;
  assigned_at: string | null;
  resolution_summary: string | null;
  sla_deadline_at: string | null;
  opened_at: string;
  closed_at: string | null;
  is_billable: boolean;
  created_at: string;
  updated_at: string | null;
}


// ============================================================================
// API RESPONSES (Paginated Envelopes)
// ============================================================================

export interface PageMeta {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  meta: PageMeta;
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
    correlation_id?: string;
  };
}

// ============================================================================
// ROOMS & COLLABORATION
// ============================================================================

export interface Room {
  id: string;
  public_room_id: string;
  organization_id: string | null;
  name: string;
  description: string | null;
  join_policy: "direct" | "invite_only" | "approval" | string;
  status: "active" | "archived" | "suspended" | string;
  created_by: string;
  has_password?: boolean;
  member_count?: number;
  created_at: string;
  updated_at?: string | null;
}

export interface RoomMember {
  id: string;
  room_id: string;
  user_id: string;
  role: "owner" | "admin" | "analyst" | "member" | string;
  status: "active" | "pending_approval" | "revoked" | string;
  joined_at: string;
  user_name?: string | null;
  public_user_id?: string | null;
}

export interface RoomInvitation {
  id: string;
  room_id: string;
  room_name: string;
  public_room_id: string;
  inviter_id: string;
  inviter_name: string;
  role: string;
  status: "pending" | "accepted" | "declined" | "expired" | string;
  expires_at: string;
  created_at: string;
}

export interface JoinRoomRequest {
  room_code: string;
  password?: string | null;
}

export interface JoinRoomResponse {
  success: boolean;
  message: string;
  room: Room;
  member_role: string;
}
