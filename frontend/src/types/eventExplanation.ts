export interface WhoInvolved {
  account_name?: string | null;
  account_type?: string | null;
  initiating_user?: string | null;
  target_user?: string | null;
  domain?: string | null;
  user_sid?: string | null;
  explanation: string;
}

export interface WhereHappened {
  monitored_device: string;
  source_workstation?: string | null;
  source_ip?: string | null;
  channel?: string | null;
  process_path?: string | null;
  explanation: string;
}

export interface WhenHappened {
  timestamp: string;
  timestamp_formatted: string;
  relative_time: string;
  timezone: string;
}

export interface SimpleView {
  what_happened: string;
  who: WhoInvolved;
  where: WhereHappened;
  when: WhenHappened;
  why_it_matters: string;
  what_should_i_do: string[];
  normal_when?: string[];
  suspicious_when?: string[];
}

export interface MitreAttack {
  technique_id: string;
  technique_name: string;
  tactic: string;
  url: string;
  mapping_reason?: string | null;
  supporting_evidence?: string | null;
}

export interface AnalystView {
  technical_properties: Record<string, any>;
  mitre_attack?: MitreAttack | null;
  detection_rule?: string | null;
  raw_payload: Record<string, any>;
}

export interface EventExplanationResponse {
  event_id: string;
  device_id?: string | null;
  device_name: string;
  original_event_id?: string | null;
  title: string;
  short_description: string;
  severity: string;
  assessment: string;
  threat_status: string;
  definition_status: "verified" | "partially_verified" | "unverified" | "unknown_definition" | string;
  category: string;
  event_time: string;
  event_time_formatted: string;
  relative_time: string;
  simple_view: SimpleView;
  analyst_view: AnalystView;
}
