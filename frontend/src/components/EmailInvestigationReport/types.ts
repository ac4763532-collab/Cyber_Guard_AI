/**
 * Shared types for the Email Investigation Report.
 *
 * Mirrors the backend's EmailInvestigationReport schema
 * (backend/app/schemas/email_report.py). Additive-only vs. the original
 * single-file component: every field below either existed in the original
 * inline interface or is a real field the backend already sends that the
 * old UI silently dropped. Nothing here is invented.
 */

export interface VerdictSection {
  classification: string
  risk_score: number
  risk_level: string
  severity: string
  confidence: number
  confidence_reasons: string[]
}

export interface AuthenticationResult {
  status: string
  evidence: string
  domain: string
  reason: string
}

export interface AuthenticationSection {
  spf: AuthenticationResult
  dkim: AuthenticationResult
  dmarc: AuthenticationResult
  raw_header: string
}

export interface ExtractedURL {
  url: string
  domain: string
  scheme: string
  display_text: string
  is_shortener: boolean
  is_ip_based: boolean
  is_suspicious_tld: boolean
  has_at_symbol: boolean
  display_href_mismatch: boolean
  severity: string
  findings: string[]
  // Per-URL threat intel lookup result, when a provider is configured.
  threat_intel_status?: string
  threat_intel_result?: string
}

export interface AttachmentAnalysis {
  filename: string
  extension: string
  mime_type: string
  size: number
  sha256: string
  sha1?: string
  md5?: string
  is_dangerous_extension: boolean
  is_double_extension: boolean
  is_macro_enabled: boolean
  has_mime_mismatch?: boolean
  is_archive?: boolean
  is_disk_image?: boolean
  severity: string
  findings: string[]
}

export interface FindingDetail {
  finding_id: string
  rule_id: string | null
  title: string
  severity: string
  description: string
  evidence: string[]
  source: string
  risk_contribution: number
  why_it_matters: string
  mitre_techniques: string[]
  recommendations: string[]
}

export interface RecommendationItem {
  action: string
  priority: string
  based_on: string
}

export interface RiskBreakdown {
  total_score: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  info_findings?: number
  // Per-category contributing-factor scores. These are a separate
  // heuristic approximation and do NOT necessarily sum to total_score -
  // treat them as "what contributed," not a strict decomposition.
  sender_score?: number
  auth_score?: number
  url_score?: number
  content_score?: number
  attachment_score?: number
  header_score?: number
  threat_intel_score?: number
}

export interface InvestigationReport {
  report_id: string
  investigation_timestamp: string
  verdict: VerdictSection
  executive_summary: string
  key_findings: FindingDetail[]
  sender: {
    from_address: string
    from_display_name: string
    from_domain: string
    reply_to: string
    reply_to_domain: string
    return_path: string
    return_path_domain?: string
    is_free_email_provider: boolean
    is_suspicious_tld: boolean
    is_lookalike_domain: boolean
    reply_to_mismatch: boolean
    return_path_mismatch: boolean
    findings: any[]
  }
  authentication: AuthenticationSection
  urls: {
    total_urls: number
    suspicious_urls: number
    urls: ExtractedURL[]
    status: string
  }
  content: {
    urgency_detected: boolean
    urgency_matches: string[]
    credential_request_detected: boolean
    credential_matches: string[]
    brand_impersonation_detected: boolean
    impersonated_brands: string[]
    social_engineering_score: number
  }
  attachments: {
    total_attachments: number
    dangerous_attachments: number
    attachments: AttachmentAnalysis[]
    status: string
  }
  headers: {
    message_id: string
    received_hops: number
    excessive_hops: boolean
    has_private_ip: boolean
    message_id_present: boolean
    findings: any[]
    status: string
  }
  threat_intel: {
    status: string
    results: any[]
    malicious_count: number
    suspicious_count: number
    providers_available?: string[]
  }
  iocs: {
    total_iocs: number
    domains: string[]
    ips: string[]
    urls: string[]
    hashes: string[]
    emails?: string[]
  }
  risk_breakdown: RiskBreakdown
  all_findings: FindingDetail[]
  recommendations: RecommendationItem[]
  detection_status: Record<string, string>
  campaign?: {
    campaign_id?: string
    related_count?: number
  } | null
}
