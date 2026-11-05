/**
 * Pure helper functions shared across the Email Investigation Report
 * components. Kept dependency-free (no React) so they're trivially
 * unit-testable.
 */
import type { ReactElement } from 'react'
import { createElement } from 'react'
import { ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react'

/**
 * Backend's flat 5-value Verdict enum (benign/suspicious/phishing/
 * malicious/unknown) mapped onto the 4 display labels the report calls
 * for. "LIKELY BENIGN" (not bare "BENIGN") deliberately keeps the
 * language soft - a benign verdict from a heuristic classifier is still
 * a probabilistic read, not a guarantee.
 */
export function getVerdictLabel(classification: string | undefined | null): string {
  switch ((classification || '').toLowerCase()) {
    case 'phishing':
    case 'malicious':
      return 'MALICIOUS'
    case 'suspicious':
      return 'SUSPICIOUS'
    case 'benign':
      return 'LIKELY BENIGN'
    case 'unknown':
      return 'INCONCLUSIVE'
    default:
      return 'INCONCLUSIVE'
  }
}

export function getRiskColorClass(score: number): string {
  if (score >= 80) return 'text-red-500'
  if (score >= 60) return 'text-orange-500'
  if (score >= 30) return 'text-yellow-500'
  return 'text-emerald-500'
}

/** Risk band label from the backend's own documented thresholds
 * (RiskLevel enum comments in email_report.py): critical >= 80,
 * high 60-79, medium 30-59, low 0-29. Falls back to deriving the band
 * from risk_score only if the backend didn't send risk_level at all. */
export function getRiskBandLabel(riskLevel: string | undefined | null, score: number): string {
  if (riskLevel) return riskLevel.toUpperCase()
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

export function getClassificationIcon(classification: string | undefined | null): ReactElement {
  switch ((classification || '').toLowerCase()) {
    case 'phishing':
    case 'malicious':
      return createElement(ShieldX, { className: 'w-8 h-8 text-red-500' })
    case 'suspicious':
      return createElement(ShieldAlert, { className: 'w-8 h-8 text-yellow-500' })
    default:
      return createElement(ShieldCheck, { className: 'w-8 h-8 text-emerald-500' })
  }
}

export function getClassificationBgClass(classification: string | undefined | null): string {
  switch ((classification || '').toLowerCase()) {
    case 'phishing':
    case 'malicious':
      return 'from-red-500/20 to-red-900/20 border-red-500/30'
    case 'suspicious':
      return 'from-yellow-500/20 to-yellow-900/20 border-yellow-500/30'
    default:
      return 'from-emerald-500/20 to-emerald-900/20 border-emerald-500/30'
  }
}

/**
 * Defensive client-side guard against a trailing ">" leaking into a
 * domain string (e.g. "mykeymate.com>"). The real fix is server-side
 * (email_agent_v2.py now cleans Reply-To/Return-Path headers via
 * parse_email_address before extracting the domain), but this stays as
 * belt-and-suspenders so a malformed value from any other code path
 * never reaches the screen as-is.
 */
export function stripTrailingBracket(value: string | undefined | null): string {
  if (!value) return ''
  return value.replace(/[<>]+$/g, '').trim()
}

/**
 * Severity rank used for sorting / comparison where needed client-side.
 * Mirrors the server's own ordering (critical=0 ... info=4) so any
 * client-side sort stays consistent with how all_findings arrives.
 */
export function severityRank(severity: string | undefined | null): number {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 0
    case 'high':
      return 1
    case 'medium':
      return 2
    case 'low':
      return 3
    default:
      return 4
  }
}
