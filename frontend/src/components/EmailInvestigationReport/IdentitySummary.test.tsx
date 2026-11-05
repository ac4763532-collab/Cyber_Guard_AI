import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { IdentitySummary } from './IdentitySummary'
import type { InvestigationReport } from './types'

function makeReport(sender: Partial<InvestigationReport['sender']>): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 50, risk_level: 'medium', severity: 'medium', confidence: 0.5, confidence_reasons: [] },
    executive_summary: '',
    key_findings: [],
    sender: {
      from_address: '',
      from_display_name: '',
      from_domain: '',
      reply_to: '',
      reply_to_domain: '',
      return_path: '',
      is_free_email_provider: false,
      is_suspicious_tld: false,
      is_lookalike_domain: false,
      reply_to_mismatch: false,
      return_path_mismatch: false,
      findings: [],
      ...sender,
    },
    authentication: {} as any,
    urls: { total_urls: 3, suspicious_urls: 0, urls: [], status: 'not_detected' },
    content: {} as any,
    attachments: { total_attachments: 1, dangerous_attachments: 0, attachments: [], status: 'not_applicable' },
    headers: {} as any,
    threat_intel: { status: 'not_configured', results: [], malicious_count: 0, suspicious_count: 0 },
    iocs: { total_iocs: 0, domains: [], ips: [], urls: [], hashes: [] },
    risk_breakdown: { total_score: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0 },
    all_findings: [],
    recommendations: [],
    detection_status: {},
  }
}

describe('IdentitySummary', () => {
  it('never renders a stray ">" in any identity field (the mykeymate.com> regression)', () => {
    const report = makeReport({
      from_domain: 'company.com',
      reply_to: 'attacker@mykeymate.com>',
      return_path: 'bounce@mykeymate.com>',
    })
    render(<IdentitySummary report={report} />)
    // The ">" character must not appear anywhere in rendered identity text
    const container = screen.getByText(/attacker@mykeymate\.com/)
    expect(container.textContent).not.toContain('>')
  })

  it('shows URL and attachment counts', () => {
    const report = makeReport({})
    render(<IdentitySummary report={report} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
  })

  it('shows a dash for empty fields rather than blank space', () => {
    const report = makeReport({})
    render(<IdentitySummary report={report} />)
    expect(screen.getAllByText('-').length).toBeGreaterThan(0)
  })

  it('shows mismatch flags only when true', () => {
    const report = makeReport({ reply_to_mismatch: true })
    render(<IdentitySummary report={report} />)
    expect(screen.getByText('Reply-To Mismatch')).toBeInTheDocument()
    expect(screen.queryByText('Return-Path Mismatch')).not.toBeInTheDocument()
  })
})
