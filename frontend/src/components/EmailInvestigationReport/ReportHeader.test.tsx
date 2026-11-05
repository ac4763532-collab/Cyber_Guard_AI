import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ReportHeader } from './ReportHeader'
import type { InvestigationReport } from './types'

function makeReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: 'RPT-123',
    investigation_timestamp: new Date('2026-01-01T12:00:00Z').toISOString(),
    verdict: {
      classification: 'benign',
      risk_score: 10,
      risk_level: 'low',
      severity: 'low',
      confidence: 0.9,
      confidence_reasons: [],
    },
    executive_summary: '',
    key_findings: [],
    sender: {} as any,
    authentication: {} as any,
    urls: { total_urls: 0, suspicious_urls: 0, urls: [], status: 'not_detected' },
    content: {} as any,
    attachments: { total_attachments: 0, dangerous_attachments: 0, attachments: [], status: 'not_applicable' },
    headers: {} as any,
    threat_intel: { status: 'not_configured', results: [], malicious_count: 0, suspicious_count: 0 },
    iocs: { total_iocs: 0, domains: [], ips: [], urls: [], hashes: [] },
    risk_breakdown: { total_score: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0 },
    all_findings: [],
    recommendations: [],
    detection_status: {},
    ...overrides,
  }
}

describe('ReportHeader', () => {
  it('maps benign classification to "LIKELY BENIGN"', () => {
    render(<ReportHeader report={makeReport()} />)
    expect(screen.getByText('LIKELY BENIGN')).toBeInTheDocument()
  })

  it('maps phishing classification to "MALICIOUS"', () => {
    render(<ReportHeader report={makeReport({ verdict: { ...makeReport().verdict, classification: 'phishing' } })} />)
    expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
  })

  it('shows the report ID with a copy control', () => {
    render(<ReportHeader report={makeReport()} />)
    expect(screen.getByText(/RPT-123/)).toBeInTheDocument()
  })

  it('does not show a primary category for a benign verdict', () => {
    render(<ReportHeader report={makeReport()} />)
    expect(screen.queryByText('Credential Phishing')).not.toBeInTheDocument()
    expect(screen.queryByText('Brand Impersonation')).not.toBeInTheDocument()
  })

  it('gates the primary category to only show when real evidence backs it', () => {
    const report = makeReport({
      verdict: { ...makeReport().verdict, classification: 'phishing' },
      content: { credential_request_detected: true } as any,
    })
    render(<ReportHeader report={report} />)
    expect(screen.getByText('Credential Phishing')).toBeInTheDocument()
  })

  it('does not invent a primary category for malicious verdict with no matching evidence', () => {
    const report = makeReport({
      verdict: { ...makeReport().verdict, classification: 'malicious' },
      all_findings: [],
      content: {} as any,
    })
    render(<ReportHeader report={report} />)
    expect(screen.queryByText('Credential Phishing')).not.toBeInTheDocument()
    expect(screen.queryByText('Brand Impersonation')).not.toBeInTheDocument()
  })

  it('renders an export control', () => {
    render(<ReportHeader report={makeReport()} />)
    expect(screen.getByText('Export Report')).toBeInTheDocument()
  })
})
