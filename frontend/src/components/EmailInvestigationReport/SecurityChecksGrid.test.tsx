import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SecurityChecksGrid } from './SecurityChecksGrid'
import type { InvestigationReport } from './types'

function makeReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 50, risk_level: 'medium', severity: 'medium', confidence: 0.5, confidence_reasons: [] },
    executive_summary: '',
    key_findings: [],
    sender: { findings: [] } as any,
    authentication: {
      spf: { status: 'pass', evidence: '', domain: '', reason: '' },
      dkim: { status: 'unknown', evidence: '', domain: '', reason: 'No DKIM-Signature header present' },
      dmarc: { status: 'fail', evidence: '', domain: '', reason: '' },
      raw_header: '',
    },
    urls: { total_urls: 0, suspicious_urls: 0, urls: [], status: 'not_detected' },
    content: {} as any,
    attachments: { total_attachments: 0, dangerous_attachments: 0, attachments: [], status: 'not_applicable' },
    headers: { status: 'unknown' } as any,
    threat_intel: { status: 'not_configured', results: [], malicious_count: 0, suspicious_count: 0 },
    iocs: { total_iocs: 0, domains: [], ips: [], urls: [], hashes: [] },
    risk_breakdown: { total_score: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0 },
    all_findings: [],
    recommendations: [],
    detection_status: {},
    ...overrides,
  }
}

describe('SecurityChecksGrid', () => {
  it('renders all 9 security check tiles', () => {
    render(<SecurityChecksGrid report={makeReport()} />)
    ;['Sender Analysis', 'SPF', 'DKIM', 'DMARC', 'URL Analysis', 'Content Analysis', 'Attachment Analysis', 'Header Forensics', 'Threat Intelligence'].forEach(
      (label) => {
        expect(screen.getByText(label)).toBeInTheDocument()
      }
    )
  })

  it('shows DKIM as UNKNOWN, not FAIL, when no header is present', () => {
    render(<SecurityChecksGrid report={makeReport()} />)
    expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThanOrEqual(1)
  })

  it('shows DMARC as FAIL distinctly from DKIM UNKNOWN', () => {
    render(<SecurityChecksGrid report={makeReport()} />)
    expect(screen.getByText('FAIL')).toBeInTheDocument()
  })

  it('shows attachment analysis as N/A when there are no attachments, not as a pass/fail', () => {
    render(<SecurityChecksGrid report={makeReport()} />)
    expect(screen.getByText('N/A')).toBeInTheDocument()
  })

  it('each tile has a descriptive tooltip via the title attribute', () => {
    render(<SecurityChecksGrid report={makeReport()} />)
    const spfTile = screen.getByText('SPF').closest('button')
    expect(spfTile).toHaveAttribute('title')
    expect(spfTile?.getAttribute('title')?.length).toBeGreaterThan(10)
  })
})
