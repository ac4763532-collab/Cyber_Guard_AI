import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { KeyFindingsList } from './KeyFindingsList'
import type { InvestigationReport, FindingDetail } from './types'

function makeFinding(id: string, title: string): FindingDetail {
  return {
    finding_id: id,
    rule_id: null,
    title,
    severity: 'medium',
    description: 'desc',
    evidence: [],
    source: 'rule',
    risk_contribution: 0,
    why_it_matters: '',
    mitre_techniques: [],
    recommendations: [],
  }
}

function makeReport(all_findings: FindingDetail[]): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 50, risk_level: 'medium', severity: 'medium', confidence: 0.5, confidence_reasons: [] },
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
    all_findings,
    recommendations: [],
    detection_status: {},
  }
}

describe('KeyFindingsList', () => {
  it('skips index 0 (already shown by PrimaryFindingCard) and shows the next findings', () => {
    const findings = [
      makeFinding('f0', 'Primary Finding (shown elsewhere)'),
      makeFinding('f1', 'Second Finding'),
      makeFinding('f2', 'Third Finding'),
    ]
    render(<KeyFindingsList report={makeReport(findings)} />)
    expect(screen.queryByText('Primary Finding (shown elsewhere)')).not.toBeInTheDocument()
    expect(screen.getByText('Second Finding')).toBeInTheDocument()
    expect(screen.getByText('Third Finding')).toBeInTheDocument()
  })

  it('renders nothing when there is only a primary finding and nothing else', () => {
    const { container } = render(<KeyFindingsList report={makeReport([makeFinding('f0', 'Only Finding')])} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows a "View all" control when more than 3 remain, and expands on click', async () => {
    const findings = [0, 1, 2, 3, 4, 5].map((i) => makeFinding(`f${i}`, `Finding ${i}`))
    render(<KeyFindingsList report={makeReport(findings)} />)

    // index 0 skipped, so 5 remain -> only first 3 shown initially
    expect(screen.getByText('Finding 1')).toBeInTheDocument()
    expect(screen.getByText('Finding 3')).toBeInTheDocument()
    expect(screen.queryByText('Finding 5')).not.toBeInTheDocument()

    const expandButton = screen.getByText(/View all 6 findings/)
    fireEvent.click(expandButton)
    expect(await screen.findByText('Finding 5')).toBeInTheDocument()
  })

  it('does not show a "View all" control when 3 or fewer findings remain', () => {
    const findings = [makeFinding('f0', 'Primary'), makeFinding('f1', 'Second')]
    render(<KeyFindingsList report={makeReport(findings)} />)
    expect(screen.queryByText(/View all/)).not.toBeInTheDocument()
  })

  it('hides evidence by default and reveals it once a row is expanded', () => {
    const findings = [
      makeFinding('f0', 'Primary Finding (shown elsewhere)'),
      { ...makeFinding('f1', 'Second Finding'), evidence: ['raw-evidence-line-1'] },
    ]
    render(<KeyFindingsList report={makeReport(findings)} />)

    expect(screen.queryByText('raw-evidence-line-1')).not.toBeInTheDocument()

    const expandToggle = screen.getByLabelText('Expand evidence')
    fireEvent.click(expandToggle)

    expect(screen.getByText('raw-evidence-line-1')).toBeInTheDocument()
  })

  it('does not show an expand toggle for a finding with no evidence', () => {
    const findings = [makeFinding('f0', 'Primary'), makeFinding('f1', 'Second Finding')]
    render(<KeyFindingsList report={makeReport(findings)} />)
    expect(screen.queryByLabelText('Expand evidence')).not.toBeInTheDocument()
  })
})
