import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { PrimaryFindingCard } from './PrimaryFindingCard'
import type { InvestigationReport, FindingDetail } from './types'

function makeFinding(overrides: Partial<FindingDetail> = {}): FindingDetail {
  return {
    finding_id: 'f1',
    rule_id: null,
    title: 'Generic Finding',
    severity: 'medium',
    description: 'A generic description.',
    evidence: [],
    source: 'rule',
    risk_contribution: 0,
    why_it_matters: '',
    mitre_techniques: [],
    recommendations: [],
    ...overrides,
  }
}

function makeReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: {
      classification: 'suspicious',
      risk_score: 50,
      risk_level: 'medium',
      severity: 'medium',
      confidence: 0.6,
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

describe('PrimaryFindingCard', () => {
  it('renders the first entry of all_findings when present', () => {
    const report = makeReport({
      all_findings: [makeFinding({ title: 'Top Finding', description: 'desc A' })],
      key_findings: [makeFinding({ title: 'Should Not Show', description: 'desc B' })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.getByText('Top Finding')).toBeInTheDocument()
    expect(screen.queryByText('Should Not Show')).not.toBeInTheDocument()
  })

  it('falls back to key_findings[0] when all_findings is empty', () => {
    const report = makeReport({
      all_findings: [],
      key_findings: [makeFinding({ title: 'Fallback Finding' })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.getByText('Fallback Finding')).toBeInTheDocument()
  })

  it('renders nothing when both all_findings and key_findings are empty', () => {
    const report = makeReport({ all_findings: [], key_findings: [] })
    const { container } = render(<PrimaryFindingCard report={report} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('only shows risk_contribution when it is greater than 0', () => {
    const report = makeReport({
      all_findings: [makeFinding({ risk_contribution: 0 })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.queryByText(/to risk score/)).not.toBeInTheDocument()
  })

  it('shows risk_contribution when positive', () => {
    const report = makeReport({
      all_findings: [makeFinding({ risk_contribution: 15 })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.getByText(/\+15/)).toBeInTheDocument()
  })

  it('renders why_it_matters when provided', () => {
    const report = makeReport({
      all_findings: [makeFinding({ why_it_matters: 'This indicates a spoofing attempt.' })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.getByText(/This indicates a spoofing attempt\./)).toBeInTheDocument()
  })

  it('shows a signal-not-proof caveat for Return-Path/Reply-To findings', () => {
    const report = makeReport({
      all_findings: [makeFinding({ title: 'Return-Path mismatch detected' })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.getByText(/signal, not proof of phishing/i)).toBeInTheDocument()
  })

  it('renders long evidence text without truncation once expanded', () => {
    const longEvidence = 'A'.repeat(300)
    const report = makeReport({
      all_findings: [makeFinding({ evidence: [longEvidence] })],
    })
    render(<PrimaryFindingCard report={report} />)
    fireEvent.click(screen.getByText('Show evidence'))
    expect(screen.getByText(longEvidence)).toBeInTheDocument()
  })

  it('hides evidence by default and shows a toggle to reveal it', () => {
    const report = makeReport({
      all_findings: [makeFinding({ evidence: ['raw-evidence-line'] })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.queryByText('raw-evidence-line')).not.toBeInTheDocument()

    const toggle = screen.getByText('Show evidence')
    fireEvent.click(toggle)

    expect(screen.getByText('raw-evidence-line')).toBeInTheDocument()
    expect(screen.getByText('Hide evidence')).toBeInTheDocument()
  })

  it('does not show an evidence toggle when there is no evidence', () => {
    const report = makeReport({
      all_findings: [makeFinding({ evidence: [] })],
    })
    render(<PrimaryFindingCard report={report} />)
    expect(screen.queryByText('Show evidence')).not.toBeInTheDocument()
  })
})
