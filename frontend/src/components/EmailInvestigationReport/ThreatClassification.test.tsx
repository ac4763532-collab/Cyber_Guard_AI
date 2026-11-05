import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ThreatClassification } from './ThreatClassification'
import type { InvestigationReport } from './types'

function makeReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 50, risk_level: 'medium', severity: 'medium', confidence: 0.5, confidence_reasons: [] },
    executive_summary: '',
    key_findings: [],
    sender: { reply_to_mismatch: false, return_path_mismatch: false } as any,
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

describe('ThreatClassification', () => {
  it('is collapsed by default', () => {
    render(<ThreatClassification report={makeReport()} />)
    expect(screen.queryByText('NOT EVALUATED')).not.toBeInTheDocument()
    const button = screen.getByRole('button', { name: /threat classification/i })
    expect(button).toHaveAttribute('aria-expanded', 'false')
  })

  it('marks every category NOT EVALUATED when there is no matching evidence', async () => {
    render(<ThreatClassification report={makeReport()} />)
    screen.getByRole('button', { name: /threat classification/i }).click()
    const notEvaluated = await screen.findAllByText('NOT EVALUATED')
    expect(notEvaluated.length).toBe(4)
  })

  it('marks a category as evidence-found only when real matching evidence exists, never claiming unsupported ML support', async () => {
    const report = makeReport({ content: { credential_request_detected: true } as any })
    render(<ThreatClassification report={report} />)
    screen.getByRole('button', { name: /threat classification/i }).click()
    const found = await screen.findAllByText('EVIDENCE FOUND')
    expect(found.length).toBe(1)
    expect(screen.getByText('Credential phishing')).toBeInTheDocument()
  })

  it('states plainly that there is no ML sub-category classifier', async () => {
    render(<ThreatClassification report={makeReport()} />)
    screen.getByRole('button', { name: /threat classification/i }).click()
    expect(await screen.findByText(/no machine-learning sub-category classifier/i)).toBeInTheDocument()
  })
})
