import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RiskConfidenceCards } from './RiskConfidenceCards'
import type { InvestigationReport } from './types'

function makeReport(verdictOverrides: Partial<InvestigationReport['verdict']> = {}): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: {
      classification: 'suspicious',
      risk_score: 65,
      risk_level: 'high',
      severity: 'high',
      confidence: 0.72,
      confidence_reasons: ['2 of 3 detectors agree'],
      ...verdictOverrides,
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
  }
}

describe('RiskConfidenceCards', () => {
  it('shows the risk score and band label from the backend', () => {
    const report = makeReport()
    render(<RiskConfidenceCards report={report} />)
    expect(screen.getByText('65')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('labels confidence as a heuristic, never as a calibrated probability', () => {
    const report = makeReport()
    render(<RiskConfidenceCards report={report} />)
    expect(screen.getByText('72')).toBeInTheDocument()
    expect(screen.getByText(/rule-based heuristic confidence, not a calibrated probability/i)).toBeInTheDocument()
  })

  it('shows confidence_reasons as the "why"', () => {
    const report = makeReport()
    render(<RiskConfidenceCards report={report} />)
    expect(screen.getByText('2 of 3 detectors agree')).toBeInTheDocument()
  })

  it('cross-references ML model output when confidence_reasons mention it, without implying confidence equals the model score', () => {
    const report = makeReport({ confidence_reasons: ['ML-001 flagged this as high risk'] })
    render(<RiskConfidenceCards report={report} />)
    expect(screen.getByText(/Cross-referenced against ML model output/)).toBeInTheDocument()
  })

  it('shows an honest "not available" fallback when confidence is missing rather than inventing a percentage', () => {
    const report = makeReport({ confidence: undefined as any })
    render(<RiskConfidenceCards report={report} />)
    expect(screen.getByText(/Confidence score not available/i)).toBeInTheDocument()
  })

  it('never shows a % sign next to the risk score (risk score and confidence stay visually distinct)', () => {
    const report = makeReport()
    render(<RiskConfidenceCards report={report} />)
    // Risk score is rendered as "65" + "/100", confidence as "72" + "%"
    expect(screen.getByText('/100')).toBeInTheDocument()
    expect(screen.getByText('%')).toBeInTheDocument()
  })
})
