import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '@/test/test-utils'
import { FeedbackExportBar, buildReadableExport } from './FeedbackExportBar'
import { feedbackApi } from '@/services/api'
import type { InvestigationReport } from './types'

vi.mock('@/services/api', () => ({
  feedbackApi: {
    submit: vi.fn(),
  },
}))

function makeReport(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    report_id: 'RPT-456',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 55, risk_level: 'medium', severity: 'medium', confidence: 0.6, confidence_reasons: [] },
    executive_summary: 'This email shows some suspicious signals.',
    key_findings: [],
    sender: { from_address: 'a@b.com', from_domain: 'b.com', reply_to: '', return_path: '' } as any,
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

describe('buildReadableExport', () => {
  it('produces non-empty text containing the report ID', () => {
    const text = buildReadableExport(makeReport())
    expect(text.length).toBeGreaterThan(0)
    expect(text).toContain('RPT-456')
  })

  it('labels confidence honestly in the export text', () => {
    const text = buildReadableExport(makeReport())
    expect(text).toContain('rule-based heuristic')
  })
})

describe('FeedbackActions (via FeedbackExportBar)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls the real feedback endpoint with the report id on False Positive click', async () => {
    ;(feedbackApi.submit as any).mockResolvedValue({ data: {} })
    renderWithProviders(<FeedbackExportBar report={makeReport()} />)

    await userEvent.click(screen.getByText('False Positive'))

    await waitFor(() => {
      expect(feedbackApi.submit).toHaveBeenCalledWith({
        analysis_id: 'RPT-456',
        feedback_type: 'false_positive',
      })
    })
  })

  it('shows a confirmation state after successful submission', async () => {
    ;(feedbackApi.submit as any).mockResolvedValue({ data: {} })
    renderWithProviders(<FeedbackExportBar report={makeReport()} />)

    await userEvent.click(screen.getByText('Missed Threat'))

    expect(await screen.findByText(/Reported as missed threat/i)).toBeInTheDocument()
  })
})
