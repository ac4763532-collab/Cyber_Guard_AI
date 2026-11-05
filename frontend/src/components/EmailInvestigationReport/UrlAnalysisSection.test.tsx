import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { UrlAnalysisSection } from './UrlAnalysisSection'
import type { ExtractedURL, InvestigationReport } from './types'

function makeUrl(overrides: Partial<ExtractedURL> = {}): ExtractedURL {
  return {
    url: 'https://example.com/path',
    domain: 'example.com',
    scheme: 'https',
    display_text: '',
    is_shortener: false,
    is_ip_based: false,
    is_suspicious_tld: false,
    has_at_symbol: false,
    display_href_mismatch: false,
    severity: 'info',
    findings: [],
    ...overrides,
  }
}

function makeReport(urls: ExtractedURL[]): InvestigationReport {
  return {
    report_id: 'r1',
    investigation_timestamp: new Date().toISOString(),
    verdict: { classification: 'suspicious', risk_score: 50, risk_level: 'medium', severity: 'medium', confidence: 0.5, confidence_reasons: [] },
    executive_summary: '',
    key_findings: [],
    sender: {} as any,
    authentication: {} as any,
    urls: { total_urls: urls.length, suspicious_urls: 0, urls, status: urls.length ? 'detected' : 'not_detected' },
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

describe('UrlAnalysisSection', () => {
  it('shows the empty state when there are no URLs', () => {
    render(<UrlAnalysisSection report={makeReport([])} />)
    expect(screen.getByText('No URLs found in this email.')).toBeInTheDocument()
  })

  it('renders the URL, its domain, and a copy control for a long URL', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(200)
    render(<UrlAnalysisSection report={makeReport([makeUrl({ url: longUrl, domain: 'example.com' })])} />)
    expect(screen.getByText(longUrl)).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByTitle('Copy to clipboard')).toBeInTheDocument()
  })

  it('shows the real threat-intel status badge when provided, not just pattern flags', () => {
    render(
      <UrlAnalysisSection
        report={makeReport([makeUrl({ threat_intel_status: 'malicious', is_shortener: false, is_ip_based: false })])}
      />
    )
    expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
  })

  it('shows a neutral NOT DETECTED badge for a URL with no threat intel and no suspicious patterns (never claims "safe")', () => {
    render(<UrlAnalysisSection report={makeReport([makeUrl()])} />)
    expect(screen.getByText('NOT DETECTED')).toBeInTheDocument()
    expect(screen.queryByText(/CLEAN|SAFE/i)).not.toBeInTheDocument()
  })

  it('shows a DETECTED badge (discovery, not a verdict) when a pattern flag is present but no threat intel result exists', () => {
    render(<UrlAnalysisSection report={makeReport([makeUrl({ is_shortener: true })])} />)
    expect(screen.getByText('DETECTED')).toBeInTheDocument()
    expect(screen.queryByText('MALICIOUS')).not.toBeInTheDocument()
  })

  it('hides technical flags until the row is expanded', () => {
    render(<UrlAnalysisSection report={makeReport([makeUrl({ is_shortener: true, is_ip_based: true })])} />)
    expect(screen.queryByText('Shortener')).not.toBeInTheDocument()
    expect(screen.queryByText('IP-based')).not.toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('Expand URL technical details'))

    expect(screen.getByText('Shortener')).toBeInTheDocument()
    expect(screen.getByText('IP-based')).toBeInTheDocument()
  })

  it('does not show an expand toggle for a URL with no technical detail to show', () => {
    render(<UrlAnalysisSection report={makeReport([makeUrl()])} />)
    expect(screen.queryByLabelText('Expand URL technical details')).not.toBeInTheDocument()
  })
})
