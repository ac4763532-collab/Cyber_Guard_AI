import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Shield } from 'lucide-react'
import { SeverityBadge, StatusBadge, CollapsibleSection } from './badges'

describe('StatusBadge', () => {
  it('renders all 9 required SOC report states with distinct labels', () => {
    const cases: Array<[string, string]> = [
      ['detected', 'DETECTED'],
      ['not_detected', 'NOT DETECTED'],
      ['pass', 'PASS'],
      ['fail', 'FAIL'],
      ['unknown', 'UNKNOWN'],
      ['not_configured', 'NOT CONFIGURED'],
      ['configured', 'CONFIGURED'],
      ['not_available', 'NOT AVAILABLE'],
      ['not_applicable', 'N/A'],
    ]
    cases.forEach(([status, label]) => {
      const { unmount } = render(<StatusBadge status={status} />)
      expect(screen.getByText(label)).toBeInTheDocument()
      unmount()
    })
  })

  it('gives no_iocs its own honest label instead of falling through to UNKNOWN', () => {
    render(<StatusBadge status="no_iocs" />)
    expect(screen.getByText('NO IOCS')).toBeInTheDocument()
  })

  it('maps temperror and permerror to ERROR, not a generic unknown', () => {
    const { unmount } = render(<StatusBadge status="temperror" />)
    expect(screen.getByText('ERROR')).toBeInTheDocument()
    unmount()
    render(<StatusBadge status="permerror" />)
    expect(screen.getByText('ERROR')).toBeInTheDocument()
  })

  it('maps per-IOC lookup statuses (clean/suspicious/malicious) to their own labels', () => {
    const cases: Array<[string, string]> = [
      ['clean', 'CLEAN'],
      ['suspicious', 'SUSPICIOUS'],
      ['malicious', 'MALICIOUS'],
    ]
    cases.forEach(([status, label]) => {
      const { unmount } = render(<StatusBadge status={status} />)
      expect(screen.getByText(label)).toBeInTheDocument()
      unmount()
    })
  })

  it('falls back to UNKNOWN for an unrecognized status rather than crashing', () => {
    render(<StatusBadge status="totally-unexpected-value" />)
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument()
  })

  it('defaults to UNKNOWN when status is missing entirely', () => {
    // @ts-expect-error - intentionally testing the missing-prop fallback
    render(<StatusBadge status={undefined} />)
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument()
  })
})

describe('SeverityBadge', () => {
  it('renders the severity text for each known level', () => {
    ;['critical', 'high', 'medium', 'low', 'info'].forEach((sev) => {
      const { unmount } = render(<SeverityBadge severity={sev} />)
      expect(screen.getByText(sev)).toBeInTheDocument()
      unmount()
    })
  })
})

describe('CollapsibleSection', () => {
  it('is closed by default and opens on click', async () => {
    render(
      <CollapsibleSection title="Test Panel" icon={Shield}>
        <p>Hidden content</p>
      </CollapsibleSection>
    )
    expect(screen.queryByText('Hidden content')).not.toBeInTheDocument()

    const button = screen.getByRole('button', { name: /test panel/i })
    expect(button).toHaveAttribute('aria-expanded', 'false')

    button.click()
    expect(await screen.findByText('Hidden content')).toBeInTheDocument()
    expect(button).toHaveAttribute('aria-expanded', 'true')
  })

  it('respects defaultOpen', () => {
    render(
      <CollapsibleSection title="Open Panel" icon={Shield} defaultOpen>
        <p>Visible content</p>
      </CollapsibleSection>
    )
    expect(screen.getByText('Visible content')).toBeInTheDocument()
  })
})
