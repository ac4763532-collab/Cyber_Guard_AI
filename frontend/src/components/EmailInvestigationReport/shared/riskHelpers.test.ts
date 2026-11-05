import { describe, it, expect } from 'vitest'
import {
  getVerdictLabel,
  getRiskColorClass,
  getRiskBandLabel,
  stripTrailingBracket,
  severityRank,
} from './riskHelpers'

describe('getVerdictLabel', () => {
  it('maps phishing and malicious to MALICIOUS', () => {
    expect(getVerdictLabel('phishing')).toBe('MALICIOUS')
    expect(getVerdictLabel('malicious')).toBe('MALICIOUS')
  })

  it('maps suspicious to SUSPICIOUS', () => {
    expect(getVerdictLabel('suspicious')).toBe('SUSPICIOUS')
  })

  it('maps benign to the soft "LIKELY BENIGN" label, not bare BENIGN', () => {
    expect(getVerdictLabel('benign')).toBe('LIKELY BENIGN')
  })

  it('maps unknown to INCONCLUSIVE', () => {
    expect(getVerdictLabel('unknown')).toBe('INCONCLUSIVE')
  })

  it('falls back to INCONCLUSIVE for missing or unrecognized values', () => {
    expect(getVerdictLabel(undefined)).toBe('INCONCLUSIVE')
    expect(getVerdictLabel(null)).toBe('INCONCLUSIVE')
    expect(getVerdictLabel('something-else')).toBe('INCONCLUSIVE')
  })

  it('is case-insensitive', () => {
    expect(getVerdictLabel('PHISHING')).toBe('MALICIOUS')
  })
})

describe('getRiskBandLabel', () => {
  it('prefers the backend-supplied risk_level over deriving from score', () => {
    expect(getRiskBandLabel('medium', 95)).toBe('MEDIUM')
  })

  it('derives the band from score using the documented thresholds when risk_level is missing', () => {
    expect(getRiskBandLabel(null, 85)).toBe('CRITICAL')
    expect(getRiskBandLabel(null, 65)).toBe('HIGH')
    expect(getRiskBandLabel(null, 35)).toBe('MEDIUM')
    expect(getRiskBandLabel(null, 10)).toBe('LOW')
  })

  it('respects the exact documented boundaries', () => {
    expect(getRiskBandLabel(null, 80)).toBe('CRITICAL')
    expect(getRiskBandLabel(null, 79)).toBe('HIGH')
    expect(getRiskBandLabel(null, 60)).toBe('HIGH')
    expect(getRiskBandLabel(null, 59)).toBe('MEDIUM')
    expect(getRiskBandLabel(null, 30)).toBe('MEDIUM')
    expect(getRiskBandLabel(null, 29)).toBe('LOW')
  })
})

describe('getRiskColorClass', () => {
  it('returns distinct colors for each band', () => {
    expect(getRiskColorClass(90)).toBe('text-red-500')
    expect(getRiskColorClass(65)).toBe('text-orange-500')
    expect(getRiskColorClass(35)).toBe('text-yellow-500')
    expect(getRiskColorClass(10)).toBe('text-emerald-500')
  })
})

describe('stripTrailingBracket', () => {
  it('strips a stray trailing ">" from a domain string', () => {
    expect(stripTrailingBracket('mykeymate.com>')).toBe('mykeymate.com')
  })

  it('strips multiple trailing bracket characters', () => {
    expect(stripTrailingBracket('example.com>>')).toBe('example.com')
  })

  it('leaves a clean domain untouched', () => {
    expect(stripTrailingBracket('example.com')).toBe('example.com')
  })

  it('handles null/undefined/empty input without throwing', () => {
    expect(stripTrailingBracket(null)).toBe('')
    expect(stripTrailingBracket(undefined)).toBe('')
    expect(stripTrailingBracket('')).toBe('')
  })
})

describe('severityRank', () => {
  it('orders severities consistently with the backend (critical first)', () => {
    expect(severityRank('critical')).toBeLessThan(severityRank('high'))
    expect(severityRank('high')).toBeLessThan(severityRank('medium'))
    expect(severityRank('medium')).toBeLessThan(severityRank('low'))
    expect(severityRank('low')).toBeLessThan(severityRank('info'))
  })

  it('falls back to the lowest rank for unknown severities', () => {
    expect(severityRank('nonsense')).toBe(4)
    expect(severityRank(undefined)).toBe(4)
  })
})
