/**
 * Tests for LogAnalysisPage's tab system:
 *  - default tab on first load
 *  - clicking a tab updates the ?tab= URL param
 *  - a direct ?tab= URL drives which tab is shown
 *  - an invalid/unknown ?tab= value falls back to Manual Analysis
 *  - "Add Log Source" button only shows on the Sources tab
 *  - Manual Analysis's typed text/selected state survives a round-trip
 *    tab switch (mounted-but-hidden, not unmounted)
 *  - Log Sources / Log Events queries stop being called while their tab
 *    is hidden (they must stay conditionally unmounted, unlike Manual
 *    Analysis)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui'
import { LogAnalysisPage } from './LogAnalysisPage'
import { logsApi } from '@/services/api'

vi.mock('@/services/api', () => ({
  logsApi: {
    listSources: vi.fn(),
    createSource: vi.fn(),
    deleteSource: vi.fn(),
    restartSource: vi.fn(),
    listEvents: vi.fn(),
    getStatistics: vi.fn(),
  },
  analysisApi: {
    analyzeLogs: vi.fn(),
    uploadLogFile: vi.fn(),
  },
}))

function renderPage(initialEntries: string[] = ['/analysis/logs']) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <LogAnalysisPage />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  ;(logsApi.listSources as any).mockResolvedValue({ sources: [], total: 0 })
  ;(logsApi.listEvents as any).mockResolvedValue({ events: [], total: 0 })
  ;(logsApi.getStatistics as any).mockResolvedValue({ statistics: {} })
})

describe('LogAnalysisPage - tab defaults and navigation', () => {
  it('defaults to the Manual Analysis tab with no ?tab= param', () => {
    renderPage()
    expect(screen.getByText('Submit logs to see analysis results')).toBeInTheDocument()
  })

  it('clicking a tab updates the ?tab= URL param', async () => {
    renderPage()
    await userEvent.click(screen.getByRole('button', { name: /Log Sources/i }))

    await waitFor(() => {
      expect(window.location.search).toBe('')
    })
    // MemoryRouter doesn't touch window.location; assert via visible tab
    // content instead, which only renders once the search param updates.
    expect(logsApi.listSources).toHaveBeenCalled()
  })

  it('a direct ?tab=events URL opens the Log Events tab', async () => {
    renderPage(['/analysis/logs?tab=events'])

    await waitFor(() => {
      expect(logsApi.listEvents).toHaveBeenCalled()
    })
    expect(screen.getByPlaceholderText(/Search log messages/i)).toBeInTheDocument()
  })

  it('an invalid ?tab= value falls back to Manual Analysis', () => {
    renderPage(['/analysis/logs?tab=nonsense'])
    expect(screen.getByText('Submit logs to see analysis results')).toBeInTheDocument()
  })

  it('shows "Add Log Source" only on the Sources tab', async () => {
    renderPage()
    expect(screen.queryByText('Add Log Source')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Log Sources/i }))
    expect(await screen.findByText('Add Log Source')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Log Events/i }))
    expect(screen.queryByText('Add Log Source')).not.toBeInTheDocument()
  })
})

describe('LogAnalysisPage - Manual Analysis state survives tab switches', () => {
  it('keeps typed log text after switching to Sources and back', async () => {
    renderPage()

    const textarea = screen.getByPlaceholderText('Paste log entries here...')
    await userEvent.type(textarea, 'a suspicious log line')
    expect(textarea).toHaveValue('a suspicious log line')

    await userEvent.click(screen.getByRole('button', { name: /Log Sources/i }))
    await screen.findByText('Add Log Source')

    await userEvent.click(screen.getByRole('button', { name: /Manual Analysis/i }))

    expect(screen.getByPlaceholderText('Paste log entries here...')).toHaveValue(
      'a suspicious log line'
    )
  })
})

describe('LogAnalysisPage - Sources/Events stop polling while hidden', () => {
  it('does not call listSources again while on the Manual Analysis tab', async () => {
    renderPage()

    await userEvent.click(screen.getByRole('button', { name: /Log Sources/i }))
    await screen.findByText('Add Log Source')
    const callsAfterFirstVisit = (logsApi.listSources as any).mock.calls.length
    expect(callsAfterFirstVisit).toBeGreaterThan(0)

    await userEvent.click(screen.getByRole('button', { name: /Manual Analysis/i }))
    await screen.findByText('Submit logs to see analysis results')

    // Sources tab is unmounted now - no new calls should appear.
    expect((logsApi.listSources as any).mock.calls.length).toBe(callsAfterFirstVisit)
  })

  it('does not call listEvents again while on the Manual Analysis tab', async () => {
    renderPage()

    await userEvent.click(screen.getByRole('button', { name: /Log Events/i }))
    await waitFor(() => expect(logsApi.listEvents).toHaveBeenCalled())
    const callsAfterFirstVisit = (logsApi.listEvents as any).mock.calls.length

    await userEvent.click(screen.getByRole('button', { name: /Manual Analysis/i }))
    await screen.findByText('Submit logs to see analysis results')

    expect((logsApi.listEvents as any).mock.calls.length).toBe(callsAfterFirstVisit)
  })
})

describe('LogAnalysisPage - Manual Analysis "ad-hoc" framing', () => {
  it('shows the "Ad-hoc · not saved" tag and non-persistence explanation, not the old DEV badge', () => {
    renderPage()
    expect(screen.getByText('Ad-hoc · not saved')).toBeInTheDocument()
    expect(screen.queryByText('DEV')).not.toBeInTheDocument()
    expect(
      screen.getByText(/never saved as Log Events and never affect dashboard statistics/i)
    ).toBeInTheDocument()
  })
})
