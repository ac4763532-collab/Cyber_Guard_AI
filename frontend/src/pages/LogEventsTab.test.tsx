/**
 * Tests for LogAnalysisPage's Log Events tab (events table, pagination,
 * filters, EventDetailPanel). The component isn't separately exported, so
 * these tests drive it through LogAnalysisPage with ?tab=events, same as
 * a real user navigating there.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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

function renderEventsTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter initialEntries={['/analysis/logs?tab=events']}>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <LogAnalysisPage />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>
  )
}

const sampleEvent = {
  id: 'evt-1',
  timestamp: '2025-01-01T00:00:00Z',
  level: 'critical',
  source_type: 'linux_ssh',
  hostname: 'web01',
  message: 'Failed password for root from 10.0.0.5',
  raw_content: 'raw line here',
  extracted_fields: { user: 'root', ip: '10.0.0.5' },
  risk_indicators: ['brute_force_suspected'],
}

beforeEach(() => {
  vi.clearAllMocks()
  ;(logsApi.listSources as any).mockResolvedValue({ sources: [{ id: 's1', name: 'Web01' }], total: 1 })
  ;(logsApi.getStatistics as any).mockResolvedValue({ statistics: {} })
})

describe('LogEventsTab - loading/empty/error states', () => {
  it('shows a loading spinner, then the empty state when there are no events', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [], total: 0 })
    renderEventsTab()

    expect(await screen.findByText('No log events found')).toBeInTheDocument()
  })

  it('shows an error state with a working retry button', async () => {
    ;(logsApi.listEvents as any).mockRejectedValueOnce(new Error('boom'))
    renderEventsTab()

    expect(await screen.findByText('Unable to load log events')).toBeInTheDocument()

    ;(logsApi.listEvents as any).mockResolvedValueOnce({ events: [sampleEvent], total: 1 })
    await userEvent.click(screen.getByText('Retry'))

    expect(await screen.findByText(/Failed password for root/)).toBeInTheDocument()
  })
})

describe('LogEventsTab - table rendering and pagination', () => {
  it('renders a row per event with level badge, host, and message', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 1 })
    renderEventsTab()

    expect(await screen.findByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('web01')).toBeInTheDocument()
    expect(screen.getByText(/Failed password for root/)).toBeInTheDocument()
  })

  it('disables Previous on the first page and advances offset on Next', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 120 })
    renderEventsTab()

    await screen.findByText(/Failed password for root/)
    expect(screen.getByText('Previous')).toBeDisabled()
    expect(screen.getByText('Next')).not.toBeDisabled()

    await userEvent.click(screen.getByText('Next'))

    await waitFor(() => {
      const lastCall = (logsApi.listEvents as any).mock.calls.at(-1)[0]
      expect(lastCall.offset).toBe(50)
    })
  })
})

describe('LogEventsTab - filters', () => {
  it('re-queries with a new level filter and resets to offset 0', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 1 })
    renderEventsTab()
    await screen.findByText(/Failed password for root/)

    // Both the Source and Level <select>s start at value="" - find Level
    // specifically by one of its distinctive options rather than by value.
    const levelSelect = screen.getAllByRole('combobox').find((el) =>
      within(el as HTMLSelectElement).queryByText('Critical')
    ) as HTMLSelectElement
    await userEvent.selectOptions(levelSelect, 'critical')

    await waitFor(() => {
      const lastCall = (logsApi.listEvents as any).mock.calls.at(-1)[0]
      expect(lastCall.level).toBe('critical')
      expect(lastCall.offset).toBe(0)
    })
  })
})

describe('LogEventsTab - EventDetailPanel', () => {
  it('opens the detail panel on row click and shows normalized fields', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 1 })
    renderEventsTab()

    const row = await screen.findByText(/Failed password for root/)
    await userEvent.click(row)

    expect(screen.getByText('Event Detail')).toBeInTheDocument()
    expect(screen.getByText('brute_force_suspected')).toBeInTheDocument()
  })

  it('toggles between Normalized and Raw views', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 1 })
    renderEventsTab()

    const row = await screen.findByText(/Failed password for root/)
    await userEvent.click(row)

    await userEvent.click(screen.getByRole('button', { name: 'Raw' }))
    expect(screen.getByText('raw line here')).toBeInTheDocument()
  })

  it('pins the honest "no related alerts/incidents" message instead of a fabricated link', async () => {
    ;(logsApi.listEvents as any).mockResolvedValue({ events: [sampleEvent], total: 1 })
    renderEventsTab()

    const row = await screen.findByText(/Failed password for root/)
    await userEvent.click(row)

    expect(
      screen.getByText(
        "Related alerts and incidents aren't available yet — the backend doesn't expose a lookup from a log event to the alerts/incidents it may have triggered."
      )
    ).toBeInTheDocument()
  })
})
